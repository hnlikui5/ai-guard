//! AI Guard (`packages/session`) — 宿主机与 WSL2 双环境 Codex 会话严格只读索引与 SHA-256 安全备份模块（Phase 4 / M5-05）。
//!
//! 满足 `AGENTS.md` §4.2 与 `PRD_V0.1.md` §4.4.2 强制红线：
//! 1. **100% 只读访问**：读取 `session_index.jsonl`、`sessions/**/rollout-*.jsonl` 及 `state_5.sqlite` / `thread_history_1.sqlite` 时，
//!    SQLite 强制采用 `file:<path>?mode=ro&immutable=1`（`SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_URI`）打开，
//!    绝不创建或修改 `-wal`、`-shm`、锁文件，也绝不改变原会话目录中任何文件的哈希与 `mtime`。
//! 2. **跨环境统一视图**：同时支持 Windows 宿主机（`host:windows`）与 WSL2（`wsl2:<distro>`）会话枚举、详情查看与快照备份。
//! 3. **隐私脱敏保护**：所有会话标题、工作目录与摘要字段均经过 `redact_secrets` 脱敏。

use ai_guard_backup::{BackupError, BackupManifest, BackupStore};
use ai_guard_security::redact_secrets;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub mod migration;

pub use migration::{
    export_ast_to_agy, export_ast_to_codex, export_ast_to_opencode, migrate_session,
    parse_agy_transcript_content, parse_codex_rollout_content, parse_opencode_session_content,
    remap_path_str, MigrationReport, MigrationRequest, SessionArtifact, SessionAst, SessionTurn,
    ToolCallAst,
};

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("[AG-SESSION-IO] 读取会话文件失败 ({path}): {detail}")]
    Io { path: String, detail: String },

    #[error("[AG-SESSION-NOT-FOUND] 在目标环境 `{target_id}` 中未找到会话 `{session_id}`")]
    NotFound {
        target_id: String,
        session_id: String,
    },

    #[error("[AG-SESSION-BACKUP] 会话备份失败: {0}")]
    Backup(#[from] BackupError),

    #[error("[AG-SESSION-MIGRATION] 会话迁移失败: {detail}")]
    Migration { detail: String },

    #[error("[AG-SESSION-PARSE] 会话格式解析失败 ({format}): {detail}")]
    Parse { format: String, detail: String },
}

impl SessionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "AG-SESSION-IO",
            Self::NotFound { .. } => "AG-SESSION-NOT-FOUND",
            Self::Backup(b) => b.code(),
            Self::Migration { .. } => "AG-SESSION-MIGRATION",
            Self::Parse { .. } => "AG-SESSION-PARSE",
        }
    }
}

/// 单条会话摘要（供 `ai-guard session list` 展示）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub target_id: String,
    pub title: String,
    pub cwd: String,
    pub updated_at: String,
    pub model: Option<String>,
    pub rollout_file_exists: bool,
    pub source_files: Vec<String>,
}

/// 会话详情（供 `ai-guard session show <id>` 展示）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDetail {
    pub summary: SessionSummary,
    pub turns_count: usize,
    pub rollout_events_count: usize,
    pub rollout_path: Option<String>,
    pub redacted_preview: Option<String>,
}

/// 会话备份报告（供 `ai-guard session backup <id>` 返回）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBackupReport {
    pub session_id: String,
    pub target_id: String,
    pub backup_manifest: BackupManifest,
    pub verified: bool,
}

#[derive(Debug, Deserialize)]
struct RawSessionIndexEntry {
    id: Option<String>,
    thread_name: Option<String>,
    updated_at: Option<String>,
}

/// 只读枚举指定 `.codex` 目录下的 Codex 会话列表。
pub fn list_codex_sessions(
    target_id: &str,
    codex_home: &Path,
    limit: usize,
) -> Result<Vec<SessionSummary>, SessionError> {
    if !codex_home.is_dir() {
        return Ok(Vec::new());
    }

    let mut map: HashMap<String, SessionSummary> = HashMap::new();
    let rollout_map = discover_rollout_files(&codex_home.join("sessions"));

    // 1. 只读解析 session_index.jsonl（若存在）
    let index_path = codex_home.join("session_index.jsonl");
    if index_path.is_file() {
        if let Ok(file) = fs::File::open(&index_path) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(raw) = serde_json::from_str::<RawSessionIndexEntry>(trimmed) {
                    if let Some(id) = raw.id.filter(|s| !s.trim().is_empty()) {
                        let rollout_opt = rollout_map.get(&id);
                        let mut sources = vec![index_path.display().to_string()];
                        if let Some(rp) = rollout_opt {
                            sources.push(rp.display().to_string());
                        }
                        map.insert(
                            id.clone(),
                            SessionSummary {
                                session_id: id,
                                target_id: target_id.to_string(),
                                title: redact_secrets(
                                    raw.thread_name.as_deref().unwrap_or("(未命名会话)"),
                                ),
                                cwd: String::new(),
                                updated_at: raw.updated_at.unwrap_or_default(),
                                model: None,
                                rollout_file_exists: rollout_opt.is_some(),
                                source_files: sources,
                            },
                        );
                    }
                }
            }
        }
    }

    // 2. 只读补充 state_5.sqlite 中的 threads 元信息（mode=ro&immutable=1）
    let state_db = codex_home.join("state_5.sqlite");
    if state_db.is_file() {
        enrich_from_state_sqlite(target_id, &state_db, &rollout_map, &mut map);
    }

    // 3. 补充仅存在于 sessions/**/rollout-*.jsonl 中的会话
    for (sid, rpath) in &rollout_map {
        map.entry(sid.clone()).or_insert_with(|| SessionSummary {
            session_id: sid.clone(),
            target_id: target_id.to_string(),
            title: "(Rollout 会话)".to_string(),
            cwd: String::new(),
            updated_at: String::new(),
            model: None,
            rollout_file_exists: true,
            source_files: vec![rpath.display().to_string()],
        });
    }

    let mut list: Vec<SessionSummary> = map.into_values().collect();
    list.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| b.session_id.cmp(&a.session_id))
    });

    let cap = if limit == 0 { 100 } else { limit };
    if list.len() > cap {
        list.truncate(cap);
    }
    Ok(list)
}

/// 只读查询单条 Codex 会话详情。
pub fn get_codex_session_detail(
    target_id: &str,
    codex_home: &Path,
    session_id: &str,
) -> Result<SessionDetail, SessionError> {
    let all = list_codex_sessions(target_id, codex_home, usize::MAX)?;
    let summary = all
        .into_iter()
        .find(|s| s.session_id == session_id || s.session_id.starts_with(session_id))
        .ok_or_else(|| SessionError::NotFound {
            target_id: target_id.to_string(),
            session_id: session_id.to_string(),
        })?;

    let rollout_map = discover_rollout_files(&codex_home.join("sessions"));
    let rollout_path_buf = rollout_map.get(&summary.session_id).cloned();

    let mut rollout_events_count = 0usize;
    let mut redacted_preview = None;

    if let Some(ref rp) = rollout_path_buf {
        if let Ok(f) = fs::File::open(rp) {
            let reader = BufReader::new(f);
            for line in reader.lines().map_while(Result::ok) {
                if !line.trim().is_empty() {
                    rollout_events_count += 1;
                    if redacted_preview.is_none() {
                        if let Ok(v) = serde_json::from_str::<Value>(&line) {
                            let snippet = v.to_string();
                            redacted_preview = Some(redact_secrets(&snippet));
                        }
                    }
                }
            }
        }
    }

    let turns_count = count_turns_in_history_sqlite(
        &codex_home.join("thread_history_1.sqlite"),
        &summary.session_id,
    )
    .unwrap_or(rollout_events_count);

    Ok(SessionDetail {
        summary,
        turns_count,
        rollout_events_count,
        rollout_path: rollout_path_buf.map(|p| p.display().to_string()),
        redacted_preview,
    })
}

/// 对指定会话关联的原始数据文件创建带 SHA-256 校验的快照备份（源目录 100% 只读零修改）。
pub fn backup_codex_session(
    target_id: &str,
    codex_home: &Path,
    session_id: &str,
    backup_store: &BackupStore,
) -> Result<SessionBackupReport, SessionError> {
    let detail = get_codex_session_detail(target_id, codex_home, session_id)?;
    let mut paths_to_backup: Vec<PathBuf> = Vec::new();

    let index_path = codex_home.join("session_index.jsonl");
    if index_path.is_file() {
        paths_to_backup.push(index_path);
    }
    if let Some(ref rp) = detail.rollout_path {
        let p = PathBuf::from(rp);
        if p.is_file() && !paths_to_backup.contains(&p) {
            paths_to_backup.push(p);
        }
    }
    for src in &detail.summary.source_files {
        let p = PathBuf::from(src);
        if p.is_file() && !paths_to_backup.contains(&p) {
            paths_to_backup.push(p);
        }
    }

    let path_refs: Vec<&Path> = paths_to_backup.iter().map(|p| p.as_path()).collect();
    let op = format!("session_backup:{}", detail.summary.session_id);
    let manifest = backup_store.create_backup(target_id, &op, &path_refs)?;
    // 立即执行 SHA-256 完整性闭环校验
    backup_store.verify_backup(&manifest.backup_id)?;

    Ok(SessionBackupReport {
        session_id: detail.summary.session_id,
        target_id: target_id.to_string(),
        backup_manifest: manifest,
        verified: true,
    })
}

fn discover_rollout_files(sessions_dir: &Path) -> HashMap<String, PathBuf> {
    let mut map = HashMap::new();
    if !sessions_dir.is_dir() {
        return map;
    }
    let mut stack = vec![sessions_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    // 兼容标准 Codex rollout-YYYY-MM-DDTHH-MM-SS-<uuid> 格式
                    if let Some(uuid_part) = extract_uuid_suffix(stem) {
                        map.insert(uuid_part, path.clone());
                    }
                    // 兼容迁移生成的 rollout-<session_id>.jsonl
                    if let Some(rest) = stem.strip_prefix("rollout-") {
                        map.insert(rest.to_string(), path);
                    }
                }
            }
        }
    }
    map
}

fn extract_uuid_suffix(stem: &str) -> Option<String> {
    if stem.len() >= 36 {
        let tail = &stem[stem.len() - 36..];
        if tail.chars().filter(|&c| c == '-').count() == 4 {
            return Some(tail.to_string());
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn enrich_from_state_sqlite(
    target_id: &str,
    state_db: &Path,
    rollout_map: &HashMap<String, PathBuf>,
    map: &mut HashMap<String, SessionSummary>,
) {
    let uri = format!("file:{}?mode=ro&immutable=1", state_db.display());
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        | rusqlite::OpenFlags::SQLITE_OPEN_URI
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(conn) = rusqlite::Connection::open_with_flags(&uri, flags) else {
        return;
    };
    let Ok(mut stmt) = conn.prepare(
        "SELECT id, COALESCE(title, name, ''), COALESCE(cwd, ''), COALESCE(updated_at, ''), model, rollout_path FROM threads",
    ) else {
        return;
    };
    let Ok(rows) = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1).unwrap_or_default(),
            r.get::<_, String>(2).unwrap_or_default(),
            r.get::<_, String>(3).unwrap_or_default(),
            r.get::<_, Option<String>>(4).ok().flatten(),
            r.get::<_, Option<String>>(5).ok().flatten(),
        ))
    }) else {
        return;
    };

    for row in rows.flatten() {
        let (id, title, cwd, updated_at, model, db_rollout) = row;
        let entry = map.entry(id.clone()).or_insert_with(|| SessionSummary {
            session_id: id.clone(),
            target_id: target_id.to_string(),
            title: String::new(),
            cwd: String::new(),
            updated_at: String::new(),
            model: None,
            rollout_file_exists: rollout_map.contains_key(&id),
            source_files: Vec::new(),
        });
        if (entry.title.is_empty() || entry.title == "(未命名会话)") && !title.trim().is_empty()
        {
            entry.title = redact_secrets(&title);
        }
        if entry.cwd.is_empty() && !cwd.trim().is_empty() {
            entry.cwd = redact_secrets(&cwd);
        }
        if entry.updated_at.is_empty() && !updated_at.trim().is_empty() {
            entry.updated_at = updated_at;
        }
        if entry.model.is_none() {
            entry.model = model;
        }
        if let Some(rp) = db_rollout {
            if Path::new(&rp).is_file() {
                entry.rollout_file_exists = true;
                if !entry.source_files.contains(&rp) {
                    entry.source_files.push(rp);
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn enrich_from_state_sqlite(
    _target_id: &str,
    _state_db: &Path,
    _rollout_map: &HashMap<String, PathBuf>,
    _map: &mut HashMap<String, SessionSummary>,
) {
}

#[cfg(not(target_os = "windows"))]
fn count_turns_in_history_sqlite(history_db: &Path, session_id: &str) -> Option<usize> {
    if !history_db.is_file() {
        return None;
    }
    let uri = format!("file:{}?mode=ro&immutable=1", history_db.display());
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        | rusqlite::OpenFlags::SQLITE_OPEN_URI
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = rusqlite::Connection::open_with_flags(&uri, flags).ok()?;
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM thread_turns WHERE thread_id = ?1",
            rusqlite::params![session_id],
            |r| r.get(0),
        )
        .ok()?;
    Some(count as usize)
}

#[cfg(target_os = "windows")]
fn count_turns_in_history_sqlite(_history_db: &Path, _session_id: &str) -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_guard_backup::sha256_file;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn test_m5_session_list_show_backup_preserves_100_percent_readonly_hashes_and_mtimes() {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ai-guard-session-test-{}-{seq}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let codex_home = root.join(".codex");
        let sessions_sub = codex_home.join("sessions/2026/11/07");
        fs::create_dir_all(&sessions_sub).unwrap();

        let sid = "01a0f65e-ea5d-7240-be4d-d00a429460b4";
        let index_file = codex_home.join("session_index.jsonl");
        let rollout_file = sessions_sub.join(format!("rollout-2026-11-07T12-00-00-{sid}.jsonl"));

        fs::write(
            &index_file,
            format!(
                "{{\"id\":\"{sid}\",\"thread_name\":\"测试会话 sk-proj-SECRET1234567890\",\"updated_at\":\"2026-11-07T04:00:00Z\"}}\n"
            ),
        )
        .unwrap();
        fs::write(
            &rollout_file,
            "{\"type\":\"session_start\",\"secret\":\"ghp_SECRET999999999999999999\"}\n",
        )
        .unwrap();

        let index_hash_before = sha256_file(&index_file).unwrap();
        let rollout_hash_before = sha256_file(&rollout_file).unwrap();
        let index_mtime_before = fs::metadata(&index_file).unwrap().modified().unwrap();
        let rollout_mtime_before = fs::metadata(&rollout_file).unwrap().modified().unwrap();

        // 1. list_codex_sessions
        let list = list_codex_sessions("wsl2:Ubuntu", &codex_home, 50).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].session_id, sid);
        assert!(!list[0].title.contains("SECRET1234567890"));
        assert!(list[0].rollout_file_exists);

        // 2. get_codex_session_detail
        let detail = get_codex_session_detail("wsl2:Ubuntu", &codex_home, sid).unwrap();
        assert_eq!(detail.rollout_events_count, 1);
        assert!(!detail
            .redacted_preview
            .as_deref()
            .unwrap_or("")
            .contains("ghp_SECRET999999"));

        // 3. backup_codex_session
        let backup_store = BackupStore::new(root.join("backups"));
        let backup_rep =
            backup_codex_session("wsl2:Ubuntu", &codex_home, sid, &backup_store).unwrap();
        assert!(backup_rep.verified);
        assert!(backup_rep.backup_manifest.files.len() >= 2);

        // 4. 校验源会话文件的 SHA-256 与 mtime 100% 未改变！
        assert_eq!(sha256_file(&index_file).unwrap(), index_hash_before);
        assert_eq!(sha256_file(&rollout_file).unwrap(), rollout_hash_before);
        assert_eq!(
            fs::metadata(&index_file).unwrap().modified().unwrap(),
            index_mtime_before
        );
        assert_eq!(
            fs::metadata(&rollout_file).unwrap().modified().unwrap(),
            rollout_mtime_before
        );

        let _ = fs::remove_dir_all(&root);
    }
}
