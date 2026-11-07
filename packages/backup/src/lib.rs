//! AI Guard (`packages/backup`) — 配置与会话 SHA-256 事务备份、完整性校验与原子恢复模块。
//!
//! 满足 `AGENTS.md` §4.2 与 §5.3 强制要求：
//! 1. 任何修改、清理或覆盖用户配置（如 `.codex/config.toml`）的操作，必须先创建快照备份并生成 `manifest.json`。
//! 2. 恢复前强制重算备份文件 SHA-256 并与 `manifest.json` 比对；若备份损坏或被篡改，立即拒绝恢复（Fail-Closed）。
//! 3. 所有文件落盘均采用“同目录临时文件写入 -> `sync_all (fsync)` -> 原子 `rename`”流程，杜绝半写入损坏。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

static BACKUP_SEQ: AtomicU64 = AtomicU64::new(1);

/// 备份与恢复错误类型。
#[derive(Debug, Error)]
pub enum BackupError {
    #[error("[AG-BACKUP-IO] 文件 I/O 错误 ({path}): {detail}")]
    Io { path: String, detail: String },

    #[error("[AG-BACKUP-MANIFEST] 解析或序列化 manifest.json 失败 ({path}): {detail}")]
    ManifestFormat { path: String, detail: String },

    #[error("[AG-BACKUP-NOT-FOUND] 找不到指定的备份记录 `{backup_id}`")]
    NotFound { backup_id: String },

    #[error("[AG-BACKUP-HASH-MISMATCH] 备份完整性校验失败（拒绝恢复）：文件 `{file}` 期望 SHA-256 为 {expected}，实际为 {actual}")]
    IntegrityMismatch {
        file: String,
        expected: String,
        actual: String,
    },
}

impl BackupError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "AG-BACKUP-IO",
            Self::ManifestFormat { .. } => "AG-BACKUP-MANIFEST",
            Self::NotFound { .. } => "AG-BACKUP-NOT-FOUND",
            Self::IntegrityMismatch { .. } => "AG-BACKUP-HASH-MISMATCH",
        }
    }
}

/// 计算字节切片的 SHA-256 十六进制摘要。
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// 计算磁盘文件的 SHA-256 十六进制摘要。
pub fn sha256_file(path: &Path) -> Result<String, BackupError> {
    let bytes = fs::read(path).map_err(|e| BackupError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    Ok(sha256_hex(&bytes))
}

/// 同目录临时文件写入 -> `sync_all` -> 原子替换目标文件。
pub fn atomic_write_file(dest: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| BackupError::Io {
        path: parent.display().to_string(),
        detail: format!("创建父目录失败: {e}"),
    })?;

    let file_name = dest
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("target");
    let seq = BACKUP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let tmp_path = parent.join(format!(".{file_name}.ai-guard-tmp-{pid}-{seq}"));

    {
        let mut f = File::create(&tmp_path).map_err(|e| BackupError::Io {
            path: tmp_path.display().to_string(),
            detail: format!("创建临时文件失败: {e}"),
        })?;
        if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
            let _ = fs::remove_file(&tmp_path);
            return Err(BackupError::Io {
                path: tmp_path.display().to_string(),
                detail: format!("写入或 fsync 临时文件失败: {e}"),
            });
        }
    }

    if let Err(e) = fs::rename(&tmp_path, dest) {
        let _ = fs::remove_file(&tmp_path);
        return Err(BackupError::Io {
            path: dest.display().to_string(),
            detail: format!("原子替换文件失败: {e}"),
        });
    }

    Ok(())
}

/// 兼容旧引用的轻量记录结构。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRecord {
    pub backup_id: String,
    pub target_id: String,
    pub source_path: String,
    pub sha256: String,
}

/// 单个被备份文件的元数据条目。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFileEntry {
    /// 备份目录内的快照文件名（如 `file_0_config.toml`）
    pub snapshot_file_name: String,
    /// 原始文件的绝对路径
    pub original_path: String,
    /// 备份时原始文件是否已存在（若为 false，恢复时将清理新创建的文件）
    pub existed_before: bool,
    /// 原始文件字节大小
    pub size_bytes: u64,
    /// 原始文件 SHA-256（当 `existed_before == false` 时为空字符串）
    pub sha256: String,
    /// 操作完成后的目标文件 SHA-256（用于卸载时检测外部冲突修改）
    pub post_operation_sha256: Option<String>,
}

/// 每次事务备份生成的 `manifest.json` 完整清单。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    pub schema_version: u32,
    pub backup_id: String,
    pub target_id: String,
    pub operation: String,
    pub created_at_epoch_ms: u64,
    pub files: Vec<BackupFileEntry>,
}

/// 跨平台快照备份管理器。
#[derive(Debug, Clone)]
pub struct BackupStore {
    root_dir: PathBuf,
}

impl BackupStore {
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: root_dir.into(),
        }
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn backup_dir(&self, backup_id: &str) -> PathBuf {
        self.root_dir.join(backup_id)
    }

    pub fn manifest_path(&self, backup_id: &str) -> PathBuf {
        self.backup_dir(backup_id).join("manifest.json")
    }

    /// 为一组目标路径创建带 SHA-256 清单的事务快照备份。
    pub fn create_backup(
        &self,
        target_id: &str,
        operation: &str,
        source_paths: &[&Path],
    ) -> Result<BackupManifest, BackupError> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let seq = BACKUP_SEQ.fetch_add(1, Ordering::Relaxed);
        let backup_id = format!("bk-{now_ms}-{seq}");
        let bdir = self.backup_dir(&backup_id);

        fs::create_dir_all(&bdir).map_err(|e| BackupError::Io {
            path: bdir.display().to_string(),
            detail: format!("创建备份目录失败: {e}"),
        })?;

        let mut files = Vec::with_capacity(source_paths.len());
        for (idx, src) in source_paths.iter().enumerate() {
            let base_name = src
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("file")
                .replace(['/', '\\', ':'], "_");
            let snapshot_file_name = format!("file_{idx}_{base_name}");
            let snapshot_path = bdir.join(&snapshot_file_name);

            if src.exists() {
                let bytes = fs::read(src).map_err(|e| BackupError::Io {
                    path: src.display().to_string(),
                    detail: format!("读取待备份源文件失败: {e}"),
                })?;
                let hash = sha256_hex(&bytes);
                atomic_write_file(&snapshot_path, &bytes)?;
                files.push(BackupFileEntry {
                    snapshot_file_name,
                    original_path: src.display().to_string(),
                    existed_before: true,
                    size_bytes: bytes.len() as u64,
                    sha256: hash,
                    post_operation_sha256: None,
                });
            } else {
                files.push(BackupFileEntry {
                    snapshot_file_name,
                    original_path: src.display().to_string(),
                    existed_before: false,
                    size_bytes: 0,
                    sha256: String::new(),
                    post_operation_sha256: None,
                });
            }
        }

        let manifest = BackupManifest {
            schema_version: 1,
            backup_id: backup_id.clone(),
            target_id: target_id.to_string(),
            operation: operation.to_string(),
            created_at_epoch_ms: now_ms,
            files,
        };

        self.save_manifest(&manifest)?;
        Ok(manifest)
    }

    /// 记录操作完成后的文件哈希（供后续卸载冲突检测使用）。
    pub fn record_post_operation_hashes(
        &self,
        backup_id: &str,
    ) -> Result<BackupManifest, BackupError> {
        let mut manifest = self.load_manifest(backup_id)?;
        for entry in &mut manifest.files {
            let p = Path::new(&entry.original_path);
            if p.is_file() {
                entry.post_operation_sha256 = Some(sha256_file(p)?);
            }
        }
        self.save_manifest(&manifest)?;
        Ok(manifest)
    }

    /// 读取指定 `backup_id` 的 `manifest.json`。
    pub fn load_manifest(&self, backup_id: &str) -> Result<BackupManifest, BackupError> {
        let mpath = self.manifest_path(backup_id);
        if !mpath.is_file() {
            return Err(BackupError::NotFound {
                backup_id: backup_id.to_string(),
            });
        }
        let content = fs::read_to_string(&mpath).map_err(|e| BackupError::Io {
            path: mpath.display().to_string(),
            detail: e.to_string(),
        })?;
        serde_json::from_str(&content).map_err(|e| BackupError::ManifestFormat {
            path: mpath.display().to_string(),
            detail: e.to_string(),
        })
    }

    fn save_manifest(&self, manifest: &BackupManifest) -> Result<(), BackupError> {
        let mpath = self.manifest_path(&manifest.backup_id);
        let json_bytes =
            serde_json::to_vec_pretty(manifest).map_err(|e| BackupError::ManifestFormat {
                path: mpath.display().to_string(),
                detail: e.to_string(),
            })?;
        atomic_write_file(&mpath, &json_bytes)
    }

    /// 严格校验指定备份的所有快照文件大小与 SHA-256 是否与 `manifest.json` 100% 一致。
    pub fn verify_backup(&self, backup_id: &str) -> Result<BackupManifest, BackupError> {
        let manifest = self.load_manifest(backup_id)?;
        let bdir = self.backup_dir(backup_id);

        for entry in &manifest.files {
            if !entry.existed_before {
                continue;
            }
            let snap_path = bdir.join(&entry.snapshot_file_name);
            let bytes = fs::read(&snap_path).map_err(|e| BackupError::Io {
                path: snap_path.display().to_string(),
                detail: format!("备份快照文件缺失或无法读取: {e}"),
            })?;
            let actual_hash = sha256_hex(&bytes);
            if actual_hash != entry.sha256 || (bytes.len() as u64) != entry.size_bytes {
                return Err(BackupError::IntegrityMismatch {
                    file: snap_path.display().to_string(),
                    expected: entry.sha256.clone(),
                    actual: actual_hash,
                });
            }
        }

        Ok(manifest)
    }

    /// 验证备份完整性并原子恢复所有文件至原始路径。
    /// 若任何一个快照文件 SHA-256 不匹配，拒绝恢复且绝不触碰任何目标文件。
    pub fn restore_backup(&self, backup_id: &str) -> Result<BackupManifest, BackupError> {
        let manifest = self.verify_backup(backup_id)?;
        let bdir = self.backup_dir(backup_id);

        for entry in &manifest.files {
            let dest = Path::new(&entry.original_path);
            if entry.existed_before {
                let snap_path = bdir.join(&entry.snapshot_file_name);
                let bytes = fs::read(&snap_path).map_err(|e| BackupError::Io {
                    path: snap_path.display().to_string(),
                    detail: e.to_string(),
                })?;
                atomic_write_file(dest, &bytes)?;
                let restored_hash = sha256_file(dest)?;
                if restored_hash != entry.sha256 {
                    return Err(BackupError::IntegrityMismatch {
                        file: dest.display().to_string(),
                        expected: entry.sha256.clone(),
                        actual: restored_hash,
                    });
                }
            } else if dest.exists() {
                fs::remove_file(dest).map_err(|e| BackupError::Io {
                    path: dest.display().to_string(),
                    detail: format!("回滚移除新增文件失败: {e}"),
                })?;
            }
        }

        Ok(manifest)
    }

    /// 列出备份记录（按创建时间降序排列，可选按 `target_id` 过滤）。
    pub fn list_backups(
        &self,
        target_filter: Option<&str>,
    ) -> Result<Vec<BackupManifest>, BackupError> {
        if !self.root_dir.exists() {
            return Ok(Vec::new());
        }
        let mut manifests = Vec::new();
        let entries = fs::read_dir(&self.root_dir).map_err(|e| BackupError::Io {
            path: self.root_dir.display().to_string(),
            detail: e.to_string(),
        })?;
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let bid = entry.file_name().to_string_lossy().into_owned();
            if let Ok(m) = self.load_manifest(&bid) {
                if let Some(filter) = target_filter {
                    if filter != "all" && !m.target_id.eq_ignore_ascii_case(filter) {
                        continue;
                    }
                }
                manifests.push(m);
            }
        }
        manifests.sort_by(|a, b| {
            b.created_at_epoch_ms
                .cmp(&a.created_at_epoch_ms)
                .then_with(|| b.backup_id.cmp(&a.backup_id))
        });
        Ok(manifests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_verify_tamper_reject_and_restore_closed_loop() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "ai-guard-backup-test-{}",
            BACKUP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        let store = BackupStore::new(tmp_dir.join("backups"));
        let config_file = tmp_dir.join("config.toml");
        let new_file = tmp_dir.join("created_later.json");

        let original_content = b"model = \"gpt-5.4\"\n# user comment\n";
        atomic_write_file(&config_file, original_content).unwrap();
        let original_hash = sha256_file(&config_file).unwrap();

        // 1. 创建备份（含已存在的 config.toml 与尚不存在的 created_later.json）
        let manifest = store
            .create_backup(
                "wsl2:Ubuntu",
                "install_codex_hook",
                &[config_file.as_path(), new_file.as_path()],
            )
            .expect("create backup must succeed");

        assert_eq!(manifest.files.len(), 2);
        assert!(manifest.files[0].existed_before);
        assert_eq!(manifest.files[0].sha256, original_hash);
        assert!(!manifest.files[1].existed_before);

        // 2. 校验完整备份通过
        store
            .verify_backup(&manifest.backup_id)
            .expect("verify untampered backup must pass");

        // 3. 模拟安装修改了 config.toml 并新增了 created_later.json
        atomic_write_file(&config_file, b"model = \"gpt-5.4\"\n[hooks]\n").unwrap();
        atomic_write_file(&new_file, b"{\"hook\":true}").unwrap();
        let modified_hash = sha256_file(&config_file).unwrap();
        assert_ne!(modified_hash, original_hash);

        // 4. 模拟备份快照文件被篡改/损坏 -> 必须拒绝恢复且保持当前磁盘文件不变
        let snap_file = store
            .backup_dir(&manifest.backup_id)
            .join(&manifest.files[0].snapshot_file_name);
        atomic_write_file(&snap_file, b"corrupted snapshot bytes").unwrap();

        let err = store
            .restore_backup(&manifest.backup_id)
            .expect_err("tampered backup MUST be rejected");
        assert_eq!(err.code(), "AG-BACKUP-HASH-MISMATCH");
        assert_eq!(
            sha256_file(&config_file).unwrap(),
            modified_hash,
            "Target file must not be modified when backup verification fails"
        );
        assert!(new_file.exists());

        // 5. 修复快照回原始字节 -> 恢复成功 -> config.toml 哈希 100% 还原，created_later.json 被移除
        atomic_write_file(&snap_file, original_content).unwrap();
        store
            .restore_backup(&manifest.backup_id)
            .expect("valid backup must restore cleanly");

        assert_eq!(sha256_file(&config_file).unwrap(), original_hash);
        assert!(
            !new_file.exists(),
            "File that did not exist before backup must be removed upon restore"
        );

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
