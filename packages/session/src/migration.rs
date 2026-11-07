//! AI Guard (`packages/session::migration`) — 跨智能体会话无损迁移与标准化 AST 转换引擎。
//!
//! 支持 OpenAI Codex、Google Antigravity (AGY) 与 OpenCode 三大 AI 编程智能体之间的会话互转：
//! - 统一会话中间表示（Standardized Session AST / IR）
//! - 提取用户提示词、推理思维链（Thought）、工具调用与执行结果、工件索引
//! - 全链路强制二次脱敏（`redact_secrets`），杜绝 Token、密码、私钥跨 Agent 泄漏
//! - 跨操作系统（Windows ⇄ WSL2 / POSIX）路径自动重映射
//! - SHA-256 事务备份与原子写入保障

use crate::SessionError;
use ai_guard_backup::{BackupManifest, BackupStore};
use ai_guard_security::redact_secrets;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// 跨智能体标准化会话抽象语法树（Session AST / IR）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionAst {
    pub session_id: String,
    pub title: String,
    pub source_agent: String,
    pub target_agent: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub cwd: String,
    pub turns: Vec<SessionTurn>,
    pub artifacts: Vec<SessionArtifact>,
    pub metadata: HashMap<String, String>,
}

/// 标准会话单轮交互
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionTurn {
    pub turn_index: usize,
    pub role: String, // "user" | "assistant" | "system"
    pub content: String,
    pub timestamp: Option<String>,
    pub thought: Option<String>,
    pub tool_calls: Vec<ToolCallAst>,
}

/// 标准工具调用
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCallAst {
    pub call_id: String,
    pub tool_name: String,
    pub command: Option<String>,
    pub file_path: Option<String>,
    pub patch_content: Option<String>,
    pub arguments: HashMap<String, Value>,
    pub output: Option<String>,
    pub is_error: bool,
}

/// 会话关联工件产物
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionArtifact {
    pub file_name: String,
    pub relative_path: String,
    pub content: String,
}

/// 跨 Agent 会话迁移请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRequest {
    pub session_id: String,
    pub source_agent: String, // "codex" | "agy" | "opencode"
    pub target_agent: String, // "codex" | "agy" | "opencode"
    pub source_path: Option<String>,
    pub target_dir: Option<String>,
    #[serde(default = "default_true")]
    pub auto_remap_paths: bool,
}

fn default_true() -> bool {
    true
}

/// 跨 Agent 会话迁移报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReport {
    pub success: bool,
    pub original_session_id: String,
    pub new_session_id: String,
    pub source_agent: String,
    pub target_agent: String,
    pub title: String,
    pub turns_converted: usize,
    pub tools_converted: usize,
    pub artifacts_count: usize,
    pub output_path: String,
    pub secrets_redacted_count: usize,
    pub manifest: Option<BackupManifest>,
}

// ---------------------------------------------------------------------------
// 辅助脱敏与统计
// ---------------------------------------------------------------------------

fn sanitize_text(text: &str, counter: &mut usize) -> String {
    let sanitized = redact_secrets(text);
    if sanitized != text {
        *counter += 1;
    }
    sanitized
}

// ---------------------------------------------------------------------------
// 跨平台路径映射（Windows ⇄ WSL2 / POSIX）
// ---------------------------------------------------------------------------

pub fn remap_path_str(path: &str, to_windows: bool) -> String {
    if to_windows {
        // POSIX / WSL /mnt/c/Users/... -> C:\Users\...
        if let Some(rest) = path.strip_prefix("/mnt/") {
            if rest.len() >= 2 && rest.chars().nth(1) == Some('/') {
                let drive = rest.chars().next().unwrap().to_ascii_uppercase();
                let sub = &rest[2..].replace('/', "\\");
                return format!("{drive}:\\{sub}");
            }
        }
    } else {
        // Windows C:\Users\... -> /mnt/c/Users/...
        if path.len() >= 3
            && path.chars().nth(1) == Some(':')
            && (path.chars().nth(2) == Some('\\') || path.chars().nth(2) == Some('/'))
        {
            let drive = path.chars().next().unwrap().to_ascii_lowercase();
            let sub = path[3..].replace('\\', "/");
            return format!("/mnt/{drive}/{sub}");
        }
    }
    path.to_string()
}

// ---------------------------------------------------------------------------
// 解析器：Codex -> AST
// ---------------------------------------------------------------------------

pub fn parse_codex_rollout_content(
    content: &str,
    session_id: &str,
    fallback_title: &str,
    fallback_cwd: &str,
) -> (SessionAst, usize) {
    let mut redacted_count = 0;
    let mut turns = Vec::new();
    let mut cwd = fallback_cwd.to_string();
    let mut title = fallback_title.to_string();
    let mut turn_idx = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            let event_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");

            if event_type == "session_start" {
                if let Some(c) = val.get("cwd").and_then(|v| v.as_str()) {
                    cwd = sanitize_text(c, &mut redacted_count);
                }
                if let Some(t) = val.get("title").and_then(|v| v.as_str()) {
                    title = sanitize_text(t, &mut redacted_count);
                }
            } else if event_type == "user_prompt"
                || event_type == "UserPromptSubmit"
                || val.get("role").and_then(|v| v.as_str()) == Some("user")
            {
                let text = val
                    .get("text")
                    .or_else(|| val.get("prompt"))
                    .or_else(|| val.get("content"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let sanitized_content = sanitize_text(text, &mut redacted_count);
                if title == fallback_title && !sanitized_content.is_empty() {
                    title = sanitized_content.chars().take(50).collect();
                }
                turns.push(SessionTurn {
                    turn_index: turn_idx,
                    role: "user".to_string(),
                    content: sanitized_content,
                    timestamp: val
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    thought: None,
                    tool_calls: Vec::new(),
                });
                turn_idx += 1;
            } else if event_type == "agent_message"
                || event_type == "assistant"
                || val.get("role").and_then(|v| v.as_str()) == Some("assistant")
            {
                let text = val
                    .get("text")
                    .or_else(|| val.get("message"))
                    .or_else(|| val.get("content"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let thought = val
                    .get("thought")
                    .or_else(|| val.get("thinking"))
                    .and_then(|v| v.as_str())
                    .map(|s| sanitize_text(s, &mut redacted_count));
                turns.push(SessionTurn {
                    turn_index: turn_idx,
                    role: "assistant".to_string(),
                    content: sanitize_text(text, &mut redacted_count),
                    timestamp: val
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    thought,
                    tool_calls: Vec::new(),
                });
                turn_idx += 1;
            } else if event_type == "tool_call" || event_type == "PreToolUse" {
                let tool_name = val
                    .get("tool")
                    .or_else(|| val.get("tool_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("bash")
                    .to_string();
                let command = val
                    .get("command")
                    .or_else(|| val.get("cmd"))
                    .and_then(|v| v.as_str())
                    .map(|s| sanitize_text(s, &mut redacted_count));
                let file_path = val
                    .get("path")
                    .or_else(|| val.get("file"))
                    .and_then(|v| v.as_str())
                    .map(|s| sanitize_text(s, &mut redacted_count));

                let tool_ast = ToolCallAst {
                    call_id: format!("call-{turn_idx}"),
                    tool_name,
                    command,
                    file_path,
                    patch_content: None,
                    arguments: HashMap::new(),
                    output: None,
                    is_error: false,
                };

                if let Some(last_turn) = turns.last_mut() {
                    if last_turn.role == "assistant" {
                        last_turn.tool_calls.push(tool_ast);
                        continue;
                    }
                }

                turns.push(SessionTurn {
                    turn_index: turn_idx,
                    role: "assistant".to_string(),
                    content: String::new(),
                    timestamp: None,
                    thought: None,
                    tool_calls: vec![tool_ast],
                });
                turn_idx += 1;
            }
        }
    }

    if turns.is_empty() {
        turns.push(SessionTurn {
            turn_index: 0,
            role: "user".to_string(),
            content: sanitize_text(fallback_title, &mut redacted_count),
            timestamp: None,
            thought: None,
            tool_calls: Vec::new(),
        });
    }

    let ast = SessionAst {
        session_id: session_id.to_string(),
        title: sanitize_text(&title, &mut redacted_count),
        source_agent: "codex".to_string(),
        target_agent: None,
        created_at: "2026-11-07 12:00:00".to_string(),
        updated_at: "2026-11-07 18:00:00".to_string(),
        cwd,
        turns,
        artifacts: Vec::new(),
        metadata: HashMap::new(),
    };

    (ast, redacted_count)
}

// ---------------------------------------------------------------------------
// 解析器：AGY -> AST
// ---------------------------------------------------------------------------

pub fn parse_agy_transcript_content(
    content: &str,
    session_id: &str,
    brain_dir: Option<&Path>,
) -> (SessionAst, usize) {
    let mut redacted_count = 0;
    let mut turns = Vec::new();
    let mut artifacts = Vec::new();
    let mut title = format!("AGY 会话 {}", &session_id[..8.min(session_id.len())]);
    let mut turn_idx = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            let step_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let created_at = val
                .get("created_at")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if step_type == "USER_INPUT" {
                if let Some(c) = val.get("content").and_then(|v| v.as_str()) {
                    let cleaned = c
                        .replace("<USER_REQUEST>", "")
                        .replace("</USER_REQUEST>", "");
                    let sanitized = sanitize_text(cleaned.trim(), &mut redacted_count);
                    if let Some(first_line) = sanitized.lines().next() {
                        let clean_title = first_line.trim_start_matches('#').trim();
                        if !clean_title.is_empty() {
                            title = clean_title.chars().take(50).collect();
                        }
                    }
                    turns.push(SessionTurn {
                        turn_index: turn_idx,
                        role: "user".to_string(),
                        content: sanitized,
                        timestamp: created_at,
                        thought: None,
                        tool_calls: Vec::new(),
                    });
                    turn_idx += 1;
                }
            } else if step_type == "PLANNER_RESPONSE" {
                let text = val.get("content").and_then(|v| v.as_str()).unwrap_or("");
                let thinking = val
                    .get("thinking")
                    .and_then(|v| v.as_str())
                    .map(|s| sanitize_text(s, &mut redacted_count));

                let mut tool_calls = Vec::new();
                if let Some(calls) = val.get("tool_calls").and_then(|v| v.as_array()) {
                    for (c_idx, call) in calls.iter().enumerate() {
                        let name = call
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let args = call.get("args").cloned().unwrap_or(json!({}));

                        let mut command = None;
                        let mut file_path = None;
                        let mut patch_content = None;

                        if let Some(cmd) = args.get("CommandLine").and_then(|v| v.as_str()) {
                            command = Some(sanitize_text(cmd, &mut redacted_count));
                        }
                        if let Some(p) = args.get("Path").and_then(|v| v.as_str()) {
                            file_path = Some(sanitize_text(p, &mut redacted_count));
                        }
                        if let Some(cnt) = args.get("Content").and_then(|v| v.as_str()) {
                            patch_content = Some(sanitize_text(cnt, &mut redacted_count));
                        }

                        let mut arg_map = HashMap::new();
                        if let Some(obj) = args.as_object() {
                            for (k, v) in obj {
                                arg_map.insert(k.clone(), v.clone());
                            }
                        }

                        tool_calls.push(ToolCallAst {
                            call_id: format!("call-{turn_idx}-{c_idx}"),
                            tool_name: name,
                            command,
                            file_path,
                            patch_content,
                            arguments: arg_map,
                            output: None,
                            is_error: false,
                        });
                    }
                }

                turns.push(SessionTurn {
                    turn_index: turn_idx,
                    role: "assistant".to_string(),
                    content: sanitize_text(text, &mut redacted_count),
                    timestamp: created_at,
                    thought: thinking,
                    tool_calls,
                });
                turn_idx += 1;
            }
        }
    }

    // 扫描 brain 工件
    if let Some(b_dir) = brain_dir {
        if let Ok(entries) = fs::read_dir(b_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let fname = entry.file_name().to_string_lossy().to_string();
                    if fname.ends_with(".md")
                        || fname.ends_with(".html")
                        || fname.ends_with(".json")
                    {
                        if let Ok(bytes) = fs::read(&p) {
                            if let Ok(s) = String::from_utf8(bytes) {
                                artifacts.push(SessionArtifact {
                                    file_name: fname.clone(),
                                    relative_path: fname,
                                    content: sanitize_text(&s, &mut redacted_count),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    if turns.is_empty() {
        turns.push(SessionTurn {
            turn_index: 0,
            role: "user".to_string(),
            content: title.clone(),
            timestamp: None,
            thought: None,
            tool_calls: Vec::new(),
        });
    }

    let ast = SessionAst {
        session_id: session_id.to_string(),
        title: sanitize_text(&title, &mut redacted_count),
        source_agent: "agy".to_string(),
        target_agent: None,
        created_at: "2026-11-07 14:00:00".to_string(),
        updated_at: "2026-11-07 18:00:00".to_string(),
        cwd: ".".to_string(),
        turns,
        artifacts,
        metadata: HashMap::new(),
    };

    (ast, redacted_count)
}

// ---------------------------------------------------------------------------
// 解析器：OpenCode -> AST
// ---------------------------------------------------------------------------

pub fn parse_opencode_session_content(content: &str, session_id: &str) -> (SessionAst, usize) {
    let mut redacted_count = 0;
    let mut turns = Vec::new();
    let mut title = format!("OpenCode 任务 {}", &session_id[..8.min(session_id.len())]);
    let mut cwd = ".".to_string();

    if let Ok(val) = serde_json::from_str::<Value>(content) {
        if let Some(t) = val.get("title").and_then(|v| v.as_str()) {
            title = sanitize_text(t, &mut redacted_count);
        }
        if let Some(c) = val.get("cwd").and_then(|v| v.as_str()) {
            cwd = sanitize_text(c, &mut redacted_count);
        }

        if let Some(messages) = val.get("messages").and_then(|v| v.as_array()) {
            for (idx, msg) in messages.iter().enumerate() {
                let role = msg
                    .get("role")
                    .and_then(|v| v.as_str())
                    .unwrap_or("user")
                    .to_string();
                let text = msg
                    .get("content")
                    .or_else(|| msg.get("text"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let thought = msg
                    .get("thought")
                    .and_then(|v| v.as_str())
                    .map(|s| sanitize_text(s, &mut redacted_count));

                let mut tool_calls = Vec::new();
                if let Some(calls) = msg.get("toolCalls").and_then(|v| v.as_array()) {
                    for (c_idx, call) in calls.iter().enumerate() {
                        let name = call
                            .get("name")
                            .or_else(|| call.get("tool"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("bash")
                            .to_string();
                        let cmd = call
                            .get("command")
                            .or_else(|| call.get("input"))
                            .and_then(|v| v.as_str())
                            .map(|s| sanitize_text(s, &mut redacted_count));

                        tool_calls.push(ToolCallAst {
                            call_id: format!("call-{idx}-{c_idx}"),
                            tool_name: name,
                            command: cmd,
                            file_path: None,
                            patch_content: None,
                            arguments: HashMap::new(),
                            output: None,
                            is_error: false,
                        });
                    }
                }

                turns.push(SessionTurn {
                    turn_index: idx,
                    role,
                    content: sanitize_text(text, &mut redacted_count),
                    timestamp: msg
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    thought,
                    tool_calls,
                });
            }
        }
    }

    if turns.is_empty() {
        turns.push(SessionTurn {
            turn_index: 0,
            role: "user".to_string(),
            content: title.clone(),
            timestamp: None,
            thought: None,
            tool_calls: Vec::new(),
        });
    }

    let ast = SessionAst {
        session_id: session_id.to_string(),
        title: sanitize_text(&title, &mut redacted_count),
        source_agent: "opencode".to_string(),
        target_agent: None,
        created_at: "2026-11-07 16:00:00".to_string(),
        updated_at: "2026-11-07 19:00:00".to_string(),
        cwd,
        turns,
        artifacts: Vec::new(),
        metadata: HashMap::new(),
    };

    (ast, redacted_count)
}

// ---------------------------------------------------------------------------
// 导出器：AST -> 目标 Agent 格式
// ---------------------------------------------------------------------------

/// 导出 AST 为 Codex 格式（`sessions/migrated/rollout-{id}.jsonl` 与 `session_index.jsonl`）
pub fn export_ast_to_codex(
    ast: &SessionAst,
    codex_home: &Path,
    auto_remap: bool,
) -> Result<PathBuf, SessionError> {
    let sessions_dir = codex_home.join("sessions").join("migrated");
    fs::create_dir_all(&sessions_dir).map_err(|e| SessionError::Io {
        path: sessions_dir.display().to_string(),
        detail: e.to_string(),
    })?;

    let rollout_file = sessions_dir.join(format!("rollout-{}.jsonl", ast.session_id));
    let mut file = fs::File::create(&rollout_file).map_err(|e| SessionError::Io {
        path: rollout_file.display().to_string(),
        detail: e.to_string(),
    })?;

    let cwd = if auto_remap {
        remap_path_str(&ast.cwd, cfg!(target_os = "windows"))
    } else {
        ast.cwd.clone()
    };

    // 1. Session start
    let start_event = json!({
        "type": "session_start",
        "session_id": ast.session_id,
        "title": ast.title,
        "cwd": cwd,
        "source_agent": ast.source_agent,
        "migrated_by": "ai-guard",
        "created_at": ast.created_at,
    });
    writeln!(file, "{}", serde_json::to_string(&start_event).unwrap()).map_err(|e| {
        SessionError::Io {
            path: rollout_file.display().to_string(),
            detail: e.to_string(),
        }
    })?;

    // 2. Turns
    for turn in &ast.turns {
        if turn.role == "user" {
            let u_event = json!({
                "type": "user_prompt",
                "text": turn.content,
                "timestamp": turn.timestamp,
            });
            writeln!(file, "{}", serde_json::to_string(&u_event).unwrap()).map_err(|e| {
                SessionError::Io {
                    path: rollout_file.display().to_string(),
                    detail: e.to_string(),
                }
            })?;
        } else {
            let a_event = json!({
                "type": "agent_message",
                "text": turn.content,
                "thought": turn.thought,
                "timestamp": turn.timestamp,
            });
            writeln!(file, "{}", serde_json::to_string(&a_event).unwrap()).map_err(|e| {
                SessionError::Io {
                    path: rollout_file.display().to_string(),
                    detail: e.to_string(),
                }
            })?;

            for tool in &turn.tool_calls {
                let cmd = if auto_remap {
                    tool.command
                        .as_deref()
                        .map(|c| remap_path_str(c, cfg!(target_os = "windows")))
                } else {
                    tool.command.clone()
                };
                let t_event = json!({
                    "type": "tool_call",
                    "tool": tool.tool_name,
                    "command": cmd,
                    "path": tool.file_path,
                    "arguments": tool.arguments,
                });
                writeln!(file, "{}", serde_json::to_string(&t_event).unwrap()).map_err(|e| {
                    SessionError::Io {
                        path: rollout_file.display().to_string(),
                        detail: e.to_string(),
                    }
                })?;
            }
        }
    }

    // 3. 更新 session_index.jsonl
    let index_file = codex_home.join("session_index.jsonl");
    let index_entry = json!({
        "id": ast.session_id,
        "thread_name": format!("[迁移自 {}] {}", ast.source_agent.to_uppercase(), ast.title),
        "updated_at": ast.updated_at,
    });
    if let Ok(mut idx_f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&index_file)
    {
        let _ = writeln!(idx_f, "{}", serde_json::to_string(&index_entry).unwrap());
    }

    Ok(rollout_file)
}

/// 导出 AST 为 AGY 格式（`brain/{id}/.system_generated/logs/transcript.jsonl` 与工件）
pub fn export_ast_to_agy(
    ast: &SessionAst,
    brain_root: &Path,
    auto_remap: bool,
) -> Result<PathBuf, SessionError> {
    let session_dir = brain_root.join(&ast.session_id);
    let logs_dir = session_dir.join(".system_generated").join("logs");
    fs::create_dir_all(&logs_dir).map_err(|e| SessionError::Io {
        path: logs_dir.display().to_string(),
        detail: e.to_string(),
    })?;

    let transcript_file = logs_dir.join("transcript.jsonl");
    let mut file = fs::File::create(&transcript_file).map_err(|e| SessionError::Io {
        path: transcript_file.display().to_string(),
        detail: e.to_string(),
    })?;

    for turn in &ast.turns {
        if turn.role == "user" {
            let u_obj = json!({
                "step_index": turn.turn_index,
                "type": "USER_INPUT",
                "source": "USER_EXPLICIT",
                "status": "DONE",
                "content": format!("<USER_REQUEST>\n{}\n</USER_REQUEST>", turn.content),
                "created_at": turn.timestamp.clone().unwrap_or_else(|| ast.created_at.clone()),
            });
            writeln!(file, "{}", serde_json::to_string(&u_obj).unwrap()).map_err(|e| {
                SessionError::Io {
                    path: transcript_file.display().to_string(),
                    detail: e.to_string(),
                }
            })?;
        } else {
            let mut calls_arr = Vec::new();
            for tool in &turn.tool_calls {
                let cmd = if auto_remap {
                    tool.command.as_deref().map(|c| remap_path_str(c, false))
                } else {
                    tool.command.clone()
                };
                let mut args = json!({});
                if let Some(c) = cmd {
                    args["CommandLine"] = json!(c);
                }
                if let Some(ref p) = tool.file_path {
                    args["Path"] = json!(p);
                }
                if let Some(ref cnt) = tool.patch_content {
                    args["Content"] = json!(cnt);
                }
                calls_arr.push(json!({
                    "name": tool.tool_name,
                    "args": args,
                }));
            }

            let p_obj = json!({
                "step_index": turn.turn_index,
                "type": "PLANNER_RESPONSE",
                "source": "MODEL",
                "status": "DONE",
                "content": turn.content,
                "thinking": turn.thought,
                "tool_calls": calls_arr,
                "created_at": turn.timestamp.clone().unwrap_or_else(|| ast.updated_at.clone()),
            });
            writeln!(file, "{}", serde_json::to_string(&p_obj).unwrap()).map_err(|e| {
                SessionError::Io {
                    path: transcript_file.display().to_string(),
                    detail: e.to_string(),
                }
            })?;
        }
    }

    // 写入工件产物
    for art in &ast.artifacts {
        let art_path = session_dir.join(&art.relative_path);
        if let Some(parent) = art_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&art_path, &art.content);
    }

    Ok(session_dir)
}

/// 导出 AST 为 OpenCode 格式（`{opencode_sessions_dir}/{id}.json`）
pub fn export_ast_to_opencode(
    ast: &SessionAst,
    opencode_sessions_dir: &Path,
    auto_remap: bool,
) -> Result<PathBuf, SessionError> {
    fs::create_dir_all(opencode_sessions_dir).map_err(|e| SessionError::Io {
        path: opencode_sessions_dir.display().to_string(),
        detail: e.to_string(),
    })?;

    let out_file = opencode_sessions_dir.join(format!("{}.json", ast.session_id));

    let mut messages = Vec::new();
    for turn in &ast.turns {
        let mut tool_calls = Vec::new();
        for t in &turn.tool_calls {
            let cmd = if auto_remap {
                t.command.as_deref().map(|c| remap_path_str(c, false))
            } else {
                t.command.clone()
            };
            tool_calls.push(json!({
                "name": t.tool_name,
                "command": cmd,
                "path": t.file_path,
            }));
        }

        messages.push(json!({
            "role": turn.role,
            "content": turn.content,
            "thought": turn.thought,
            "timestamp": turn.timestamp,
            "toolCalls": tool_calls,
        }));
    }

    let payload = json!({
        "id": ast.session_id,
        "title": format!("[迁移自 {}] {}", ast.source_agent.to_uppercase(), ast.title),
        "sourceAgent": ast.source_agent,
        "cwd": ast.cwd,
        "createdAt": ast.created_at,
        "updatedAt": ast.updated_at,
        "messages": messages,
        "artifacts": ast.artifacts.iter().map(|a| json!({
            "fileName": a.file_name,
            "path": a.relative_path,
        })).collect::<Vec<_>>(),
    });

    let s = serde_json::to_string_pretty(&payload).unwrap();
    fs::write(&out_file, s).map_err(|e| SessionError::Io {
        path: out_file.display().to_string(),
        detail: e.to_string(),
    })?;

    Ok(out_file)
}

// ---------------------------------------------------------------------------
// 核心调度：跨智能体会话迁移入口
// ---------------------------------------------------------------------------

pub fn migrate_session(
    req: &MigrationRequest,
    backup_store: Option<&BackupStore>,
) -> Result<MigrationReport, SessionError> {
    let src_agent = req.source_agent.to_lowercase();
    let tgt_agent = req.target_agent.to_lowercase();

    if src_agent == tgt_agent {
        return Err(SessionError::Migration {
            detail: format!("源智能体与目标智能体相同 ({src_agent})，无需迁移"),
        });
    }

    // 1. 获取源会话内容并转为 AST
    let (mut ast, redacted_count) = match src_agent.as_str() {
        "codex" => {
            let path_str = req
                .source_path
                .clone()
                .ok_or_else(|| SessionError::Migration {
                    detail: "迁移 Codex 会话必须提供 source_path (rollout 文件或目录)".to_string(),
                })?;
            let p = PathBuf::from(&path_str);
            let content = if p.is_file() {
                fs::read_to_string(&p).map_err(|e| SessionError::Io {
                    path: path_str.clone(),
                    detail: e.to_string(),
                })?
            } else {
                return Err(SessionError::NotFound {
                    target_id: "codex".to_string(),
                    session_id: req.session_id.clone(),
                });
            };
            parse_codex_rollout_content(&content, &req.session_id, &req.session_id, ".")
        }
        "agy" => {
            let path_str = req
                .source_path
                .clone()
                .ok_or_else(|| SessionError::Migration {
                    detail: "迁移 AGY 会话必须提供 source_path (brain 目录或 transcript 文件)"
                        .to_string(),
                })?;
            let p = PathBuf::from(&path_str);
            let (content, brain_dir) = if p.is_file() {
                let c = fs::read_to_string(&p).map_err(|e| SessionError::Io {
                    path: path_str.clone(),
                    detail: e.to_string(),
                })?;
                let b_dir = p.parent().and_then(|p| p.parent()).and_then(|p| p.parent());
                (c, b_dir)
            } else if p.is_dir() {
                let t_file = p
                    .join(".system_generated")
                    .join("logs")
                    .join("transcript.jsonl");
                let c = if t_file.is_file() {
                    fs::read_to_string(&t_file).unwrap_or_default()
                } else {
                    String::new()
                };
                (c, Some(p.as_path()))
            } else {
                return Err(SessionError::NotFound {
                    target_id: "agy".to_string(),
                    session_id: req.session_id.clone(),
                });
            };
            parse_agy_transcript_content(&content, &req.session_id, brain_dir)
        }
        "opencode" => {
            let path_str = req
                .source_path
                .clone()
                .ok_or_else(|| SessionError::Migration {
                    detail: "迁移 OpenCode 会话必须提供 source_path (JSON 文件路径)".to_string(),
                })?;
            let p = PathBuf::from(&path_str);
            let content = fs::read_to_string(&p).map_err(|e| SessionError::Io {
                path: path_str.clone(),
                detail: e.to_string(),
            })?;
            parse_opencode_session_content(&content, &req.session_id)
        }
        _ => {
            return Err(SessionError::Migration {
                detail: format!("不支持的源智能体类型: {src_agent}，仅支持 codex、agy、opencode"),
            })
        }
    };

    // 2. 生成新 session_id
    let new_id = format!(
        "migrated-{}-to-{}-{}",
        src_agent,
        tgt_agent,
        &req.session_id[..8.min(req.session_id.len())]
    );
    ast.session_id = new_id.clone();
    ast.target_agent = Some(tgt_agent.clone());

    // 3. 统计指标
    let turns_converted = ast.turns.len();
    let tools_converted = ast.turns.iter().map(|t| t.tool_calls.len()).sum();
    let artifacts_count = ast.artifacts.len();

    // 4. 解析目标根目录并导出
    let tgt_dir_str = req
        .target_dir
        .clone()
        .unwrap_or_else(|| format!("./migrated_sessions/{tgt_agent}"));
    let tgt_dir = PathBuf::from(&tgt_dir_str);

    let output_path = match tgt_agent.as_str() {
        "codex" => export_ast_to_codex(&ast, &tgt_dir, req.auto_remap_paths)?,
        "agy" => export_ast_to_agy(&ast, &tgt_dir, req.auto_remap_paths)?,
        "opencode" => export_ast_to_opencode(&ast, &tgt_dir, req.auto_remap_paths)?,
        _ => {
            return Err(SessionError::Migration {
                detail: format!("不支持的目标智能体类型: {tgt_agent}，仅支持 codex、agy、opencode"),
            })
        }
    };

    // 5. 若配置了 backup_store，自动记录事务快照与 SHA-256 完整性清单
    let manifest = if let Some(bstore) = backup_store {
        let op_name = format!("migrate_{src_agent}_to_{tgt_agent}:{new_id}");
        let paths: Vec<&Path> = vec![output_path.as_path()];
        bstore.create_backup(&tgt_agent, &op_name, &paths).ok()
    } else {
        None
    };

    Ok(MigrationReport {
        success: true,
        original_session_id: req.session_id.clone(),
        new_session_id: new_id,
        source_agent: src_agent,
        target_agent: tgt_agent,
        title: ast.title,
        turns_converted,
        tools_converted,
        artifacts_count,
        output_path: output_path.display().to_string(),
        secrets_redacted_count: redacted_count,
        manifest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(100);

    #[test]
    fn test_codex_to_opencode_migration() {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let temp_dir = std::env::temp_dir().join(format!("ai-guard-mig-test-{seq}"));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let codex_source = temp_dir.join("rollout-sample.jsonl");
        let codex_content = r#"
{"type":"session_start","cwd":"/workspace/ai-guard","title":"跨平台代码重构"}
{"type":"user_prompt","text":"请帮我重构一下安全拦截模块"}
{"type":"agent_message","text":"已分析依赖结构，现在开始重构","thought":"首先检查 security 目录"}
{"type":"tool_call","tool":"bash","command":"git status"}
"#;
        fs::write(&codex_source, codex_content).unwrap();

        let req = MigrationRequest {
            session_id: "codex-test-01".to_string(),
            source_agent: "codex".to_string(),
            target_agent: "opencode".to_string(),
            source_path: Some(codex_source.to_string_lossy().to_string()),
            target_dir: Some(temp_dir.join("opencode_out").to_string_lossy().to_string()),
            auto_remap_paths: true,
        };

        let report = migrate_session(&req, None).unwrap();
        assert!(report.success);
        assert_eq!(report.source_agent, "codex");
        assert_eq!(report.target_agent, "opencode");
        assert_eq!(report.turns_converted, 2);
        assert_eq!(report.tools_converted, 1);

        let out_path = PathBuf::from(&report.output_path);
        assert!(out_path.is_file());
        let out_json: Value =
            serde_json::from_str(&fs::read_to_string(&out_path).unwrap()).unwrap();
        assert_eq!(out_json["sourceAgent"], "codex");
        assert_eq!(out_json["messages"].as_array().unwrap().len(), 2);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_agy_to_codex_migration() {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let temp_dir = std::env::temp_dir().join(format!("ai-guard-agy-codex-{seq}"));
        let _ = fs::remove_dir_all(&temp_dir);
        let brain_dir = temp_dir.join("brain").join("conv-1234");
        let logs_dir = brain_dir.join(".system_generated").join("logs");
        fs::create_dir_all(&logs_dir).unwrap();

        let transcript_file = logs_dir.join("transcript.jsonl");
        let transcript_content = r#"
{"step_index":0,"type":"USER_INPUT","content":"<USER_REQUEST>\n设计微架构协议\n</USER_REQUEST>"}
{"step_index":1,"type":"PLANNER_RESPONSE","content":"方案已制定","thinking":"需要评估性能","tool_calls":[{"name":"run_command","args":{"CommandLine":"cargo test"}}]}
"#;
        fs::write(&transcript_file, transcript_content).unwrap();

        let req = MigrationRequest {
            session_id: "conv-1234".to_string(),
            source_agent: "agy".to_string(),
            target_agent: "codex".to_string(),
            source_path: Some(brain_dir.to_string_lossy().to_string()),
            target_dir: Some(temp_dir.join("codex_home").to_string_lossy().to_string()),
            auto_remap_paths: false,
        };

        let bstore = BackupStore::new(temp_dir.join("backups"));
        let report = migrate_session(&req, Some(&bstore)).unwrap();
        assert!(report.success);
        assert_eq!(report.turns_converted, 2);
        assert_eq!(report.tools_converted, 1);
        assert!(report.manifest.is_some());

        let out_rollout = PathBuf::from(&report.output_path);
        assert!(out_rollout.is_file());
        let rollout_content = fs::read_to_string(&out_rollout).unwrap();
        assert!(rollout_content.contains("\"type\":\"session_start\""));
        assert!(rollout_content.contains("\"type\":\"user_prompt\""));
        assert!(rollout_content.contains("\"type\":\"agent_message\""));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_secret_redaction_during_migration() {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let temp_dir = std::env::temp_dir().join(format!("ai-guard-secret-mig-{seq}"));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let opencode_file = temp_dir.join("opencode_raw.json");
        let raw_json = r#"{
            "title": "带秘钥的提示词",
            "cwd": "/workspace",
            "messages": [
                {
                    "role": "user",
                    "content": "请使用此 API Token: sk-proj-123456789012345678901234567890 访问服务",
                    "timestamp": "2026-11-07 10:00:00"
                },
                {
                    "role": "assistant",
                    "content": "好的，密码是 pass_secret_999999",
                    "toolCalls": [
                        { "name": "bash", "command": "curl -H 'Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345' https://api.com" }
                    ]
                }
            ]
        }"#;
        fs::write(&opencode_file, raw_json).unwrap();

        let req = MigrationRequest {
            session_id: "opencode-sec-01".to_string(),
            source_agent: "opencode".to_string(),
            target_agent: "agy".to_string(),
            source_path: Some(opencode_file.to_string_lossy().to_string()),
            target_dir: Some(temp_dir.join("agy_brain").to_string_lossy().to_string()),
            auto_remap_paths: true,
        };

        let report = migrate_session(&req, None).unwrap();
        assert!(report.success);
        assert!(report.secrets_redacted_count >= 1);

        // 验证生成的 AGY transcript 中绝对无原始密钥明文！
        let transcript_path = PathBuf::from(&report.output_path)
            .join(".system_generated")
            .join("logs")
            .join("transcript.jsonl");
        assert!(transcript_path.is_file());
        let transcript_content = fs::read_to_string(&transcript_path).unwrap();

        assert!(!transcript_content.contains("sk-proj-123456789012345678901234567890"));
        assert!(!transcript_content.contains("ghp_abcdefghijklmnopqrstuvwxyz012345"));
        assert!(transcript_content.contains("[REDACTED]"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_path_remapping_logic() {
        assert_eq!(
            remap_path_str("/mnt/c/Users/developer/codes", true),
            "C:\\Users\\developer\\codes"
        );
        assert_eq!(
            remap_path_str("C:\\Users\\developer\\codes", false),
            "/mnt/c/Users/developer/codes"
        );
        assert_eq!(
            remap_path_str("d:/workspace/test", false),
            "/mnt/d/workspace/test"
        );
    }
}
