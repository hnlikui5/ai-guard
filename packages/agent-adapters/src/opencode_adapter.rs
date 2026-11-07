//! AI Guard (`packages/agent-adapters`) — OpenCode & `opencode` CLI Hook 协议适配层。
//!
//! 严格遵循 `docs/OPENCODE_HOOK_CONTRACT.md` 契约规范：
//! - 适配 OpenCode 原生 `tool.execute.before` / `execute.before` 插件桥接协议；
//! - 限制 `stdin` 流式最大读取字节数（默认 2 MiB），防止超大输入引发 OOM；
//! - 剔除可能存在的 UTF-8 BOM；
//! - 归一化工具调用：`bash`、`sh`、`write_file`、`edit_file` 等转译为通用 `ActionEvent`；
//! - 遵循 Fail-Closed 安全铁律：任何解析异常、输入超限或缺少必填关键字段时，必须默认显式输出 `decision = "deny"`。

use ai_guard_security::{
    redact_secrets, ActionEvent, ActionKind, ClientSurface, Decision, Enforcement, EnvironmentKind,
    PolicyEngine, SecurityError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

/// OpenCode `PreToolUse` Hook `stdin` 最大允许读取字节数（2 MiB）。
pub const MAX_OPENCODE_HOOK_STDIN_BYTES: usize = 2 * 1024 * 1024;

/// OpenCode `PreToolUse` Wire 输入结构。
#[derive(Debug, Deserialize)]
pub struct OpenCodePreToolUseWireInput {
    #[serde(alias = "hook_event_name")]
    pub event: Option<String>,
    #[serde(alias = "toolName")]
    pub tool_name: Option<String>,
    #[serde(alias = "toolInput", alias = "args")]
    pub tool_input: Option<Value>,
    pub cwd: Option<String>,
    #[serde(alias = "workspaceRoot", alias = "workspace_root")]
    pub workspace_root: Option<String>,
    #[serde(alias = "sourceScope", alias = "source_scope")]
    pub source_scope: Option<String>,
    #[serde(alias = "sessionId", alias = "session_id")]
    pub session_id: Option<String>,
}

/// OpenCode `PreToolUse` Wire 输出顶层结构（stdout 单行 JSON）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenCodePreToolUseWireOutput {
    pub decision: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl OpenCodePreToolUseWireOutput {
    /// 构造标准 OpenCode 正常放行输出。
    pub fn allow() -> Self {
        Self {
            decision: "allow".to_string(),
            action: "allow".to_string(),
            reason: None,
        }
    }

    /// 构造标准 OpenCode 阻断输出（经过脱敏处理）。
    pub fn deny(reason: &str) -> Self {
        let redacted = redact_secrets(reason);
        let safe_reason = if redacted.trim().is_empty() {
            "[AI卫士安全阻断] 触发默认安全防护策略（Fail-Closed）".to_string()
        } else {
            redacted
        };
        Self {
            decision: "deny".to_string(),
            action: "block".to_string(),
            reason: Some(safe_reason),
        }
    }

    /// 序列化为单行紧凑 JSON 字符串。
    pub fn to_single_line_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"decision":"deny","action":"block","reason":"[AI卫士安全阻断] 协议输出序列化异常（Fail-Closed）"}"#.to_string()
        })
    }
}

/// 从任意 `Read` 流中限长读取字节并解析为 `ActionEvent`。
pub fn read_and_parse_opencode_pre_tool_use<R: Read>(
    reader: R,
    max_bytes: usize,
) -> Result<ActionEvent, SecurityError> {
    let mut buf = Vec::new();
    let mut limited = reader.take((max_bytes as u64).saturating_add(1));
    limited.read_to_end(&mut buf).map_err(|e| {
        SecurityError::protocol(
            "AG-PROTO-IO-ERROR",
            format!("读取 OpenCode Hook stdin 失败: {e}"),
        )
    })?;

    if buf.len() > max_bytes {
        return Err(SecurityError::protocol(
            "AG-PROTO-PAYLOAD-TOO-LARGE",
            format!("输入大小超过限制 ({max_bytes} 字节)，默认阻断（Fail-Closed）"),
        ));
    }

    parse_opencode_pre_tool_use_bytes(&buf)
}

/// 解析字节流为标准化 `ActionEvent`。
pub fn parse_opencode_pre_tool_use_bytes(bytes: &[u8]) -> Result<ActionEvent, SecurityError> {
    let raw = std::str::from_utf8(bytes).map_err(|_| {
        SecurityError::protocol(
            "AG-PROTO-INVALID-UTF8",
            "输入包含非合法 UTF-8 编码，默认阻断",
        )
    })?;

    let trimmed = raw.strip_prefix('\u{feff}').unwrap_or(raw).trim();
    if trimmed.is_empty() {
        return Err(SecurityError::protocol(
            "AG-PROTO-EMPTY-INPUT",
            "OpenCode Hook stdin 为空，默认阻断（Fail-Closed）",
        ));
    }

    let wire: OpenCodePreToolUseWireInput = serde_json::from_str(trimmed).map_err(|e| {
        SecurityError::protocol(
            "AG-PROTO-JSON-PARSE-ERROR",
            format!("解析 OpenCode PreToolUse JSON 载荷失败: {e}"),
        )
    })?;

    let tool_name = wire.tool_name.unwrap_or_default();
    if tool_name.trim().is_empty() {
        return Err(SecurityError::protocol(
            "AG-PROTO-MISSING-TOOL-NAME",
            "OpenCode 载荷缺少 tool_name 字段，默认阻断（Fail-Closed）",
        ));
    }

    let is_windows = cfg!(target_os = "windows");
    let env_kind = if is_windows {
        EnvironmentKind::WindowsHost
    } else {
        EnvironmentKind::Wsl2Distro {
            distro_name: std::env::var("WSL_DISTRO_NAME").unwrap_or_else(|_| "Ubuntu".to_string()),
        }
    };

    let target_id = env_kind.default_target_id();
    let client_surface = if is_windows {
        ClientSurface::OpenCodeDesktopApp
    } else {
        ClientSurface::OpenCodeCli
    };

    let session_id = wire
        .session_id
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "opencode-session-ephemeral".to_string());

    let cwd = wire
        .cwd
        .or(wire.workspace_root)
        .filter(|c| !c.trim().is_empty())
        .unwrap_or_else(|| {
            std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| ".".to_string())
        });

    let tool_input = wire.tool_input.unwrap_or(Value::Null);

    // 动作归一化转译
    let tool_name_lower = tool_name.to_lowercase();
    let (action_kind, normalized_command, target_paths, redacted_summary) = if tool_name_lower
        == "bash"
        || tool_name_lower == "sh"
        || tool_name_lower == "shell"
        || tool_name_lower == "terminal"
        || tool_name_lower == "exec"
        || tool_input.get("command").is_some()
        || tool_input.get("cmd").is_some()
    {
        let cmd = tool_input
            .get("command")
            .or_else(|| tool_input.get("cmd"))
            .and_then(|v| {
                if let Some(s) = v.as_str() {
                    Some(s.to_string())
                } else if let Some(arr) = v.as_array() {
                    let parts: Vec<String> = arr
                        .iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect();
                    Some(parts.join(" "))
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let summary = format!("[OpenCode:{tool_name}] {}", redact_secrets(&cmd));
        (ActionKind::Shell, Some(cmd), Vec::new(), summary)
    } else if tool_name_lower.contains("write")
        || tool_name_lower.contains("edit")
        || tool_name_lower.contains("patch")
    {
        let mut paths = Vec::new();
        if let Some(p) = tool_input
            .get("path")
            .or_else(|| tool_input.get("file_path"))
            .or_else(|| tool_input.get("filePath"))
            .and_then(|v| v.as_str())
        {
            paths.push(p.to_string());
        }

        let content = tool_input
            .get("content")
            .or_else(|| tool_input.get("patch"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let summary = format!("[OpenCode:{tool_name}] 写入/编辑文件: {}", paths.join(", "));
        (
            ActionKind::FilePatch,
            if content.is_empty() {
                None
            } else {
                Some(content.to_string())
            },
            paths,
            summary,
        )
    } else {
        let mut paths = Vec::new();
        if let Some(p) = tool_input
            .get("path")
            .or_else(|| tool_input.get("file_path"))
            .or_else(|| tool_input.get("filePath"))
            .and_then(|v| v.as_str())
        {
            paths.push(p.to_string());
        }
        let summary = format!(
            "[OpenCode:{tool_name}] 参数: {}",
            redact_secrets(&tool_input.to_string())
        );
        (ActionKind::LocalTool, None, paths, summary)
    };

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    Ok(ActionEvent {
        target_id,
        environment_kind: env_kind,
        client_surface,
        agent: "opencode".to_string(),
        session_id,
        turn_id: "opencode-turn-001".to_string(),
        tool_use_id: format!("opencode-tool-{now_ms}"),
        tool_name,
        action_kind,
        cwd,
        normalized_command,
        target_paths,
        redacted_summary,
    })
}

/// 接收 OpenCode Hook 输入并使用给定策略引擎裁决，返回单行 JSON、安全判定与动作事件。
pub fn handle_opencode_pre_tool_use_bytes_with_engine(
    bytes: &[u8],
    engine: &PolicyEngine,
) -> (String, Decision, Option<ActionEvent>) {
    let action = match parse_opencode_pre_tool_use_bytes(bytes) {
        Ok(act) => act,
        Err(err) => {
            let (code, detail) = match &err {
                SecurityError::ProtocolError {
                    code,
                    redacted_detail,
                }
                | SecurityError::EvaluationError {
                    code,
                    redacted_detail,
                } => (code.clone(), redacted_detail.clone()),
            };
            let reason = format!("[AI卫士安全阻断][{code}] {detail}");
            let wire_out = OpenCodePreToolUseWireOutput::deny(&reason);
            let decision = Decision::fail_closed_deny("opencode", code, detail);
            return (wire_out.to_single_line_json(), decision, None);
        }
    };

    let decision = engine.evaluate(&action);
    let wire_out = match decision.enforcement {
        Enforcement::Allow | Enforcement::Observe => OpenCodePreToolUseWireOutput::allow(),
        Enforcement::Deny => {
            let reason = format!(
                "[AI卫士安全阻断][{}] {}",
                decision.reason_code, decision.display_message
            );
            OpenCodePreToolUseWireOutput::deny(&reason)
        }
        Enforcement::Unsupported => {
            OpenCodePreToolUseWireOutput::deny("[AI卫士安全阻断] 不受支持的操作类型（Fail-Closed）")
        }
    };

    (wire_out.to_single_line_json(), decision, Some(action))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_guard_security::default_policy_engine;

    #[test]
    fn test_opencode_allow_normal_command() {
        let json = r#"{
            "event": "PreToolUse",
            "tool_name": "bash",
            "tool_input": {
                "command": "git status",
                "workdir": "/home/user/project"
            },
            "cwd": "/home/user/project",
            "session_id": "sess-opencode-01"
        }"#;

        let engine = default_policy_engine();
        let (out_json, decision, action) =
            handle_opencode_pre_tool_use_bytes_with_engine(json.as_bytes(), engine);

        assert_eq!(decision.enforcement, Enforcement::Allow);
        assert!(action.is_some());
        let wire_out: OpenCodePreToolUseWireOutput = serde_json::from_str(&out_json).unwrap();
        assert_eq!(wire_out.decision, "allow");
        assert_eq!(wire_out.action, "allow");
        assert!(wire_out.reason.is_none());
    }

    #[test]
    fn test_opencode_deny_destructive_rm() {
        let json = r#"{
            "event": "PreToolUse",
            "tool_name": "bash",
            "tool_input": {
                "command": "rm -rf /",
                "workdir": "/workspace"
            },
            "cwd": "/workspace"
        }"#;

        let engine = default_policy_engine();
        let (out_json, decision, _) =
            handle_opencode_pre_tool_use_bytes_with_engine(json.as_bytes(), engine);

        assert_eq!(decision.enforcement, Enforcement::Deny);
        let wire_out: OpenCodePreToolUseWireOutput = serde_json::from_str(&out_json).unwrap();
        assert_eq!(wire_out.decision, "deny");
        assert_eq!(wire_out.action, "block");
        assert!(wire_out.reason.unwrap().contains("SHELL-DESTRUCTIVE-RM"));
    }

    #[test]
    fn test_opencode_deny_sensitive_credential_access() {
        let json = r#"{
            "event": "PreToolUse",
            "tool_name": "bash",
            "tool_input": {
                "command": "cat ~/.ssh/id_rsa",
                "workdir": "/workspace"
            }
        }"#;

        let engine = default_policy_engine();
        let (out_json, decision, _) =
            handle_opencode_pre_tool_use_bytes_with_engine(json.as_bytes(), engine);

        assert_eq!(decision.enforcement, Enforcement::Deny);
        let wire_out: OpenCodePreToolUseWireOutput = serde_json::from_str(&out_json).unwrap();
        assert_eq!(wire_out.decision, "deny");
        assert!(wire_out.reason.unwrap().contains("PATH-SENSITIVE-CRED"));
    }

    #[test]
    fn test_opencode_fail_closed_on_corrupted_json() {
        let bad_json = r#"{"event": "PreToolUse", "tool_name": { broken ... "#;
        let engine = default_policy_engine();
        let (out_json, decision, _) =
            handle_opencode_pre_tool_use_bytes_with_engine(bad_json.as_bytes(), engine);

        assert_eq!(decision.enforcement, Enforcement::Deny);
        let wire_out: OpenCodePreToolUseWireOutput = serde_json::from_str(&out_json).unwrap();
        assert_eq!(wire_out.decision, "deny");
        assert!(wire_out
            .reason
            .unwrap()
            .contains("AG-PROTO-JSON-PARSE-ERROR"));
    }

    #[test]
    fn test_opencode_fail_closed_on_empty_input() {
        let empty = b"   ";
        let engine = default_policy_engine();
        let (out_json, decision, _) = handle_opencode_pre_tool_use_bytes_with_engine(empty, engine);

        assert_eq!(decision.enforcement, Enforcement::Deny);
        let wire_out: OpenCodePreToolUseWireOutput = serde_json::from_str(&out_json).unwrap();
        assert_eq!(wire_out.decision, "deny");
        assert!(wire_out.reason.unwrap().contains("AG-PROTO-EMPTY-INPUT"));
    }

    #[test]
    fn test_opencode_write_file_patch_handling() {
        let json = r#"{
            "event": "PreToolUse",
            "tool_name": "write_file",
            "tool_input": {
                "path": "/workspace/src/lib.rs",
                "content": "pub fn hello() {}"
            },
            "cwd": "/workspace"
        }"#;

        let engine = default_policy_engine();
        let (out_json, decision, action) =
            handle_opencode_pre_tool_use_bytes_with_engine(json.as_bytes(), engine);

        assert_eq!(decision.enforcement, Enforcement::Allow);
        assert!(action.is_some());
        let act = action.unwrap();
        assert_eq!(act.action_kind, ActionKind::FilePatch);
        assert_eq!(act.target_paths, vec!["/workspace/src/lib.rs"]);
        let wire_out: OpenCodePreToolUseWireOutput = serde_json::from_str(&out_json).unwrap();
        assert_eq!(wire_out.decision, "allow");
    }
}
