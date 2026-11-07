//! AI Guard (`packages/agent-adapters`) — Antigravity (AGY) & `agy` CLI Hook 协议适配层。
//!
//! 严格遵循 `docs/AGY_HOOK_CONTRACT.md` 契约规范：
//! - 适配 AGY 官方基于 ProtoJSON (camelCase) 的 `PreToolUse` Wire 协议；
//! - 限制 `stdin` 流式最大读取字节数（默认 2 MiB），防止超大输入引发 OOM；
//! - 兼容 Windows/PowerShell 等可能附带的 UTF-8 BOM；
//! - 归一化工具调用：`run_command`、`write_file`、`edit_file`、`call_mcp_tool` 转换为通用 `ActionEvent`；
//! - 遵循 Fail-Closed 安全铁律：任何解析异常、输入超限或缺少必填关键字段时，必须默认显式输出 `decision = "deny"`。

use ai_guard_security::{
    redact_secrets, ActionEvent, ActionKind, ClientSurface, Decision, Enforcement, EnvironmentKind,
    PolicyEngine, SecurityError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;

/// AGY `PreToolUse` Hook `stdin` 最大允许读取字节数（2 MiB）。
pub const MAX_AGY_HOOK_STDIN_BYTES: usize = 2 * 1024 * 1024;

/// AGY `PreToolUse` Wire 输入结构（宽松反序列化以容纳多版本差异并捕获异常）。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgyPreToolUseWireInput {
    pub conversation_id: Option<Value>,
    pub workspace_paths: Option<Value>,
    pub transcript_path: Option<Value>,
    pub artifact_directory_path: Option<Value>,
    pub model_name: Option<Value>,
    pub last_user_input: Option<Value>,
    pub step_idx: Option<Value>,
    pub tool_call: Option<AgyToolCallWireInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgyToolCallWireInput {
    pub name: Option<Value>,
    pub args: Option<Value>,
}

/// AGY `PreToolUse` Wire 输出顶层结构（stdout 单行 JSON）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgyPreToolUseWireOutput {
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AgyPreToolUseWireOutput {
    /// 构造标准 AGY 正常放行输出。
    pub fn allow() -> Self {
        Self {
            decision: "allow".to_string(),
            reason: None,
        }
    }

    /// 构造标准 AGY 阻断输出（经过脱敏处理）。
    pub fn deny(reason: &str) -> Self {
        let redacted = redact_secrets(reason);
        let safe_reason = if redacted.trim().is_empty() {
            "[AI卫士安全阻断] 触发默认安全防护策略（Fail-Closed）".to_string()
        } else {
            redacted
        };
        Self {
            decision: "deny".to_string(),
            reason: Some(safe_reason),
        }
    }

    /// 构造标准 AGY 人机二次确认提示输出。
    pub fn ask(reason: &str) -> Self {
        let redacted = redact_secrets(reason);
        Self {
            decision: "ask".to_string(),
            reason: Some(redacted),
        }
    }

    /// 序列化为单行紧凑 JSON 字符串（供 `stdout` 打印）。
    pub fn to_single_line_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"decision":"deny","reason":"[AI卫士安全阻断] 协议输出序列化异常（Fail-Closed）"}"#.to_string()
        })
    }
}

/// 从任意 `Read` 流中限长读取字节并解析为 `ActionEvent`。
pub fn read_and_parse_agy_pre_tool_use<R: Read>(
    reader: R,
    max_bytes: usize,
) -> Result<ActionEvent, SecurityError> {
    let mut buf = Vec::new();
    let mut limited = reader.take((max_bytes as u64).saturating_add(1));
    limited.read_to_end(&mut buf).map_err(|e| {
        SecurityError::protocol(
            "AG-PROTO-IO-ERROR",
            format!("读取 AGY Hook stdin 失败: {e}"),
        )
    })?;

    if buf.len() > max_bytes {
        return Err(SecurityError::protocol(
            "AG-PROTO-PAYLOAD-TOO-LARGE",
            format!("输入大小超过限制 ({max_bytes} 字节)，默认阻断（Fail-Closed）"),
        ));
    }

    parse_agy_pre_tool_use_bytes(&buf)
}

/// 解析字节流为标准化 `ActionEvent`。
pub fn parse_agy_pre_tool_use_bytes(bytes: &[u8]) -> Result<ActionEvent, SecurityError> {
    let raw = std::str::from_utf8(bytes).map_err(|_| {
        SecurityError::protocol(
            "AG-PROTO-INVALID-UTF8",
            "输入包含非合法 UTF-8 编码，默认阻断",
        )
    })?;

    // 剔除可能存在的 UTF-8 BOM
    let trimmed = raw.strip_prefix('\u{feff}').unwrap_or(raw).trim();
    if trimmed.is_empty() {
        return Err(SecurityError::protocol(
            "AG-PROTO-EMPTY-INPUT",
            "AGY Hook stdin 为空，默认阻断（Fail-Closed）",
        ));
    }

    let wire: AgyPreToolUseWireInput = serde_json::from_str(trimmed).map_err(|e| {
        SecurityError::protocol(
            "AG-PROTO-JSON-PARSE-ERROR",
            format!("JSON 语法错误或非预期结构: {e}"),
        )
    })?;

    let session_id = wire
        .conversation_id
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "agy-unknown-session".to_string());

    let turn_id = wire
        .step_idx
        .and_then(|v| {
            if let Some(n) = v.as_u64() {
                Some(n.to_string())
            } else {
                v.as_str().map(|s| s.to_string())
            }
        })
        .unwrap_or_else(|| "0".to_string());

    let cwd = wire
        .workspace_paths
        .as_ref()
        .and_then(|v| {
            if let Some(arr) = v.as_array() {
                arr.first().and_then(|p| p.as_str().map(|s| s.to_string()))
            } else {
                v.as_str().map(|s| s.to_string())
            }
        })
        .unwrap_or_else(|| {
            std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "/workspace".to_string())
        });

    let env_kind = EnvironmentKind::infer_from_path(&cwd);
    let target_id = env_kind.default_target_id();

    let tool_call = wire.tool_call.ok_or_else(|| {
        SecurityError::protocol("AG-PROTO-MISSING-TOOL-CALL", "缺少必填字段 toolCall")
    })?;

    let tool_name = tool_call
        .name
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    if tool_name.trim().is_empty() {
        return Err(SecurityError::protocol(
            "AG-PROTO-MISSING-TOOL-NAME",
            "缺少必填工具名 toolCall.name",
        ));
    }

    let args_val = tool_call.args.unwrap_or(Value::Null);

    let action_kind;
    let mut normalized_command = None;
    let mut target_paths = Vec::new();
    let summary;

    match tool_name.as_str() {
        "run_command" => {
            action_kind = ActionKind::Shell;
            let cmd = extract_string_field(&args_val, "CommandLine").unwrap_or_default();
            let summary_text = extract_string_field(&args_val, "toolSummary")
                .unwrap_or_else(|| "Execute Shell Command".to_string());
            summary = format!("{summary_text}: {cmd}");
            normalized_command = Some(cmd);
        }
        "write_file" => {
            action_kind = ActionKind::FilePatch;
            if let Some(path) = extract_string_field(&args_val, "Path") {
                summary = format!("Write file: {path}");
                target_paths.push(path.clone());
                // 也设置 normalized_command 便于路径越界规则命中
                normalized_command = Some(format!("write {path}"));
            } else {
                summary = "Write file without path".to_string();
            }
        }
        "edit_file" => {
            action_kind = ActionKind::FilePatch;
            if let Some(path) = extract_string_field(&args_val, "Path") {
                summary = format!("Edit file: {path}");
                target_paths.push(path.clone());
                normalized_command = Some(format!("edit {path}"));
            } else {
                summary = "Edit file without path".to_string();
            }
        }
        "call_mcp_tool" => {
            action_kind = ActionKind::McpTool;
            let srv = extract_string_field(&args_val, "ServerName")
                .unwrap_or_else(|| "unknown".to_string());
            let tool = extract_string_field(&args_val, "ToolName")
                .unwrap_or_else(|| "unknown".to_string());
            summary = format!("Call MCP {srv}::{tool}");
        }
        _ => {
            action_kind = ActionKind::LocalTool;
            summary = format!("Invoke AGY tool {tool_name}");
        }
    }

    let redacted_summary = redact_secrets(&summary);

    Ok(ActionEvent {
        target_id,
        environment_kind: env_kind,
        client_surface: ClientSurface::AgyCli,
        agent: "agy".to_string(),
        session_id,
        tool_use_id: format!("agy-step-{turn_id}"),
        turn_id,
        tool_name,
        action_kind,
        cwd,
        normalized_command,
        target_paths,
        redacted_summary,
    })
}

/// 辅助从 `serde_json::Value` 中提取指定字段字符串（支持 camelCase 与 PascalCase）。
fn extract_string_field(val: &Value, field_name: &str) -> Option<String> {
    if let Value::Object(map) = val {
        if let Some(Value::String(s)) = map.get(field_name) {
            return Some(s.clone());
        }
        // 尝试首字母小写形式
        let mut chars = field_name.chars();
        if let Some(first) = chars.next() {
            let camel = format!("{}{}", first.to_lowercase(), chars.as_str());
            if let Some(Value::String(s)) = map.get(&camel) {
                return Some(s.clone());
            }
        }
    }
    None
}

/// 将安全裁决转换为标准 AGY `PreToolUse` Wire 输出。
pub fn format_agy_pre_tool_use_output(decision: &Decision) -> AgyPreToolUseWireOutput {
    match decision.enforcement {
        Enforcement::Deny => {
            let reason = if decision.display_message.trim().is_empty() {
                format!(
                    "[AI卫士安全阻断] 触发策略规则 [{}]，操作已被强制拒绝执行。",
                    decision.reason_code
                )
            } else {
                format!("[{}] {}", decision.reason_code, decision.display_message)
            };
            AgyPreToolUseWireOutput::deny(&reason)
        }
        Enforcement::Allow | Enforcement::Observe => AgyPreToolUseWireOutput::allow(),
        Enforcement::Unsupported => {
            AgyPreToolUseWireOutput::deny("[AI卫士安全阻断] 不受支持的操作模式（Fail-Closed）")
        }
    }
}

/// 处理原始 `stdin` 字节流并执行策略评估，向调用方返回 (stdout_json, decision, action_event)。
pub fn handle_agy_pre_tool_use_bytes_with_engine(
    bytes: &[u8],
    engine: &PolicyEngine,
) -> (String, Decision, Option<ActionEvent>) {
    let parsed = parse_agy_pre_tool_use_bytes(bytes);
    match parsed {
        Ok(action) => {
            let decision = engine.evaluate(&action);
            let wire_out = format_agy_pre_tool_use_output(&decision);
            (wire_out.to_single_line_json(), decision, Some(action))
        }
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
            let fallback_decision = Decision::fail_closed_deny("unknown", code.clone(), detail);
            let reason = format!("[{code}] {}", fallback_decision.display_message);
            let wire_out = AgyPreToolUseWireOutput::deny(&reason);
            (wire_out.to_single_line_json(), fallback_decision, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_guard_security::default_policy_engine;

    #[test]
    fn test_agy_allow_normal_command() {
        let json = r#"{
            "conversationId": "test-conv-001",
            "workspacePaths": ["/home/ai-li/codes/ai-guard"],
            "stepIdx": 5,
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "git status",
                    "toolSummary": "Git status check"
                }
            }
        }"#;

        let engine = default_policy_engine();
        let (out_json, decision, action) =
            handle_agy_pre_tool_use_bytes_with_engine(json.as_bytes(), engine);

        assert_eq!(decision.enforcement, Enforcement::Allow);
        assert!(action.is_some());
        let wire_out: AgyPreToolUseWireOutput = serde_json::from_str(&out_json).unwrap();
        assert_eq!(wire_out.decision, "allow");
        assert!(wire_out.reason.is_none());
    }

    #[test]
    fn test_agy_deny_destructive_rm() {
        let json = r#"{
            "conversationId": "test-conv-002",
            "workspacePaths": ["/home/ai-li/codes/ai-guard"],
            "stepIdx": 8,
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "rm -rf /",
                    "toolSummary": "Clean root"
                }
            }
        }"#;

        let engine = default_policy_engine();
        let (out_json, decision, _) =
            handle_agy_pre_tool_use_bytes_with_engine(json.as_bytes(), engine);

        assert_eq!(decision.enforcement, Enforcement::Deny);
        let wire_out: AgyPreToolUseWireOutput = serde_json::from_str(&out_json).unwrap();
        assert_eq!(wire_out.decision, "deny");
        assert!(wire_out.reason.unwrap().contains("SHELL-DESTRUCTIVE-RM"));
    }

    #[test]
    fn test_agy_deny_sensitive_credential_access() {
        let json = r#"{
            "conversationId": "test-conv-003",
            "workspacePaths": ["/home/ai-li/codes/ai-guard"],
            "stepIdx": 10,
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "cat ~/.ssh/id_rsa",
                    "toolSummary": "Read private key"
                }
            }
        }"#;

        let engine = default_policy_engine();
        let (out_json, decision, _) =
            handle_agy_pre_tool_use_bytes_with_engine(json.as_bytes(), engine);

        assert_eq!(decision.enforcement, Enforcement::Deny);
        let wire_out: AgyPreToolUseWireOutput = serde_json::from_str(&out_json).unwrap();
        assert_eq!(wire_out.decision, "deny");
        assert!(wire_out.reason.unwrap().contains("PATH-SENSITIVE-CRED"));
    }

    #[test]
    fn test_agy_fail_closed_on_corrupted_json() {
        let bad_json = r#"{"conversationId": "corrupted", "toolCall": { broken ... "#;
        let engine = default_policy_engine();
        let (out_json, decision, _) =
            handle_agy_pre_tool_use_bytes_with_engine(bad_json.as_bytes(), engine);

        assert_eq!(decision.enforcement, Enforcement::Deny);
        let wire_out: AgyPreToolUseWireOutput = serde_json::from_str(&out_json).unwrap();
        assert_eq!(wire_out.decision, "deny");
        assert!(wire_out
            .reason
            .unwrap()
            .contains("AG-PROTO-JSON-PARSE-ERROR"));
    }

    #[test]
    fn test_agy_fail_closed_on_empty_input() {
        let empty = b"   ";
        let engine = default_policy_engine();
        let (out_json, decision, _) = handle_agy_pre_tool_use_bytes_with_engine(empty, engine);

        assert_eq!(decision.enforcement, Enforcement::Deny);
        let wire_out: AgyPreToolUseWireOutput = serde_json::from_str(&out_json).unwrap();
        assert_eq!(wire_out.decision, "deny");
        assert!(wire_out.reason.unwrap().contains("AG-PROTO-EMPTY-INPUT"));
    }

    #[test]
    fn test_agy_write_file_patch_handling() {
        let json = r#"{
            "conversationId": "test-conv-004",
            "workspacePaths": ["/home/ai-li/codes/ai-guard"],
            "stepIdx": 12,
            "toolCall": {
                "name": "write_file",
                "args": {
                    "Path": "/home/ai-li/codes/ai-guard/src/main.rs",
                    "Content": "fn main() {}"
                }
            }
        }"#;

        let engine = default_policy_engine();
        let (out_json, decision, action) =
            handle_agy_pre_tool_use_bytes_with_engine(json.as_bytes(), engine);

        assert_eq!(decision.enforcement, Enforcement::Allow);
        assert!(action.is_some());
        let act = action.unwrap();
        assert_eq!(act.action_kind, ActionKind::FilePatch);
        assert_eq!(
            act.target_paths,
            vec!["/home/ai-li/codes/ai-guard/src/main.rs"]
        );
        let wire_out: AgyPreToolUseWireOutput = serde_json::from_str(&out_json).unwrap();
        assert_eq!(wire_out.decision, "allow");
    }
}
