//! AI Guard (`packages/agent-adapters`) — Codex Hook 协议适配层。
//!
//! 严格基于 Phase 0（`docs/CODEX_HOOK_CONTRACT.md`）实测固化的 Codex `PreToolUse` 协议：
//! - 限制 `stdin` 最大读取字节数（默认 1 MiB），防止超大输入导致 OOM 或超时 Fail-Open。
//! - 兼容 Windows PowerShell 管道可能附带的 UTF-8 BOM (`\u{feff}`)。
//! - 当输入为空、超长、非合法 UTF-8、JSON 语法错误或缺失必填字段时，不发生 panic，
//!   直接生成显式 Fail-Closed `Deny` 决策并序列化为合法的单行 Codex `PreToolUse` JSON。

pub mod installer;

pub use installer::{
    compute_unified_diff, inspect_toml_hooks, install_codex_hook, preflight_codex_run,
    render_managed_toml_block, strip_managed_toml_block, uninstall_codex_hook, InstallReport,
    InstallRequest, InstallScope, InstallerError, PreflightCheckItem, PreflightReport,
    PreflightRequest, UninstallReport, UninstallRequest,
};

use ai_guard_security::{
    default_policy_engine, redact_secrets, ActionEvent, ActionKind, ClientSurface, Decision,
    Enforcement, EnvironmentKind, PolicyEngine, SecurityError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;

/// `PreToolUse` Hook `stdin` 最大允许读取字节数（1 MiB）。
pub const MAX_HOOK_STDIN_BYTES: usize = 1024 * 1024;

/// Codex `PreToolUse` Wire 输入结构（宽松反序列化以便捕获字段类型错误并转为显式 Deny）。
#[derive(Debug, Deserialize)]
struct CodexPreToolUseWireInput {
    session_id: Option<Value>,
    turn_id: Option<Value>,
    transcript_path: Option<Value>,
    cwd: Option<Value>,
    hook_event_name: Option<Value>,
    #[allow(dead_code)]
    model: Option<Value>,
    #[allow(dead_code)]
    permission_mode: Option<Value>,
    tool_name: Option<Value>,
    tool_input: Option<Value>,
    tool_use_id: Option<Value>,
}

/// Codex `PreToolUse` Wire 输出顶层结构。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexPreToolUseWireOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: CodexHookSpecificOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexHookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

impl CodexPreToolUseWireOutput {
    /// 构造标准 Codex `PreToolUse` 拒绝输出对象（保证 `permissionDecisionReason` 非空且已脱敏）。
    pub fn deny(reason: &str) -> Self {
        let redacted = redact_secrets(reason);
        let safe_reason = if redacted.trim().is_empty() {
            "[AI卫士安全阻断] 触发默认安全保护策略（Fail-Closed）".to_string()
        } else {
            redacted
        };
        Self {
            hook_specific_output: CodexHookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: safe_reason,
            },
        }
    }

    /// 序列化为单行紧凑 JSON 字符串（供 `stdout` 输出）。
    pub fn to_single_line_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[AI卫士安全阻断] 协议输出序列化异常（Fail-Closed）"}}"#.to_string()
        })
    }
}

/// 从任意 `Read` 流中限长读取字节并解析为 `ActionEvent`。
pub fn read_and_parse_codex_pre_tool_use<R: Read>(
    reader: R,
    max_bytes: usize,
) -> Result<ActionEvent, SecurityError> {
    let mut buf = Vec::new();
    let mut limited = reader.take((max_bytes as u64).saturating_add(1));
    limited.read_to_end(&mut buf).map_err(|e| {
        SecurityError::protocol("AG-PROTO-IO-ERROR", format!("读取 Hook stdin 失败: {e}"))
    })?;

    if buf.len() > max_bytes {
        return Err(SecurityError::protocol(
            "AG-PROTO-OVERSIZE",
            format!("Hook stdin 超过最大允许长度 ({max_bytes} bytes)"),
        ));
    }

    parse_codex_pre_tool_use_bytes(&buf)
}

/// 从原始字节切片解析 Codex `PreToolUse` 事件。
pub fn parse_codex_pre_tool_use_bytes(bytes: &[u8]) -> Result<ActionEvent, SecurityError> {
    let raw_str = std::str::from_utf8(bytes).map_err(|_| {
        SecurityError::protocol(
            "AG-PROTO-INVALID-UTF8",
            "Hook stdin 包含非法的 UTF-8 字节序列",
        )
    })?;

    // 剥离 Windows PowerShell 可能注入的 UTF-8 BOM
    let trimmed = raw_str.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Err(SecurityError::protocol(
            "AG-PROTO-EMPTY-STDIN",
            "Hook stdin 为空，无法解析工具调用上下文",
        ));
    }

    let wire: CodexPreToolUseWireInput = serde_json::from_str(trimmed).map_err(|e| {
        SecurityError::protocol(
            "AG-PROTO-INVALID-JSON",
            format!("Hook stdin JSON 解析失败: {e}"),
        )
    })?;

    let event_name = extract_required_non_empty_str(&wire.hook_event_name, "hook_event_name")?;
    if event_name != "PreToolUse" {
        return Err(SecurityError::protocol(
            "AG-PROTO-UNEXPECTED-EVENT",
            format!("不支持的 hook_event_name `{event_name}`，仅支持 `PreToolUse`"),
        ));
    }

    let session_id = extract_required_non_empty_str(&wire.session_id, "session_id")?;
    let turn_id = match &wire.turn_id {
        Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
        _ => "unknown-turn".to_string(),
    };
    let cwd = extract_required_non_empty_str(&wire.cwd, "cwd")?;
    let tool_name = extract_required_non_empty_str(&wire.tool_name, "tool_name")?;
    let tool_use_id = match &wire.tool_use_id {
        Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
        _ => "unknown-tool-use-id".to_string(),
    };

    let tool_input = wire.tool_input.as_ref().ok_or_else(|| {
        SecurityError::protocol("AG-PROTO-MISSING-FIELD", "缺少必填字段 `tool_input`")
    })?;

    let env_kind = EnvironmentKind::infer_from_path(&cwd);
    let target_id = env_kind.default_target_id();
    let client_surface = infer_client_surface(&wire.transcript_path, &env_kind);

    let (action_kind, normalized_command, target_paths, redacted_summary) =
        normalize_tool_invocation(&tool_name, tool_input)?;

    Ok(ActionEvent {
        target_id,
        environment_kind: env_kind,
        client_surface,
        agent: "codex".to_string(),
        session_id,
        turn_id,
        tool_use_id,
        tool_name,
        action_kind,
        cwd,
        normalized_command,
        target_paths,
        redacted_summary,
    })
}

fn extract_required_non_empty_str(
    val: &Option<Value>,
    field_name: &str,
) -> Result<String, SecurityError> {
    match val {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.clone()),
        Some(_) => Err(SecurityError::protocol(
            "AG-PROTO-INVALID-FIELD-TYPE",
            format!("字段 `{field_name}` 类型非法或为空字符串"),
        )),
        None => Err(SecurityError::protocol(
            "AG-PROTO-MISSING-FIELD",
            format!("缺少必填字段 `{field_name}`"),
        )),
    }
}

fn infer_client_surface(
    transcript_path: &Option<Value>,
    env_kind: &EnvironmentKind,
) -> ClientSurface {
    if let EnvironmentKind::WindowsHost = env_kind {
        return ClientSurface::CodexDesktopApp;
    }
    if let Some(Value::String(p)) = transcript_path {
        if p.contains("codex_work_desktop") {
            return ClientSurface::CodexDesktopApp;
        }
    }
    ClientSurface::CodexCli
}

/// 根据 `tool_name` 与 `tool_input` 提取标准化动作分类、命令/补丁文本、目标路径列表及脱敏摘要。
fn normalize_tool_invocation(
    tool_name: &str,
    tool_input: &Value,
) -> Result<(ActionKind, Option<String>, Vec<String>, String), SecurityError> {
    match tool_name {
        "Bash" | "exec_command" | "shell" => {
            let obj = tool_input.as_object().ok_or_else(|| {
                SecurityError::protocol(
                    "AG-PROTO-INVALID-TOOL-INPUT",
                    format!("工具 `{tool_name}` 的 `tool_input` 必须为 JSON 对象"),
                )
            })?;

            let cmd_str =
                if let Some(Value::String(s)) = obj.get("command").or_else(|| obj.get("cmd")) {
                    s.clone()
                } else if let Some(Value::Array(arr)) = obj.get("command") {
                    let parts: Result<Vec<String>, _> = arr
                        .iter()
                        .map(|v| {
                            v.as_str().map(|s| s.to_string()).ok_or_else(|| {
                                SecurityError::protocol(
                                    "AG-PROTO-INVALID-TOOL-INPUT",
                                    "command 数组包含非字符串元素",
                                )
                            })
                        })
                        .collect();
                    parts?.join(" ")
                } else {
                    return Err(SecurityError::protocol(
                        "AG-PROTO-MISSING-COMMAND",
                        format!("工具 `{tool_name}` 缺少字符串类型的 `command` 或 `cmd` 字段"),
                    ));
                };

            let summary = redact_secrets(&cmd_str);
            Ok((ActionKind::Shell, Some(cmd_str), Vec::new(), summary))
        }
        "apply_patch" => {
            // Phase 0 实测：Codex 0.160.1 的 apply_patch 在 PreToolUse 中传入 tool_input.command！
            // 同时兼容 tool_input.patch、tool_input.input 或直接字符串。
            let patch_text = match tool_input {
                Value::String(s) => s.clone(),
                Value::Object(obj) => obj
                    .get("command")
                    .or_else(|| obj.get("patch"))
                    .or_else(|| obj.get("input"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| {
                        SecurityError::protocol(
                            "AG-PROTO-MISSING-PATCH",
                            "工具 `apply_patch` 的 `tool_input` 缺少 `command`/`patch`/`input` 字符串",
                        )
                    })?,
                _ => {
                    return Err(SecurityError::protocol(
                        "AG-PROTO-INVALID-TOOL-INPUT",
                        "工具 `apply_patch` 的 `tool_input` 类型非法",
                    ))
                }
            };

            let paths = extract_apply_patch_paths(&patch_text);
            let summary = redact_secrets(&patch_text);
            Ok((ActionKind::FilePatch, Some(patch_text), paths, summary))
        }
        name if name.starts_with("mcp__") => {
            let raw_json = serde_json::to_string(tool_input).unwrap_or_default();
            let summary = redact_secrets(&format!("{name}({raw_json})"));
            Ok((ActionKind::McpTool, None, Vec::new(), summary))
        }
        _ => {
            let raw_json = serde_json::to_string(tool_input).unwrap_or_default();
            let summary = redact_secrets(&format!("{tool_name}({raw_json})"));
            Ok((ActionKind::Unknown, None, Vec::new(), summary))
        }
    }
}

/// 从 `*** Begin Patch` 格式补丁中提取涉及的目标文件路径。
pub fn extract_apply_patch_paths(patch_text: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in patch_text.lines() {
        let trimmed = line.trim();
        for prefix in [
            "*** Add File:",
            "*** Update File:",
            "*** Delete File:",
            "*** Move to:",
        ] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let path = rest.trim();
                if !path.is_empty() && !paths.contains(&path.to_string()) {
                    paths.push(path.to_string());
                }
            }
        }
    }
    paths
}

/// 端到端处理一次 Codex `PreToolUse` Hook 调用（使用默认内置策略引擎）：
/// - 返回 `(Decision, Option<String>)`，其中 `Option<String>` 为需要写往 `stdout` 的单行 JSON（Allow 时为 `None`）。
/// - 发生任何协议解析错误时，自动执行 Fail-Closed 返回显式 `Deny` 决策与合法的 Codex 拒绝 JSON。
pub fn handle_codex_pre_tool_use_bytes(bytes: &[u8]) -> (Decision, Option<String>) {
    handle_codex_pre_tool_use_bytes_with_engine(bytes, default_policy_engine())
}

/// 使用指定 `PolicyEngine` 端到端处理一次 Codex `PreToolUse` Hook 调用。
pub fn handle_codex_pre_tool_use_bytes_with_engine(
    bytes: &[u8],
    engine: &PolicyEngine,
) -> (Decision, Option<String>) {
    match parse_codex_pre_tool_use_bytes(bytes) {
        Ok(event) => {
            let decision = engine.evaluate(&event);
            let stdout_line = match decision.enforcement {
                Enforcement::Deny => Some(
                    CodexPreToolUseWireOutput::deny(&decision.display_message)
                        .to_single_line_json(),
                ),
                Enforcement::Allow | Enforcement::Observe | Enforcement::Unsupported => None,
            };
            (decision, stdout_line)
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
            let decision = Decision::fail_closed_deny("unknown", code, detail);
            let stdout_line =
                CodexPreToolUseWireOutput::deny(&decision.display_message).to_single_line_json();
            (decision, Some(stdout_line))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/codex")
    }

    #[test]
    fn test_all_16_codex_fixtures_never_panic_and_produce_valid_protocol_output() {
        let dir = fixtures_dir();
        let mut count = 0;
        for entry in fs::read_dir(&dir).expect("fixtures directory must exist") {
            let entry = entry.expect("valid dir entry");
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            count += 1;
            let bytes = fs::read(&path).expect("read fixture file");
            let (decision, stdout_json) = handle_codex_pre_tool_use_bytes(&bytes);
            if let Some(ref line) = stdout_json {
                assert!(!line.contains('\n'), "stdout JSON must be single-line");
                let parsed: CodexPreToolUseWireOutput =
                    serde_json::from_str(line).expect("Deny JSON must match Codex wire contract");
                assert_eq!(parsed.hook_specific_output.hook_event_name, "PreToolUse");
                assert_eq!(parsed.hook_specific_output.permission_decision, "deny");
                assert!(!parsed
                    .hook_specific_output
                    .permission_decision_reason
                    .trim()
                    .is_empty());
            } else {
                assert_ne!(decision.enforcement, Enforcement::Deny);
            }
        }
        assert!(
            count >= 15,
            "Must test at least 15 fixtures (found {count})"
        );
    }

    #[test]
    fn test_fixture_04_block_sentinel_triggers_deny_json() {
        let bytes = fs::read(fixtures_dir().join("04_wsl2_bash_block_sentinel.json")).unwrap();
        let (decision, stdout_json) = handle_codex_pre_tool_use_bytes(&bytes);
        assert_eq!(decision.enforcement, Enforcement::Deny);
        assert_eq!(decision.matched_rule_ids, vec!["TEST-DENY-001".to_string()]);
        assert!(stdout_json.is_some());
    }

    #[test]
    fn test_fixture_07_apply_patch_extracts_command_and_paths() {
        let bytes = fs::read(fixtures_dir().join("07_wsl2_apply_patch_safe.json")).unwrap();
        let ev = parse_codex_pre_tool_use_bytes(&bytes).expect("must parse apply_patch");
        assert_eq!(ev.action_kind, ActionKind::FilePatch);
        assert_eq!(ev.target_paths, vec!["src/hello.rs".to_string()]);
    }

    #[test]
    fn test_fixture_11_secret_never_leaks_in_event_or_error() {
        let bytes = fs::read(fixtures_dir().join("11_mcp_tool_with_secret_arg.json")).unwrap();
        let ev = parse_codex_pre_tool_use_bytes(&bytes).expect("must parse mcp tool");
        assert!(!ev.redacted_summary.contains("SECRET_TEST_XYZ"));
        assert!(!ev.redacted_summary.contains("FAKE_TEST_KEY"));

        // Even if JSON is corrupted mid-secret, error message must redact SECRET_TEST_XYZ
        let broken = br#"{"session_id":"1","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"SECRET_TEST_XYZ_LEAK"#;
        let (decision, stdout_json) = handle_codex_pre_tool_use_bytes(broken);
        assert_eq!(decision.enforcement, Enforcement::Deny);
        assert!(!decision.display_message.contains("SECRET_TEST_XYZ"));
        assert!(!stdout_json.unwrap().contains("SECRET_TEST_XYZ"));
    }

    #[test]
    fn test_edge_cases_empty_invalid_utf8_and_oversize_fail_closed() {
        // 1. Empty input
        let (d_empty, out_empty) = handle_codex_pre_tool_use_bytes(b"   ");
        assert_eq!(d_empty.enforcement, Enforcement::Deny);
        assert_eq!(d_empty.reason_code, "AG-PROTO-EMPTY-STDIN");
        assert!(out_empty.is_some());

        // 2. Invalid UTF-8
        let (d_utf8, out_utf8) = handle_codex_pre_tool_use_bytes(&[0xff, 0xfe, 0xfd]);
        assert_eq!(d_utf8.enforcement, Enforcement::Deny);
        assert_eq!(d_utf8.reason_code, "AG-PROTO-INVALID-UTF8");
        assert!(out_utf8.is_some());

        // 3. Oversized input (> max_bytes)
        let big = vec![b'a'; 1025];
        let err = read_and_parse_codex_pre_tool_use(big.as_slice(), 1024).unwrap_err();
        assert!(matches!(
            err,
            SecurityError::ProtocolError { ref code, .. } if code == "AG-PROTO-OVERSIZE"
        ));
    }
}
