//! AI Guard (`packages/security`) — 跨平台安全领域模型、脱敏引擎与策略裁决内核。
//!
//! 安全铁律（AGENTS.md 第 4.1 条）：
//! - 默认安全、失败可控（Fail-Closed）：在解析失败、未知关键结构或内部异常时，
//!   必须默认阻断（Deny），严禁因异常而默认放行（Fail-Open）。
//! - 敏感信息零残留：任何错误、日志与事件摘要均必须经过 `redact_secrets` 脱敏。

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use thiserror::Error;

/// 受管目标环境分类（宿主机 Windows vs WSL2 Linux 发行版）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnvironmentKind {
    WindowsHost,
    Wsl2Distro { distro_name: String },
}

impl EnvironmentKind {
    /// 根据工作目录或路径特征自动推断所属目标环境。
    pub fn infer_from_path(path: &str) -> Self {
        let trimmed = path.trim();
        let is_windows_drive = trimmed.len() >= 2
            && trimmed.as_bytes()[0].is_ascii_alphabetic()
            && trimmed.as_bytes()[1] == b':'
            || trimmed.starts_with("\\\\");
        if is_windows_drive {
            Self::WindowsHost
        } else {
            let distro = std::env::var("WSL_DISTRO_NAME").unwrap_or_else(|_| "Ubuntu".to_string());
            Self::Wsl2Distro {
                distro_name: distro,
            }
        }
    }

    pub fn default_target_id(&self) -> String {
        match self {
            Self::WindowsHost => "host:windows".to_string(),
            Self::Wsl2Distro { distro_name } => format!("wsl2:{distro_name}"),
        }
    }
}

/// 触发事件的客户端表面形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientSurface {
    CodexDesktopApp,
    CodexCli,
    CodexAppServerDaemon,
    Unknown,
}

/// 标准化后的工具动作类型（与具体 Agent 协议解耦）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Shell,
    FilePatch,
    McpTool,
    LocalTool,
    Unknown,
}

/// 能力覆盖等级，用于诚实披露防护边界。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLevel {
    Supported,
    Partial,
    Unsupported,
}

/// 策略执行动作（裁决结果）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    Allow,
    Deny,
    Observe,
    Unsupported,
}

/// 标准化安全事件（不泄漏 Codex 原始 JSON 或未脱敏参数）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionEvent {
    pub target_id: String,
    pub environment_kind: EnvironmentKind,
    pub client_surface: ClientSurface,
    pub agent: String,
    pub session_id: String,
    pub turn_id: String,
    pub tool_use_id: String,
    pub tool_name: String,
    pub action_kind: ActionKind,
    pub cwd: String,
    #[serde(skip_serializing)]
    pub normalized_command: Option<String>,
    pub target_paths: Vec<String>,
    pub redacted_summary: String,
}

/// 标准化安全裁决结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub target_id: String,
    pub enforcement: Enforcement,
    pub matched_rule_ids: Vec<String>,
    pub reason_code: String,
    pub display_message: String,
    pub policy_revision: String,
    pub coverage: CoverageLevel,
}

impl Decision {
    /// 生成显式 Fail-Closed 阻断决策。
    pub fn fail_closed_deny(
        target_id: impl Into<String>,
        reason_code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let safe_msg = redact_secrets(&message.into());
        Self {
            target_id: target_id.into(),
            enforcement: Enforcement::Deny,
            matched_rule_ids: vec!["FAIL-CLOSED-DEFAULT".to_string()],
            reason_code: reason_code.into(),
            display_message: format!("[AI卫士安全阻断] {safe_msg}"),
            policy_revision: "phase1-builtin-v1".to_string(),
            coverage: CoverageLevel::Supported,
        }
    }
}

/// 安全核心统一错误码体系（绝不攜带未脱敏原始输入）。
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityError {
    #[error("[{code}] {redacted_detail}")]
    ProtocolError {
        code: String,
        redacted_detail: String,
    },
    #[error("[{code}] {redacted_detail}")]
    EvaluationError {
        code: String,
        redacted_detail: String,
    },
}

impl SecurityError {
    pub fn protocol(code: impl Into<String>, detail: impl AsRef<str>) -> Self {
        Self::ProtocolError {
            code: code.into(),
            redacted_detail: redact_secrets(detail.as_ref()),
        }
    }
}

/// 敏感信息脱敏器：对 API Key、Token、私钥块、Bearer 凭据及内联密钥赋值执行确定性脱敏。
pub fn redact_secrets(input: &str) -> String {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        vec![
            // Private Key PEM block
            (
                Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
                    .expect("valid regex"),
                "[REDACTED_PRIVATE_KEY]",
            ),
            // OpenAI / Anthropic / Standard sk- keys
            (
                Regex::new(r"\bsk-[A-Za-z0-9_-]{8,}\b").expect("valid regex"),
                "sk-[REDACTED]",
            ),
            // GitHub tokens
            (
                Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{8,}\b")
                    .expect("valid regex"),
                "gh-[REDACTED]",
            ),
            // AWS Access Key ID
            (
                Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b").expect("valid regex"),
                "AKIA[REDACTED]",
            ),
            // Slack tokens
            (
                Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{8,}\b").expect("valid regex"),
                "xox-[REDACTED]",
            ),
            // Explicit test secret marker SECRET_TEST_XYZ*
            (
                Regex::new(r"SECRET_TEST_XYZ[A-Za-z0-9_-]*").expect("valid regex"),
                "[REDACTED_TEST_SECRET]",
            ),
            // Bearer token
            (
                Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*").expect("valid regex"),
                "Bearer [REDACTED]",
            ),
            // Key/Value assignments for API_KEY, SECRET, TOKEN, PASSWORD
            (
                Regex::new(r#"(?i)\b([A-Za-z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY)[A-Za-z0-9_]*)\s*([=:])\s*("[^"]*"|'[^']*'|[^\s"',;]+)"#)
                    .expect("valid regex"),
                "$1$2[REDACTED]",
            ),
        ]
    });

    let mut out = input.to_string();
    for (re, replacement) in patterns {
        out = re.replace_all(&out, *replacement).into_owned();
    }
    // 限制摘要最大长度，防止超长 payload 污染日志或 UI
    const MAX_REDACTED_CHARS: usize = 512;
    if out.chars().count() > MAX_REDACTED_CHARS {
        let truncated: String = out.chars().take(MAX_REDACTED_CHARS).collect();
        format!("{truncated}...[TRUNCATED]")
    } else {
        out
    }
}

/// Phase 1（M1 + M2）最小确定性安全裁决引擎。
///
/// - 内置确定性阻断规则 `TEST-DENY-001`（匹配 `AI_GUARD_BLOCK_ME`），用于 M2 真实拦截 E2E 验证与 `self-test`。
/// - 对未知动作类型（`ActionKind::Unknown`）明确标记 `CoverageLevel::Unsupported`。
/// - 对空命令或缺失关键载荷的异常事件执行 Fail-Closed `Deny`。
pub fn evaluate_action_event(event: &ActionEvent) -> Decision {
    // 1. 检查关键载荷是否缺失（Fail-Closed）
    match event.action_kind {
        ActionKind::Shell | ActionKind::FilePatch => {
            let cmd = event.normalized_command.as_deref().unwrap_or("").trim();
            if cmd.is_empty() {
                return Decision::fail_closed_deny(
                    &event.target_id,
                    "AG-SEC-EMPTY-PAYLOAD",
                    format!(
                        "工具 `{}` 缺少可分析的命令或补丁载荷，触发默认安全阻断（Fail-Closed）",
                        event.tool_name
                    ),
                );
            }

            // 2. 确定性测试拦截规则 TEST-DENY-001（匹配 AI_GUARD_BLOCK_ME）
            if cmd.contains("AI_GUARD_BLOCK_ME") {
                return Decision {
                    target_id: event.target_id.clone(),
                    enforcement: Enforcement::Deny,
                    matched_rule_ids: vec!["TEST-DENY-001".to_string()],
                    reason_code: "AG-RULE-TEST-DENY-001".to_string(),
                    display_message:
                        "[AI卫士阻断] 命中确定性阻断规则 TEST-DENY-001：检测到禁止执行的标记指令 AI_GUARD_BLOCK_ME"
                            .to_string(),
                    policy_revision: "phase1-builtin-v1".to_string(),
                    coverage: CoverageLevel::Supported,
                };
            }

            Decision {
                target_id: event.target_id.clone(),
                enforcement: Enforcement::Allow,
                matched_rule_ids: vec![],
                reason_code: "AG-ALLOW-DEFAULT".to_string(),
                display_message: "未命中阻断规则，允许执行".to_string(),
                policy_revision: "phase1-builtin-v1".to_string(),
                coverage: CoverageLevel::Supported,
            }
        }
        ActionKind::McpTool | ActionKind::LocalTool => {
            if event.redacted_summary.contains("AI_GUARD_BLOCK_ME") {
                return Decision {
                    target_id: event.target_id.clone(),
                    enforcement: Enforcement::Deny,
                    matched_rule_ids: vec!["TEST-DENY-001".to_string()],
                    reason_code: "AG-RULE-TEST-DENY-001".to_string(),
                    display_message:
                        "[AI卫士阻断] 命中确定性阻断规则 TEST-DENY-001：MCP/本地工具参数包含 AI_GUARD_BLOCK_ME"
                            .to_string(),
                    policy_revision: "phase1-builtin-v1".to_string(),
                    coverage: CoverageLevel::Supported,
                };
            }
            Decision {
                target_id: event.target_id.clone(),
                enforcement: Enforcement::Allow,
                matched_rule_ids: vec![],
                reason_code: "AG-ALLOW-MCP".to_string(),
                display_message: "MCP 工具调用未命中阻断规则，允许执行".to_string(),
                policy_revision: "phase1-builtin-v1".to_string(),
                coverage: CoverageLevel::Supported,
            }
        }
        ActionKind::Unknown => Decision {
            target_id: event.target_id.clone(),
            enforcement: Enforcement::Unsupported,
            matched_rule_ids: vec![],
            reason_code: "AG-UNSUPPORTED-TOOL".to_string(),
            display_message: format!(
                "工具 `{}` 当前属于未建模扩展工具类型（Coverage: Unsupported）",
                event.tool_name
            ),
            policy_revision: "phase1-builtin-v1".to_string(),
            coverage: CoverageLevel::Unsupported,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_secrets_removes_sensitive_tokens() {
        let raw = "export OPENAI_API_KEY=sk-proj-1234567890abcdef GITHUB_TOKEN=ghp_1234567890abcdef Authorization: Bearer SECRET_TEST_XYZ_999";
        let redacted = redact_secrets(raw);
        assert!(!redacted.contains("sk-proj-1234567890abcdef"));
        assert!(!redacted.contains("ghp_1234567890abcdef"));
        assert!(!redacted.contains("SECRET_TEST_XYZ"));
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_private_key_pem() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----";
        let redacted = redact_secrets(pem);
        assert_eq!(redacted, "[REDACTED_PRIVATE_KEY]");
    }

    #[test]
    fn test_evaluate_test_deny_001_blocks_marker() {
        let ev = ActionEvent {
            target_id: "wsl2:Ubuntu".to_string(),
            environment_kind: EnvironmentKind::Wsl2Distro {
                distro_name: "Ubuntu".to_string(),
            },
            client_surface: ClientSurface::CodexCli,
            agent: "codex".to_string(),
            session_id: "sess-1".to_string(),
            turn_id: "turn-1".to_string(),
            tool_use_id: "call-1".to_string(),
            tool_name: "Bash".to_string(),
            action_kind: ActionKind::Shell,
            cwd: "/tmp".to_string(),
            normalized_command: Some("echo AI_GUARD_BLOCK_ME && touch /tmp/s.txt".to_string()),
            target_paths: vec![],
            redacted_summary: "echo AI_GUARD_BLOCK_ME && touch /tmp/s.txt".to_string(),
        };
        let decision = evaluate_action_event(&ev);
        assert_eq!(decision.enforcement, Enforcement::Deny);
        assert_eq!(decision.matched_rule_ids, vec!["TEST-DENY-001".to_string()]);
        assert_eq!(decision.reason_code, "AG-RULE-TEST-DENY-001");
    }

    #[test]
    fn test_evaluate_empty_shell_command_fails_closed() {
        let ev = ActionEvent {
            target_id: "host:windows".to_string(),
            environment_kind: EnvironmentKind::WindowsHost,
            client_surface: ClientSurface::CodexDesktopApp,
            agent: "codex".to_string(),
            session_id: "sess-1".to_string(),
            turn_id: "turn-1".to_string(),
            tool_use_id: "call-1".to_string(),
            tool_name: "Bash".to_string(),
            action_kind: ActionKind::Shell,
            cwd: "C:\\Users\\demo".to_string(),
            normalized_command: Some("   ".to_string()),
            target_paths: vec![],
            redacted_summary: "".to_string(),
        };
        let decision = evaluate_action_event(&ev);
        assert_eq!(decision.enforcement, Enforcement::Deny);
        assert_eq!(decision.reason_code, "AG-SEC-EMPTY-PAYLOAD");
    }
}
