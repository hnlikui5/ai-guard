//! TOML 安全策略 Schema、静态校验器、可信快照回退与优先级裁决引擎（Phase 2 / M3）。
//!
//! 安全约束（PRD P2-T1 / M3-01）：
//! - 使用 `#[serde(deny_unknown_fields)]` 拒绝任何拼写错误或未知字段，严禁静默忽略导致规则放宽。
//! - 支持 `schema_version = 1`、`revision`、`mode`（`protect` | `observe`）、`[[rules]]`。
//! - 当主策略文件损坏或校验不通过时，自动回退至最近一次验证通过的可信快照（`snapshot_path`）；
//!   若无可用快照则在 Hook 侧显式返回 `Deny` 并附带 `AG-POLICY-001` 告警。

use crate::detectors::{analyze_event_coverage, BuiltinDetectorId};
use crate::{
    redact_secrets, ActionEvent, ActionKind, CoverageLevel, Decision, Enforcement, EnvironmentKind,
    SecurityError,
};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub const SUPPORTED_POLICY_SCHEMA_VERSION: u32 = 1;
pub const MAX_REGEX_PATTERN_LEN: usize = 2048;

/// 全局策略运行模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// 强制保护模式：命中 `Deny` 规则时真实阻断执行。
    Protect,
    /// 仅观察模式：命中 `Deny` 规则时转化为 `Observe`（记录告警与命中规则但不阻断，用于新规则灰度演练）。
    Observe,
}

/// 规则适用的操作系统范围（支持宿主机 Windows 与 WSL2 Linux 统一策略文件中的差异化规则）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsScope {
    All,
    Linux,
    Windows,
}

impl OsScope {
    pub fn matches_env(&self, env: &EnvironmentKind) -> bool {
        matches!(
            (self, env),
            (Self::All, _)
                | (Self::Linux, EnvironmentKind::Wsl2Distro { .. })
                | (Self::Windows, EnvironmentKind::WindowsHost)
        )
    }
}

/// 规则匹配器类型（受控 Rust 枚举，禁止不受限动态脚本）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// 内置高置信度跨平台检测器（如 `SHELL-DESTRUCTIVE-RM`、`PATH-SENSITIVE-CRED`）。
    BuiltinDetector,
    /// 命令或补丁文本包含指定子串（区分大小写）。
    CommandContains,
    /// 命令或补丁文本匹配受限正则表达式（开启 `size_limit` 防 ReDoS）。
    CommandRegex,
    /// 目标路径包含指定前缀或敏感片段。
    PathContains,
}

/// 单条安全策略规则定义。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: String,
    pub enabled: bool,
    pub priority: u32,
    pub name: String,
    pub agent: String,
    pub tool: String,
    pub os_scope: OsScope,
    pub match_kind: MatchKind,
    pub match_value: String,
    pub effect: Enforcement,
    pub reason_code: String,
    pub message: String,
}

/// 顶层 `policy.toml` 配置结构。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub schema_version: u32,
    pub revision: String,
    pub mode: PolicyMode,
    pub rules: Vec<PolicyRule>,
}

/// 编译并校验通过的策略引擎实例。
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    config: PolicyConfig,
    sorted_enabled_rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// 生成内置默认高置信度跨平台策略引擎（覆盖 Windows PowerShell/CMD 与 WSL2 Bash/sh）。
    pub fn default_builtin() -> Self {
        let cfg = default_builtin_policy_config();
        Self::from_config(cfg).expect("builtin policy config must be valid")
    }

    /// 从 `PolicyConfig` 构建并执行静态合法性校验。
    pub fn from_config(config: PolicyConfig) -> Result<Self, SecurityError> {
        if config.schema_version != SUPPORTED_POLICY_SCHEMA_VERSION {
            return Err(SecurityError::protocol(
                "AG-POLICY-001",
                format!(
                    "不支持的 policy schema_version `{}`（当前仅支持 {}）",
                    config.schema_version, SUPPORTED_POLICY_SCHEMA_VERSION
                ),
            ));
        }

        if config.revision.trim().is_empty() {
            return Err(SecurityError::protocol(
                "AG-POLICY-001",
                "策略字段 `revision` 不能为空",
            ));
        }

        let mut seen_ids = HashSet::new();
        for rule in &config.rules {
            if rule.id.trim().is_empty() {
                return Err(SecurityError::protocol(
                    "AG-POLICY-001",
                    "策略规则 `id` 不能为空字符串",
                ));
            }
            if !seen_ids.insert(rule.id.clone()) {
                return Err(SecurityError::protocol(
                    "AG-POLICY-001",
                    format!("策略存在重复的规则 ID `{}`", rule.id),
                ));
            }
            if rule.reason_code.trim().is_empty() || rule.message.trim().is_empty() {
                return Err(SecurityError::protocol(
                    "AG-POLICY-001",
                    format!("规则 `{}` 的 `reason_code` 与 `message` 不能为空", rule.id),
                ));
            }
            if rule.effect == Enforcement::Unsupported {
                return Err(SecurityError::protocol(
                    "AG-POLICY-001",
                    format!("规则 `{}` 不允许将 `effect` 配置为 `unsupported`", rule.id),
                ));
            }

            // 校验每种 MatchKind 的 match_value 合法性
            match rule.match_kind {
                MatchKind::BuiltinDetector => {
                    if BuiltinDetectorId::from_name(&rule.match_value).is_none() {
                        return Err(SecurityError::protocol(
                            "AG-POLICY-001",
                            format!(
                                "规则 `{}` 引用了未知的内置检测器 `{}`",
                                rule.id, rule.match_value
                            ),
                        ));
                    }
                }
                MatchKind::CommandContains | MatchKind::PathContains => {
                    if rule.match_value.trim().is_empty() {
                        return Err(SecurityError::protocol(
                            "AG-POLICY-001",
                            format!("规则 `{}` 的匹配值 `match_value` 不能为空", rule.id),
                        ));
                    }
                }
                MatchKind::CommandRegex => {
                    if rule.match_value.trim().is_empty()
                        || rule.match_value.len() > MAX_REGEX_PATTERN_LEN
                    {
                        return Err(SecurityError::protocol(
                            "AG-POLICY-001",
                            format!("规则 `{}` 的正则表达式为空或超过长度上限", rule.id),
                        ));
                    }
                    RegexBuilder::new(&rule.match_value)
                        .size_limit(1 << 20)
                        .dfa_size_limit(1 << 20)
                        .build()
                        .map_err(|e| {
                            SecurityError::protocol(
                                "AG-POLICY-001",
                                format!("规则 `{}` 的正则表达式编译失败: {e}", rule.id),
                            )
                        })?;
                }
            }
        }

        let mut sorted_enabled_rules: Vec<PolicyRule> =
            config.rules.iter().filter(|r| r.enabled).cloned().collect();
        sorted_enabled_rules
            .sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));

        Ok(Self {
            config,
            sorted_enabled_rules,
        })
    }

    /// 从 TOML 文本解析并校验策略。
    pub fn from_toml_str(toml_str: &str) -> Result<Self, SecurityError> {
        let cfg: PolicyConfig = toml::from_str(toml_str).map_err(|e| {
            SecurityError::protocol("AG-POLICY-001", format!("解析 policy.toml 语法失败: {e}"))
        })?;
        Self::from_config(cfg)
    }

    /// 从 TOML 文件路径读取并校验策略。
    pub fn from_toml_path(path: &Path) -> Result<Self, SecurityError> {
        let content = fs::read_to_string(path).map_err(|e| {
            SecurityError::protocol(
                "AG-POLICY-001",
                format!("读取策略文件 `{}` 失败: {e}", path.display()),
            )
        })?;
        Self::from_toml_str(&content)
    }

    /// 从主策略路径加载；若主策略损坏且提供了可信快照路径，则自动回退至可信快照并返回告警说明。
    /// 若主策略验证通过且提供了 `snapshot_path`，则自动刷新可信快照。
    pub fn load_with_snapshot_fallback(
        primary_path: &Path,
        snapshot_path: Option<&Path>,
    ) -> Result<(Self, Option<String>), SecurityError> {
        let primary_res = fs::read_to_string(primary_path)
            .map_err(|e| {
                SecurityError::protocol(
                    "AG-POLICY-001",
                    format!("读取主策略文件 `{}` 失败: {e}", primary_path.display()),
                )
            })
            .and_then(|s| Self::from_toml_str(&s));

        match primary_res {
            Ok(engine) => {
                if let Some(snap) = snapshot_path {
                    if let Ok(raw) = fs::read(primary_path) {
                        let _ = write_atomic_snapshot(snap, &raw);
                    }
                }
                Ok((engine, None))
            }
            Err(primary_err) => {
                if let Some(snap) = snapshot_path {
                    if snap.is_file() {
                        if let Ok(snap_str) = fs::read_to_string(snap) {
                            if let Ok(snap_engine) = Self::from_toml_str(&snap_str) {
                                let warn_msg = format!(
                                    "主策略文件校验失败（{}），已自动回退至可信策略快照 `{}` (revision={})",
                                    primary_err,
                                    snap.display(),
                                    snap_engine.config.revision
                                );
                                return Ok((snap_engine, Some(warn_msg)));
                            }
                        }
                    }
                }
                Err(primary_err)
            }
        }
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    pub fn policy_revision(&self) -> &str {
        &self.config.revision
    }

    /// 对标准化 `ActionEvent` 执行确定性策略评估。
    pub fn evaluate(&self, event: &ActionEvent) -> Decision {
        // 1. 基础完整性 Fail-Closed 检查
        if matches!(event.action_kind, ActionKind::Shell | ActionKind::FilePatch) {
            let cmd = event.normalized_command.as_deref().unwrap_or("").trim();
            if cmd.is_empty() {
                return Decision {
                    target_id: event.target_id.clone(),
                    enforcement: Enforcement::Deny,
                    matched_rule_ids: vec!["FAIL-CLOSED-EMPTY-PAYLOAD".to_string()],
                    reason_code: "AG-SEC-EMPTY-PAYLOAD".to_string(),
                    display_message: format!(
                        "[AI卫士安全阻断] 工具 `{}` 缺少可分析的命令或补丁载荷，触发默认安全阻断（Fail-Closed）",
                        event.tool_name
                    ),
                    policy_revision: self.config.revision.clone(),
                    coverage: CoverageLevel::Supported,
                };
            }
        }

        if event.action_kind == ActionKind::Unknown {
            return Decision {
                target_id: event.target_id.clone(),
                enforcement: Enforcement::Unsupported,
                matched_rule_ids: vec![],
                reason_code: "AG-UNSUPPORTED-TOOL".to_string(),
                display_message: format!(
                    "工具 `{}` 当前属于未建模扩展工具类型（Coverage: Unsupported）",
                    event.tool_name
                ),
                policy_revision: self.config.revision.clone(),
                coverage: CoverageLevel::Unsupported,
            };
        }

        let coverage = analyze_event_coverage(event);
        let mut matched_rule_ids = Vec::new();
        let mut first_winning_rule: Option<&PolicyRule> = None;

        for rule in &self.sorted_enabled_rules {
            if !rule_matches_context(rule, event) {
                continue;
            }
            if rule_matches_payload(rule, event) {
                matched_rule_ids.push(rule.id.clone());
                if first_winning_rule.is_none() {
                    first_winning_rule = Some(rule);
                }
            }
        }

        if let Some(winner) = first_winning_rule {
            let effective_enforcement = match (self.config.mode, winner.effect) {
                (PolicyMode::Observe, Enforcement::Deny) => Enforcement::Observe,
                (_, eff) => eff,
            };
            let prefix = match effective_enforcement {
                Enforcement::Deny => "[AI卫士阻断]",
                Enforcement::Observe => "[AI卫士观察告警]",
                Enforcement::Allow => "[AI卫士放行]",
                Enforcement::Unsupported => "[AI卫士未覆盖]",
            };
            return Decision {
                target_id: event.target_id.clone(),
                enforcement: effective_enforcement,
                matched_rule_ids,
                reason_code: winner.reason_code.clone(),
                display_message: format!(
                    "{} {} (规则: {}, 原因码: {})",
                    prefix,
                    redact_secrets(&winner.message),
                    winner.id,
                    winner.reason_code
                ),
                policy_revision: self.config.revision.clone(),
                coverage,
            };
        }

        Decision {
            target_id: event.target_id.clone(),
            enforcement: Enforcement::Allow,
            matched_rule_ids: vec![],
            reason_code: "AG-ALLOW-DEFAULT".to_string(),
            display_message: "未命中阻断规则，允许执行".to_string(),
            policy_revision: self.config.revision.clone(),
            coverage,
        }
    }
}

fn rule_matches_context(rule: &PolicyRule, event: &ActionEvent) -> bool {
    if !rule.os_scope.matches_env(&event.environment_kind) {
        return false;
    }
    if rule.agent != "*" && !rule.agent.eq_ignore_ascii_case(&event.agent) {
        return false;
    }
    if rule.tool != "*" {
        if let Some(prefix) = rule.tool.strip_suffix('*') {
            if !event.tool_name.starts_with(prefix) {
                return false;
            }
        } else if !rule.tool.eq_ignore_ascii_case(&event.tool_name) {
            return false;
        }
    }
    true
}

fn rule_matches_payload(rule: &PolicyRule, event: &ActionEvent) -> bool {
    match rule.match_kind {
        MatchKind::BuiltinDetector => BuiltinDetectorId::from_name(&rule.match_value)
            .map(|d| d.matches(event))
            .unwrap_or(false),
        MatchKind::CommandContains => {
            let text = event
                .normalized_command
                .as_deref()
                .unwrap_or(&event.redacted_summary);
            text.contains(&rule.match_value)
        }
        MatchKind::CommandRegex => {
            let text = event
                .normalized_command
                .as_deref()
                .unwrap_or(&event.redacted_summary);
            RegexBuilder::new(&rule.match_value)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
                .map(|re| re.is_match(text))
                .unwrap_or(true) // Fail-Closed on unexpected regex runtime failure
        }
        MatchKind::PathContains => {
            let needle = rule.match_value.replace('\\', "/").to_ascii_lowercase();
            event
                .target_paths
                .iter()
                .any(|p| p.replace('\\', "/").to_ascii_lowercase().contains(&needle))
                || event
                    .normalized_command
                    .as_deref()
                    .unwrap_or("")
                    .replace('\\', "/")
                    .to_ascii_lowercase()
                    .contains(&needle)
        }
    }
}

fn write_atomic_snapshot(snap_path: &Path, content: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = snap_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = snap_path.with_extension("tmp");
    fs::write(&tmp, content)?;
    fs::rename(&tmp, snap_path)
}

/// 生成 V0.1 内置默认跨平台策略配置（同时覆盖 Windows PowerShell/CMD 与 WSL2 Linux Bash/sh）。
pub fn default_builtin_policy_config() -> PolicyConfig {
    PolicyConfig {
        schema_version: SUPPORTED_POLICY_SCHEMA_VERSION,
        revision: "v0.1-default-r1".to_string(),
        mode: PolicyMode::Protect,
        rules: vec![
            PolicyRule {
                id: "TEST-DENY-001".to_string(),
                enabled: true,
                priority: 10,
                name: "确定性自检与 E2E 测试阻断规则".to_string(),
                agent: "*".to_string(),
                tool: "*".to_string(),
                os_scope: OsScope::All,
                match_kind: MatchKind::BuiltinDetector,
                match_value: "TEST-DENY-001".to_string(),
                effect: Enforcement::Deny,
                reason_code: "AG-RULE-TEST-DENY-001".to_string(),
                message: "命中确定性阻断规则 TEST-DENY-001：检测到禁止执行的标记指令 AI_GUARD_BLOCK_ME".to_string(),
            },
            PolicyRule {
                id: "SHELL-DISK-WIPE".to_string(),
                enabled: true,
                priority: 20,
                name: "跨平台磁盘格式化与块设备擦除阻断".to_string(),
                agent: "*".to_string(),
                tool: "Bash".to_string(),
                os_scope: OsScope::All,
                match_kind: MatchKind::BuiltinDetector,
                match_value: "SHELL-DISK-WIPE".to_string(),
                effect: Enforcement::Deny,
                reason_code: "AG-RULE-DISK-WIPE".to_string(),
                message: "禁止执行磁盘格式化、分区表破坏或底层块设备擦除命令（mkfs/fdisk/dd/Format-Volume/Clear-Disk/diskpart）".to_string(),
            },
            PolicyRule {
                id: "SHELL-DESTRUCTIVE-RM".to_string(),
                enabled: true,
                priority: 30,
                name: "跨平台高危目录递归强制删除阻断".to_string(),
                agent: "*".to_string(),
                tool: "Bash".to_string(),
                os_scope: OsScope::All,
                match_kind: MatchKind::BuiltinDetector,
                match_value: "SHELL-DESTRUCTIVE-RM".to_string(),
                effect: Enforcement::Deny,
                reason_code: "AG-RULE-DESTRUCTIVE-RM".to_string(),
                message: "禁止对根目录、用户主目录、上级目录或系统关键路径执行递归强制删除（rm -rf / Remove-Item -Recurse / rmdir /s）".to_string(),
            },
            PolicyRule {
                id: "SHELL-PIPE-EXEC".to_string(),
                enabled: true,
                priority: 40,
                name: "跨平台远程脚本下载/解码即执行阻断".to_string(),
                agent: "*".to_string(),
                tool: "Bash".to_string(),
                os_scope: OsScope::All,
                match_kind: MatchKind::BuiltinDetector,
                match_value: "SHELL-PIPE-EXEC".to_string(),
                effect: Enforcement::Deny,
                reason_code: "AG-RULE-PIPE-EXEC".to_string(),
                message: "禁止将远程下载或 Base64 解码内容直接通过管道交由解释器执行（curl|sh / iwr|iex / powershell -enc / certutil）".to_string(),
            },
            PolicyRule {
                id: "PATH-SENSITIVE-CRED".to_string(),
                enabled: true,
                priority: 50,
                name: "跨平台敏感凭据文件访问与工作区路径穿越阻断".to_string(),
                agent: "*".to_string(),
                tool: "*".to_string(),
                os_scope: OsScope::All,
                match_kind: MatchKind::BuiltinDetector,
                match_value: "PATH-SENSITIVE-CRED".to_string(),
                effect: Enforcement::Deny,
                reason_code: "AG-RULE-SENSITIVE-PATH".to_string(),
                message: "禁止读取或修改敏感凭据路径（.ssh/.aws/.gnupg/.codex/auth.json/.env/*.pem/*.key）或跨越工作区根目录进行路径穿越".to_string(),
            },
            PolicyRule {
                id: "GIT-DANGEROUS-OP".to_string(),
                enabled: true,
                priority: 60,
                name: "高危不可逆 Git 操作阻断".to_string(),
                agent: "*".to_string(),
                tool: "Bash".to_string(),
                os_scope: OsScope::All,
                match_kind: MatchKind::BuiltinDetector,
                match_value: "GIT-DANGEROUS-OP".to_string(),
                effect: Enforcement::Deny,
                reason_code: "AG-RULE-GIT-DANGEROUS".to_string(),
                message: "禁止执行可能导致未提交代码丢失或远端历史覆写的高危 Git 命令（git reset --hard / git clean -fdx / git push --force）".to_string(),
            },
        ],
    }
}
