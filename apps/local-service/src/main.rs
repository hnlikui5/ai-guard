mod cli;

use ai_guard_agent_adapters::{
    extract_apply_patch_paths, handle_codex_pre_tool_use_bytes, CodexPreToolUseWireOutput,
    MAX_HOOK_STDIN_BYTES,
};
use ai_guard_security::{
    evaluate_action_event, redact_secrets, ActionEvent, ActionKind, ClientSurface, Decision,
    EnvironmentKind,
};
use clap::Parser;
use cli::{Cli, CodexHookEvents, Commands, HookAgents, RuleSubcommands};
use serde::Serialize;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor { target, json } => run_doctor(&target, json),
        Commands::Rule { subcommand } => match subcommand {
            RuleSubcommands::Test {
                agent,
                tool,
                input,
                cwd,
                json,
            } => run_rule_test(&agent, &tool, &input, &cwd, json),
        },
        Commands::Hook { agent } => match agent {
            HookAgents::Codex { event } => match event {
                CodexHookEvents::PreToolUse => run_codex_pre_tool_use_hook(),
            },
        },
    }
}

#[derive(Debug, Serialize)]
struct DoctorTargetReport {
    target_id: String,
    environment_kind: EnvironmentKind,
    codex_home: String,
    codex_home_exists: bool,
    config_toml_exists: bool,
    hook_configured_in_toml: bool,
    hook_trusted_in_toml: bool,
    protection_state: String,
    real_interception_verified: bool,
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    schema_version: u32,
    ai_guard_version: &'static str,
    overall_status: String,
    targets: Vec<DoctorTargetReport>,
}

fn run_doctor(target_filter: &str, as_json: bool) {
    let mut targets = Vec::new();
    let filter = target_filter.trim().to_ascii_lowercase();

    // 1. 探测 WSL2 当前环境目标
    if filter == "all" || filter.starts_with("wsl2") {
        let distro = std::env::var("WSL_DISTRO_NAME").unwrap_or_else(|_| "Ubuntu".to_string());
        let wsl_home = std::env::var("CODEX_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/home/ai-li".to_string());
                PathBuf::from(home).join(".codex")
            });
        targets.push(inspect_codex_target(
            format!("wsl2:{distro}"),
            EnvironmentKind::Wsl2Distro {
                distro_name: distro,
            },
            &wsl_home,
        ));
    }

    // 2. 探测 Windows 宿主机环境目标（支持在 Windows 原生或 WSL2 /mnt/c 下只读探测）
    if filter == "all" || filter == "host" || filter == "host:windows" {
        if let Some(win_codex_home) = discover_windows_host_codex_home() {
            targets.push(inspect_codex_target(
                "host:windows".to_string(),
                EnvironmentKind::WindowsHost,
                &win_codex_home,
            ));
        } else {
            targets.push(DoctorTargetReport {
                target_id: "host:windows".to_string(),
                environment_kind: EnvironmentKind::WindowsHost,
                codex_home: "C:\\Users\\<User>\\.codex".to_string(),
                codex_home_exists: false,
                config_toml_exists: false,
                hook_configured_in_toml: false,
                hook_trusted_in_toml: false,
                protection_state: "unknown".to_string(),
                real_interception_verified: false,
                limitations: vec!["未检测到可访问的 Windows 宿主机 .codex 目录".to_string()],
            });
        }
    }

    let overall_status = if targets.is_empty() {
        "warning".to_string()
    } else {
        "ok".to_string()
    };

    let report = DoctorReport {
        schema_version: 1,
        ai_guard_version: env!("CARGO_PKG_VERSION"),
        overall_status,
        targets,
    };

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("AI卫士（AI Guard）v{} 诊断报告", report.ai_guard_version);
        for t in &report.targets {
            println!(
                "- [{}] codex_home={} exists={} config.toml={} state={} verified={}",
                t.target_id,
                t.codex_home,
                t.codex_home_exists,
                t.config_toml_exists,
                t.protection_state,
                t.real_interception_verified
            );
        }
    }
}

fn discover_windows_host_codex_home() -> Option<PathBuf> {
    if cfg!(windows) {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            return Some(PathBuf::from(profile).join(".codex"));
        }
    }
    let mnt_c_users = PathBuf::from("/mnt/c/Users");
    let mut fallback = None;
    if let Ok(entries) = std::fs::read_dir(&mnt_c_users) {
        for entry in entries.flatten() {
            let user_name = entry.file_name().to_string_lossy().into_owned();
            if user_name.starts_with("CodexSandbox")
                || matches!(
                    user_name.as_str(),
                    "Public" | "Default" | "Default User" | "All Users"
                )
            {
                continue;
            }
            let candidate = entry.path().join(".codex");
            if candidate.join("config.toml").is_file() {
                return Some(candidate);
            }
            if candidate.is_dir() && fallback.is_none() {
                fallback = Some(candidate);
            }
        }
    }
    fallback
}

fn inspect_codex_target(
    target_id: String,
    environment_kind: EnvironmentKind,
    codex_home: &Path,
) -> DoctorTargetReport {
    let codex_home_exists = codex_home.is_dir();
    let config_path = codex_home.join("config.toml");
    let config_toml_exists = config_path.is_file();

    let mut hook_configured_in_toml = false;
    let mut hook_trusted_in_toml = false;
    if config_toml_exists {
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            hook_configured_in_toml =
                content.contains("hooks.PreToolUse") && content.contains("ai-guard");
            hook_trusted_in_toml = content.contains("trusted_hash");
        }
    }

    let protection_state = if hook_configured_in_toml && hook_trusted_in_toml {
        "partially_protected".to_string()
    } else {
        "unprotected".to_string()
    };

    let limitations = vec![
        "Codex 0.160.1+ 中 write_stdin 交互式 PTY 输入不触发 PreToolUse 钩子".to_string(),
        "未完成真实隔离自检（self-test）前不标记为 protected_verified".to_string(),
    ];

    DoctorTargetReport {
        target_id,
        environment_kind,
        codex_home: codex_home.to_string_lossy().into_owned(),
        codex_home_exists,
        config_toml_exists,
        hook_configured_in_toml,
        hook_trusted_in_toml,
        protection_state,
        real_interception_verified: false,
        limitations,
    }
}

fn run_rule_test(agent: &str, tool: &str, input: &str, cwd: &str, as_json: bool) {
    let env_kind = EnvironmentKind::infer_from_path(cwd);
    let target_id = env_kind.default_target_id();
    let action_kind = match tool {
        "Bash" | "exec_command" | "shell" => ActionKind::Shell,
        "apply_patch" => ActionKind::FilePatch,
        t if t.starts_with("mcp__") => ActionKind::McpTool,
        _ => ActionKind::Unknown,
    };

    let target_paths = if action_kind == ActionKind::FilePatch {
        extract_apply_patch_paths(input)
    } else {
        Vec::new()
    };

    let event = ActionEvent {
        target_id,
        environment_kind: env_kind,
        client_surface: ClientSurface::CodexCli,
        agent: agent.to_string(),
        session_id: "rule-test-session".to_string(),
        turn_id: "rule-test-turn".to_string(),
        tool_use_id: "rule-test-call".to_string(),
        tool_name: tool.to_string(),
        action_kind,
        cwd: cwd.to_string(),
        normalized_command: Some(input.to_string()),
        target_paths,
        redacted_summary: redact_secrets(input),
    };

    let decision = evaluate_action_event(&event);
    if as_json {
        #[derive(Serialize)]
        struct RuleTestOutput {
            event: ActionEvent,
            decision: Decision,
        }
        let out = RuleTestOutput { event, decision };
        println!(
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!(
            "Decision: {:?} | Reason: {} | Message: {}",
            decision.enforcement, decision.reason_code, decision.display_message
        );
    }
}

/// Codex `PreToolUse` 极速热路径：
/// - 注册顶层 panic hook：即便发生未预期 panic，也保证向 `stdout` 输出合法的单行 Deny JSON（Fail-Closed）。
/// - 严格分离 `stdout`（仅输出协议 JSON）与 `stderr`（仅输出脱敏后的诊断摘要）。
fn run_codex_pre_tool_use_hook() {
    std::panic::set_hook(Box::new(|_| {
        let fallback = CodexPreToolUseWireOutput::deny(
            "[AI卫士安全阻断] Hook 内部发生未预期异常，触发默认阻断保护（Fail-Closed）",
        )
        .to_single_line_json();
        let _ = writeln!(io::stdout(), "{fallback}");
        let _ = io::stdout().flush();
    }));

    let mut buf = Vec::new();
    let stdin = io::stdin();
    let mut handle = stdin
        .lock()
        .take((MAX_HOOK_STDIN_BYTES as u64).saturating_add(1));

    if let Err(e) = handle.read_to_end(&mut buf) {
        let decision = Decision::fail_closed_deny(
            "unknown",
            "AG-PROTO-IO-ERROR",
            format!("读取 stdin 失败: {e}"),
        );
        let line = CodexPreToolUseWireOutput::deny(&decision.display_message).to_single_line_json();
        let _ = writeln!(io::stdout(), "{line}");
        let _ = io::stdout().flush();
        return;
    }

    if buf.len() > MAX_HOOK_STDIN_BYTES {
        let decision = Decision::fail_closed_deny(
            "unknown",
            "AG-PROTO-OVERSIZE",
            format!("Hook stdin 超过最大允许长度 ({MAX_HOOK_STDIN_BYTES} bytes)"),
        );
        let line = CodexPreToolUseWireOutput::deny(&decision.display_message).to_single_line_json();
        let _ = writeln!(io::stdout(), "{line}");
        let _ = io::stdout().flush();
        return;
    }

    let (decision, stdout_json) = handle_codex_pre_tool_use_bytes(&buf);
    if let Some(line) = stdout_json {
        let _ = writeln!(io::stdout(), "{line}");
        let _ = io::stdout().flush();
        let _ = writeln!(
            io::stderr(),
            "[ai-guard] DENY code={} rules={:?}",
            decision.reason_code,
            decision.matched_rule_ids
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_nonexistent_codex_target_never_panics() {
        let missing = PathBuf::from("/tmp/ai-guard-definitely-does-not-exist-99999");
        let report = inspect_codex_target(
            "wsl2:Ubuntu".to_string(),
            EnvironmentKind::Wsl2Distro {
                distro_name: "Ubuntu".to_string(),
            },
            &missing,
        );
        assert!(!report.codex_home_exists);
        assert!(!report.config_toml_exists);
        assert_eq!(report.protection_state, "unprotected");
        assert!(!report.real_interception_verified);
    }
}
