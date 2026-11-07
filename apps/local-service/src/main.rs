mod cli;

use ai_guard_agent_adapters::{
    extract_apply_patch_paths, handle_codex_pre_tool_use_bytes_with_engine, install_codex_hook,
    parse_codex_pre_tool_use_bytes, preflight_codex_run, uninstall_codex_hook,
    CodexPreToolUseWireOutput, InstallRequest, InstallScope, PreflightRequest, UninstallRequest,
    MAX_HOOK_STDIN_BYTES,
};
use ai_guard_backup::BackupStore;
use ai_guard_security::{
    default_policy_engine, redact_secrets, ActionEvent, ActionKind, ClientSurface, Decision,
    EnvironmentKind, PolicyEngine, SecurityError,
};
use clap::Parser;
use cli::{
    BackupSubcommands, Cli, CodexHookEvents, Commands, HookAgents, InstallAgents, RuleSubcommands,
    RunAgents, UninstallAgents,
};
use serde::Serialize;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor { target, json } => run_doctor(&target, json),
        Commands::Rule { subcommand } => match subcommand {
            RuleSubcommands::Validate { path, json } => run_rule_validate(&path, json),
            RuleSubcommands::Test {
                agent,
                tool,
                input,
                cwd,
                event_file,
                policy,
                json,
            } => run_rule_test(
                &agent,
                tool.as_deref(),
                input.as_deref(),
                &cwd,
                event_file.as_deref(),
                policy.as_deref(),
                json,
            ),
        },
        Commands::Install { agent } => match agent {
            InstallAgents::Codex {
                target,
                scope,
                codex_home,
                backup_dir,
                hook_command,
                binary_source,
                binary_dest,
                policy_source,
                policy_dest,
                trusted_hash,
                dry_run,
                json,
            } => run_install_codex(
                &target,
                &scope,
                codex_home.as_deref(),
                backup_dir.as_deref(),
                hook_command.as_deref(),
                binary_source.as_deref(),
                binary_dest.as_deref(),
                policy_source.as_deref(),
                policy_dest.as_deref(),
                trusted_hash,
                dry_run,
                json,
            ),
        },
        Commands::Uninstall { agent } => match agent {
            UninstallAgents::Codex {
                target,
                scope,
                codex_home,
                backup_dir,
                dry_run,
                force,
                json,
            } => run_uninstall_codex(
                &target,
                &scope,
                codex_home.as_deref(),
                backup_dir.as_deref(),
                dry_run,
                force,
                json,
            ),
        },
        Commands::Run { agent } => match agent {
            RunAgents::Codex {
                target,
                codex_home,
                codex_bin,
                policy,
                expected_policy_sha256,
                require_trusted,
                dry_run,
                json,
                codex_args,
            } => run_managed_codex(
                &target,
                codex_home.as_deref(),
                &codex_bin,
                policy.as_deref(),
                expected_policy_sha256,
                require_trusted,
                dry_run,
                json,
                &codex_args,
            ),
        },
        Commands::Backup { subcommand } => match subcommand {
            BackupSubcommands::List {
                target,
                backup_dir,
                json,
            } => run_backup_list(&target, backup_dir.as_deref(), json),
            BackupSubcommands::Verify {
                id,
                backup_dir,
                json,
            } => run_backup_verify(&id, backup_dir.as_deref(), json),
            BackupSubcommands::Restore {
                id,
                backup_dir,
                json,
            } => run_backup_restore(&id, backup_dir.as_deref(), json),
        },
        Commands::Hook { agent } => match agent {
            HookAgents::Codex { event } => match event {
                CodexHookEvents::PreToolUse { policy } => {
                    run_codex_pre_tool_use_hook(policy.as_deref())
                }
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

fn resolve_codex_home_for_target(
    target_id: &str,
    scope: InstallScope,
    explicit_codex_home: Option<&str>,
) -> PathBuf {
    if let Some(p) = explicit_codex_home {
        return PathBuf::from(p);
    }
    if scope == InstallScope::Project {
        return std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".codex");
    }
    if target_id.starts_with("host") {
        if let Some(win) = discover_windows_host_codex_home() {
            return win;
        }
    }
    std::env::var("CODEX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home/ai-li".to_string());
            PathBuf::from(home).join(".codex")
        })
}

fn resolve_backup_store(explicit_backup_dir: Option<&str>) -> BackupStore {
    let dir = if let Some(p) = explicit_backup_dir {
        PathBuf::from(p)
    } else if let Ok(env_dir) = std::env::var("AI_GUARD_BACKUP_DIR") {
        PathBuf::from(env_dir)
    } else if cfg!(windows) {
        let local_app_data =
            std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:\\Temp".to_string());
        PathBuf::from(local_app_data)
            .join("ai-guard")
            .join("backups")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("ai-guard")
            .join("backups")
    };
    BackupStore::new(dir)
}

#[allow(clippy::too_many_arguments)]
fn run_install_codex(
    target: &str,
    scope_str: &str,
    explicit_codex_home: Option<&str>,
    explicit_backup_dir: Option<&str>,
    explicit_hook_cmd: Option<&str>,
    binary_source: Option<&str>,
    binary_dest: Option<&str>,
    policy_source: Option<&str>,
    policy_dest: Option<&str>,
    trusted_hash: Option<String>,
    dry_run: bool,
    as_json: bool,
) {
    let scope = match InstallScope::parse(scope_str) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ERROR [{}]: {e}", e.code());
            std::process::exit(1);
        }
    };

    let codex_home = resolve_codex_home_for_target(target, scope, explicit_codex_home);
    let backup_store = resolve_backup_store(explicit_backup_dir);

    let default_bin = binary_dest
        .map(PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .unwrap_or_else(|| PathBuf::from("ai-guard"));

    let hook_command = if let Some(cmd) = explicit_hook_cmd {
        cmd.to_string()
    } else if let Some(p_dest) = policy_dest {
        format!(
            "{} hook codex pre-tool-use --policy {}",
            default_bin.display(),
            p_dest
        )
    } else {
        format!("{} hook codex pre-tool-use", default_bin.display())
    };

    let req = InstallRequest {
        target_id: target.to_string(),
        scope,
        codex_home,
        hook_command,
        guard_binary_source: binary_source.map(PathBuf::from),
        guard_binary_dest: binary_dest.map(PathBuf::from),
        policy_source: policy_source.map(PathBuf::from),
        policy_dest: policy_dest.map(PathBuf::from),
        trusted_hash,
        dry_run,
    };

    match install_codex_hook(&req, &backup_store) {
        Ok(report) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!(
                    "OK: Codex Hook {}成功 (target={}, config={}, preserved_third_party_hooks={}, backup_id={:?})",
                    if report.dry_run { "预览(--dry-run)" } else { "安装" },
                    report.target_id,
                    report.config_toml_path,
                    report.third_party_hooks_preserved,
                    report.backup_id
                );
                println!("{}", report.unified_diff);
                println!("提示: {}", report.trust_guidance);
            }
        }
        Err(err) => {
            if as_json {
                let err_json = serde_json::json!({
                    "ok": false,
                    "error_code": err.code(),
                    "error_detail": err.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&err_json).unwrap());
            } else {
                eprintln!("ERROR [{}]: {err}", err.code());
            }
            std::process::exit(1);
        }
    }
}

fn run_uninstall_codex(
    target: &str,
    scope_str: &str,
    explicit_codex_home: Option<&str>,
    explicit_backup_dir: Option<&str>,
    dry_run: bool,
    force: bool,
    as_json: bool,
) {
    let scope = match InstallScope::parse(scope_str) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ERROR [{}]: {e}", e.code());
            std::process::exit(1);
        }
    };

    let codex_home = resolve_codex_home_for_target(target, scope, explicit_codex_home);
    let backup_store = resolve_backup_store(explicit_backup_dir);

    let req = UninstallRequest {
        target_id: target.to_string(),
        scope,
        codex_home,
        dry_run,
        force,
    };

    match uninstall_codex_hook(&req, &backup_store) {
        Ok(report) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!(
                    "OK: Codex Hook {}完成 (target={}, removed={}, remaining_third_party_hooks={}, exact_pre_install_hash={})",
                    if report.dry_run { "卸载预览(--dry-run)" } else { "安全卸载" },
                    report.target_id,
                    report.removed_ai_guard_hook,
                    report.third_party_hooks_remaining,
                    report.restored_to_exact_pre_install_hash
                );
                println!("{}", report.unified_diff);
            }
        }
        Err(err) => {
            if as_json {
                let err_json = serde_json::json!({
                    "ok": false,
                    "error_code": err.code(),
                    "error_detail": err.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&err_json).unwrap());
            } else {
                eprintln!("ERROR [{}]: {err}", err.code());
            }
            std::process::exit(1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_managed_codex(
    target: &str,
    explicit_codex_home: Option<&str>,
    codex_bin: &str,
    policy_path: Option<&str>,
    expected_policy_sha256: Option<String>,
    require_trusted: bool,
    dry_run: bool,
    as_json: bool,
    codex_args: &[String],
) {
    let codex_home = resolve_codex_home_for_target(target, InstallScope::User, explicit_codex_home);
    let req = PreflightRequest {
        target_id: target.to_string(),
        codex_home,
        codex_bin: PathBuf::from(codex_bin),
        policy_path: policy_path.map(PathBuf::from),
        expected_policy_sha256,
        require_trusted,
    };

    let report = preflight_codex_run(&req);
    if !report.overall_passed {
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
            );
        } else {
            eprintln!(
                "[AI卫士安全阻断] 受管启动预检未通过（原因码: {}），已拒绝启动 Codex：",
                report.blocked_reason_code.as_deref().unwrap_or("UNKNOWN")
            );
            for c in &report.checks {
                let status = if c.passed { "PASS" } else { "FAIL" };
                eprintln!("  - [{}] {}: {}", status, c.check_id, c.detail);
                if let Some(ref rem) = c.remediation {
                    eprintln!("    修复指引: {rem}");
                }
            }
        }
        std::process::exit(1);
    }

    if dry_run {
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
            );
        } else {
            println!(
                "OK: 受管启动预检全部通过 (target={}, codex_home={})",
                report.target_id, report.codex_home
            );
        }
        return;
    }

    // 预检全部通过：使用独立 argv 数组直接拉起目标 codex，严禁通过 Shell 字符串拼接执行！
    let status = Command::new(&req.codex_bin)
        .args(codex_args)
        .env("CODEX_HOME", &req.codex_home)
        .status();

    match status {
        Ok(s) => std::process::exit(s.code().unwrap_or(0)),
        Err(e) => {
            eprintln!(
                "[AI卫士安全阻断] 启动 Codex 进程 `{}` 失败: {e}",
                req.codex_bin.display()
            );
            std::process::exit(1);
        }
    }
}

fn run_backup_list(target_filter: &str, explicit_backup_dir: Option<&str>, as_json: bool) {
    let store = resolve_backup_store(explicit_backup_dir);
    match store.list_backups(Some(target_filter)) {
        Ok(list) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&list).unwrap_or_else(|_| "[]".to_string())
                );
            } else {
                println!(
                    "共找到 {} 条备份记录 (root={}):",
                    list.len(),
                    store.root_dir().display()
                );
                for m in &list {
                    println!(
                        "- [{}] target={} op={} files={}",
                        m.backup_id,
                        m.target_id,
                        m.operation,
                        m.files.len()
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("ERROR [{}]: {e}", e.code());
            std::process::exit(1);
        }
    }
}

fn run_backup_verify(backup_id: &str, explicit_backup_dir: Option<&str>, as_json: bool) {
    let store = resolve_backup_store(explicit_backup_dir);
    match store.verify_backup(backup_id) {
        Ok(m) => {
            if as_json {
                let out = serde_json::json!({
                    "valid": true,
                    "backup_id": m.backup_id,
                    "target_id": m.target_id,
                    "files": m.files,
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                println!(
                    "OK: 备份 `{}` SHA-256 完整性校验通过（共 {} 个文件）",
                    m.backup_id,
                    m.files.len()
                );
            }
        }
        Err(e) => {
            if as_json {
                let out = serde_json::json!({
                    "valid": false,
                    "backup_id": backup_id,
                    "error_code": e.code(),
                    "error_detail": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                eprintln!("ERROR [{}]: {e}", e.code());
            }
            std::process::exit(1);
        }
    }
}

fn run_backup_restore(backup_id: &str, explicit_backup_dir: Option<&str>, as_json: bool) {
    let store = resolve_backup_store(explicit_backup_dir);
    match store.restore_backup(backup_id) {
        Ok(m) => {
            if as_json {
                let out = serde_json::json!({
                    "restored": true,
                    "backup_id": m.backup_id,
                    "target_id": m.target_id,
                    "files": m.files,
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                println!(
                    "OK: 已从备份 `{}` 原子恢复 {} 个文件并完成 SHA-256 校验",
                    m.backup_id,
                    m.files.len()
                );
            }
        }
        Err(e) => {
            if as_json {
                let out = serde_json::json!({
                    "restored": false,
                    "backup_id": backup_id,
                    "error_code": e.code(),
                    "error_detail": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                eprintln!("ERROR [{}]: {e}", e.code());
            }
            std::process::exit(1);
        }
    }
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

#[derive(Debug, Serialize)]
struct RuleValidateReport {
    valid: bool,
    path: String,
    policy_revision: Option<String>,
    rules_total: usize,
    rules_enabled: usize,
    error_code: Option<String>,
    error_detail: Option<String>,
}

fn run_rule_validate(path_str: &str, as_json: bool) {
    let path = Path::new(path_str);
    match PolicyEngine::from_toml_path(path) {
        Ok(engine) => {
            let cfg = engine.config();
            let enabled_count = cfg.rules.iter().filter(|r| r.enabled).count();
            let report = RuleValidateReport {
                valid: true,
                path: path_str.to_string(),
                policy_revision: Some(engine.policy_revision().to_string()),
                rules_total: cfg.rules.len(),
                rules_enabled: enabled_count,
                error_code: None,
                error_detail: None,
            };
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!(
                    "OK: policy `{}` is valid (revision={}, rules_total={}, rules_enabled={})",
                    report.path,
                    engine.policy_revision(),
                    report.rules_total,
                    report.rules_enabled
                );
            }
        }
        Err(err) => {
            let (code, detail) = extract_security_error_fields(&err);
            let report = RuleValidateReport {
                valid: false,
                path: path_str.to_string(),
                policy_revision: None,
                rules_total: 0,
                rules_enabled: 0,
                error_code: Some(code.clone()),
                error_detail: Some(detail.clone()),
            };
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                eprintln!(
                    "ERROR [{}]: policy `{}` validation failed: {}",
                    code, report.path, detail
                );
            }
            std::process::exit(1);
        }
    }
}

#[derive(Debug, Serialize)]
struct RuleTestOutput {
    event: ActionEvent,
    decision: Decision,
    policy_revision: String,
    used_snapshot_fallback: bool,
    policy_warning: Option<String>,
    duration_us: u128,
}

fn run_rule_test(
    agent: &str,
    tool: Option<&str>,
    input: Option<&str>,
    cwd: &str,
    event_file: Option<&str>,
    policy_path: Option<&str>,
    as_json: bool,
) {
    let start = Instant::now();

    let event = if let Some(file_path) = event_file {
        let bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("读取事件文件 `{file_path}` 失败: {e}");
                std::process::exit(1);
            }
        };
        match parse_codex_pre_tool_use_bytes(&bytes) {
            Ok(ev) => ev,
            Err(err) => {
                let (code, detail) = extract_security_error_fields(&err);
                let decision = Decision::fail_closed_deny("unknown", code, detail);
                let duration_us = start.elapsed().as_micros();
                let fallback_ev = ActionEvent {
                    target_id: "unknown".to_string(),
                    environment_kind: EnvironmentKind::infer_from_path(cwd),
                    client_surface: ClientSurface::CodexCli,
                    agent: agent.to_string(),
                    session_id: "invalid-event".to_string(),
                    turn_id: "invalid-turn".to_string(),
                    tool_use_id: "invalid-call".to_string(),
                    tool_name: "unknown".to_string(),
                    action_kind: ActionKind::Unknown,
                    cwd: cwd.to_string(),
                    normalized_command: None,
                    target_paths: Vec::new(),
                    redacted_summary: "[INVALID_EVENT_PAYLOAD]".to_string(),
                };
                print_rule_test_result(
                    fallback_ev,
                    decision,
                    "protocol-fail-closed".to_string(),
                    false,
                    None,
                    duration_us,
                    as_json,
                );
                return;
            }
        }
    } else {
        let tool_name = tool.unwrap_or("Bash");
        let raw_input = input.unwrap_or("");
        let env_kind = EnvironmentKind::infer_from_path(cwd);
        let target_id = env_kind.default_target_id();
        let action_kind = match tool_name {
            "Bash" | "exec_command" | "shell" => ActionKind::Shell,
            "apply_patch" => ActionKind::FilePatch,
            t if t.starts_with("mcp__") => ActionKind::McpTool,
            _ => ActionKind::Unknown,
        };

        let target_paths = if action_kind == ActionKind::FilePatch {
            extract_apply_patch_paths(raw_input)
        } else {
            Vec::new()
        };

        ActionEvent {
            target_id,
            environment_kind: env_kind,
            client_surface: ClientSurface::CodexCli,
            agent: agent.to_string(),
            session_id: "rule-test-session".to_string(),
            turn_id: "rule-test-turn".to_string(),
            tool_use_id: "rule-test-call".to_string(),
            tool_name: tool_name.to_string(),
            action_kind,
            cwd: cwd.to_string(),
            normalized_command: Some(raw_input.to_string()),
            target_paths,
            redacted_summary: redact_secrets(raw_input),
        }
    };

    let (decision, policy_revision, used_fallback, warning) = if let Some(p) = policy_path {
        match PolicyEngine::load_with_snapshot_fallback(Path::new(p), None) {
            Ok((engine, warn)) => {
                let d = engine.evaluate(&event);
                (
                    d,
                    engine.policy_revision().to_string(),
                    warn.is_some(),
                    warn,
                )
            }
            Err(err) => {
                let (code, detail) = extract_security_error_fields(&err);
                let d = Decision::fail_closed_deny(&event.target_id, code, detail);
                (d, "policy-error-fail-closed".to_string(), false, None)
            }
        }
    } else {
        let engine = default_policy_engine();
        let d = engine.evaluate(&event);
        (d, engine.policy_revision().to_string(), false, None)
    };

    let duration_us = start.elapsed().as_micros();
    print_rule_test_result(
        event,
        decision,
        policy_revision,
        used_fallback,
        warning,
        duration_us,
        as_json,
    );
}

fn print_rule_test_result(
    event: ActionEvent,
    decision: Decision,
    policy_revision: String,
    used_snapshot_fallback: bool,
    policy_warning: Option<String>,
    duration_us: u128,
    as_json: bool,
) {
    if as_json {
        let out = RuleTestOutput {
            event,
            decision,
            policy_revision,
            used_snapshot_fallback,
            policy_warning,
            duration_us,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!(
            "Decision: {:?} | Reason: {} | Rules: {:?} | Latency: {}us | Message: {}",
            decision.enforcement,
            decision.reason_code,
            decision.matched_rule_ids,
            duration_us,
            decision.display_message
        );
    }
}

fn extract_security_error_fields(err: &SecurityError) -> (String, String) {
    match err {
        SecurityError::ProtocolError {
            code,
            redacted_detail,
        }
        | SecurityError::EvaluationError {
            code,
            redacted_detail,
        } => (code.clone(), redacted_detail.clone()),
    }
}

/// Codex `PreToolUse` 极速热路径：
/// - 注册顶层 panic hook：即便发生未预期 panic，也保证向 `stdout` 输出合法的单行 Deny JSON（Fail-Closed）。
/// - 严格分离 `stdout`（仅输出协议 JSON）与 `stderr`（仅输出脱敏后的诊断摘要）。
fn run_codex_pre_tool_use_hook(policy_arg: Option<&str>) {
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

    let env_policy = std::env::var("AI_GUARD_POLICY_PATH").ok();
    let effective_policy_path = policy_arg.or(env_policy.as_deref());

    let (decision, stdout_json) = if let Some(path_str) = effective_policy_path {
        let snapshot_env = std::env::var("AI_GUARD_POLICY_SNAPSHOT_PATH").ok();
        let snapshot_path = snapshot_env.as_deref().map(Path::new);
        match PolicyEngine::load_with_snapshot_fallback(Path::new(path_str), snapshot_path) {
            Ok((engine, warn)) => {
                if let Some(w) = warn {
                    let _ = writeln!(io::stderr(), "[ai-guard] WARN: {w}");
                }
                handle_codex_pre_tool_use_bytes_with_engine(&buf, &engine)
            }
            Err(err) => {
                let (code, detail) = extract_security_error_fields(&err);
                let d = Decision::fail_closed_deny("unknown", code, detail);
                let line =
                    CodexPreToolUseWireOutput::deny(&d.display_message).to_single_line_json();
                (d, Some(line))
            }
        }
    } else {
        handle_codex_pre_tool_use_bytes_with_engine(&buf, default_policy_engine())
    };

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
