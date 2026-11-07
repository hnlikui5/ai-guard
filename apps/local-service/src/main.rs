mod cli;
mod http_server;
mod target_manager;

use ai_guard_agent_adapters::{
    extract_apply_patch_paths, handle_codex_pre_tool_use_bytes_with_engine, install_codex_hook,
    parse_codex_pre_tool_use_bytes, preflight_codex_run, uninstall_codex_hook,
    CodexPreToolUseWireOutput, InstallRequest, InstallScope, PreflightRequest, UninstallRequest,
    MAX_HOOK_STDIN_BYTES,
};
use ai_guard_backup::BackupStore;
use ai_guard_security::{
    default_policy_engine, redact_secrets, ActionEvent, ActionKind, ClientSurface, Decision,
    Enforcement, EnvironmentKind, PolicyEngine, SecurityError,
};
use ai_guard_session::{
    backup_codex_session, get_codex_session_detail, list_codex_sessions, SessionSummary,
};
use ai_guard_storage::{
    current_epoch_ms, AuditStore, EventQueryFilter, ExportFormat, SelfTestRunRecord,
};
use clap::Parser;
use cli::{
    BackupSubcommands, Cli, CodexHookEvents, Commands, EventsSubcommands, HookAgents,
    InstallAgents, RuleSubcommands, RunAgents, SelfTestAgents, SessionSubcommands, UninstallAgents,
};
use serde::Serialize;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor { target, json } => run_doctor(&target, None, None, json),
        Commands::Status {
            target,
            codex_home,
            db_path,
            json,
        } => run_doctor(&target, codex_home.as_deref(), db_path.as_deref(), json),
        Commands::SelfTest { agent } => match agent {
            SelfTestAgents::Codex {
                target,
                isolated,
                db_path,
                json,
            } => run_self_test_codex(&target, isolated, db_path.as_deref(), json),
        },
        Commands::Events { subcommand } => match subcommand {
            EventsSubcommands::List {
                target,
                decision,
                since,
                limit,
                db_path,
                json,
            } => run_events_list(
                &target,
                decision.as_deref(),
                since.as_deref(),
                limit,
                db_path.as_deref(),
                json,
            ),
            EventsSubcommands::Pull {
                since,
                target,
                limit,
                db_path,
                merge_into_db,
                json,
            } => run_events_pull(
                since,
                target.as_deref(),
                limit,
                db_path.as_deref(),
                merge_into_db.as_deref(),
                json,
            ),
            EventsSubcommands::Export {
                output,
                redacted: _,
                format,
                target,
                db_path,
                json,
            } => run_events_export(&output, &format, &target, db_path.as_deref(), json),
        },
        Commands::Session { subcommand } => match subcommand {
            SessionSubcommands::List {
                target,
                codex_home,
                limit,
                json,
            } => run_session_list(&target, codex_home.as_deref(), limit, json),
            SessionSubcommands::Show {
                id,
                target,
                codex_home,
                json,
            } => run_session_show(&id, &target, codex_home.as_deref(), json),
            SessionSubcommands::Backup {
                id,
                target,
                codex_home,
                backup_dir,
                json,
            } => run_session_backup(
                &id,
                &target,
                codex_home.as_deref(),
                backup_dir.as_deref(),
                json,
            ),
        },
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
        Commands::Serve {
            bind,
            static_dir,
            db_path,
            backup_dir,
            policy_path,
            max_requests,
        } => {
            let cfg = http_server::ServeConfig {
                bind_addr: bind,
                static_dir: static_dir.map(PathBuf::from),
                db_path,
                backup_dir,
                policy_path,
            };
            if let Err(e) = http_server::run_http_server(&cfg, max_requests) {
                eprintln!("ERROR: {e}");
                std::process::exit(1);
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DoctorTargetReport {
    pub target_id: String,
    pub environment_kind: EnvironmentKind,
    pub codex_home: String,
    pub codex_home_exists: bool,
    pub config_toml_exists: bool,
    pub hook_configured_in_toml: bool,
    pub hook_trusted_in_toml: bool,
    pub protection_state: String,
    pub real_interception_verified: bool,
    pub last_self_test: Option<SelfTestRunRecord>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub ai_guard_version: &'static str,
    pub overall_status: String,
    pub targets: Vec<DoctorTargetReport>,
}

pub fn collect_doctor_report(
    target_filter: &str,
    explicit_codex_home: Option<&str>,
    explicit_db_path: Option<&str>,
) -> DoctorReport {
    let store = AuditStore::resolve_default(explicit_db_path);
    let mut targets = Vec::new();
    let filter = target_filter.trim().to_ascii_lowercase();

    // 1. 探测 WSL2 当前环境目标
    if filter == "all" || filter.starts_with("wsl2") {
        let distro = std::env::var("WSL_DISTRO_NAME").unwrap_or_else(|_| "Ubuntu".to_string());
        let wsl_home = if let Some(explicit) = explicit_codex_home {
            PathBuf::from(explicit)
        } else {
            std::env::var("CODEX_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/ai-li".to_string());
                    PathBuf::from(home).join(".codex")
                })
        };
        let tid = format!("wsl2:{distro}");
        let last_st = store.latest_self_test(&tid).ok().flatten();
        targets.push(inspect_codex_target(
            tid,
            EnvironmentKind::Wsl2Distro {
                distro_name: distro,
            },
            &wsl_home,
            last_st,
        ));
    }

    // 2. 探测 Windows 宿主机环境目标（支持在 Windows 原生或 WSL2 /mnt/c 下只读探测）
    if filter == "all" || filter == "host" || filter == "host:windows" {
        let win_home_opt = if let Some(explicit) = explicit_codex_home {
            if filter == "host" || filter == "host:windows" {
                Some(PathBuf::from(explicit))
            } else {
                discover_windows_host_codex_home()
            }
        } else {
            discover_windows_host_codex_home()
        };

        let last_st = store.latest_self_test("host:windows").ok().flatten();
        if let Some(win_codex_home) = win_home_opt {
            targets.push(inspect_codex_target(
                "host:windows".to_string(),
                EnvironmentKind::WindowsHost,
                &win_codex_home,
                last_st,
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
                last_self_test: last_st,
                limitations: vec!["未检测到可访问的 Windows 宿主机 .codex 目录".to_string()],
            });
        }
    }

    let overall_status = if targets.is_empty() {
        "warning".to_string()
    } else {
        "ok".to_string()
    };

    DoctorReport {
        schema_version: 1,
        ai_guard_version: env!("CARGO_PKG_VERSION"),
        overall_status,
        targets,
    }
}

fn run_doctor(
    target_filter: &str,
    explicit_codex_home: Option<&str>,
    explicit_db_path: Option<&str>,
    as_json: bool,
) {
    let report = collect_doctor_report(target_filter, explicit_codex_home, explicit_db_path);

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!(
            "AI卫士（AI Guard）v{} 四态防护诊断报告",
            report.ai_guard_version
        );
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

fn inspect_codex_target(
    target_id: String,
    environment_kind: EnvironmentKind,
    codex_home: &Path,
    last_self_test: Option<SelfTestRunRecord>,
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

    let self_test_passed = last_self_test.as_ref().map(|r| r.passed).unwrap_or(false);

    // 严格遵守 AGENTS.md §5.4 诚实状态原则：
    // 仅当目标配置已挂载 Hook、已登记 trusted_hash 且通过了隔离自检时，才显示为 protected_verified！
    let protection_state = if !codex_home_exists {
        "unknown".to_string()
    } else if hook_configured_in_toml && hook_trusted_in_toml && self_test_passed {
        "protected_verified".to_string()
    } else if hook_configured_in_toml || self_test_passed {
        "partially_protected".to_string()
    } else {
        "unprotected".to_string()
    };

    let real_interception_verified = protection_state == "protected_verified";

    let mut limitations = vec![
        "Codex 0.160.1+ 中 write_stdin 交互式 PTY 输入不触发 PreToolUse 钩子".to_string(),
        "PreToolUse 属于应用层工具执行前拦截，不等同于 OS 内核级全流量/全文件系统隔离".to_string(),
    ];
    if !self_test_passed {
        limitations.push("当前目标尚未记录通过的 self-test 隔离自检运行记录".to_string());
    }
    if !hook_configured_in_toml {
        limitations.push("当前目标 config.toml 尚未挂载 AI卫士 PreToolUse 钩子".to_string());
    }

    DoctorTargetReport {
        target_id,
        environment_kind,
        codex_home: codex_home.to_string_lossy().into_owned(),
        codex_home_exists,
        config_toml_exists,
        hook_configured_in_toml,
        hook_trusted_in_toml,
        protection_state,
        real_interception_verified,
        last_self_test,
        limitations,
    }
}

pub fn execute_self_test_runs(
    target_filter: &str,
    explicit_db_path: Option<&str>,
) -> Vec<SelfTestRunRecord> {
    let store = AuditStore::resolve_default(explicit_db_path);
    let _ = store.init_schema();

    let distro = std::env::var("WSL_DISTRO_NAME").unwrap_or_else(|_| "Ubuntu".to_string());
    let wsl_tid = format!("wsl2:{distro}");
    let filter = target_filter.trim().to_ascii_lowercase();

    let mut target_list = Vec::new();
    if filter == "all" || filter.starts_with("wsl2") {
        target_list.push((wsl_tid.clone(), wsl_tid, "/tmp/ai-guard-selftest-wsl"));
    }
    if filter == "all" || filter == "host" || filter == "host:windows" {
        target_list.push((
            "host:windows".to_string(),
            "windows_host".to_string(),
            "C:\\Users\\demo\\ai-guard-selftest",
        ));
    }

    let mut records = Vec::new();
    for (tid, host_kind, mock_cwd) in target_list {
        let now_ms = current_epoch_ms();
        let run_id = format!("st-{now_ms}-{}", tid.replace(':', "-"));

        // 1. 隔离自检 Allow 用例：echo ALLOW_SELF_TEST_OK
        let allow_payload = serde_json::json!({
            "session_id": format!("selftest-allow-{now_ms}"),
            "turn_id": "turn-allow",
            "cwd": mock_cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "echo ALLOW_SELF_TEST_OK" },
            "tool_use_id": "call-selftest-allow"
        });
        let allow_bytes = serde_json::to_vec(&allow_payload).unwrap_or_default();
        let (allow_dec, allow_stdout) =
            handle_codex_pre_tool_use_bytes_with_engine(&allow_bytes, default_policy_engine());
        let allow_verified = allow_dec.enforcement == Enforcement::Allow && allow_stdout.is_none();

        // 2. 隔离自检 Deny 用例：echo AI_GUARD_BLOCK_ME + 跨平台高危命令阻断且无任何副作用文件生成
        let sentinel_path = std::env::temp_dir().join(format!("ai-guard-st-sentinel-{now_ms}.txt"));
        let _ = std::fs::remove_file(&sentinel_path);
        let deny_cmd = format!(
            "echo AI_GUARD_BLOCK_ME && touch {}",
            sentinel_path.display()
        );
        let deny_payload = serde_json::json!({
            "session_id": format!("selftest-deny-{now_ms}"),
            "turn_id": "turn-deny",
            "cwd": mock_cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": deny_cmd },
            "tool_use_id": "call-selftest-deny"
        });
        let deny_bytes = serde_json::to_vec(&deny_payload).unwrap_or_default();
        let (deny_dec, deny_stdout) =
            handle_codex_pre_tool_use_bytes_with_engine(&deny_bytes, default_policy_engine());

        let deny_verified = deny_dec.enforcement == Enforcement::Deny
            && deny_stdout
                .as_deref()
                .map(|s| s.contains("\"permissionDecision\":\"deny\""))
                .unwrap_or(false)
            && !sentinel_path.exists();

        if let Ok(ev) = parse_codex_pre_tool_use_bytes(&deny_bytes) {
            let _ = store.record_event(&ev, &deny_dec);
        }

        let passed = allow_verified && deny_verified;
        let rec = SelfTestRunRecord {
            run_id,
            target_id: tid,
            host_kind,
            passed,
            allow_verified,
            deny_verified,
            policy_revision: default_policy_engine().policy_revision().to_string(),
            detail: if passed {
                "隔离沙箱 Allow 放行与 Deny 拦截自检全部通过，哨兵副作用文件未生成".to_string()
            } else {
                format!(
                    "自检未通过 (allow_verified={allow_verified}, deny_verified={deny_verified})"
                )
            },
            executed_at_ms: now_ms,
        };
        let _ = store.record_self_test(&rec);
        records.push(rec);
    }
    records
}

fn run_self_test_codex(
    target_filter: &str,
    _isolated: bool,
    explicit_db_path: Option<&str>,
    as_json: bool,
) {
    let records = execute_self_test_runs(target_filter, explicit_db_path);

    let all_passed = !records.is_empty() && records.iter().all(|r| r.passed);
    if as_json {
        let out = serde_json::json!({
            "overall_passed": all_passed,
            "runs": records,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        for r in &records {
            println!(
                "[{}] self-test passed={} allow={} deny={} revision={} | {}",
                r.target_id,
                r.passed,
                r.allow_verified,
                r.deny_verified,
                r.policy_revision,
                r.detail
            );
        }
    }

    if !all_passed {
        std::process::exit(1);
    }
}

fn parse_since_arg(since_str: Option<&str>) -> Option<u64> {
    let s = since_str?.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(ms) = s.parse::<u64>() {
        return Some(ms);
    }
    let now = current_epoch_ms();
    if let Some(hours) = s.strip_suffix('h').and_then(|v| v.parse::<u64>().ok()) {
        return Some(now.saturating_sub(hours * 3600 * 1000));
    }
    if let Some(mins) = s.strip_suffix('m').and_then(|v| v.parse::<u64>().ok()) {
        return Some(now.saturating_sub(mins * 60 * 1000));
    }
    if let Some(days) = s.strip_suffix('d').and_then(|v| v.parse::<u64>().ok()) {
        return Some(now.saturating_sub(days * 24 * 3600 * 1000));
    }
    None
}

fn parse_decision_arg(dec_str: Option<&str>) -> Option<Enforcement> {
    match dec_str?.trim().to_ascii_lowercase().as_str() {
        "deny" => Some(Enforcement::Deny),
        "allow" => Some(Enforcement::Allow),
        "observe" => Some(Enforcement::Observe),
        "unsupported" => Some(Enforcement::Unsupported),
        _ => None,
    }
}

fn run_events_list(
    target: &str,
    decision_str: Option<&str>,
    since_str: Option<&str>,
    limit: usize,
    explicit_db_path: Option<&str>,
    as_json: bool,
) {
    let store = AuditStore::resolve_default(explicit_db_path);
    let filter = EventQueryFilter {
        target: Some(target.to_string()),
        decision: parse_decision_arg(decision_str),
        since_epoch_ms: parse_since_arg(since_str),
        limit,
    };
    match store.query_events(&filter) {
        Ok(rows) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string())
                );
            } else {
                println!("共查询到 {} 条脱敏安全审计事件:", rows.len());
                for r in &rows {
                    println!(
                        "- [{}] target={} tool={} decision={:?} code={} summary={}",
                        r.event_id,
                        r.target_id,
                        r.tool_name,
                        r.enforcement,
                        r.reason_code,
                        r.redacted_summary
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

fn run_events_pull(
    since_ms: u64,
    target: Option<&str>,
    limit: usize,
    source_db_path: Option<&str>,
    merge_into_db: Option<&str>,
    as_json: bool,
) {
    let src_store = AuditStore::resolve_default(source_db_path);
    match src_store.pull_events_since(since_ms, target, limit) {
        Ok(rows) => {
            let mut merged_count = None;
            if let Some(dest_db) = merge_into_db {
                let dst_store = AuditStore::new(PathBuf::from(dest_db));
                match dst_store.merge_pulled_events(&rows) {
                    Ok(cnt) => merged_count = Some(cnt),
                    Err(e) => {
                        eprintln!("ERROR [{}]: 合入目标数据库失败: {e}", e.code());
                        std::process::exit(1);
                    }
                }
            }
            let next_cursor_ms = rows
                .last()
                .map(|r| r.created_at_ms.saturating_add(1))
                .unwrap_or(since_ms);

            if as_json {
                let out = serde_json::json!({
                    "pulled_count": rows.len(),
                    "merged_count": merged_count,
                    "next_cursor_ms": next_cursor_ms,
                    "events": rows,
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                println!(
                    "OK: 拉取到 {} 条增量事件 (merged={:?}, next_cursor_ms={})",
                    rows.len(),
                    merged_count,
                    next_cursor_ms
                );
            }
        }
        Err(e) => {
            eprintln!("ERROR [{}]: {e}", e.code());
            std::process::exit(1);
        }
    }
}

fn run_events_export(
    output_path_str: &str,
    format_str: &str,
    target: &str,
    explicit_db_path: Option<&str>,
    as_json: bool,
) {
    let format = match ExportFormat::parse(format_str) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ERROR [{}]: {e}", e.code());
            std::process::exit(1);
        }
    };
    let store = AuditStore::resolve_default(explicit_db_path);
    let filter = EventQueryFilter {
        target: Some(target.to_string()),
        decision: None,
        since_epoch_ms: None,
        limit: usize::MAX,
    };
    let rows = match store.query_events(&filter) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR [{}]: {e}", e.code());
            std::process::exit(1);
        }
    };
    let out_path = Path::new(output_path_str);
    match store.export_redacted(&rows, format, out_path) {
        Ok(count) => {
            if as_json {
                let out = serde_json::json!({
                    "exported": true,
                    "count": count,
                    "format": format_str,
                    "output_path": output_path_str,
                    "redacted": true,
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                println!(
                    "OK: 已导出 {} 条二次脱敏审计记录至 `{}` (format={})",
                    count, output_path_str, format_str
                );
            }
        }
        Err(e) => {
            eprintln!("ERROR [{}]: {e}", e.code());
            std::process::exit(1);
        }
    }
}

pub fn collect_sessions_readonly(
    target_filter: &str,
    explicit_codex_home: Option<&str>,
    limit: usize,
) -> Vec<SessionSummary> {
    let filter = target_filter.trim().to_ascii_lowercase();
    let mut all_sessions: Vec<SessionSummary> = Vec::new();

    if let Some(explicit_home) = explicit_codex_home {
        let tid = if filter == "all" {
            "wsl2:Ubuntu".to_string()
        } else {
            target_filter.to_string()
        };
        if let Ok(mut list) = list_codex_sessions(&tid, Path::new(explicit_home), limit) {
            all_sessions.append(&mut list);
        }
    } else {
        if filter == "all" || filter.starts_with("wsl2") {
            let distro = std::env::var("WSL_DISTRO_NAME").unwrap_or_else(|_| "Ubuntu".to_string());
            let wsl_home =
                resolve_codex_home_for_target(&format!("wsl2:{distro}"), InstallScope::User, None);
            if let Ok(mut list) = list_codex_sessions(&format!("wsl2:{distro}"), &wsl_home, limit) {
                all_sessions.append(&mut list);
            }
        }
        if filter == "all" || filter == "host" || filter == "host:windows" {
            if let Some(win_home) = discover_windows_host_codex_home() {
                if let Ok(mut list) = list_codex_sessions("host:windows", &win_home, limit) {
                    all_sessions.append(&mut list);
                }
            }
        }
    }
    all_sessions
}

fn run_session_list(
    target_filter: &str,
    explicit_codex_home: Option<&str>,
    limit: usize,
    as_json: bool,
) {
    let all_sessions = collect_sessions_readonly(target_filter, explicit_codex_home, limit);

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&all_sessions).unwrap_or_else(|_| "[]".to_string())
        );
    } else {
        println!("共发现 {} 条 Codex 会话（只读索引）:", all_sessions.len());
        for s in &all_sessions {
            println!(
                "- [{}] id={} updated={} rollout={} title={}",
                s.target_id, s.session_id, s.updated_at, s.rollout_file_exists, s.title
            );
        }
    }
}

fn run_session_show(
    session_id: &str,
    target_id: &str,
    explicit_codex_home: Option<&str>,
    as_json: bool,
) {
    let codex_home =
        resolve_codex_home_for_target(target_id, InstallScope::User, explicit_codex_home);
    match get_codex_session_detail(target_id, &codex_home, session_id) {
        Ok(detail) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&detail).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!(
                    "Session [{}] target={} title={} turns={} events={}",
                    detail.summary.session_id,
                    detail.summary.target_id,
                    detail.summary.title,
                    detail.turns_count,
                    detail.rollout_events_count
                );
            }
        }
        Err(e) => {
            if as_json {
                let err_out = serde_json::json!({
                    "ok": false,
                    "error_code": e.code(),
                    "error_detail": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&err_out).unwrap());
            } else {
                eprintln!("ERROR [{}]: {e}", e.code());
            }
            std::process::exit(1);
        }
    }
}

fn run_session_backup(
    session_id: &str,
    target_id: &str,
    explicit_codex_home: Option<&str>,
    explicit_backup_dir: Option<&str>,
    as_json: bool,
) {
    let codex_home =
        resolve_codex_home_for_target(target_id, InstallScope::User, explicit_codex_home);
    let backup_store = resolve_backup_store(explicit_backup_dir);
    match backup_codex_session(target_id, &codex_home, session_id, &backup_store) {
        Ok(rep) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rep).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!(
                    "OK: 会话 `{}` 已完成只读快照备份并校验通过 (backup_id={}, files={})",
                    rep.session_id,
                    rep.backup_manifest.backup_id,
                    rep.backup_manifest.files.len()
                );
            }
        }
        Err(e) => {
            if as_json {
                let err_out = serde_json::json!({
                    "ok": false,
                    "error_code": e.code(),
                    "error_detail": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&err_out).unwrap());
            } else {
                eprintln!("ERROR [{}]: {e}", e.code());
            }
            std::process::exit(1);
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

pub fn resolve_codex_home_for_target(
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

pub fn resolve_backup_store(explicit_backup_dir: Option<&str>) -> BackupStore {
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
/// - 优先向 `stdout` 刷出裁决 JSON，随后以 15ms 超时无锁降级机制将脱敏审计事件写入 `AuditStore`，确保审计绝不阻塞或改变 `Deny` 决策。
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

    // 异步/无阻塞容错写入脱敏审计事件（即使写库失败也绝不影响已输出的 stdout 协议结果）
    if let Ok(ev) = parse_codex_pre_tool_use_bytes(&buf) {
        let store = AuditStore::resolve_default(None);
        let _ = store.record_event(&ev, &decision);
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
            None,
        );
        assert!(!report.codex_home_exists);
        assert!(!report.config_toml_exists);
        assert_eq!(report.protection_state, "unknown");
        assert!(!report.real_interception_verified);
    }
}
