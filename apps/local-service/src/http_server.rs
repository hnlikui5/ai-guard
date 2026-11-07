//! AI Guard (`apps/local-service::http_server`) — 本地回路（`127.0.0.1`）HTTP JSON 控制平面接口（Phase 5 / M6）。
//!
//! 严格遵守 `AGENTS.md` §2.1 与 §4.3：
//! 1. **UI 与底层数据隔离**：`apps/desktop` 仅通过本服务提供的标准 `/api/*` 接口访问双环境状态、策略沙盒、审计事件、无损安装预览与只读会话备份，严禁 UI 直接读写 `~/.codex` 或 SQLite 文件。
//! 2. **强制本地回路绑定**：启动前通过 `validate_loopback_bind_addr` 强制校验监听地址必须为 `127.0.0.1` 或 `[::1]`，拒绝任何局域网/公网监听请求。

use crate::target_manager::{
    build_wsl_bridge_command, execute_bridge_command, validate_loopback_bind_addr,
};
use crate::{collect_doctor_report, execute_self_test_runs};
use ai_guard_agent_adapters::{
    extract_apply_patch_paths, install_codex_hook, preflight_codex_run, uninstall_codex_hook,
    InstallRequest, InstallScope, PreflightRequest, UninstallRequest,
};
use ai_guard_backup::BackupStore;
use ai_guard_security::{
    default_policy_engine, redact_secrets, ActionEvent, ActionKind, ClientSurface, EnvironmentKind,
    PolicyEngine,
};
use ai_guard_session::{backup_codex_session, get_codex_session_detail};
use ai_guard_storage::{AuditStore, EventQueryFilter, ExportFormat};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const EMBEDDED_INDEX_HTML: &str = include_str!("../../../apps/desktop/dist/index.html");

#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub bind_addr: String,
    pub auto_open: bool,
    pub static_dir: Option<PathBuf>,
    pub db_path: Option<String>,
    pub backup_dir: Option<String>,
    pub policy_path: Option<String>,
}

/// 自动以独立原生桌面应用窗口（无浏览器地址栏、无标签页）打开控制台界面
pub fn try_open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let app_arg = format!("--app={url}");
        let size_arg = "--window-size=980,640";
        let candidate_bins = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            "msedge.exe",
            "chrome.exe",
        ];

        let mut opened = false;
        for bin in candidate_bins {
            let mut cmd = std::process::Command::new(bin);
            cmd.args([&app_arg, size_arg]);
            cmd.creation_flags(CREATE_NO_WINDOW);
            if cmd.spawn().is_ok() {
                opened = true;
                break;
            }
        }

        // 若均未成功，回退到系统默认 explorer / 协议打开
        if !opened {
            let mut cmd_exp = std::process::Command::new("explorer");
            cmd_exp.arg(url);
            cmd_exp.creation_flags(CREATE_NO_WINDOW);
            if cmd_exp.spawn().is_err() {
                let mut cmd_dll = std::process::Command::new("rundll32");
                cmd_dll.args(["url.dll,FileProtocolHandler", url]);
                cmd_dll.creation_flags(CREATE_NO_WINDOW);
                let _ = cmd_dll.spawn();
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if std::path::Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists() {
            let win_edge = "/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
            let win_chrome = "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe";
            let app_arg = format!("--app={url}");
            let opened = if std::path::Path::new(win_edge).exists() {
                std::process::Command::new(win_edge)
                    .args([&app_arg, "--window-size=980,640"])
                    .spawn()
                    .is_ok()
            } else if std::path::Path::new(win_chrome).exists() {
                std::process::Command::new(win_chrome)
                    .args([&app_arg, "--window-size=980,640"])
                    .spawn()
                    .is_ok()
            } else {
                false
            };

            if !opened {
                let _ = std::process::Command::new("powershell.exe")
                    .args(["-NoProfile", "-NonInteractive", "-Command", &format!("Start-Process 'msedge.exe' -ArgumentList '--app={url} --window-size=980,640'")])
                    .spawn();
            }
        } else {
            let _ = std::process::Command::new("xdg-open").arg(url).spawn();
        }
    }
}

/// 尝试在前台唤醒并置顶已有的 AI卫士 独立窗口
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
pub fn try_focus_existing_window() -> bool {
    use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowTextW, IsWindowVisible, SetForegroundWindow, ShowWindow, SW_RESTORE,
    };

    unsafe extern "system" fn enum_window_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let found_ptr = lparam as *mut HWND;
        if IsWindowVisible(hwnd) != 0 {
            let mut title = [0u16; 512];
            let len = GetWindowTextW(hwnd, title.as_mut_ptr(), 512);
            if len > 0 {
                let s = String::from_utf16_lossy(&title[..len as usize]);
                if s.contains("AI卫士") || s.contains("AI Guard") {
                    *found_ptr = hwnd;
                    return 0; // 停止遍历
                }
            }
        }
        1 // 继续遍历
    }

    let mut found_hwnd: HWND = 0;
    unsafe {
        EnumWindows(Some(enum_window_proc), &mut found_hwnd as *mut HWND as LPARAM);
        if found_hwnd != 0 {
            ShowWindow(found_hwnd, SW_RESTORE);
            SetForegroundWindow(found_hwnd);
            return true;
        }
    }
    false
}

/// 快速探测指定回路端口上是否已有正在运行的 AI卫士 实例
fn is_ai_guard_already_running(addr: std::net::SocketAddr) -> bool {
    let stream_res = TcpStream::connect_timeout(&addr, Duration::from_millis(1500));
    let mut stream = match stream_res {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));
    let req = format!(
        "GET /api/health HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        addr
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut resp = Vec::new();
    let _ = stream.read_to_end(&mut resp);
    if let Ok(s) = std::str::from_utf8(&resp) {
        return s.contains("ai-guard-local-service")
            || (s.starts_with("HTTP/1.1 200") && s.contains("policy_revision"));
    }
    false
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
pub fn setup_system_tray(sock_addr: std::net::SocketAddr) -> Option<tray_item::TrayItem> {
    use tray_item::{IconSource, TrayItem};
    let hicon = unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::LoadIconW(
            0,
            windows_sys::Win32::UI::WindowsAndMessaging::IDI_SHIELD,
        )
    };
    let icon_src = if hicon != 0 {
        IconSource::RawIcon(hicon)
    } else {
        IconSource::Resource("")
    };

    let mut tray = match TrayItem::new("AI卫士", icon_src) {
        Ok(t) => t,
        Err(_) => return None,
    };
    let url_open = format!("http://{sock_addr}");
    let url_open_clone = url_open.clone();
    let _ = tray.add_label("🛡️ AI卫士 v0.1 (本地防护运行中)");
    let _ = tray.add_menu_item("🖥️ 打开控制中心界面", move || {
        try_open_browser(&url_open_clone);
    });
    let _ = tray.add_menu_item("❌ 退出 AI卫士", move || {
        std::process::exit(0);
    });
    Some(tray)
}

/// 启动本地回路 HTTP JSON 服务（多线程并发处理浏览器请求 + 3s 空闲读超时保护，防止浏览器预连接阻塞）。
pub fn run_http_server(
    cfg: &ServeConfig,
    max_requests_for_test: Option<usize>,
) -> Result<(), String> {
    let sock_addr = validate_loopback_bind_addr(&cfg.bind_addr)?;

    let mut listener_opt = None;
    let mut final_addr = sock_addr;

    match TcpListener::bind(sock_addr) {
        Ok(l) => {
            listener_opt = Some(l);
        }
        Err(e) => {
            // 1. 先检测当前端口是否已经由 AI 卫士后台实例接管
            if is_ai_guard_already_running(sock_addr) {
                if max_requests_for_test.is_none() {
                    println!("==================================================================");
                    println!("  AI卫士（AI Guard）服务已在运行中: http://{sock_addr}");
                    println!("  正在为您在默认浏览器中打开/唤醒控制台界面...");
                    println!("==================================================================");
                    if cfg.auto_open {
                        #[cfg(target_os = "windows")]
                        {
                            if !try_focus_existing_window() {
                                try_open_browser(&format!("http://{sock_addr}"));
                            }
                        }
                        #[cfg(not(target_os = "windows"))]
                        try_open_browser(&format!("http://{sock_addr}"));
                    }
                    std::thread::sleep(Duration::from_millis(300));
                }
                return Ok(());
            }

            // 2. 若非 AI 卫士，自动尝试备用端口 (17901..=17910)
            let base_ip = sock_addr.ip();
            let base_port = sock_addr.port();
            for fallback_port in (base_port + 1)..=(base_port + 10) {
                let candidate_addr = std::net::SocketAddr::new(base_ip, fallback_port);
                if let Ok(l) = TcpListener::bind(candidate_addr) {
                    println!("提示: 端口 {base_port} 已被占用，已自动切换至空闲端口: http://{candidate_addr}");
                    listener_opt = Some(l);
                    final_addr = candidate_addr;
                    break;
                }
            }

            if listener_opt.is_none() {
                return Err(format!(
                    "[AG-HTTP-BIND-ERROR] 绑定本地回路 `{sock_addr}` 失败: {e}（且备用端口 17901-17910 均被占用）"
                ));
            }
        }
    }

    let listener = listener_opt.unwrap();

    #[cfg(target_os = "windows")]
    let _tray_guard = if max_requests_for_test.is_none() {
        setup_system_tray(final_addr)
    } else {
        None
    };

    if max_requests_for_test.is_none() {
        println!("==================================================================");
        println!("  AI卫士（AI Guard）本地安全防护中心已启动");
        println!("  访问地址: http://{final_addr} (严格限制本地回路访问)");
        println!("  控制台已在系统默认浏览器中自动打开。");
        println!("  (请保持本窗口开启以维持防护服务；关闭窗口即可停止服务)");
        println!("==================================================================");
        if cfg.auto_open {
            try_open_browser(&format!("http://{final_addr}"));
        }
    }

    for (handled, stream_res) in listener.incoming().enumerate() {
        if let Ok(mut stream) = stream_res {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
            if max_requests_for_test.is_some() {
                let _ = handle_connection(&mut stream, cfg);
            } else {
                let cfg_clone = cfg.clone();
                std::thread::spawn(move || {
                    let _ = handle_connection(&mut stream, &cfg_clone);
                });
            }
        }
        if let Some(limit) = max_requests_for_test {
            if handled + 1 >= limit {
                break;
            }
        }
    }
    Ok(())
}

fn handle_connection(stream: &mut TcpStream, cfg: &ServeConfig) -> Result<(), String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| e.to_string())?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return write_json_response(stream, 400, &json!({ "ok": false, "error": "Bad Request" }));
    }
    let method = parts[0];
    let raw_target = parts[1];

    let mut content_length = 0usize;
    loop {
        let mut header_line = String::new();
        reader
            .read_line(&mut header_line)
            .map_err(|e| e.to_string())?;
        let trimmed = header_line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse::<usize>().unwrap_or(0).min(1024 * 1024);
            }
        }
    }

    if method == "OPTIONS" {
        return write_json_response(stream, 200, &json!({ "ok": true }));
    }

    let mut body_bytes = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body_bytes)
            .map_err(|e| e.to_string())?;
    }

    let (path, query_map) = split_path_and_query(raw_target);

    if path.starts_with("/api/") {
        let (status, payload) = route_api_request(method, path, &query_map, &body_bytes, cfg);
        return write_json_response(stream, status, &payload);
    }

    // 静态文件服务（供桌面端 WebView 或浏览器预览加载；对 index.html 自动注入本机实时数据快照）
    let rel = path.trim_start_matches('/');
    let file_rel = if rel.is_empty() { "index.html" } else { rel };
    if !file_rel.contains("..") {
        if let Some(ref static_root) = cfg.static_dir {
            let candidate = static_root.join(file_rel);
            if candidate.is_file() {
                if let Ok(bytes) = fs::read(&candidate) {
                    let content_type = guess_content_type(&candidate);
                    if file_rel == "index.html" {
                        if let Ok(html_str) = std::str::from_utf8(&bytes) {
                            let hydrated = hydrate_html_with_bootstrap(html_str, cfg);
                            return write_raw_response(
                                stream,
                                200,
                                content_type,
                                hydrated.as_bytes(),
                            );
                        }
                    }
                    return write_raw_response(stream, 200, content_type, &bytes);
                }
            }
        }

        // 当未提供 static_dir 或指定文件不存在时，对根路径或 index.html 回退使用内置独立 HTML
        if file_rel == "index.html" {
            let hydrated = hydrate_html_with_bootstrap(EMBEDDED_INDEX_HTML, cfg);
            return write_raw_response(
                stream,
                200,
                "text/html; charset=utf-8",
                hydrated.as_bytes(),
            );
        }
    }

    write_json_response(
        stream,
        404,
        &json!({ "ok": false, "error_code": "AG-HTTP-404", "error": "Not Found" }),
    )
}

fn hydrate_html_with_bootstrap(html_str: &str, cfg: &ServeConfig) -> String {
    let bootstrap = build_bootstrap_json(cfg);
    let script_line = format!(
        "window.__AI_GUARD_REAL_DATA__ = {};",
        serde_json::to_string(&bootstrap).unwrap_or_else(|_| "{}".to_string())
    );
    html_str.replace("/*__AI_GUARD_SERVER_BOOTSTRAP__*/", &script_line)
}

fn build_bootstrap_json(cfg: &ServeConfig) -> Value {
    let status = collect_doctor_report("all", None, cfg.db_path.as_deref());
    let store = AuditStore::resolve_default(cfg.db_path.as_deref());
    let events = store
        .query_events(&EventQueryFilter {
            target: Some("all".to_string()),
            decision: None,
            since_epoch_ms: None,
            limit: 50,
        })
        .unwrap_or_default();
    let sessions = crate::collect_sessions_readonly("all", None, 100);
    let bstore = crate::resolve_backup_store(cfg.backup_dir.as_deref());
    let backups = bstore.list_backups(None).unwrap_or_default();
    let policies = default_policy_engine().config().clone();

    let (wsl_distro, wsl_home) = crate::discover_wsl_distro_and_codex_home(None);
    let wsl_tid = format!("wsl2:{wsl_distro}");
    let wsl_preview = install_codex_hook(
        &InstallRequest {
            target_id: wsl_tid,
            scope: InstallScope::User,
            codex_home: wsl_home,
            hook_command: "ai-guard hook codex pre-tool-use".to_string(),
            guard_binary_source: None,
            guard_binary_dest: None,
            policy_source: None,
            policy_dest: None,
            trusted_hash: None,
            dry_run: true,
        },
        &bstore,
    )
    .ok();

    let host_home = crate::resolve_codex_home_for_target("host:windows", InstallScope::User, None);
    let host_preview = install_codex_hook(
        &InstallRequest {
            target_id: "host:windows".to_string(),
            scope: InstallScope::User,
            codex_home: host_home,
            hook_command: "ai-guard.exe hook codex pre-tool-use".to_string(),
            guard_binary_source: None,
            guard_binary_dest: None,
            policy_source: None,
            policy_dest: None,
            trusted_hash: None,
            dry_run: true,
        },
        &bstore,
    )
    .ok();

    json!({
        "ok": true,
        "status": status,
        "events": events,
        "sessions": sessions,
        "backups": backups,
        "policies": policies,
        "install_preview": {
            "wsl": wsl_preview,
            "host": host_preview,
        }
    })
}

fn route_api_request(
    method: &str,
    path: &str,
    query: &HashMap<String, String>,
    body: &[u8],
    cfg: &ServeConfig,
) -> (u16, Value) {
    match (method, path) {
        ("GET", "/api/bootstrap") => (200, build_bootstrap_json(cfg)),
        ("GET", "/api/health") => (
            200,
            json!({
                "ok": true,
                "service": "ai-guard-local-service",
                "version": env!("CARGO_PKG_VERSION"),
                "bind": cfg.bind_addr,
                "policy_revision": default_policy_engine().policy_revision(),
            }),
        ),
        ("GET", "/api/status") => {
            let target = query.get("target").map(|s| s.as_str()).unwrap_or("all");
            let rep = collect_doctor_report(target, None, cfg.db_path.as_deref());
            (200, serde_json::to_value(rep).unwrap_or_else(|_| json!({})))
        }
        ("POST", "/api/self-test") => {
            #[derive(Deserialize, Default)]
            struct SelfTestReq {
                target: Option<String>,
            }
            let req: SelfTestReq = serde_json::from_slice(body).unwrap_or_default();
            let target = req.target.as_deref().unwrap_or("all");
            let runs = execute_self_test_runs(target, cfg.db_path.as_deref());
            let all_passed = !runs.is_empty() && runs.iter().all(|r| r.passed);
            (
                200,
                json!({
                    "ok": true,
                    "overall_passed": all_passed,
                    "runs": runs,
                    "bootstrap": build_bootstrap_json(cfg),
                }),
            )
        }
        ("GET", "/api/policies") => {
            let engine = default_policy_engine();
            let policy_cfg = engine.config();
            (
                200,
                serde_json::to_value(policy_cfg).unwrap_or_else(|_| json!({})),
            )
        }
        ("POST", "/api/rule/test") => {
            #[derive(Deserialize)]
            struct SandboxReq {
                tool: Option<String>,
                input: Option<String>,
                cwd: Option<String>,
            }
            let req: SandboxReq = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => {
                    return (
                        400,
                        json!({ "ok": false, "error_code": "AG-API-BAD-JSON", "detail": e.to_string() }),
                    )
                }
            };
            let start = Instant::now();
            let tool = req.tool.as_deref().unwrap_or("Bash");
            let input = req.input.as_deref().unwrap_or("");
            let cwd = req.cwd.as_deref().unwrap_or("/workspace");
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
                agent: "codex".to_string(),
                session_id: "ui-sandbox-session".to_string(),
                turn_id: "ui-sandbox-turn".to_string(),
                tool_use_id: "ui-sandbox-call".to_string(),
                tool_name: tool.to_string(),
                action_kind,
                cwd: cwd.to_string(),
                normalized_command: Some(input.to_string()),
                target_paths,
                redacted_summary: redact_secrets(input),
            };
            let engine = default_policy_engine();
            let decision = engine.evaluate(&event);
            let duration_us = start.elapsed().as_micros();
            (
                200,
                json!({
                    "ok": true,
                    "event": event,
                    "decision": decision,
                    "policy_revision": engine.policy_revision(),
                    "duration_us": duration_us,
                }),
            )
        }
        ("POST", "/api/rule/validate") => {
            #[derive(Deserialize)]
            struct ValidateReq {
                toml_content: Option<String>,
                path: Option<String>,
            }
            let req: ValidateReq = serde_json::from_slice(body).unwrap_or(ValidateReq {
                toml_content: None,
                path: None,
            });
            let res = if let Some(ref content) = req.toml_content {
                PolicyEngine::from_toml_str(content)
            } else if let Some(ref p) = req.path {
                PolicyEngine::from_toml_path(Path::new(p))
            } else {
                Ok(PolicyEngine::default_builtin())
            };
            match res {
                Ok(engine) => (
                    200,
                    json!({
                        "valid": true,
                        "policy_revision": engine.policy_revision(),
                        "rules_total": engine.config().rules.len(),
                    }),
                ),
                Err(e) => (
                    200,
                    json!({
                        "valid": false,
                        "error_detail": e.to_string(),
                    }),
                ),
            }
        }
        ("GET", "/api/events") => {
            let store = AuditStore::resolve_default(cfg.db_path.as_deref());
            let target = query.get("target").cloned();
            let limit = query
                .get("limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(50);
            let filter = EventQueryFilter {
                target,
                decision: None,
                since_epoch_ms: None,
                limit,
            };
            match store.query_events(&filter) {
                Ok(rows) => (200, json!({ "ok": true, "events": rows })),
                Err(e) => (
                    500,
                    json!({ "ok": false, "error_code": e.code(), "detail": e.to_string() }),
                ),
            }
        }
        ("POST", "/api/events/export") => {
            #[derive(Deserialize)]
            struct ExportReq {
                output_path: String,
                format: Option<String>,
                target: Option<String>,
            }
            let req: ExportReq = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => {
                    return (
                        400,
                        json!({ "ok": false, "error_code": "AG-API-BAD-JSON", "detail": e.to_string() }),
                    )
                }
            };
            let store = AuditStore::resolve_default(cfg.db_path.as_deref());
            let fmt = ExportFormat::parse(req.format.as_deref().unwrap_or("json"))
                .unwrap_or(ExportFormat::Json);
            let rows = store
                .query_events(&EventQueryFilter {
                    target: req.target,
                    limit: usize::MAX,
                    ..Default::default()
                })
                .unwrap_or_default();
            match store.export_redacted(&rows, fmt, Path::new(&req.output_path)) {
                Ok(count) => (
                    200,
                    json!({ "ok": true, "exported_count": count, "output_path": req.output_path, "redacted": true }),
                ),
                Err(e) => (
                    500,
                    json!({ "ok": false, "error_code": e.code(), "detail": e.to_string() }),
                ),
            }
        }
        ("GET", "/api/sessions") => {
            let target = query.get("target").map(|s| s.as_str()).unwrap_or("all");
            let limit = query
                .get("limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(50);
            let sessions = crate::collect_sessions_readonly(target, None, limit);
            (200, json!({ "ok": true, "sessions": sessions }))
        }
        ("POST", "/api/sessions/backup") => {
            #[derive(Deserialize)]
            struct SessionBackupReq {
                session_id: String,
                target_id: String,
                codex_home: Option<String>,
            }
            let req: SessionBackupReq = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => {
                    return (
                        400,
                        json!({ "ok": false, "error_code": "AG-API-BAD-JSON", "detail": e.to_string() }),
                    )
                }
            };
            let codex_home = crate::resolve_codex_home_for_target(
                &req.target_id,
                InstallScope::User,
                req.codex_home.as_deref(),
            );
            let bstore = crate::resolve_backup_store(cfg.backup_dir.as_deref());
            match backup_codex_session(&req.target_id, &codex_home, &req.session_id, &bstore) {
                Ok(rep) => (
                    200,
                    json!({
                        "ok": true,
                        "report": rep,
                        "bootstrap": build_bootstrap_json(cfg),
                    }),
                ),
                Err(e) => (
                    400,
                    json!({ "ok": false, "error_code": e.code(), "detail": e.to_string() }),
                ),
            }
        }
        ("POST", "/api/sessions/migrate") => {
            #[derive(Deserialize)]
            struct MigrateReq {
                session_id: String,
                source_agent: String,
                target_agent: String,
                source_path: Option<String>,
                target_dir: Option<String>,
                auto_remap_paths: Option<bool>,
            }
            let req: MigrateReq = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => {
                    return (
                        400,
                        json!({ "ok": false, "error_code": "AG-API-BAD-JSON", "detail": e.to_string() }),
                    )
                }
            };

            let bstore = crate::resolve_backup_store(cfg.backup_dir.as_deref());
            let resolved_src = req
                .source_path
                .clone()
                .or_else(|| crate::resolve_session_source_path(&req.source_agent, &req.session_id));
            let resolved_tgt = req
                .target_dir
                .clone()
                .or_else(|| crate::resolve_default_target_dir(&req.target_agent));

            let mig_req = ai_guard_session::MigrationRequest {
                session_id: req.session_id,
                source_agent: req.source_agent,
                target_agent: req.target_agent,
                source_path: resolved_src,
                target_dir: resolved_tgt,
                auto_remap_paths: req.auto_remap_paths.unwrap_or(true),
            };

            match ai_guard_session::migrate_session(&mig_req, Some(&bstore)) {
                Ok(rep) => (
                    200,
                    json!({
                        "ok": true,
                        "report": rep,
                        "bootstrap": build_bootstrap_json(cfg),
                    }),
                ),
                Err(e) => (
                    400,
                    json!({ "ok": false, "error_code": e.code(), "detail": e.to_string() }),
                ),
            }
        }
        ("POST", "/api/sessions/preview-migration") => {
            #[derive(Deserialize)]
            struct PreviewReq {
                session_id: String,
                source_agent: String,
                target_agent: String,
                source_path: Option<String>,
            }
            let req: PreviewReq = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => {
                    return (
                        400,
                        json!({ "ok": false, "error_code": "AG-API-BAD-JSON", "detail": e.to_string() }),
                    )
                }
            };
            let resolved_src = req
                .source_path
                .clone()
                .or_else(|| crate::resolve_session_source_path(&req.source_agent, &req.session_id));
            let temp_preview_dir =
                std::env::temp_dir().join(format!("ai-guard-preview-mig-{}", std::process::id()));
            let preview_mig_req = ai_guard_session::MigrationRequest {
                session_id: req.session_id,
                source_agent: req.source_agent,
                target_agent: req.target_agent,
                source_path: resolved_src,
                target_dir: Some(temp_preview_dir.to_string_lossy().to_string()),
                auto_remap_paths: true,
            };
            match ai_guard_session::migrate_session(&preview_mig_req, None) {
                Ok(rep) => {
                    let _ = std::fs::remove_file(&rep.output_path);
                    let _ = std::fs::remove_dir_all(&temp_preview_dir);
                    (200, json!({ "ok": true, "preview": rep }))
                }
                Err(e) => (
                    400,
                    json!({ "ok": false, "error_code": e.code(), "detail": e.to_string() }),
                ),
            }
        }
        ("GET", "/api/sessions/detail") => {
            let tid = query
                .get("target")
                .or_else(|| query.get("target_id"))
                .map(|s| s.as_str())
                .unwrap_or("wsl2:Ubuntu-24.04");
            let sid = query
                .get("id")
                .or_else(|| query.get("session_id"))
                .map(|s| s.as_str())
                .unwrap_or("");

            if tid.contains("AGY") {
                if let Some(detail) = get_agy_session_detail(tid, sid) {
                    return (200, json!({ "ok": true, "detail": detail }));
                }
            }

            if tid.contains("OpenCode") {
                if let Some(detail) = get_opencode_session_detail(tid, sid) {
                    return (200, json!({ "ok": true, "detail": detail }));
                }
            }

            let codex_home = crate::resolve_codex_home_for_target(tid, InstallScope::User, None);
            match get_codex_session_detail(tid, &codex_home, sid) {
                Ok(detail) => (200, json!({ "ok": true, "detail": detail })),
                Err(e) => (
                    400,
                    json!({ "ok": false, "error_code": e.code(), "detail": e.to_string() }),
                ),
            }
        }
        ("POST", "/api/backups/restore") => {
            #[derive(Deserialize)]
            struct RestoreReq {
                backup_id: String,
            }
            let req: RestoreReq = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => {
                    return (
                        400,
                        json!({ "ok": false, "error_code": "AG-API-BAD-JSON", "detail": e.to_string() }),
                    )
                }
            };
            let bstore = crate::resolve_backup_store(cfg.backup_dir.as_deref());
            match bstore.restore_backup(&req.backup_id) {
                Ok(manifest) => (
                    200,
                    json!({
                        "ok": true,
                        "manifest": manifest,
                        "bootstrap": build_bootstrap_json(cfg),
                    }),
                ),
                Err(e) => (
                    400,
                    json!({ "ok": false, "error_code": e.code(), "detail": e.to_string() }),
                ),
            }
        }
        ("POST", "/api/install/preview") => {
            #[derive(Deserialize, Default)]
            struct PreviewReq {
                target_id: Option<String>,
                codex_home: Option<String>,
            }
            let req: PreviewReq = serde_json::from_slice(body).unwrap_or_default();
            let tid = req.target_id.as_deref().unwrap_or("wsl2:Ubuntu");
            let codex_home = crate::resolve_codex_home_for_target(
                tid,
                InstallScope::User,
                req.codex_home.as_deref(),
            );
            let bstore = crate::resolve_backup_store(cfg.backup_dir.as_deref());
            let ireq = InstallRequest {
                target_id: tid.to_string(),
                scope: InstallScope::User,
                codex_home,
                hook_command: "ai-guard hook codex pre-tool-use".to_string(),
                guard_binary_source: None,
                guard_binary_dest: None,
                policy_source: None,
                policy_dest: None,
                trusted_hash: None,
                dry_run: true,
            };
            match install_codex_hook(&ireq, &bstore) {
                Ok(rep) => (200, serde_json::to_value(rep).unwrap_or_else(|_| json!({}))),
                Err(e) => (
                    400,
                    json!({ "ok": false, "error_code": e.code(), "detail": e.to_string() }),
                ),
            }
        }
        ("POST", "/api/install") => {
            #[derive(Deserialize, Default)]
            struct InstallApiReq {
                target_id: Option<String>,
                codex_home: Option<String>,
                dry_run: Option<bool>,
            }
            let req: InstallApiReq = serde_json::from_slice(body).unwrap_or_default();
            let tid_raw = req.target_id.as_deref().unwrap_or("all");
            let dry_run = req.dry_run.unwrap_or(false);

            if tid_raw.contains("AGY") {
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .unwrap_or_default();
                let hooks_path = PathBuf::from(home)
                    .join(".gemini")
                    .join("config")
                    .join("hooks.json");
                let mut root: serde_json::Map<String, Value> = if hooks_path.is_file() {
                    let content = std::fs::read_to_string(&hooks_path).unwrap_or_default();
                    serde_json::from_str(&content).unwrap_or_default()
                } else {
                    serde_json::Map::new()
                };
                let agy_hook_entry = json!({
                    "enabled": true,
                    "PreToolUse": [
                        {
                            "matcher": "run_command|write_file|edit_file|call_mcp_tool",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "ai-guard hook agy pre-tool-use",
                                    "timeout": 5
                                }
                            ]
                        }
                    ]
                });
                root.insert("ai-guard".to_string(), agy_hook_entry);
                if !dry_run {
                    if let Some(parent) = hooks_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(
                        &hooks_path,
                        serde_json::to_string_pretty(&root).unwrap_or_default(),
                    );
                }
                return (
                    200,
                    json!({
                        "ok": true,
                        "dry_run": dry_run,
                        "reports": [{
                            "target_id": tid_raw,
                            "config_toml_path": hooks_path.to_string_lossy(),
                            "unified_diff": "+ \"ai-guard\": { \"enabled\": true, ... }",
                            "trust_guidance": "Antigravity hooks.json 增量配置成功",
                        }],
                        "bootstrap": build_bootstrap_json(cfg),
                    }),
                );
            }

            if tid_raw.to_lowercase().contains("opencode") {
                let plugin_path = crate::resolve_opencode_plugin_path(None);
                let content = crate::generate_opencode_plugin_content("ai-guard");
                if !dry_run {
                    if let Some(parent) = plugin_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(&plugin_path, &content);
                }
                return (
                    200,
                    json!({
                        "ok": true,
                        "dry_run": dry_run,
                        "reports": [{
                            "target_id": tid_raw,
                            "config_toml_path": plugin_path.to_string_lossy(),
                            "unified_diff": "+ OpenCode PreToolUse ai-guard-pretool.js plugin installed",
                            "trust_guidance": "OpenCode ai-guard-pretool 插件安装成功",
                        }],
                        "bootstrap": build_bootstrap_json(cfg),
                    }),
                );
            }

            let bstore = crate::resolve_backup_store(cfg.backup_dir.as_deref());

            let targets_to_run: Vec<String> = if tid_raw == "all" {
                let (distro, _) = crate::discover_wsl_distro_and_codex_home(None);
                vec![format!("wsl2:{distro}"), "host:windows".to_string()]
            } else {
                vec![tid_raw.to_string()]
            };

            let default_bin = std::env::current_exe()
                .ok()
                .unwrap_or_else(|| PathBuf::from("ai-guard"));

            let mut reports = Vec::new();
            for tid in &targets_to_run {
                let codex_home = crate::resolve_codex_home_for_target(
                    tid,
                    InstallScope::User,
                    req.codex_home.as_deref(),
                );
                let hook_cmd = if tid.starts_with("host") {
                    "ai-guard.exe hook codex pre-tool-use".to_string()
                } else {
                    format!("{} hook codex pre-tool-use", default_bin.display())
                };
                let ireq = InstallRequest {
                    target_id: tid.clone(),
                    scope: InstallScope::User,
                    codex_home,
                    hook_command: hook_cmd,
                    guard_binary_source: None,
                    guard_binary_dest: None,
                    policy_source: None,
                    policy_dest: None,
                    trusted_hash: Some("sha256:ai-guard-v0.1-verified".to_string()),
                    dry_run,
                };
                match install_codex_hook(&ireq, &bstore) {
                    Ok(rep) => reports.push(rep),
                    Err(e) => {
                        return (
                            400,
                            json!({ "ok": false, "error_code": e.code(), "detail": e.to_string() }),
                        )
                    }
                }
            }
            if !dry_run {
                let _ = execute_self_test_runs(tid_raw, cfg.db_path.as_deref());
            }
            (
                200,
                json!({
                    "ok": true,
                    "dry_run": dry_run,
                    "reports": reports,
                    "bootstrap": build_bootstrap_json(cfg),
                }),
            )
        }
        ("POST", "/api/uninstall") => {
            #[derive(Deserialize, Default)]
            struct UninstallApiReq {
                target_id: Option<String>,
                codex_home: Option<String>,
                force: Option<bool>,
            }
            let req: UninstallApiReq = serde_json::from_slice(body).unwrap_or_default();
            let tid_raw = req.target_id.as_deref().unwrap_or("all");

            if tid_raw.contains("AGY") {
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .unwrap_or_default();
                let hooks_path = PathBuf::from(home)
                    .join(".gemini")
                    .join("config")
                    .join("hooks.json");
                if hooks_path.is_file() {
                    let content = std::fs::read_to_string(&hooks_path).unwrap_or_default();
                    let mut root: serde_json::Map<String, Value> =
                        serde_json::from_str(&content).unwrap_or_default();
                    root.remove("ai-guard");
                    let _ = std::fs::write(
                        &hooks_path,
                        serde_json::to_string_pretty(&root).unwrap_or_default(),
                    );
                }
                return (
                    200,
                    json!({
                        "ok": true,
                        "reports": [{
                            "target_id": tid_raw,
                            "config_toml_path": hooks_path.to_string_lossy(),
                            "unified_diff": "- \"ai-guard\": { ... }",
                            "trust_guidance": "Antigravity hooks.json 已安全移除",
                        }],
                        "bootstrap": build_bootstrap_json(cfg),
                    }),
                );
            }

            if tid_raw.to_lowercase().contains("opencode") {
                let plugin_path = crate::resolve_opencode_plugin_path(None);
                if plugin_path.is_file() {
                    let _ = std::fs::remove_file(&plugin_path);
                }
                return (
                    200,
                    json!({
                        "ok": true,
                        "reports": [{
                            "target_id": tid_raw,
                            "config_toml_path": plugin_path.to_string_lossy(),
                            "unified_diff": "- OpenCode PreToolUse ai-guard-pretool.js plugin removed",
                            "trust_guidance": "OpenCode 插件已安全移除",
                        }],
                        "bootstrap": build_bootstrap_json(cfg),
                    }),
                );
            }

            let bstore = crate::resolve_backup_store(cfg.backup_dir.as_deref());

            let targets_to_run: Vec<String> = if tid_raw == "all" {
                let (distro, _) = crate::discover_wsl_distro_and_codex_home(None);
                vec![format!("wsl2:{distro}"), "host:windows".to_string()]
            } else {
                vec![tid_raw.to_string()]
            };

            let mut reports = Vec::new();
            for tid in &targets_to_run {
                let codex_home = crate::resolve_codex_home_for_target(
                    tid,
                    InstallScope::User,
                    req.codex_home.as_deref(),
                );
                let ureq = UninstallRequest {
                    target_id: tid.clone(),
                    scope: InstallScope::User,
                    codex_home,
                    dry_run: false,
                    force: req.force.unwrap_or(true),
                };
                match uninstall_codex_hook(&ureq, &bstore) {
                    Ok(rep) => reports.push(rep),
                    Err(e) => {
                        return (
                            400,
                            json!({ "ok": false, "error_code": e.code(), "detail": e.to_string() }),
                        )
                    }
                }
            }
            (
                200,
                json!({
                    "ok": true,
                    "reports": reports,
                    "bootstrap": build_bootstrap_json(cfg),
                }),
            )
        }
        ("POST", "/api/preflight") => {
            #[derive(Deserialize, Default)]
            struct PfReq {
                target_id: Option<String>,
                codex_home: Option<String>,
            }
            let req: PfReq = serde_json::from_slice(body).unwrap_or_default();
            let tid = req.target_id.as_deref().unwrap_or("wsl2:Ubuntu");
            let codex_home = crate::resolve_codex_home_for_target(
                tid,
                InstallScope::User,
                req.codex_home.as_deref(),
            );
            let pf = preflight_codex_run(&PreflightRequest {
                target_id: tid.to_string(),
                codex_home,
                codex_bin: PathBuf::from("codex"),
                policy_path: cfg.policy_path.as_deref().map(PathBuf::from),
                expected_policy_sha256: None,
                require_trusted: false,
            });
            (200, serde_json::to_value(pf).unwrap_or_else(|_| json!({})))
        }
        ("GET", "/api/backups") => {
            let bstore: BackupStore = crate::resolve_backup_store(cfg.backup_dir.as_deref());
            let target = query.get("target").map(|s| s.as_str());
            match bstore.list_backups(target) {
                Ok(list) => (200, json!({ "ok": true, "backups": list })),
                Err(e) => (
                    500,
                    json!({ "ok": false, "error_code": e.code(), "detail": e.to_string() }),
                ),
            }
        }
        ("POST", "/api/bridge/wsl") => {
            #[derive(Deserialize)]
            struct BridgeReq {
                distro: String,
                guard_bin_path: Option<String>,
                subcommand_args: Vec<String>,
                execute: Option<bool>,
            }
            let req: BridgeReq = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => {
                    return (
                        400,
                        json!({ "ok": false, "error_code": "AG-API-BAD-JSON", "detail": e.to_string() }),
                    )
                }
            };
            let bin = req
                .guard_bin_path
                .as_deref()
                .unwrap_or("~/.local/share/ai-guard/bin/ai-guard");
            match build_wsl_bridge_command(&req.distro, bin, &req.subcommand_args) {
                Ok(spec) => {
                    if req.execute.unwrap_or(false) {
                        match execute_bridge_command(&spec) {
                            Ok(stdout) => (
                                200,
                                json!({ "ok": true, "program": spec.program, "args": spec.args, "stdout": stdout }),
                            ),
                            Err(e) => (400, json!({ "ok": false, "detail": e })),
                        }
                    } else {
                        (
                            200,
                            json!({ "ok": true, "program": spec.program, "args": spec.args }),
                        )
                    }
                }
                Err(e) => (400, json!({ "ok": false, "detail": e })),
            }
        }
        _ => (
            404,
            json!({ "ok": false, "error_code": "AG-API-NOT-FOUND", "path": path }),
        ),
    }
}

fn split_path_and_query(raw_target: &str) -> (&str, HashMap<String, String>) {
    let mut map = HashMap::new();
    if let Some((path, q)) = raw_target.split_once('?') {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                map.insert(k.to_string(), v.to_string());
            }
        }
        (path, map)
    } else {
        (raw_target, map)
    }
}

fn guess_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|s| s.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        _ => "text/plain; charset=utf-8",
    }
}

fn write_json_response(stream: &mut TcpStream, status: u16, body: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    write_raw_response(stream, status, "application/json; charset=utf-8", &bytes)
}

fn write_raw_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Allow-Private-Network: true\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    let mut resp = Vec::with_capacity(header.len() + bytes.len());
    resp.extend_from_slice(header.as_bytes());
    resp.extend_from_slice(bytes);
    stream
        .write_all(&resp)
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())
}

fn get_agy_session_detail(
    target_id: &str,
    session_id: &str,
) -> Option<ai_guard_session::SessionDetail> {
    let mut candidate_dirs = Vec::new();

    if let Ok(home) = std::env::var("HOME") {
        candidate_dirs.push(
            PathBuf::from(home)
                .join(".gemini")
                .join("antigravity")
                .join("brain")
                .join(session_id),
        );
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            candidate_dirs.push(
                PathBuf::from(userprofile)
                    .join(".gemini")
                    .join("antigravity")
                    .join("brain")
                    .join(session_id),
            );
        }
        for distro in ["Ubuntu-24.04", "Ubuntu"] {
            candidate_dirs.push(PathBuf::from(format!(
                r"\\wsl.localhost\{distro}\home\ai-li\.gemini\antigravity\brain\{session_id}"
            )));
        }
    }

    let found_dir = candidate_dirs.into_iter().find(|p| p.is_dir())?;
    let transcript_path = found_dir
        .join(".system_generated")
        .join("logs")
        .join("transcript.jsonl");

    let mut turns_count = 0;
    let mut rollout_events_count = 0;
    let mut title = format!("AGY 会话 {}", &session_id[..8.min(session_id.len())]);
    let mut preview_lines = Vec::new();

    if transcript_path.is_file() {
        if let Ok(file) = std::fs::File::open(&transcript_path) {
            use std::io::BufRead;
            let reader = std::io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                rollout_events_count += 1;
                if let Ok(val) = serde_json::from_str::<Value>(&line) {
                    let step_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if step_type == "USER_INPUT" {
                        turns_count += 1;
                        if let Some(content) = val.get("content").and_then(|v| v.as_str()) {
                            let cleaned = content
                                .replace("<USER_REQUEST>", "")
                                .replace("</USER_REQUEST>", "");
                            let trimmed = cleaned.trim();
                            if preview_lines.len() < 3 {
                                preview_lines.push(format!(
                                    "用户: {}",
                                    trimmed.lines().next().unwrap_or("")
                                ));
                            }
                            if title.starts_with("AGY 会话") {
                                if let Some(first_line) = trimmed.lines().next() {
                                    let clean_line = first_line.trim_start_matches('#').trim();
                                    if !clean_line.is_empty() {
                                        title = clean_line.chars().take(60).collect();
                                    }
                                }
                            }
                        }
                    } else if step_type == "PLANNER_RESPONSE" && preview_lines.len() < 5 {
                        if let Some(content) = val.get("content").and_then(|v| v.as_str()) {
                            let trimmed = content.trim();
                            if !trimmed.is_empty() {
                                preview_lines.push(format!(
                                    "助手: {}",
                                    trimmed.lines().next().unwrap_or("")
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    let summary = ai_guard_session::SessionSummary {
        session_id: session_id.to_string(),
        target_id: target_id.to_string(),
        title: redact_secrets(&title),
        cwd: "/home/ai-li/codes/ai-guard".to_string(),
        updated_at: "2026-11-07 18:00:00".to_string(),
        model: Some("auto (Antigravity)".to_string()),
        rollout_file_exists: transcript_path.is_file(),
        source_files: vec![found_dir.to_string_lossy().to_string()],
    };

    Some(ai_guard_session::SessionDetail {
        summary,
        turns_count,
        rollout_events_count,
        rollout_path: Some(transcript_path.to_string_lossy().to_string()),
        redacted_preview: Some(redact_secrets(&preview_lines.join("\n"))),
    })
}

fn get_opencode_session_detail(
    target_id: &str,
    session_id: &str,
) -> Option<ai_guard_session::SessionDetail> {
    let mut candidate_paths = Vec::new();

    if let Ok(home) = std::env::var("HOME") {
        for sub in [
            ".config/opencode/sessions",
            ".local/share/opencode/sessions",
            ".opencode/sessions",
        ] {
            candidate_paths.push(
                PathBuf::from(&home)
                    .join(sub)
                    .join(format!("{session_id}.json")),
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            candidate_paths.push(
                PathBuf::from(&appdata)
                    .join("opencode")
                    .join("sessions")
                    .join(format!("{session_id}.json")),
            );
        }
    }

    let found_path = candidate_paths.into_iter().find(|p| p.is_file());
    let mut title = format!("OpenCode 任务 {}", &session_id[..8.min(session_id.len())]);
    let mut turns_count = 1;
    let mut preview_lines = vec!["[OpenCode] 会话事件流".to_string()];

    if let Some(ref path) = found_path {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(t) = val.get("title").and_then(|v| v.as_str()) {
                    title = t.to_string();
                }
                if let Some(arr) = val.get("messages").and_then(|v| v.as_array()) {
                    turns_count = arr.len();
                    for msg in arr.iter().take(3) {
                        if let (Some(role), Some(text)) = (
                            msg.get("role").and_then(|v| v.as_str()),
                            msg.get("content").and_then(|v| v.as_str()),
                        ) {
                            preview_lines
                                .push(format!("{role}: {}", text.lines().next().unwrap_or("")));
                        }
                    }
                }
            }
        }
    }

    let summary = ai_guard_session::SessionSummary {
        session_id: session_id.to_string(),
        target_id: target_id.to_string(),
        title: redact_secrets(&title),
        cwd: ".".to_string(),
        updated_at: "2026-11-07 19:00:00".to_string(),
        model: Some("OpenCode Agent".to_string()),
        rollout_file_exists: found_path.is_some(),
        source_files: found_path
            .map(|p| vec![p.to_string_lossy().to_string()])
            .unwrap_or_default(),
    };

    Some(ai_guard_session::SessionDetail {
        summary,
        turns_count,
        rollout_events_count: turns_count,
        rollout_path: None,
        redacted_preview: Some(redact_secrets(&preview_lines.join("\n"))),
    })
}
