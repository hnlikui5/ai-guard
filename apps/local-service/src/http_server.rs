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
    extract_apply_patch_paths, install_codex_hook, preflight_codex_run, InstallRequest,
    InstallScope, PreflightRequest,
};
use ai_guard_backup::BackupStore;
use ai_guard_security::{
    default_policy_engine, redact_secrets, ActionEvent, ActionKind, ClientSurface, EnvironmentKind,
    PolicyEngine,
};
use ai_guard_session::backup_codex_session;
use ai_guard_storage::{AuditStore, EventQueryFilter, ExportFormat};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub bind_addr: String,
    pub static_dir: Option<PathBuf>,
    pub db_path: Option<String>,
    pub backup_dir: Option<String>,
    pub policy_path: Option<String>,
}

/// 启动本地回路 HTTP JSON 服务（阻塞运行；供 `ai-guard serve` 调用）。
pub fn run_http_server(
    cfg: &ServeConfig,
    max_requests_for_test: Option<usize>,
) -> Result<(), String> {
    let sock_addr = validate_loopback_bind_addr(&cfg.bind_addr)?;
    let listener = TcpListener::bind(sock_addr)
        .map_err(|e| format!("[AG-HTTP-BIND-ERROR] 绑定本地回路 `{sock_addr}` 失败: {e}"))?;

    if max_requests_for_test.is_none() {
        println!("AI卫士本地控制服务已启动: http://{sock_addr} (严格限制本地回路访问)");
    }

    for (handled, stream_res) in listener.incoming().enumerate() {
        if let Ok(mut stream) = stream_res {
            let _ = handle_connection(&mut stream, cfg);
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

    // 静态文件服务（供桌面端 WebView 或浏览器预览加载）
    if let Some(ref static_root) = cfg.static_dir {
        let rel = path.trim_start_matches('/');
        let file_rel = if rel.is_empty() { "index.html" } else { rel };
        if !file_rel.contains("..") {
            let candidate = static_root.join(file_rel);
            if candidate.is_file() {
                if let Ok(bytes) = fs::read(&candidate) {
                    let content_type = guess_content_type(&candidate);
                    return write_raw_response(stream, 200, content_type, &bytes);
                }
            }
        }
    }

    write_json_response(
        stream,
        404,
        &json!({ "ok": false, "error_code": "AG-HTTP-404", "error": "Not Found" }),
    )
}

fn route_api_request(
    method: &str,
    path: &str,
    query: &HashMap<String, String>,
    body: &[u8],
    cfg: &ServeConfig,
) -> (u16, Value) {
    match (method, path) {
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
                    "overall_passed": all_passed,
                    "runs": runs,
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
                Ok(rep) => (200, serde_json::to_value(rep).unwrap_or_else(|_| json!({}))),
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
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: http://127.0.0.1:17900\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(bytes))
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())
}
