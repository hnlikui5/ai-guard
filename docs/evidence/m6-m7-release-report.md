# Phase 5（M6 + M7）桌面端控制平面、WSL2 安全桥接与 V0.1-GA 发布验收报告

- **所属阶段**：Phase 5（`M6 + M7`）
- **生成时间**：2026-11-07
- **目标版本**：`v0.1.0`（Personal Edition V0.1-GA）
- **关联需求与设计**：
  - `docs/PRD_V0.1.md`（§5.2 桌面端信息架构、§5.6 M6/M7 里程碑）
  - `docs/AI_Guard_Implementation_Pack/docs/IMPLEMENTATION_BACKLOG_V1.0.md`（`M6-01` ~ `M6-04`、`M7-01` ~ `M7-04`）
  - `AGENTS.md`（§2.1 UI 与底层数据隔离、§3 开源参考代码红线、§4 安全模块开发强制约束、§5.4 实际拦截测试证据原则）

---

## 1. Phase 5（M6 + M7）核心交付物清单

| 任务 ID | 模块路径 | 核心实现摘要 | 状态 |
| :--- | :--- | :--- | :---: |
| `M6-01` | `apps/local-service/src/target_manager.rs` | 实现 Windows 宿主机 -> WSL2 跨边界安全桥接器 `build_wsl_bridge_command`、`validate_wsl_distro_name`、`validate_safe_bridge_token`（强制拦截以 `-` 开头的参数注入、控制字符、NUL 字节，固定生成 `wsl.exe -d <distro> --exec <bin> ...` 独立参数数组）及 `validate_loopback_bind_addr`（强制拦截 `0.0.0.0` 等非本地回路监听请求，返回 `AG-SECURITY-NON-LOOPBACK`）。 | 已完成 |
| `M6-02` | `apps/local-service/src/http_server.rs`<br>`apps/desktop/src/api/client.ts` | 实现严格绑定 `127.0.0.1` 的本地控制服务 `ai-guard serve`，提供 `/api/health`、`/api/status`、`/api/self-test`、`/api/policies`、`/api/rule/test`、`/api/rule/validate`、`/api/events`、`/api/events/export`、`/api/sessions`、`/api/sessions/backup`、`/api/install/preview`、`/api/preflight`、`/api/backups`、`/api/bridge/wsl` 共 14 个标准 API 端点，严格隔离 UI 与底层 `~/.codex` / SQLite 文件。 | 已完成 |
| `M6-03` | `apps/desktop/src/App.tsx`<br>`apps/desktop/dist/index.html`<br>`apps/desktop/src-tauri/tauri.conf.json` | 完成 6 页全中文桌面端 UI（总览仪表盘、规则策略中心 + 在线测试沙盒、拦截审计时间线、安装向导 + Unified Diff 预览、Codex 会话只读浏览器、备份回滚与设置）及 Tauri 2 桌面壳配置。 | 已完成 |
| `M6-04` | `apps/local-service/src/target_manager.rs` | 完成跨边界命令注入负向回归测试（`test_m6_wsl_bridge_blocks_option_and_control_char_injection`）与非本地回路拒绝测试（`test_m6_loopback_bind_guard_rejects_external_interfaces`）。 | 已完成 |
| `M7-01` | `Cargo.toml`<br>`apps/desktop/src-tauri/tauri.conf.json` | 统一 Workspace 双端构建入口，Linux / WSL2 原生编译与 `x86_64-pc-windows-gnu` 跨平台静态检查 100% 零警告通过。 | 已完成 |
| `M7-02` | `tests/e2e/run_m2_codex_e2e.py`<br>`packages/*/src/*.rs` | 完成 V0.1 全量验收矩阵（`AT-01` ~ `AT-12`）：19 项 Rust 单元与集成测试全部通过，86 条正负向规则语料 0 误杀 / 0 漏判，真实 Codex CLI `PreToolUse` E2E 阻断复测通过。 | 已完成 |
| `M7-03` | `README.md`<br>`INSTALL.md`<br>`UNINSTALL.md`<br>`SECURITY.md`<br>`PRIVACY.md`<br>`LIMITATIONS.md`<br>`LICENSE` / `NOTICE` | 完备齐套开源合规声明、安装回滚手册、安全隐私红线与已知能力边界文档；静态扫描确认 `apps/` 与 `packages/` 对 `references/` 零引用。 | 已完成 |
| `M7-04` | `docs/evidence/m6-m7-release-report.md` | 产出 V0.1-GA 发布验收证据与二进制 SHA-256 校验报告。 | 已完成 |

---

## 2. V0.1-GA 全量验收矩阵（`AT-01` ~ `AT-12`）验证结果

| 验收编号 | 验收场景 | 验证方式与证据 | 结果 |
| :--- | :--- | :--- | :---: |
| `AT-01` | 双环境探测与四态防护模型诚实展示 | `ai-guard status --target all --json` 与 `GET /api/status`：仅在配置挂载、哈希受信且自检通过时返回 `protected_verified`，绝不虚标防护状态。 | PASS |
| `AT-02` | 真实 Codex CLI `PreToolUse` 高危命令阻断 | `python3 tests/e2e/run_m2_codex_e2e.py`：在隔离沙箱启动真实 `codex exec`，触发 `AI_GUARD_BLOCK_ME`，阻断率 100%，哨兵文件未生成。 | PASS |
| `AT-03` | 真实 Codex CLI 正常开发命令放行 | `python3 tests/e2e/run_m2_codex_e2e.py`：正常 `echo` / `git status` 命令 0 延迟放行，哨兵文件正常生成。 | PASS |
| `AT-04` | 异常输入 Fail-Closed 默认阻断 | `test_edge_cases_empty_invalid_utf8_and_oversize_fail_closed`：空输入、非法 UTF-8、畸形 JSON、超大输入（>256KB）100% 触发 `permissionDecision: "deny"`。 | PASS |
| `AT-05` | 跨平台 TOML 策略引擎与正负向语料回归 | `test_m3_36_positive_high_risk_cases_100_percent_deny`（40 条正向高危 100% 拦截）与 `test_m3_44_negative_safe_dev_cases_zero_false_positives`（46 条安全命令 0 误拦），P95 耗时 `< 0.5ms`。 | PASS |
| `AT-06` | 第三方 Hook 无损共存与 SHA-256 精确卸载恢复 | `test_m4_dual_env_install_preserve_third_party_hooks_sync_policy_and_uninstall_exact_hash`：第三方 Hook 100% 保留，卸载后文件 SHA-256 与安装前逐字节一致。 | PASS |
| `AT-07` | 受管启动四步预检（Preflight）强阻断 | `test_m4_fault_injection_conflict_detection_and_preflight_blocks_missing_binary`：Hook 缺失、二进制不可执行或策略 SHA-256 漂移时拒绝启动 Codex。 | PASS |
| `AT-08` | SQLite WAL 审计存储与 15ms 锁降级保护 | `test_m5_corrupted_db_or_lock_falls_back_to_jsonl_and_queries_seamlessly`：写库异常自动追加 `events-fallback.jsonl`，绝不阻塞或改变 Hook `Deny` 裁决。 | PASS |
| `AT-09` | 全链路敏感凭证零明文落盘（Secret Redaction） | `test_m5_sqlite_wal_zero_secret_leak_and_export_redacted`：API Key / Token / 私钥在入库与 CSV/JSON 导出时 100% 脱敏为 `[REDACTED_*]`。 | PASS |
| `AT-10` | 双环境 Codex 会话 100% 只读浏览与快照备份 | `test_m5_session_list_show_backup_preserves_100_percent_readonly_hashes_and_mtimes`：`file:<path>?mode=ro&immutable=1` 访问前后原文件 SHA-256 与 `mtime` 零变化。 | PASS |
| `AT-11` | WSL2 桥接器防命令注入与本地回路监听防护 | `test_m6_wsl_bridge_blocks_option_and_control_char_injection` 与 `test_m6_loopback_bind_guard_rejects_external_interfaces`：拦截 `-e`/`--user` 注入与 `0.0.0.0` 外部监听。 | PASS |
| `AT-12` | 宿主与 WSL2 真实 `~/.codex` 零污染校验 | 全阶段研发与测试期间，宿主与 WSL2 真实 `config.toml` SHA-256 保持 100% 未改动。 | PASS |

---

## 3. 真实用户环境零污染与开源合规校验

1. **真实 `.codex/config.toml` SHA-256 校验**：
   - `/home/ai-li/.codex/config.toml`：`ca080ce591a7b8aa1315b831107852d02071af825d3bf1e180392e6fbf5daec6`（与 Phase 0 基线完全一致）
   - `/mnt/c/Users/kui.li/.codex/config.toml`：`ae970ff855b64021bf98d1e5927da0ea4db13111e4d34b8b2420a32f3a14c9ef`（与 Phase 0 基线完全一致）
2. **第三方参考代码零复制（No Copy-Paste）合规检查**：
   - `Cargo.toml`、`apps/`、`packages/` 中零引用 `references/` 目录下的任何文件；`references/` 已在 `.gitignore` 中排除。
