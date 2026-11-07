# M5 + M1 汇入（Phase 4）SQLite 审计库、跨环境事件同步、四态自检与双环境 Session 只读保护验证报告

- **验证时间**：`2026-11-07`
- **覆盖环境**：Windows 宿主机（`host:windows`）+ WSL2 Ubuntu（`wsl2:Ubuntu`）
- **验证目标**：完成 `P4-T1`（5 表 SQLite WAL 审计库、15ms 无锁 `events-fallback.jsonl` 熔断降级与跨环境增量拉取合入）、`P4-T2`（二次强制脱敏查询与 JSON/CSV 导出）、`P4-T3`（双环境四态 `status` 汇总与 `self-test` 隔离自检）、`P4-T4`（宿主机与 WSL2 双环境 Codex Session 只读索引与 SHA-256 快照备份）。

---

## 1. 核心交付物清单

1. **宿主机统一 SQLite WAL 审计库与 15ms 无锁 Fallback（`P4-T1` / `M5-01`）**：
   - `packages/storage/src/lib.rs`
   - 初始化并管理 5 张核心表：`schema_migrations`、`security_events`、`policy_revisions`、`integration_state`、`self_test_runs`。
   - 启用 `PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;` 与 `busy_timeout = 15ms`。
   - 当发生写锁竞争、磁盘只读或数据库损坏时，自动无锁降级追加至 `events-fallback.jsonl`，确保 Hook 热路径永不阻塞且绝不改变 `Deny` 决策。
   - 支持 `ai-guard events pull --since <cursor> --merge-into-db <host_db>` 将 WSL2 增量审计事件幂等合入宿主机主库。
2. **二次脱敏审计查询与导出（`P4-T2` / `M5-02`）**：
   - `ai-guard events list [--target <all|host|wsl2:distro>] [--decision <deny|allow|observe>] [--since <duration>] [--limit <N>] --json`
   - `ai-guard events export --output <path> --redacted [--format json|csv]`
   - 对所有落盘与导出的字段执行二次 `redact_secrets` 清洗，确保 `sk-proj-*`、`ghp_*`、SSH 私钥等真实凭据原文 **0 残留**。
3. **双环境四态状态汇总与隔离自检（`P4-T3` / `M5-03` & `M5-04`）**：
   - `ai-guard self-test codex [--target <all|host|wsl2:distro>] --isolated --json`：在临时沙箱内执行 Allow 与 Deny 端到端自检，验证副作用哨兵文件未生成，并将结果记入 `self_test_runs`。
   - `ai-guard status [--target <all|host|wsl2:distro>] --json`：严格区分 `protected_verified`（Hook 已挂载 + 已信任 + 自检通过）、`partially_protected`、`unprotected`、`unknown` 四种状态，并诚实列出已知安全边界（`limitations`）。
4. **双环境 Codex Session 严格只读索引与 SHA-256 备份（`P4-T4` / `M5-05`）**：
   - `packages/session/src/lib.rs`
   - 同时对接宿主机 `C:\Users\<User>\.codex` 与 WSL2 `~/.codex` 下的 `session_index.jsonl`、`sessions/**/rollout-*.jsonl`、`state_5.sqlite` 与 `thread_history_1.sqlite`。
   - SQLite 强制采用 `file:<path>?mode=ro&immutable=1`（`SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_URI`）打开，确保原目录所有文件的 SHA-256 与 `mtime` 100% 零改动。
   - 提供 `ai-guard session list`、`ai-guard session show <id>`、`ai-guard session backup <id>`（自动调用 `packages/backup` 归档并完成 SHA-256 闭环校验）。

---

## 2. 阶段验收门禁结果（Phase 4 Gate）

| 验收项 | 要求标准 | 实测结果 | 状态 |
| :--- | :--- | :--- | :--- |
| 隐私红线测试（秘钥 0 残留） | 注入 `sk-proj-*`、`ghp_*`、OpenSSH 私钥后，`events.db`、Fallback JSONL 与导出 JSON/CSV 原文 0 残留 | `test_m5_sqlite_wal_zero_secret_leak_and_export_redacted` 通过 | PASS |
| 15ms 数据库损坏/锁冲突无锁降级 | 模拟 `events.db` 损坏或写失败时自动写入 `events-fallback.jsonl` 且查询无缝合并 | `test_m5_corrupted_db_or_lock_falls_back_to_jsonl_and_queries_seamlessly` 通过 | PASS |
| 跨环境（WSL2 -> Host）增量拉取与幂等归并 | WSL2 触发阻断事件后，宿主机执行 `events pull` 准确拉取并幂等去重合入主库 | `test_m5_cross_env_wsl2_to_host_event_pull_and_idempotent_merge` 通过 | PASS |
| 双环境 Session 只读保护与备份测试 | 执行 `session list/show/backup` 前后，源会话文件 SHA-256 与 `mtime` 100% 不变 | `test_m5_session_list_show_backup_preserves_100_percent_readonly_hashes_and_mtimes` 通过 | PASS |
