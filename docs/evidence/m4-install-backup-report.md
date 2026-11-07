# M4（Phase 3）事务备份、双环境无损安装器、策略镜像同步与受管启动验证报告

- **验证时间**：`2026-11-07`
- **覆盖环境**：Windows 宿主机（`host:windows`）+ WSL2 Ubuntu（`wsl2:Ubuntu`）
- **验证目标**：完成 `P3-T1`（`packages/backup` SHA-256 事务快照、篡改拒止与原子恢复）、`P3-T2`（双环境 Codex Hook 无损安装/预览/安全卸载、探针部署与策略镜像同步）、`P3-T3`（`ai-guard run codex` 四项 Preflight 预检与受管启动）。

---

## 1. 核心交付物清单

1. **SHA-256 事务快照备份底座（`P3-T1` / `M4-02`）**：
   - `packages/backup/src/lib.rs`
   - `BackupStore`：每次修改前自动生成 `manifest.json`（含 `backup_id`、`target_id`、`operation`、`existed_before`、`size_bytes`、`sha256`、`post_operation_sha256`）。
   - `atomic_write_file`：同目录临时文件写入 -> `sync_all (fsync)` -> 原子 `rename` 替换。
   - `verify_backup` / `restore_backup`：恢复前强制重算所有快照文件 SHA-256，若被篡改或字节数不符立即返回 `AG-BACKUP-HASH-MISMATCH` 拒绝恢复且保持目标文件零改动。
2. **双环境无损 Hook 安装器与卸载冲突保护（`P3-T2` / `M4-01` & `M4-02`）**：
   - `packages/agent-adapters/src/installer.rs`
   - `install_codex_hook`：支持 `--target <host|wsl2:distro>`、`--scope <user|project>`、`--dry-run`（输出 Unified Diff 与影响事件列表，零磁盘写入）、探针二进制部署与策略镜像同步（强制校验源与目标 `policy.toml` SHA-256 一致）。
   - 100% 保留已有用户注释、模型配置与第三方 `[[hooks.PreToolUse]]` 条目。
   - `uninstall_codex_hook`：卸载前自动对比 `post_operation_sha256`；若检测到安装后存在外部冲突改动且未传 `--force`，立即报错 `AG-INSTALL-CONFLICT` 中止覆盖并给出 `ai-guard backup restore --id <backup_id>` 指引；无外部改动时精准剥离受管段落，保证卸载后 `config.toml` SHA-256 与安装前 100% 一致。
3. **受管启动与四项安全预检（`P3-T3` / `M4-03` & `M4-04`）**：
   - `apps/local-service/src/cli.rs`
   - `apps/local-service/src/main.rs`
   - `ai-guard run codex`：启动前依次执行 `codex_binary`、`hook_registration`（含 AI卫士二进制路径存在性校验）、`policy_integrity`（含镜像哈希一致性校验）、`hook_trust`（`[hooks.state]` 信任校验與 `/hooks` 向导指引）四项预检；任一未通过立即 Fail-Closed 拒绝启动，通过后以独立 `argv` 直接拉起目标 `codex`。

---

## 2. 阶段验收门禁结果（Phase 3 Gate）

| 验收项 | 期望行为 | 实测结果 | 状态 |
| :--- | :--- | :--- | :--- |
| 备份闭环测试（创建 -> 校验 -> 篡改拒止 -> 正常恢复） | 篡改快照返回 `AG-BACKUP-HASH-MISMATCH` 且不破坏原文件；修复后恢复哈希 100% 一致 | `test_backup_verify_tamper_reject_and_restore_closed_loop` 通过 | PASS |
| 双环境（`host:windows` + `wsl2:Ubuntu`）安装/卸载闭环 | 保留第三方 Hook，策略镜像 SHA-256 一致，卸载后 `config.toml` SHA-256 与安装前完全一致 (`07ab5952...`) | `test_m4_dual_env_install_preserve_third_party_hooks_sync_policy_and_uninstall_exact_hash` 及 CLI 实测通过 | PASS |
| 外部冲突修改保护 | 安装后手动修改 `config.toml`，`uninstall` 拒绝覆盖并返回 `AG-INSTALL-CONFLICT` | `test_m4_fault_injection_conflict_detection_and_preflight_blocks_missing_binary` 通过 | PASS |
| 探针二进制缺失时受管启动阻断 | 删除 Hook 二进制后 `ai-guard run codex` 拒绝代启动并返回 `AG-PREFLIGHT-GUARD-BIN-MISSING` | 单测与 CLI 预检验证通过 | PASS |
| 用户真实双环境 `.codex` 零改动校验 | WSL2 与宿主机真实 `config.toml` SHA-256 与 Phase 0 基线 100% 一致 | 校验哈希无任何变化 | PASS |
