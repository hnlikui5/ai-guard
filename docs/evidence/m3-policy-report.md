# M3（Phase 2）跨平台 TOML 策略引擎与高危规则库验证报告

- **验证时间**：`2026-11-07`
- **覆盖环境**：Windows 宿主机（PowerShell / CMD）+ WSL2 Ubuntu（Bash / sh）
- **验证目标**：完成 `P2-T1`（TOML 策略 Schema 与可信快照降级保护）、`P2-T2`（跨平台内置高危检测器）、`P2-T3`（`ai-guard rule validate` 与 `ai-guard rule test` 模拟器）、`P2-T4`（正向与负向回归矩阵）。

---

## 1. 核心交付物清单

1. **跨平台 TOML 策略引擎**：
   - `packages/security/src/policy.rs`
   - `config/policy.default.toml`
   - 支持 `#[serde(deny_unknown_fields)]` 强 Schema 校验、重复规则 ID 拒止、非法正则拒止、空字段拒止（统一返回 `AG-POLICY-001`）。
   - 支持主策略文件损坏时自动回退至最近一次验证通过的可信快照（`policy.last_good.toml`）；若快照亦不可用，严格执行 Fail-Closed。
2. **跨平台内置高危检测器（Win + Linux）**：
   - `packages/security/src/detectors.rs`
   - `TEST-DENY-001`：测试阻断哨兵指令（`AI_GUARD_BLOCK_ME`）。
   - `SHELL-DESTRUCTIVE-RM`：Linux `rm -rf /`、`rm -rf ~`、`rm -rf ..` 与 Windows `Remove-Item -Recurse -Force`、`rmdir /s /q`、`del /f /s /q`。
   - `SHELL-DISK-WIPE`：Linux `mkfs.*`、`wipefs`、`fdisk`、`dd of=/dev/...` 与 Windows `Format-Volume`、`Clear-Disk`、`diskpart`。
   - `SHELL-PIPE-EXEC`：Linux `curl/wget | sh/bash/python`、`base64 -d | sh` 与 Windows `iwr/irm | iex`、`powershell -EncodedCommand`、`certutil -urlcache`。
   - `PATH-SENSITIVE-CRED`：跨平台敏感凭据文件（`.ssh`、`.aws`、`.gnupg`、`.kube`、`.codex/auth.json`、`.codex/config.toml`、`.env`、`/etc/shadow`、`SAM`）与 `..` 工作区外路径穿越检测（同时覆盖 `Bash` 与 `apply_patch`）。
   - `GIT-DANGEROUS-OP`：`git reset --hard`、`git clean -fd/-fx`、`git push --force`（放行 `--force-with-lease`）、`git checkout -- .`。
3. **CLI 策略校验器与离线规则模拟器**：
   - `apps/local-service/src/cli.rs`
   - `apps/local-service/src/main.rs`
   - 新增 `ai-guard rule validate --path <policy.toml> [--json]`。
   - 增强 `ai-guard rule test` 支持 `--policy <policy.toml>`、`--event-file <fixture.json>`、输出 `duration_us` 与 `policy_revision`。

---

## 2. 回归测试矩阵与性能门禁结果

| 门禁指标 | 要求阈值 | 实测结果 | 状态 |
| :--- | :--- | :--- | :--- |
| 正向高危拦截用例（Linux + Windows） | `>= 30` 条，拦截率 `100%` | `40` 条（38 Shell + 2 Patch），拦截率 `100%` | PASS |
| 负向安全研发用例（零误报验证） | `>= 40` 条，误报率 `0%` | `46` 条（44 Shell + 2 Patch），误报率 `0%` | PASS |
| 单次规则评估延迟（P95） | `< 10ms` (`10,000us`) | 实测 P95 `< 250us`（约 `0.25ms`） | PASS |
| 未知复合命令语法标记（`Unsupported`） | 显式标记 `Coverage::Unsupported` | 子 Shell / 复合重定向上报 `AG-UNSUPPORTED-COMPOUND-SHELL` | PASS |
| 真实被测破坏性命令零执行 | 测试期间 `0` 次真实 Shell 执行 | 纯内存评估 + 哨兵文件 E2E，双环境 `.codex` SHA-256 零变动 | PASS |
