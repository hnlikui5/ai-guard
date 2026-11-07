# Codex 执行前拦截（PreToolUse）Allow / Deny 端到端测试规程（M2 E2E）

- **阶段**：Phase 1（M2-01 ～ M2-03）
- **自动化脚本**：`tests/e2e/run_m2_codex_e2e.py`
- **安全约束**：
  - 全程在临时隔离目录 `/tmp/ai-guard-m2-e2e` 中运行，**绝不读取或修改**用户真实 `/home/ai-li/.codex` 与 `/mnt/c/Users/kui.li/.codex`。
  - 使用编译产出的真实 Rust 二进制 `target/debug/ai-guard hook codex pre-tool-use`。
  - 通过 `codex app-server --listen stdio://` 的 `hooks/list` 接口获取精确 `currentHash` 并写入 `[hooks.state."<key>"].trusted_hash`，在**不传 `--dangerously-bypass-hook-trust`** 的真实生产信任模式下验证拦截生效。

---

## 1. 一键复现命令

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo build
python3 tests/e2e/run_m2_codex_e2e.py
```

---

## 2. 端到端测试用例矩阵

| 用例编号 | 场景名称 | 触发工具与载荷 | 预期 Hook 决策 | 预期副作用验证 |
| :--- | :--- | :--- | :--- | :--- |
| **E2E-DENY-SHELL** | 危险标记 Shell 命令执行前拒绝 | `exec_command`: `echo AI_GUARD_BLOCK_ME && touch /tmp/ai-guard-m2-e2e/workspace/sentinel_blocked.txt` | `Deny` (`AG-RULE-TEST-DENY-001`) | **`sentinel_blocked.txt` 必须不存在（0 副作用）** |
| **E2E-ALLOW-SHELL** | 正常 Shell 命令放行执行 | `exec_command`: `pwd && echo ALLOW_VERIFIED > /tmp/ai-guard-m2-e2e/workspace/sentinel_allowed.txt` | `Allow` (`AG-ALLOW-DEFAULT`) | **`sentinel_allowed.txt` 正常生成且内容为 `ALLOW_VERIFIED`** |
| **E2E-DENY-PATCH** | 含危险标记的 `apply_patch` 补丁拒绝 | `apply_patch`: `*** Add File: patched_blocked.txt\n+AI_GUARD_BLOCK_ME` | `Deny` (`AG-RULE-TEST-DENY-001`) | **`patched_blocked.txt` 必须不存在（0 副作用）** |
