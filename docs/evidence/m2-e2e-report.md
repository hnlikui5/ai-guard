# Phase 1（M1 + M2）真实 Codex 执行前拦截端到端验证证据报告

- **验证日期**：2026-11-07
- **验证阶段**：Phase 1 Gate（M1 + M2 产品生死线）
- **被测 Codex 版本**：`codex-cli 0.160.1`（WSL2 Ubuntu 24.04）+ Windows 宿主机协议兼容校验（`0.166.0-alpha.5.1`）
- **被测 AI卫士版本**：`ai-guard 0.1.0`（Rust `1.99.1` 编译产物 `target/debug/ai-guard`）
- **五级完成度状态**：**真实 E2E 通过（4/5）**

---

## 1. 静态检查、跨平台编译与单元测试结果

| 检查项 | 执行命令 | 退出码 | 实际结果摘要 |
| :--- | :--- | :--- | :--- |
| **代码格式检查** | `cargo fmt --all -- --check` | `0` | 全部 6 个 Workspace 成员包通过，0 差异 |
| **静态 Lint 检查** | `cargo clippy --workspace --all-targets -- -D warnings` | `0` | 全部目标通过，0 warning / 0 error |
| **Windows 目标交叉检查** | `cargo check --workspace --target x86_64-pc-windows-gnu` | `0` | 全工作区在 Windows 目标下 100% 编译通过 |
| **全工作区单元测试** | `cargo test --workspace` | `0` | 10 项测试全部通过（含全部 16 组 Codex Hook 协议夹具、空输入/乱码 UTF-8/超长流式截断 Fail-Closed 测试、`SECRET_TEST_XYZ` 零泄露测试、无 Codex 目录 `doctor` 防 panic 测试） |

---

## 2. CLI 基础命令与 `SECRET_TEST_XYZ` 零泄露验证

### 2.1 双环境只读诊断（`ai-guard doctor --json`）
成功自动发现 WSL2（`/home/ai-li/.codex`）与 Windows 宿主机（`/mnt/c/Users/kui.li/.codex`）双目标环境，并诚实报告当前真实状态为 `unprotected`（未安装前绝不误报受保护）。

### 2.2 离线规则测试与秘密脱敏（`ai-guard rule test`）
执行命令：
```bash
./target/debug/ai-guard rule test --agent codex --tool Bash --input "echo AI_GUARD_BLOCK_ME && export TOKEN=SECRET_TEST_XYZ_123" --json
```
实际输出验证：
- `decision.enforcement`: `"deny"`
- `decision.matched_rule_ids`: `["TEST-DENY-001"]`
- `decision.reason_code`: `"AG-RULE-TEST-DENY-001"`
- `event.redacted_summary`: `"echo AI_GUARD_BLOCK_ME && export TOKEN=[REDACTED]"`
- **`SECRET_TEST_XYZ` 在 `stdout` 与 `stderr` 中出现次数：`0` 次**。

---

## 3. 真实 Codex 执行前拦截端到端验证（`python3 tests/e2e/run_m2_codex_e2e.py`）

在隔离临时目录 `/tmp/ai-guard-m2-e2e` 下，使用真实 `codex-cli 0.160.1` 与编译后的 Rust 二进制 `target/debug/ai-guard`，通过 `[hooks.state."<key>"].trusted_hash` 生产级信任机制（**未传 `--dangerously-bypass-hook-trust`**）完成了 3 项真实端到端测试：

### 3.1 实际执行输出日志
```text
[PASS] Hook configured and trusted: key=/tmp/ai-guard-m2-e2e/codex_home/config.toml:pre_tool_use:0:0 trustStatus=trusted
[PASS] E2E-DENY-SHELL: sentinel_blocked.txt exists=False | output=[{"type": "function_call_output", "id": "fco_01a1b43a-3bf7-7233-9c43-59e9321aaa9a", "call_id": "call_e2e_deny_001", "output": "Command blocked by PreToolUse hook: [AI卫士阻断] 命中确定性阻断规则 TEST-DENY-001：检测到禁止执行的标记指令 AI_GUARD_BLOCK_ME. Command: echo AI_GUARD_BLOCK_ME && touch /tmp/ai-guard-m2-e2e/workspace/sentinel_blocked.txt"}]
[PASS] E2E-ALLOW-SHELL: sentinel_allowed.txt exists=True | content=ALLOW_VERIFIED
[PASS] E2E-DENY-PATCH: patched_blocked.txt exists=False | output=[{"type": "custom_tool_call_output", "id": "ctco_01a1b43a-44c7-7ee3-92cc-978601b7566e", "call_id": "call_e2e_patch_003", "output": "Command blocked by PreToolUse hook: [AI卫士阻断] 命中确定性阻断规则 TEST-DENY-001：检测到禁止执行的标记指令 AI_GUARD_BLOCK_ME. Command: *** Begin Patch\n*** Add File: patched_blocked.txt\n+AI_GUARD_BLOCK_ME\n*** End Patch\n"}]
ALL M2 REAL CODEX E2E TESTS PASSED.
```

### 3.2 核心生死线结论
1. **真实执行前拒绝生效**：当真实 `codex exec` 尝试执行包含 `AI_GUARD_BLOCK_ME` 的命令以创建 `sentinel_blocked.txt` 时，`ai-guard hook codex pre-tool-use` 成功返回 `PreToolUse` Deny JSON，Codex 拒绝执行命令且 **`sentinel_blocked.txt` 未被创建（`exists=False`）**。
2. **文件补丁修改前拒绝生效**：当真实 `codex exec` 尝试通过 `apply_patch` 创建包含 `AI_GUARD_BLOCK_ME` 的 `patched_blocked.txt` 时，被 `ai-guard` 成功拦截且 **`patched_blocked.txt` 未被创建（`exists=False`）**。
3. **正常命令放行无误伤**：正常 `pwd && echo ALLOW_VERIFIED > sentinel_allowed.txt` 命令被 `ai-guard` 放行并成功写入文件。
4. **用户真实 `.codex` 零改动**：测试前后校验 `/home/ai-li/.codex/config.toml` 与 `/mnt/c/Users/kui.li/.codex/config.toml` 的 SHA-256 哈希 100% 未变。
