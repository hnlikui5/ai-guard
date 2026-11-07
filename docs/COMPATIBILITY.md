# AI卫士（AI Guard）兼容性、拦截覆盖率与故障表现矩阵

- **文档阶段**：Phase 0（M0-01 / M0-02）初始化，随 M2 E2E 持续更新
- **实测基准日期**：2026-11-07
- **诚实度原则**：严禁将未经过 `PreToolUse` 钩子或存在已知 Fail-Open 的场景谎称为“完全受保护（`protected_verified`）”；所有已知盲区必须在 CLI `status --json` 与桌面端 UI 中如实披露。

---

## 1. 目标环境与客户端版本兼容矩阵

| 环境标识 (`EnvironmentKind`) | 客户端形态 (`ClientSurface`) | 实测版本 | 协议 Schema 兼容性 | Hook 配置方式 | 当前验证等级 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Wsl2Distro` (`Ubuntu 24.04`)** | `CodexCli` / `CodexAppServerDaemon` | `codex-cli 0.160.1` | 100% 兼容 (`pre-tool-use.command.input/output`) | `/home/ai-li/.codex/config.toml` (`command` + `trusted_hash`) | M0 隔离探针实测通过 |
| **`WindowsHost` (`Win11 26200`)** | `CodexDesktopApp` / `CodexCli` | `0.166.0-alpha.5.1` | 100% 兼容（内嵌 JSON Schema 与 `0.160.1` 完全一致） | `C:\Users\kui.li\.codex\config.toml` (`command` + `commandWindows` + `trusted_hash`) | M0 协议与 Schema 核验通过 |

---

## 2. Codex 工具级 `PreToolUse` 拦截覆盖矩阵（基于 `0.160.1` 实测）

| Codex 内部工具类型 | `PreToolUse` 传入的 `tool_name` | `tool_input` 关键字段 | 是否触发 `PreToolUse` | Deny 后副作用是否被阻断 | 覆盖分级 (`CoverageLevel`) | 备注与安全应对策略 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`exec_command` (`unified_exec`)** | `"Bash"` | `{"command": "<cmd>"}` | **是（已实测）** | **是（`blocked`，sentinel 未生成）** | `Supported` | 覆盖单次与脚本式 Shell 命令执行 |
| **`apply_patch` (`custom_tool_call`)** | `"apply_patch"` | `{"command": "*** Begin Patch..."}` | **是（已实测）** | **是（`blocked`，目标文件未创建）** | `Supported` | 补丁原文位于 `tool_input.command` 字段，适配器同时兼容 `.command` / `.patch` / `.input` |
| **MCP 工具调用 (`mcp__<srv>__<tool>`)** | `"mcp__<srv>__<tool>"` | `<MCP 参数 JSON 对象>` | **是（已实测）** | **是（`blocked`，MCP Server 未收到调用）** | `Supported` | 支持按 MCP Server / 工具名及敏感参数规则拦截 |
| **`write_stdin`（向已打开 PTY 写输入）** | 不触发 | `{"session_id": N, "chars": "..."}` | **否（已实测盲区）** | **否（`continued`）** | `Unsupported` | **关键实测发现**：`write_stdin` 不会再次触发 `PreToolUse`。应在默认策略中管控/拦截直接启动裸交互式 Shell（如 `exec_command` 启动裸 `bash`/`sh`/`zsh`/`pwsh`/`cmd` 且 `tty=true`），并在 UI 明确披露该盲区 |
| **内置非执行工具 (`view_image` / `web_search` / `get_goal`)** | 不触发 | - | **否** | - | `Unsupported` | 不经过 `PreToolUse` 命令钩子 |

---

## 3. Hook 运行时故障与边界条件表现矩阵（M0 隔离探针实测）

以下结果均基于本机 `codex-cli 0.160.1` 在隔离沙箱（`/tmp/ai-guard-m0-probe`）中的真实执行结果记录：

| 测试用例 ID | 场景描述 | Hook 退出码与输出 | Hook 是否被调用 | Codex 实际行为 (`blocked` / `continued`) | Sentinel 副作用文件是否生成 | AI卫士防护设计应对措施 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **COMPAT-01 (`allow_empty`)** | 正常放行：Hook 退出码 `0`，`stdout` 为空 | `exit 0`, `stdout=""` | 是 | `continued`（正常执行） | 是（符合预期） | Allow / Observe 决策标准返回路径 |
| **COMPAT-02 (`deny_json`)** | 标准 JSON 拒绝：退出码 `0`，`stdout` 输出 `permissionDecision: "deny"` | `exit 0`, `stdout={"hookSpecificOutput":...}` | 是 | **`blocked`（成功阻断）** | **否（0 副作用）** | AI卫士主阻断返回路径 |
| **COMPAT-03 (`exit_code_2_stderr`)** | 退出码 `2` 拒绝：`stderr` 输出非空拒绝原因 | `exit 2`, `stderr="Blocked..."` | 是 | **`blocked`（成功阻断）** | **否（0 副作用）** | 可作为极端异常下的二级兜底阻断手段 |
| **COMPAT-04 (`untrusted_hook`)** | Hook 未配置 `trusted_hash` 且未传 `--dangerously-bypass-hook-trust` | - | **否（被跳过）** | **`continued`（Codex Fail-Open！）** | **是（危险放行）** | **生死线发现**：未受信任的 Hook 会被静默跳过！`ai-guard install` 必须写入精确 `trusted_hash`，且 `ai-guard status/doctor` 必须校验 `trustStatus == "trusted"`，若为 `untrusted`/`modified` 必须报告 `unprotected` |
| **COMPAT-05 (`trusted_hash_configured`)** | 在 `config.toml` 配置匹配 `[hooks.state."<key>"].trusted_hash`（不传 bypass 标志） | `exit 0`, `stdout={"hookSpecificOutput":...}` | **是** | **`blocked`（成功阻断）** | **否（0 副作用）** | 证明无需 `--dangerously-bypass-hook-trust` 即可在常规 CLI、后台 Daemon 与桌面端生效 |
| **COMPAT-06 (`malformed_json_exit_0`)** | Hook 崩溃或向 `stdout` 打印非法 JSON（如日志污染） | `exit 0`, `stdout="NOT_VALID_JSON"` | 是 | **`continued`（Codex Fail-Open！）** | **是（危险放行）** | **严禁污染 `stdout`**：AI卫士一切日志只准写 `stderr`；顶层捕获所有错误与 panic，确保 `stdout` 永远输出合法单行 Deny JSON |
| **COMPAT-07 (`missing_binary`)** | 配置中的 Hook 可执行文件路径不存在或不可执行 | Spawn 失败 | 否 | **`continued`（Codex Fail-Open！）** | **是（危险放行）** | `ai-guard status/doctor` 每次巡检必须校验二进制存在性与可执行权限；缺失时立即降级告警为 `unprotected` |
| **COMPAT-08 (`timeout_exceeded`)** | Hook 执行耗时超过配置的 `timeout` 秒数 | 超时被杀 | 是 | **`continued`（Codex Fail-Open！）** | **是（危险放行）** | **性能硬约束**：采用就地原生二进制（Windows `ai-guard.exe` / WSL2 `ai-guard-linux`），SQLite 锁超时限制 `15ms` 并降级 `events-fallback.jsonl`，确保 Hook 在 `< 10ms` 内返回，绝不触发超时 Fail-Open |
