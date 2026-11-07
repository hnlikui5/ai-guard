# Codex Hook 协议真实契约规范（M0 实测固化版）

- **文档阶段**：Phase 0（M0-02）
- **实测覆盖版本**：
  - WSL2 Ubuntu：`codex-cli 0.160.1`（`linux-x86_64`）
  - Windows 宿主机：Codex Desktop / Sandbox Runner `0.166.0-alpha.5.1`（`windows-x86_64`）
- **取证方式**：在隔离临时目录（`CODEX_HOME=/tmp/ai-guard-m0-probe/...`）通过本地回路 Mock Responses API Server 驱动真实 `codex exec` 与 `codex app-server` 执行，并交叉比对双端二进制内嵌的 Draft-07 JSON Schema。

---

## 1. 重大实测发现摘要（修正猜测与文档偏差）

1. **特性开关名称已演进**：
   - 在 `0.160.1+` 中，正式 Feature 名称为 `hooks`（默认 `stable = true` 开启）。
   - 旧配置 `[features]\ncodex_hooks = true` 被识别为 `legacy feature flag: codex_hooks -> hooks`。AI卫士安装器在生成配置时应优先确保 `hooks = true`（或保持默认开启），同时兼容识别 `codex_hooks = true`。
2. **禁止在同一配置层同时写入 `config.toml` `[hooks]` 与 `hooks.json`**：
   - 实测发现：若 `$CODEX_HOME/config.toml` 的 `[hooks]` 段与 `$CODEX_HOME/hooks.json` 同时存在，Codex 会在运行时输出错误告警：
     `loading hooks from both $CODEX_HOME/hooks.json and $CODEX_HOME/config.toml; prefer a single representation for this layer`。
   - **架构定案**：AI卫士统一采用 **`$CODEX_HOME/config.toml` 内嵌 `[[hooks.PreToolUse]]` + `[hooks.state]`** 的单一表示法（若用户已有 `hooks.json` 则在合并前先备份并提示用户）。
3. **跨平台命令字段（`command` 与 `commandWindows`）**：
   - Codex 的 `HookHandlerConfig`（`type = "command"`）原生支持：
     - `command`：POSIX / 默认执行命令（在 WSL2 下为 `/home/<user>/.local/bin/ai-guard-linux hook codex pre-tool-use`）。
     - `commandWindows`：Windows 专属覆盖命令（在 Windows 宿主机下为 `C:\Users\<User>\AppData\Local\ai-guard\bin\ai-guard.exe hook codex pre-tool-use`）。
     - `timeout`：超时秒数（整数，对应 Schema 中的 `timeoutSec`）。
     - `statusMessage`：执行 Hook 期间展示给用户的状态文案（如 `"AI卫士安全检查中..."`）。
4. **Hook 信任持久化机制（`[hooks.state."<key>"].trusted_hash`）已完全破译并实测跑通**：
   - 若未传 `--dangerously-bypass-hook-trust` 且未配置 `trusted_hash`，所有用户级/项目级 Hook 的 `trustStatus` 均为 `"untrusted"`，**Codex 会直接跳过该 Hook 并放行命令执行（Fail-Open）**！
   - 通过 `codex app-server --listen stdio://` 调用 JSON-RPC 方法 `hooks/list`（参数 `{"cwds": ["..."]}`），可直接获取每个 Hook 的精确 `key`（格式为 `"<sourcePath>:pre_tool_use:<group_idx>:<handler_idx>"`）与 `currentHash`（格式为 `"sha256:<64位hex>"`）。
   - 在 `$CODEX_HOME/config.toml` 中写入：
     ```toml
     [hooks.state."<key>"]
     enabled = true
     trusted_hash = "sha256:<currentHash>"
     ```
     后，`hooks/list` 返回 `"trustStatus": "trusted"`，此时**无需 `--dangerously-bypass-hook-trust` 参数，Codex CLI、后台 `app-server-daemon` 与 Codex Desktop App 均会自动信任并强制执行该 `PreToolUse` Hook**！
5. **各工具在 `PreToolUse` 中的真实映射与盲区**：
   - **`exec_command`（`unified_exec`）**：自动映射为 `"tool_name": "Bash"`，`"tool_input": {"command": "..."}`。
   - **`apply_patch`（`custom_tool_call`）**：**受 `PreToolUse` 拦截**！实测传入 `"tool_name": "apply_patch"`，且补丁内容存放在 **`"tool_input": {"command": "*** Begin Patch..."}`**（注意字段名为 `command` 而非 `patch`！适配器必须同时兼容提取 `tool_input.command`、`tool_input.patch` 与 `tool_input.input`）。
   - **`mcp__<server>__<tool>`（MCP 工具调用）**：**受 `PreToolUse` 拦截**！实测传入 `"tool_name": "mcp__demo__ping"`，`"tool_input": { ... }`。
   - **`write_stdin`（向已打开的交互式 PTY 会话追加输入）**：**实测不触发 `PreToolUse`（真实盲区）**！若模型先通过 `exec_command`（`cmd: "bash", tty: true`）开启交互式 Shell，后续通过 `write_stdin` 发送的子命令不会经过 `PreToolUse`。因此策略引擎需对直接启动裸交互式 Shell（如裸 `bash`/`sh`/`zsh`/`pwsh`/`cmd`）提供专门规则或风险提示，并在 `COMPATIBILITY.md` 中明确标注。

---

## 2. Hook 配置规范（`config.toml`）

### 2.1 WSL2 目标环境（`/home/<user>/.codex/config.toml`）
```toml
[features]
hooks = true

[[hooks.PreToolUse]]
matcher = "*"
hooks = [
  { type = "command", command = "/home/ai-li/.local/bin/ai-guard-linux hook codex pre-tool-use", timeout = 5, statusMessage = "AI卫士安全检查中..." }
]

[hooks.state."/home/ai-li/.codex/config.toml:pre_tool_use:0:0"]
enabled = true
trusted_hash = "sha256:<由 codex app-server hooks/list 获取的精确哈希>"
```

### 2.2 Windows 宿主机目标环境（`C:\Users\<User>\.codex\config.toml`）
```toml
[features]
hooks = true

[[hooks.PreToolUse]]
matcher = "*"
hooks = [
  { type = "command", command = "C:\\Users\\kui.li\\AppData\\Local\\ai-guard\\bin\\ai-guard.exe hook codex pre-tool-use", commandWindows = "C:\\Users\\kui.li\\AppData\\Local\\ai-guard\\bin\\ai-guard.exe hook codex pre-tool-use", timeout = 5, statusMessage = "AI卫士安全检查中..." }
]

[hooks.state."C:\\Users\\kui.li\\.codex\\config.toml:pre_tool_use:0:0"]
enabled = true
trusted_hash = "sha256:<由 codex app-server hooks/list 获取的精确哈希>"
```

---

## 3. `PreToolUse` 输入协议契约（`stdin` JSON）

双端（`0.160.1` 与 `0.166.0-alpha.5.1`）内嵌的 `pre-tool-use.command.input` Schema 完全一致：

### 3.1 字段定义
| 字段名 | 类型 | 是否必填 | 说明 |
| :--- | :--- | :--- | :--- |
| `session_id` | `string` | 是 | 当前 Codex 会话 UUID（如 `"01a1b424-7a3c-70a3-9375-d6e356b7fe77"`） |
| `turn_id` | `string` | 是 | 当前对话轮次 UUID |
| `transcript_path` | `string \| null` | 是 | 当前会话 rollout JSONL 文件绝对路径 |
| `cwd` | `string` | 是 | 当前工作目录绝对路径（Linux POSIX 路径或 Windows 路径） |
| `hook_event_name` | `"PreToolUse"` | 是 | 固定常量 `"PreToolUse"` |
| `model` | `string` | 是 | 当前模型标识（如 `"gpt-5.6-sol"`） |
| `permission_mode` | `string` | 是 | 枚举：`"default"` \| `"acceptEdits"` \| `"plan"` \| `"dontAsk"` \| `"bypassPermissions"` |
| `tool_name` | `string` | 是 | 工具名：`"Bash"` \| `"apply_patch"` \| `"mcp__<server>__<tool>"` |
| `tool_input` | `any (object)` | 是 | 工具参数对象（见 3.2 实测样本） |
| `tool_use_id` | `string` | 是 | 本次工具调用唯一 ID（如 `"call_probe_001"`） |
| `agent_id` | `string` | 否 | 子 Agent ID（可选） |
| `agent_type` | `string` | 否 | 子 Agent 类型（可选） |

### 3.2 实测捕获的三种核心工具 `stdin` 样本

#### 样本 A：Shell 命令执行（`exec_command` -> `tool_name: "Bash"`）
```json
{
  "session_id": "01a1b424-7a3c-70a3-9375-d6e356b7fe77",
  "turn_id": "01a1b424-7a5c-7593-866d-38a98c8279c9",
  "transcript_path": "/tmp/ai-guard-m0-probe/codex_home/sessions/2026/11/07/rollout-2026-11-07T11-54-11-01a1b424-7a3c-70a3-9375-d6e356b7fe77.jsonl",
  "cwd": "/tmp/ai-guard-m0-probe/workspace",
  "hook_event_name": "PreToolUse",
  "model": "gpt-5.1-codex-max",
  "permission_mode": "bypassPermissions",
  "tool_name": "Bash",
  "tool_input": {
    "command": "echo AI_GUARD_PROBE_TEST && touch /tmp/ai-guard-m0-probe/sentinel.txt"
  },
  "tool_use_id": "call_probe_001"
}
```

#### 样本 B：文件补丁修改（`apply_patch` -> `tool_name: "apply_patch"`）
```json
{
  "session_id": "01a1b42e-202f-7c83-a826-5659c955a940",
  "turn_id": "01a1b42e-2039-7a01-861c-34612325a2db",
  "transcript_path": "/tmp/ai-guard-m0-probe/home_apply_patch/sessions/2026/11/07/rollout-2026-11-07T12-04-44-01a1b42e-202f-7c83-a826-5659c955a940.jsonl",
  "cwd": "/tmp/ai-guard-m0-probe/workspace",
  "hook_event_name": "PreToolUse",
  "model": "gpt-5.6-sol",
  "permission_mode": "bypassPermissions",
  "tool_name": "apply_patch",
  "tool_input": {
    "command": "*** Begin Patch\n*** Add File: patched_by_custom_tool.txt\n+hello patch\n*** End Patch\n"
  },
  "tool_use_id": "call_patch_001"
}
```

#### 样本 C：MCP 工具调用（`mcp__<server>__<tool>`）
```json
{
  "session_id": "01a1b42d-7761-7c71-89a4-355af5310099",
  "turn_id": "01a1b42d-7782-70d2-91fc-5d0a66dd3dee",
  "transcript_path": "/tmp/ai-guard-m0-probe/home_mcp_only/sessions/2026/11/07/rollout-2026-11-07T12-04-00-01a1b42d-7761-7c71-89a4-355af5310099.jsonl",
  "cwd": "/tmp/ai-guard-m0-probe/workspace",
  "hook_event_name": "PreToolUse",
  "model": "gpt-5.1-codex-max",
  "permission_mode": "bypassPermissions",
  "tool_name": "mcp__demo__ping",
  "tool_input": {
    "msg": "hello_from_codex"
  },
  "tool_use_id": "call_mcp_ns_003"
}
```

---

## 4. `PreToolUse` 输出协议契约（`stdout` / `stderr` / Exit Code）

### 4.1 阻断（Deny）标准输出格式（首选方式）
- **进程退出码**：`0`
- **`stdout` 内容**（单行紧凑 JSON）：
```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[AI卫士阻断] 命中高危规则 SHELL-DESTRUCTIVE-RM：禁止递归强制删除关键目录"}}
```
- **Codex 实测校验约束**：
  - `hookSpecificOutput.hookEventName` 必须为 `"PreToolUse"`。
  - `hookSpecificOutput.permissionDecision` 为 `"deny"` 时，**`permissionDecisionReason` 必须是非空字符串**（否则报错 `PreToolUse hook returned permissionDecision:deny without a non-empty permissionDecisionReason`）。
  - 注意：当前版本 Codex **不支持**在 `PreToolUse` 中返回 `permissionDecision: "allow"` 或 `"ask"`（源码中包含显式拒绝报错 `PreToolUse hook returned unsupported permissionDecision:allow` / `ask`），放行必须采用空输出或 `{}`！

### 4.2 阻断（Deny）备选方式（Exit Code 2）
- **进程退出码**：`2`
- **`stderr` 内容**：非空阻断原因文本（若 `stderr` 为空则报错 `PreToolUse hook exited with code 2 but did not write a blocking reason to stderr` 并放行）。
- **设计决策**：AI卫士主路径统一使用 **4.1 显式 JSON Deny + Exit Code 0**；在进程顶层 panic hook 中，若 JSON 序列化异常，可同时向 `stdout` 写入静态常量 Deny JSON 并确保绝不因空输出而误放行。

### 4.3 放行（Allow / Observe）标准输出格式
- **进程退出码**：`0`
- **`stdout` 内容**：空输出（0 字节），一切诊断日志只允许写入 `stderr`。

---

## 5. `app-server-daemon` 与 Codex 桌面端刷新协议

1. **WSL2 `app-server-daemon` 状态与重启**：
   - 检查状态：`codex doctor --json` 中的 `checks["app_server.status"]` 或 `codex app-server daemon version`。
   - 刷新配置：`codex app-server daemon restart`（支持在不丢失持久化会话的前提下重新加载 `$CODEX_HOME/config.toml` 中的 Hook 配置）。
2. **Hook 信任状态机化核验**：
   - 通过向 `codex app-server --listen stdio://` 发送 JSON-RPC 请求 `{"jsonrpc":"2.0","id":2,"method":"hooks/list","params":{"cwds":["<workspace>"]}}`，可精确读取每个 Hook 的 `trustStatus`（`"trusted"` | `"untrusted"` | `"modified"` | `"managed"`）与 `currentHash`。
