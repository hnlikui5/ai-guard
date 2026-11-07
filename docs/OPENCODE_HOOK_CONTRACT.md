# OpenCode & opencode CLI Hook 协议通信契约（Wire Protocol Specification）

本文档定义 **AI卫士（AI Guard）** 纳管 **OpenCode（含 `opencode` CLI 及桌面工作区）** 的执行前生命周期钩子（PreToolUse）通信协议契约。

---

## 1. 架构定位与设计哲学

1. **就地执行前强拦截（Pre-Tool Gate）**：
   OpenCode 原生支持插件扩展并在工具执行前触发 `tool.execute.before`（或 V2 `execute.before`）生命周期。AI卫士通过在 OpenCode 全局或项目插件目录注入轻量桥接插件 `ai-guard-pretool.ts`，在工具命令真正交付系统执行前完成毫秒级安全裁决。
2. **默认安全（Fail-Closed / Safe Default）**：
   若输入数据为空、JSON 格式损坏、数据超长（> 2 MiB）或策略引擎出现内部错误，必须**100% 默认阻断（Deny）**，退出码置为 `1`，严禁因异常放行（Fail-Open）。
3. **极速热路径（< 15ms P95）**：
   Hook 进程通过标准管道（stdin/stdout）通信，裁决逻辑完全在内存中执行；审计落盘异步写库，若写库超时自动降级，绝不阻塞 OpenCode 的正常交互。

---

## 2. 进程通信规范

- **启动命令**：
  ```bash
  ai-guard hook opencode pre-tool-use
  ```
- **输入流（`stdin`）**：单次传输的 UTF-8 编码 JSON 字符串（最大限制 2 MiB）。
- **输出流（`stdout`）**：单行紧凑 JSON 字符串。
- **退出码（Exit Code）**：
  - `0`：判定结果为放行（`allow`）；
  - `1`：判定结果为阻断（`deny`）或解析异常（Fail-Closed）；
  - `2`：需要人工确认（`ask` / review）。

---

## 3. 请求载荷规范（stdin Wire Input）

OpenCode 桥接插件将当前待执行的工具信息格式化为如下 JSON 结构传入 `stdin`：

```json
{
  "event": "PreToolUse",
  "tool_name": "bash",
  "tool_input": {
    "command": "git status",
    "workdir": "/home/user/project",
    "description": "Check git repository status"
  },
  "cwd": "/home/user/project",
  "workspace_root": "/home/user/project",
  "source_scope": "project",
  "session_id": "opencode-session-001"
}
```

### 字段说明与归一化映射

| 字段名 | 类型 | 必填 | 含义与归一化逻辑 |
| :--- | :--- | :--- | :--- |
| `event` / `hook_event_name` | string | 是 | 固定为 `"PreToolUse"` |
| `tool_name` | string | 是 | 工具名称，如 `"bash"`、`"sh"`、`"write_file"`、`"edit_file"`、`"read_file"` |
| `tool_input` | object | 是 | 工具调用参数字典，解析 `command`、`cmd`、`path`、`file_path`、`patch` |
| `cwd` / `workdir` | string | 否 | 工具执行工作目录（缺省回退至当前进程 cwd） |
| `workspace_root` | string | 否 | 项目根目录 |
| `source_scope` | string | 否 | `"project"` 或 `"global"` |
| `session_id` | string | 否 | OpenCode 当前会话标识 |

---

## 4. 响应载荷规范（stdout Wire Output）

### 4.1 放行响应（Allow）

退出码：`0`

```json
{
  "decision": "allow",
  "action": "allow"
}
```

### 4.2 阻断响应（Deny）

退出码：`1`

```json
{
  "decision": "deny",
  "action": "block",
  "reason": "[AI卫士安全阻断][AG-RULE-DESTRUCTIVE-RM] 命中禁止规则: 禁止在根目录或关键路径执行递归强行删除"
}
```

### 4.3 异常/降级阻断响应（Fail-Closed）

退出码：`1`

```json
{
  "decision": "deny",
  "action": "block",
  "reason": "[AI卫士安全阻断][AG-PROTO-JSON-PARSE-ERROR] 输入 JSON 格式损坏，触发默认安全阻断（Fail-Closed）"
}
```

---

## 5. 插件挂载路径标准

OpenCode 原生扫描以下插件目录：
- **Linux / WSL2**：`~/.config/opencode/plugins/ai-guard-pretool.ts`
- **Windows 宿主机**：`%APPDATA%\opencode\plugins\ai-guard-pretool.ts` 或 `~/.config/opencode/plugins/ai-guard-pretool.ts`
- **项目级覆盖**：`<workspace>/.opencode/plugins/ai-guard-pretool.ts`

插件由 `ai-guard install opencode` 命令幂等生成，卸载时通过 `ai-guard uninstall opencode` 干净移除。
