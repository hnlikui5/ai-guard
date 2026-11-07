# Antigravity（AGY）与 agy CLI Hook 协议真实契约规范

- **文档阶段**：Phase 5.5（AGY 扩展规范）
- **适用产品与客户端形态**：
  - Antigravity CLI（`agy`）：基于终端的 AI 交互客户端，配置位于 `~/.gemini/antigravity-cli/`
  - Antigravity 2.0（桌面端）：基于独立窗口的多 Agent 协作桌面应用，配置位于 `~/.gemini/antigravity/`
  - Antigravity IDE：AI-First 独立开发环境，配置位于 `~/.gemini/antigravity-ide/`
- **契约依据**：遵循 Antigravity 官方 Lifecycle Hooks 规范（`hooks.json` Draft-07 ProtoJSON 协议）。

---

## 1. 核心架构与管控定位

AI卫士对 AGY / `agy` CLI 的管控，定位为 **“基于原生 Lifecycle Hooks 的执行前（PreToolUse）强拦截与会话只读治理”**：

1. **执行前强拦截（PreToolUse）**：
   - AGY 在模型发起工具调用（执行终端命令、修改代码文件、调用 MCP 工具等）之后、真实系统调用执行**之前**，强制同步调用 AI卫士进行安全裁决；
   - 裁决在毫秒级内完成（目标延迟 < 2ms），若发现高危删库、裸盘格式化、未授权私钥读取或外联攻击，返回 `deny` 阻断执行，目标副作用文件绝对不会生成。
2. **多层级配置覆盖（Hierarchical Discovery）**：
   - **全局管控层**：`~/.gemini/config/hooks.json`，对本机所有 `agy` CLI 命令与所有工作区全局生效，无需每个项目单独配置；
   - **项目级管控层**：`<workspace>/.agents/hooks.json`，支持针对特定敏感代码仓库设定专属管控规则。
3. **对话索引与快照备份**：
   - 自动发现各形态 AGY 的 `transcript.jsonl` 转录文件与 `artifacts/` 目录；
   - 提供 100% 只读的会话检索与带 SHA-256 完整性哈希校验的快照备份归档。

---

## 2. Hook 配置文件规范（`hooks.json`）

### 2.1 全局配置路径
- Linux / WSL2：`$HOME/.gemini/config/hooks.json`
- Windows 宿主机：`%USERPROFILE%\.gemini\config\hooks.json`

### 2.2 配置 JSON 结构
```json
{
  "ai-guard": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "run_command|write_file|edit_file|call_mcp_tool",
        "hooks": [
          {
            "type": "command",
            "command": "ai-guard hook agy pre-tool-use",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

- **`"ai-guard"`**：命名的 Hook 命名空间，可与用户既有其他 Hook（如 `lint-checker`、`telemetry` 等）和平共存并顺序合并。
- **`"enabled"`**：布尔值，设为 `true` 开启防护，设为 `false` 即可一键安全停用，无需删除文件。
- **`"matcher"`**：正则匹配器，支持精确匹配或管道分割：
  - `"run_command"`：匹配所有终端 Shell 命令执行；
  - `"write_file|edit_file"`：匹配所有写文件与补丁编辑操作；
  - `"call_mcp_tool"`：匹配所有外部 MCP 服务工具调用；
  - `"*"`：匹配全部工具调用。
- **`"command"`**：执行裁决的可执行文件路径：
  - Linux / WSL2：`ai-guard hook agy pre-tool-use`
  - Windows 宿主机：`ai-guard.exe hook agy pre-tool-use`
- **`"timeout"`**：单次 Hook 执行超时时间（秒），默认设为 5 秒；超时或异常退出默认 Fail-Closed 阻断。

---

## 3. 标准 I/O 通信协议（Wire Protocol）

AGY 的 Hook 机制通过标准输入（**stdin**）传入 JSON 上下文，并通过标准输出（**stdout**）接收 JSON 裁决结果。
所有 JSON 字段采用 **camelCase** 命名（遵循 ProtoJSON 规范）。

### 3.1 接收输入（stdin JSON Schema）

```json
{
  "conversationId": "ead0513b-e890-4e56-848b-c32a685ffe3a",
  "workspacePaths": [
    "/home/ai-li/codes/ai-guard"
  ],
  "transcriptPath": "/home/ai-li/.gemini/antigravity/transcript.jsonl",
  "artifactDirectoryPath": "/home/ai-li/.gemini/antigravity/brain/ead0513b-e890-4e56-848b-c32a685ffe3a",
  "modelName": "auto",
  "lastUserInput": "帮我清理临时编译目录",
  "stepIdx": 18,
  "toolCall": {
    "name": "run_command",
    "args": {
      "CommandLine": "rm -rf ~/codes/ai-guard/target",
      "toolSummary": "Clean target directory",
      "WaitMsBeforeAsync": 5000
    }
  }
}
```

#### 关键字段映射说明：
| AGY 输入字段 | 类型 | AI卫士领域模型映射 (`ActionEvent`) | 说明 |
| :--- | :--- | :--- | :--- |
| `conversationId` | `string` | `ActionEvent::session_id` | 统一会话唯一标识 |
| `workspacePaths[0]` | `string` | `ActionEvent::cwd` | 当前工作区根目录绝对路径 |
| `stepIdx` | `u64` | `ActionEvent::turn_id` | 当前执行步骤序号 |
| `toolCall.name` | `string` | 工具识别器 | `"run_command"`, `"write_file"`, `"edit_file"`, `"call_mcp_tool"` 等 |
| `toolCall.args.CommandLine` | `string` | `ActionKind::ExecuteShellCommand` | 待执行的终端命令文本 |
| `toolCall.args.Path` | `string` | `ActionKind::WriteFile` / `EditFile` | 待写入或修改的文件绝对路径 |
| `toolCall.args.Content` | `string` | 补丁与文件内容提取 | 检查是否包含恶意代码或敏感凭据泄露 |
| `toolCall.args.ServerName` | `string` | `ActionKind::InvokeMcpTool` | MCP 服务器标识 |

---

### 3.2 裁决输出（stdout JSON Schema）

AI卫士在完成策略引擎（`packages/security`）高速规则运算后，向 stdout 打印紧凑 JSON：

#### 场景 A：合法操作放行（Allow）
```json
{
  "decision": "allow"
}
```

#### 场景 B：高危操作硬阻断（Deny，零副作用生成）
```json
{
  "decision": "deny",
  "reason": "[AG-RISK-DESTRUCTIVE-CMD] AI卫士安全阻断：检测到可能导致系统或主目录破坏的高危删除指令（rm -rf /），已严格拒绝执行。"
}
```
> 当 AGY 收到 `decision = "deny"` 时，Agent 会立即收到拦截错误响应并停止执行，不会产生任何文件系统或进程副作用。

#### 场景 C：中高风险操作降级人机确认（Ask）
```json
{
  "decision": "ask",
  "reason": "AI卫士提醒：该命令涉及敏感配置修改，请确认是否允许执行。"
}
```
> AGY 界面会弹出交互式确认弹窗，由开发者决定是否授权本次操作。

---

## 4. 故障隔离与默认安全（Fail-Closed 规范）

满足 `AGENTS.md` §4.1 核心安全红线：
1. **解析异常保底阻断**：若 stdin 传入的数据超过最大限制（如 > 2 MiB）、格式损坏或缺少关键字段，`ai-guard hook agy` 必须**默认输出 `decision = "deny"`**，严禁因内部异常而默认放行（Fail-Open）。
2. **凭据脱敏保底**：`reason` 文本和审计记录中的所有 Token、API Key、私钥等必须经过 `redact_secrets` 脱敏后再输出，严禁泄露用户敏感信息。
3. **非阻塞与超时防护**：Hook 执行严格设定 5 秒超时，避免阻塞开发者的正常交互。

---

## 5. 会话转录与工件管理契约（Session & Artifacts）

| 项目 | 存储位置 | AI卫士管理动作 |
| :--- | :--- | :--- |
| **转录流水** | `~/.gemini/antigravity/transcript.jsonl`<br>`~/.gemini/antigravity-cli/transcript.jsonl` | 只读索引 `step_index`、时间戳、模型名称与对话轮次 |
| **生成工件** | `~/.gemini/antigravity/brain/<conv_id>/` | 扫描 `.md`、`.html` 与预览资源文件 |
| **快照备份** | `~/.local/share/ai-guard/backups/`（Linux）<br>`%LOCALAPPDATA%\ai-guard\backups\`（Windows） | 生成包含清单（Manifest）与 SHA-256 校验的压缩快照 |
