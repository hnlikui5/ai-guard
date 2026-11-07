# packages/agent-adapters

AI 编程 Agent 统一适配层。

## 模块职责

- 屏蔽不同 AI 编程 Agent 的底层协议、配置文件与运行机制差异
- V0.1 阶段聚焦 **Codex** 接入（包括 Codex App Server 交互协议及本地只读运行状态探测）
- 后续扩展支持 Claude Code、OpenCode 等其他主流 Agent
- 将具体 Agent 的工具调用、命令执行事件标准化为内部统一的拦截与审计事件模型

## 架构约束

- 与 `packages/session` 解耦：适配层负责连接与协议转换，不直接承担通用 Session 索引与归档管理。
- 与 `packages/security` 策略引擎解耦：适配层仅负责采集上下文并执行策略裁决结果（放行/阻断/挂起等待审批），不包含具体安全策略判定逻辑。
