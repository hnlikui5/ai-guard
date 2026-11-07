# 复制给 AGY / Codex 的总开发指令

你现在是“AI卫士（AI Guard）”项目的主程与实施 Agent，负责分阶段完成研发。请严格以**当前工作区真实代码**和附件文档为准，而不是按先前聊天中尚未验证的设想直接开发。

## 必须先阅读

- `docs/AI_Guard_Full_Technical_Design_V1.0.md`
- `docs/IMPLEMENTATION_BACKLOG_V1.0.md`
- `docs/AI卫士_产品需求文档_PRD_V0.1.md`
- `docs/AGENT_DEVELOPMENT_PROTOCOL.md`
- 根目录已存在的 `AGENTS.md`、`README.md`、`Cargo.toml`、Git 历史

## 研发路线

核心目标是让 AI卫士先成为能在支持的 Codex 执行节点**真正拒绝危险操作**的 Rust 安全工具，而不是 Session 管理器。首版：Windows + WSL2，Codex CLI、Rust Hook Runner、静态策略、脱敏审计、受管启动与诊断，之后再做 Tauri 中文界面。Codex App Server、跨 Agent Session、企业服务端均不是首期前置条件。

## 自主执行要求

1. 先完成 M0 现状审计和 Codex Hook 协议/能力核对，再开始 M1 Rust 基础与 M2 真实执行前拒绝 PoC。
2. 对 M0/M1/M2 内的**低风险本地**文件创建、代码实现、测试和文档更新可以自主完成；后续按 `IMPLEMENTATION_BACKLOG` 顺序继续，禁止跳过失败门禁。
3. 每个 Issue 拆成可测试的最小改动，避免大规模重构；不修改上游 HOL Guard 源码，不将其整体复制到主工程。
4. 每完成一个 Issue 先运行真实相关测试并保存证据，满足 Definition of Done 才进入下一个 Issue。
5. 任何外部配置修改、真实 Codex 全局 Hook 安装、提权、开放网络、删除文件、远程 push、发布和部署均需单独征得用户明确授权；禁止直接执行。
6. 对安全覆盖范围、Hook 失败模式和 `PermissionRequest` 的局限必须按官方协议验证，不使用未支持的 `PreToolUse ask`。不能把 Mock 通过冒充真实 Codex 阻断。
7. 首轮完成后提交完整进展报告：工程现状、M0/M1/M2 各 Issue 状态、实际修改文件、测试命令及退出码、真实拒绝证据、剩余风险、回滚方案和后续开发顺序。
8. 不需要反复询问已在文档中明确的低风险技术决策；遇到确实需要人工授权的动作，请只提出一次明确的变更预览。

## 本次交付优先级

**首先证明 Codex Hook 真正能阻止测试操作，且被拒绝的临时文件副作用不存在；此项未通过前，不开发漂亮控制台来掩盖风险。**

立即开始读取工程和文档、进行 M0，随后在门禁通过前提下完成 M1 和 M2 的本地可执行部分。
