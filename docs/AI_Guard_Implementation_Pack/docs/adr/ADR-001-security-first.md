# ADR-001：安全优先、Session 后置

- 状态：Proposed
- 日期：2026-11-07
- 决策：AI卫士 V0.1 的核心完成条件是 Codex 已验证路径的执行前拦截、规则、诊断与脱敏审计；Codex App Server 和 Session 管理延后到 V0.2。
- 原因：产品首先是 AI 编程 Agent 安全工具。Session 不构成执行前安全控制边界。
- 后果：首版功能范围收敛，保留以后集成 Session Provider 的模块边界。
- 验证：真实 Codex E2E Deny 后副作用文件不存在；Hook 未受信时不能宣称保护。
