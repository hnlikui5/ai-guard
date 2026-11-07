# AI卫士 · 交给 Codex / AGY 的完整开发包

**版本：** V1.0（2026-11-07）｜**状态：** 方案和任务基线，不代表现有代码已实现。

## 文件说明

- `docs/AI_Guard_Full_Technical_Design_V1.0.md`：完整技术方案（系统架构、Hook 契约、规则、数据库、API、Windows/WSL2、企业架构、测试）。
- `docs/AI卫士_产品需求文档_PRD_V0.1.md`：个人版 V0.1 产品 PRD，FR-001～FR-018。
- `docs/IMPLEMENTATION_BACKLOG_V1.0.md`：M0～M9 逐项任务、依赖和验收门禁。
- `docs/AGENT_DEVELOPMENT_PROTOCOL.md`：Codex/AGY 自动开发的安全和质量纪律。
- `docs/adr/`：初始架构决策记录。
- `PROMPT_AGY_CODEX_START.md`：首次交给 AGY/Codex 的总提示词。
- `assets/`：Word 版中使用的技术架构配图。

## 如何导入已有 Git 仓库

1. 保留已有工程目录和 `.git`，不要重新初始化仓库。
2. 将本包的 `docs/` 文件复制到工程 `docs/`，检查已有文件后再合并冲突。
3. **不要覆盖**工程已存在的根 `AGENTS.md`；将 `docs/AGENT_DEVELOPMENT_PROTOCOL.md` 的规则审阅后按需合并进现有 `AGENTS.md`，并让 AGY 在开发中读取该文件。
4. 把 `PROMPT_AGY_CODEX_START.md` 的内容粘贴给 AGY/Codex，要求它先检查现实代码再开展 M0。
5. 默认不自动修改真实 `~/.codex`、全局系统配置、提权或 Git 远程状态；涉及此类动作须明确授权。

## 重要的技术边界

本项目是安全工具，但首版的 Codex Hook **不是不可绕过的 OS 安全屏障**：未受信、未启用、超时、执行错误或某些未覆盖的工具路径都有可能造成防护失效。只有真实 Codex E2E 证明被拒绝的操作未执行，才能宣称该路径具备已验证阻拦能力。

## 建议启动顺序

`M0 工程审计/Hook 协议 → M1 Rust Core → M2 真实拦截 PoC → M3 规则 → M4 安装回滚 → M5 审计诊断 → M6 桌面端 → M7 发布`。此后再评估 Session、沙箱和企业版。
