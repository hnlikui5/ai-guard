# 安全架构与能力边界声明（LIMITATIONS.md）

本文档向用户与安全审计人员诚实披露 **AI卫士（AI Guard）个人版 V0.1** 的真实安全能力边界与已知限制。

---

## 1. Hook 执行前拦截 ≠ OS 内核级全面沙箱隔离

- AI卫士个人版 V0.1 基于 Codex 官方 `PreToolUse` Hook 协议，在 Agent 调用 `Bash`（`exec_command`）、`apply_patch` 与 `mcp__*` 工具**执行前**做确定性策略评估与拦截。
- 这属于**应用层协议级拦截**，不等同于 Linux Landlock / Seccomp、Windows Job Object / AppContainer 或独立虚拟机等 OS 内核级强制访问控制。
- 如果某个已放行的合法构建脚本（如 `npm test` 或 `cargo test`）内部间接执行了恶意代码，应用层 `PreToolUse` 钩子不会二次拦截子进程内部的系统调用。

---

## 2. Codex 0.160.1+ 协议已知盲区

基于 Phase 0 与 Phase 1 的真实二进制逆向与实测验证：
1. **`write_stdin` 交互式终端续写不触发 `PreToolUse`**：
   - 在 `codex-cli 0.160.1+` 中，首次打开终端（`exec_command`）会触发 `PreToolUse`，但后续向已打开的交互式 PTY 发送按键（`write_stdin`）不会触发 `PreToolUse`。
2. **复合/动态 Shell 表达式的静态分析边界**：
   - 对于包含复杂动态变量展开、子 Shell 嵌套（`$(...)`）或非常规编码的复合命令，策略引擎会将其标记为 `CoverageLevel::Unsupported`（原因码 `AG-UNSUPPORTED-COMPOUND-SHELL`），而不会虚假标记为“完全安全”。
3. **Hook 信任机制（`trusted_hash`）**：
   - Codex 要求 `config.toml` 中的 Hook 在 `[hooks.state]` 下具有匹配的 `trusted_hash`（或用户在 Codex TUI 中通过 `/hooks` 确认信任）才会实际执行拦截。
   - 因此，AI卫士严格区分 `unprotected`、`partially_protected` 与 `protected_verified`，绝不将“仅存在配置文件”谎称为“已验证拦截（`protected_verified`）”。
