# ADR-002：WSL 执行侧 Rust、Windows 桌面只管理

- 状态：Proposed
- 日期：2026-11-07
- 决策：V0.1 Rust Hook Runner 和策略评估在 WSL2 Linux Codex 执行侧运行；Windows Tauri 2 GUI 通过受限 `wsl.exe --exec` JSON 命令桥接管理。
- 原因：安全判定必须靠近真实工具执行位置；GUI 关闭不应影响 Hook 基本判定。
- 后果：Windows 原生 Codex 并不自动受保护；未来独立设计其原生适配。
- 验证：WSL Hook E2E、Windows/WSL 断连与注入测试、无开放监听端口。
