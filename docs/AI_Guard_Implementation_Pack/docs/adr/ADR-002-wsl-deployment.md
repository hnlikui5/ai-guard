# ADR-002：Windows 宿主机中心化主控与宿主机/WSL2 双环境就地拦截

- 状态：Accepted（已同步至 `docs/decisions/0003-wsl2-execution-and-desktop-bridge.md`）
- 日期：2026-11-07
- 决策：AI卫士作为运行在 Windows 宿主机上的原生桌面应用，以宿主机为主控中心（管理全局策略 `policy.toml`、统一审计库 `events.db` 与备份仓），同时纳管 **Windows 宿主机下的 Codex（`C:\Users\<User>\.codex` 桌面版/CLI，挂载 `ai-guard.exe`）** 与 **WSL2 下的 Codex（`/home/<user>/.codex`，由宿主机分发 `ai-guard-linux` 探针与策略镜像并通过受控 `wsl.exe --exec` 汇总审计）**。
- 原因：桌面软件运行在宿主机，必须能独立管理宿主机本机 Codex，同时跨边界管理 WSL2 子系统内的 Codex；而 Hook 拦截必须就地执行以保障 <10ms 低延迟。
- 后果：Rust 核心库从 Day 1 保持 Windows + Linux 双目标同源编译；未开启 WSL2 时宿主机功能完全独立可用。
- 验证：宿主机与 WSL2 双环境 Hook E2E、Windows/WSL 断连隔离与注入测试、无开放监听端口。
