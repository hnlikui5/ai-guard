# ADR-0003：WSL2 执行侧独立裁决与 Windows 桌面受限命令桥接

- **状态**：已确认（Accepted）
- **日期**：2026-11-07
- **决策范围**：`apps/local-service`、`apps/desktop`

---

## 1. 背景（Context）

首发目标环境中，Codex CLI（`0.160.1+`）运行在 WSL2 Ubuntu Linux 环境内，而管理界面（Tauri 2 Desktop）运行在 Windows 宿主机。需要确定安全裁决的运行位置、是否依赖常驻后台守护进程（Daemon）以及跨系统 IPC 通信方式。

## 2. 决策内容（Decision）

1. **安全裁决靠近执行侧且不依赖常驻 Daemon**：
   - Rust 二进制 `ai-guard` 直接部署在 WSL2 Ubuntu 内。
   - `ai-guard hook codex pre-tool-use` 作为单次短生命周期进程由 Codex 触发，直接读取本地可信策略快照完成毫秒级同步裁决，即使 Windows 桌面端关闭也完全不影响安全拦截生效。
2. **审计写入超时的无锁降级保护**：
   - 为防止多进程并发写 SQLite 触发锁等待导致 Hook 超时（进而引发 Codex Fail-Open 放行），SQLite 开启 WAL 模式并将 `busy_timeout` 限制在 15ms 以内；若写库超时或失败，优先向 `stdout` 输出 `Deny/Allow` 协议结果，并将审计记录追加至本地无锁 fallback 文件。
3. **Windows 桌面端采用白名单 `wsl.exe --exec` 桥接**：
   - V0.1 阶段不在 WSL2 暴露常驻 HTTP 监听端口，由 Windows 侧 Tauri Rust Command 通过独立 `argv` 调用 `wsl.exe --distribution <distro> --exec <ai-guard-bin> <approved-subcommand> --json` 交互。
   - 严禁拼接 Shell 命令字符串，且在 WSL2 断连或命令超时时立即在 UI 显示“状态未知”。
