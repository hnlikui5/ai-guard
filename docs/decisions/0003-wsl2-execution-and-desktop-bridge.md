# ADR-0003：多执行目标（WSL2 + Windows 原生）独立裁决与桌面受限命令桥接

- **状态**：已确认（Accepted）
- **日期**：2026-11-07
- **决策范围**：`apps/local-service`、`apps/desktop`、`packages/agent-adapters`、`packages/security`

---

## 1. 背景（Context）

首发目标环境中，`codex-cli (0.160.1+)` 运行在 WSL2 Ubuntu Linux 环境内，同时用户未来还会使用 **Codex 桌面应用（Codex Desktop App）**（其工作区可能位于 WSL2 内，也可能直接运行在 Windows 原生环境中）。需要确定安全裁决的运行位置、是否依赖常驻后台守护进程（Daemon）、跨平台编译约束以及桌面端 IPC 通信方式。

## 2. 决策内容（Decision）

1. **安全裁决靠近真实执行侧且不依赖常驻 Daemon**：
   - 遵循“Agent 在哪里执行工具，Hook Runner 就部署在哪里”的原则：
     - 针对 **WSL2 内的 Codex CLI 及 Codex 桌面应用（WSL2 模式）**：部署 Linux 原生编译的 `ai-guard` 二进制。
     - 针对 **Windows 原生模式的 Codex 桌面应用**：由同一套 Rust 源码编译产出 Windows 原生 `ai-guard.exe` 二进制，避免从 Windows 每次跨 `wsl.exe` 触发 Hook 带来的高延迟与引号转义问题。
   - `ai-guard` 核心包（`packages/*`）从 Phase 1 起强制保持 Linux + Windows 双平台可编译，显式建模 `ExecutionTarget`（`Wsl2Distro` / `WindowsNative`）与 `ClientSurface`（`CodexCli` / `CodexDesktop`）。
2. **审计写入超时的无锁降级保护**：
   - 为防止多进程并发写 SQLite 触发锁等待导致 Hook 超时（进而引发 Codex Fail-Open 放行），SQLite 开启 WAL 模式并将 `busy_timeout` 限制在 15ms 以内；若写库超时或失败，优先向 `stdout` 输出 `Deny/Allow` 协议结果，并将审计记录追加至本地无锁 fallback 文件。
3. **AI卫士桌面端采用白名单双通道桥接（`TargetBridge`）**：
   - 管理 WSL2 目标时，通过独立 `argv` 调用 `wsl.exe --distribution <distro> --exec <ai-guard-bin> <approved-subcommand> --json`。
   - 管理 Windows 原生 Codex 桌面目标时，通过独立 `argv` 直接调用本机 `ai-guard.exe <approved-subcommand> --json`。
   - 严禁拼接 Shell 命令字符串，且在目标断连或命令超时时立即在 UI 显示“状态未知”。
