# ADR-0003：Windows 宿主机中心化主控与宿主机/WSL2 双环境 Codex 统一纳管架构

- **状态**：已确认（Accepted，替代原单向 WSL2 中心化假设）
- **日期**：2026-11-07
- **决策范围**：`apps/desktop`、`apps/local-service`、`packages/*`

---

## 1. 背景（Context）

AI卫士（AI Guard）的最终产品形态是运行在 **Windows 宿主机上的桌面应用程序（`AI卫士.exe`）**。在实际开发机环境中，用户同时存在两类需要被保护和管理的 Codex 运行环境：
1. **Windows 宿主机原生环境**：如安装在宿主机上的 Codex 桌面应用与 Windows CLI（配置与 700MB+ 会话数据位于 `C:\Users\<User>\.codex\`）。
2. **WSL2 子系统环境**：如安装在 WSL2 Ubuntu 内的 `codex-cli` 与 `app-server-daemon`（配置与会话数据位于 `/home/<user>/.codex/`）。

早期草案由于在 WSL2 内使用 AGY 研发，曾将 WSL2 视为唯一核心运行位置、将 Windows 桌面端仅视为转发外壳（WSL2-Centric）。这一假设会导致未开启 WSL2 时宿主机桌面程序无法独立工作，且无法原生纳管宿主机本机的 Codex 桌面应用。

---

## 2. 决策内容（Decision）

### 2.1 确立“Windows 宿主机为主控中心（Host-Centric Master）”
1. **主程序与全局真相源驻留宿主机**：
   - `AI卫士 Desktop`（Tauri 2 GUI + 宿主机 Rust 核心服务）运行在 Windows 宿主机上。
   - 全局策略真源（`policy.toml`）、统一安全审计数据库（`events.db`）与备份中心均存放在宿主机 `%LOCALAPPDATA%\ai-guard\` 下。
2. **双受管目标（`ManagedTarget`）架构**：
   - 宿主机主控程序通过统一的 `TargetManager` 抽象，同时纳管：
     - **目标类型 A（`WindowsHost`）**：宿主机本机 `C:\Users\<User>\.codex\`（含 Codex 桌面版与 Windows CLI）。
     - **目标类型 B（`Wsl2Distro`）**：WSL2 各发行版内的 `/home/<user>/.codex/`（含 WSL2 `codex-cli` 与 WSL2 `app-server-daemon`）。

### 2.2 “控制面集中、数据面（Hook 拦截）就地执行”协同机制
1. **宿主机目标就地拦截**：
   - 宿主机 `C:\Users\<User>\.codex` 挂载宿主机原生编译的 `ai-guard.exe hook codex pre-tool-use`，直接读取宿主机策略并写入宿主机审计库。
2. **WSL2 目标就地拦截 + 镜像同步**：
   - 宿主机主程序自动向受管 WSL2 发行版部署同源编译的 Linux 原生探针 `~/.local/bin/ai-guard-linux`，并将宿主机主策略 `policy.toml` 镜像同步至 WSL2 `~/.config/ai-guard/policy.toml`。
   - WSL2 内的 Codex 触发 Hook 时直接执行 WSL2 内部的 `ai-guard-linux`（耗时 <10ms，避免跨虚拟机进程启动延迟），审计结果写入 WSL2 本地缓冲，并由宿主机主控通过受控 `wsl.exe --distribution <distro> --exec ~/.local/bin/ai-guard-linux ... --json` 增量拉取归并至宿主机主库展示。
   - 严禁从宿主机跨 `\\wsl.localhost\`（9P 协议）直接并发读写 WSL2 内的 SQLite 数据库文件。

### 2.3 审计写入 15ms 熔断降级保护
- 无论在宿主机还是 WSL2 内部，Hook 进程写 SQLite 均开启 `WAL` 模式且设置 `busy_timeout = 15ms`；若遇锁竞争或 I/O 异常，优先向 `stdout` 输出 `Deny/Allow` 协议 JSON，并将未落盘事件写入无锁 `events-fallback.jsonl`，杜绝因写库阻塞触发 Hook 超时放行（Fail-Open）。

---

## 3. 后果与研发约束（Consequences）

1. **Rust 核心库 100% 跨平台**：`packages/*` 与 `apps/local-service` 严禁硬编码仅限 Linux 的系统调用，确保同一套源码同时编译出 Windows `ai-guard.exe` 与 Linux `ai-guard-linux`。
2. **跨平台规则全覆盖**：`packages/security` 内置规则必须同时覆盖 Linux Bash/sh 与 Windows PowerShell/CMD 高危命令模式及两套操作系统的敏感路径格式。
