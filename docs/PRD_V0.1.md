# AI卫士（AI Guard）产品需求文档与分阶段研发 PRD（双 Agent 统一管控定稿版）

- **文档编号**：`AG-PRD-V0.1`
- **版本**：`V0.1-DualAgent`（Windows 宿主机主控 + 宿主机/WSL2 Codex 与 Antigravity / `agy` CLI 统一纳管定稿版）
- **日期**：2026-11-07
- **文档状态**：已确认基线（研发与阶段验收唯一依据）
- **代码仓库**：`https://github.com/hnlikui5/ai-guard.git`
- **产品运行形态**：**Windows 宿主机原生桌面应用（主控中心）**，同时纳管 **Codex（桌面版/CLI，Windows 宿主机与 WSL2）** 与 **Antigravity（AGY 桌面版 / `agy` CLI，Windows 宿主机与 WSL2）**
- **主力技术栈**：Rust（跨平台同源编译 Windows `.exe` 与 WSL2 Linux 探针）+ SQLite（宿主机统一主库 + WSL2 缓冲同步）+ Tauri 2 / React / TypeScript（宿主机中文桌面端）
- **开源许可证**：Apache License 2.0（个人版）

---

## 1. 产品综述与优化基线说明

### 1.1 一句话产品定义

**AI卫士（AI Guard）** 是一款运行在 **Windows 宿主机** 上的 AI 编程 Agent 本地安全防护与运行治理桌面软件，能够**同时发现、保护和管理“宿主机与 WSL2 双环境下的 Codex（桌面应用/CLI）”与“Antigravity（AGY 桌面版 / `agy` CLI）”**，在各自执行节点就地阻断高危操作、在宿主机桌面端统一呈现防护状态与脱敏审计，并提供跨 Agent 与跨环境的会话（Session）只读索引与安全备份能力。

### 1.2 相较初始方案包的关键重构与优化（已纳入本 PRD）

1. **架构视角纠正：从“WSL2 中心化”重构为“Windows 宿主机中心化主控 + 双环境纳管”**：
   - 修正原方案将主库与主服务放在 WSL2 内的主次颠倒假设。明确 **AI卫士最终是运行在 Windows 宿主机上的桌面软件**，全局策略真源（`policy.toml`）、统一审计库（`events.db`）和备份中心均位于 Windows 宿主机（`%LOCALAPPDATA%\ai-guard\`）。
   - 宿主机主程序向下统一纳管两类环境：**宿主机原生环境（如 `C:\Users\kui.li\.codex`，含 Codex 桌面版与 750MB+ 会话库）** 与 **WSL2 子系统环境（如 `/home/ai-li/.codex`，含 WSL2 `codex-cli`）**。即使未开启 WSL2，宿主机防护与管理功能依然完整可用。
2. **“控制面集中管理、数据面（Hook 拦截）就地极速执行”机制**：
   - 同一套 Rust 核心代码编译出宿主机 `ai-guard.exe` 与 WSL2 探针 `ai-guard-linux`：宿主机 Codex / AGY 直接触发 `ai-guard.exe hook`；WSL2 Codex / AGY 触发由宿主机自动分发到 WSL2 内的 `ai-guard-linux hook`（读取宿主机下发的策略镜像），避免每次工具调用跨 Windows/WSL2 虚拟机拉起进程的高延迟，再由宿主机主控增量拉取归并 WSL2 审计事件。
3. **对齐本机宿主机 Codex（`0.166.0`）与 WSL2 Codex（`0.160.1`）真实运行架构**：
   - 实测本机宿主机已安装 Codex 桌面版（`C:\Users\kui.li\.codex`，含 `codex.exe` 与 `codex-command-runner-0.166.0-alpha.5.1.exe`），WSL2 内已安装 `codex-cli 0.160.1`（`hooks`、`daemon_auto_start`、`unified_exec` 均为 `stable=true`）。
   - 本 PRD 将 **宿主机与 WSL2 双环境的 Hook 配置结构、Daemon 刷新验证及跨平台工具名映射** 纳入 Phase 0/1 强制验收项。
4. **明确“安全主线优先 + Backup 前置 + M1 Session 双环境汇入”排期策略**：
   - V0.1 坚持以 **“真实执行前拦截闭环（Hook Allow/Deny + 零副作用证明）”** 为第一优先级。
   - `packages/backup` 在 **Phase 3** 即投入使用（承担宿主机与 WSL2 Codex / AGY 配置文件、策略文件的事务备份、SHA-256 校验与原子回滚）。
   - 原 M1 阶段的 Codex Session 管理成果在 **Phase 4B** 对齐迁入 `packages/session`，支持在宿主机界面上统一只读浏览和备份 **宿主机 `C:\Users\<User>\.codex` 与 WSL2 `~/.codex`** 的会话数据。
5. **扩展跨平台 Hook 事件、Shell 语法与路径覆盖模型**：
   - 适配层完整建模 Codex 四大标准 Hook 事件（`PreToolUse`、`PermissionRequest`、`UserPromptSubmit`、`PostToolUse`）与 Antigravity 原生 `PreToolUse` Hook。
   - 规则引擎同时覆盖 **Linux Shell（`bash`/`sh`）** 与 **Windows Shell（`powershell`/`pwsh`/`cmd`）** 的高危命令语法及 Windows/POSIX 敏感路径。
6. **解决无常驻 Daemon 模式下 SQLite 并发锁与 Hook 超时矛盾**：
   - 单次 Hook 进程内策略裁决与审计落盘解耦：SQLite 开启 `WAL` 模式且设置 `busy_timeout = 15ms`；若遇锁竞争或 I/O 异常，**优先在 50ms 内向 `stdout` 返回 `Deny/Allow` 协议 JSON**，未落盘事件自动写入本地无锁 `events-fallback.jsonl` 并在后续查询时归并，杜绝因写库阻塞引发 Hook 超时放行（Fail-Open）。
7. **统一工程目录与双目标编译工具链基线**：
   - 在 Phase 0 明确建立支持 Linux 与 Windows 双目标编译的 Rust 工具链基线。

### 1.3 面向 Codex CLI 与 Codex 桌面应用（Codex Desktop）的双形态支持设计

除命令行形态的 `codex-cli` 外，AI卫士在架构与产品规划上明确支持 **Codex 桌面应用（Codex Desktop App）** 的两种运行模式：

1. **模式 A：Codex 桌面应用连接 WSL2 工作区（WSL2 Backend 模式）**
   - 桌面应用通过 WSL2 内的 `~/.codex/app-server-daemon` 执行命令与文件操作，与 WSL2 内的 `codex-cli` 共享 `~/.codex/` 配置与 Hook 机制。
   - **关键保障**：在 `doctor` / `install` / `self-test` 中纳入对 `app-server-daemon` 及 `app-server-control` 的状态检测与配置刷新验证，确保桌面应用新建或恢复会话时立即加载最新 Hook。
2. **模式 B：Codex 桌面应用运行于 Windows 原生环境（Windows Native 模式）**
   - 桌面应用直接在 Windows 宿主机（`C:\Users\<User>\.codex\`）下运行并调用 `powershell.exe` / `pwsh.exe` / `cmd.exe`。
   - **关键保障**：
     - **核心代码跨平台同源编译**：`apps/local-service` 与 `packages/*` 从 Phase 1 起禁用 Linux 专属硬编码，通过 `#![cfg(unix)]` / `#![cfg(windows)]` 隔离文件权限与原子重命名差异，使同一套 Rust 代码既可编译为 WSL2 Linux 二进制 `ai-guard`，也可编译为 Windows 原生二进制 `ai-guard.exe`（避免 Windows 原生 Hook 每次跨 `wsl.exe` 调用的冷启动延迟与引号丢失问题）。
     - **多执行目标模型（`ExecutionTarget` & `ClientSurface`）**：在领域模型中显式区分 `ClientSurface`（`CodexCli` / `CodexDesktop` / `CodexAppServer`）与 `ExecutionTarget`（`Wsl2Distro` / `WindowsNative`）。
     - **跨 Shell 与跨路径规则覆盖**：`packages/security` 同步支持 POSIX Shell（`bash`/`sh`）与 Windows Shell（`PowerShell`/`CMD`）的高危命令模式（如 `Remove-Item -Recurse -Force`、`iwr ... | iex`、`powershell -enc`）及 Windows 敏感路径（`%USERPROFILE%\.ssh`、`C:\Users\*\...`）归一化检测。

### 1.4 面向 Antigravity（AGY）与 agy CLI 的原生 Lifecycle Hook 管控体系设计

针对 Antigravity 2.0、Antigravity IDE 以及 `agy` 命令行客户端，AI卫士提供全链路原生管控支持：

1. **分层 Hook 配置发现与挂接（Hierarchical Hooks）**：
   - **全局层**：Linux/WSL2 为 `~/.gemini/config/hooks.json`，Windows 宿主机为 `%USERPROFILE%\.gemini\config\hooks.json`；
   - **工作区层**：`<workspace>/.agents/hooks.json`；
   - AI卫士通过命名空间 `"ai-guard"` 进行幂等增量挂载，保留用户原有的其他 hook（如 linter、telemetry 等），并支持一键通过 `"enabled": false` 停用或通过 uninstall 干净移除。
2. **ProtoJSON Wire 协议与执行前拦截（PreToolUse）**：
   - 适配 AGY 原生标准 I/O 协议：stdin 传入 camelCase ProtoJSON，涵盖 `conversationId`、`workspacePaths`、`toolCall`（`name`、`args`）；
   - 归一化提取工具调用：将 `run_command`、`write_file`、`edit_file`、`call_mcp_tool` 转换为 AI卫士标准领域对象 `ActionEvent`；
   - stdout 返回标准决策 JSON：`{"decision": "allow" | "deny" | "ask", "reason": "..."}`。在 `decision = "deny"` 时 Agent 立即终止工具执行，确保零副作用产生。
3. **Fail-Closed 异常防护与脱敏审计**：
   - 协议解析异常、输入超长（> 2 MiB）或策略引擎异常时，严格遵循 Fail-Closed 默认阻断（输出 `deny`）；
   - 输出的 `reason` 及落库的审计事件经脱敏器过滤，杜绝 Token、API Key 及未脱敏内容泄露。
4. **会话转录与工件治理**：
   - 只读解析 `~/.gemini/antigravity/transcript.jsonl` 转录文件与 `brain/<conversation-id>/` 工件目录，在宿主机主控界面上统一提供会话检索、轮次预览与带 SHA-256 校验的快照备份。

---

## 2. 产品核心原则与安全红线

1. **真实拦截证据优先**：
   - `Mock 测试通过` ≠ `真实 Codex 端到端阻拦生效`。
   - `Hook 配置文件存在` ≠ `Hook 已受信任并被当前 Codex 加载`。
   - 任何宣称“已保护”的能力，必须具备真实 Codex 隔离环境下 **“触发拒绝规则 → 返回 Deny → 目标副作用文件不存在”** 的可复核证据。
2. **三层能力严格区分（禁止虚假宣传）**：
   - **观察（Observe）**：仅记录脱敏事件，不阻断执行。
   - **协议层拦截（Hook Deny）**：在 Codex 支持的 `PreToolUse` 路径上返回明确拒绝（`permissionDecision = "deny"`）。
   - **内核强制隔离（Sandbox Enforcement）**：由 OS 级沙箱（如 Codex 自带 Sandbox 或 V0.2 选配的 `nono` / Landlock）强制限制。
3. **四态防护状态机**：
   - `protected_verified`（已验证保护）：Hook 已注册、已受信任、版本匹配且最近一次隔离自检 Allow/Deny 全部通过。
   - `partially_protected`（部分保护）：核心 Shell/Patch Hook 已生效，但存在已知未覆盖工具或自检过期。
   - `unprotected`（未受保护）：未安装、已禁用、未信任、Runner 丢失或自检失败。
   - `unknown`（状态未知）：未执行检测、Codex 版本未知或 Windows UI 与 WSL2 通信中断。
4. **默认隐私最小化（Privacy by Default）**：
   - 默认离线运行，无云端账号，无默认遥测。
   - 审计库与日志默认**绝不保存**完整 Prompt、源码正文、完整未脱敏 Shell 命令原文、API Key / Token / 私钥或 `.env` 内容。

---

## 3. V0.1 全局功能需求总表（FR-001 ～ FR-020）

| 需求编号 | 所属模块 | 功能名称 | 优先级 | 对应研发阶段 | 核心验收口径 |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **FR-001** | `agent-adapters` | 宿主机与 WSL2 双环境 Codex 目标发现 | P0 | Phase 0 / 3 | 宿主机主控自动发现本机 `WindowsHost`（`C:\Users\<User>\.codex`，含 Codex 桌面版与 CLI）与各 `Wsl2Distro`（`/home/<user>/.codex`，含 WSL2 CLI 与 `app-server-daemon`），不读取 `auth.json` 密钥 |
| **FR-002** | `agent-adapters` | 跨平台 Codex `PreToolUse` 协议适配 | P0 | Phase 1 | 解析 stdin JSON（上限 1 MiB），支持 Linux（`Bash`/`unified_exec`）与 Windows（`PowerShell`/`CMD`/`codex-command-runner`）及 `apply_patch`/MCP 工具归一化，输出标准 Deny/Allow JSON |
| **FR-003** | `security` | 确定性策略评估引擎 | P0 | Phase 1 / 2 | 支持 `Allow` / `Deny` / `Observe` 三态裁决，遵循 Deny 优先，异常输入默认显式 Deny（Fail-Closed） |
| **FR-004** | `security` | 跨平台高危 Shell 命令拦截规则包 | P0 | Phase 2 | 准确拦截 Linux（`rm -rf`、`curl \| sh`、`mkfs`）与 Windows PowerShell/CMD（`Remove-Item -Recurse -Force`、`rmdir /s /q`、`iwr \| iex`、`-EncodedCommand`）高危模式 |
| **FR-005** | `security` | 跨平台敏感凭据与路径越界保护 | P0 | Phase 2 | 拦截对 Windows（`C:\Users\*\.ssh`、`%USERPROFILE%\.codex\auth.json`）与 POSIX（`~/.ssh`、`~/.codex/auth.json`）、`.env`、`*.pem` 的直接访问及 `../` / `..\` 路径穿越 |
| **FR-006** | `security` | 危险 Git 操作识别规则 | P1 | Phase 2 | 识别 `git reset --hard`、`git clean -fdx`、`git push --force`，支持配置为 Observe 或 Deny |
| **FR-007** | `security` | 观察模式与保护模式切换 | P0 | Phase 2 | `observe` 模式仅记录命中规则不阻断；`protect` 模式对命中 `deny` 规则返回明确拒绝 |
| **FR-008** | `local-service` | 离线规则校验与跨平台模拟测试 | P0 | Phase 2 | `ai-guard rule validate` 与 `ai-guard rule test` 纯内存重放判定（支持模拟 Windows 与 WSL2 上下文），绝不真实执行被测命令 |
| **FR-009** | `backup` | 宿主机与 WSL2 配置及策略快照备份 | P0 | Phase 3 | 修改宿主机或 WSL2 任何配置前自动生成带 SHA-256 清单的备份快照，支持完整性校验与一键原子回滚 |
| **FR-010** | `local-service` | 双环境 Hook 事务安装、探针分发与无损卸载 | P0 | Phase 3 | 支持 `--target <host\|wsl2:distro>` 与 `--dry-run` 预览 Diff；对宿主机挂载 `ai-guard.exe`，对 WSL2 自动分发挂载 `ai-guard-linux` 并同步策略镜像；卸载仅移除本产品条目并恢复原状 |
| **FR-011** | `local-service` | 双环境受管启动与 Daemon 刷新检查 | P0 | Phase 3 | 启动前强制校验目标环境 Hook 注册、Runner 可执行、策略同步一致及 `app-server-daemon` 状态；不合规时拒绝代启动并提示修复 |
| **FR-012** | `storage` | 宿主机统一 SQLite 审计库与 WSL2 增量归并 | P0 | Phase 4 | 宿主机 `%LOCALAPPDATA%\ai-guard\events.db` 作为全局统一审计库，自动增量拉取归并 WSL2 本地缓冲事件；双端 Hook 均开启 WAL + 15ms 超时无锁 fallback，绝不因写库阻塞改变或拖慢 Deny 裁决 |
| **FR-013** | `storage` | 敏感信息自动脱敏器 | P0 | Phase 1 / 4 | 自动剥离命令与参数中的 Token、API Key、私钥、密码与敏感路径内容，支持按环境（宿主机 / WSL2）分页过滤与脱敏导出 |
| **FR-014** | `local-service` | 分环境四态防护状态诊断（`status`/`doctor`） | P0 | Phase 3 / 4 | 对宿主机 Codex 与各 WSL2 Codex 独立计算并汇总输出四态，绝不以“配置文件存在”冒充 `protected_verified` |
| **FR-015** | `local-service` | 双环境隔离端到端自检向导 | P0 | Phase 4 | `ai-guard self-test codex --target <host\|wsl2:distro> --isolated` 在目标环境的临时隔离目录执行真实 Allow/Deny 验证并持久化自检证据 |
| **FR-016** | `session` / `backup` | 宿主机与 WSL2 双环境 Session 统一只读索引与备份 | P1 | Phase 4B | 在宿主机统一只读解析并展示宿主机 `C:\Users\<User>\.codex`（750MB+ 会话库）与 WSL2 `~/.codex` 会话列表与详情；支持跨环境一键创建带 SHA-256 校验的会话备份 |
| **FR-017** | `desktop` | 宿主机双目标调度器（`TargetManager`） | P0 | Phase 5 | 宿主机 Tauri 后端直连管理宿主机目标（`WindowsHost`），并通过受控 `argv` 白名单 `wsl.exe --distribution <distro> --exec` 桥接管理 WSL2 目标（`Wsl2Distro`），防命令注入 |
| **FR-018** | `desktop` | 全中文宿主机主控桌面界面（六大页面） | P0 | Phase 5 | 交付安全概览（双环境汇总）、Agent 与环境管理（宿主机 + WSL2）、安全策略、统一风险事件、防护诊断/安装/Session 备份、设置与隐私六大中文页面 |
| **FR-019** | `desktop` | 独立运行保障与子环境断连诚实展示 | P0 | Phase 5 | 未开启 WSL2 时宿主机防护与 UI 100% 独立正常工作；当某 WSL2 发行版未启动或失联时，仅该 WSL2 目标卡片显示“状态未知”，绝不沿用旧绿灯缓存 |
| **FR-020** | 全局文档与合规 | 保护边界声明与开源发布门禁 | P0 | Phase 5 | 明确展示支持范围与已知盲区（如未覆盖 Hosted Tools、同权限用户绕过限制），通过全部安全与许可证检查 |
| **FR-AGY-001** | `agent-adapters` | Antigravity (AGY) & `agy` CLI 目标与工作区自动发现 | P0 | Phase 5.5 | 自动发现全局配置（Linux/WSL2 `~/.gemini/config/`，Windows `%USERPROFILE%\.gemini\config\`）与工作区级（`<workspace>/.agents/`）配置，支持探测 AGY 桌面版、IDE 与 `agy` CLI |
| **FR-AGY-002** | `agent-adapters` / `security` | AGY 原生 ProtoJSON `PreToolUse` Hook 协议适配与拦截 | P0 | Phase 5.5 | 解析 stdin camelCase ProtoJSON，将 `run_command`、`write_file`、`edit_file`、`call_mcp_tool` 转换为通用 `ActionEvent`；Fail-Closed 默认阻断，输出标准 `{"decision":"allow"\|"deny"\|"ask"}` JSON |
| **FR-AGY-003** | `session` / `backup` | AGY 转录流水（`transcript.jsonl`）与工件只读索引与备份 | P1 | Phase 5.5 | 严格只读解析 AGY 转录流、步骤序号、模型与对话内容，扫描 `brain/<conv_id>/` 工件，支持一键创建 SHA-256 校验的快照备份 |
| **FR-AGY-004** | `desktop` | 宿主机多 Agent（Codex + AGY）协同管控看板与 Hook 事务安装 | P0 | Phase 5.5 | 宿主机主控界面升级支持 Codex 与 AGY 并行卡片展示、四态防护诊断、一键增量注册/安全卸载 `hooks.json`、事件来源过滤（Codex/AGY）与一键自检 |

---

## 4. 分阶段开发 PRD 详细规格（Phase 0 ～ Phase 6）

```mermaid
flowchart LR
    P0["Phase 0 (M0)\n宿主机与 WSL2 双环境基线\n及 Codex Hook 协议实测"] --> P1["Phase 1 (M1+M2)\n跨平台 Rust 核心与双环境\n真实执行前拦截 PoC (生死线)"]
    P1 --> P2["Phase 2 (M3)\nTOML 策略引擎、跨平台\n(Win+Linux) 高危规则与测试"]
    P2 --> P3["Phase 3 (M4)\nbackup 事务备份、双环境安装器\n策略镜像同步与受管启动"]
    P3 --> P4["Phase 4 (M5 + M1 迁移)\n宿主机统一审计库、WSL2 归并\n与双环境 Session 只读保护"]
    P4 --> P5["Phase 5 (M6+M7)\nWindows 宿主机 Tauri 2 主控端\n双目标调度与 V0.1 发布"]
    P5 --> P55["Phase 5.5\nAntigravity (AGY) & agy CLI\n全链路原生 Hook 管控与治理"]
    P55 --> P6["Phase 6 (V0.2+ / M8+M9)\n多 Agent 扩展、OS 沙箱\n与企业版控制平面"]
```

---

### Phase 0（对应 M0）：宿主机与 WSL2 双环境基线审计及 Codex Hook 协议实测 PRD

#### 4.0.1 阶段目标
在不修改用户真实宿主机 `C:\Users\<User>\.codex` 与 WSL2 `~/.codex` 配置的前提下，补齐跨平台 Rust 工具链，完成对本机**宿主机 Codex（桌面版 `0.166.0+`）**与 **WSL2 `codex-cli`（`0.160.1+`）** 的 Hook 触发机制、输入输出 JSON 结构、信任机制及 `app-server-daemon` 交互行为的实测取证。

#### 4.0.2 功能与研发任务说明
1. **P0-T1：双环境基线盘点与跨平台 Rust 工具链配置**
   - 盘点并记录宿主机 Windows 环境（`C:\Users\kui.li\.codex`、`codex.exe`、`codex-command-runner`）与 WSL2 Ubuntu 环境（内核版本、Landlock 支持、`codex-cli 0.160.1`）的真实路径与状态。
   - 安装 Rust stable 工具链（`rustup`、`cargo`、`rustc`、`clippy`、`rustfmt`），配置 Linux（`x86_64-unknown-linux-gnu`）与 Windows（`x86_64-pc-windows-msvc` / `x86_64-pc-windows-gnu`）编译目标，在工程根目录创建 `rust-toolchain.toml`。
2. **P0-T2：宿主机与 WSL2 Codex Hook 协议隔离探针实测**
   - 分别在隔离的临时 `CODEX_HOME` 下实测并记录宿主机 Codex 与 WSL2 Codex 的核心协议事实：
     - 配置文件加载位置与格式（`config.toml` / `hooks.json` 在 Windows 与 Linux 下的精确字段结构与路径引号转义要求）。
     - `PreToolUse` 事件触发时传入 `stdin` 的真实 JSON 字段（`session_id`、`turn_id`、`cwd`、`hook_event_name`、`tool_name`、`tool_input`、`tool_use_id`）。
     - 不同环境工具调用对应的 `tool_name` 精确取值（如 `Bash`、`unified_exec`、`write_stdin`、Windows PowerShell/CMD、`apply_patch`、MCP 工具）。
     - 返回 `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}` 时 Codex 的实际拦截表现。
     - 当后台 `app-server-daemon` 或宿主机 Codex 桌面版常驻时，修改 Hook 配置后的生效与刷新方式。
3. **P0-T3：安全边界 ADR 归档**
   - 在 `docs/decisions/` 下归档核心架构决策记录（`ADR-0001` ～ `ADR-0003`）。

#### 4.0.3 交付产物清单
- `rust-toolchain.toml`
- `docs/BASELINE.md`（含宿主机与 WSL2 双环境盘点数据）
- `docs/CODEX_HOOK_CONTRACT.md`
- `docs/COMPATIBILITY.md`
- `tests/fixtures/codex/*.json`（含 Windows 与 WSL2 脱敏协议样本）

#### 4.0.4 阶段验收门禁（Phase 0 Gate）
- [ ] `rustc --version` 与 `cargo --version` 正常可用。
- [ ] `docs/CODEX_HOOK_CONTRACT.md` 中包含基于本机实测捕获的脱敏 JSON 结构，明确宿主机与 WSL2 下的配置与命令行差异。
- [ ] 确认用户真实宿主机 `C:\Users\kui.li\.codex` 与 WSL2 `/home/ai-li/.codex` 目录在实测前后无任何新增或修改。

---

### Phase 1（对应 M1 + M2）：跨平台 Rust 安全内核与真实执行前拦截 PoC PRD（产品生死线）

#### 4.1.1 阶段目标
搭建跨平台 Rust Workspace 核心骨架，使同一套代码可编译出宿主机 `ai-guard.exe` 与 WSL2 `ai-guard-linux`，实现 `hook codex pre-tool-use` 热路径，并在隔离环境跑通真实 Codex 的执行前拒绝（Deny）与正常放行（Allow）端到端测试。

#### 4.1.2 功能与研发任务说明
1. **P1-T1：跨平台 Cargo Workspace 与最小 CLI 构建（对应 M1-01）**
   - 建立根 `Cargo.toml`，包含成员：`apps/local-service`、`packages/agent-adapters`、`packages/security`、`packages/backup`、`packages/storage`、`packages/session`。
   - 实现基础 CLI 框架（基于 `clap`）：支持 `ai-guard --version`、`ai-guard doctor [--target <all|host|wsl2:distro>] --json`、`ai-guard hook codex pre-tool-use`。
2. **P1-T2：多目标安全领域模型与脱敏错误体系（对应 M1-02、M1-04）**
   - 在 `packages/security` 与 `packages/agent-adapters` 定义跨平台领域结构：
     - `EnvironmentKind`（`WindowsHost`, `Wsl2Distro { distro_name }`）
     - `ClientSurface`（`CodexDesktopApp`, `CodexCli`, `CodexAppServerDaemon`）
     - `ActionKind`（`Shell`, `FilePatch`, `McpTool`, `LocalTool`, `Unknown`）
     - `Enforcement`（`Allow`, `Deny`, `Observe`, `Unsupported`）
     - `ActionEvent` 与 `Decision`（含 `target_id`、`matched_rule_ids`、`reason_code`、`display_message`、`policy_revision`、`coverage`）
   - 实现基础脱敏器与统一错误码：确保任何异常日志或错误输出绝不打印原始 `raw_tool_args` 中的秘密。
3. **P1-T3：`CodexHookAdapter` 协议解析与 Fail-Closed 输出（对应 M1-03）**
   - 在 `packages/agent-adapters` 实现 `stdin` 流式限长读取（默认上限 1 MiB，强制 UTF-8 解码兼容 Windows 代码页差异）。
   - 当输入为空、超长、非合法 UTF-8、JSON 畸形或缺少关键字段时，不发生 `panic`，直接生成显式 `Deny` 决策并输出合法的 Codex `PreToolUse` 拒绝 JSON。
   - 严格保证 `stdout` 只输出单行协议 JSON，调试/错误日志只写 `stderr`。
4. **P1-T4：真实 Codex 执行前拦截 E2E 验证（对应 M2-01 ～ M2-04）**
   - 内置确定性规则 `TEST-DENY-001`（匹配 `AI_GUARD_BLOCK_ME`）。
   - 在隔离临时目录编写并执行真实 Codex E2E 测试：
     - **用例 1（真实拒绝）**：触发含 `AI_GUARD_BLOCK_ME` 并尝试创建 `sentinel.txt` 的命令 → 验证 Hook 返回 Deny 且 **`sentinel.txt` 不存在**。
     - **用例 2（正常放行）**：触发正常查看目录/状态命令 → 验证命令正常执行。
     - **用例 3（故障与绕过取证）**：测试 Hook 二进制不存在、超时、返回非 JSON 时的 Codex 实际表现，如实记入 `docs/COMPATIBILITY.md`。

#### 4.1.3 阶段验收门禁（Phase 1 Gate — 不可跳过）
- [ ] `cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace` 全部通过，且核心包在 Windows 与 Linux 目标下均可编译。
- [ ] 至少 15 组畸形/边界 JSON 输入单测通过，0 panic。
- [ ] 伪造密钥 `SECRET_TEST_XYZ` 在 stdout/stderr 中 0 泄露。
- [ ] **核心生死线**：真实 Codex 隔离 E2E 测试证明 `sentinel.txt` 未被创建，测试日志与证据归档于 `docs/evidence/m2-e2e-report.md`。

---

### Phase 2（对应 M3）：TOML 策略引擎、跨平台（Win+Linux）高危规则包与离线测试 PRD

#### 4.2.1 阶段目标
实现完整的 TOML 策略加载、静态校验、优先级裁决与快照回退机制，交付同时覆盖 Windows（PowerShell/CMD）与 WSL2（Bash/sh）的默认高置信度安全规则集，并提供不执行命令的离线模拟测试工具。

#### 4.2.2 功能与研发任务说明
1. **P2-T1：TOML 策略 Schema、编译校验与可信快照（对应 M3-01）**
   - 宿主机主策略位于 `%LOCALAPPDATA%\ai-guard\policy.toml`，WSL2 镜像策略位于 `~/.config/ai-guard/policy.toml`（权限 `0600`）。
   - 支持字段：`schema_version`、`revision`、`mode`（`observe` | `protect`）、`[[rules]]`（`id`, `enabled`, `priority`, `name`, `agent`, `tool`, `os_scope`, `match_kind`, `match_value`, `effect`, `reason_code`）。
   - **防降级保护**：当策略文件语法错误、版本不兼容或包含未知 `match_kind` 时，拒绝激活损坏配置，优先回退至最近一次验证通过的策略快照；若无快照可用则在 Hook 侧显式返回 Deny 并附带 `AG-POLICY-001` 告警。
2. **P2-T2：V0.1 跨平台高危规则检测器（对应 M3-02、M3-03）**
   - 所有规则检测器采用受控 Rust 枚举与确定性词法/路径分析实现，设置输入长度与正则计算上限（防 ReDoS）：
     - `SHELL-DESTRUCTIVE-RM`：同时拦截 Linux 递归删除（`rm -rf /`、`rm -rf ~`、`rm -rf ..`）与 Windows PowerShell/CMD 递归删除（`Remove-Item -Recurse -Force`、`ri -r -fo`、`rmdir /s /q`、`del /f /s /q`）。
     - `SHELL-DISK-WIPE`：同时拦截 Linux（`mkfs`、`fdisk`、`dd of=/dev/...`）与 Windows（`Format-Volume`、`Clear-Disk`、`diskpart`）磁盘破坏命令。
     - `SHELL-PIPE-EXEC`：同时拦截 Linux（`curl/wget ... | sh/bash/python/node`、`base64 -d | sh`）与 Windows（`Invoke-WebRequest (iwr) / Invoke-RestMethod (irm) ... | Invoke-Expression (iex)`、`powershell -EncodedCommand (-enc)`、`certutil -urlcache`）下载/解码即执行模式。
     - `PATH-SENSITIVE-CRED`：对 Shell 命令参数及 `apply_patch` 补丁目标路径做 POSIX 与 Windows 双向规范化解析（Windows 路径大小写不敏感），拦截读取或修改 `.ssh/`、`.aws/`、`.gnupg/`、`.codex/auth.json`、`.env`、`*.pem`、`*.key` 及跨越工作区根目录的 `../` 或 `..\` 路径穿越。
     - `GIT-DANGEROUS-OP`：识别 `git reset --hard`、`git clean -fdx`、`git push --force` / `-f`。
3. **P2-T3：离线规则校验与模拟测试命令（对应 M3-04）**
   - 实现 `ai-guard rule validate --path <policy.toml> --json`。
   - 实现 `ai-guard rule test --input <event.json> [--policy <policy.toml>] --json`：**纯内存评估，严禁真实执行命令**，返回命中规则列表、最终决策、中文原因说明与耗时。

#### 4.2.3 阶段验收门禁（Phase 2 Gate）
- [ ] 跨平台正向/反向回归测试集：不少于 **30 个高危命令/路径正例（含 Linux Bash 与 Windows PowerShell/CMD 用例，100% 命中 Deny）** + **40 个日常合法开发命令反例（100% Allow，0 误报）**。
- [ ] 策略文件损坏、非法字段注入、POSIX 与 Windows 路径穿越（`a/../../etc/passwd` 与 `a\..\..\Windows\System32`）专项单测全部通过。
- [ ] 单次离线规则评估 P95 耗时 ≤ 10ms。

---

### Phase 3（对应 M4）：`packages/backup` 事务备份、双环境安装器、策略镜像同步与受管启动 PRD

#### 4.3.1 阶段目标
打通 `packages/backup` 的跨平台文件备份与 SHA-256 完整性校验能力，实现宿主机主控对“宿主机 `.codex`”与“WSL2 `.codex`”的无损 Hook 安装/卸载、WSL2 探针自动分发与策略镜像同步，以及 `ai-guard run codex` 受管启动器。

#### 4.3.2 功能与研发任务说明
1. **P3-T1：`packages/backup` 跨平台快照备份、校验与原子恢复底座**
   - 实现通用的备份管理器（同时服务于宿主机/WSL2 配置文件事务备份与后续的 Session 备份）：
     - 创建备份时生成 `manifest.json`（记录目标环境 `target_id`、源文件路径、文件大小、SHA-256 哈希、备份时间戳、关联操作类型）。
     - 恢复前强制重新计算备份文件 SHA-256 并与 Manifest 比对；校验失败立即拒绝恢复并报错。
     - 采用“同目录临时文件写入 → `fsync` → 原子替换（POSIX `rename` / Windows `MoveFileExW`）”确保落盘无半写入损坏。
2. **P3-T2：双环境配置发现、安装预览（`--dry-run`）、探针分发与增量合并安装（对应 M4-01、M4-02）**
   - 实现 `ai-guard install codex --target <host|wsl2:distro> --scope user|project --dry-run [--json]`：扫描指定目标环境的配置，计算并展示 unified diff 及将影响的 Hook 事件列表，不修改磁盘。
   - 实现正式安装 `ai-guard install codex --target <host|wsl2:distro> --scope user|project`：
     - **针对 `host`（Windows 宿主机目标）**：调用 `packages/backup` 备份 `C:\Users\<User>\.codex\config.toml` / `hooks.json`，增量注入指向宿主机 `ai-guard.exe` 绝对路径的 Hook 条目。
     - **针对 `wsl2:<distro>`（WSL2 子系统目标）**：宿主机主控自动将同版本 `ai-guard-linux` 二进制部署至该 WSL2 的 `~/.local/bin/ai-guard-linux`，将宿主机主策略 `policy.toml` 镜像同步至 WSL2 `~/.config/ai-guard/policy.toml`，并在 WSL2 内完成 `~/.codex` 配置备份与 Hook 增量合并。
     - **100% 保留用户已有的其他配置项与第三方 Hook**。
   - 实现安全卸载 `ai-guard uninstall codex --target <host|wsl2:distro> --scope user|project [--dry-run]`：
     - 仅移除 AI卫士管理的 Hook 条目；若检测到外部冲突改动，停止自动覆盖并提供从 `packages/backup` 快照回滚的指引。
3. **P3-T3：受管启动 `ai-guard run codex -- [args...]` 与信任/Daemon 诊断（对应 M4-03、M4-04）**
   - 启动前依次执行 Preflight 检查：
     1. 目标环境 `codex` 可执行文件是否存在；
     2. AI卫士 Hook 是否已注册且指向当前有效的 `ai-guard.exe` 或 `ai-guard-linux` 绝对路径；
     3. 本地策略文件（及 WSL2 策略镜像哈希）是否存在且一致；
     4. Hook 信任状态与 `app-server-daemon` 加载状态是否有效。
   - 若 Preflight 失败：拒绝代启动并输出中文修复指引；若通过：使用独立 `argv` 直接拉起目标 `codex`。

#### 4.3.3 阶段验收门禁（Phase 3 Gate）
- [ ] 双环境闭环测试：在模拟的宿主机 `.codex` 与 WSL2 `.codex` 目录（均含第三方自定义 Hook）执行 `install -> 验证第三方 Hook 完好 -> 验证策略哈希一致 -> uninstall -> 验证文件哈希与安装前完全一致` 全部通过。
- [ ] 故障注入：模拟写入中断、备份文件篡改（SHA-256 不匹配拒绝恢复）、Hook 二进制丢失时 `ai-guard run codex` 成功阻断启动。

---

### Phase 4（对应 M5 + M1 迁移汇入）：宿主机统一 SQLite 审计库、WSL2 事件归并、四态自检与双环境 Session 保护 PRD

#### 4.4.1 阶段目标
完成 `packages/storage` 的宿主机统一 SQLite 审计库与 WSL2 缓冲增量同步机制，实现支持双环境的隔离自检（`self-test`）与四态状态汇总（`status`），并在安全主线验收后将原 M1 阶段的 Codex Session 只读管理能力汇入 `packages/session`（同时纳管宿主机与 WSL2 会话）。

#### 4.4.2 功能与研发任务说明
1. **P4-T1：`packages/storage` 宿主机主审计库、WSL2 缓冲同步与 15ms 无锁 Fallback（对应 M5-01）**
   - 宿主机主库位于 `%LOCALAPPDATA%\ai-guard\events.db`，WSL2 本地缓冲库位于 `~/.local/share/ai-guard/events.db`，均管理 5 张核心表：`schema_migrations`、`security_events`（含 `target_id` 与 `host_kind` 字段）、`policy_revisions`、`integration_state`、`self_test_runs`。
   - 实现 Hook 审计快速写入：开启 WAL，超时上限 **15ms**；当遇到数据库锁冲突或磁盘异常时，自动降级追加至无锁 `events-fallback.jsonl`，确保 Hook 进程绝不因审计失败而超时或改变 `Deny` 决策。
   - 实现跨环境增量归并：宿主机主控通过 `wsl.exe --distribution <distro> --exec ~/.local/bin/ai-guard-linux events pull --since <cursor> --json` 将 WSL2 新增的拦截事件拉取并幂等合入宿主机主库 `events.db`。
2. **P4-T2：统一脱敏审计查询、按环境分页过滤与导出（对应 M5-02）**
   - 实现 `ai-guard events list [--target <all|host|wsl2:distro>] [--since <duration>] [--decision <deny|allow|observe>] [--limit <N>] --json`。
   - 实现 `ai-guard events export --output <path> --redacted [--format json|csv]`。
   - 对所有落盘与导出的摘要字段执行二次脱敏校验。
3. **P4-T3：双环境四态防护状态汇总与一键隔离自检（对应 M5-03、M5-04）**
   - 实现 `ai-guard self-test codex [--target <all|host|wsl2:distro>] --isolated --json`：在对应环境的临时沙箱目录自动运行 Allow 与 Deny 自检用例，校验副作用文件未生成，并将结果写入 `self_test_runs`。
   - 实现 `ai-guard status [--target <all|host|wsl2:distro>] --json`：针对宿主机目标与各 WSL2 目标分别返回 `protected_verified` / `partially_protected` / `unprotected` / `unknown` 及各自的已知盲区列表（`limitations`）。
4. **P4-T4（Phase 4B 扩展包）：M1 Codex Session 宿主机与 WSL2 统一只读索引与安全备份（`packages/session`）**
   - 同时对接**宿主机 `C:\Users\<User>\.codex\`**（含 750MB+ `thread_history_1.sqlite` 与 `session_index.jsonl`）与 **WSL2 `~/.codex/`** 下的会话数据（**严格只读打开，如 SQLite `SQLITE_OPEN_READ_ONLY`**）。
   - 提供 CLI 子命令：`ai-guard session list [--target <all|host|wsl2:distro>] --json`、`ai-guard session show <id> --json`、`ai-guard session backup <id> --json`（调用 `packages/backup` 统一归档至宿主机备份仓并进行 SHA-256 校验）。

#### 4.4.3 阶段验收门禁（Phase 4 Gate）
- [ ] 隐私红线测试：注入含 `sk-proj-xxxx`、`ghp_xxxx`、`-----BEGIN OPENSSH PRIVATE KEY-----` 的模拟工具调用，验证宿主机与 WSL2 的 `events.db`、日志文件与导出文件中秘钥原文 **0 残留**。
- [ ] 跨环境事件同步测试：在 WSL2 内触发一次模拟拦截事件，验证宿主机主控执行 `events list --target all` 能准确拉取并展示该事件（带 `wsl2:Ubuntu` 标签）。
- [ ] 双环境 Session 只读保护测试：对宿主机与 WSL2 会话目录执行 `session list/show/backup` 前后，原会话文件的哈希与 `mtime` 保持 100% 不变。

---

### Phase 5（对应 M6 + M7）：Windows 宿主机 Tauri 2 中文主控桌面端、双环境联调与 V0.1 个人版发布 PRD

#### 4.5.1 阶段目标
交付运行于 Windows 宿主机的 Tauri 2 + React + TypeScript 全中文主控桌面程序（`AI卫士.exe`），在宿主机上统一管理 **宿主机本机 Codex（`C:\Users\<User>\.codex`）** 与 **WSL2 子系统 Codex（`/home/<user>/.codex`）**，完成全部交互闭环并通过 V0.1 开源发布门禁。

#### 4.5.2 功能与研发任务说明
1. **P5-T1：宿主机双目标调度器（`TargetManager`）与 WSL2 受限桥接层（对应 M6-01、M6-02）**
   - 在 `apps/desktop/src-tauri` 与宿主机核心服务中实现统一的目标调度器：
     - **对宿主机目标（`WindowsHost`）**：直接调用宿主机进程内服务或同目录 `ai-guard.exe` 管理 `C:\Users\<User>\.codex`，并在宿主机挂载 `ai-guard.exe hook`。
     - **对 WSL2 目标（`Wsl2Distro`）**：自动分发更新 WSL2 内的 `~/.local/bin/ai-guard-linux`，将宿主机主策略 `policy.toml` 同步至 WSL2，并通过独立 `argv` 调用 `wsl.exe --distribution <distro> --exec ~/.local/bin/ai-guard-linux <subcommand> --json` 执行安装、自检与增量审计拉取。
     - 严禁拼装 Shell 字符串，设置单次命令超时与输出体积上限。
2. **P5-T2：全中文桌面端核心页面交付（对应 M6-03、M6-04）**
   - **1. 安全概览（`/overview`）**：汇总展示宿主机 Codex 与 WSL2 Codex 的各自四态防护状态卡片、全局/分环境最近 24h 拦截统计、一键全环境自检。
   - **2. Agent 与环境管理（`/agents`）**：清晰列出已发现的所有受管环境（如 `[宿主机 Windows] Codex Desktop / CLI` 与 `[WSL2: Ubuntu] Codex CLI`），分别展示版本、路径、能力覆盖矩阵及一键启用/停用保护。
   - **3. 安全策略（`/policies`）**：在宿主机集中编辑观察/保护模式与规则列表（修改后自动同步至已启用的 WSL2 环境）、内置“跨平台规则沙盒测试器”（支持测试 Bash 与 PowerShell/CMD 命令）、策略历史版本回滚。
   - **4. 风险事件（`/events`）**：统一时间线展示宿主机与 WSL2 汇总的 Allow/Deny/Observe 记录（带环境来源标签过滤）、查看中文拦截原因与脱敏摘要、一键导出脱敏报告。
   - **5. 防护诊断与安装恢复（`/diagnostics` & `/integrations`）**：针对宿主机或 WSL2 目标可视化执行 `install --dry-run` 查看配置文件 Diff、二次确认安装/卸载、`/hooks` 信任引导、配置备份恢复，以及跨环境（宿主机 + WSL2）Session 只读浏览与一键备份。
   - **6. 设置与隐私（`/settings`）**：宿主机主数据目录与 WSL2 缓冲路径说明、审计保留周期设置、产品安全能力边界与免责声明。
3. **P5-T3：V0.1 发布质量与开源合规门禁（对应 M7-01 ～ M7-04）**
   - 完成宿主机 + WSL2 双环境安装/自检/卸载测试、CI 脚本、依赖许可证与漏洞扫描、产物 SHA-256 校验清单及 `SECURITY.md` / `LIMITATIONS.md` 文档定稿。

#### 4.5.3 阶段验收门禁（Phase 5 / V0.1-GA Gate）
- [ ] **宿主机独立运行验证**：在未启动 WSL2 的情况下，宿主机 `AI卫士.exe` 正常打开，且对宿主机 Codex（`C:\Users\<User>\.codex`）的策略管理、Hook 拦截、审计查询与 Session 浏览备份 100% 正常工作。
- [ ] **WSL2 跨边界纳管验证**：启动 WSL2 后，宿主机 `AI卫士.exe` 可一键下发策略并挂载 WSL2 Hook，WSL2 内 Codex 触发拒绝事件后可在宿主机桌面端“风险事件页”实时刷新查看到。
- [ ] **命令注入与断连诚实度测试**：在 UI 输入框注入恶意字符无命令执行；关闭 WSL2 后，WSL2 目标卡片立即显示“状态未知”，不影响宿主机目标卡片的正常状态展示。
- [ ] PRD 定义的 `AT-01` ～ `AT-12` 验收用例与 `SEC-E2E-001` ～ `SEC-E2E-012` 全部通过并附真实记录。

---

### Phase 5.5：Antigravity（AGY）与 agy CLI 全链路原生 Hook 管控与治理 PRD

#### 4.5.5.1 阶段目标
在保持现有 Codex 管控能力 100% 稳定运行的前提下，基于 Antigravity 原生 Lifecycle Hook 规范（`hooks.json`），实现对 **Antigravity 2.0（桌面版）**、**Antigravity IDE** 及 **`agy` CLI** 的原生接入与双环境统一治理。实现执行前工具调用（`run_command`、`write_file`、`edit_file`、`call_mcp_tool`）的强拦截、转录文件与工件的只读索引与安全备份，以及宿主机桌面端多 Agent（Codex + AGY）并列治理看板。

#### 4.5.5.2 功能与研发任务说明
1. **P5.5-T1：`packages/agent-adapters` 之 `AgyHookAdapter` 实现与 ProtoJSON 映射契约**
   - 实现符合 Antigravity 官方 Draft-07 ProtoJSON 规范的流式反序列化（限制 2 MiB，兼容 camelCase）：
     - 解析 `conversationId`、`workspacePaths`、`transcriptPath`、`artifactDirectoryPath`、`stepIdx` 与 `toolCall`。
     - 将工具调用归一化映射为通用 `ActionEvent`：
       - `toolCall.name == "run_command"` 映射为 `ActionKind::ExecuteShellCommand`，提取 `CommandLine`；
       - `toolCall.name == "write_file"` 或 `"edit_file"` 映射为 `ActionKind::WriteFile` / `FilePatch`，提取 `Path` 与 `Content`；
       - `toolCall.name == "call_mcp_tool"` 映射为 `ActionKind::InvokeMcpTool`，提取 `ServerName` 与参数。
   - 裁决输出协议适配：将策略引擎结果序列化为 `{"decision": "allow" | "deny" | "ask", "reason": "..."}`。
   - **Fail-Closed 异常保护**：输入为空、超长、JSON 语法错误或引擎解析故障时，严格输出 `{"decision": "deny", "reason": "AI卫士防护保底阻断：..."}`。
2. **P5.5-T2：`apps/local-service` Hook 入口与事务安装器扩展**
   - 增加 CLI 极速执行入口：`ai-guard hook agy pre-tool-use`（同时在 Windows `ai-guard.exe` 与 Linux `ai-guard-linux` 可用）。
   - 实现 AGY Hook 事务安装与卸载：
     - 支持 `ai-guard install agy [--scope user|project] [--dry-run]` 与 `ai-guard uninstall agy`；
     - 自动定位全局 `~/.gemini/config/hooks.json` 或项目级 `<workspace>/.agents/hooks.json`；
     - 调用 `packages/backup` 自动生成带 SHA-256 的快照备份；
     - 增量合并注入 `"ai-guard"` 命名空间块，不影响用户已有的其他 hook 插件；
     - 卸载时精准移除 `"ai-guard"` 命名空间并原子回滚。
3. **P5.5-T3：`packages/session` 之 AGY 转录与工件只读索引与完整性备份**
   - 支持跨平台探测并只读解析 AGY 转录流（`transcript.jsonl`），提取会话 ID、步骤数、时间戳与脱敏对话内容；
   - 扫描对应会话的 `brain/<conversation-id>/` 工件目录（工件文件、草稿、临时数据）；
   - 在 `packages/backup` 建立 AGY 会话快照结构，支持将转录与工件打包为带 SHA-256 校验的快照归档并支持完整性验签。
4. **P5.5-T4：`apps/desktop` 多 Agent 统一管控看板与交互升级**
   - 桌面主控端升级为双 Agent 并行架构：在安全概览与 Agent 管理页面独立呈现 **Codex** 与 **Antigravity (AGY)** 两个管理卡片；
   - 分别展示 Codex 与 AGY 的运行版本、配置路径、当前挂载状态与四态防护诊断（`protected_verified` / `unprotected` 等）；
   - 支持对 AGY 单独执行一键启用防护（增量写入 `hooks.json`）、一键停用、差异预览与一键离线测试；
   - 统一风险事件流支持按 Agent 来源（Codex / AGY）进行筛选与脱敏详情查看；
   - 对话与备份工作区支持无缝切换浏览 Codex 与 AGY 会话列表，支持统一的备份与 SHA-256 验证。

#### 4.5.5.3 交付产物清单
- `docs/AGY_HOOK_CONTRACT.md`（权威 Wire Protocol 契约）
- `packages/agent-adapters/src/agy_adapter.rs`
- `tests/fixtures/agy/*.json`（正常放行、高危删除、敏感凭据越界、畸形输入样例）
- 单元测试与 E2E 验证脚本：`tests/e2e_agy_pre_tool_use.rs`

#### 4.5.5.4 阶段验收门禁（Phase 5.5 Gate）
- [ ] **协议兼容测试**：涵盖 `run_command`、`write_file`、`edit_file`、`call_mcp_tool` 四类核心工具调用，正向合法输入 100% 返回 `decision: "allow"`，高危命令（如 `rm -rf /`、读取 `.ssh/id_rsa`）100% 返回 `decision: "deny"`。
- [ ] **Fail-Closed 异常防护测试**：输入畸形 JSON、截断输入、超大体积 JSON（> 2 MiB），系统 100% 安全返回 `deny`，0 panic，0 异常放行。
- [ ] **配置零破坏安装与卸载测试**：在包含用户既有 Hook 的 `hooks.json` 模拟环境中执行 `install` 与 `uninstall`，非 AI卫士配置项 100% 保持完好，卸载后完全恢复原样。
- [ ] **桌面端与只读备份闭环**：在桌面 UI 中成功显示 AGY 状态卡片，能列出 AGY 会话并成功完成带 SHA-256 校验的会话备份与恢复校验。

---

### Phase 6（对应 M8 + M9，V0.2+ 演进）：多 Agent 适配、OS 沙箱与企业版控制平面

- **Phase 6A（V0.2 个人版增强）**：
  - 接入 **Claude Code** 与 **OpenCode**（同样支持宿主机与 WSL2 双环境探测与就地 Hook 拦截）。
  - 完整版跨 Agent Session 全文搜索、恢复冲突预览与安全恢复。
  - 引入 **nono / Linux Landlock**（WSL2 侧）及 **Windows Job Object / 受限令牌**（宿主机侧）沙箱 PoC，对文件读写白名单与网络外传提供 OS 级强制隔离验证。
- **Phase 6B（V1.0 企业版，独立私有仓库 `ai-guard-enterprise`）**：
  - 基于 Rust Axum + PostgreSQL 实现设备注册与 mTLS 身份认证、Ed25519 签名策略强制下发（宿主机主控验签后再分发至本机与 WSL2）、OIDC/RBAC 权限控制与多租户脱敏审计汇聚中心。
