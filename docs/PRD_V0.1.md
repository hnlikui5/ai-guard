# AI卫士（AI Guard）产品需求文档与分阶段研发 PRD（优化定稿版）

- **文档编号**：`AG-PRD-V0.1`
- **版本**：`V0.1-Optimized`（基于初始方案包评估与本机 `codex-cli 0.160.1` 实况优化）
- **日期**：2026-11-07
- **文档状态**：已确认基线（研发与阶段验收唯一依据）
- **代码仓库**：`https://github.com/hnlikui5/ai-guard.git`
- **首发目标环境**：Windows 宿主机（Tauri 2 桌面管理端）+ WSL2 Ubuntu（Rust 安全内核 + Codex CLI `0.160.1+`）
- **主力技术栈**：Rust（Workspace 核心与 Hook Runner）+ SQLite（WAL 本地持久化）+ Tauri 2 / React / TypeScript（中文桌面端）
- **开源许可证**：Apache License 2.0（个人版）

---

## 1. 产品综述与优化基线说明

### 1.1 一句话产品定义

**AI卫士（AI Guard）** 是一款面向 AI 编程 Agent 的本地安全防护与运行治理平台，在 Agent 真实执行节点（WSL2）对工具调用进行执行前风险判定、阻断高危操作、提供可验证的防护状态诊断与脱敏审计，并在安全底座稳定后提供会话（Session）只读索引与安全备份恢复能力。

### 1.2 相较初始方案包的 6 项关键优化（已纳入本 PRD）

1. **对齐本机 `codex-cli 0.160.1` 真实运行架构**：
   - 实测本机 `codex-cli 0.160.1` 已默认启用 `hooks (stable)`、`daemon_auto_start (stable)`、`unified_exec (stable)`，且 `~/.codex/` 下存在活跃的 `app-server-daemon` 及多个 SQLite 状态库（`state_5.sqlite`、`thread_history_1.sqlite`、`logs_2.sqlite`）。
   - 本 PRD 将 **Hook 配置写入后的 Daemon 感知/刷新验证** 以及 **`Bash` / `unified_exec` / `write_stdin` / `apply_patch` / `MCP` 真实工具名映射** 纳入 Phase 0/1 强制验收项。
2. **明确“安全主线优先 + Backup 前置 + M1 Session 阶段性汇入”排期策略**：
   - V0.1 坚持以 **“真实执行前拦截闭环（Hook Allow/Deny + 零副作用证明）”** 为第一优先级（Phase 0 ～ Phase 5 主线）。
   - `packages/backup` 在 **Phase 3** 即投入使用（承担 Codex 配置文件与策略文件的事务备份、SHA-256 校验与原子回滚）。
   - 原 M1 阶段的 Codex Session 管理成果在 **Phase 4B（安全底座跑通后）** 对齐迁入 `packages/session`，实现只读会话浏览与备份恢复，既不阻塞安全主线，也不丢弃既有资产。
3. **扩展 Hook 事件与工具覆盖模型**：
   - 适配层（`packages/agent-adapters`）在架构上完整建模 Codex 四大标准 Hook 事件（`PreToolUse`、`PermissionRequest`、`UserPromptSubmit`、`PostToolUse`），V0.1 首期重点激活并验证 `PreToolUse`，预留提示词防泄密与输出脱敏扩展点。
4. **解决无常驻 Daemon 模式下 SQLite 并发锁与 Hook 超时矛盾**：
   - 单次 Hook 进程内策略裁决与审计落盘解耦：SQLite 开启 `WAL` 模式且设置 `busy_timeout = 15ms`；若遇锁竞争或 I/O 异常，**优先在 50ms 内向 `stdout` 返回 `Deny/Allow` 协议 JSON**，未落盘事件自动写入本地无锁 `events-fallback.jsonl` 并在后续查询时归并，杜绝因写库阻塞引发 Hook 超时放行（Fail-Open）。
5. **统一工程目录与架构决策记录（ADR）体系**：
   - 统一收敛至工程根目录 `AGENTS.md`、`docs/decisions/`、`docs/ARCHITECTURE.md` 与本文件 `docs/PRD_V0.1.md`。
6. **补齐 WSL2 Rust 工具链前置门禁**：
   - 在 Phase 0 明确将安装 Rust stable 工具链及锁定 `rust-toolchain.toml` 列为编码前准备事项。

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
| **FR-001** | `agent-adapters` | Codex 多形态环境与执行目标探测 | P0 | Phase 0 / 3 | 准确识别 `ExecutionTarget`（WSL2 发行版 `~/.codex` 与 Windows 原生 `C:\Users\<User>\.codex`）、`ClientSurface`（`CodexCli` / `CodexDesktop`）及 `app-server-daemon` 状态，不读取 `auth.json` 密钥 |
| **FR-002** | `agent-adapters` | Codex `PreToolUse` 协议适配 | P0 | Phase 1 | 解析 stdin JSON（上限 1 MiB），支持 `Bash`/`unified_exec`/`apply_patch`/Windows Shell 等工具归一化，输出标准 Deny/Allow JSON |
| **FR-003** | `security` | 确定性策略评估引擎 | P0 | Phase 1 / 2 | 支持 `Allow` / `Deny` / `Observe` 三态裁决，遵循 Deny 优先，异常输入默认显式 Deny（Fail-Closed） |
| **FR-004** | `security` | 跨平台高危 Shell 命令拦截规则包 | P0 | Phase 2 | 准确拦截 Linux（`rm -rf`、`curl \| sh`、`mkfs`）与 Windows PowerShell/CMD（`Remove-Item -Recurse -Force`、`rmdir /s /q`、`iwr \| iex`、`-EncodedCommand`）高危模式 |
| **FR-005** | `security` | 跨平台敏感凭据与路径越界保护 | P0 | Phase 2 | 拦截对 POSIX 与 Windows 下 `.ssh`、`.aws`、`.codex/auth.json`、`.env`、`*.pem` 的直接访问及 `../` / `..\` 路径穿越 |
| **FR-006** | `security` | 危险 Git 操作识别规则 | P1 | Phase 2 | 识别 `git reset --hard`、`git clean -fdx`、`git push --force`，支持配置为 Observe 或 Deny |
| **FR-007** | `security` | 观察模式与保护模式切换 | P0 | Phase 2 | `observe` 模式仅记录命中规则不阻断；`protect` 模式对命中 `deny` 规则返回明确拒绝 |
| **FR-008** | `local-service` | 离线规则校验与模拟测试 | P0 | Phase 2 | `ai-guard rule validate` 与 `ai-guard rule test` 纯内存重放判定，绝不真实执行被测命令 |
| **FR-009** | `backup` | 配置文件与策略快照备份 | P0 | Phase 3 | 修改任何配置前自动生成带 SHA-256 清单的备份快照，支持完整性校验与一键原子回滚 |
| **FR-010** | `local-service` | Hook 事务安装与无损卸载 | P0 | Phase 3 | 支持 `--dry-run` 预览 Diff；增量合并保留用户既有 Hook；卸载仅移除本产品条目并恢复原状 |
| **FR-011** | `local-service` | 受管启动（`ai-guard run codex`） | P0 | Phase 3 | 启动前强制校验 Hook 注册、Runner 可执行、策略有效及自检状态；不合规时拒绝代启动并提示修复 |
| **FR-012** | `storage` | 本地 SQLite 脱敏审计存储 | P0 | Phase 4 | WAL 模式存储最小化脱敏事件，支持 15ms 超时无锁 fallback，绝不因写库阻塞改变或拖慢 Deny 裁决 |
| **FR-013** | `storage` | 敏感信息自动脱敏器 | P0 | Phase 1 / 4 | 自动剥离命令与参数中的 Token、API Key、私钥、密码与敏感路径内容，支持审计分页查询与脱敏导出 |
| **FR-014** | `local-service` | 四态防护状态诊断（`status`/`doctor`） | P0 | Phase 3 / 4 | 综合配置完整性、信任状态与自检记录输出四态，绝不以“配置文件存在”冒充 `protected_verified` |
| **FR-015** | `local-service` | 隔离环境端到端自检向导 | P0 | Phase 4 | `ai-guard self-test codex --isolated` 在临时目录执行真实 Allow/Deny 验证并持久化自检证据 |
| **FR-016** | `session` / `backup` | M1 Session 只读索引与安全备份 | P1 | Phase 4B | 只读解析本地 Codex 会话列表与详情；执行会话清理/归档前强制联动 `packages/backup` 校验备份 |
| **FR-017** | `desktop` | Windows ↔ WSL2 白名单安全桥接 | P0 | Phase 5 | Tauri Rust Command 仅通过受控 `argv` 调用 `wsl.exe --exec ai-guard <subcommand> --json`，防命令注入 |
| **FR-018** | `desktop` | 全中文桌面管理界面（六大页面） | P0 | Phase 5 | 交付安全概览、Agent 管理、安全策略、风险事件、防护诊断/安装、设置与隐私六大中文页面（含 Session 扩展视图） |
| **FR-019** | `desktop` | 断连感知与诚实状态展示 | P0 | Phase 5 | WSL2 未启动、命令超时或桥接失败时，UI 立即展示“状态未知”及排障引导，严禁沿用旧绿灯缓存 |
| **FR-020** | 全局文档与合规 | 保护边界声明与开源发布门禁 | P0 | Phase 5 | 明确展示支持范围与已知盲区（如未覆盖 Hosted Tools、同权限用户绕过限制），通过全部安全与许可证检查 |

---

## 4. 分阶段开发 PRD 详细规格（Phase 0 ～ Phase 6）

```mermaid
flowchart LR
    P0["Phase 0 (M0)\n环境基线与 Codex 0.160.1\nHook 协议隔离实测"] --> P1["Phase 1 (M1+M2)\nRust 核心与真实 Codex\n执行前拦截 PoC (生死线)"]
    P1 --> P2["Phase 2 (M3)\nTOML 策略引擎、内置规则包\n与离线模拟测试"]
    P2 --> P3["Phase 3 (M4)\nbackup 事务备份、Hook 安装器\n无损卸载与受管启动"]
    P3 --> P4["Phase 4 (M5 + M1 迁移)\nSQLite 脱敏审计、四态自检\n与 M1 Session 只读保护"]
    P4 --> P5["Phase 5 (M6+M7)\nWindows Tauri 2 中文桌面端\nWSL2 桥接与 V0.1 发布"]
    P5 --> P6["Phase 6 (V0.2+ / M8+M9)\n多 Agent 适配、nono 沙箱\n与企业版控制平面"]
```

---

### Phase 0（对应 M0）：工程基线审计与 Codex 0.160.1 Hook 协议实测 PRD

#### 4.0.1 阶段目标
在不修改用户真实 `~/.codex` 配置的前提下，补齐 Rust 工具链，完成对本机 `codex-cli 0.160.1` 的 Hook 触发机制、输入输出 JSON 结构、信任机制及 `app-server-daemon` 交互行为的实测取证。

#### 4.0.2 功能与研发任务说明
1. **P0-T1：环境基线盘点与 Rust 工具链安装**
   - 记录当前 WSL2 Ubuntu 版本、内核版本（检查 Landlock 支持情况）、Node.js (`v18.19.1`)、pnpm (`10.11.0`)、Python (`3.12.3`)、Codex CLI (`0.160.1`) 真实路径与状态。
   - 在 WSL2 环境安装 Rust stable 工具链（`rustup`、`cargo`、`rustc`、`clippy`、`rustfmt`），在工程根目录创建 `rust-toolchain.toml`。
2. **P0-T2：Codex 0.160.1 Hook 协议隔离探针实测**
   - 在 `/tmp/ai-guard-m0-probe` 下建立独立测试目录与隔离的 `CODEX_HOME`。
   - 实测并记录 `codex-cli 0.160.1` 的以下核心协议事实：
     - 配置文件加载位置与格式（`config.toml` / `hooks.json` 的精确字段结构）。
     - `PreToolUse` 事件触发时传入 `stdin` 的真实 JSON 字段（`session_id`、`turn_id`、`cwd`、`hook_event_name`、`tool_name`、`tool_input`、`tool_use_id`）。
     - 不同工具调用对应的 `tool_name` 精确取值（如 `Bash`、`unified_exec`、`write_stdin`、`apply_patch`、MCP 工具）。
     - 返回 `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}` 时 Codex 的实际拦截表现。
     - 当后台 `app-server-daemon` 存在时，修改 Hook 配置后是否需要重启 daemon 或传 `--no-daemon`。
3. **P0-T3：安全边界 ADR 归档**
   - 在 `docs/decisions/` 下归档核心架构决策记录（技术栈与许可证、安全主线优先与 Session 阶段性汇入、WSL2 执行侧与 Windows 桌面桥接）。

#### 4.0.3 交付产物清单
- `rust-toolchain.toml`
- `docs/BASELINE.md`
- `docs/CODEX_HOOK_CONTRACT.md`
- `docs/COMPATIBILITY.md`
- `tests/fixtures/codex/*.json`（脱敏后的真实协议样本）

#### 4.0.4 阶段验收门禁（Phase 0 Gate）
- [ ] `rustc --version` 与 `cargo --version` 正常可用。
- [ ] `docs/CODEX_HOOK_CONTRACT.md` 中包含基于本机 `codex-cli 0.160.1` 实测捕获的脱敏 JSON 结构，无主观猜测字段。
- [ ] 确认用户真实 `~/.codex` 目录在实测前后无任何新增或修改。

---

### Phase 1（对应 M1 + M2）：Rust 安全内核与真实执行前拦截 PoC PRD（产品生死线）

#### 4.1.1 阶段目标
搭建 Rust Workspace 核心骨架，实现 `ai-guard hook codex pre-tool-use` 热路径二进制，并在隔离环境跑通真实 `codex-cli 0.160.1` 的执行前拒绝（Deny）与正常放行（Allow）端到端测试。

#### 4.1.2 功能与研发任务说明
1. **P1-T1：Cargo Workspace 与最小 CLI 构建（对应 M1-01）**
   - 建立根 `Cargo.toml`，包含成员：`apps/local-service`（二进制 `ai-guard`）、`packages/agent-adapters`、`packages/security`、`packages/backup`、`packages/storage`、`packages/session`。
   - 实现基础 CLI 框架（基于 `clap`）：支持 `ai-guard --version`、`ai-guard doctor --json`（基础版）、`ai-guard hook codex pre-tool-use`。
2. **P1-T2：安全领域模型与脱敏错误体系（对应 M1-02、M1-04）**
   - 在 `packages/security` 定义与具体 Agent 解耦的领域结构：
     - `AgentKind`（`Codex`）
     - `ActionKind`（`Shell`, `FilePatch`, `McpTool`, `LocalTool`, `Unknown`）
     - `Enforcement`（`Allow`, `Deny`, `Observe`, `Unsupported`）
     - `ActionEvent` 与 `Decision`（含 `matched_rule_ids`、`reason_code`、`display_message`、`policy_revision`、`coverage`）
   - 实现基础脱敏器与统一错误码（`AG-HOOK-001` 等）：确保任何异常日志或错误输出绝不打印原始 `raw_tool_args` 中的秘密。
3. **P1-T3：`CodexHookAdapter` 协议解析与 Fail-Closed 输出（对应 M1-03）**
   - 在 `packages/agent-adapters` 实现 `stdin` 流式限长读取（默认上限 1 MiB）。
   - 当输入为空、超长、非合法 UTF-8、JSON 畸形或缺少关键字段时，不发生 `panic`，直接生成显式 `Deny` 决策并输出合法的 Codex `PreToolUse` 拒绝 JSON。
   - 严格保证 `stdout` 只输出单行协议 JSON，调试/错误日志只写 `stderr`。
4. **P1-T4：真实 Codex 执行前拦截 E2E 验证（对应 M2-01 ～ M2-04）**
   - 内置确定性规则 `TEST-DENY-001`（匹配 `AI_GUARD_BLOCK_ME`）。
   - 在隔离临时目录编写并执行自动化/半自动化真实 Codex E2E 脚本：
     - **用例 1（真实拒绝）**：触发含 `AI_GUARD_BLOCK_ME` 并尝试创建 `sentinel.txt` 的命令 → 验证 Hook 返回 Deny 且 **`sentinel.txt` 不存在**。
     - **用例 2（正常放行）**：触发 `pwd` / `echo hello` → 验证命令正常执行。
     - **用例 3（故障与绕过取证）**：测试 Hook 二进制不存在、超时、返回非 JSON 时的 Codex 实际表现，如实记入 `docs/COMPATIBILITY.md`。

#### 4.1.3 阶段验收门禁（Phase 1 Gate — 不可跳过）
- [ ] `cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace` 全部通过。
- [ ] 至少 15 组畸形/边界 JSON 输入单测通过，0 panic。
- [ ] 伪造密钥 `SECRET_TEST_XYZ` 在 stdout/stderr 中 0 泄露。
- [ ] **核心生死线**：真实 `codex-cli 0.160.1` 隔离 E2E 测试证明 `sentinel.txt` 未被创建，测试日志与证据归档于 `docs/evidence/m2-e2e-report.md`。

---

### Phase 2（对应 M3）：TOML 策略引擎、内置高危规则包与离线测试 PRD

#### 4.2.1 阶段目标
实现完整的 TOML 策略加载、静态校验、优先级裁决与快照回退机制，交付 V0.1 默认高置信度安全规则集，并提供不执行命令的离线模拟测试工具。

#### 4.2.2 功能与研发任务说明
1. **P2-T1：TOML 策略 Schema、编译校验与可信快照（对应 M3-01）**
   - 支持加载 `~/.config/ai-guard/policy.toml`（权限 `0600`）。
   - 支持字段：`schema_version`、`revision`、`mode`（`observe` | `protect`）、`[[rules]]`（`id`, `enabled`, `priority`, `name`, `agent`, `tool`, `match_kind`, `match_value`, `effect`, `reason_code`）。
   - **防降级保护**：当策略文件语法错误、版本不兼容或包含未知 `match_kind` 时，拒绝激活损坏配置，优先回退至最近一次验证通过的策略快照；若无快照可用则在 Hook 侧显式返回 Deny 并附带 `AG-POLICY-001` 告警。
2. **P2-T2：V0.1 内置高危规则检测器（对应 M3-02、M3-03）**
   - 所有规则检测器采用受控 Rust 枚举与确定性词法/路径分析实现，设置输入长度与正则计算上限（防 ReDoS）：
     - `SHELL-DESTRUCTIVE-RM`：拦截 `rm -rf /`、`rm -rf ~`、`rm -rf ..`、根目录或系统关键目录删除、通配符高危删除。
     - `SHELL-DISK-WIPE`：拦截 `mkfs`、`fdisk`、`dd if=... of=/dev/...` 等磁盘破坏命令。
     - `SHELL-PIPE-EXEC`：拦截 `curl`/`wget` 等网络下载通过管道直接交给 `sh`/`bash`/`zsh`/`python`/`node`/`perl` 执行，或 `base64 -d | sh` 模式。
     - `PATH-SENSITIVE-CRED`：对 Shell 命令参数及 `apply_patch` 补丁目标路径做规范化解析，拦截读取或修改 `~/.ssh/`、`~/.aws/`、`~/.gnupg/`、`~/.codex/auth.json`、`.env`、`*.pem`、`*.key` 及跨越工作区根目录的 `../` 路径穿越。
     - `GIT-DANGEROUS-OP`：识别 `git reset --hard`、`git clean -fdx`、`git push --force` / `-f`。
3. **P2-T3：离线规则校验与模拟测试命令（对应 M3-04）**
   - 实现 `ai-guard rule validate --path <policy.toml> --json`。
   - 实现 `ai-guard rule test --input <event.json> [--policy <policy.toml>] --json`：**纯内存评估，严禁真实执行命令**，返回命中规则列表、最终决策、中文原因说明与耗时。

#### 4.2.3 阶段验收门禁（Phase 2 Gate）
- [ ] 正向/反向回归测试集：不少于 **20 个高危命令/路径正例（100% 命中 Deny）** + **40 个日常合法开发命令反例（100% Allow，0 误报）**。
- [ ] 策略文件损坏、非法字段注入、路径穿越（`a/../../etc/passwd`）专项单测全部通过。
- [ ] WSL2 下离线规则评估 P95 耗时 ≤ 10ms。

---

### Phase 3（对应 M4）：`packages/backup` 事务备份、安全安装器与受管启动 PRD

#### 4.3.1 阶段目标
打通 `packages/backup` 的文件备份与 SHA-256 完整性校验能力，实现不破坏用户现有配置的 Hook 安装/卸载事务，以及确保防护生效才启动的 `ai-guard run codex` 受管启动器。

#### 4.3.2 功能与研发任务说明
1. **P3-T1：`packages/backup` 本地快照备份、校验与原子恢复底座**
   - 实现通用的备份管理器（同时服务于配置文件事务备份与后续的 Session 备份）：
     - 创建备份时生成 `manifest.json`（记录源文件路径、文件大小、SHA-256 哈希、备份时间戳、关联操作类型）。
     - 恢复前强制重新计算备份文件 SHA-256 并与 Manifest 比对；校验失败立即拒绝恢复并报错。
     - 采用“同目录临时文件写入 → `fsync` → 原子 `rename`”确保落盘无半写入损坏。
2. **P3-T2：配置发现、安装预览（`--dry-run`）与增量合并安装（对应 M4-01、M4-02）**
   - 实现 `ai-guard install codex --scope user|project --dry-run [--json]`：扫描目标配置，计算并展示 unified diff 及将影响的 Hook 事件列表，不修改磁盘。
   - 实现正式安装 `ai-guard install codex --scope user|project`：
     - 先调用 `packages/backup` 备份原配置文件。
     - 使用保留格式/结构的解析器（如 `toml_edit` / 结构化 JSON 合并）仅注入带有 AI卫士唯一身份标识的 Hook Handler（使用 `ai-guard` 二进制绝对路径），**100% 保留用户已有的其他配置项与第三方 Hook**。
   - 实现安全卸载 `ai-guard uninstall codex --scope user|project [--dry-run]`：
     - 仅移除 AI卫士管理的 Hook 条目；若检测到无法安全归属的外部冲突改动，停止自动覆盖并输出手动恢复指引或提供一键从 `packages/backup` 快照回滚。
3. **P3-T3：受管启动 `ai-guard run codex -- [args...]` 与信任诊断（对应 M4-03、M4-04）**
   - 启动前依次执行 Preflight 检查：
     1. `codex` 二进制是否存在且可执行；
     2. AI卫士 Hook 是否已注册且指向当前有效的 `ai-guard` 绝对路径；
     3. 本地 `policy.toml` 是否存在且通过校验；
     4. Hook 是否已受信任 / 最近一次自检是否有效。
   - 若 Preflight 失败：拒绝启动 `codex`，返回非零退出码并输出中文原因与修复命令；若通过：使用 `Command::new(codex_bin).args(args)` 直接拉起（严禁通过 `sh -c` 拼接参数）。

#### 4.3.3 阶段验收门禁（Phase 3 Gate）
- [ ] 闭环测试：“包含第三方自定义 Hook 的配置文件 → 执行 install → 验证第三方 Hook 完好 → 执行 uninstall → 验证文件哈希与安装前一致”全部通过。
- [ ] 故障注入：模拟写入中断、备份文件篡改（SHA-256 不匹配拒绝恢复）、Hook 二进制丢失时 `ai-guard run codex` 成功阻断启动。

---

### Phase 4（对应 M5 + M1 迁移汇入）：SQLite 脱敏审计、四态自检与 Session 保护 PRD

#### 4.4.1 阶段目标
完成 `packages/storage` 的 SQLite 审计与状态持久化，实现一键隔离自检（`self-test`）与四态状态汇总（`status`），并在安全主线验收后将原 M1 阶段的 Codex Session 只读管理能力汇入 `packages/session`。

#### 4.4.2 功能与研发任务说明
1. **P4-T1：`packages/storage` SQLite Schema、迁移与无锁 Fallback（对应 M5-01）**
   - 在 `~/.local/share/ai-guard/events.db`（目录 `0700`，文件 `0600`）创建并管理 5 张核心表：`schema_migrations`、`security_events`、`policy_revisions`、`integration_state`、`self_test_runs`。
   - 实现 Hook 审计快速写入：开启 WAL，超时上限 15ms；当遇到数据库锁冲突或磁盘异常时，自动降级追加至 `~/.local/state/ai-guard/events-fallback.jsonl`，确保 Hook 进程绝不因审计失败而超时或改变 `Deny` 决策。
2. **P4-T2：脱敏审计查询、分页过滤与导出（对应 M5-02）**
   - 实现 `ai-guard events list [--since <duration>] [--decision <deny|allow|observe>] [--limit <N>] --json`。
   - 实现 `ai-guard events export --output <path> --redacted [--format json|csv]`。
   - 对所有落盘与导出的摘要字段执行二次脱敏校验。
3. **P4-T3：四态防护状态汇总与一键隔离自检（对应 M5-03、M5-04）**
   - 实现 `ai-guard self-test codex --isolated --json`：在 `/tmp` 自动创建隔离沙箱，运行 Allow 与 Deny 自检用例，校验副作用文件未生成，并将结果写入 `self_test_runs`。
   - 实现 `ai-guard status --json`：根据配置哈希、信任状态、版本匹配度及 `self_test_runs` 记录，精确计算并返回 `protected_verified` / `partially_protected` / `unprotected` / `unknown` 及已知盲区列表（`limitations`）。
4. **P4-T4（Phase 4B 扩展包）：M1 Codex Session 只读索引与安全备份（`packages/session`）**
   - 对接本机 `~/.codex/session_index.jsonl`、`sessions/` 及 `thread_history_1.sqlite`（**严格只读打开，如 SQLite `SQLITE_OPEN_READ_ONLY`**）。
   - 提供 CLI 子命令：`ai-guard session list --json`、`ai-guard session show <id> --json`、`ai-guard session backup <id> --json`（调用 `packages/backup` 创建带 SHA-256 校验的会话归档包）。

#### 4.4.3 阶段验收门禁（Phase 4 Gate）
- [ ] 隐私红线测试：注入含 `sk-proj-xxxx`、`ghp_xxxx`、`-----BEGIN OPENSSH PRIVATE KEY-----` 的模拟工具调用，验证 `events.db`、日志文件与导出文件中秘钥原文 **0 残留**。
- [ ] 状态诚实度测试：当未运行 `self-test` 或篡改配置文件后，`ai-guard status --json` 绝不返回 `protected_verified`。
- [ ] Session 只读保护测试：执行 `session list/show/backup` 前后，用户 `~/.codex` 下原会话文件的哈希与 `mtime` 保持不变。

---

### Phase 5（对应 M6 + M7）：Windows Tauri 2 中文桌面端与 V0.1 个人版发布 PRD

#### 4.5.1 阶段目标
构建运行于 Windows 宿主机的 Tauri 2 + React + TypeScript 全中文管理界面，通过白名单桥接调用 WSL2 内的 `ai-guard` CLI，完成全部交互闭环并通过 V0.1 开源发布门禁。

#### 4.5.2 功能与研发任务说明
1. **P5-T1：Windows ↔ WSL2 受限命令桥接层（对应 M6-01、M6-02）**
   - 在 `apps/desktop/src-tauri` 中实现受控桥接函数：
     - 仅允许调用白名单子命令（`status`, `doctor`, `install --dry-run`, `install`, `uninstall --dry-run`, `uninstall`, `rule validate`, `rule test`, `events list`, `events export`, `self-test`, `session list`, `session backup`）。
     - 严禁拼装 Shell 字符串，统一使用 `std::process::Command::new("wsl.exe").args(["--distribution", distro, "--exec", ai_guard_bin, ...])`。
     - 校验返回 JSON 的 `api_version == "1.0"`，设置单次命令超时与输出体积上限。
2. **P5-T2：全中文桌面端核心页面交付（对应 M6-03、M6-04）**
   - **1. 安全概览（`/overview`）**：四态防护状态卡片（带颜色与盲区说明）、最近 24h 拦截统计、一键自检按钮、受管启动命令快捷复制。
   - **2. Agent 管理（`/agents`）**：展示 WSL2 发行版、Codex `0.160.1` 路径与版本、各工具路径覆盖矩阵（`Bash`: 已验证 / `apply_patch`: 已验证 / `Hosted Tools`: 不支持）。
   - **3. 安全策略（`/policies`）**：观察/保护模式切换、规则列表查询与启停、内置“规则沙盒测试器”（输入命令查看模拟命中结果）、策略历史版本回滚。
   - **4. 风险事件（`/events`）**：时间线展示 Allow/Deny/Observe 记录、按规则/时间筛选、查看中文拦截原因与脱敏摘要、一键导出脱敏报告。
   - **5. 防护诊断与安装恢复（`/diagnostics` & `/integrations`）**：可视化执行 `install --dry-run` 查看配置文件 Diff、二次确认安装/卸载、`/hooks` 信任操作图文指引、配置备份一键恢复、（若启用 Phase 4B）Session 列表与备份入口。
   - **6. 设置与隐私（`/settings`）**：本地数据存储路径说明、审计保留周期设置、产品安全能力边界与免责声明。
3. **P5-T3：V0.1 发布质量与开源合规门禁（对应 M7-01 ～ M7-04）**
   - 完成干净环境安装/自检/卸载测试、CI 脚本、依赖许可证与漏洞扫描、产物 SHA-256 校验清单及 `SECURITY.md` / `LIMITATIONS.md` 文档定稿。

#### 4.5.3 阶段验收门禁（Phase 5 / V0.1-GA Gate）
- [ ] 命令注入防护测试：在 UI 规则测试框或路径配置框中输入 `$(touch /tmp/pwn)`、`; rm -rf /`、`` `id` ``，验证 WSL2 内无任何命令被拼接执行。
- [ ] 断连诚实度测试：关闭 WSL2 或重命名 `ai-guard` 二进制后，UI 立即显示“状态未知 / 未受保护”，不残留绿色“已验证保护”状态。
- [ ] PRD 第 9 章定义的 `AT-01` ～ `AT-12` 验收用例与技术方案 `SEC-E2E-001` ～ `SEC-E2E-012` 全部通过并附真实记录。

---

### Phase 6（对应 M8 + M9，V0.1.5 ～ V1.0 演进）：Codex 桌面应用原生目标、多 Agent 适配、OS 沙箱与企业版控制平面

- **Phase 5.5（V0.1.5 专项增强：Codex 桌面应用全模式闭环）**：
  - **WSL2 工作区模式**：在 V0.1（Phase 0 ～ Phase 5）中已随 WSL2 `~/.codex` 与 `app-server-daemon` 刷新检测同步支持。
  - **Windows 原生执行目标模式（`WindowsNative`）**：
    1. 将同一套 `apps/local-service` Rust 代码编译为 Windows 原生 `ai-guard.exe`，随 Tauri 桌面安装包一同分发。
    2. 支持扫描与挂载 Windows 宿主机 `C:\Users\<User>\.codex\` 配置与 Hook（针对 Windows Shell 引号转义做安全参数封装）。
    3. AI卫士桌面端“Agent 管理页”支持同时纳管并切换查看 **`WSL2 Codex (CLI / Desktop WSL)`** 与 **`Windows Native Codex Desktop`** 两个执行目标的防护状态、风险事件与 Session 备份。
- **Phase 6A（V0.2 个人版增强）**：
  - 接入 **Claude Code** 与 **OpenCode**（独立实现 `AgentAdapter` 并完成各自真实 Hook E2E 验证）。
  - 完整版跨 Agent Session 搜索、恢复冲突预览与安全恢复。
  - 引入 **nono / Linux Landlock**（WSL2）及 **Windows Job Object / 受限令牌** 沙箱 PoC，对文件读写白名单与网络外传提供 OS 级强制隔离验证。
- **Phase 6B（V1.0 企业版，独立私有仓库 `ai-guard-enterprise`）**：
  - 基于 Rust Axum + PostgreSQL 实现设备注册与 mTLS 身份认证、Ed25519 签名策略强制下发（防止终端私自放宽企业基线）、OIDC/RBAC 权限控制与多租户脱敏审计汇聚中心。
