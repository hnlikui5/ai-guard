# ADR-0001：V0.1 核心技术栈与开源许可证选型决策

- **状态**：已确认（Accepted）
- **日期**：2026-11-07
- **决策范围**：`apps/*`、`packages/*`、根目录开源协议

---

## 1. 背景（Context）

AI卫士（AI Guard）定位为本地优先的 AI 编程 Agent 安全与运行管理平台，采用“个人版开源免费 + 企业版商业化演进”的双轨模式。在工程初始化完成后，需要正式拍板两项基础决策：

1. 本地后台服务（`apps/local-service`）与核心领域模块（`packages/*`）的主力编程语言。
2. 个人版开源仓库的许可证（`LICENSE`）类型。

---

## 2. 决策内容（Decision）

### 2.1 技术栈定型

1. **桌面应用层（`apps/desktop`）**：采用 **Tauri 2.x + React + TypeScript**。
   - 前端提供全中文可视化界面，通过本地受控接口与 `apps/local-service` 通信。
2. **本地服务与核心业务包（`apps/local-service`、`packages/*`）**：采用 **Rust** 作为主力后端与安全内核开发语言。
   - 通过 Cargo Workspace 统一组织 `apps/local-service`、`packages/agent-adapters`、`packages/security`、`packages/session`、`packages/backup`、`packages/storage`。
   - 对既有 M1 阶段（Codex Session 管理）成果，若原实现为其他语言（如 Python/TypeScript），在迁移阶段重点复用其业务模型、解析规则与测试用例，并按需收敛为 Rust 实现或通过明确进程间契约衔接。
3. **本地持久化层（`packages/storage`）**：采用 **SQLite（开启 WAL 模式 + FTS5 全文检索）+ 本地受控文件系统**。
4. **Windows + WSL2 跨边界架构**：
   - `apps/local-service` 原生运行于 Codex 所在的 WSL2 Ubuntu 环境内，直接访问 Linux 文件系统与 Codex App Server。
   - Windows 宿主机桌面端通过受控本地回路（`127.0.0.1` + 鉴权 Token）或 WSL 标准通道与本地服务通信，避免跨 9P 文件系统直接操作 SQLite。

### 2.2 开源许可证定型

- 个人版主工程采用 **Apache License 2.0**（根目录 `LICENSE` 文件）。

---

## 3. 决策理由（Rationale）

1. **为什么选择 Rust 作为核心服务与安全底座**：
   - **原生性能与单二进制分发**：安全拦截钩子（Pre-tool Hook）对启动延迟与评估耗时极度敏感，Rust 编译产物零运行时依赖、启动极快，不会因目标机器缺少特定 Python/Node 版本而失效。
   - **内存安全与类型强约束**：契合安全模块“默认安全、失败可控（Fail-Closed）”的工程要求，利用 Rust 的 `Result`/`enum` 类型系统在编译期杜绝未处理的异常分支。
   - **架构栈统一性**：与桌面端 Tauri 2.x 的 Rust 宿主层技术栈同源，便于共享类型定义与构建工具链。
2. **为什么选择 Apache License 2.0**：
   - 提供明确的专利授权与商标保护条款，兼顾个人版开源社区传播与未来企业版商业化边界。
   - 与核心参考生态（如 HOL Guard、Codex 等）许可证天然兼容。

---

## 4. 影响与后续行动（Consequences）

1. **环境要求**：后续启动代码开发前，需在当前 WSL2 开发环境中通过 `rustup` 安装最新 stable 版 Rust 工具链（`rustc`、`cargo`、`clippy`、`rustfmt`）。
2. **M1 迁移要求**：在获得原 M1 工程路径后，先提炼其数据 Schema、Codex Session 解析逻辑与边界测试样本，对齐至 `packages/session` 与 `packages/storage` 的 Rust 模块设计中。
