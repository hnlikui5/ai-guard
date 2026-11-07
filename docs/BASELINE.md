# AI卫士（AI Guard）双环境工程基线报告（M0 Baseline）

- **审计阶段**：Phase 0（M0-01）
- **审计日期**：2026-11-07
- **审计结论**：通过（已实测宿主机 Windows 与 WSL2 Ubuntu 双环境真实版本、工具链、Codex 安装形态及 `.codex` 原始配置只读哈希基线）

---

## 1. 宿主机与 WSL2 双环境系统基线

| 维度 | Windows 宿主机（主控端运行环境） | WSL2 子系统（受管 Linux 环境） |
| :--- | :--- | :--- |
| **操作系统版本** | Microsoft Windows 11 (`10.0.26200.9711`) | Ubuntu 24.04.4 LTS (`noble`, 64-bit) |
| **内核版本** | Windows NT 10.0 Build 26200 | Linux `6.6.87.2-microsoft-standard-WSL2` (`x86_64`) |
| **OS 级沙箱支持** | Windows Sandbox / AppContainer / Restricted Token | Linux Landlock 已启用（`CONFIG_SECURITY_LANDLOCK=y`） |
| **Codex 形态与版本** | Codex Desktop App / Sandbox Runner `0.166.0-alpha.5.1` | `codex-cli 0.160.1`（npm 全局包 `@openai/codex`） |
| **Codex 可执行文件路径** | `C:\Users\kui.li\.codex\.sandbox-bin\codex.exe`<br>`C:\Users\kui.li\.codex\.sandbox-bin\codex-command-runner-0.166.0-alpha.5.1.exe` | `/home/ai-li/.local/npm/bin/codex` -> `.../vendor/x86_64-unknown-linux-musl/bin/codex` |
| **Codex 数据目录 (`CODEX_HOME`)** | `C:\Users\kui.li\.codex`（WSL2 映射：`/mnt/c/Users/kui.li/.codex`） | `/home/ai-li/.codex` |
| **关键目录特征** | 含 `config.toml`、`session_index.jsonl`、`thread_history_1.sqlite` (754 MB)、`logs_2.sqlite` (43.8 MB)、`models_cache.codex_work_desktop.json` | 含 `config.toml`、`app-server-daemon/`、`state_5.sqlite`、`thread_history_1.sqlite`、`logs_2.sqlite` |

---

## 2. 研发与构建工具链基线

已在 WSL2 开发环境中完成跨平台 Rust 工具链安装与校验（配置文件：`rust-toolchain.toml`）：

| 工具名称 | 实测版本 | 路径 / 备注 |
| :--- | :--- | :--- |
| **rustc** | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` | `/home/ai-li/.cargo/bin/rustc` |
| **cargo** | `cargo 1.99.1 (5f94df478 2026-08-27)` | `/home/ai-li/.cargo/bin/cargo` |
| **clippy** | `clippy 0.1.99 (58cf8f9c35 2026-10-13)` | `cargo clippy` |
| **rustfmt** | `rustfmt 1.10.0-stable (58cf8f9c35 2026-10-13)` | `cargo fmt` |
| **Rust Targets** | `x86_64-unknown-linux-gnu`（默认）<br>`x86_64-pc-windows-gnu`（已安装标准库） | 支持同一套核心源码编译 Linux 与 Windows 产物 |
| **GCC / CC** | `/usr/bin/gcc` | Linux 本地编译链接器 |
| **Node.js / pnpm** | Node `v18.19.1` / pnpm `10.11.0` | 用于 Tauri 2 前端（React + TypeScript）构建 |
| **Python / uv** | Python `3.12.3` / `uv` | 用于本地隔离 E2E Mock Server 与辅助验证脚本 |
| **Git** | `git version 2.43.0` | 已配置 SSH 认证并连接 `origin/main` |

---

## 3. Codex 特性开关基线（`codex features list` 实测）

在 `codex-cli 0.160.1` 中，与安全拦截和后台服务直接相关的 Feature 状态如下：

- `hooks`：`stable = true`（默认启用；旧名 `codex_hooks` 已作为 legacy alias 自动映射至 `hooks`）
- `daemon_auto_start`：`stable = true`（默认启用，后台常驻 `app-server-daemon`）
- `unified_exec`：`stable = true`（默认启用，Shell 命令通过 `exec_command` + `write_stdin` 执行）
- `unified_exec_tty`：`stable = true`（默认启用，支持分配交互式 PTY 会话）
- `shell_tool`：`stable = true`（默认启用）
- `write_stdin_approval`：`stable = true`（默认启用）
- `guardian_approval`：`stable = true`（默认启用）

---

## 4. 工程目录结构现状（已存在 vs 拟新增）

### 4.1 已存在目录与文件
- `AGENTS.md`：工程研发与安全红线规范
- `LICENSE`：Apache-2.0 许可证
- `rust-toolchain.toml`：跨平台 Rust 工具链锁定配置
- `apps/desktop/`：Windows 宿主机 Tauri 2 桌面端目录骨架
- `apps/local-service/`：Rust CLI / Hook Runner / 本地核心服务目录骨架
- `packages/agent-adapters/`：Agent 协议适配层目录骨架
- `packages/security/`：跨平台安全策略与规则引擎目录骨架
- `packages/backup/`：配置与会话 SHA-256 事务备份目录骨架
- `packages/session/`：双环境会话只读索引目录骨架
- `packages/storage/`：SQLite 审计与状态存储目录骨架
- `docs/`：权威 PRD、架构设计、路线图、ADR 及本基线文档
- `references/hol-guard/`：只读参考仓库（`v3.59.0`，Commit `634eafea1bb6ce91fc58f13d1c8d0646d3d18fcb`，已由 `.gitignore` 排除）

### 4.2 Phase 1（M1+M2）拟新增文件
- 根 `Cargo.toml` 及各成员包 `Cargo.toml` / `src/lib.rs` / `src/main.rs`
- `tests/fixtures/codex/*.json`（已在 Phase 0 建立首批实测脱敏夹具）
- `docs/evidence/m2-e2e-report.md`（Phase 1 真实拦截 E2E 证据报告）

---

## 5. 用户真实 `.codex` 目录只读保护基线校验

根据 `AGENTS.md` 第 4.2 条与 Phase 0 Gate 要求，在实测前后对宿主机与 WSL2 真实配置文件进行了只读校验（严禁读取或记录 `auth.json`）：

| 目标环境 | 文件路径 | 文件大小 (Bytes) | 修改时间 (`mtime`) | SHA-256 校验和 | 实测前后状态 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **WSL2 Ubuntu** | `/home/ai-li/.codex/config.toml` | `375` | `1793424095` | `ca080ce591a7b8aa1315b831107852d02071af825d3bf1e180392e6fbf5daec6` | **100% 未修改** |
| **WSL2 Ubuntu** | `/home/ai-li/.codex/hooks.json` | - | - | `NOT_EXISTS` | **100% 未修改** |
| **Windows 宿主机** | `/mnt/c/Users/kui.li/.codex/config.toml` | `3899` | `1794012990` | `ae970ff855b64021bf98d1e5927da0ea4db13111e4d34b8b2420a32f3a14c9ef` | **100% 未修改** |
| **Windows 宿主机** | `/mnt/c/Users/kui.li/.codex/hooks.json` | - | - | `NOT_EXISTS` | **100% 未修改** |
