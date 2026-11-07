# AI卫士（AI Guard）产品研发路线图（Roadmap）

本文档规划 **AI卫士（AI Guard）** 从 V0.1 个人版基线到多 Agent 扩展及未来企业版演进的阶段性研发目标。各阶段详细功能规格、接口契约与验收门禁以 `docs/PRD_V0.1.md` 为准。

---

## 阶段一：V0.1 个人版分阶段研发（Phase 0 ～ Phase 5）

**核心策略**：采用 **“Windows 宿主机中心化主控 + 宿主机/WSL2 双环境就地拦截”** 架构，坚持 **“安全主线优先（真实 Hook 拦截 + 零副作用证明）+ `packages/backup` 事务备份前置 + M1 Session 双环境汇入”**。

### 1.0 已完成基线：工程初始化与规划定稿
- [x] 建立模块化单体工程目录结构与 `AGENTS.md` 开发规范
- [x] 完成 `references/hol-guard`（v3.59.0）只读参考区引入与登记
- [x] 确定 Apache License 2.0 开源许可证与 Rust 跨平台核心技术栈（`ADR-0001` ～ `ADR-0003`）
- [x] 确立“Windows 宿主机主控桌面软件 + 同时纳管宿主机 Codex（`C:\Users\<User>\.codex`）与 WSL2 Codex（`/home/<user>/.codex`）”的分阶段开发 PRD（`docs/PRD_V0.1.md`）

### 1.1 Phase 0（M0）：双环境基线审计与 Codex Hook 协议实测
- [x] 安装 Rust stable 工具链（配置 Linux 与 Windows 双编译目标）并锁定 `rust-toolchain.toml`
- [x] 在隔离临时目录实测宿主机 Codex（`0.166.0+`）与 WSL2 `codex-cli`（`0.160.1+`）的 `PreToolUse` Hook 输入/输出协议、工具名映射及 `app-server-daemon` 刷新行为
- [x] 输出 `docs/BASELINE.md`、`docs/CODEX_HOOK_CONTRACT.md`、`docs/COMPATIBILITY.md` 与 `tests/fixtures/codex/`

### 1.2 Phase 1（M1 + M2）：Rust 跨平台安全内核与真实执行前拦截 PoC（产品生死线）
- [x] 建立根 `Cargo.toml` Workspace，打通 `apps/local-service`（同源编译宿主机 `ai-guard.exe` 与 WSL2 `ai-guard-linux`）与 `packages/*`
- [x] 实现 `ManagedTarget`（`WindowsHost` / `Wsl2Distro`）、`ActionEvent` / `Decision` 领域模型、`CodexHookAdapter` 及异常默认拒绝（Fail-Closed）机制
- [x] 在隔离环境中通过真实 Codex 执行前拒绝（Deny）E2E 验证，证明副作用文件未生成

### 1.3 Phase 2（M3）：TOML 策略引擎、跨平台内置高危规则包与离线测试
- [x] 实现 `policy.toml` 编译校验、优先级裁决与防降级快照回退
- [x] 交付 V0.1 跨平台高置信度规则集（同时覆盖 Linux Bash/sh 与 Windows PowerShell/CMD 破坏性命令、管道下载执行、POSIX/Windows 敏感凭据路径保护、危险 Git 操作）
- [x] 实现 `ai-guard rule validate` 与 `ai-guard rule test` 纯内存模拟测试

### 1.4 Phase 3（M4）：`packages/backup` 事务备份、双环境 Hook 安装器与受管启动
- [x] 实现 `packages/backup` 跨平台快照创建、SHA-256 完整性校验与原子恢复底座
- [x] 实现针对宿主机 `.codex` 与 WSL2 `.codex` 的 `ai-guard install/uninstall codex`（支持 `--dry-run` Diff 预览、保留用户既有第三方 Hook）
- [x] 实现 `ai-guard run codex` 受管启动与 Preflight 安全检查

### 1.5 Phase 4（M5 + Phase 4B M1 迁移）：SQLite 脱敏审计、双环境事件同步与 Session 保护
- [x] 实现 `packages/storage` SQLite（WAL + 15ms 超时无锁 fallback）、敏感凭据自动脱敏器及 WSL2 审计事件向宿主机主库的增量同步归并
- [x] 实现 `ai-guard self-test codex --isolated` 一键隔离自检与 `ai-guard status --json` 四态汇总
- [x] **Phase 4B**：迁入原 M1 阶段 Codex Session 成果至 `packages/session`，支持对宿主机 `C:\Users\<User>\.codex` 与 WSL2 `~/.codex` 会话的统一只读索引浏览与 SHA-256 安全备份

### 1.6 Phase 5（M6 + M7）：Windows 宿主机 Tauri 2/独立桌面端与 V0.1 个人版发布
- [x] 实现宿主机主控桌面端（`apps/desktop`）及 `TargetManager`（本机直管 `WindowsHost` + `wsl.exe --exec` 受限桥接管理 `Wsl2Distro` 并自动下发 `ai-guard-linux` 探针与策略镜像）
- [x] 交付六大中文核心管理页面（安全概览、双环境 Agent 管理、安全策略、统一风险事件、防护诊断/安装/Session 备份、设置与隐私）
- [x] 支持 Windows 系统托盘常驻运行、管家式紧凑应用窗口（980x640）、条件框吸顶固定与数据区域独立滚动、静默无黑窗口启动
- [x] 完成宿主机独立运行与 WSL2 联动全量验收（`AT-01` ～ `AT-12` 与 `SEC-E2E-001` ～ `SEC-E2E-012`）及 V0.1 NSIS 安装包打包发布

### 1.7 Phase 5.5：Antigravity（AGY）与 agy CLI 全链路原生 Hook 管控
- [x] 输出《AGY 原生 Hook 协议真实契约规范》（`docs/AGY_HOOK_CONTRACT.md`）并在 PRD 与系统架构中确立技术方案
- [ ] 在 `packages/agent-adapters` 实现 `AgyHookAdapter`，完成 ProtoJSON 解析、四大工具（`run_command`、`write_file`、`edit_file`、`call_mcp_tool`）归一化映射与 Fail-Closed 默认阻断
- [ ] 在 `apps/local-service` 增加 `ai-guard hook agy pre-tool-use` 执行入口与 `ai-guard install agy` 事务安装/无损卸载
- [ ] 在 `packages/session` 与 `packages/backup` 实现 AGY 转录流（`transcript.jsonl`）与 `brain/` 工件只读索引与 SHA-256 安全备份
- [ ] 升级宿主机主控界面（`apps/desktop`），交付 Codex 与 AGY 双 Agent 并行治理看板与多源审计检索
- [ ] 开展 AGY 离线与端到端拦截测试（涵盖放行、高危命令拦截与异常阻断）

---

## 阶段二：Phase 6A（V0.2 ~ V0.3）多 Agent 扩展与 OS 内核级沙箱

1. **多 Agent 适配扩展（`packages/agent-adapters`）**
   - 接入 **Claude Code** 与 **OpenCode**，独立完成各自原生 Hook 协议契约与真实拦截 E2E 验证
2. **OS 级沙箱与防外传增强（`packages/security`）**
   - 开展 `nono` / Linux Landlock（WSL2 侧）及 Windows Job Object（宿主机侧）隔离 PoC，提供文件系统读写白名单与网络外传强制边界
3. **跨 Agent Session 治理升级（`packages/session`、`packages/backup`）**
   - 支持跨 Agent 会话检索、增量快照备份与带冲突检测的会话恢复

---

## 阶段三：Phase 6B（V1.0+）企业版商业能力演进（独立私有仓库）

1. **终端设备注册与资产盘点**：设备证书（mTLS）身份准入、在线状态监控与防护覆盖率盘点
2. **Ed25519 签名策略中心**：组织级强制安全基线下发（宿主机主控验签后统一下发至本机与 WSL2），防止终端私自降级规则
3. **集中脱敏审计与 RBAC**：基于 Rust Axum + PostgreSQL + OIDC 的多租户审计汇聚与私有化部署套件
