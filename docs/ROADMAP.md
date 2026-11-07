# AI卫士（AI Guard）产品研发路线图（Roadmap）

本文档规划 **AI卫士（AI Guard）** 从 V0.1 个人版基线到多 Agent 扩展及未来企业版演进的阶段性研发目标。各阶段详细功能规格、接口契约与验收门禁以 `docs/PRD_V0.1.md` 为准。

---

## 阶段一：V0.1 个人版分阶段研发（Phase 0 ～ Phase 5）

**核心策略**：坚持“**安全主线优先（真实 Hook 拦截 + 零副作用证明）+ `packages/backup` 事务备份前置 + M1 Session 成果阶段性汇入**”。

### 1.0 已完成基线：工程初始化与规划定稿
- [x] 建立模块化单体工程目录结构与 `AGENTS.md` 开发规范
- [x] 完成 `references/hol-guard`（v3.59.0）只读参考区引入与登记
- [x] 确定 Apache License 2.0 开源许可证与 Rust 核心技术栈（`ADR-0001` ～ `ADR-0003`）
- [x] 完成分阶段开发 PRD（`docs/PRD_V0.1.md`）评估优化与定稿

### 1.1 Phase 0（M0）：环境基线审计与 Codex 0.160.1 Hook 协议实测
- [ ] 安装 WSL2 Rust stable 工具链并锁定 `rust-toolchain.toml`
- [ ] 在隔离临时目录实测本机 `codex-cli 0.160.1` 的 `PreToolUse` Hook 输入/输出协议、工具名映射及 `app-server-daemon` 交互行为
- [ ] 输出 `docs/BASELINE.md`、`docs/CODEX_HOOK_CONTRACT.md`、`docs/COMPATIBILITY.md` 与 `tests/fixtures/codex/`

### 1.2 Phase 1（M1 + M2）：Rust 安全内核与真实执行前拦截 PoC（产品生死线）
- [ ] 建立根 `Cargo.toml` Workspace，打通 `apps/local-service`（`ai-guard` CLI）与 `packages/*`
- [ ] 实现 `ActionEvent` / `Decision` 领域模型、`CodexHookAdapter` 及异常默认拒绝（Fail-Closed）机制
- [ ] 在隔离环境中通过真实 `codex-cli 0.160.1` 执行前拒绝（Deny）E2E 验证，证明副作用文件未生成

### 1.3 Phase 2（M3）：TOML 策略引擎、内置高危规则包与离线测试
- [ ] 实现 `policy.toml` 编译校验、优先级裁决与防降级快照回退
- [ ] 交付 V0.1 内置高置信度规则集（破坏性 Shell、管道下载执行、敏感凭据路径保护、危险 Git 操作）
- [ ] 实现 `ai-guard rule validate` 与 `ai-guard rule test` 纯内存模拟测试

### 1.4 Phase 3（M4）：`packages/backup` 事务备份、Hook 安装器与受管启动
- [ ] 实现 `packages/backup` 快照创建、SHA-256 完整性校验与原子恢复底座
- [ ] 实现 `ai-guard install/uninstall codex`（支持 `--dry-run` Diff 预览、保留用户既有第三方 Hook）
- [ ] 实现 `ai-guard run codex` 受管启动与 Preflight 安全检查

### 1.5 Phase 4（M5 + Phase 4B M1 迁移）：SQLite 脱敏审计、四态自检与 Session 保护
- [ ] 实现 `packages/storage` SQLite（WAL + 15ms 超时无锁 fallback）与敏感凭据自动脱敏器
- [ ] 实现 `ai-guard self-test codex --isolated` 一键隔离自检与 `ai-guard status --json` 四态汇总
- [ ] **Phase 4B**：迁入原 M1 阶段 Codex Session 成果至 `packages/session`，支持会话只读索引浏览与 SHA-256 安全备份

### 1.6 Phase 5（M6 + M7）：Windows Tauri 2 中文桌面端与 V0.1 个人版发布
- [ ] 实现 Windows Tauri 2 到 WSL2 `ai-guard` 的受限白名单 `wsl.exe --exec` 桥接（同时预留 Windows 原生 `ai-guard.exe` 通道）
- [ ] 交付六大中文核心管理页面（安全概览、Agent 管理、安全策略、风险事件、防护诊断/安装、设置与隐私）
- [ ] 完成 `AT-01` ～ `AT-12` 与 `SEC-E2E-001` ～ `SEC-E2E-012` 全量验收及 V0.1 开源合规发布

### 1.7 Phase 5.5（V0.1.5）：Codex 桌面应用（Codex Desktop App）全模式支持
- [ ] 验证并打通 **Codex 桌面应用 WSL2 工作区模式** 的 `app-server-daemon` Hook 热刷新与拦截闭环
- [ ] 编译分发 Windows 原生 `ai-guard.exe`，支持 **Codex 桌面应用 Windows 原生模式**（`C:\Users\<User>\.codex`）的 Hook 安装、PowerShell/CMD 高危命令拦截与 Session 统一纳管

---

## 阶段二：Phase 6A（V0.2 ~ V0.3）多 Agent 扩展与 OS 内核级沙箱

1. **多 Agent 适配扩展（`packages/agent-adapters`）**
   - 接入 **Claude Code** 与 **OpenCode**，独立完成各自原生 Hook 协议契约与真实拦截 E2E 验证
2. **OS 级沙箱与防外传增强（`packages/security`）**
   - 开展 `nono` / Linux Landlock 内核隔离 PoC，提供文件系统读写白名单与网络外传（Pipelock 思路）强制边界
3. **跨 Agent Session 治理升级（`packages/session`、`packages/backup`）**
   - 支持跨 Agent 会话检索、增量快照备份与带冲突检测的会话恢复

---

## 阶段三：Phase 6B（V1.0+）企业版商业能力演进（独立私有仓库）

1. **终端设备注册与资产盘点**：设备证书（mTLS）身份准入、在线状态监控与防护覆盖率盘点
2. **Ed25519 签名策略中心**：组织级强制安全基线下发，防止终端私自降级规则
3. **集中脱敏审计与 RBAC**：基于 Rust Axum + PostgreSQL + OIDC 的多租户审计汇聚与私有化部署套件
