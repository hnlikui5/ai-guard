# AI卫士实施任务拆解与验收清单

**版本：** V1.0 ｜ **目标：** 供 AGY/Codex 按阶段自动编码。  
**来源：** `AI_Guard_Full_Technical_Design_V1.0.md` + `AI卫士_产品需求文档_PRD_V0.1.md`。  
**当前真实状态：** 工程已初始化、完成首次 Git 提交；下面任务的“未开始”是基于目前已知状态，实施 Agent 必须先以仓库事实更新。  
**严格顺序：** M0 → M1 → M2 → M3 → M4 → M5 → M6 → M7。M8/M9 只保留路线图，未得到授权不实施。

## 0. 通用 Definition of Done（所有 Issue 必须满足）

- 以最新仓库事实为起点，不覆盖已有实现，不重写 Git 历史。
- 对应功能和规则必须有自动化测试；无法自动测试的 E2E 明确提供操作步骤与证据。
- 运行相关的 `cargo fmt`, `cargo clippy`, `cargo test`，将实际结果记录在 `docs/evidence/`；不存在命令就标记未配置，不编造输出。
- 改动不得静默放宽安全策略，不新增未经验证的网络开放端口，不记录完整秘密或未脱敏原始命令。
- 文档同步更新 CLI/API、配置 Schema、兼容矩阵、已知风险与回滚方案。
- 标明“设计 / 编码完成 / 单测通过 / 真实 E2E 通过 / 发布”五级状态；未完成真实 E2E 不得宣布 `protected_verified`。
- 新增第三方代码逐项登记版本、来源、许可证、NOTICE 与替代方案；`references/` 不打包、不进入发行物。

## M0：工程审计与协议基线（不可跳过）

**目标：** 先知道本机真正有些什么，再让 AGY 写代码。  
**依赖：** 已初始化仓库。  
**不包含：** 修改用户级 Codex 配置、安装 Hook 到真实环境。

### M0-01 核实工程现状与安装 Rust 工具链
- 工作：读取工作区、Git 状态、已有 `AGENTS.md`、文档与参考仓库；检查 `codex-cli 0.160.1`/Node/WSL2 版本；安装 WSL2 Rust stable 工具链（`rustc`/`cargo`/`clippy`/`rustfmt`）并创建 `rust-toolchain.toml`；识别旧 M1 代码迁移边界。
- 输出：`rust-toolchain.toml`、`docs/BASELINE.md`（实际版本、目录树、风险、可执行命令）、`docs/COMPATIBILITY.md` 初始空矩阵。
- 验收：不破坏原文件；报告明确“已存在”与“拟新增”；版本从真实命令读取。

### M0-02 固定 Codex 0.160.1 Hook 协议与 Daemon 交互
- 工作：阅读官方 Hooks 文档并在隔离临时目录（`CODEX_HOME=/tmp/...`）实测本机 `codex-cli 0.160.1` 的实际 Hook 支持（含 `Bash`、`unified_exec`、`write_stdin`、`apply_patch`、MCP 工具名映射及 `app-server-daemon` 刷新行为）；保存已去敏的测试输入输出与版本信息；验证非托管 Hook 的信任流。
- 输出：`tests/fixtures/codex/`、`docs/CODEX_HOOK_CONTRACT.md`、协议版本证据。
- 验收：能说明哪些工具在当前版本的 PreToolUse 内、哪些不能、Hook 未信任及后台 daemon 存在时如何表现；尚不宣称真实阻断。
- 暂停条件：Codex 版本不可用或不能验证协议时保留不确定项，**不能凭参考文档猜测运行结果**。

### M0-03 锁定安全边界 ADR
- 工作：确认首发只支持 WSL2 Codex CLI、不是 EDR/全网 DLP；明确“安全主线优先 + `packages/backup` 事务备份前置 + Phase 4B 汇入 M1 Session 只读保护”策略；明确安全状态的四类定义。
- 输出：`docs/decisions/0001-tech-stack-and-license.md`、`docs/decisions/0002-security-first-and-phased-session.md`、`docs/decisions/0003-wsl2-execution-and-desktop-bridge.md`。
- 验收：后续 Agent 严格遵循安全主线优先，不跳过真实拦截门禁。

**M0 Gate：** `BASELINE.md`、`COMPATIBILITY.md`、Hook 契约和测试计划齐全；只读检查完成。

## M1：Rust 核心与最小 CLI

### M1-01 Rust CLI 构建
- 工作：建立或调整现有 `apps/local-service`，实现最小 `ai-guard --version`, `doctor --json`, `rule test`；支持 `--help` 和结构化错误。
- 设计文件：`apps/local-service/src/main.rs`, `cli.rs`，必要的 Cargo workspace 配置。
- 测试：无 Codex 环境 doctor 不能 panic；JSON 错误输出符合契约。
- 依赖：M0 Gate。

### M1-02 ActionEvent/Decision 域模型
- 工作：最小统一事件、决策、覆盖能力与原因码；类型安全；不把 Codex 原 JSON 泄漏到策略核心。
- 目标文件：`packages/security` 或现有 Rust module。
- 测试：序列化/反序列化、未知工具类型、极端长度、完整匹配解释。

### M1-03 CodexHookAdapter 协议实现
- 工作：stdin JSON → ActionEvent；Decision → Codex PreToolUse Deny JSON；Allow 使用官方支持的空输出。非协议日志只写 stderr。
- 目标文件：`packages/agent-adapters` 与 `apps/local-service/src/hook.rs`。
- 测试：至少 15 个 Hook 夹具；输入丢字段、错类型、过长、异常 UTF-8 不 panic；Deny 输出可解析。

### M1-04 核心错误处理与敏感字段保护
- 工作：统一错误码，输出限制，Rust 捕获可处理错误后尽可能输出符合协议的显式 Deny；日志默认不包含 raw tool_args。
- 测试：伪造 `SECRET_TEST_XYZ` 在 stdout/stderr/事件记录中不可见。

**M1 Gate：** Rust 可编译、协议 Mock 测试通过、CLI 只读运行正常；“真实执行阻断”仍显示待验证。

## M2：真实 Codex 执行前拦截 PoC（产品生死线）

### M2-01 最小 Hook 安装测试环境
- 工作：在独立临时目录/临时 HOME 和临时测试项目建立 Codex Hook 设置；用绝对路径 Rust binary；避免修改真实 `~/.codex`。
- 输出：`tests/e2e/codex_pretool_allow_deny.md`、自动化测试脚本（能自动则自动）。
- 测试：当前 Codex 版本确认 Hook 加载并得到真实测试日志。

### M2-02 执行前拒绝 E2E
- 工作：定义测试规则，拒绝带 `AI_GUARD_BLOCK_ME` 标记的无害 Shell 命令（例如写入临时 sentinel 文件）。
- 验收：真实 Codex 产生指定操作请求 → Hook Deny → **临时 sentinel 文件不存在** → 事件记录匹配；附 Codex 版本、运行命令、退出码、测试文件清单。
- 不得用“直接对 `ai-guard hook` 发 JSON”代替真实 E2E。

### M2-03 正常操作 Allow E2E
- 工作：允许临时目录内正常 `pwd`、`echo`、`git status` 类测试，证明不严重误阻断。
- 验收：真实 Codex 测试操作正常完成，日志不泄露用户数据。

### M2-04 Hook 故障与绕过事实记录
- 工作：测试 Hook 未信任、关闭、丢失、超时、格式错误；记录 Codex 的实际反应。
- 输出：`docs/COMPATIBILITY.md` 对每种情况明确 `blocked/continued/unknown`。
- 验收：任何 fail-open 场景都记录清楚，界面后续不得误称受保护。

**M2 Gate：** 真实 E2E “Deny + 无副作用”通过。**若失败，阻塞后续产品安全功能：只允许修复兼容和安全问题。**

## M3：策略规则与诊断能力

### M3-01 策略 Schema 与编译校验
- 工作：TOML schema_version/revision/mode/rules/priority/effect；未知或非法规则不能静默放宽；本地可信快照。
- 验收：规则正例/反例，非法规则、文件损坏和回滚测试通过。

### M3-02 基础危险命令规则
- 工作：从高置信度规则开始（测试标记、少量删除风险、下载即执行）。建立误报/漏报夹具，复杂命令返回部分覆盖而不是谎称安全。
- 验收：至少 20 个正例/40 个正常反例，全部固定规则可解释。

### M3-03 敏感路径与 Patch 检测
- 工作：结构化 `apply_patch` 目标、已知危险路径、路径标准化/符号链接风险标注。无法可靠解析时不给“完全安全”标签。
- 验收：相对/绝对路径、路径遍历、符号链接用例；明确未覆盖的动态执行。

### M3-04 `rule test` 与规则回滚
- 工作：命令不执行仅模拟判定，输出命中规则和原因，支持用户导入前验证与规则版本回滚。
- 验收：差异预览、版本记录与回滚后结果可复现。

**M3 Gate：** 规则引擎行为确定、异常规则有安全行为、误报有评估报告。

## M4：安全安装、受管启动与恢复

### M4-01 配置发现 + 安装预览
- 工作：识别用户级/项目级 Hooks；JSON/TOML 保留已有项；产生仅由用户确认的变更差异。
- 验收：已存在第三方 Hook 不丢失；安装前不修改文件。

### M4-02 基于 `packages/backup` 的安装/卸载原子性与冲突处理
- 工作：在 `packages/backup` 实现带 SHA-256 `manifest.json` 的快照备份、完整性校验与原子恢复；修改 Codex 配置前强制备份原配置、临时文件写入、权限校验、原子替换；卸载仅移除本产品标记段。
- 验收：模拟断电/写入失败/备份篡改校验拒止/冲突；旧配置可恢复；不覆盖用户新变更。

### M4-03 受管启动 `ai-guard run codex`
- 工作：预检 Hook 路径、配置启用、规则版本、最近自检，失败则拒绝代启动；不通过命令拼接执行 Codex。
- 验收：禁用 Hook、删掉二进制、配置损坏时受管启动失败并解释原因；正常时可启动。

### M4-04 Hook 信任诊断与修复指引
- 工作：提供 `/hooks` 信任向导、状态诊断、失效修复预览；不尝试绕过非托管 Hook 信任。
- 验收：不把 `hooks.json` 存在当作 verified。

**M4 Gate：** 安装、升级、回滚、卸载和已有用户配置安全性通过。

## M5：本地安全事件与质量闭环

### M5-01 SQLite Schema、WAL 与 15ms 超时无锁 Fallback
- 工作：按技术方案在 `packages/storage` 创建 `security_events`, `policy_revisions`, `integration_state`, `self_test_runs`；开启 WAL 模式与 `busy_timeout = 15ms`；若写库锁超时或失败，立即输出 Hook 协议结果并将脱敏事件追加至 `events-fallback.jsonl`。
- 验收：schema 升级、数据库锁定 15ms 熔断降级、数据损坏、并发插入均有测试，绝不因写库阻塞引发 Hook 超时。

### M5-05（Phase 4B 扩展）M1 Codex Session 只读索引与安全备份
- 工作：在安全主线（M1~M5-04）通过后，于 `packages/session` 对接本机 `~/.codex/session_index.jsonl` 与 `thread_history_1.sqlite`（强制只读打开），结合 `packages/backup` 提供会话列表、详情查询与带 SHA-256 校验的快照备份。
- 验收：对 `~/.codex` 会话目录零修改，备份与校验闭环测试通过。

### M5-02 脱敏审计、分页与导出
- 工作：Hook 记录最小化事件；事件查询支持限制/分页/过滤，脱敏 JSON/CSV 导出。
- 验收：伪造 Secret 不在数据库、日志和导出包内出现；审计失败不改变 Deny 决策。

### M5-03 防护状态汇总
- 工作：`status --json` 返回覆盖矩阵四态、上次自检与已知盲区；准确反映运行时错误。
- 验收：未信任/未验证/失败状态不能显示 protected_verified。

### M5-04 自检向导与证据包
- 工作：临时测试目录的允许/拒绝 E2E，可导出无密钥的测试报告，追溯版本及规则修订。
- 验收：缺少真实 Codex 测试结果时状态为 unknown/partial，不自动补成功记录。

**M5 Gate：** 事件、规则、自检之间可追溯，脱敏与失败路径通过。

## M6：Windows Tauri 2 中文桌面端

### M6-01 Desktop 最小项目
- 工作：依现有框架初始化 Tauri 2 + React/TS，中文默认，合理的菜单和状态框架。
- 验收：Windows 上可以启动并显示“未连接/未知”而不伪造数据。

### M6-02 `wsl.exe --exec` 受限桥接
- 工作：Tauri Rust Command 用 argv 指向固定子命令，选择已明确 WSL 发行版和 Rust 二进制；JSON 有严格 schema、长度和超时。
- 验收：输入恶意 Shell 文本不能成为可执行命令；WSL 未启动/未安装/超时错误清楚。

### M6-03 6 大页面基础交付
- 工作：概览、Agent、策略、事件、诊断、设置（安装/恢复也可独立导航）；与 CLI 真实数据绑定。
- 验收：全部页面空/错/加载态，简体中文默认，不能靠假数据驱动状态颜色。

### M6-04 配置预览与安装事务 UI
- 工作：策略变更/Hook 安装二次确认、文件差异预览、结果通知、回滚入口。
- 验收：关闭 UI 不影响 WSL 内已经安装的 Rust Hook；修改失败有回退提示。

**M6 Gate：** Windows/WSL2 独立部署联调成功，所有状态来自真实服务。

## M7：发布质量与开源合规

### M7-01 全新环境安装/更新/卸载测试
- 工作：干净 Windows+WSL2 环境、全新 Codex/已有 Codex 两类安装；安装包/CLI 不篡改真实配置。
- 验收：产品正常启用、自检、卸载和恢复原配置。

### M7-02 CI 与依赖/许可检查
- 工作：Cargo format, clippy, test；UI lint/typecheck/build；SBOM、依赖许可证、Secret scan、第三方 NOTICE。
- 验收：构建可复现，生成测试与依赖报告，无真实密钥。

### M7-03 文档与安全声明
- 工作：README、SECURITY、PRIVACY、INSTALL、UNINSTALL、LIMITATIONS、COMPATIBILITY，明确个人版边界；许可证需人工决定。
- 验收：用户能理解“Hook 防护 ≠ OS 全面隔离”。

### M7-04 发布候选与验收回顾
- 工作：创建候选产物、校验 SHA256、发布说明；**不得未经授权上传 GitHub Release、自动推送或使用签名凭据**。
- 验收：发布检查清单由人审阅，列出所有剩余已知安全盲区。

**M7 Gate：** 满足 V0.1-GA 的核心验收，才允许用“AI卫士个人版 V0.1”对外分发。

## M8：V0.2 增强（将来单独立项）

- **M8-01** Agent Adapter V2：OpenCode 或 Claude Code 的首个新适配器，独立 Hook E2E。
- **M8-02** SessionProvider：只读列表、详情、源数据版本兼容。
- **M8-03** SessionBackup：带哈希 Manifest 的备份和完整性校验。
- **M8-04** SessionRestore：运行中保护、冲突预览、恢复回滚、兼容性测试。
- **M8-05** nono PoC：WSL2 内核能力检测与沙箱生效证明。
- **M8-06** MCP/网络专项 PoC：按接入覆盖实际验证，不能称为全流量控制。

## M9：企业版试点（将来单独立项）

- **M9-01** 产品验证与真实客户权限模型；明确租户/组织/设备/角色。
- **M9-02** 设备注册、证书和撤销流程。
- **M9-03** 策略 Ed25519 签名发布与离线快照。
- **M9-04** OIDC/RBAC、最小管理 UI。
- **M9-05** 脱敏审计批量上报、租户隔离、数据保留。
- **M9-06** 私有化部署与管理员安全审计。

## 每阶段交接报告模板（由 Codex/AGY 填写真实证据）

```markdown
# Mx 阶段交接
- 状态：未开始 / 进行中 / 编码完成 / 单测通过 / 真实 E2E 通过 / 待人工确认
- 本次 Issue：Mx-xx
- 实际修改的文件：
- 安全边界变化：
- 测试命令、退出码和证据文件：
- 当前 Codex 版本、Rust 版本、OS/WSL 版本：
- 真实行为与预期差异：
- 新增未解决风险：
- 回滚方式：
- Git diff / Commit：
- 是否涉及需人工授权动作（修改全局配置/提权/推送/发布）：
- 下一步计划：
```

**执行纪律：** Agent 可以连续开展已经授权的低风险本地开发与测试；遇到失败门禁必须停在相应阶段解决问题；不能为了完成进度跨越“真实拒绝 E2E”这个核心门槛。
