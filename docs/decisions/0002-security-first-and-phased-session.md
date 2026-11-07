# ADR-0002：安全拦截主线优先与 Backup/Session 分阶段汇入策略

- **状态**：已确认（Accepted）
- **日期**：2026-11-07
- **决策范围**：`packages/security`、`packages/agent-adapters`、`packages/backup`、`packages/session`

---

## 1. 背景（Context）

在评估初始方案包（`docs/AI_Guard_Implementation_Pack`）与项目早期 M1（Codex Session 管理）既有成果时，需要在“先做纯安全拦截”与“同时做 Session 管理”之间确定明确的研发优先级与架构边界。

## 2. 决策内容（Decision）

1. **V0.1 核心主线聚焦“真实执行前拦截闭环”**：
   - Phase 0 ～ Phase 2 集中全部研发资源打通 `codex-cli 0.160.1` 的原生 `PreToolUse` Hook 协议、Rust 确定性策略引擎以及隔离环境下的“Deny 后零副作用”端到端验证。
   - 在真实拦截闭环未通过前，不开发复杂 UI，也不将 Session 管理作为前置依赖。
2. **`packages/backup` 在 Phase 3 前置落地**：
   - `packages/backup` 首先服务于 Phase 3 的 Codex 配置文件（`config.toml` / `hooks.json`）与安全策略文件（`policy.toml`）的事务性备份、SHA-256 完整性校验与原子回滚。
3. **M1 Session 成果在 Phase 4B 阶段性汇入**：
   - 在 Phase 1 ～ Phase 4A 安全拦截与脱敏审计底座验收通过后，于 Phase 4B 将原 M1 阶段的 Codex Session 只读索引与备份能力对齐迁入 `packages/session`，复用 `packages/backup` 与 `packages/storage` 底座。

## 3. 后果与约束（Consequences）

- 保证了 AI卫士作为“AI 编程 Agent 安全工具”的核心差异化定位不失焦。
- 避免了 `packages/backup` 沦为空目录，实现了配置安全备份与会话安全备份的能力复用。
- 对本机 `~/.codex` 会话数据（含 `session_index.jsonl`、`thread_history_1.sqlite`）严格执行只读访问与变更前强制备份红线。
