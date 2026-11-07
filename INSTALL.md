# 安装、卸载与恢复指南（INSTALL.md & UNINSTALL.md）

## 1. 无损安装流程

1. **预览变更（不修改任何磁盘文件）**：
   ```bash
   ai-guard install codex --target wsl2:Ubuntu --dry-run
   ai-guard install codex --target host:windows --dry-run
   ```
2. **正式安装（自动备份原配置并保留已有第三方 Hook）**：
   ```bash
   ai-guard install codex --target wsl2:Ubuntu --policy-source config/policy.default.toml --policy-dest ~/.config/ai-guard/policy.toml
   ```
3. **确认信任与隔离自检**：
   - 在 Codex 中运行 `/hooks` 确认 AI卫士钩子处于 `trusted` 状态。
   - 运行 `ai-guard self-test codex --target all --isolated` 执行端到端自检。
   - 运行 `ai-guard status --target all` 确认状态更新为 `protected_verified`。

---

## 2. 安全卸载与快照回滚流程

1. **预览卸载 Diff**：
   ```bash
   ai-guard uninstall codex --target wsl2:Ubuntu --dry-run
   ```
2. **执行安全卸载**：
   ```bash
   ai-guard uninstall codex --target wsl2:Ubuntu
   ```
   - 若卸载前检测到 `config.toml` 在安装后被外部修改，AI卫士会中止覆盖并返回 `AG-INSTALL-CONFLICT`。
   - 您可使用 `ai-guard backup list` 与 `ai-guard backup restore --id <backup_id>` 从 SHA-256 校验通过的快照一键恢复，或附加 `--force` 仅剥离 AI卫士受管段落。
