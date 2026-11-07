# AI卫士（AI Guard）卸载与回滚指南（UNINSTALL.md）

## 1. 一键无损卸载并恢复原始配置

AI卫士提供事务级非破坏性卸载能力，仅移除包含 `"__ai_guard_managed": true` 标记的受管节点，完整保留用户的自定义配置与第三方 Hook：

```bash
# 卸载当前环境 Codex 防护并恢复安装前快照
ai-guard uninstall codex

# 在 Windows 宿主机卸载指定 WSL2 发行版内的 Codex 防护
ai-guard uninstall codex --target wsl --distro Ubuntu
```

卸载完成后，工具会自动计算恢复后的 `hooks.json` 与 `config.toml` 的 SHA-256 哈希，并与安装前备份快照（`manifest.json`）逐字节比对。

---

## 2. 使用备份快照手动回滚

若需回滚到任意历史备份时间点：

```bash
# 1. 查看本地所有备份快照及 SHA-256 摘要
ai-guard uninstall codex --dry-run

# 2. 指定快照 ID 恢复并校验 SHA-256
ai-guard uninstall codex --snapshot-id <SNAPSHOT_ID>
```

---

## 3. 紧急手工恢复（当 `ai-guard` 二进制已被删除时）

如果 `ai-guard` 二进制文件已被提前删除，可按以下步骤手工恢复：

1. 打开 `~/.codex/hooks.json`（Windows 为 `%USERPROFILE%\.codex\hooks.json`）：
   - 删除包含 `"__ai_guard_managed": true` 的 Hook 条目；若无其他 Hook，可直接从 `~/.local/share/ai-guard/backups/<最新快照ID>/files/` 考回原始文件。
2. 打开 `~/.codex/config.toml`：
   - 若无需使用其他 Hook，可将 `[features]` 下的 `codex_hooks = true` 恢复为原值。
3. 清理本地数据目录（可选）：
   - Linux / WSL2：`rm -rf ~/.local/share/ai-guard`
   - Windows 宿主机：`Remove-Item -Recurse -Force "$env:LOCALAPPDATA\AIGuard"`
