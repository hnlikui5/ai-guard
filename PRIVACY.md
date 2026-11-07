# AI卫士（AI Guard）隐私声明（PRIVACY.md）

## 1. 零遥测承诺（Zero Telemetry by Default）

- **默认无网络外联**：AI卫士（AI Guard）个人版 V0.1 全部安全策略判定、Hook 裁决、审计事件落盘与 Session 索引均在用户本机（Windows 宿主机及 WSL2 子系统）100% 离线完成。
- **不收集任何用户数据**：不包含任何第三方统计 SDK、崩溃上报服务或云端遥测接口。

---

## 2. 本地数据存储位置与范围

1. **审计数据库（SQLite WAL）**：
   - Windows 宿主机：`%LOCALAPPDATA%\AIGuard\data\events.db`
   - WSL2 Linux：`~/.local/share/ai-guard/events.db`
   - 失败降级队列：`events-fallback.jsonl`
2. **配置文件与事务备份**：
   - 事务备份目录：`~/.local/share/ai-guard/backups/<snapshot_id>/`
   - 仅备份受管配置文件（`config.toml`、`hooks.json`）及用户显式触发备份的 Codex 会话文件。
3. **只读会话访问**：
   - 读取 Codex 会话历史时固定采用 `file:<path>?mode=ro&immutable=1` 只读不可变模式，绝不修改或上传用户的 Prompt 正文。

---

## 3. 敏感信息自动脱敏（Secret Redaction）

在写入本地 SQLite 审计库、降级 JSONL 队列、桌面端 UI 展示以及导出诊断包（CSV / JSON）前，所有命令参数与结果摘要均强制经过 `packages/security::redactor` 脱敏处理，自动掩码：
- OpenAI / Anthropic / GitHub / AWS / Google Cloud API Key 与 Token
- `Authorization: Bearer` 凭证头与 `password` / `secret` / `token` 键值对
- PEM 私钥块（RSA / EC / OPENSSH PRIVATE KEY）
