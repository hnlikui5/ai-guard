# AI卫士（AI Guard）— 个人版 V0.1

**AI卫士（AI Guard）** 是一款运行于 **Windows 宿主机**、同时纳管 **Windows 宿主机本机 Codex（Desktop / CLI）** 与 **WSL2 子系统 Codex CLI** 的本地执行前安全防火墙、脱敏审计与会话只读保护系统。

---

## 1. 核心架构亮点（宿主机中心化 + 双环境就地拦截）

- **宿主机中心化主控**：主控桌面端（Tauri 2 + React）与控制服务运行在 Windows 宿主机，仅监听本地回路 `127.0.0.1:17900`。
- **双环境就地极速拦截**：
  - **宿主机目标（`host:windows`）**：挂载 `ai-guard.exe hook codex pre-tool-use`。
  - **WSL2 目标（`wsl2:<distro>`）**：自动分发 `~/.local/bin/ai-guard-linux` 原生探针并镜像同步 `policy.toml`，实现微秒级就地拦截（P95 `< 0.25ms`），避免跨 OS 管道延迟。
- **默认安全（Fail-Closed）**：输入为空、超长（> 1 MiB）、非法 UTF-8、JSON 损坏、缺失必填字段或策略文件损坏且无可用快照时，100% 默认返回 `Deny`。
- **15ms 无锁审计降级与二次强制脱敏**：SQLite WAL 模式 + 15ms 超时熔断降级 `events-fallback.jsonl`；所有落盘与导出数据经过二次 `redact_secrets` 清洗，真实密钥 0 落盘。
- **会话 100% 只读保护与 SHA-256 事务备份**：通过 `file:<path>?mode=ro&immutable=1` 只读打开 Codex SQLite 会话库，修改任何配置前强制生成带 SHA-256 `manifest.json` 的事务备份。

---

## 2. 快速开始（CLI 核心命令）

```bash
# 1. 诊断宿主机与 WSL2 双环境状态
ai-guard status --target all --json

# 2. 运行双环境隔离沙箱自检（不触碰真实 ~/.codex）
ai-guard self-test codex --target all --isolated --json

# 3. 校验策略文件与离线模拟测试规则
ai-guard rule validate --path config/policy.default.toml --json
ai-guard rule test --tool Bash --input "rm -fr ~/Documents" --cwd "/workspace" --json

# 4. 预览无损安装 Unified Diff（--dry-run 不修改磁盘）
ai-guard install codex --target wsl2:Ubuntu --dry-run

# 5. 只读查看与备份双环境 Codex 会话
ai-guard session list --target all --limit 20
ai-guard session backup <session_id> --target wsl2:Ubuntu

# 6. 启动本地回路控制平面与桌面 Web 视图（仅限 127.0.0.1）
ai-guard serve --bind 127.0.0.1:17900 --static-dir apps/desktop/dist
```

---

## 3. 安全声明与能力边界

请在使用前务必阅读：
- `SECURITY.md`：安全架构与漏洞报告流程
- `LIMITATIONS.md`：个人版 V0.1 能力边界与已知盲区（**Hook 防护 ≠ OS 内核级全面隔离**）
- `PRIVACY.md`：本地零上传承诺与二次脱敏机制
- `INSTALL.md` / `UNINSTALL.md`：无损安装、卸载与故障恢复指南
