# 安全策略与隐私保护说明（SECURITY.md & PRIVACY.md）

## 1. 默认安全红线（Fail-Closed）

1. **协议层 Fail-Closed**：当 `PreToolUse` 输入为空、超过 1 MiB、非合法 UTF-8、JSON 语法损坏或缺失必填字段时，`packages/agent-adapters` 100% 返回显式 `Deny` 决策。
2. **策略层 Fail-Closed**：当自定义 `policy.toml` 损坏时，优先回退至最近一次验证通过的可信快照（`policy.last_good.toml`）；若无可用快照，立即返回 `AG-POLICY-001` 拒绝执行。
3. **网络监听隔离**：`ai-guard serve` 强制校验绑定地址必须属于本地回路（`127.0.0.1` 或 `[::1]`），拒绝绑定 `0.0.0.0` 或任何局域网网卡。
4. **跨环境桥接零拼接**：宿主机调用 WSL2 探针时，强制使用独立 `argv` 数组（`wsl.exe --distribution <distro> --exec ...`），并拦截控制字符与 `-` 前缀选项注入。

## 2. 隐私与敏感信息保护（PRIVACY）

1. **100% 本地离线运行**：个人版 V0.1 不包含任何遥测上报、外部网络请求或云端同步逻辑。
2. **二次强制脱敏**：在协议层与存储/导出层双重调用 `redact_secrets`，自动抹除 OpenAI API Key（`sk-*`）、GitHub Token（`ghp_*` / `github_pat_*`）、AWS AKIA、Slack Token、Bearer 凭据、环境变量密钥赋值及 PEM/SSH 私钥块。
3. **源会话 100% 只读**：访问用户 `.codex` 目录下的 SQLite 数据库时，强制使用 `file:<path>?mode=ro&immutable=1`（`SQLITE_OPEN_READ_ONLY`），绝不修改原文件哈希或时间戳。
