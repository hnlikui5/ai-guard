use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "ai-guard",
    version,
    about = "AI卫士（AI Guard）— 宿主机中心化主控与 WSL2 双环境 AI 编程 Agent 本地执行前安全防火墙"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// 本地回路监听地址（直接运行且未指定子命令时生效，默认 127.0.0.1:17900）
    #[arg(long)]
    pub bind: Option<String>,

    /// 是否在启动后自动打开系统默认浏览器（直接运行且未指定子命令时生效，默认 true）
    #[arg(long)]
    pub open: Option<bool>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// 只读诊断宿主机与 WSL2 双环境 Codex 安装状态、Hook 配置与防护健康度
    Doctor {
        /// 目标环境过滤：all | host | wsl2:<distro>
        #[arg(long, default_value = "all")]
        target: String,

        /// 以机器可读的脱敏 JSON 格式输出诊断报告
        #[arg(long)]
        json: bool,
    },

    /// 查询双环境四态防护状态汇总（protected_verified / partially_protected / unprotected / unknown）
    Status {
        /// 目标环境过滤：all | host | wsl2:<distro>
        #[arg(long, default_value = "all")]
        target: String,

        /// 显式指定目标 .codex 目录路径（可选）
        #[arg(long)]
        codex_home: Option<String>,

        /// 显式指定审计数据库路径（可选）
        #[arg(long)]
        db_path: Option<String>,

        /// 以 JSON 格式输出四态状态汇总
        #[arg(long)]
        json: bool,
    },

    /// 在隔离临时沙箱中执行 Allow/Deny 端到端自检并记录证据（绝不触碰真实 ~/.codex）
    SelfTest {
        #[command(subcommand)]
        agent: SelfTestAgents,
    },

    /// 查询、跨环境拉取或导出二次脱敏后的安全审计事件
    Events {
        #[command(subcommand)]
        subcommand: EventsSubcommands,
    },

    /// 宿主机与 WSL2 双环境 Codex 会话严格只读索引与 SHA-256 快照备份
    Session {
        #[command(subcommand)]
        subcommand: SessionSubcommands,
    },

    /// 离线校验策略语法或模拟规则裁决（绝不真实执行任何被测命令）
    Rule {
        #[command(subcommand)]
        subcommand: RuleSubcommands,
    },

    /// 无损安装或预览 Agent 安全防护钩子（强制先备份，保留已有配置与第三方 Hook）
    Install {
        #[command(subcommand)]
        agent: InstallAgents,
    },

    /// 安全卸载 Agent 安全防护钩子（仅移除 AI卫士受管段落，带外部修改冲突保护）
    Uninstall {
        #[command(subcommand)]
        agent: UninstallAgents,
    },

    /// 受管安全启动 Agent（先执行 4 项安全预检，失败即 Fail-Closed 拒绝启动）
    Run {
        #[command(subcommand)]
        agent: RunAgents,
    },

    /// 管理 SHA-256 事务备份（列表、完整性校验、原子恢复）
    Backup {
        #[command(subcommand)]
        subcommand: BackupSubcommands,
    },

    /// Agent Hook 极速裁决热路径入口（供 Codex PreToolUse 调用）
    Hook {
        #[command(subcommand)]
        agent: HookAgents,
    },

    /// 启动仅监听本地回路（127.0.0.1）的桌面控制平面服务（供 apps/desktop 调用）
    Serve {
        /// 本地回路监听地址（严禁指定 0.0.0.0 或外部网卡地址）
        #[arg(long, default_value = "127.0.0.1:17900")]
        bind: String,

        /// 是否在启动后自动打开系统默认浏览器
        #[arg(long, default_value_t = true)]
        open: bool,

        /// 静态前端资源目录（可选，如 apps/desktop/dist；未指定时自动使用内置独立控制台）
        #[arg(long)]
        static_dir: Option<String>,

        /// 显式指定审计数据库路径
        #[arg(long)]
        db_path: Option<String>,

        /// 显式指定备份仓库根目录
        #[arg(long)]
        backup_dir: Option<String>,

        /// 显式指定策略文件路径
        #[arg(long)]
        policy_path: Option<String>,

        /// 测试模式：处理指定数量的请求后自动退出
        #[arg(long)]
        max_requests: Option<usize>,
    },
}

#[derive(Debug, Subcommand)]
pub enum SelfTestAgents {
    /// 执行 Codex PreToolUse 隔离自检
    Codex {
        /// 目标环境标识：all | host:windows | wsl2:Ubuntu
        #[arg(long, default_value = "all")]
        target: String,

        /// 在隔离沙箱目录中运行自检（默认开启）
        #[arg(long, default_value_t = true)]
        isolated: bool,

        /// 显式指定审计数据库路径
        #[arg(long)]
        db_path: Option<String>,

        /// 以 JSON 格式输出自检报告
        #[arg(long)]
        json: bool,
    },
    /// 执行 OpenCode PreToolUse 隔离自检
    Opencode {
        /// 目标环境标识：all | host:windows | wsl2:Ubuntu
        #[arg(long, default_value = "all")]
        target: String,

        /// 在隔离沙箱目录中运行自检（默认开启）
        #[arg(long, default_value_t = true)]
        isolated: bool,

        /// 显式指定审计数据库路径
        #[arg(long)]
        db_path: Option<String>,

        /// 以 JSON 格式输出自检报告
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum EventsSubcommands {
    /// 分页查询并过滤脱敏安全审计事件
    List {
        /// 目标环境过滤：all | host | wsl2:<distro>
        #[arg(long, default_value = "all")]
        target: String,

        /// 按裁决结果过滤：deny | allow | observe
        #[arg(long)]
        decision: Option<String>,

        /// 起始时间戳（毫秒）或相对时长（如 24h / 60m）
        #[arg(long)]
        since: Option<String>,

        /// 最大返回条数
        #[arg(long, default_value_t = 50)]
        limit: usize,

        /// 显式指定审计数据库路径
        #[arg(long)]
        db_path: Option<String>,

        /// 以 JSON 格式输出
        #[arg(long)]
        json: bool,
    },

    /// 按游标拉取增量审计事件（供宿主机主控从 WSL2 缓冲库同步归并）
    Pull {
        /// 起始毫秒时间戳游标
        #[arg(long, default_value_t = 0)]
        since: u64,

        /// 目标环境过滤（可选）
        #[arg(long)]
        target: Option<String>,

        /// 单次拉取最大条数
        #[arg(long, default_value_t = 500)]
        limit: usize,

        /// 源审计库路径（如 WSL2 缓冲库）
        #[arg(long)]
        db_path: Option<String>,

        /// 可选：直接将拉取到的事件幂等合入指定的宿主机主库路径
        #[arg(long)]
        merge_into_db: Option<String>,

        /// 以 JSON 格式输出
        #[arg(long)]
        json: bool,
    },

    /// 导出二次强制脱敏后的审计报告（支持 JSON 与 CSV）
    Export {
        /// 导出文件输出路径
        #[arg(long)]
        output: String,

        /// 强制启用二次脱敏校验（默认开启）
        #[arg(long, default_value_t = true)]
        redacted: bool,

        /// 导出格式：json | csv
        #[arg(long, default_value = "json")]
        format: String,

        /// 目标环境过滤：all | host | wsl2:<distro>
        #[arg(long, default_value = "all")]
        target: String,

        /// 显式指定审计数据库路径
        #[arg(long)]
        db_path: Option<String>,

        /// 以 JSON 格式输出导出结果摘要
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum SessionSubcommands {
    /// 只读列出宿主机与 WSL2 下的 Codex 会话索引
    List {
        /// 目标环境过滤：all | host | wsl2:<distro>
        #[arg(long, default_value = "all")]
        target: String,

        /// 显式指定 .codex 目录路径（可选）
        #[arg(long)]
        codex_home: Option<String>,

        /// 每个目标环境最多返回条数
        #[arg(long, default_value_t = 50)]
        limit: usize,

        /// 以 JSON 格式输出
        #[arg(long)]
        json: bool,
    },

    /// 只读查看指定 Codex 会话详情
    Show {
        /// 会话 ID（支持完整 UUID 或前缀匹配）
        id: String,

        /// 目标环境：host:windows | wsl2:Ubuntu
        #[arg(long, default_value = "wsl2:Ubuntu")]
        target: String,

        /// 显式指定 .codex 目录路径（可选）
        #[arg(long)]
        codex_home: Option<String>,

        /// 以 JSON 格式输出
        #[arg(long)]
        json: bool,
    },

    /// 对指定 Codex 会话创建带 SHA-256 校验的快照备份（源目录 100% 只读零修改）
    Backup {
        /// 会话 ID（支持完整 UUID 或前缀匹配）
        id: String,

        /// 目标环境：host:windows | wsl2:Ubuntu
        #[arg(long, default_value = "wsl2:Ubuntu")]
        target: String,

        /// 显式指定 .codex 目录路径（可选）
        #[arg(long)]
        codex_home: Option<String>,

        /// 显式指定备份仓库根目录（可选）
        #[arg(long)]
        backup_dir: Option<String>,

        /// 以 JSON 格式输出
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum InstallAgents {
    /// 安装或预览 Codex PreToolUse 防护钩子与策略镜像
    Codex {
        /// 目标环境标识（如 host:windows 或 wsl2:Ubuntu）
        #[arg(long, default_value = "wsl2:Ubuntu")]
        target: String,

        /// 安装作用域：user | project
        #[arg(long, default_value = "user")]
        scope: String,

        /// 显式指定目标 .codex 目录路径（用于沙箱隔离测试或指定项目目录）
        #[arg(long)]
        codex_home: Option<String>,

        /// 显式指定备份仓库根目录
        #[arg(long)]
        backup_dir: Option<String>,

        /// 显式指定 Hook 执行命令（省略时自动指向当前 ai-guard 二进制）
        #[arg(long)]
        hook_command: Option<String>,

        /// 待分发部署的源 ai-guard 二进制路径
        #[arg(long)]
        binary_source: Option<String>,

        /// 目标环境探针二进制部署路径（如 ~/.local/bin/ai-guard-linux）
        #[arg(long)]
        binary_dest: Option<String>,

        /// 待同步的源 policy.toml 路径
        #[arg(long)]
        policy_source: Option<String>,

        /// 目标环境策略镜像路径（如 ~/.config/ai-guard/policy.toml）
        #[arg(long)]
        policy_dest: Option<String>,

        /// 可选预置的 Hook trusted_hash
        #[arg(long)]
        trusted_hash: Option<String>,

        /// 仅预览 Unified Diff 与影响范围，不修改任何磁盘文件
        #[arg(long)]
        dry_run: bool,

        /// 以 JSON 格式输出安装或预览结果
        #[arg(long)]
        json: bool,
    },
    /// 安装或预览 Antigravity (AGY) PreToolUse 防护钩子
    Agy {
        /// 目标环境标识（如 host:windows 或 wsl2:Ubuntu）
        #[arg(long, default_value = "wsl2:Ubuntu")]
        target: String,

        /// 安装作用域：user | project
        #[arg(long, default_value = "user")]
        scope: String,

        /// 显式指定 hooks.json 所在目录或配置文件路径（可选）
        #[arg(long)]
        config_path: Option<String>,

        /// 显式指定 Hook 执行命令（省略时自动指向当前 ai-guard 二进制）
        #[arg(long)]
        hook_command: Option<String>,

        /// 显式指定备份仓库根目录
        #[arg(long)]
        backup_dir: Option<String>,

        /// 仅预览 Unified Diff 与影响范围，不修改磁盘文件
        #[arg(long)]
        dry_run: bool,

        /// 以 JSON 格式输出安装或预览结果
        #[arg(long)]
        json: bool,
    },
    /// 安装或预览 OpenCode PreToolUse 防护插件
    Opencode {
        /// 目标环境标识（如 host:windows 或 wsl2:Ubuntu）
        #[arg(long, default_value = "wsl2:Ubuntu")]
        target: String,

        /// 安装作用域：user | project
        #[arg(long, default_value = "user")]
        scope: String,

        /// 显式指定 OpenCode 配置或插件目录路径（可选）
        #[arg(long)]
        config_path: Option<String>,

        /// 显式指定 Hook 执行命令（省略时自动指向当前 ai-guard 二进制）
        #[arg(long)]
        hook_command: Option<String>,

        /// 显式指定备份仓库根目录
        #[arg(long)]
        backup_dir: Option<String>,

        /// 仅预览 Unified Diff 与影响范围，不修改磁盘文件
        #[arg(long)]
        dry_run: bool,

        /// 以 JSON 格式输出安装或预览结果
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum UninstallAgents {
    /// 安全卸载 Codex PreToolUse 防护钩子
    Codex {
        /// 目标环境标识（如 host:windows 或 wsl2:Ubuntu）
        #[arg(long, default_value = "wsl2:Ubuntu")]
        target: String,

        /// 卸载作用域：user | project
        #[arg(long, default_value = "user")]
        scope: String,

        /// 显式指定目标 .codex 目录路径
        #[arg(long)]
        codex_home: Option<String>,

        /// 显式指定备份仓库根目录
        #[arg(long)]
        backup_dir: Option<String>,

        /// 仅预览卸载 Diff，不修改磁盘文件
        #[arg(long)]
        dry_run: bool,

        /// 当检测到外部修改冲突时，仍强制仅剥离 AI卫士受管段落
        #[arg(long)]
        force: bool,

        /// 以 JSON 格式输出卸载报告
        #[arg(long)]
        json: bool,
    },
    /// 安全卸载 Antigravity (AGY) PreToolUse 防护钩子
    Agy {
        /// 目标环境标识（如 host:windows 或 wsl2:Ubuntu）
        #[arg(long, default_value = "wsl2:Ubuntu")]
        target: String,

        /// 卸载作用域：user | project
        #[arg(long, default_value = "user")]
        scope: String,

        /// 显式指定 hooks.json 所在目录或配置文件路径（可选）
        #[arg(long)]
        config_path: Option<String>,

        /// 显式指定备份仓库根目录
        #[arg(long)]
        backup_dir: Option<String>,

        /// 仅预览卸载 Diff，不修改磁盘文件
        #[arg(long)]
        dry_run: bool,

        /// 以 JSON 格式输出卸载报告
        #[arg(long)]
        json: bool,
    },
    /// 安全卸载 OpenCode PreToolUse 防护插件
    Opencode {
        /// 目标环境标识（如 host:windows 或 wsl2:Ubuntu）
        #[arg(long, default_value = "wsl2:Ubuntu")]
        target: String,

        /// 卸载作用域：user | project
        #[arg(long, default_value = "user")]
        scope: String,

        /// 显式指定 OpenCode 配置或插件目录路径（可选）
        #[arg(long)]
        config_path: Option<String>,

        /// 显式指定备份仓库根目录
        #[arg(long)]
        backup_dir: Option<String>,

        /// 仅预览卸载 Diff，不修改磁盘文件
        #[arg(long)]
        dry_run: bool,

        /// 以 JSON 格式输出卸载报告
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum RunAgents {
    /// 经 Preflight 安全预检后受管启动 Codex
    Codex {
        /// 目标环境标识（如 host:windows 或 wsl2:Ubuntu）
        #[arg(long, default_value = "wsl2:Ubuntu")]
        target: String,

        /// 显式指定目标 .codex 目录路径
        #[arg(long)]
        codex_home: Option<String>,

        /// 显式指定 codex 可执行文件路径（默认在 PATH 中查找 codex）
        #[arg(long, default_value = "codex")]
        codex_bin: String,

        /// 指定需校验的本地 policy.toml 路径
        #[arg(long)]
        policy: Option<String>,

        /// 期望的策略文件 SHA-256 哈希（用于校验宿主机与 WSL2 策略镜像一致性）
        #[arg(long)]
        expected_policy_sha256: Option<String>,

        /// 要求 config.toml 中必须已登记 trusted_hash，否则拒绝启动
        #[arg(long)]
        require_trusted: bool,

        /// 仅执行 Preflight 检查并输出结果，不实际拉起 codex 进程
        #[arg(long)]
        dry_run: bool,

        /// 以 JSON 格式输出 Preflight 检查报告
        #[arg(long)]
        json: bool,

        /// 透传给 codex 的命令行参数列表（通过独立 argv 传递，严禁拼装 Shell 字符串）
        #[arg(last = true)]
        codex_args: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum BackupSubcommands {
    /// 列出已有事务备份快照
    List {
        /// 按目标环境过滤（all | host:windows | wsl2:Ubuntu）
        #[arg(long, default_value = "all")]
        target: String,

        /// 备份仓库根目录
        #[arg(long)]
        backup_dir: Option<String>,

        /// 以 JSON 格式输出
        #[arg(long)]
        json: bool,
    },

    /// 校验指定备份快照的 SHA-256 完整性
    Verify {
        /// 备份 ID（如 bk-1731000000000-1）
        #[arg(long)]
        id: String,

        /// 备份仓库根目录
        #[arg(long)]
        backup_dir: Option<String>,

        /// 以 JSON 格式输出
        #[arg(long)]
        json: bool,
    },

    /// 校验 SHA-256 后从备份快照原子恢复原始文件
    Restore {
        /// 备份 ID（如 bk-1731000000000-1）
        #[arg(long)]
        id: String,

        /// 备份仓库根目录
        #[arg(long)]
        backup_dir: Option<String>,

        /// 以 JSON 格式输出
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum RuleSubcommands {
    /// 离线校验 TOML 策略配置文件语法、Schema 与正则合法性
    Validate {
        /// 策略文件路径（如 config/policy.default.toml）
        #[arg(long)]
        path: String,

        /// 以 JSON 格式输出校验结果
        #[arg(long)]
        json: bool,
    },

    /// 离线测试单条工具输入或事件文件是否命中安全规则
    Test {
        /// Agent 类型（当前支持 codex）
        #[arg(long, default_value = "codex")]
        agent: String,

        /// 工具名称（如 Bash / apply_patch / mcp__demo__ping；使用 --event-file 时可省略）
        #[arg(long)]
        tool: Option<String>,

        /// 待测试的命令文本、补丁内容或 JSON 参数（使用 --event-file 时可省略）
        #[arg(long)]
        input: Option<String>,

        /// 模拟工作目录路径（用于推断 WindowsHost 或 Wsl2Distro）
        #[arg(long, default_value = "/workspace")]
        cwd: String,

        /// 从 Codex PreToolUse JSON 夹具文件读取完整事件进行离线测试
        #[arg(long)]
        event_file: Option<String>,

        /// 指定自定义 TOML 策略文件路径（省略时使用内置默认策略）
        #[arg(long)]
        policy: Option<String>,

        /// 以 JSON 格式输出裁决详情
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum HookAgents {
    /// Codex Hook 协议入口
    Codex {
        #[command(subcommand)]
        event: CodexHookEvents,
    },
    /// Antigravity（AGY）与 agy CLI Hook 协议入口
    Agy {
        #[command(subcommand)]
        event: AgyHookEvents,
    },
    /// OpenCode 与 opencode CLI Hook 协议入口
    Opencode {
        #[command(subcommand)]
        event: OpencodeHookEvents,
    },
}

#[derive(Debug, Subcommand)]
pub enum CodexHookEvents {
    /// Codex PreToolUse 执行前拦截钩子
    PreToolUse {
        /// 可选自定义 TOML 策略文件路径（也可通过 AI_GUARD_POLICY_PATH 环境变量指定）
        #[arg(long)]
        policy: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum AgyHookEvents {
    /// AGY PreToolUse 执行前拦截钩子（stdin 接收 ProtoJSON，stdout 输出标准 decision）
    PreToolUse {
        /// 可选自定义 TOML 策略文件路径（也可通过 AI_GUARD_POLICY_PATH 环境变量指定）
        #[arg(long)]
        policy: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum OpencodeHookEvents {
    /// OpenCode PreToolUse 执行前拦截钩子（stdin 接收 JSON，stdout 输出标准 decision）
    PreToolUse {
        /// 可选自定义 TOML 策略文件路径（也可通过 AI_GUARD_POLICY_PATH 环境变量指定）
        #[arg(long)]
        policy: Option<String>,
    },
}
