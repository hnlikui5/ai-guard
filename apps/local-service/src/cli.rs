use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "ai-guard",
    version,
    about = "AI卫士（AI Guard）— 宿主机中心化主控与 WSL2 双环境 AI 编程 Agent 本地执行前安全防火墙"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
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

    /// 离线校验策略语法或模拟规则裁决（绝不真实执行任何被测命令）
    Rule {
        #[command(subcommand)]
        subcommand: RuleSubcommands,
    },

    /// Agent Hook 极速裁决热路径入口（供 Codex PreToolUse 调用）
    Hook {
        #[command(subcommand)]
        agent: HookAgents,
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
