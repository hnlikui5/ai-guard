//! 跨平台（Linux Bash/sh + Windows PowerShell/CMD）高置信度危险命令与敏感路径检测器。
//!
//! 遵循 AGENTS.md 第 3.3 条与第 4.1 条：
//! - 完全自主实现，兼顾 WSL2 POSIX 路径与 Windows 宿主机盘符/反斜杠路径。
//! - 对复杂动态执行（如 `eval`、变量展开子 Shell、符号链接创建）诚实标注 `CoverageLevel::Partial`。

use crate::{ActionEvent, ActionKind, CoverageLevel};
use regex::Regex;
use std::sync::OnceLock;

/// 内置检测器枚举标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinDetectorId {
    TestDeny001,
    ShellDestructiveRm,
    ShellDiskWipe,
    ShellPipeExec,
    PathSensitiveCred,
    GitDangerousOp,
}

impl BuiltinDetectorId {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim() {
            "TEST-DENY-001" => Some(Self::TestDeny001),
            "SHELL-DESTRUCTIVE-RM" => Some(Self::ShellDestructiveRm),
            "SHELL-DISK-WIPE" => Some(Self::ShellDiskWipe),
            "SHELL-PIPE-EXEC" => Some(Self::ShellPipeExec),
            "PATH-SENSITIVE-CRED" => Some(Self::PathSensitiveCred),
            "GIT-DANGEROUS-OP" => Some(Self::GitDangerousOp),
            _ => None,
        }
    }

    pub fn matches(&self, event: &ActionEvent) -> bool {
        match self {
            Self::TestDeny001 => detect_test_deny_001(event),
            Self::ShellDestructiveRm => detect_shell_destructive_rm(event),
            Self::ShellDiskWipe => detect_shell_disk_wipe(event),
            Self::ShellPipeExec => detect_shell_pipe_exec(event),
            Self::PathSensitiveCred => detect_path_sensitive_cred(event),
            Self::GitDangerousOp => detect_git_dangerous_op(event),
        }
    }
}

fn detect_test_deny_001(event: &ActionEvent) -> bool {
    if let Some(ref cmd) = event.normalized_command {
        if cmd.contains("AI_GUARD_BLOCK_ME") {
            return true;
        }
    }
    event.redacted_summary.contains("AI_GUARD_BLOCK_ME")
}

/// 检测 Linux (`rm -rf /`, `rm -rf ~`, `rm -rf ..`) 与 Windows (`Remove-Item -Recurse -Force`, `rmdir /s /q`, `del /f /s /q`) 破坏性递归删除。
pub fn detect_shell_destructive_rm(event: &ActionEvent) -> bool {
    if event.action_kind != ActionKind::Shell {
        return false;
    }
    let cmd = match event.normalized_command.as_deref() {
        Some(c) if !c.trim().is_empty() => c,
        _ => return false,
    };

    static RE_LIST: OnceLock<Vec<Regex>> = OnceLock::new();
    let regexes = RE_LIST.get_or_init(|| {
        vec![
            // 1. Linux rm with --no-preserve-root or find / -delete
            Regex::new(r"(?i)\brm\b[^\n;|&]*--no-preserve-root").unwrap(),
            Regex::new(r"(?i)\bfind\s+/(?:\s|$)[^\n;|&]*\s-delete\b").unwrap(),
            // 2. Linux rm with recursive flag (-r/-R/--recursive/-rf/-fr) targeting critical roots/home/parent/wildcard
            Regex::new(
                r#"(?i)(?:^|[;&|]\s*|\bsudo\s+)\brm\s+(?:-[a-zA-Z]*[rR][a-zA-Z]*\s+|-[a-zA-Z]*f[a-zA-Z]*\s+|--recursive\s+|--force\s+)*(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)\s+(?:-[a-zA-Z]+\s+)*(?:["']?(?:/|/\*|~(?:/[^"'\s;|&]*)?|\$HOME(?:/[^"'\s;|&]*)?|\$\{HOME\}(?:/[^"'\s;|&]*)?|\.\.(?:/[^"'\s;|&]*)?|\.|/\w+|/mnt/[a-z](?:/\*?)?)["']?)(?:\s|$|[;&|])"#,
            )
            .unwrap(),
            // 3. Windows PowerShell Remove-Item / ri / rm / rmdir / del with -Recurse and critical path
            Regex::new(
                r#"(?i)\b(?:Remove-Item|ri|rm|rmdir|rd|del|erase)\b[^\n;|&]*(?:-(?:Recurse|r)\b)[^\n;|&]*(?:["']?(?:[a-zA-Z]:\\(?:\*)?|[a-zA-Z]:/(?:\*)?|[a-zA-Z]:\\(?:Windows|Users|Program Files)[^"'\s]*|~(?:[\\/]\*)?|\$HOME|\$env:USERPROFILE|\.\.(?:[\\/]\*)?|\*)(?:["']?))(?:\s|$|[;&|])"#,
            )
            .unwrap(),
            // Also match when path comes BEFORE -Recurse in PowerShell: Remove-Item C:\Users\demo\* -Recurse -Force
            Regex::new(
                r#"(?i)\b(?:Remove-Item|ri)\b[^\n;|&]*(?:["']?(?:[a-zA-Z]:\\(?:\*)?|[a-zA-Z]:\\(?:Windows|Users)[^"'\s]*|~(?:[\\/]\*)?|\$HOME|\$env:USERPROFILE|\.\.(?:[\\/]\*)?)(?:["']?))[^\n;|&]*-(?:Recurse|r)\b"#,
            )
            .unwrap(),
            // 4. Windows CMD rmdir /s /q or rd /s /q or del /f /s /q targeting drive root, system dir, parent, or user profile
            Regex::new(
                r#"(?i)\b(?:rmdir|rd)\b[^\n;|&]*/s[^\n;|&]*(?:[a-zA-Z]:\\(?:\s|$|[;&|"'])|[a-zA-Z]:\\(?:Windows|Users)\b|\.\.|%USERPROFILE%|%SYSTEMROOT%)"#,
            )
            .unwrap(),
            Regex::new(
                r#"(?i)\b(?:del|erase)\b[^\n;|&]*/s[^\n;|&]*(?:[a-zA-Z]:\\(?:\*|\s|$|[;&|"'])|[a-zA-Z]:\\(?:Windows|Users)\b|\.\.|%USERPROFILE%)"#,
            )
            .unwrap(),
        ]
    });

    regexes.iter().any(|re| re.is_match(cmd))
}

/// 检测 Linux (`mkfs`, `fdisk`, `dd of=/dev/...`, `wipefs`) 与 Windows (`Format-Volume`, `Clear-Disk`, `diskpart`) 磁盘格式化/擦除命令。
pub fn detect_shell_disk_wipe(event: &ActionEvent) -> bool {
    if event.action_kind != ActionKind::Shell {
        return false;
    }
    let cmd = match event.normalized_command.as_deref() {
        Some(c) if !c.trim().is_empty() => c,
        _ => return false,
    };

    static RE_LIST: OnceLock<Vec<Regex>> = OnceLock::new();
    let regexes = RE_LIST.get_or_init(|| {
        vec![
            Regex::new(r"(?i)(?:^|[;&|]\s*|\bsudo\s+)\b(?:mkfs(?:\.[a-z0-9]+)?|wipefs|fdisk|parted|sfdisk)\b").unwrap(),
            Regex::new(r"(?i)\bdd\b[^\n;|&]*\bof=/dev/(?:sd[a-z]|nvme\d+n\d+|vd[a-z]|hd[a-z]|loop\d+|disk\d+|mmcblk\d+)").unwrap(),
            Regex::new(r"(?i)\bshred\b[^\n;|&]*/dev/").unwrap(),
            Regex::new(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:").unwrap(),
            Regex::new(r"(?i)\b(?:Format-Volume|Clear-Disk|Initialize-Disk|diskpart(?:\.exe)?)\b").unwrap(),
            Regex::new(r"(?i)\bformat(?:\.com)?\s+[a-zA-Z]:").unwrap(),
            Regex::new(r"(?i)\bcipher(?:\.exe)?\s+/w:").unwrap(),
        ]
    });

    regexes.iter().any(|re| re.is_match(cmd))
}

/// 检测 Linux (`curl/wget ... | sh/bash`, `base64 -d | sh`) 与 Windows (`iwr/irm ... | iex`, `powershell -enc`, `certutil -urlcache`) 下载/解码即执行。
pub fn detect_shell_pipe_exec(event: &ActionEvent) -> bool {
    if event.action_kind != ActionKind::Shell {
        return false;
    }
    let cmd = match event.normalized_command.as_deref() {
        Some(c) if !c.trim().is_empty() => c,
        _ => return false,
    };

    static RE_LIST: OnceLock<Vec<Regex>> = OnceLock::new();
    let regexes = RE_LIST.get_or_init(|| {
        vec![
            // Linux curl / wget piped into shell / interpreter
            Regex::new(r"(?i)\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b").unwrap(),
            Regex::new(r"(?i)\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby|php)\b").unwrap(),
            // Process substitution / eval with curl or wget: bash <(curl ...) or eval "$(curl ...)"
            Regex::new(r"(?i)\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b").unwrap(),
            Regex::new(r#"(?i)\b(?:eval|source|\.)\s+["']?\$\(\s*(?:curl|wget)\b"#).unwrap(),
            // Base64 decode piped into shell / interpreter
            Regex::new(r"(?i)\bbase64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b").unwrap(),
            Regex::new(r"(?i)\bbase64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:python3?|node|perl|pwsh|powershell)\b").unwrap(),
            // Windows PowerShell Invoke-WebRequest (iwr) / Invoke-RestMethod (irm) / curl piped to Invoke-Expression (iex) / pwsh
            Regex::new(r"(?i)\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|curl(?:\.exe)?|wget)\b[^\n|]*\|\s*(?:Invoke-Expression|iex|powershell(?:\.exe)?|pwsh(?:\.exe)?)\b").unwrap(),
            // iex (iwr ...) or Invoke-Expression (New-Object Net.WebClient).DownloadString(...)
            Regex::new(r"(?i)\b(?:Invoke-Expression|iex)\b[^\n;|&]*\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|DownloadString|DownloadData)\b").unwrap(),
            // PowerShell -EncodedCommand / -enc
            Regex::new(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n;|&]*\s-(?:EncodedCommand|enc|e)\s+[A-Za-z0-9+/=]{12,}").unwrap(),
            // Windows LOLBins: certutil -urlcache, mshta http, regsvr32 scrobj.dll
            Regex::new(r"(?i)\bcertutil(?:\.exe)?\b[^\n;|&]*-urlcache\b").unwrap(),
            Regex::new(r"(?i)\bmshta(?:\.exe)?\s+(?:https?://|javascript:|vbscript:)").unwrap(),
            Regex::new(r"(?i)\bregsvr32(?:\.exe)?\b[^\n;|&]*/i:https?://").unwrap(),
        ]
    });

    regexes.iter().any(|re| re.is_match(cmd))
}

/// 检测 `git reset --hard`, `git clean -fdx`, `git push --force` / `-f`（放行 `--force-with-lease`）。
pub fn detect_git_dangerous_op(event: &ActionEvent) -> bool {
    if event.action_kind != ActionKind::Shell {
        return false;
    }
    let cmd = match event.normalized_command.as_deref() {
        Some(c) if !c.trim().is_empty() => c,
        _ => return false,
    };

    static RE_RESET_CLEAN: OnceLock<Vec<Regex>> = OnceLock::new();
    let list = RE_RESET_CLEAN.get_or_init(|| {
        vec![
            Regex::new(r"(?i)\bgit\s+reset\b[^\n;|&]*--hard\b").unwrap(),
            Regex::new(r"(?i)\bgit\s+clean\b[^\n;|&]*-[a-zA-Z]*f[a-zA-Z]*[dx][a-zA-Z]*\b").unwrap(),
            Regex::new(r"(?i)\bgit\s+checkout\s+(?:--\s+)?\.(?:\s|$|[;&|])").unwrap(),
        ]
    });
    if list.iter().any(|re| re.is_match(cmd)) {
        return true;
    }

    // For git push --force / -f, explicitly allow --force-with-lease and --force-if-includes
    static RE_GIT_PUSH: OnceLock<Regex> = OnceLock::new();
    let re_push = RE_GIT_PUSH.get_or_init(|| Regex::new(r"(?i)\bgit\s+push\b([^\n;|&]*)").unwrap());
    for cap in re_push.captures_iter(cmd) {
        let args = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        for token in args.split_whitespace() {
            if token == "--force" || token == "-f" || token == "--force-with-lease=false" {
                return true;
            }
        }
    }

    false
}

/// 检测敏感凭据文件（`.ssh/`, `.aws/`, `.gnupg/`, `.codex/auth.json`, `.env`, `*.pem`, `*.key`）及跨越工作区根目录的路径穿越（`../` 或 `..\`）。
pub fn detect_path_sensitive_cred(event: &ActionEvent) -> bool {
    // 1. 检查显式提取的 target_paths（如 apply_patch）
    for p in &event.target_paths {
        if is_sensitive_or_traversal_path(p) {
            return true;
        }
    }

    // 2. 检查命令或补丁原文
    let text = match event.normalized_command.as_deref() {
        Some(c) if !c.trim().is_empty() => c,
        _ => &event.redacted_summary,
    };

    if event.action_kind == ActionKind::FilePatch {
        for p in crate::extract_patch_paths_internal(text) {
            if is_sensitive_or_traversal_path(&p) {
                return true;
            }
        }
    }

    // 3. 在 Shell 命令或文本中提取可疑路径 Token 并做 POSIX + Windows 双向规范化判定
    static RE_SENSITIVE_CMD: OnceLock<Vec<Regex>> = OnceLock::new();
    let regexes = RE_SENSITIVE_CMD.get_or_init(|| {
        vec![
            // Direct references to sensitive directories / files in POSIX or Windows format
            Regex::new(r#"(?i)(?:^|[\s'"=:/\\~])(?:\.ssh|\.aws|\.gnupg|\.kube)[/\\]"#).unwrap(),
            Regex::new(r#"(?i)(?:^|[\s'"=:/\\~])\.codex[/\\](?:auth\.json|config\.toml|hooks\.json)\b"#).unwrap(),
            Regex::new(r#"(?i)(?:^|[\s'"=:/\\~])(?:\.npmrc|\.pypirc|\.netrc|\.git-credentials)\b"#).unwrap(),
            Regex::new(r#"(?i)(?:^|[\s'"=:/\\])(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys)\b"#).unwrap(),
            Regex::new(r#"(?i)(?:^|[\s'"=:/\\])[A-Za-z0-9_.-]+\.(?:pem|key|pfx|p12)\b"#).unwrap(),
            Regex::new(r"(?i)(?:/etc/(?:shadow|sudoers|passwd|gshadow)\b|[a-zA-Z]:\\Windows\\System32\\(?:config\\SAM|drivers\\etc\\hosts)\b)").unwrap(),
        ]
    });

    if regexes.iter().any(|re| re.is_match(text)) {
        return true;
    }

    // 检查逐个命令行参数是否命中 `.env`（排除 `.env.example` / `.env.sample` / `.env.template`）或工作区路径穿越
    for raw_token in text.split_whitespace() {
        let token =
            raw_token.trim_matches(|c: char| matches!(c, '"' | '\'' | ';' | ',' | '(' | ')'));
        if token.is_empty() || token.starts_with('-') {
            continue;
        }
        // Handle key=value like --file=../../etc/passwd
        let candidate = token.split_once('=').map(|(_, v)| v).unwrap_or(token);
        if is_sensitive_or_traversal_path(candidate) {
            return true;
        }
    }

    false
}

/// 判断单个路径字符串（兼容 POSIX `/` 与 Windows `\`）是否为敏感凭据路径或逃逸出工作区根目录的相对路径穿越。
pub fn is_sensitive_or_traversal_path(raw_path: &str) -> bool {
    let trimmed = raw_path
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'));
    if trimmed.is_empty() {
        return false;
    }

    // 统一将反斜杠转换为正斜杠用于结构化分段分析，同时转为小写（兼顾 Windows 大小写不敏感）
    let unified = trimmed.replace('\\', "/");
    let lower = unified.to_ascii_lowercase();

    // 1. 检查敏感系统绝对路径
    for sys_prefix in [
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/passwd",
        "/etc/gshadow",
        "/root/.ssh",
        "c:/windows/system32/config",
        "c:/windows/system32/drivers/etc/hosts",
    ] {
        if lower == sys_prefix || lower.starts_with(&format!("{sys_prefix}/")) {
            return true;
        }
    }

    // 2. 栈式规范化分段并检查是否穿越工作区根边界（depth < 0）
    let is_abs = lower.starts_with('/')
        || lower.starts_with("~/")
        || (lower.len() >= 3 && lower.as_bytes()[0].is_ascii_alphabetic() && &lower[1..3] == ":/");

    let mut depth: i32 = 0;
    let mut normalized_segments: Vec<&str> = Vec::new();

    for seg in lower.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if !is_abs {
                depth -= 1;
                if depth < 0 {
                    // 相对路径跨越了工作区根目录（如 `../secret` 或 `a/../../etc/passwd` 或 `a\..\..\Windows\System32`）
                    return true;
                }
            }
            normalized_segments.pop();
        } else {
            if !is_abs {
                depth += 1;
            }
            normalized_segments.push(seg);
        }
    }

    // 3. 检查规范化后的路径段是否包含敏感目录或文件
    for (idx, seg) in normalized_segments.iter().enumerate() {
        if matches!(*seg, ".ssh" | ".aws" | ".gnupg" | ".kube") {
            return true;
        }
        if *seg == ".codex" {
            if let Some(next_seg) = normalized_segments.get(idx + 1) {
                if matches!(*next_seg, "auth.json" | "config.toml" | "hooks.json") {
                    return true;
                }
            }
        }
    }

    if let Some(file_name) = normalized_segments.last().copied() {
        // .env 敏感文件判定（白名单放行 .env.example / .env.sample / .env.template / .env.dist）
        if file_name == ".env"
            || (file_name.starts_with(".env.")
                && !matches!(
                    file_name,
                    ".env.example"
                        | ".env.sample"
                        | ".env.template"
                        | ".env.dist"
                        | ".env.test.example"
                ))
        {
            return true;
        }

        if matches!(
            file_name,
            "id_rsa"
                | "id_ed25519"
                | "id_ecdsa"
                | "authorized_keys"
                | ".npmrc"
                | ".pypirc"
                | ".netrc"
                | ".git-credentials"
        ) {
            return true;
        }

        if file_name.ends_with(".pem")
            || file_name.ends_with(".key")
            || file_name.ends_with(".pfx")
            || file_name.ends_with(".p12")
        {
            return true;
        }
    }

    false
}

/// 评估命令是否包含动态求值、子 Shell 变量展开、内联脚本解释器或符号链接创建：
/// 若未被 Deny，则诚实返回 `CoverageLevel::Partial` 而非 `Supported`。
pub fn analyze_event_coverage(event: &ActionEvent) -> CoverageLevel {
    match event.action_kind {
        ActionKind::Unknown => CoverageLevel::Unsupported,
        ActionKind::Shell => {
            let cmd = event.normalized_command.as_deref().unwrap_or("");
            static RE_DYNAMIC: OnceLock<Regex> = OnceLock::new();
            let re = RE_DYNAMIC.get_or_init(|| {
                Regex::new(
                    r"(?i)(?:\beval\s+|\b(?:ba|z|da)?sh\s+-c\s+.*\$\{|\bln\s+-s\b|\bmklink\b|\b(?:python3?|node|perl|ruby)\s+-(?:c|e)\s+)",
                )
                .unwrap()
            });
            if re.is_match(cmd) {
                CoverageLevel::Partial
            } else {
                CoverageLevel::Supported
            }
        }
        ActionKind::FilePatch | ActionKind::McpTool | ActionKind::LocalTool => {
            CoverageLevel::Supported
        }
    }
}
