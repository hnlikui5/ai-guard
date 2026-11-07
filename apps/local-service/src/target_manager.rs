//! AI Guard (`apps/local-service::target_manager`) — 宿主机中心化双目标调度器与 WSL2 受限桥接层（Phase 5 / M6-01 & M6-02）。
//!
//! 核心职责与安全边界：
//! 1. **宿主机中心化调度**：统一纳管 Windows 宿主机目标（`host:windows`）与一个或多个 WSL2 发行版目标（`wsl2:<distro>`）。
//! 2. **WSL2 受限 `argv` 桥接**：跨边界调用 WSL2 探针时，强制构造独立参数数组 `wsl.exe --distribution <distro> --exec <linux_bin> ...`，
//!    严禁拼装 Shell 字符串，并对所有标识符与路径参数执行控制字符/空字节注入拦截。
//! 3. **故障隔离与诚实降级**：当 WSL2 未启动或跨边界命令失败时，仅将对应 `wsl2:<distro>` 标记为 `unknown`，绝不阻塞或影响宿主机 `host:windows` 目标的独立运行。

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::process::{Command, Stdio};

/// 单次跨边界桥接命令最大允许输出字节数（2 MiB）。
pub const MAX_BRIDGE_STDOUT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeCommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

/// 校验传入桥接层的参数（禁止包含 `\0` 或换行控制字符，防止参数注入）。
pub fn validate_safe_bridge_token(field_name: &str, val: &str) -> Result<(), String> {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "[AG-BRIDGE-INVALID-ARG] 参数 `{field_name}` 不能为空"
        ));
    }
    if val.chars().any(|c| c == '\0' || c == '\r' || c == '\n') {
        return Err(format!(
            "[AG-BRIDGE-INJECTION-BLOCKED] 参数 `{field_name}` 包含非法的控制字符或换行符"
        ));
    }
    Ok(())
}

/// 校验 WSL2 发行版名称合法性（仅允许字母、数字、`.`、`_`、`-`，严禁以 `-` 开头防止选项注入）。
pub fn validate_wsl_distro_name(distro: &str) -> Result<(), String> {
    validate_safe_bridge_token("distro", distro)?;
    if distro.starts_with('-') {
        return Err(format!(
            "[AG-BRIDGE-INJECTION-BLOCKED] 非法的 WSL2 发行版名称 `{distro}`（禁止以 `-` 开头）"
        ));
    }
    if !distro
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!(
            "[AG-BRIDGE-INJECTION-BLOCKED] WSL2 发行版名称 `{distro}` 包含非法字符"
        ));
    }
    Ok(())
}

/// 构造从 Windows 宿主机调用 WSL2 内 `ai-guard-linux` 探针的受限 `argv` 规范（严禁经过 `sh -c` 或 `cmd /C`）。
pub fn build_wsl_bridge_command(
    distro: &str,
    linux_bin_path: &str,
    subcommand_args: &[String],
) -> Result<BridgeCommandSpec, String> {
    validate_wsl_distro_name(distro)?;
    validate_safe_bridge_token("linux_bin_path", linux_bin_path)?;
    if linux_bin_path.starts_with('-') {
        return Err("[AG-BRIDGE-INJECTION-BLOCKED] 探针二进制路径禁止以 `-` 开头".to_string());
    }
    for (idx, arg) in subcommand_args.iter().enumerate() {
        validate_safe_bridge_token(&format!("subcommand_args[{idx}]"), arg)?;
    }

    let mut args = Vec::with_capacity(4 + subcommand_args.len());
    args.push("--distribution".to_string());
    args.push(distro.to_string());
    args.push("--exec".to_string());
    args.push(linux_bin_path.to_string());
    args.extend_from_slice(subcommand_args);

    Ok(BridgeCommandSpec {
        program: "wsl.exe".to_string(),
        args,
    })
}

/// 执行受限桥接命令并限长读取输出。
pub fn execute_bridge_command(spec: &BridgeCommandSpec) -> Result<String, String> {
    let mut child = Command::new(&spec.program)
        .args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!(
                "[AG-BRIDGE-SPAWN-FAILED] 启动桥接进程 `{}` 失败: {e}",
                spec.program
            )
        })?;

    let mut stdout_buf = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let mut limited = stdout.take((MAX_BRIDGE_STDOUT_BYTES as u64).saturating_add(1));
        limited
            .read_to_end(&mut stdout_buf)
            .map_err(|e| format!("[AG-BRIDGE-IO-ERROR] 读取桥接进程输出失败: {e}"))?;
    }

    if stdout_buf.len() > MAX_BRIDGE_STDOUT_BYTES {
        let _ = child.kill();
        return Err(format!(
            "[AG-BRIDGE-OUTPUT-OVERSIZE] 桥接进程输出超过上限 ({MAX_BRIDGE_STDOUT_BYTES} bytes)"
        ));
    }

    let status = child
        .wait()
        .map_err(|e| format!("[AG-BRIDGE-WAIT-ERROR] 等待桥接进程结束失败: {e}"))?;

    let out_str = String::from_utf8_lossy(&stdout_buf).into_owned();
    if !status.success() {
        return Err(format!(
            "[AG-BRIDGE-EXIT-NONZERO] 桥接进程退出码 {:?}: {}",
            status.code(),
            out_str.trim()
        ));
    }

    Ok(out_str)
}

/// 校验本地控制服务监听地址是否严格属于本地回路（`127.0.0.1` 或 `::1`）。
/// 满足 `AGENTS.md` §4.3 强制要求：防止局域网未授权访问。
pub fn validate_loopback_bind_addr(addr_str: &str) -> Result<std::net::SocketAddr, String> {
    let addr: std::net::SocketAddr = addr_str
        .parse()
        .map_err(|e| format!("[AG-SECURITY-INVALID-ADDR] 监听地址 `{addr_str}` 解析失败: {e}"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "[AG-SECURITY-NON-LOOPBACK] 安全红线阻断：禁止监听非本地回路地址 `{addr}`，仅允许 `127.0.0.1` 或 `[::1]`"
        ));
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_m6_wsl_bridge_blocks_option_and_control_char_injection() {
        // 正常构造通过
        let spec = build_wsl_bridge_command(
            "Ubuntu-24.04",
            "/home/ai-li/.local/bin/ai-guard-linux",
            &[
                "events".to_string(),
                "pull".to_string(),
                "--since".to_string(),
                "0".to_string(),
                "--json".to_string(),
            ],
        )
        .expect("valid bridge command must succeed");
        assert_eq!(spec.program, "wsl.exe");
        assert_eq!(
            spec.args,
            vec![
                "--distribution",
                "Ubuntu-24.04",
                "--exec",
                "/home/ai-li/.local/bin/ai-guard-linux",
                "events",
                "pull",
                "--since",
                "0",
                "--json"
            ]
        );

        // 注入测试 1：发行版名称以 `-` 开头（企图注入 wsl.exe 选项）
        assert!(build_wsl_bridge_command("--system", "/bin/ai-guard", &[]).is_err());

        // 注入测试 2：发行版名称含 `;` 或空格或管道符
        assert!(build_wsl_bridge_command("Ubuntu;rm -rf /", "/bin/ai-guard", &[]).is_err());

        // 注入测试 3：参数包含换行或 NUL 字节
        assert!(build_wsl_bridge_command(
            "Ubuntu",
            "/bin/ai-guard",
            &["status\nmalicious".to_string()]
        )
        .is_err());
        assert!(build_wsl_bridge_command(
            "Ubuntu",
            "/bin/ai-guard",
            &["status\0malicious".to_string()]
        )
        .is_err());
    }

    #[test]
    fn test_m6_loopback_bind_guard_rejects_external_interfaces() {
        assert!(validate_loopback_bind_addr("127.0.0.1:17900").is_ok());
        assert!(validate_loopback_bind_addr("[::1]:17900").is_ok());
        let err = validate_loopback_bind_addr("0.0.0.0:17900").unwrap_err();
        assert!(err.contains("AG-SECURITY-NON-LOOPBACK"));
        assert!(validate_loopback_bind_addr("192.168.1.10:17900").is_err());
    }
}
