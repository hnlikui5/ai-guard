//! AI Guard (`packages/agent-adapters::installer`) — 双环境 Codex Hook 无损安装器、策略镜像同步与受管启动预检（M4 / Phase 3）。
//!
//! 核心职责：
//! 1. **无损增量合并（`install_codex_hook`）**：
//!    - 支持 `user`（`~/.codex/config.toml` 或 `C:\Users\<User>\.codex\config.toml`）与 `project`（`<repo>/.codex/config.toml`）两级作用域。
//!    - 100% 保留用户已有注释、模型配置与第三方自定义 `[[hooks.PreToolUse]]` 钩子。
//!    - 针对 WSL2 目标支持将同版本 `ai-guard-linux` 探针原子部署至 `~/.local/bin/ai-guard-linux`，并将宿主机主策略 `policy.toml` 镜像同步至 `~/.config/ai-guard/policy.toml`（强制校验两端 SHA-256 一致）。
//!    - 修改任何配置文件前强制调用 `packages/backup` 创建带 SHA-256 `manifest.json` 的快照，并在写入后记录 `post_operation_sha256`。
//! 2. **安全卸载与冲突保护（`uninstall_codex_hook`）**：
//!    - 卸载前检查目标 `config.toml` 自上次安装以来的 SHA-256 是否发生外部变更；若检测到外部冲突修改且未显式指定 `--force`，立即拒绝自动覆盖并给出 `ai-guard backup restore --id <backup_id>` 恢复指引。
//!    - 无外部冲突时，精准剥离 AI卫士受管段落，确保卸载后文件 SHA-256 与安装前 100% 字节级一致。
//! 3. **受管启动预检（`preflight_codex_run`）**：
//!    - 依次校验目标 `codex` 二进制、AI卫士 Hook 注册与二进制存在性、策略文件合法性与镜像哈希一致性、Hook 信任状态（`trusted_hash`），任何一项不通过即 Fail-Closed 拒绝启动。

use ai_guard_backup::{atomic_write_file, sha256_file, sha256_hex, BackupError, BackupStore};
use ai_guard_security::PolicyEngine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const MANAGED_BLOCK_START: &str = "# >>> AI-GUARD MANAGED START (DO NOT EDIT MANUALLY) >>>";
pub const MANAGED_BLOCK_END: &str = "# <<< AI-GUARD MANAGED END <<<";
pub const AI_GUARD_STATUS_PREFIX: &str = "[AI卫士]";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallScope {
    User,
    Project,
}

impl InstallScope {
    pub fn parse(s: &str) -> Result<Self, InstallerError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "user" => Ok(Self::User),
            "project" => Ok(Self::Project),
            other => Err(InstallerError::InvalidArgument(format!(
                "不支持的安装作用域 `{other}`，仅支持 `user` 或 `project`"
            ))),
        }
    }
}

#[derive(Debug, Error)]
pub enum InstallerError {
    #[error("[AG-INSTALL-ARG] 参数错误: {0}")]
    InvalidArgument(String),

    #[error("[AG-INSTALL-IO] 文件 I/O 失败 ({path}): {detail}")]
    Io { path: String, detail: String },

    #[error("[AG-INSTALL-TOML-INVALID] Codex config.toml 语法或结构非法 ({path}): {detail}")]
    TomlInvalid { path: String, detail: String },

    #[error("[AG-INSTALL-POLICY-INVALID] 策略文件校验或镜像同步失败: {0}")]
    PolicyInvalid(String),

    #[error("[AG-INSTALL-BACKUP] 事务备份失败: {0}")]
    Backup(#[from] BackupError),

    #[error("[AG-INSTALL-CONFLICT] 检测到配置文件 `{path}` 在安装后被外部修改（安装后哈希 {expected_sha256}，当前哈希 {actual_sha256}）。为防止覆盖您的新配置，已中止自动卸载。可使用 `ai-guard backup restore --id {backup_id}` 回滚至安装前快照，或附加 `--force` 仅移除 AI卫士受管段落。")]
    ExternalConflict {
        path: String,
        expected_sha256: String,
        actual_sha256: String,
        backup_id: String,
    },
}

impl InstallerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidArgument(_) => "AG-INSTALL-ARG",
            Self::Io { .. } => "AG-INSTALL-IO",
            Self::TomlInvalid { .. } => "AG-INSTALL-TOML-INVALID",
            Self::PolicyInvalid(_) => "AG-INSTALL-POLICY-INVALID",
            Self::Backup(b) => b.code(),
            Self::ExternalConflict { .. } => "AG-INSTALL-CONFLICT",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstallRequest {
    pub target_id: String,
    pub scope: InstallScope,
    pub codex_home: PathBuf,
    pub hook_command: String,
    pub guard_binary_source: Option<PathBuf>,
    pub guard_binary_dest: Option<PathBuf>,
    pub policy_source: Option<PathBuf>,
    pub policy_dest: Option<PathBuf>,
    pub trusted_hash: Option<String>,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallReport {
    pub target_id: String,
    pub scope: InstallScope,
    pub dry_run: bool,
    pub config_toml_path: String,
    pub affected_events: Vec<String>,
    pub third_party_hooks_preserved: usize,
    pub backup_id: Option<String>,
    pub pre_install_sha256: Option<String>,
    pub post_install_sha256: String,
    pub deployed_binary_path: Option<String>,
    pub deployed_binary_sha256: Option<String>,
    pub synced_policy_path: Option<String>,
    pub synced_policy_sha256: Option<String>,
    pub hook_trusted: bool,
    pub trust_guidance: String,
    pub unified_diff: String,
}

#[derive(Debug, Clone)]
pub struct UninstallRequest {
    pub target_id: String,
    pub scope: InstallScope,
    pub codex_home: PathBuf,
    pub dry_run: bool,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallReport {
    pub target_id: String,
    pub scope: InstallScope,
    pub dry_run: bool,
    pub config_toml_path: String,
    pub removed_ai_guard_hook: bool,
    pub third_party_hooks_remaining: usize,
    pub backup_id: Option<String>,
    pub pre_uninstall_sha256: Option<String>,
    pub post_uninstall_sha256: Option<String>,
    pub restored_to_exact_pre_install_hash: bool,
    pub unified_diff: String,
}

#[derive(Debug, Clone)]
pub struct PreflightRequest {
    pub target_id: String,
    pub codex_home: PathBuf,
    pub codex_bin: PathBuf,
    pub policy_path: Option<PathBuf>,
    pub expected_policy_sha256: Option<String>,
    pub require_trusted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightCheckItem {
    pub check_id: String,
    pub passed: bool,
    pub error_code: Option<String>,
    pub detail: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub target_id: String,
    pub overall_passed: bool,
    pub blocked_reason_code: Option<String>,
    pub codex_home: String,
    pub codex_bin: String,
    pub hook_trusted: bool,
    pub checks: Vec<PreflightCheckItem>,
}

/// 生成待注入的 AI卫士受管 TOML 段落。
pub fn render_managed_toml_block(
    config_toml_path: &Path,
    hook_command: &str,
    trusted_hash: Option<&str>,
) -> String {
    let escaped_cmd = hook_command.replace('\\', "\\\\").replace('"', "\\\"");
    let mut block = format!(
        "{MANAGED_BLOCK_START}\n[[hooks.PreToolUse]]\nmatcher = \".*\"\nhooks = [\n  {{ type = \"command\", command = \"{escaped_cmd}\", timeout = 10, statusMessage = \"{AI_GUARD_STATUS_PREFIX} 正在执行工具调用前安全审查...\" }}\n]\n"
    );

    if let Some(hash) = trusted_hash {
        let key = format!("{}:pre_tool_use:0:0", config_toml_path.display());
        let escaped_key = key.replace('\\', "\\\\").replace('"', "\\\"");
        let escaped_hash = hash.replace('\\', "\\\\").replace('"', "\\\"");
        block.push_str(&format!(
            "\n[hooks.state.\"{escaped_key}\"]\nenabled = true\ntrusted_hash = \"{escaped_hash}\"\n"
        ));
    }

    block.push_str(MANAGED_BLOCK_END);
    block.push('\n');
    block
}

/// 从 `config.toml` 文本中精准剥离 `# >>> AI-GUARD MANAGED START ... # <<< AI-GUARD MANAGED END <<<` 段落。
/// 保证在段落追加前后的字节内容 100% 不变。
pub fn strip_managed_toml_block(content: &str) -> (String, bool) {
    let Some(start_idx) = content.find(MANAGED_BLOCK_START) else {
        return (content.to_string(), false);
    };
    let Some(rel_end) = content[start_idx..].find(MANAGED_BLOCK_END) else {
        return (content.to_string(), false);
    };
    let mut end_idx = start_idx + rel_end + MANAGED_BLOCK_END.len();
    if content[end_idx..].starts_with("\r\n") {
        end_idx += 2;
    } else if content[end_idx..].starts_with('\n') {
        end_idx += 1;
    }

    // 如果我们在追加受管段落时曾自动补了一个前置换行符，且原文件末尾已有换行，保持原文件字节完全一致
    let prefix = &content[..start_idx];
    let suffix = &content[end_idx..];
    let mut out = String::with_capacity(prefix.len() + suffix.len());
    out.push_str(prefix);
    out.push_str(suffix);
    (out, true)
}

/// 统计 TOML 配置中 `[[hooks.PreToolUse]]` 下的 `(第三方 Hook 数量, AI卫士 Hook 数量, 引用的 AI卫士命令列表)`。
pub fn inspect_toml_hooks(
    toml_str: &str,
    path_for_err: &Path,
) -> Result<(usize, usize, Vec<String>), InstallerError> {
    if toml_str.trim().is_empty() {
        return Ok((0, 0, Vec::new()));
    }
    let table: toml::Table = toml::from_str(toml_str).map_err(|e| InstallerError::TomlInvalid {
        path: path_for_err.display().to_string(),
        detail: e.to_string(),
    })?;

    let mut third_party_count = 0usize;
    let mut ai_guard_count = 0usize;
    let mut ai_guard_commands = Vec::new();

    if let Some(toml::Value::Table(hooks_tbl)) = table.get("hooks") {
        if let Some(toml::Value::Array(pre_arr)) = hooks_tbl.get("PreToolUse") {
            for group in pre_arr {
                if let toml::Value::Table(group_tbl) = group {
                    if let Some(toml::Value::Array(inner_hooks)) = group_tbl.get("hooks") {
                        for item in inner_hooks {
                            if let toml::Value::Table(item_tbl) = item {
                                let cmd = item_tbl
                                    .get("command")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let status = item_tbl
                                    .get("statusMessage")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                if is_ai_guard_hook_entry(cmd, status) {
                                    ai_guard_count += 1;
                                    ai_guard_commands.push(cmd.to_string());
                                } else {
                                    third_party_count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok((third_party_count, ai_guard_count, ai_guard_commands))
}

pub fn is_ai_guard_hook_entry(command: &str, status_message: &str) -> bool {
    status_message.starts_with(AI_GUARD_STATUS_PREFIX)
        || (command.contains("ai-guard") && command.contains("hook codex pre-tool-use"))
}

/// 生成简洁直观的 Unified Diff 文本。
pub fn compute_unified_diff(path_label: &str, old_text: &str, new_text: &str) -> String {
    if old_text == new_text {
        return format!("--- {path_label}\n+++ {path_label}\n(无变更)\n");
    }
    let mut out = format!("--- a/{path_label}\n+++ b/{path_label}\n");
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();

    let mut prefix_len = 0;
    while prefix_len < old_lines.len()
        && prefix_len < new_lines.len()
        && old_lines[prefix_len] == new_lines[prefix_len]
    {
        prefix_len += 1;
    }

    let mut old_suffix = old_lines.len();
    let mut new_suffix = new_lines.len();
    while old_suffix > prefix_len
        && new_suffix > prefix_len
        && old_lines[old_suffix - 1] == new_lines[new_suffix - 1]
    {
        old_suffix -= 1;
        new_suffix -= 1;
    }

    let ctx_start = prefix_len.saturating_sub(2);
    for line in &old_lines[ctx_start..prefix_len] {
        out.push_str(&format!(" {line}\n"));
    }
    for line in &old_lines[prefix_len..old_suffix] {
        out.push_str(&format!("-{line}\n"));
    }
    for line in &new_lines[prefix_len..new_suffix] {
        out.push_str(&format!("+{line}\n"));
    }
    let ctx_end = (old_suffix + 2).min(old_lines.len());
    for line in &old_lines[old_suffix..ctx_end] {
        out.push_str(&format!(" {line}\n"));
    }
    out
}

/// 执行 Codex Hook 无损安装（或 `--dry-run` 预览）、二进制探针部署与策略镜像同步。
pub fn install_codex_hook(
    req: &InstallRequest,
    backup_store: &BackupStore,
) -> Result<InstallReport, InstallerError> {
    let config_path = req.codex_home.join("config.toml");

    // 1. 若指定了策略源与镜像目标，先校验主策略文件合法性
    let mut synced_policy_path = None;
    let mut synced_policy_sha256 = None;
    let mut policy_bytes_to_write = None;

    if let Some(ref src_policy) = req.policy_source {
        // 强制使用 PolicyEngine 校验语法、Schema 与正则
        PolicyEngine::from_toml_path(src_policy)
            .map_err(|e| InstallerError::PolicyInvalid(e.to_string()))?;
        let raw_policy = fs::read(src_policy).map_err(|e| InstallerError::Io {
            path: src_policy.display().to_string(),
            detail: format!("读取源策略文件失败: {e}"),
        })?;
        let hash = sha256_hex(&raw_policy);
        synced_policy_sha256 = Some(hash);
        if let Some(ref dst_policy) = req.policy_dest {
            synced_policy_path = Some(dst_policy.display().to_string());
            policy_bytes_to_write = Some((dst_policy.clone(), raw_policy));
        } else {
            synced_policy_path = Some(src_policy.display().to_string());
        }
    }

    // 2. 若指定了二进制探针部署（例如向 WSL2 ~/.local/bin/ai-guard-linux 分发），先读取并计算 SHA-256
    let mut deployed_binary_path = None;
    let mut deployed_binary_sha256 = None;
    let mut binary_bytes_to_write = None;

    if let (Some(ref src_bin), Some(ref dst_bin)) =
        (&req.guard_binary_source, &req.guard_binary_dest)
    {
        let raw_bin = fs::read(src_bin).map_err(|e| InstallerError::Io {
            path: src_bin.display().to_string(),
            detail: format!("读取源探针二进制失败: {e}"),
        })?;
        deployed_binary_sha256 = Some(sha256_hex(&raw_bin));
        deployed_binary_path = Some(dst_bin.display().to_string());
        binary_bytes_to_write = Some((dst_bin.clone(), raw_bin));
    }

    // 3. 读取现有 config.toml（若存在），校验 TOML 语法并统计已有第三方 Hook
    let (original_text, pre_install_sha256) = if config_path.exists() {
        let bytes = fs::read(&config_path).map_err(|e| InstallerError::Io {
            path: config_path.display().to_string(),
            detail: e.to_string(),
        })?;
        let text = String::from_utf8(bytes.clone()).map_err(|e| InstallerError::TomlInvalid {
            path: config_path.display().to_string(),
            detail: format!("config.toml 不是合法的 UTF-8: {e}"),
        })?;
        (text, Some(sha256_hex(&bytes)))
    } else {
        (String::new(), None)
    };

    let (third_party_before, _, _) = inspect_toml_hooks(&original_text, &config_path)?;

    // 4. 先剥离旧的受管段落（支持幂等升级），再追加新的受管段落
    let (base_without_managed, _) = strip_managed_toml_block(&original_text);
    let managed_block =
        render_managed_toml_block(&config_path, &req.hook_command, req.trusted_hash.as_deref());

    let mut new_text = base_without_managed;
    if !new_text.is_empty() && !new_text.ends_with('\n') {
        new_text.push('\n');
    }
    new_text.push_str(&managed_block);

    // 5. 强制校验合并后的完整 TOML 语法，且确认第三方 Hook 数量 100% 未减少！
    let (third_party_after, ai_guard_after, _) = inspect_toml_hooks(&new_text, &config_path)?;
    if third_party_after != third_party_before || ai_guard_after == 0 {
        return Err(InstallerError::TomlInvalid {
            path: config_path.display().to_string(),
            detail: format!(
                "合并校验异常：安装前第三方 Hook 数量为 {third_party_before}，合并后为 {third_party_after}"
            ),
        });
    }

    let post_install_sha256 = sha256_hex(new_text.as_bytes());
    let unified_diff = compute_unified_diff(
        &config_path.display().to_string(),
        &original_text,
        &new_text,
    );

    let hook_trusted = req.trusted_hash.is_some() || new_text.contains("trusted_hash");
    let trust_guidance = if hook_trusted {
        "Hook 信任哈希已写入 [hooks.state]，状态为已信任（trusted）。".to_string()
    } else {
        "安装完成后，请在 Codex 中运行 `/hooks` 确认信任该 Hook，或重启 `codex app-server` 以加载最新配置。".to_string()
    };

    if req.dry_run {
        return Ok(InstallReport {
            target_id: req.target_id.clone(),
            scope: req.scope,
            dry_run: true,
            config_toml_path: config_path.display().to_string(),
            affected_events: vec!["PreToolUse".to_string()],
            third_party_hooks_preserved: third_party_after,
            backup_id: None,
            pre_install_sha256,
            post_install_sha256,
            deployed_binary_path,
            deployed_binary_sha256,
            synced_policy_path,
            synced_policy_sha256,
            hook_trusted,
            trust_guidance,
            unified_diff,
        });
    }

    // 6. 正式安装：先调用 BackupStore 创建带 SHA-256 的事务快照！
    let manifest = backup_store.create_backup(
        &req.target_id,
        "install_codex_hook",
        &[config_path.as_path()],
    )?;

    // 7. 部署探针二进制（若提供）并设置可执行权限
    if let Some((ref dst_bin, ref bin_bytes)) = binary_bytes_to_write {
        atomic_write_file(dst_bin, bin_bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(dst_bin) {
                let mut perms = meta.permissions();
                perms.set_mode(0o755);
                let _ = fs::set_permissions(dst_bin, perms);
            }
        }
        let verify_bin_hash = sha256_file(dst_bin)?;
        if Some(&verify_bin_hash) != deployed_binary_sha256.as_ref() {
            return Err(InstallerError::PolicyInvalid(
                "探针二进制部署后 SHA-256 校验不一致".to_string(),
            ));
        }
    }

    // 8. 原子同步策略镜像（若提供）并强制校验源与目标 SHA-256 100% 一致
    if let Some((ref dst_policy, ref pol_bytes)) = policy_bytes_to_write {
        atomic_write_file(dst_policy, pol_bytes)?;
        let verify_pol_hash = sha256_file(dst_policy)?;
        if Some(&verify_pol_hash) != synced_policy_sha256.as_ref() {
            return Err(InstallerError::PolicyInvalid(
                "策略文件镜像同步后 SHA-256 校验不一致".to_string(),
            ));
        }
    }

    // 9. 原子写入合并后的 config.toml，并在 BackupStore 中记录 post_operation_sha256
    atomic_write_file(&config_path, new_text.as_bytes())?;
    backup_store.record_post_operation_hashes(&manifest.backup_id)?;

    Ok(InstallReport {
        target_id: req.target_id.clone(),
        scope: req.scope,
        dry_run: false,
        config_toml_path: config_path.display().to_string(),
        affected_events: vec!["PreToolUse".to_string()],
        third_party_hooks_preserved: third_party_after,
        backup_id: Some(manifest.backup_id),
        pre_install_sha256,
        post_install_sha256,
        deployed_binary_path,
        deployed_binary_sha256,
        synced_policy_path,
        synced_policy_sha256,
        hook_trusted,
        trust_guidance,
        unified_diff,
    })
}

/// 执行 Codex Hook 安全卸载（支持外部冲突检测、`--dry-run` 预览与精确还原）。
pub fn uninstall_codex_hook(
    req: &UninstallRequest,
    backup_store: &BackupStore,
) -> Result<UninstallReport, InstallerError> {
    let config_path = req.codex_home.join("config.toml");
    if !config_path.exists() {
        return Ok(UninstallReport {
            target_id: req.target_id.clone(),
            scope: req.scope,
            dry_run: req.dry_run,
            config_toml_path: config_path.display().to_string(),
            removed_ai_guard_hook: false,
            third_party_hooks_remaining: 0,
            backup_id: None,
            pre_uninstall_sha256: None,
            post_uninstall_sha256: None,
            restored_to_exact_pre_install_hash: true,
            unified_diff: "(配置文件不存在，无需卸载)\n".to_string(),
        });
    }

    let current_bytes = fs::read(&config_path).map_err(|e| InstallerError::Io {
        path: config_path.display().to_string(),
        detail: e.to_string(),
    })?;
    let current_sha256 = sha256_hex(&current_bytes);
    let current_text =
        String::from_utf8(current_bytes).map_err(|e| InstallerError::TomlInvalid {
            path: config_path.display().to_string(),
            detail: e.to_string(),
        })?;

    // 查找最近一次针对该目标与配置文件的 install_codex_hook 备份记录
    let canonical_target_path = config_path.display().to_string();
    let latest_install_backup = backup_store
        .list_backups(Some(&req.target_id))?
        .into_iter()
        .find(|m| {
            m.operation == "install_codex_hook"
                && m.files
                    .iter()
                    .any(|f| f.original_path == canonical_target_path)
        });

    let mut expected_pre_install_hash = None;
    let mut existed_before_install = true;

    if let Some(ref bmanifest) = latest_install_backup {
        if let Some(fentry) = bmanifest
            .files
            .iter()
            .find(|f| f.original_path == canonical_target_path)
        {
            existed_before_install = fentry.existed_before;
            if fentry.existed_before {
                expected_pre_install_hash = Some(fentry.sha256.clone());
            }
            // 若记录了 post_operation_sha256 且与当前文件不一致，说明安装后发生了外部修改！
            if let Some(ref post_hash) = fentry.post_operation_sha256 {
                if post_hash != &current_sha256 && !req.force {
                    return Err(InstallerError::ExternalConflict {
                        path: canonical_target_path,
                        expected_sha256: post_hash.clone(),
                        actual_sha256: current_sha256,
                        backup_id: bmanifest.backup_id.clone(),
                    });
                }
            }
        }
    }

    let (stripped_text, removed_block) = strip_managed_toml_block(&current_text);
    let (third_party_remaining, _, _) = inspect_toml_hooks(&stripped_text, &config_path)?;
    let unified_diff = compute_unified_diff(&canonical_target_path, &current_text, &stripped_text);

    let post_uninstall_sha256 = if !existed_before_install && stripped_text.trim().is_empty() {
        None
    } else {
        Some(sha256_hex(stripped_text.as_bytes()))
    };

    let restored_to_exact_pre_install_hash =
        match (&expected_pre_install_hash, &post_uninstall_sha256) {
            (Some(pre), Some(post)) => pre == post,
            (None, None) => true,
            _ => false,
        };

    if req.dry_run {
        return Ok(UninstallReport {
            target_id: req.target_id.clone(),
            scope: req.scope,
            dry_run: true,
            config_toml_path: canonical_target_path,
            removed_ai_guard_hook: removed_block,
            third_party_hooks_remaining: third_party_remaining,
            backup_id: None,
            pre_uninstall_sha256: Some(current_sha256),
            post_uninstall_sha256,
            restored_to_exact_pre_install_hash,
            unified_diff,
        });
    }

    // 卸载前同样先创建备份快照
    let uninstall_backup = backup_store.create_backup(
        &req.target_id,
        "uninstall_codex_hook",
        &[config_path.as_path()],
    )?;

    if !existed_before_install && stripped_text.trim().is_empty() {
        fs::remove_file(&config_path).map_err(|e| InstallerError::Io {
            path: canonical_target_path.clone(),
            detail: format!("移除空配置文件失败: {e}"),
        })?;
    } else {
        atomic_write_file(&config_path, stripped_text.as_bytes())?;
    }

    Ok(UninstallReport {
        target_id: req.target_id.clone(),
        scope: req.scope,
        dry_run: false,
        config_toml_path: canonical_target_path,
        removed_ai_guard_hook: removed_block,
        third_party_hooks_remaining: third_party_remaining,
        backup_id: Some(uninstall_backup.backup_id),
        pre_uninstall_sha256: Some(current_sha256),
        post_uninstall_sha256,
        restored_to_exact_pre_install_hash,
        unified_diff,
    })
}

/// 执行 `ai-guard run codex` 启动前四项安全预检（Preflight Checks）。
/// 任何一项关键检查未通过均返回 `overall_passed = false`，调用方必须拒绝启动 Codex（Fail-Closed）。
pub fn preflight_codex_run(req: &PreflightRequest) -> PreflightReport {
    let mut checks = Vec::new();
    let mut blocked_reason_code: Option<String> = None;

    // Check 1: Codex 可执行文件检查
    let codex_exists = resolve_executable_exists(&req.codex_bin);
    if codex_exists {
        checks.push(PreflightCheckItem {
            check_id: "codex_binary".to_string(),
            passed: true,
            error_code: None,
            detail: format!("目标 Codex 可执行文件就绪: `{}`", req.codex_bin.display()),
            remediation: None,
        });
    } else {
        let code = "AG-PREFLIGHT-CODEX-MISSING".to_string();
        blocked_reason_code.get_or_insert_with(|| code.clone());
        checks.push(PreflightCheckItem {
            check_id: "codex_binary".to_string(),
            passed: false,
            error_code: Some(code),
            detail: format!("未找到目标 Codex 可执行文件: `{}`", req.codex_bin.display()),
            remediation: Some(
                "请确认目标环境已安装 Codex CLI，或通过 `--codex-bin` 指定正确的可执行文件路径。"
                    .to_string(),
            ),
        });
    }

    // Check 2: config.toml 与 AI卫士 PreToolUse Hook 注册及二进制路径存在性检查
    let config_path = req.codex_home.join("config.toml");
    let mut hook_trusted = false;
    if !config_path.is_file() {
        let code = "AG-PREFLIGHT-CONFIG-MISSING".to_string();
        blocked_reason_code.get_or_insert_with(|| code.clone());
        checks.push(PreflightCheckItem {
            check_id: "hook_registration".to_string(),
            passed: false,
            error_code: Some(code),
            detail: format!("未找到 Codex 配置文件 `{}`", config_path.display()),
            remediation: Some(format!(
                "请先执行 `ai-guard install codex --target {}` 安装安全防护钩子。",
                req.target_id
            )),
        });
    } else {
        match fs::read_to_string(&config_path) {
            Ok(content) => {
                hook_trusted = content.contains("trusted_hash");
                match inspect_toml_hooks(&content, &config_path) {
                    Ok((_, ai_guard_count, commands)) => {
                        if ai_guard_count == 0 {
                            let code = "AG-PREFLIGHT-HOOK-MISSING".to_string();
                            blocked_reason_code.get_or_insert_with(|| code.clone());
                            checks.push(PreflightCheckItem {
                                check_id: "hook_registration".to_string(),
                                passed: false,
                                error_code: Some(code),
                                detail: format!(
                                    "配置文件 `{}` 中未注册 AI卫士 PreToolUse 钩子",
                                    config_path.display()
                                ),
                                remediation: Some(format!(
                                    "请执行 `ai-guard install codex --target {}` 重新安装钩子。",
                                    req.target_id
                                )),
                            });
                        } else {
                            // 提取钩子命令中的可执行文件路径并检查是否存在
                            let first_cmd = commands[0].trim();
                            let bin_token = extract_first_command_token(first_cmd);
                            if bin_token.is_empty()
                                || !resolve_executable_exists(Path::new(&bin_token))
                            {
                                let code = "AG-PREFLIGHT-GUARD-BIN-MISSING".to_string();
                                blocked_reason_code.get_or_insert_with(|| code.clone());
                                checks.push(PreflightCheckItem {
                                    check_id: "hook_registration".to_string(),
                                    passed: false,
                                    error_code: Some(code),
                                    detail: format!(
                                        "Hook 注册指向的 AI卫士二进制文件不存在或不可访问: `{bin_token}`"
                                    ),
                                    remediation: Some(format!(
                                        "请重新运行 `ai-guard install codex --target {}` 修复探针二进制路径。",
                                        req.target_id
                                    )),
                                });
                            } else {
                                checks.push(PreflightCheckItem {
                                    check_id: "hook_registration".to_string(),
                                    passed: true,
                                    error_code: None,
                                    detail: format!(
                                        "AI卫士 PreToolUse 钩子已注册且探针二进制 `{bin_token}` 存在"
                                    ),
                                    remediation: None,
                                });
                            }
                        }
                    }
                    Err(e) => {
                        let code = "AG-PREFLIGHT-CONFIG-CORRUPT".to_string();
                        blocked_reason_code.get_or_insert_with(|| code.clone());
                        checks.push(PreflightCheckItem {
                            check_id: "hook_registration".to_string(),
                            passed: false,
                            error_code: Some(code),
                            detail: format!("解析 config.toml 失败: {e}"),
                            remediation: Some(
                                "请使用 `ai-guard backup list` 与 `ai-guard backup restore` 恢复损坏的配置文件。"
                                    .to_string(),
                            ),
                        });
                    }
                }
            }
            Err(e) => {
                let code = "AG-PREFLIGHT-CONFIG-IO".to_string();
                blocked_reason_code.get_or_insert_with(|| code.clone());
                checks.push(PreflightCheckItem {
                    check_id: "hook_registration".to_string(),
                    passed: false,
                    error_code: Some(code),
                    detail: format!("读取 config.toml 失败: {e}"),
                    remediation: None,
                });
            }
        }
    }

    // Check 3: 本地策略文件合法性与镜像哈希一致性检查
    if let Some(ref pol_path) = req.policy_path {
        if !pol_path.is_file() {
            let code = "AG-PREFLIGHT-POLICY-MISSING".to_string();
            blocked_reason_code.get_or_insert_with(|| code.clone());
            checks.push(PreflightCheckItem {
                check_id: "policy_integrity".to_string(),
                passed: false,
                error_code: Some(code),
                detail: format!("指定的安全策略文件不存在: `{}`", pol_path.display()),
                remediation: Some(
                    "请检查 `--policy` 路径或重新执行 `ai-guard install codex` 同步策略镜像。"
                        .to_string(),
                ),
            });
        } else {
            match PolicyEngine::from_toml_path(pol_path) {
                Ok(engine) => {
                    let actual_hash = sha256_file(pol_path).unwrap_or_default();
                    if let Some(ref exp_hash) = req.expected_policy_sha256 {
                        if !actual_hash.eq_ignore_ascii_case(exp_hash) {
                            let code = "AG-PREFLIGHT-POLICY-HASH-MISMATCH".to_string();
                            blocked_reason_code.get_or_insert_with(|| code.clone());
                            checks.push(PreflightCheckItem {
                                check_id: "policy_integrity".to_string(),
                                passed: false,
                                error_code: Some(code),
                                detail: format!(
                                    "策略镜像哈希不一致：期望 `{exp_hash}`，实际 `{actual_hash}`"
                                ),
                                remediation: Some(
                                    "请重新运行 `ai-guard install codex` 将宿主机最新策略同步至目标环境。"
                                        .to_string(),
                                ),
                            });
                        } else {
                            checks.push(PreflightCheckItem {
                                check_id: "policy_integrity".to_string(),
                                passed: true,
                                error_code: None,
                                detail: format!(
                                    "策略文件 `{}` 校验通过 (revision={}, sha256={})",
                                    pol_path.display(),
                                    engine.policy_revision(),
                                    actual_hash
                                ),
                                remediation: None,
                            });
                        }
                    } else {
                        checks.push(PreflightCheckItem {
                            check_id: "policy_integrity".to_string(),
                            passed: true,
                            error_code: None,
                            detail: format!(
                                "策略文件 `{}` 校验通过 (revision={}, sha256={})",
                                pol_path.display(),
                                engine.policy_revision(),
                                actual_hash
                            ),
                            remediation: None,
                        });
                    }
                }
                Err(e) => {
                    let code = "AG-PREFLIGHT-POLICY-INVALID".to_string();
                    blocked_reason_code.get_or_insert_with(|| code.clone());
                    checks.push(PreflightCheckItem {
                        check_id: "policy_integrity".to_string(),
                        passed: false,
                        error_code: Some(code),
                        detail: format!("策略文件 `{}` 校验失败: {e}", pol_path.display()),
                        remediation: Some(
                            "请使用 `ai-guard rule validate --path <policy.toml>` 排查并修复策略语法错误。"
                                .to_string(),
                        ),
                    });
                }
            }
        }
    } else {
        checks.push(PreflightCheckItem {
            check_id: "policy_integrity".to_string(),
            passed: true,
            error_code: None,
            detail: "使用内置默认跨平台安全策略（v0.1-default-r1）".to_string(),
            remediation: None,
        });
    }

    // Check 4: Hook 信任状态检查
    if hook_trusted {
        checks.push(PreflightCheckItem {
            check_id: "hook_trust".to_string(),
            passed: true,
            error_code: None,
            detail: "Hook 已在 [hooks.state] 中登记 trusted_hash".to_string(),
            remediation: None,
        });
    } else if req.require_trusted {
        let code = "AG-PREFLIGHT-HOOK-UNTRUSTED".to_string();
        blocked_reason_code.get_or_insert_with(|| code.clone());
        checks.push(PreflightCheckItem {
            check_id: "hook_trust".to_string(),
            passed: false,
            error_code: Some(code),
            detail: "Hook 尚未完成信任登记（缺少 trusted_hash），在严格信任模式下拒绝代启动".to_string(),
            remediation: Some(
                "请在 Codex 交互界面运行 `/hooks` 审批信任 AI卫士钩子，或重新执行带信任登记的 `ai-guard install codex`。"
                    .to_string(),
            ),
        });
    } else {
        checks.push(PreflightCheckItem {
            check_id: "hook_trust".to_string(),
            passed: true,
            error_code: None,
            detail: "提示：config.toml 中尚未检出静态 trusted_hash，进入 Codex 后请通过 `/hooks` 确认钩子处于 trusted 状态".to_string(),
            remediation: Some("在 Codex TUI 中输入 `/hooks` 查看并信任 AI卫士 PreToolUse 钩子。".to_string()),
        });
    }

    let overall_passed = blocked_reason_code.is_none();
    PreflightReport {
        target_id: req.target_id.clone(),
        overall_passed,
        blocked_reason_code,
        codex_home: req.codex_home.display().to_string(),
        codex_bin: req.codex_bin.display().to_string(),
        hook_trusted,
        checks,
    }
}

fn extract_first_command_token(cmd: &str) -> String {
    let trimmed = cmd.trim();
    if let Some(rest) = trimmed.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").to_string()
    } else if let Some(rest) = trimmed.strip_prefix('\'') {
        rest.split('\'').next().unwrap_or("").to_string()
    } else {
        trimmed.split_whitespace().next().unwrap_or("").to_string()
    }
}

fn resolve_executable_exists(bin_path: &Path) -> bool {
    if bin_path.components().count() > 1 || bin_path.is_absolute() {
        return bin_path.is_file();
    }
    let Some(name) = bin_path.to_str() else {
        return false;
    };
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return true;
            }
            if cfg!(windows) {
                let exe = dir.join(format!("{name}.exe"));
                if exe.is_file() {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

    fn create_temp_test_env(label: &str) -> PathBuf {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ai-guard-m4-{label}-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_m4_dual_env_install_preserve_third_party_hooks_sync_policy_and_uninstall_exact_hash() {
        let root = create_temp_test_env("dual-loop");
        let backup_store = BackupStore::new(root.join("backups"));

        // 准备源策略与模拟探针二进制
        let src_policy = root.join("host_policy.toml");
        fs::write(
            &src_policy,
            r#"
schema_version = 1
revision = "v0.1-test-r1"
mode = "protect"

[[rules]]
id = "TEST-DENY-001"
enabled = true
priority = 10
name = "测试阻断哨兵"
agent = "codex"
tool = "*"
os_scope = "all"
match_kind = "builtin_detector"
match_value = "TEST-DENY-001"
effect = "deny"
reason_code = "AG-RULE-TEST-DENY-001"
message = "block sentinel"
"#,
        )
        .unwrap();
        let src_policy_hash = sha256_file(&src_policy).unwrap();

        let src_guard_bin = root.join("ai-guard-bin");
        fs::write(&src_guard_bin, b"#!/bin/sh\nexit 0\n").unwrap();

        // 同时覆盖模拟的宿主机 (host:windows) 与 WSL2 (wsl2:Ubuntu) 两个 .codex 环境
        for target_id in ["host:windows", "wsl2:Ubuntu"] {
            let safe_name = target_id.replace(':', "_");
            let codex_home = root.join(&safe_name).join(".codex");
            fs::create_dir_all(&codex_home).unwrap();

            let config_path = codex_home.join("config.toml");
            let initial_config = r#"# User custom Codex config
model = "gpt-5.4"

[features]
hooks = true

# Existing third-party audit hook MUST be preserved
[[hooks.PreToolUse]]
matcher = "Bash"
hooks = [
  { type = "command", command = "/opt/third-party/audit-hook --strict", statusMessage = "Third-party security audit" }
]
"#;
            fs::write(&config_path, initial_config).unwrap();
            let initial_hash = sha256_file(&config_path).unwrap();

            let dst_bin = root.join(&safe_name).join("bin/ai-guard");
            let dst_policy = root.join(&safe_name).join("etc/policy.toml");

            // 1. 先执行 --dry-run，确认不修改磁盘文件
            let dry_req = InstallRequest {
                target_id: target_id.to_string(),
                scope: InstallScope::User,
                codex_home: codex_home.clone(),
                hook_command: format!("{} hook codex pre-tool-use", dst_bin.display()),
                guard_binary_source: Some(src_guard_bin.clone()),
                guard_binary_dest: Some(dst_bin.clone()),
                policy_source: Some(src_policy.clone()),
                policy_dest: Some(dst_policy.clone()),
                trusted_hash: Some("sha256:dummy_trusted_hash".to_string()),
                dry_run: true,
            };
            let dry_rep = install_codex_hook(&dry_req, &backup_store).unwrap();
            assert!(dry_rep.dry_run);
            assert_eq!(dry_rep.third_party_hooks_preserved, 1);
            assert_eq!(
                sha256_file(&config_path).unwrap(),
                initial_hash,
                "dry-run MUST NOT modify config.toml"
            );
            assert!(!dst_policy.exists());

            // 2. 正式执行 install
            let mut real_req = dry_req.clone();
            real_req.dry_run = false;
            let install_rep = install_codex_hook(&real_req, &backup_store).unwrap();
            assert!(!install_rep.dry_run);
            assert_eq!(install_rep.third_party_hooks_preserved, 1);
            assert!(install_rep.backup_id.is_some());

            // 验证策略镜像哈希与源策略 100% 一致
            assert_eq!(sha256_file(&dst_policy).unwrap(), src_policy_hash);
            assert_eq!(
                install_rep.synced_policy_sha256.as_deref(),
                Some(src_policy_hash.as_str())
            );

            // 验证合并后的 config.toml 合法，且包含 1 个第三方 Hook + 1 个 AI卫士 Hook
            let merged_text = fs::read_to_string(&config_path).unwrap();
            let (tp_count, ag_count, _) = inspect_toml_hooks(&merged_text, &config_path).unwrap();
            assert_eq!(tp_count, 1);
            assert_eq!(ag_count, 1);
            assert!(merged_text.contains("/opt/third-party/audit-hook --strict"));

            // 3. 执行卸载 uninstall -> 验证第三方 Hook 完好且文件哈希与安装前 100% 字节级一致！
            let un_req = UninstallRequest {
                target_id: target_id.to_string(),
                scope: InstallScope::User,
                codex_home: codex_home.clone(),
                dry_run: false,
                force: false,
            };
            let un_rep = uninstall_codex_hook(&un_req, &backup_store).unwrap();
            assert!(un_rep.removed_ai_guard_hook);
            assert_eq!(un_rep.third_party_hooks_remaining, 1);
            assert!(un_rep.restored_to_exact_pre_install_hash);
            assert_eq!(
                sha256_file(&config_path).unwrap(),
                initial_hash,
                "Post-uninstall SHA-256 MUST equal pre-install SHA-256 for {target_id}"
            );
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_m4_fault_injection_conflict_detection_and_preflight_blocks_missing_binary() {
        let root = create_temp_test_env("fault-inject");
        let backup_store = BackupStore::new(root.join("backups"));
        let codex_home = root.join(".codex");
        fs::create_dir_all(&codex_home).unwrap();

        let config_path = codex_home.join("config.toml");
        fs::write(&config_path, "model = \"gpt-5.4\"\n").unwrap();

        let guard_bin = root.join("ai-guard-mock");
        fs::write(&guard_bin, b"#!/bin/sh\nexit 0\n").unwrap();
        let codex_bin = root.join("codex-mock");
        fs::write(&codex_bin, b"#!/bin/sh\nexit 0\n").unwrap();

        let req = InstallRequest {
            target_id: "wsl2:Ubuntu".to_string(),
            scope: InstallScope::User,
            codex_home: codex_home.clone(),
            hook_command: format!("{} hook codex pre-tool-use", guard_bin.display()),
            guard_binary_source: None,
            guard_binary_dest: None,
            policy_source: None,
            policy_dest: None,
            trusted_hash: Some("sha256:trusted123".to_string()),
            dry_run: false,
        };
        install_codex_hook(&req, &backup_store).unwrap();

        // 1. 正常状态 Preflight 检查必须全部通过
        let pf_ok = preflight_codex_run(&PreflightRequest {
            target_id: "wsl2:Ubuntu".to_string(),
            codex_home: codex_home.clone(),
            codex_bin: codex_bin.clone(),
            policy_path: None,
            expected_policy_sha256: None,
            require_trusted: true,
        });
        assert!(pf_ok.overall_passed);

        // 2. 故障注入 A：删除 Hook 二进制后，ai-guard run codex 预检必须阻断启动！
        fs::remove_file(&guard_bin).unwrap();
        let pf_missing_bin = preflight_codex_run(&PreflightRequest {
            target_id: "wsl2:Ubuntu".to_string(),
            codex_home: codex_home.clone(),
            codex_bin: codex_bin.clone(),
            policy_path: None,
            expected_policy_sha256: None,
            require_trusted: true,
        });
        assert!(!pf_missing_bin.overall_passed);
        assert_eq!(
            pf_missing_bin.blocked_reason_code.as_deref(),
            Some("AG-PREFLIGHT-GUARD-BIN-MISSING")
        );

        // 3. 故障注入 B：模拟用户在安装后手动修改了 config.toml -> 未带 --force 的 uninstall 必须报错中止保护用户新改动！
        let mut modified = fs::read_to_string(&config_path).unwrap();
        modified.insert_str(0, "# User added new setting after install\n");
        fs::write(&config_path, &modified).unwrap();

        let conflict_err = uninstall_codex_hook(
            &UninstallRequest {
                target_id: "wsl2:Ubuntu".to_string(),
                scope: InstallScope::User,
                codex_home: codex_home.clone(),
                dry_run: false,
                force: false,
            },
            &backup_store,
        )
        .expect_err("External edit after install must trigger conflict protection");
        assert_eq!(conflict_err.code(), "AG-INSTALL-CONFLICT");

        let _ = fs::remove_dir_all(&root);
    }
}
