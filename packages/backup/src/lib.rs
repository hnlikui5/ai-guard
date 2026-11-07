//! AI Guard (`packages/backup`) — 配置与会话 SHA-256 事务备份基础模块。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 计算字节切片的 SHA-256 十六进制摘要。
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRecord {
    pub backup_id: String,
    pub target_id: String,
    pub source_path: String,
    pub sha256: String,
}
