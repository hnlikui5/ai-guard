//! AI Guard (`packages/storage`) — 宿主机统一审计库与 WSL2 本地缓冲存储接口。

use ai_guard_security::{ActionEvent, Decision};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub event: ActionEvent,
    pub decision: Decision,
}
