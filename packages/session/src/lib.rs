//! AI Guard (`packages/session`) — 宿主机与 WSL2 双环境 Codex 会话只读索引模块。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub target_id: String,
    pub cwd: String,
}
