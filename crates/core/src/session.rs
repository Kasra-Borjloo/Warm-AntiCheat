use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Initialized,
    Active,
    Paused,
    Interrupted,
    Concluded,
    Submitted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompetitionSession {
    pub session_id: Uuid,
    pub contest_id: String,
    pub participant_id: String,
    pub state: SessionState,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
}
