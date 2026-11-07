//! Competition event definitions and schemas for Warm-AntiCheat.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventCategory {
    Process,
    Browser,
    Network,
    SystemLifecycle,
    Security,
    ManualMarker,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub event_uuid: Uuid,
    pub contest_uuid: Uuid,
    pub participant_id: String,
    pub session_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub category: EventCategory,
    pub payload: serde_json::Value,
    pub sequence_number: u64,
    pub previous_event_hash: String,
    pub current_event_hash: String,
}
