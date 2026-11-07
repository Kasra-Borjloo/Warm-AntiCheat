use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents an authorized competition/contest specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contest {
    pub id: String,
    pub uuid: Uuid,
    pub title: String,
    pub organizer: String,
    pub description: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
