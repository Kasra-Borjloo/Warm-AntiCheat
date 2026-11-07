use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Participant {
    pub id: String,
    pub contest_id: String,
    pub display_name: String,
    pub email_hash: Option<String>,
}
