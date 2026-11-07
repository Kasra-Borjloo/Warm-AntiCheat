use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentToken {
    pub contest_id: String,
    pub participant_id: String,
    pub token: String,
    pub signature: String,
}
