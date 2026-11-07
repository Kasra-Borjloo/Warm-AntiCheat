use crate::error::{Result, WarmError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentToken {
    pub contest_id: String,
    pub participant_id: String,
    pub token: String,
    pub signature: String,
}

impl EnrollmentToken {
    pub fn new(
        contest_id: impl Into<String>,
        participant_id: impl Into<String>,
        token: impl Into<String>,
        signature: impl Into<String>,
    ) -> Result<Self> {
        let contest_id = contest_id.into().trim().to_string();
        let participant_id = participant_id.into().trim().to_string();
        let token = token.into().trim().to_string();
        let signature = signature.into().trim().to_string();

        if contest_id.is_empty() {
            return Err(WarmError::Token("Contest ID cannot be empty".into()));
        }
        if participant_id.is_empty() {
            return Err(WarmError::Token("Participant ID cannot be empty".into()));
        }
        if token.is_empty() {
            return Err(WarmError::Token("Token value cannot be empty".into()));
        }

        Ok(Self {
            contest_id,
            participant_id,
            token,
            signature,
        })
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        format!("{}:{}:{}", self.contest_id, self.participant_id, self.token).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrollment_token() {
        let token = EnrollmentToken::new("gocup-1", "team-1", "tok_abc123", "sig_hex").unwrap();

        assert_eq!(token.contest_id, "gocup-1");
        assert_eq!(token.signing_bytes(), b"gocup-1:team-1:tok_abc123".to_vec());
    }
}
