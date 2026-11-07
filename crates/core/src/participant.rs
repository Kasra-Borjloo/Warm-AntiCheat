use crate::error::{Result, WarmError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Participant {
    pub id: String,
    pub contest_id: String,
    pub display_name: String,
    pub email_hash: Option<String>,
}

impl Participant {
    pub fn new(
        id: impl Into<String>,
        contest_id: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Result<Self> {
        let id = id.into().trim().to_string();
        let contest_id = contest_id.into().trim().to_string();
        let display_name = display_name.into().trim().to_string();

        if id.is_empty() {
            return Err(WarmError::Participant(
                "Participant ID cannot be empty".into(),
            ));
        }
        if contest_id.is_empty() {
            return Err(WarmError::Participant("Contest ID cannot be empty".into()));
        }
        let display_name = if display_name.is_empty() {
            id.clone()
        } else {
            display_name
        };

        Ok(Self {
            id,
            contest_id,
            display_name,
            email_hash: None,
        })
    }

    pub fn with_email_hash(mut self, email_hash: impl Into<String>) -> Self {
        self.email_hash = Some(email_hash.into());
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(WarmError::Participant(
                "Participant ID cannot be empty".into(),
            ));
        }
        if self.contest_id.trim().is_empty() {
            return Err(WarmError::Participant("Contest ID cannot be empty".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_participant_creation() {
        let p = Participant::new("team-42", "gocup-1", "Team 42").unwrap();
        assert_eq!(p.id, "team-42");
        assert_eq!(p.display_name, "Team 42");
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_participant_empty_id() {
        let res = Participant::new("   ", "gocup-1", "Team");
        assert!(res.is_err());
    }
}
