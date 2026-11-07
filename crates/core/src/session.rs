use crate::error::{Result, WarmError};
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

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initialized => write!(f, "Initialized"),
            Self::Active => write!(f, "Active"),
            Self::Paused => write!(f, "Paused"),
            Self::Interrupted => write!(f, "Interrupted"),
            Self::Concluded => write!(f, "Concluded"),
            Self::Submitted => write!(f, "Submitted"),
        }
    }
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

impl CompetitionSession {
    pub fn new(contest_id: impl Into<String>, participant_id: impl Into<String>) -> Result<Self> {
        let contest_id = contest_id.into().trim().to_string();
        let participant_id = participant_id.into().trim().to_string();

        if contest_id.is_empty() {
            return Err(WarmError::Session("Contest ID cannot be empty".into()));
        }
        if participant_id.is_empty() {
            return Err(WarmError::Session("Participant ID cannot be empty".into()));
        }

        Ok(Self {
            session_id: Uuid::new_v4(),
            contest_id,
            participant_id,
            state: SessionState::Initialized,
            start_time: Utc::now(),
            end_time: None,
        })
    }

    pub fn start(&mut self) -> Result<()> {
        match self.state {
            SessionState::Initialized => {
                self.state = SessionState::Active;
                self.start_time = Utc::now();
                Ok(())
            }
            other => Err(WarmError::InvalidStateTransition {
                from: other.to_string(),
                to: SessionState::Active.to_string(),
            }),
        }
    }

    pub fn pause(&mut self) -> Result<()> {
        match self.state {
            SessionState::Active => {
                self.state = SessionState::Paused;
                Ok(())
            }
            other => Err(WarmError::InvalidStateTransition {
                from: other.to_string(),
                to: SessionState::Paused.to_string(),
            }),
        }
    }

    pub fn resume(&mut self) -> Result<()> {
        match self.state {
            SessionState::Paused | SessionState::Interrupted => {
                self.state = SessionState::Active;
                Ok(())
            }
            other => Err(WarmError::InvalidStateTransition {
                from: other.to_string(),
                to: SessionState::Active.to_string(),
            }),
        }
    }

    pub fn mark_interrupted(&mut self) -> Result<()> {
        match self.state {
            SessionState::Active | SessionState::Paused => {
                self.state = SessionState::Interrupted;
                Ok(())
            }
            other => Err(WarmError::InvalidStateTransition {
                from: other.to_string(),
                to: SessionState::Interrupted.to_string(),
            }),
        }
    }

    pub fn conclude(&mut self) -> Result<()> {
        match self.state {
            SessionState::Active | SessionState::Paused | SessionState::Interrupted => {
                self.state = SessionState::Concluded;
                self.end_time = Some(Utc::now());
                Ok(())
            }
            other => Err(WarmError::InvalidStateTransition {
                from: other.to_string(),
                to: SessionState::Concluded.to_string(),
            }),
        }
    }

    pub fn submit(&mut self) -> Result<()> {
        match self.state {
            SessionState::Concluded => {
                self.state = SessionState::Submitted;
                Ok(())
            }
            other => Err(WarmError::InvalidStateTransition {
                from: other.to_string(),
                to: SessionState::Submitted.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_lifecycle_transitions() {
        let mut session = CompetitionSession::new("gocup-1", "user-101").unwrap();
        assert_eq!(session.state, SessionState::Initialized);

        session.start().unwrap();
        assert_eq!(session.state, SessionState::Active);

        session.pause().unwrap();
        assert_eq!(session.state, SessionState::Paused);

        session.resume().unwrap();
        assert_eq!(session.state, SessionState::Active);

        session.mark_interrupted().unwrap();
        assert_eq!(session.state, SessionState::Interrupted);

        session.resume().unwrap();
        assert_eq!(session.state, SessionState::Active);

        session.conclude().unwrap();
        assert_eq!(session.state, SessionState::Concluded);
        assert!(session.end_time.is_some());

        session.submit().unwrap();
        assert_eq!(session.state, SessionState::Submitted);
    }

    #[test]
    fn test_invalid_lifecycle_transition() {
        let mut session = CompetitionSession::new("gocup-1", "user-101").unwrap();
        assert!(session.conclude().is_err());
        assert!(session.pause().is_err());
    }
}
