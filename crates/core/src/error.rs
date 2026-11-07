use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum WarmError {
    #[error("Contest error: {0}")]
    Contest(String),

    #[error("Participant error: {0}")]
    Participant(String),

    #[error("Session error: {0}")]
    Session(String),

    #[error("Invalid state transition: cannot transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: String, to: String },

    #[error("Token error: {0}")]
    Token(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Policy error: {0}")]
    Policy(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Verification error: {0}")]
    Verification(String),
}

pub type Result<T> = std::result::Result<T, WarmError>;
