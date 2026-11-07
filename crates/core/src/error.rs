use thiserror::Error;

#[derive(Error, Debug)]
pub enum WarmError {
    #[error("Contest error: {0}")]
    Contest(String),
    #[error("Participant error: {0}")]
    Participant(String),
    #[error("Session error: {0}")]
    Session(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Policy violation: {0}")]
    Policy(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, WarmError>;
