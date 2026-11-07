use thiserror::Error;

#[derive(Debug, Error)]
pub enum CompilerError {
    #[error("Toolchain error: {0}")]
    Toolchain(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Source file error: {0}")]
    Source(String),

    #[error("Compilation failed with exit code {0:?}: {1}")]
    CompilationFailed(Option<i32>, String),

    #[error("Execution error: {0}")]
    Execution(String),

    #[error("Timeout error: process exceeded {0}ms limit")]
    Timeout(u64),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, CompilerError>;
