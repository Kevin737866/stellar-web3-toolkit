use thiserror::Error;

#[derive(Error, Debug)]
pub enum ToolkitError {
    #[error("compilation failed: {0}")]
    CompilationFailed(String),
    #[error("session error: {0}")]
    // Reserved for session-key errors; not raised yet.
    #[allow(dead_code)]
    Session(String),
    #[error("execution error: {0}")]
    ExecutionError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("wallet error: {0}")]
    Wallet(String),
    #[error("treasury error: {0}")]
    Treasury(String),
    #[error("amount overflow: {0}")]
    AmountOverflow(String),
    #[error("insufficient treasury balance: have {0}, need {1}")]
    InsufficientBalance(i128, i128),
    #[error("stream {0} not found")]
    StreamNotFound(String),
    #[error("stream {0} is cancelled")]
    StreamCancelled(String),
    #[error("invalid stream schedule: {0}")]
    InvalidSchedule(String),
    #[error("glossary error: {0}")]
    Glossary(String),
    #[error("contract spec error: {0}")]
    ContractSpec(String),
}

pub type Result<T> = std::result::Result<T, ToolkitError>;
