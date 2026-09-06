use thiserror::Error;

#[derive(Error, Debug)]
pub enum ToolkitError {
    #[error("compilation failed: {0}")]
    CompilationFailed(String),
    #[error("session error: {0}")]
    Session(String),
    #[error("execution error: {0}")]
    ExecutionError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("wallet error: {0}")]
    Wallet(String),
}

pub type Result<T> = std::result::Result<T, ToolkitError>;
