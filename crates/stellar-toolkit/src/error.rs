use thiserror::Error;

#[derive(Error, Debug)]
pub enum ToolkitError {
    #[error("compilation failed: {0}")]
    CompilationFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ToolkitError>;
