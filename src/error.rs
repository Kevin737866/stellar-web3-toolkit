use thiserror::Error;

#[derive(Error, Debug)]
pub enum ToolkitError {
    #[error("Compilation failed: {0}")]
    CompilationFailed(String),
    
    #[error("Deployment failed: {0}")]
    DeploymentFailed(String),
    
    #[error("Test failed: {0}")]
    TestFailed(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    
    #[error("Stellar SDK error: {0}")]
    StellarError(String),
    
    #[error("Soroban error: {0}")]
    SorobanError(String),
    
    #[error("Invalid contract: {0}")]
    InvalidContract(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Transaction failed: {0}")]
    TransactionError(String),
    
    #[error("Key generation error: {0}")]
    KeyError(String),
}

pub type Result<T> = std::result::Result<T, ToolkitError>;
