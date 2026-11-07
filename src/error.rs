use thiserror::Error;

#[derive(Error, Debug)]
pub enum SentryScanError {
    #[error("Target error: {0}")]
    InvalidTarget(String),

    #[error("Port error: {0}")]
    InvalidPort(String),

    #[error("Scan error: {0}")]
    ScanExecution(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}
