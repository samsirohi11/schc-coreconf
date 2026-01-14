//! Error types for schc-coreconf

use thiserror::Error;

/// Result type alias for schc-coreconf operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in schc-coreconf operations
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to load or parse SID file
    #[error("SID file error: {0}")]
    SidFile(String),

    /// Failed to load or parse rules file
    #[error("Rules file error: {0}")]
    RulesFile(String),

    /// Attempted to modify an M-Rule via CORECONF
    #[error("M-Rules cannot be modified via CORECONF (rule ID {0} is reserved)")]
    MRuleModificationForbidden(u32),

    /// Unknown YANG identity
    #[error("Unknown YANG identity: {0}")]
    UnknownIdentity(String),

    /// Conversion error between YANG and SCHC formats
    #[error("Conversion error: {0}")]
    Conversion(String),

    /// CoRECONF operation error
    #[error("CORECONF error: {0}")]
    Coreconf(String),

    /// Rule not found
    #[error("Rule not found: ID={0}, length={1}")]
    RuleNotFound(u32, u8),

    /// Guard period not elapsed
    #[error("Rule {0} is pending activation (guard period not elapsed)")]
    RulePending(u32),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// SCHC error
    #[error("SCHC error: {0}")]
    Schc(String),
}
