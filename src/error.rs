//! Error types for schc-coreconf
//!
//! Provides error types with CoAP response code mapping per

use thiserror::Error;

/// Result type alias for schc-coreconf operations
pub type Result<T> = std::result::Result<T, Error>;

/// CoAP response code representation (class, detail)
///
/// Per RFC 7252, response codes are encoded as (class * 32 + detail).
/// Common codes used in CORECONF:
/// - 2.01 Created, 2.04 Changed, 2.05 Content (success)
/// - 4.00 Bad Request, 4.01 Unauthorized, 4.04 Not Found, 4.09 Conflict (client error)
/// - 5.00 Internal Server Error (server error)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoapCode(pub u8, pub u8);

impl CoapCode {
    // Success codes
    pub const CREATED: CoapCode = CoapCode(2, 1);
    pub const CHANGED: CoapCode = CoapCode(2, 4);
    pub const CONTENT: CoapCode = CoapCode(2, 5);

    // Client error codes
    pub const BAD_REQUEST: CoapCode = CoapCode(4, 0);
    pub const UNAUTHORIZED: CoapCode = CoapCode(4, 1);
    pub const NOT_FOUND: CoapCode = CoapCode(4, 4);
    pub const CONFLICT: CoapCode = CoapCode(4, 9);
    pub const UNSUPPORTED_CONTENT_FORMAT: CoapCode = CoapCode(4, 15);

    // Server error codes
    pub const INTERNAL_SERVER_ERROR: CoapCode = CoapCode(5, 0);

    /// Convert to raw CoAP code byte
    #[must_use]
    pub fn to_byte(self) -> u8 {
        (self.0 << 5) | self.1
    }

    /// Check if this is a success code (2.xx)
    #[must_use]
    pub fn is_success(self) -> bool {
        self.0 == 2
    }
}

impl std::fmt::Display for CoapCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:02}", self.0, self.1)
    }
}

/// Errors that can occur in schc-coreconf operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Failed to load or parse SID file
    #[error("SID file error: {0}")]
    SidFile(String),

    /// Failed to load or parse rules file
    #[error("Rules file error: {0}")]
    RulesFile(String),

    /// Attempted to modify an M-Rule via CORECONF
    /// Per draft-toutain: returns 4.01 Unauthorized
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
    /// Per draft-toutain: returns 4.04 Not Found
    #[error("Rule not found: ID={0}, length={1}")]
    RuleNotFound(u32, u8),

    /// Guard period not elapsed
    #[error("Rule {0} is pending activation (guard period not elapsed)")]
    RulePending(u32),

    /// Rule ID blocked during deletion guard period
    #[error("Rule ID {0}/{1} is blocked during deletion guard period")]
    RuleIdBlocked(u32, u8),

    /// Rule already exists
    #[error("Rule {0}/{1} already exists")]
    RuleAlreadyExists(u32, u8),

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

impl Error {
    /// Map error to CoAP response code per draft-toutain-schc-coreconf-management
    ///
    /// Error mapping:
    /// - M-Rule modification forbidden -> 4.01 Unauthorized
    /// - Rule not found -> 4.04 Not Found
    /// - Rule ID blocked -> 4.09 Conflict
    /// - Rule already exists -> 4.09 Conflict
    /// - Conversion/validation errors -> 4.00 Bad Request
    /// - Internal errors -> 5.00 Internal Server Error
    pub fn to_coap_code(&self) -> CoapCode {
        match self {
            // 4.01 Unauthorized - M-Rule protection per draft
            Error::MRuleModificationForbidden(_) => CoapCode::UNAUTHORIZED,

            // 4.04 Not Found - Invalid rule references per draft
            Error::RuleNotFound(_, _) => CoapCode::NOT_FOUND,

            // 4.09 Conflict - YANG validation errors / state conflicts
            Error::RuleIdBlocked(_, _) => CoapCode::CONFLICT,
            Error::RuleAlreadyExists(_, _) => CoapCode::CONFLICT,
            Error::RulePending(_) => CoapCode::CONFLICT,

            // 4.00 Bad Request - Invalid input
            Error::Conversion(_) => CoapCode::BAD_REQUEST,
            Error::UnknownIdentity(_) => CoapCode::BAD_REQUEST,
            Error::Json(_) => CoapCode::BAD_REQUEST,

            // 5.00 Internal Server Error - Internal issues
            Error::SidFile(_) => CoapCode::INTERNAL_SERVER_ERROR,
            Error::RulesFile(_) => CoapCode::INTERNAL_SERVER_ERROR,
            Error::Coreconf(_) => CoapCode::INTERNAL_SERVER_ERROR,
            Error::Io(_) => CoapCode::INTERNAL_SERVER_ERROR,
            Error::Schc(_) => CoapCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get a short diagnostic message suitable for CoAP response payload
    pub fn diagnostic(&self) -> String {
        match self {
            Error::MRuleModificationForbidden(id) => {
                format!("M-Rule {} is protected", id)
            }
            Error::RuleNotFound(id, len) => {
                format!("Rule {}/{} not found", id, len)
            }
            Error::RuleIdBlocked(id, len) => {
                format!("Rule {}/{} blocked during guard period", id, len)
            }
            Error::RuleAlreadyExists(id, len) => {
                format!("Rule {}/{} already exists", id, len)
            }
            _ => self.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coap_code_mapping() {
        let err = Error::MRuleModificationForbidden(0);
        assert_eq!(err.to_coap_code(), CoapCode::UNAUTHORIZED);
        assert_eq!(err.to_coap_code().to_string(), "4.01");

        let err = Error::RuleNotFound(100, 8);
        assert_eq!(err.to_coap_code(), CoapCode::NOT_FOUND);
        assert_eq!(err.to_coap_code().to_string(), "4.04");

        let err = Error::RuleIdBlocked(50, 6);
        assert_eq!(err.to_coap_code(), CoapCode::CONFLICT);
        assert_eq!(err.to_coap_code().to_string(), "4.09");
    }

    #[test]
    fn test_coap_code_byte() {
        assert_eq!(CoapCode::UNAUTHORIZED.to_byte(), 0x81); // 4*32 + 1
        assert_eq!(CoapCode::NOT_FOUND.to_byte(), 0x84); // 4*32 + 4
        assert_eq!(CoapCode::CONTENT.to_byte(), 0x45); // 2*32 + 5
    }
}
