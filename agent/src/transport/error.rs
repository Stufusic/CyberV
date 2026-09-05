//! CyberV Transport Error Types
//!
//! Ref: Rule.md Điều 18, 19: Phân định chi tiết lỗi mạng, không giấu lỗi.

use thiserror::Error;

/// Lỗi giao tiếp mạng giữa Agent và Cloud Edge Functions
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    #[error("Network connection failed: {0}")]
    NetworkFailure(String),

    #[error("Request timed out after deadline")]
    Timeout,

    #[error("Unauthorized (401): invalid or expired user JWT session")]
    Unauthorized,

    #[error("Forbidden (403): {0}")]
    Forbidden(String),

    #[error("Resource not found (404): {0}")]
    NotFound(String),

    #[error("Conflict (409): {0}")]
    Conflict(String),

    #[error("Server returned error ({0}): {1}")]
    ServerError(u16, String),

    #[error("Serialization or parsing error: {0}")]
    Serialization(String),
}
