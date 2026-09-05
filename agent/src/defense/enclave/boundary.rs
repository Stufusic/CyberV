//! Secure I/O Boundary Memory Isolation (FSE-4)
//!
//! Ref: Docs/rv11.md Section 5:
//! "Boundary Security: Không bao giờ trust con trỏ thô từ VTL0 mà không probe/copy
//! (Secure I/O buffer copying), bounds checking, and memory sanitization."

use thiserror::Error;

pub const MAX_SECURE_PAYLOAD_SIZE: usize = 65536; // 64 KB safe max payload

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundaryError {
    #[error(
        "Payload exceeds maximum allowable size: {0} > {}",
        MAX_SECURE_PAYLOAD_SIZE
    )]
    PayloadTooLarge(usize),
    #[error("Untrusted buffer is empty")]
    EmptyBuffer,
    #[error("Invalid memory alignment: required {required}, got {actual}")]
    InvalidAlignment { required: usize, actual: usize },
    #[error("Buffer length mismatch: expected {expected}, got {actual}")]
    LengthMismatch { expected: usize, actual: usize },
}

/// Secure isolated buffer that guarantees sanitization and bounds checking
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureIsoBuffer {
    data: Vec<u8>,
}

impl SecureIsoBuffer {
    /// Sao chép an toàn từ buffer không tin cậy của VTL0 vào bộ nhớ cách ly của Enclave
    pub fn copy_from_untrusted(untrusted_slice: &[u8]) -> Result<Self, BoundaryError> {
        if untrusted_slice.is_empty() {
            return Err(BoundaryError::EmptyBuffer);
        }

        if untrusted_slice.len() > MAX_SECURE_PAYLOAD_SIZE {
            return Err(BoundaryError::PayloadTooLarge(untrusted_slice.len()));
        }

        // Deep copy sang vector được phân bổ độc lập trong enclave
        let mut data = Vec::with_capacity(untrusted_slice.len());
        data.extend_from_slice(untrusted_slice);

        Ok(Self { data })
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureIsoBuffer {
    fn drop(&mut self) {
        // Zero out memory to prevent cold-boot or memory dump leakage
        for b in self.data.iter_mut() {
            *b = 0;
        }
    }
}
