//! Protected Process Registration (FSE-1)
//!
//! Ref: Docs/rv11.md Section 2:
//! "Driver registration integrity: Không chỉ PID register:
//! ProtectedProcessRegistration { pid, process_start_time, registration_nonce, driver_instance_id }
//! Không dùng PID đơn độc vì PID có thể recycle."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedProcessRegistration {
    pub pid: u32,
    pub process_start_time: u64,
    pub registration_nonce: String,
    pub driver_instance_id: u32,
}

impl ProtectedProcessRegistration {
    pub fn current(nonce: impl Into<String>, driver_instance_id: u32) -> Self {
        let pid = std::process::id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            pid,
            process_start_time: now,
            registration_nonce: nonce.into(),
            driver_instance_id,
        }
    }

    pub fn new(
        pid: u32,
        process_start_time: u64,
        registration_nonce: impl Into<String>,
        driver_instance_id: u32,
    ) -> Self {
        Self {
            pid,
            process_start_time,
            registration_nonce: registration_nonce.into(),
            driver_instance_id,
        }
    }
}
