//! TPM 2.0 Hardware Detector (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 4:
//! "TpmDetector: present, unavailable, degraded states.
//! Fallback to software identity when TPM unavailable."

use super::capability::{TpmCapabilities, TpmStatus};

pub trait TpmDetector: Send + Sync {
    fn detect(&self) -> TpmCapabilities;
}

/// Bộ phát hiện TPM thực tế trên hệ điều hành Windows
pub struct WindowsTpmDetector;

impl WindowsTpmDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsTpmDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmDetector for WindowsTpmDetector {
    fn detect(&self) -> TpmCapabilities {
        // Kiểm tra thực tế qua WMI Win32_Tpm hoặc TBS service
        #[cfg(windows)]
        {
            // Thử kiểm tra WMI root\CIMV2\Security\MicrosoftTpm
            let wmi_res = (|| -> Result<TpmCapabilities, Box<dyn std::error::Error>> {
                let wmi_con =
                    wmi::WMIConnection::with_namespace_path(r"ROOT\CIMV2\Security\MicrosoftTpm")?;
                let results: Vec<std::collections::HashMap<String, serde_json::Value>> =
                    wmi_con.raw_query("SELECT IsActivated_InitialValue, IsEnabled_InitialValue, ManufacturerId FROM Win32_Tpm")?;

                if let Some(tpm_props) = results.first() {
                    let mfg = tpm_props
                        .get("ManufacturerId")
                        .and_then(|v| v.as_u64())
                        .map(|id| format!("TPM-MFG-{:X}", id))
                        .unwrap_or_else(|| "GENERIC_TPM".to_string());

                    Ok(TpmCapabilities::standard_tpm2(mfg))
                } else {
                    Ok(TpmCapabilities::unavailable())
                }
            })();

            if let Ok(caps) = wmi_res {
                return caps;
            }
        }

        // Nếu WMI không khả dụng hoặc truy cập bị từ chối
        TpmCapabilities {
            present: false,
            status: TpmStatus::TpmUnavailable,
            version: None,
            manufacturer: None,
            supports_key_storage: false,
            supports_attestation: false,
            supports_pcr_quote: false,
        }
    }
}

/// Bộ giả lập Mock TPM Detector dùng cho kiểm thử ma trận an ninh
pub struct MockTpmDetector {
    caps: TpmCapabilities,
}

impl MockTpmDetector {
    pub fn present(manufacturer: impl Into<String>) -> Self {
        Self {
            caps: TpmCapabilities::standard_tpm2(manufacturer),
        }
    }

    pub fn unavailable() -> Self {
        Self {
            caps: TpmCapabilities::unavailable(),
        }
    }

    pub fn degraded(manufacturer: impl Into<String>, reason: &str) -> Self {
        Self {
            caps: TpmCapabilities::degraded(manufacturer, reason),
        }
    }
}

impl TpmDetector for MockTpmDetector {
    fn detect(&self) -> TpmCapabilities {
        self.caps.clone()
    }
}
