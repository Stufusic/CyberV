//! 3-Tier PE-Aware Binary & Loaded Image Integrity (P24.7)
//!
//! Ref: Docs/rv13.md Section 2:
//! "Self-Integrity phải tách thành 3 tầng: Disk, Loaded Image (PE-aware), Runtime Configuration.
//! Không so sánh .text RAM với .text disk byte-for-byte ngây thơ vì loader relocations và IAT.
//! Thay vào đó dùng PE-aware verification kiểm tra Section Headers, IAT và Memory Protections."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskIntegrityReport {
    pub authenticode_valid: bool,
    pub file_sha512: String,
    pub expected_sha512: String,
    pub is_disk_intact: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedImageIntegrityReport {
    pub pe_sections_intact: bool,
    pub iat_unhooked: bool,
    pub text_section_r_x_only: bool,
    pub is_loaded_image_intact: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfigIntegrityReport {
    pub acg_enforced: bool,
    pub driver_connected: bool,
    pub is_runtime_config_intact: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryIntegrityReport {
    pub disk: DiskIntegrityReport,
    pub loaded_image: LoadedImageIntegrityReport,
    pub runtime_config: RuntimeConfigIntegrityReport,
    pub binary_integrity_score: u32, // 0 - 10000
    pub summary: String,
}

pub struct BinaryIntegrityChecker;

impl BinaryIntegrityChecker {
    /// Đánh giá toàn diện 3 tầng tính toàn vẹn của mã nhị phân
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        authenticode_valid: bool,
        file_sha512: &str,
        expected_sha512: &str,
        pe_sections_intact: bool,
        iat_unhooked: bool,
        text_r_x_only: bool,
        acg_enforced: bool,
        driver_connected: bool,
    ) -> BinaryIntegrityReport {
        let is_disk_intact = authenticode_valid && (file_sha512 == expected_sha512);
        let is_loaded_image_intact = pe_sections_intact && iat_unhooked && text_r_x_only;
        let is_runtime_config_intact = acg_enforced && driver_connected;

        let disk = DiskIntegrityReport {
            authenticode_valid,
            file_sha512: file_sha512.to_string(),
            expected_sha512: expected_sha512.to_string(),
            is_disk_intact,
        };

        let loaded_image = LoadedImageIntegrityReport {
            pe_sections_intact,
            iat_unhooked,
            text_section_r_x_only: text_r_x_only,
            is_loaded_image_intact,
        };

        let runtime_config = RuntimeConfigIntegrityReport {
            acg_enforced,
            driver_connected,
            is_runtime_config_intact,
        };

        // Tính điểm: Disk 40%, Loaded Image 40%, Runtime Config 20%
        let mut score: u32 = 0;
        if is_disk_intact {
            score += 4000;
        }
        if is_loaded_image_intact {
            score += 4000;
        }
        if is_runtime_config_intact {
            score += 2000;
        }

        let summary = format!(
            "3-Tier Binary Integrity: DiskIntact={}, LoadedImagePEAware={}, RuntimeConfigIntact={} (Score: {}/10000)",
            is_disk_intact, is_loaded_image_intact, is_runtime_config_intact, score
        );

        BinaryIntegrityReport {
            disk,
            loaded_image,
            runtime_config,
            binary_integrity_score: score,
            summary,
        }
    }
}
