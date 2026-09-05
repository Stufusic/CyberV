//! Windows Defender Application Control (WDAC) CIPolicy Generator (Phase 24.2)
//!
//! Ref: Docs/rv15.md Section 7, 8, 9:
//! "WDAC Layer A: System Code Integrity.
//! Chuẩn hóa CIPolicy.xml với nguyên tắc Audit Mode First (is_audit_mode = true).
//! Không tự ý nạp .p7b vào EFI runtime gây lockout."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WdacPolicyConfig {
    pub policy_id: String,
    pub policy_name: String,
    pub is_audit_mode: bool,
    pub allow_whql: bool,
    pub allow_cyberv: bool,
    pub deny_unsigned: bool,
    pub break_glass_recovery_enabled: bool,
}

impl Default for WdacPolicyConfig {
    fn default() -> Self {
        Self {
            policy_id: "{B8F4628E-6C12-4C1B-84A8-2E5D1293B8A1}".to_string(),
            policy_name: "CyberV_Endpoint_CodeIntegrity_Policy".to_string(),
            is_audit_mode: true, // Audit Mode First per rv15.md Section 9
            allow_whql: true,
            allow_cyberv: true,
            deny_unsigned: true,
            break_glass_recovery_enabled: true,
        }
    }
}

pub struct WdacPolicyGenerator;

impl WdacPolicyGenerator {
    /// Khởi tạo chính sách ở chế độ Audit Mode (Khuyến nghị mặc định)
    pub fn audit_mode_config() -> WdacPolicyConfig {
        WdacPolicyConfig {
            is_audit_mode: true,
            ..Default::default()
        }
    }

    /// Khởi tạo chính sách ở chế độ Enforced (Cưỡng chế sau khi kiểm toán)
    pub fn enforced_config() -> WdacPolicyConfig {
        WdacPolicyConfig {
            is_audit_mode: false,
            ..Default::default()
        }
    }

    /// Sinh nội dung tệp XML chính sách tuân thủ lược đồ Microsoft Code Integrity
    pub fn generate_cipolicy_xml(config: &WdacPolicyConfig) -> String {
        let audit_rule = if config.is_audit_mode {
            "        <RuleType>Enabled:Audit Mode</RuleType>\n"
        } else {
            ""
        };

        let break_glass_rule = if config.break_glass_recovery_enabled {
            "        <RuleType>Enabled:Boot Menu Protection with Safe Recovery</RuleType>\n"
        } else {
            ""
        };

        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
    <VersionEx>10.0.1.0</VersionEx>
    <PlatformID>{policy_id}</PlatformID>
    <Rules>
        <RuleType>Enabled:UMCI</RuleType>
        <RuleType>Required:WHQL</RuleType>
{audit_rule}{break_glass_rule}    </Rules>
    <Signers>
        <Signer ID="ID_SIGNER_WHQL" Name="Microsoft Windows Hardware Compatibility WHQL">
            <CertRoot Type="Wellknown" Value="05" />
        </Signer>
        <Signer ID="ID_SIGNER_CYBERV" Name="CyberV Corporation Production Code Signing CA">
            <CertRoot Type="TBS" Value="E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" />
        </Signer>
    </Signers>
    <SigningScenarios>
        <SigningScenario Value="131" ID="ID_SIGNING_SCENARIO_DRIVERS" FriendlyName="Kernel Mode Drivers">
            <ProductSigners>
                <AllowedSigners>
                    <AllowedSigner SignerId="ID_SIGNER_WHQL" />
                    <AllowedSigner SignerId="ID_SIGNER_CYBERV" />
                </AllowedSigners>
            </ProductSigners>
        </SigningScenario>
        <SigningScenario Value="12" ID="ID_SIGNING_SCENARIO_USER" FriendlyName="User Mode Code Integrity">
            <ProductSigners>
                <AllowedSigners>
                    <AllowedSigner SignerId="ID_SIGNER_WHQL" />
                    <AllowedSigner SignerId="ID_SIGNER_CYBERV" />
                </AllowedSigners>
            </ProductSigners>
        </SigningScenario>
    </SigningScenarios>
</SiPolicy>"#,
            policy_id = config.policy_id,
            audit_rule = audit_rule,
            break_glass_rule = break_glass_rule
        )
    }

    /// Thẩm định tính hợp lệ của tài liệu CIPolicy XML
    pub fn validate_cipolicy_xml(xml: &str) -> Result<(), &'static str> {
        if !xml.contains("<SiPolicy xmlns=\"urn:schemas-microsoft-com:sipolicy\"") {
            return Err("Missing valid SiPolicy root namespace");
        }
        if !xml.contains("ID_SIGNER_WHQL") || !xml.contains("ID_SIGNER_CYBERV") {
            return Err("Policy must explicitly contain WHQL and CyberV signers");
        }
        if !xml.contains("ID_SIGNING_SCENARIO_DRIVERS") {
            return Err("Missing kernel driver signing scenario");
        }
        Ok(())
    }
}
