//! TPM 2.0 Platform Crypto Provider Interface (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 5 & 8:
//! "Platform Crypto Provider: hardware-backed key storage and PCR attestation."

use super::capability::TpmCapabilities;
use super::errors::TpmError;
use super::key::TpmIdentityKey;
use super::pcr::{HashAlgorithm, PcrBank, PcrPolicy};
use super::quote::TpmQuote;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

pub trait TpmProvider: Send + Sync {
    fn capabilities(&self) -> TpmCapabilities;
    fn generate_key(&mut self, key_id: &str) -> Result<TpmIdentityKey, TpmError>;
    fn read_pcr_bank(&self, policy: &PcrPolicy) -> Result<PcrBank, TpmError>;
    fn generate_quote(
        &self,
        device_id: &str,
        nonce: &str,
        policy: &PcrPolicy,
        timestamp: u64,
        key: &TpmIdentityKey,
    ) -> Result<TpmQuote, TpmError>;
}

/// Bộ giả lập Mock TPM Provider hỗ trợ kiểm thử tự động toàn diện
pub struct MockTpmProvider {
    capabilities: TpmCapabilities,
    pcr_bank: PcrBank,
    keys: std::collections::HashMap<String, SigningKey>,
}

impl MockTpmProvider {
    pub fn new_standard(manufacturer: impl Into<String>) -> Self {
        let mut pcr_bank = PcrBank::new(HashAlgorithm::Sha512);
        // Khởi tạo các giá trị PCR chuẩn
        pcr_bank.set_pcr(0, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        pcr_bank.set_pcr(2, "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
        pcr_bank.set_pcr(7, "77777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777");
        pcr_bank.set_pcr(11, "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");

        Self {
            capabilities: TpmCapabilities::standard_tpm2(manufacturer),
            pcr_bank,
            keys: std::collections::HashMap::new(),
        }
    }

    pub fn set_pcr_value(&mut self, index: u32, hex_value: impl Into<String>) {
        self.pcr_bank.set_pcr(index, hex_value);
    }
}

impl TpmProvider for MockTpmProvider {
    fn capabilities(&self) -> TpmCapabilities {
        self.capabilities.clone()
    }

    fn generate_key(&mut self, key_id: &str) -> Result<TpmIdentityKey, TpmError> {
        if !self.capabilities.supports_key_storage {
            return Err(TpmError::NotPresent);
        }

        let signing_key = SigningKey::generate(&mut OsRng);
        self.keys.insert(key_id.to_string(), signing_key.clone());

        let mfg = self.capabilities.manufacturer.clone().unwrap_or_default();
        let key_ref = format!("tpm://mock-pcp/{}", key_id);
        Ok(TpmIdentityKey::new_hardware_backed(
            key_ref,
            mfg,
            signing_key,
        ))
    }

    fn read_pcr_bank(&self, _policy: &PcrPolicy) -> Result<PcrBank, TpmError> {
        Ok(self.pcr_bank.clone())
    }

    fn generate_quote(
        &self,
        device_id: &str,
        nonce: &str,
        policy: &PcrPolicy,
        timestamp: u64,
        key: &TpmIdentityKey,
    ) -> Result<TpmQuote, TpmError> {
        let signing_key = self
            .keys
            .get(&key.key_reference)
            .cloned()
            .or_else(|| {
                // Cho phép tìm theo reference hoặc tạo lại từ handle
                self.keys.values().next().cloned()
            })
            .ok_or_else(|| {
                TpmError::KeyError("Signing key not found in TPM provider".to_string())
            })?;

        TpmQuote::generate(
            device_id,
            nonce,
            policy,
            &self.pcr_bank,
            timestamp,
            &signing_key,
        )
    }
}
