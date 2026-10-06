// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
//! P2-1b — TPM-backed Attestation Key qua PCP/CNG (Microsoft Platform Crypto
//! Provider).
//!
//! Ref: `Docs/PHASE1_2_IMPLEMENTATION_PLAN.md` P2-1b. Thiết kế đúng giới hạn
//! nền tảng: TPM 2.0 PCP chỉ hỗ trợ RSA/ECC P-256 — **không có Ed25519**, vì
//! vậy khóa attestation này là **KHÓA RIÊNG** (ECC P-256, sinh trong TPM qua
//! PCP, private key không bao giờ rời TPM); khóa identity Ed25519 trong DPAPI
//! vault giữ nguyên vai trò signing hàng ngày. Hai khóa, hai vai trò:
//! - Ed25519 (DPAPI): device identity + chữ ký protocol/enrollment;
//! - P-256 (TPM PCP): chữ ký attestation — bằng chứng "khóa nằm trong TPM".
//!
//! Ranh giới trung thực (INV-007): máy không TPM / PCP từ chối →
//! `TpmError::NotPresent` — mọi caller phải báo `SoftwareFallback`, KHÔNG
//! BAO GIỜ giả vờ hardware-backed. Private key không bao giờ export được
//! (PCP chặn sẵn — export chỉ public blob).

use sha2::{Digest, Sha256};

use super::errors::TpmError;
use super::nv_counter::TpmAssuranceType;

/// Tên key persisted trong PCP — ổn định giữa các lần chạy.
pub const CYBERV_ATTEST_KEY_NAME: &str = "CyberV-Attest-P256";
/// Chữ ký ECDSA P-256 (r||s) = 64 byte.
pub const P256_SIG_LEN: usize = 64;
/// SHA-256 digest — đầu vào bắt buộc của NCryptSignHash.
pub const P256_HASH_LEN: usize = 32;

/// Khóa attestation PCP đã mở. Free object khi drop (NCryptFreeObject).
pub struct PcpAttestationKey {
    key_handle: usize, // NCRYPT_KEY_HANDLE = usize trong windows-sys 0.52
}

// Safety: NCrypt key handle tự do dùng chéo thread (CNG tự đồng bộ nội bộ);
// không chứa dữ liệu ptr ngoài handle.
unsafe impl Send for PcpAttestationKey {}

impl Drop for PcpAttestationKey {
    fn drop(&mut self) {
        if self.key_handle != 0 {
            unsafe {
                windows_sys::Win32::Security::Cryptography::NCryptFreeObject(self.key_handle);
            }
            self.key_handle = 0;
        }
    }
}

/// Khóa công khai P-256 export được (X || Y, 64 byte) — pin phía verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P256PublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl P256PublicKey {
    /// X || Y — dạng wire cho verifier.
    pub fn to_xy_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x);
        out[32..].copy_from_slice(&self.y);
        out
    }
}

impl PcpAttestationKey {
    /// Mở provider PCP + key persisted (mở có sẵn, chưa có thì tạo mới với
    /// key usage = SIGN only). Máy không TPM / PCP bị chặn → `NotPresent`.
    pub fn open_or_create() -> Result<Self, TpmError> {
        use windows_sys::Win32::Security::Cryptography::{
            NCryptCreatePersistedKey, NCryptOpenKey, NCryptOpenStorageProvider,
            NCryptSetProperty, NCryptFinalizeKey, BCRYPT_ECDSA_P256_ALGORITHM,
            MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_KEY_USAGE_PROPERTY,
        };

        let mut provider: usize = 0;
        // SILENT_FLAG: provider không được pop UI nào cả.
        let status =
            unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
        if status != 0 {
            // 0x80090016 = NTE_BAD_KEYSET thường báo "TPM không sẵn sàng".
            return Err(TpmError::NotPresent);
        }
        // Provider handle phải free — dùng guard thủ công qua closure.
        let result = (|| -> Result<Self, TpmError> {
            let key_name: Vec<u16> = CYBERV_ATTEST_KEY_NAME
                .encode_utf16()
                .chain([0])
                .collect();

            let mut key: usize = 0;
            let open_status = unsafe { NCryptOpenKey(provider, &mut key, key_name.as_ptr(), 0, 0) };

            if open_status != 0 {
                // Chưa có → tạo mới (P-256, sign-only). Không OVERWRITE —
                // chạm key có sẵn của người khác là tuyệt đối cấm.
                let create_status = unsafe {
                    NCryptCreatePersistedKey(
                        provider,
                        &mut key,
                        BCRYPT_ECDSA_P256_ALGORITHM,
                        key_name.as_ptr(),
                        0,
                        0,
                    )
                };
                if create_status != 0 {
                    return Err(TpmError::KeyError(format!(
                        "PCP create persisted key thất bại: NTSTATUS 0x{create_status:08X}"
                    )));
                }
                // Key usage: chỉ SIGN — khóa attestation không dùng decrypt.
                let usage: u32 = NCRYPT_ALLOW_SIGNING_FLAG;
                let set_status = unsafe {
                    NCryptSetProperty(
                        key,
                        NCRYPT_KEY_USAGE_PROPERTY,
                        &usage as *const u32 as *const u8,
                        4,
                        0,
                    )
                };
                if set_status != 0 {
                    return Err(TpmError::KeyError(format!(
                        "PCP set key usage thất bại: NTSTATUS 0x{set_status:08X}"
                    )));
                }
                let finalize_status =
                    unsafe { NCryptFinalizeKey(key, 0) };
                if finalize_status != 0 {
                    return Err(TpmError::KeyError(format!(
                        "PCP finalize key thất bại: NTSTATUS 0x{finalize_status:08X}"
                    )));
                }
            }

            Ok(Self { key_handle: key })
        })();

        // Free provider handle (key handle sống trong Self, không free ở đây).
        unsafe {
            windows_sys::Win32::Security::Cryptography::NCryptFreeObject(provider);
        }
        result
    }

    /// Ký payload bất kỳ: SHA-256(payload) rồi NCryptSignHash (ECDSA, không
    /// padding). Trả 64 byte r||s.
    pub fn sign(&self, payload: &[u8]) -> Result<[u8; P256_SIG_LEN], TpmError> {
        use windows_sys::Win32::Security::Cryptography::NCryptSignHash;

        let mut hasher = Sha256::new();
        hasher.update(payload);
        let digest = hasher.finalize();

        let mut sig = [0u8; P256_SIG_LEN];
        let mut sig_len: u32 = sig.len() as u32;
        let status = unsafe {
            NCryptSignHash(
                self.key_handle,
                std::ptr::null(), // ECDSA: không padding info
                digest.as_ptr(),
                digest.len() as u32,
                sig.as_mut_ptr(),
                sig_len,
                &mut sig_len,
                0, // NCRYPT_NO_PADDING_FLAG = 0 cho ECDSA
            )
        };
        if status != 0 {
            return Err(TpmError::KeyError(format!(
                "PCP sign hash thất bại: NTSTATUS 0x{status:08X}"
            )));
        }
        if sig_len as usize != P256_SIG_LEN {
            return Err(TpmError::KeyError(format!(
                "PCP chữ ký lệch độ dài: {sig_len} ≠ {P256_SIG_LEN}"
            )));
        }
        Ok(sig)
    }

    /// Export KHÓA CÔNG (ECCPUBLICBLOB → X||Y). Private key PCP không bao
    /// giờ export được — đây là chính tính chất "hardware-backed".
    pub fn public_key(&self) -> Result<P256PublicKey, TpmError> {
        use windows_sys::Win32::Security::Cryptography::{
            NCryptExportKey, BCRYPT_ECCPUBLIC_BLOB,
        };

        // Lần 1: hỏi độ dài; lần 2: export thật.
        let mut len: u32 = 0;
        let probe = unsafe {
            NCryptExportKey(
                self.key_handle,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
                &mut len,
                0,
            )
        };
        if probe != 0 || len == 0 {
            return Err(TpmError::KeyError(format!(
                "PCP export probe thất bại: NTSTATUS 0x{probe:08X}"
            )));
        }
        let mut blob = vec![0u8; len as usize];
        let status = unsafe {
            NCryptExportKey(
                self.key_handle,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                std::ptr::null(),
                blob.as_mut_ptr(),
                len,
                &mut len,
                0,
            )
        };
        if status != 0 {
            return Err(TpmError::KeyError(format!(
                "PCP export thất bại: NTSTATUS 0x{status:08X}"
            )));
        }
        // BCRYPT_ECCKEY_BLOB: magic(4) + cbKey(4) + X(cbKey) + Y(cbKey)
        if blob.len() < 8 + 64 {
            return Err(TpmError::KeyError(format!(
                "PCP public blob ngắn bất thường: {}",
                blob.len()
            )));
        }
        let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
        if magic != windows_sys::Win32::Security::Cryptography::BCRYPT_ECDSA_PUBLIC_P256_MAGIC {
            return Err(TpmError::KeyError(format!(
                "PCP public blob sai magic: 0x{magic:08X}"
            )));
        }
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&blob[8..40]);
        y.copy_from_slice(&blob[40..72]);
        Ok(P256PublicKey { x, y })
    }

    pub fn assurance(&self) -> TpmAssuranceType {
        // PCP mở được ⟹ private key sinh trong TPM — hardware-backed.
        TpmAssuranceType::HardwareBacked
    }
}

/// Verify độc lập (BCrypt, software) chữ ký PCP — dùng trong test + bất kỳ
/// verifier nào nhận public X||Y. Tách khỏi `PcpAttestationKey` để không cần
/// mở TPM khi verify.
pub fn verify_p256(
    public_xy: &[u8; 64],
    payload: &[u8],
    signature: &[u8; P256_SIG_LEN],
) -> Result<bool, TpmError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptImportKeyPair, BCryptOpenAlgorithmProvider, BCryptVerifySignature,
        BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
    };

    let mut alg: *mut std::ffi::c_void = std::ptr::null_mut();
    let status = unsafe {
        BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_ECDSA_P256_ALGORITHM, std::ptr::null(), 0)
    };
    if status != 0 {
        return Err(TpmError::ProviderError(format!(
            "BCrypt open ECDSA_P256 thất bại: NTSTATUS 0x{status:08X}"
        )));
    }
    let result = (|| -> Result<bool, TpmError> {
        // BLOB: magic(4) + cbKey(4) + X + Y
        let mut blob = Vec::with_capacity(8 + 64);
        blob.extend_from_slice(&BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes());
        blob.extend_from_slice(&32u32.to_le_bytes());
        blob.extend_from_slice(public_xy);

        let mut key: *mut std::ffi::c_void = std::ptr::null_mut();
        let import_status = unsafe {
            BCryptImportKeyPair(
                alg,
                std::ptr::null_mut(),
                BCRYPT_ECCPUBLIC_BLOB,
                &mut key,
                blob.as_mut_ptr(),
                blob.len() as u32,
                0,
            )
        };
        if import_status != 0 {
            return Err(TpmError::KeyError(format!(
                "BCrypt import public key thất bại: NTSTATUS 0x{import_status:08X}"
            )));
        }
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let digest = hasher.finalize();

        let verify_status = unsafe {
            BCryptVerifySignature(
                key,
                std::ptr::null(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_ptr(),
                signature.len() as u32,
                0,
            )
        };
        unsafe {
            windows_sys::Win32::Security::Cryptography::BCryptDestroyKey(key);
        }
        match verify_status {
            0 => Ok(true),
            code if code == 0xC000A000u32 as i32 => Ok(false), // STATUS_INVALID_SIGNATURE
            code if code < 0 => Err(TpmError::KeyError(format!(
                "BCrypt verify lỗi: NTSTATUS 0x{:08X}",
                code as u32
            ))),
            _ => Ok(false),
        }
    })();
    unsafe {
        windows_sys::Win32::Security::Cryptography::BCryptCloseAlgorithmProvider(alg, 0);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcp_roundtrip_or_honest_not_present() {
        // Máy có TPM (fTPM/dTPM) → khóa P-256 thật trong TPM, sign/verify
        // roundtrip + tái sử dụng public key giữa các lần mở.
        // Máy không có → NotPresent (INV-007 — không giả vờ hardware-backed).
        let key = match PcpAttestationKey::open_or_create() {
            Ok(k) => k,
            Err(TpmError::NotPresent) => {
                eprintln!("SKIP (máy không có PCP/TPM khả dụng — trung thực)");
                return;
            }
            Err(e) => panic!("PCP lỗi khác NotPresent phải điều tra: {e}"),
        };
        assert_eq!(key.assurance(), TpmAssuranceType::HardwareBacked);

        let payload = b"cyberv-pcp-attestation-roundtrip-v1";
        let sig = key.sign(payload).expect("sign qua TPM");
        let pubkey = key.public_key().expect("export public key");
        assert!(
            verify_p256(&pubkey.to_xy_bytes(), payload, &sig).unwrap(),
            "chữ ký PCP phải verify bằng BCrypt độc lập"
        );

        // Chữ ký bị sửa 1 bit → verify FALSE.
        let mut tampered = sig;
        tampered[7] ^= 0x01;
        assert!(!verify_p256(&pubkey.to_xy_bytes(), payload, &tampered).unwrap());

        // Payload khác → verify FALSE (không ký chéo).
        assert!(!verify_p256(&pubkey.to_xy_bytes(), b"khac payload", &sig).unwrap());

        // Mở lại — key persisted: cùng public key (không tạo key mới mỗi lần).
        let key2 = PcpAttestationKey::open_or_create().expect("open lần hai");
        assert_eq!(key2.public_key().unwrap(), pubkey, "key phải persisted ổn định");
    }

    #[test]
    fn verify_rejects_malformed_public_blob() {
        // Public key rác (không phải điểm curve hợp lệ) + chữ ký rác:
        // BCrypt trả INVALID_PARAMETER (KeyError) hoặc false — chấp nhận cả
        // hai; điều bị cấm là true hoặc panic.
        let mut xy = [0u8; 64];
        xy[0] = 0xFF;
        let sig = [0u8; P256_SIG_LEN];
        match verify_p256(&xy, b"x", &sig) {
            Ok(false) => {}
            Err(TpmError::KeyError(_)) => {}
            other => panic!("phải false hoặc KeyError, got: {other:?}"),
        }
    }
}
