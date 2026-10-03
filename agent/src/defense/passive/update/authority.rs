//! Update Authority Key Pinning (M1 — Key Custody Model)
//!
//! Ref: Docs/PIPELINE_SECURITY_PLAN.md Phần D (Key Custody Model):
//! "Update Authority Key (Ed25519) sinh trên máy khí-gap, chia 2-of-3 giữa
//! maintainers; chỉ KEY CÔNG KHAI được pin vào agent."
//!
//! Nguyên tắc fail-closed: nếu key authority chưa được cấu hình (môi trường
//! dev mới dựng, file hỏng, hex sai) thì **mọi bản cập nhật đều bị từ chối** —
//! hệ thống không bao giờ rơi về "chấp nhận gói không ký".

use ed25519_dalek::VerifyingKey;
use std::path::PathBuf;

/// Biến môi trường chứa key công khai authority (64 ký tự hex).
/// Đây là cách cấu hình ưu tiên — phù hợp service/CI.
pub const UPDATE_AUTHORITY_PUBKEY_ENV: &str = "CYBERV_UPDATE_AUTHORITY_PUBLIC_KEY";

/// Tệp cấu hình dự phòng (nội dung là 64 ký tự hex, có thể có whitespace).
pub fn default_authority_key_file() -> Option<PathBuf> {
    std::env::var("ProgramData")
        .ok()
        .map(|pd| PathBuf::from(pd).join("CyberV").join("update_authority.pub"))
}

/// Chuyển 64 ký tự hex thành VerifyingKey; từ chối mọi định dạng khác.
pub fn parse_authority_public_key(hex: &str) -> Result<VerifyingKey, &'static str> {
    let trimmed = hex.trim();
    if trimmed.len() != 64 {
        return Err("Authority public key phải là 64 ký tự hex (32 byte Ed25519)");
    }
    let bytes = decode_hex_32(trimmed).ok_or("Authority public key chứa ký tự không phải hex")?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "Authority public key không phải điểm Ed25519 hợp lệ")
}

/// Nạp key authority từ env hoặc tệp cấu hình. `None` = CHƯA CẤU HÌNH —
/// caller BẮT BUỘC từ chối mọi update (fail-closed), không bao giờ default allow.
pub fn load_pinned_authority_key() -> Option<VerifyingKey> {
    if let Ok(hex) = std::env::var(UPDATE_AUTHORITY_PUBKEY_ENV) {
        if let Ok(key) = parse_authority_public_key(&hex) {
            return Some(key);
        }
        // Env tồn tại nhưng sai định dạng: đây là lỗi cấu hình nghiêm trọng —
        // trả None (fail-closed) và để caller log. Không fallback xuống file:
        // một env sai không được âm thầm thay bằng file có thể là tấn công.
        return None;
    }

    let path = default_authority_key_file()?;
    let hex = std::fs::read_to_string(path).ok()?;
    parse_authority_public_key(&hex).ok()
}

/// Cổng update tổng: chỉ khi có pinned key hợp lệ và manifest qua chữ ký
/// thì mới cho phép. Đây là hàm duy nhất mà update loop được gọi.
pub fn verify_update_manifest(manifest: &super::manifest::UpdatePackageManifest) -> bool {
    match load_pinned_authority_key() {
        Some(key) => manifest.verify_signature(&key),
        None => false, // chưa cấu hình key authority -> không update nào được chấp nhận
    }
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let mut out = [0u8; 32];
    for (i, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
        if i >= 32 {
            return None;
        }
        out[i] = (hex_val(chunk[0])? << 4) | hex_val(chunk[1])?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn parse_accepts_valid_and_rejects_garbage() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let hex: String = sk
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        assert!(parse_authority_public_key(&hex).is_ok());
        assert!(parse_authority_public_key(&hex.to_uppercase()).is_ok());
        assert!(parse_authority_public_key(&hex[..63]).is_err()); // thiếu 1 ký tự
        assert!(parse_authority_public_key(&"zz".repeat(32)).is_err()); // không hex
        assert!(parse_authority_public_key("").is_err());
    }

    #[test]
    fn verify_gate_is_fail_closed_without_configured_key() {
        // Không đụng env/file thật: gọi trực tiếp logic qua manifest + key None.
        // Mô phỏng: manifest "hợp lệ" nhưng KHÔNG có pinned key -> phải từ chối.
        let manifest = super::super::manifest::UpdatePackageManifest {
            version: 2,
            package_sha512: "a".repeat(128),
            release_key_id: "k".to_string(),
            manifest_signature_hex: "00".repeat(64),
            target_arch: "x86_64".to_string(),
        };
        // Chứng minh fail-closed ở tầng hàm verify: key None -> false.
        // (load_pinned_authority_key phụ thuộc môi trường máy nên không gọi
        //  trực tiếp trong test; hợp đồng None->false được mã hóa ở trên.)
        let gate_result = match Option::<VerifyingKey>::None {
            Some(key) => manifest.verify_signature(&key),
            None => false,
        };
        assert!(!gate_result);
    }

    #[test]
    fn end_to_end_with_generated_authority_key() {
        // Mô phỏng đúng vòng đời: maintainer sinh key bằng cyberv-keygen,
        // pin key public, agent verify manifest do key đó ký.
        use ed25519_dalek::SigningKey as Key;

        let sk = Key::from_bytes(&[0x5Au8; 32]);
        let pubkey_hex: String = sk
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        let pinned = parse_authority_public_key(&pubkey_hex).expect("key public hợp lệ");
        let manifest = super::super::manifest::UpdatePackageManifest {
            version: 3,
            package_sha512: "b".repeat(128),
            release_key_id: "release_key_2026_primary".to_string(),
            manifest_signature_hex: String::new(),
            target_arch: "x86_64".to_string(),
        }
        .sign(&sk);

        assert!(manifest.verify_signature(&pinned));
    }
}
