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
//! CyberV Update Authority Key Generator — công cụ OFFLINE (M1, miễn phí)
//!
//! Ref: Docs/PIPELINE_SECURITY_PLAN.md Phần D (Key Custody Model) +
//! Docs/DRIVER_SIGNING_RUNBOOK.md.
//!
//! Vòng đời chuẩn:
//!   1. `generate`  — chạy TRÊN MÁY KHÍ-GAP: sinh seed Ed25519 + chia 3 share
//!      Shamir 2-of-3. Mỗi maintainer giữ 1 share (giấy/offline).
//!   2. `reconstruct` — xác minh 2 share tái tạo đúng key public đã pin.
//!   3. `sign`      — ký UpdatePackageManifest bằng 2 share (dùng release).
//!   4. `verify`    — kiểm tra manifest bằng key public (ai cũng chạy được).
//!
//! Private key KHÔNG BAO GIỜ được in ra màn hình hay ghi ra tệp — chỉ tồn tại
//! trong bộ nhớ và bị zeroize khi tiến trình kết thúc.

use cyberv_agent::defense::passive::update::manifest::UpdatePackageManifest;
use cyberv_agent::defense::passive::update::authority::parse_authority_public_key;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::fmt::Write as _;
use std::path::PathBuf;
use zeroize::Zeroize;

// ================= GF(256) arithmetic — đa thức AES 0x11B =================

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        // xtime
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

fn gf_pow(mut base: u8, mut exp: u8) -> u8 {
    let mut acc = 1u8;
    while exp != 0 {
        if exp & 1 != 0 {
            acc = gf_mul(acc, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    acc
}

fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "GF(256) inverse của 0 không tồn tại");
    gf_pow(a, 254)
}

// ================= Shamir Secret Sharing 2-of-3 =================

const SHARE_COUNT: u8 = 3;
const SECRET_LEN: usize = 32;

/// Chia secret thành `SHARE_COUNT` share (x = 1..=3). Bất kỳ 2 share nào
/// tái tạo được secret; 1 share không tiết lộ gì (đa thức bậc 1 ngẫu nhiên).
fn shamir_split(secret: &[u8; SECRET_LEN]) -> [[u8; SECRET_LEN + 1]; SHARE_COUNT as usize] {
    let mut rng = rand::rngs::OsRng;
    let mut shares = [[0u8; SECRET_LEN + 1]; SHARE_COUNT as usize];
    for (j, share) in shares.iter_mut().enumerate() {
        share[0] = (j + 1) as u8; // x của share, bắt đầu từ 1 (x=0 chính là secret)
    }

    for (i, &s) in secret.iter().enumerate() {
        let mut coeff = [0u8; 1];
        rng.fill_bytes(&mut coeff);
        let a1 = coeff[0];
        for share in shares.iter_mut() {
            // f(x) = s + a1*x (GF(256)); share y = f(x)
            share[i + 1] = s ^ gf_mul(a1, share[0]);
        }
    }
    shares
}

/// Tái tạo secret từ đúng 2 share (x phải khác nhau).
fn shamir_join(share_a: &[u8; SECRET_LEN + 1], share_b: &[u8; SECRET_LEN + 1]) -> [u8; SECRET_LEN] {
    assert!(
        share_a[0] != share_b[0],
        "Hai share phải có chỉ số khác nhau"
    );
    let (x1, x2) = (share_a[0], share_b[0]);

    // Lagrange tại x=0: secret = y1 * (x2/(x2-x1)) + y2 * (x1/(x1-x2))
    let l1 = gf_mul(x2, gf_inv(x2 ^ x1));
    let l2 = gf_mul(x1, gf_inv(x1 ^ x2));

    let mut secret = [0u8; SECRET_LEN];
    for i in 0..SECRET_LEN {
        secret[i] = gf_mul(share_a[i + 1], l1) ^ gf_mul(share_b[i + 1], l2);
    }
    secret
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Đọc 1 share từ tệp: dòng hex 66 ký tự (1 byte chỉ số + 32 byte payload)
fn parse_share_hex(hex: &str) -> Result<[u8; SECRET_LEN + 1], String> {
    let trimmed = hex.trim();
    if trimmed.len() != (SECRET_LEN + 1) * 2 {
        return Err(format!(
            "Share phải là {} ký tự hex, nhận được {} ký tự",
            (SECRET_LEN + 1) * 2,
            trimmed.len()
        ));
    }
    let mut out = [0u8; SECRET_LEN + 1];
    let bytes = trimmed.as_bytes();
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    for (i, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (hex_val(chunk[0]).ok_or("Share chứa ký tự không phải hex")? << 4)
            | hex_val(chunk[1]).ok_or("Share chứa ký tự không phải hex")?;
    }
    if out[0] == 0 || out[0] > SHARE_COUNT {
        return Err(format!("Chỉ số share không hợp lệ: {}", out[0]));
    }
    Ok(out)
}

fn read_share_file(path: &str) -> Result<[u8; SECRET_LEN + 1], String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Không đọc được share file {}: {}", path, e))?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        return parse_share_hex(line);
    }
    Err(format!("File {} không chứa dòng share hex nào", path))
}

/// Tái tạo SigningKey từ 2 share file; seed bị zeroize khi key drop.
fn signing_key_from_shares(
    share_a_path: &str,
    share_b_path: &str,
) -> Result<(SigningKey, String), String> {
    let a = read_share_file(share_a_path)?;
    let b = read_share_file(share_b_path)?;
    if a[0] == b[0] {
        return Err("Hai share trùng chỉ số — cần 2 share KHÁC nhau (2-of-3)".to_string());
    }
    let mut seed = shamir_join(&a, &b);
    let sk = SigningKey::from_bytes(&seed);
    seed.zeroize();

    let pubkey_hex = to_hex(sk.verifying_key().as_bytes());
    Ok((sk, pubkey_hex))
}

fn write_share_files(out_dir: &PathBuf, shares: &[[u8; SECRET_LEN + 1]; 3]) -> Result<(), String> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("Không tạo được thư mục {}: {}", out_dir.display(), e))?;
    for (idx, share) in shares.iter().enumerate() {
        let path = out_dir.join(format!("authority_share_{}_of_3.txt", idx + 1));
        let content = format!(
            "# CyberV Update Authority Key - share {}/3 (Shamir 2-of-3)\n\
             # GIỮ OFFLINE: in ra giấy hoặc lưu vào USB kín. KHÔNG commit, KHÔNG đưa lên cloud.\n\
             # Cần ĐỦ 2 share bất kỳ trong 3 share để ký release. Mất 2 share trở lên = mất khả năng ký.\n\
             {}\n",
            idx + 1,
            to_hex(share)
        );
        std::fs::write(&path, content)
            .map_err(|e| format!("Không ghi được {}: {}", path.display(), e))?;
    }
    Ok(())
}

const USAGE: &str = "cyberv-keygen — Update Authority Key tool (OFFLINE ONLY)

Lệnh:
  generate   --out-dir <DIR>
      Sinh seed Ed25519 mới + chia 3 share Shamir 2-of-3 vào DIR.
      Ghi: authority_share_{1,2,3}_of_3.txt + authority_public_key.txt

  reconstruct --share-a <FILE> --share-b <FILE>
      Tái tạo key từ 2 share và CHỈ in key public (để xác minh trước khi pin).

  sign --manifest <FILE.json> --share-a <FILE> --share-b <FILE>
      Ký UpdatePackageManifest (ghi đè file với manifest_signature_hex mới).

  verify --manifest <FILE.json> --public-key <HEX64>
      Kiểm tra chữ ký manifest bằng key public (ai cũng chạy được).
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{}", USAGE);
        std::process::exit(2);
    }

    let result = match args[0].as_str() {
        "generate" => cmd_generate(&args[1..]),
        "reconstruct" => cmd_reconstruct(&args[1..]),
        "sign" => cmd_sign(&args[1..]),
        "verify" => cmd_verify(&args[1..]),
        "--help" | "-h" | "help" => Ok(()),
        _ => Err(format!("Lệnh không rõ: {}. Xem --help.", args[0])),
    };

    if let Err(e) = result {
        eprintln!("[LỖI] {}", e);
        std::process::exit(1);
    }
}

fn take_opt(args: &[String], flag: &str) -> Result<String, String> {
    let pos = args
        .iter()
        .position(|a| a == flag)
        .ok_or_else(|| format!("Thiếu tham số {}", flag))?;
    args.get(pos + 1)
        .cloned()
        .ok_or_else(|| format!("{} cần một giá trị", flag))
}

fn cmd_generate(args: &[String]) -> Result<(), String> {
    let out_dir = PathBuf::from(take_opt(args, "--out-dir")?);

    let mut seed = [0u8; SECRET_LEN];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let shares = shamir_split(&seed);

    // Key public tính từ seed rồi mới zeroize — seed không bao giờ rời bộ nhớ
    let sk = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let pubkey_hex = to_hex(sk.verifying_key().as_bytes());
    drop(sk);

    write_share_files(&out_dir, &shares)?;

    let pubkey_path = out_dir.join("authority_public_key.txt");
    std::fs::write(&pubkey_path, format!("{}\n", pubkey_hex))
        .map_err(|e| format!("Không ghi được {}: {}", pubkey_path.display(), e))?;

    println!("Đã sinh Update Authority Key (Ed25519) và chia 3 share Shamir 2-of-3.");
    println!();
    println!("  KEY PUBLIC (pin vào cấu hình agent / CI):");
    println!("    {}", pubkey_hex);
    println!();
    for idx in 1..=3 {
        let path = out_dir.join(format!("authority_share_{}_of_3.txt", idx));
        println!("  Share {}/3: {}", idx, path.display());
    }
    println!();
    println!("HƯỚNG DẪN LƯU TRỮ:");
    println!("  1. In mỗi share ra giấy HOẶC lưu vào USB riêng, giao 3 người giữ.");
    println!("  2. XÓA các file share khỏi máy này sau khi lưu trữ an toàn.");
    println!("  3. Cấu hình agent: đặt env CYBERV_UPDATE_AUTHORITY_PUBLIC_KEY=<key public ở trên>");
    println!("     hoặc ghi key public vào ProgramData\\CyberV\\update_authority.pub");
    println!("  4. Xác minh tái tạo: cyberv-keygen reconstruct --share-a f1 --share-b f2");
    println!("     -> key public in ra phải TRÙNG KHỚP với key public ở trên.");
    Ok(())
}

fn cmd_reconstruct(args: &[String]) -> Result<(), String> {
    let share_a = take_opt(args, "--share-a")?;
    let share_b = take_opt(args, "--share-b")?;
    let (_sk, pubkey_hex) = signing_key_from_shares(&share_a, &share_b)?;
    println!("{}", pubkey_hex);
    println!("(So khớp key public này với key đã pin — trùng khớp nghĩa là 2 share hợp lệ.)");
    Ok(())
}

fn cmd_sign(args: &[String]) -> Result<(), String> {
    let manifest_path = take_opt(args, "--manifest")?;
    let share_a = take_opt(args, "--share-a")?;
    let share_b = take_opt(args, "--share-b")?;

    let json = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Không đọc được manifest {}: {}", manifest_path, e))?;
    let manifest: UpdatePackageManifest = serde_json::from_str(&json)
        .map_err(|e| format!("Manifest không hợp lệ (JSON/Trường): {}", e))?;

    let (sk, pubkey_hex) = signing_key_from_shares(&share_a, &share_b)?;
    let signed = manifest.clone().sign(&sk);
    drop(sk);

    let output = serde_json::to_string_pretty(&signed)
        .map_err(|e| format!("Serialize lại manifest thất bại: {}", e))?;
    std::fs::write(&manifest_path, output + "\n")
        .map_err(|e| format!("Không ghi manifest {}: {}", manifest_path, e))?;

    println!("Đã ký manifest v{} bằng authority key.", signed.version);
    println!("  Key public (ký): {}", pubkey_hex);
    println!("  Signature:       {}", signed.manifest_signature_hex);
    println!("  Đối chiếu chữ ký với key public đã pin trước khi phát hành!");
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let manifest_path = take_opt(args, "--manifest")?;
    let pubkey_hex = take_opt(args, "--public-key")?;

    let json = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Không đọc được manifest {}: {}", manifest_path, e))?;
    let manifest: UpdatePackageManifest = serde_json::from_str(&json)
        .map_err(|e| format!("Manifest không hợp lệ: {}", e))?;
    let pinned = parse_authority_public_key(&pubkey_hex)?;

    if manifest.verify_signature(&pinned) {
        println!("OK: chữ ký manifest v{} HỢP LỆ với key public đã cho.", manifest.version);
        Ok(())
    } else {
        println!("TỪ CHỐI: chữ ký manifest v{} KHÔNG khớp key public đã cho.", manifest.version);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_arithmetic_matches_known_values() {
        // Ví dụ kinh điển của AES/GF(2^8) với đa thức 0x11B
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
        assert_eq!(gf_mul(0x57, 0x02), 0xAE); // xtime(0x57)
        assert_eq!(gf_mul(0x80, 0x02), 0x1B); // overflow quay lại đa thức
        assert_eq!(gf_mul(0x53, gf_inv(0x53)), 0x01); // a * a^-1 = 1
        assert_eq!(gf_mul(0x00, 0xFF), 0x00);
    }

    #[test]
    fn shamir_roundtrip_for_every_share_pair() {
        let mut secret = [0u8; SECRET_LEN];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let shares = shamir_split(&secret);

        let pairs = [(0usize, 1usize), (0, 2), (1, 2)];
        for (i, j) in pairs {
            let recovered = shamir_join(&shares[i], &shares[j]);
            assert_eq!(recovered, secret, "cặp share ({}, {}) phải tái tạo đúng", i + 1, j + 1);
        }
    }

    #[test]
    fn different_shares_for_same_secret_look_unrelated() {
        let secret = [0x11u8; SECRET_LEN];
        let s1 = shamir_split(&secret);
        let s2 = shamir_split(&secret);
        // Hai lần chia cùng 1 secret phải cho share payload khác nhau
        // (coefficient a1 ngẫu nhiên) — nếu không, share có thể suy ra secret.
        assert_ne!(s1[0][1..], s2[0][1..]);
        assert_ne!(s1[1][1..], s2[1][1..]);
    }

    #[test]
    fn single_share_reveals_nothing_structural() {
        // Đa thức bậc 1: 1 điểm không xác định được hằng số — kiểm tra cấu trúc:
        // mỗi share chỉ là (x, f(x)) với f(0) = secret; không có phép kiểm tra
        // trực tiếp ngoài toán học, nhưng đảm bảo share KHÔNG chứa secret phẳng.
        let secret = [0xABu8; SECRET_LEN];
        let shares = shamir_split(&secret);
        for share in shares.iter() {
            assert_ne!(&share[1..], &secret[..], "share không được trùng secret");
        }
    }

    #[test]
    fn parse_share_rejects_bad_input() {
        // Share hợp lệ: byte chỉ số (01..=03) + 32 byte payload
        let mut valid = "01".to_string();
        valid.push_str(&"ab".repeat(32));
        assert!(parse_share_hex(&valid).is_ok());

        assert!(parse_share_hex(&"ab".repeat(32)).is_err()); // thiếu độ dài
        assert!(parse_share_hex(&"zz".repeat(33)).is_err()); // không hex
        // Chỉ số 0 hoặc >3 bị từ chối
        let mut bad = "00".to_string();
        bad.push_str(&"ab".repeat(32));
        assert!(parse_share_hex(&bad).is_err());
        let mut bad2 = "04".to_string();
        bad2.push_str(&"ab".repeat(32));
        assert!(parse_share_hex(&bad2).is_err());
    }
}
