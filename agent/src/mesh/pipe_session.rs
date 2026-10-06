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
//! Pipe handshake (P1-1) — bắt tay 2 bước, xác thực MỘT CHIỀU cho pipe IPC
//!
//! Ref: PHASE1_2 plan P1-1. Khác mesh handshake (3 bước mutual): client UI
//! KHÔNG có khóa identity — xác thực client dựa trên PID do kernel xác nhận
//! (allowlist fail-closed) + DACL của pipe. Server ký HelloAck để client pin
//! khóa agent (chống MITM/squatting). Domain RIÊNG — không dùng chéo với mesh
//! handshake. Khóa phiên: HKDF-SHA512(X25519, transcript) → 2 khóa 2 chiều;
//! phiên AEAD tái dụng nguyên khối `MeshSession` (một primitive, hai nơi dùng).

use hkdf::Hkdf;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::identity::keypair::DeviceIdentityKey;

use super::session::{MeshSession, Role, MESH_WIRE_VERSION, MAX_FRAME_SIZE};
use super::MeshError;

/// Miền chữ ký bắt tay pipe — bóc tách khỏi `CYBERV/MESH/*`.
pub const DOMAIN_PIPE_HANDSHAKE: &[u8] = b"CYBERV/PIPE/HANDSHAKE/v1";
/// Miền dẫn xuất khóa phiên pipe.
pub const DOMAIN_PIPE_SESSION: &[u8] = b"CYBERV/PIPE/SESSION/v1";

/// ClientHello — bước 1: client gửi PK ephemeral (chưa có gì cần ký).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeHello {
    pub version: u32,
    pub pk_ephemeral: [u8; 32],
}

/// ServerHelloAck — bước 2: server trả PK ephemeral + chữ ký identity
/// bám version + CẢ HAI PK (MITM thay PK nào cũng vỡ khi client verify).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeHelloAck {
    pub version: u32,
    pub pk_ephemeral: [u8; 32],
    pub identity_sig: [u8; 64],
}

impl PipeHello {
    /// Canonical: DOMAIN || 0x00 || version(4) || pk(32).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(DOMAIN_PIPE_HANDSHAKE.len() + 38);
        b.extend_from_slice(DOMAIN_PIPE_HANDSHAKE);
        b.push(0x00);
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&self.pk_ephemeral);
        b
    }

    pub fn encode(&self) -> Vec<u8> {
        let body = self.canonical_bytes();
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MeshError> {
        if bytes.len() < 4 {
            return Err(MeshError::Frame("thiếu length prefix".into()));
        }
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(MeshError::Frame(format!("frame quá giới hạn: {len}")));
        }
        let body = bytes
            .get(4..4 + len)
            .ok_or_else(|| MeshError::Frame("độ dài frame lệch prefix".into()))?;
        let dlen = DOMAIN_PIPE_HANDSHAKE.len();
        if body.len() != dlen + 1 + 4 + 32 {
            return Err(MeshError::Frame("thân PipeHello lệch chuẩn".into()));
        }
        if &body[..dlen] != DOMAIN_PIPE_HANDSHAKE || body[dlen] != 0x00 {
            return Err(MeshError::Frame("domain bắt tay pipe sai".into()));
        }
        let version = u32::from_be_bytes([
            body[dlen + 1],
            body[dlen + 2],
            body[dlen + 3],
            body[dlen + 4],
        ]);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&body[dlen + 5..]);
        Ok(Self { version, pk_ephemeral: pk })
    }
}

impl PipeHelloAck {
    /// Canonical: DOMAIN || 0x00 || version(4) || pk(32) || sig(64).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(DOMAIN_PIPE_HANDSHAKE.len() + 102);
        b.extend_from_slice(DOMAIN_PIPE_HANDSHAKE);
        b.push(0x00);
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&self.pk_ephemeral);
        b.extend_from_slice(&self.identity_sig);
        b
    }

    pub fn encode(&self) -> Vec<u8> {
        let body = self.canonical_bytes();
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MeshError> {
        if bytes.len() < 4 {
            return Err(MeshError::Frame("thiếu length prefix".into()));
        }
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(MeshError::Frame(format!("frame quá giới hạn: {len}")));
        }
        let body = bytes
            .get(4..4 + len)
            .ok_or_else(|| MeshError::Frame("độ dài frame lệch prefix".into()))?;
        let dlen = DOMAIN_PIPE_HANDSHAKE.len();
        if body.len() != dlen + 1 + 4 + 32 + 64 {
            return Err(MeshError::Frame("thân PipeHelloAck lệch chuẩn".into()));
        }
        if &body[..dlen] != DOMAIN_PIPE_HANDSHAKE || body[dlen] != 0x00 {
            return Err(MeshError::Frame("domain bắt tay pipe sai".into()));
        }
        let version = u32::from_be_bytes([
            body[dlen + 1],
            body[dlen + 2],
            body[dlen + 3],
            body[dlen + 4],
        ]);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&body[dlen + 5..dlen + 37]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&body[dlen + 37..]);
        Ok(Self { version, pk_ephemeral: pk, identity_sig: sig })
    }
}

/// Payload chữ ký ServerHelloAck: bám version + role + CẢ HAI PK. Công khai
/// vì là wire format (test MITM dựng ack giả để kiểm chứng gate client).
pub fn pipe_ack_sig_payload(
    version: u32,
    client_pk: &[u8; 32],
    server_pk: &[u8; 32],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(DOMAIN_PIPE_HANDSHAKE.len() + 70);
    b.extend_from_slice(DOMAIN_PIPE_HANDSHAKE);
    b.push(0x00);
    b.extend_from_slice(&version.to_be_bytes());
    b.push(Role::Responder.as_u8());
    b.extend_from_slice(client_pk);
    b.extend_from_slice(server_pk);
    b
}

/// HKDF-SHA512 → (khoá client→server, khoá server→client). Salt = transcript
/// hash bám version + cả hai PK — khóa phiên phụ thuộc toàn bộ bắt tay.
pub fn derive_pipe_session_keys(
    shared: &[u8],
    client_pk: &[u8; 32],
    server_pk: &[u8; 32],
    version: u32,
) -> ([u8; 32], [u8; 32]) {
    let mut t = Sha512::new();
    t.update(DOMAIN_PIPE_SESSION);
    t.update([0x00]);
    t.update(version.to_be_bytes());
    t.update(client_pk);
    t.update(server_pk);
    let transcript = t.finalize();
    let hk = Hkdf::<Sha512>::new(Some(&transcript), shared);
    let mut info_c2s = DOMAIN_PIPE_SESSION.to_vec();
    info_c2s.extend_from_slice(b"c2s");
    let mut info_s2c = DOMAIN_PIPE_SESSION.to_vec();
    info_s2c.extend_from_slice(b"s2c");
    let mut k_c2s = [0u8; 32];
    let mut k_s2c = [0u8; 32];
    hk.expand(&info_c2s, &mut k_c2s).expect("HKDF output 32B luôn hợp lệ");
    hk.expand(&info_s2c, &mut k_s2c).expect("HKDF output 32B luôn hợp lệ");
    (k_c2s, k_s2c)
}

/// Phía SERVER: xử lý PipeHello → (HelloAck có chữ ký, phiên AEAD chiều
/// Responder — send = s2c, recv = c2s).
pub fn server_handle_pipe_hello(
    hello: &PipeHello,
    identity: &DeviceIdentityKey,
    eph_secret: &StaticSecret,
    server_pk: &[u8; 32],
) -> Result<(PipeHelloAck, MeshSession), MeshError> {
    if hello.version != MESH_WIRE_VERSION {
        return Err(MeshError::HandshakeFailed(format!(
            "version pipe lệch: {} ≠ {} (downgrade?)",
            hello.version, MESH_WIRE_VERSION
        )));
    }
    let payload = pipe_ack_sig_payload(hello.version, &hello.pk_ephemeral, server_pk);
    let identity_sig = identity.sign(&payload);
    let shared = eph_secret.diffie_hellman(&PublicKey::from(hello.pk_ephemeral));
    let (k_c2s, k_s2c) =
        derive_pipe_session_keys(shared.as_bytes(), &hello.pk_ephemeral, server_pk, hello.version);
    Ok((
        PipeHelloAck {
            version: hello.version,
            pk_ephemeral: *server_pk,
            identity_sig,
        },
        MeshSession::new(Role::Responder, &k_c2s, &k_s2c),
    ))
}

/// Phía CLIENT: verify HelloAck bằng khóa agent đã pin → phiên AEAD.
/// `client_eph_secret` phải là secret sinh ra PK đã gửi trong Hello.
pub fn client_finish_pipe_handshake(
    ack: &PipeHelloAck,
    pinned_agent_vk: &ed25519_dalek::VerifyingKey,
    client_eph_secret: &StaticSecret,
    client_pk: &[u8; 32],
) -> Result<MeshSession, MeshError> {
    if ack.version != MESH_WIRE_VERSION {
        return Err(MeshError::HandshakeFailed(format!(
            "version pipe lệch ở ack: {} ≠ {}",
            ack.version, MESH_WIRE_VERSION
        )));
    }
    let payload = pipe_ack_sig_payload(ack.version, client_pk, &ack.pk_ephemeral);
    DeviceIdentityKey::verify(pinned_agent_vk, &payload, &ack.identity_sig).map_err(|e| {
        MeshError::HandshakeFailed(format!("chữ ký ServerHelloAck không khớp (MITM?): {e}"))
    })?;
    let shared = client_eph_secret.diffie_hellman(&PublicKey::from(ack.pk_ephemeral));
    let (k_c2s, k_s2c) =
        derive_pipe_session_keys(shared.as_bytes(), client_pk, &ack.pk_ephemeral, ack.version);
    Ok(MeshSession::new(Role::Initiator, &k_c2s, &k_s2c))
}

#[cfg(test)]
mod pipe_tests {
    use super::*;
    use crate::identity::rng::{OsCryptoRng, SecureRandom};

    fn eph_pair() -> (StaticSecret, [u8; 32]) {
        let mut seed = [0u8; 32];
        OsCryptoRng.fill(&mut seed).unwrap();
        let secret = StaticSecret::from(seed);
        let pk = PublicKey::from(&secret).to_bytes();
        (secret, pk)
    }

    #[test]
    fn pipe_handshake_roundtrip_both_sessions_agree() {
        let identity = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
        let (client_eph, client_pk) = eph_pair();
        let (server_eph, server_pk) = eph_pair();

        let hello = PipeHello { version: MESH_WIRE_VERSION, pk_ephemeral: client_pk };
        let (ack, mut server_session) =
            server_handle_pipe_hello(&hello, &identity, &server_eph, &server_pk).unwrap();
        let mut client_session =
            client_finish_pipe_handshake(&ack, identity.verifying_key(), &client_eph, &client_pk)
                .unwrap();

        // Trao đổi frame hai chiều qua hai phiên độc lập — key confirmation.
        let f = client_session.seal(1, b"ping").unwrap();
        let (t, p) = server_session.open(&f).unwrap();
        assert_eq!((t, p.as_slice()), (1, b"ping".as_slice()));
        let r = server_session.seal(2, b"pong").unwrap();
        let (t, p) = client_session.open(&r).unwrap();
        assert_eq!((t, p.as_slice()), (2, b"pong".as_slice()));
    }

    #[test]
    fn pipe_ack_binds_client_pk_mitm_substitution_rejected() {
        // MITM thay PK của client trong Hello — ack ký bám PK giả; client
        // THẬT verify bằng PK của chính mình → vỡ.
        let identity = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
        let (client_eph, client_pk) = eph_pair();
        let (_, server_pk) = eph_pair();
        let (attacker_eph, attacker_pk) = eph_pair();

        let hello_forged =
            PipeHello { version: MESH_WIRE_VERSION, pk_ephemeral: attacker_pk };
        let (ack, _) =
            server_handle_pipe_hello(&hello_forged, &identity, &StaticSecret::from([7u8; 32]), &server_pk)
                .unwrap();

        let err = client_finish_pipe_handshake(
            &ack,
            identity.verifying_key(),
            &client_eph,
            &client_pk,
        );
        assert!(matches!(err, Err(MeshError::HandshakeFailed(_))));
        let _ = attacker_eph;
    }

    #[test]
    fn pipe_ack_from_wrong_server_key_rejected_by_pinning() {
        // Server GIẢ ký ack — client pin khóa agent thật → từ chối.
        let real_agent = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
        let fake_agent = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
        let (client_eph, client_pk) = eph_pair();
        let (_, server_pk) = eph_pair();

        let hello = PipeHello { version: MESH_WIRE_VERSION, pk_ephemeral: client_pk };
        let (fake_ack, _) =
            server_handle_pipe_hello(&hello, &fake_agent, &StaticSecret::from([7u8; 32]), &server_pk)
                .unwrap();
        let err = client_finish_pipe_handshake(
            &fake_ack,
            real_agent.verifying_key(),
            &client_eph,
            &client_pk,
        );
        assert!(matches!(err, Err(MeshError::HandshakeFailed(_))));
    }

    #[test]
    fn pipe_hello_version_downgrade_rejected() {
        let identity = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
        let old = PipeHello { version: MESH_WIRE_VERSION - 1, pk_ephemeral: [1; 32] };
        let err = server_handle_pipe_hello(
            &old,
            &identity,
            &StaticSecret::from([7u8; 32]),
            &[0x22; 32],
        );
        assert!(matches!(err, Err(MeshError::HandshakeFailed(_))));
    }

    #[test]
    fn pipe_message_decode_roundtrip_and_rejects() {
        let hello = PipeHello { version: 1, pk_ephemeral: [2; 32] };
        assert_eq!(PipeHello::decode(&hello.encode()).unwrap(), hello);
        let mut cut = hello.encode();
        cut.truncate(cut.len() - 2);
        assert!(PipeHello::decode(&cut).is_err());

        let ack = PipeHelloAck { version: 1, pk_ephemeral: [3; 32], identity_sig: [4; 64] };
        assert_eq!(PipeHelloAck::decode(&ack.encode()).unwrap(), ack);
    }

    // ---- Golden vectors: neo chéo ngôn ngữ Rust <-> Python (P1-1b) ----
    // Khoa co dinh seed [0x42]/[0x43] - moi gia tri deterministic.

    fn gold_client_eph() -> StaticSecret {
        StaticSecret::from([0x42u8; 32])
    }

    fn gold_identity() -> DeviceIdentityKey {
        use crate::identity::secret::Secret32;
        DeviceIdentityKey::from_secret_bytes(&Secret32::new([0x42u8; 32])).unwrap()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    #[ignore = "generator - chay: cargo test --release -p cyberv-agent --lib generate_pipe_golden -- --ignored --nocapture"]
    fn generate_pipe_golden_vectors() {
        let identity = gold_identity();
        let client_eph = gold_client_eph();
        let client_pk = PublicKey::from(&client_eph).to_bytes();
        let server_eph = StaticSecret::from([0x43u8; 32]);
        let server_pk = PublicKey::from(&server_eph).to_bytes();

        let hello = PipeHello { version: MESH_WIRE_VERSION, pk_ephemeral: client_pk };
        let (ack, _server_session) =
            server_handle_pipe_hello(&hello, &identity, &server_eph, &server_pk).unwrap();
        let mut client_session =
            client_finish_pipe_handshake(&ack, identity.verifying_key(), &client_eph, &client_pk)
                .unwrap();
        let frame = client_session.seal(1, b"gold-vectors").unwrap();

        println!("client_pk = {}", hex(&client_pk));
        println!("server_pk = {}", hex(&server_pk));
        println!("ack_sig   = {}", hex(&ack.identity_sig));
        println!("frame     = {}", hex(&frame));
    }

    /// Gia tri sinh boi generate_pipe_golden_vectors (seed 0x42/0x43, version 1)
    /// — Python khai bao CUNG cac hang so nay trong test_pipe_session.py.
    const GOLD_CLIENT_PK: &str =
        "132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472";
    const GOLD_SERVER_PK: &str =
        "cdefd8783a91b446640e2e1f95599db35e484a0071bd2182b3b60d0812c10c70";
    const GOLD_ACK_SIG: &str =
        "e23e84e827e8258f5092cc76645c421382eb34083e994caed90a0b3d1eda0c4d\
         fade275f8ec3f77bd46b6e861d9261fc7c0e3a2c81482d8fa0ff46daaa296a05";
    const GOLD_FRAME: &str =
        "0000002900000001010000000000000000f85797135398f3e3db9e5e2529dbd2\
         56389c1e105c6c008355d80914";

    /// Neo on dinh: cac vector sinh tu generate_pipe_golden_vectors phai KHONG
    /// DOI khi doi implementation - Python (cyberv_ui/ipc/pipe_session.py)
    /// khong dinh CUNG cac gia tri nay (test cheo ngon ngu).
    #[test]
    fn pipe_golden_vectors_are_stable() {
        let identity = gold_identity();
        let client_eph = gold_client_eph();
        let client_pk = PublicKey::from(&client_eph).to_bytes();
        let server_eph = StaticSecret::from([0x43u8; 32]);
        let server_pk = PublicKey::from(&server_eph).to_bytes();

        assert_eq!(hex(&client_pk), GOLD_CLIENT_PK, "client_pk golden lech");
        assert_eq!(hex(&server_pk), GOLD_SERVER_PK, "server_pk golden lech");

        let hello = PipeHello { version: MESH_WIRE_VERSION, pk_ephemeral: client_pk };
        let (ack, _server_session) =
            server_handle_pipe_hello(&hello, &identity, &server_eph, &server_pk).unwrap();
        let mut client_session =
            client_finish_pipe_handshake(&ack, identity.verifying_key(), &client_eph, &client_pk)
                .unwrap();
        let frame = client_session.seal(1, b"gold-vectors").unwrap();

        assert_eq!(hex(&ack.identity_sig), GOLD_ACK_SIG, "ack_sig golden lech");
        assert_eq!(hex(&frame), GOLD_FRAME, "frame golden lech");
    }
}
