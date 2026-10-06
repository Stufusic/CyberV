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
//! Mesh Session — bắt tay 3 bước X25519 + phiên AEAD ChaCha20-Poly1305 (NSG-2)
//!
//! Ref: plan v2 §7.1 (UC-1 bước 2-3), §8 M2 (replay/MITM), §14 (INV-012).
//! Cùng primitive mà PHASE1_2 plan P1-1 chỉ định cho IPC — **một primitive,
//! hai nơi dùng**: tầng mesh hiện dùng, IPC pipe sẽ tái dụng khi P1-1 wire.
//!
//! Bắt tay (mutual attestation — KHÔNG dùng presence làm trust, INV-012):
//! 1. `Hello`   (initiator → responder): version + node_id + PK ephemeral.
//! 2. `HelloAck`(responder → initiator): PK ephemeral + chữ ký identity
//!    **bám cả hai PK ephemeral + hai node_id + version** — MITM thay PK
//!    nào cũng làm chữ ký lệch.
//! 3. `Confirm` (initiator → responder): chữ ký identity theo chiều ngược.
//!
//! Khóa phiên: HKDF-SHA512(X25519(eph, peer_eph), salt = transcript hash,
//! info = domain + chiều) — **hai khóa riêng hai chiều**, nonce = sequence
//! monotonic; frame sai/ replay/ đổi AAD đều từ chối + windows chỉ commit
//! SAU khi tag AEAD verify thành công (kẻ xấu không thể đẩy cửa sổ replay
//! bằng frame giả). Tầng này KHÔNG có I/O — transport đưa bytes, session
//! seal/open.

use hkdf::Hkdf;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

use crate::identity::keypair::DeviceIdentityKey;
use crate::identity::rng::SecureRandom;

use super::graph::NodeId;
use super::MeshError;

/// Miền chữ ký bắt tay — cách ly khỏi mọi domain khác của dự án.
pub const DOMAIN_MESH_HANDSHAKE: &[u8] = b"CYBERV/MESH/HANDSHAKE/v1";
/// Miền dẫn xuất khóa phiên (đồng thời là tiền tố info HKDF).
pub const DOMAIN_MESH_SESSION: &[u8] = b"CYBERV/MESH/SESSION/v1";

/// Phiên bản wire của bắt tay + frame — bám vào chữ ký (chống downgrade).
pub const MESH_WIRE_VERSION: u32 = 1;

/// Giới hạn frame dữ liệu (INV-015 planned — sẽ chuyển signed policy).
pub const MAX_FRAME_SIZE: usize = 64 * 1024;
/// Cửa sổ replay: chấp nhận frame trong 128 sequence gần nhất, không lặp.
pub const REPLAY_WINDOW: u64 = 128;
/// Header tối thiểu của frame dữ liệu: version(4) + type(1) + seq(8).
const DATA_HEADER_LEN: usize = 4 + 1 + 8;
/// Tag AEAD Poly1305.
const TAG_LEN: usize = 16;

/// Vai trò trong bắt tay — bám vào payload chữ ký (chống reflection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    pub const fn as_u8(self) -> u8 {
        match self {
            Role::Initiator => 1,
            Role::Responder => 2,
        }
    }
}

/// Cấu hình bắt tay cho MỘT đầu. `peer_vk` + `peer_node_id` là neo pinning
/// đã lấy từ enrollment (KHÔNG bao giờ tin từ quảng bá mạng — plan §2.3).
pub struct HandshakeConfig<'a> {
    pub identity: &'a DeviceIdentityKey,
    pub peer_vk: ed25519_dalek::VerifyingKey,
    pub peer_node_id: NodeId,
    pub version: u32,
}

impl<'a> HandshakeConfig<'a> {
    fn local_node_id(&self) -> NodeId {
        self.identity.verifying_key().to_bytes()
    }

    fn check_peer(&self, got: NodeId) -> Result<(), MeshError> {
        if got != self.peer_node_id {
            return Err(MeshError::HandshakeFailed(
                "node_id của peer không khớp neo đã pin".into(),
            ));
        }
        Ok(())
    }
}

/// Thông điệp bắt tay — encode/decode canonical có bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeMessage {
    Hello { version: u32, node_id: NodeId, pk_ephemeral: [u8; 32] },
    HelloAck {
        version: u32,
        node_id: NodeId,
        pk_ephemeral: [u8; 32],
        identity_sig: [u8; 64],
    },
    Confirm { version: u32, node_id: NodeId, identity_sig: [u8; 64] },
}

impl HandshakeMessage {
    const HELLO: u8 = 1;
    const HELLO_ACK: u8 = 2;
    const CONFIRM: u8 = 3;

    /// Canonical bytes (KHÔNG có length prefix — lớp frame lo).
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(120);
        b.extend_from_slice(DOMAIN_MESH_HANDSHAKE);
        b.push(0x00);
        match self {
            HandshakeMessage::Hello { version, node_id, pk_ephemeral } => {
                b.push(Self::HELLO);
                b.extend_from_slice(&version.to_be_bytes());
                b.extend_from_slice(node_id);
                b.extend_from_slice(pk_ephemeral);
            }
            HandshakeMessage::HelloAck { version, node_id, pk_ephemeral, identity_sig } => {
                b.push(Self::HELLO_ACK);
                b.extend_from_slice(&version.to_be_bytes());
                b.extend_from_slice(node_id);
                b.extend_from_slice(pk_ephemeral);
                b.extend_from_slice(identity_sig);
            }
            HandshakeMessage::Confirm { version, node_id, identity_sig } => {
                b.push(Self::CONFIRM);
                b.extend_from_slice(&version.to_be_bytes());
                b.extend_from_slice(node_id);
                b.extend_from_slice(identity_sig);
            }
        }
        b
    }

    /// Encode kèm length prefix u32 BE — sẵn sàng đưa xuống transport.
    pub fn encode(&self) -> Vec<u8> {
        let body = self.canonical_bytes();
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode + bounds: chặn trước khi cấp phát, chặn discriminant lạ.
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
            .ok_or_else(|| MeshError::Frame("độ dài frame lệch với prefix".into()))?;
        // Cấu trúc tối thiểu: domain(23) + 0x00 + discriminant + version(4)
        // + node_id(32) — phần sau tùy loại message, take() tự chặn cắt cụt.
        let domain_len = DOMAIN_MESH_HANDSHAKE.len();
        if body.len() < domain_len + 1 + 1 + 4 + 32 {
            return Err(MeshError::Frame("thân bắt tay ngắn bất thường".into()));
        }
        if &body[..domain_len] != DOMAIN_MESH_HANDSHAKE || body[domain_len] != 0x00 {
            return Err(MeshError::Frame("domain bắt tay sai".into()));
        }
        // Discriminant nằm NGAY SAU domain+0x00 — phải thuộc {Hello, HelloAck, Confirm}.
        let discriminant = body[domain_len + 1];
        if !matches!(
            discriminant,
            Self::HELLO | Self::HELLO_ACK | Self::CONFIRM
        ) {
            return Err(MeshError::Frame("discriminant bắt tay lạ".into()));
        }
        // Bỏ domain + 0x00 + discriminant, bắt đầu từ version.
        let mut rd = &body[domain_len + 2..];
        let mut take = |n: usize| -> Result<&[u8], MeshError> {
            if rd.len() < n {
                return Err(MeshError::Frame("thân bắt tay cắt cụt".into()));
            }
            let (chunk, rest) = rd.split_at(n);
            rd = rest;
            Ok(chunk)
        };
        let take_fixed = |slice: &[u8], what: &str| -> Result<[u8; 32], MeshError> {
            slice
                .try_into()
                .map_err(|_| MeshError::Frame(format!("{what} cắt cụt")))
        };
        let version = u32::from_be_bytes(
            take(4)?
                .try_into()
                .map_err(|_| MeshError::Frame("version cắt cụt".into()))?,
        );
        let node_id = take_fixed(take(32)?, "node_id")?;
        match discriminant {
            Self::HELLO => {
                let pk = take_fixed(take(32)?, "pk ephemeral")?;
                if !rd.is_empty() {
                    return Err(MeshError::Frame("Hello dư byte".into()));
                }
                Ok(HandshakeMessage::Hello { version, node_id, pk_ephemeral: pk })
            }
            Self::HELLO_ACK => {
                let pk = take_fixed(take(32)?, "pk ephemeral")?;
                let mut identity_sig = [0u8; 64];
                identity_sig.copy_from_slice(take(64)?);
                if !rd.is_empty() {
                    return Err(MeshError::Frame("HelloAck dư byte".into()));
                }
                Ok(HandshakeMessage::HelloAck { version, node_id, pk_ephemeral: pk, identity_sig })
            }
            Self::CONFIRM => {
                let mut identity_sig = [0u8; 64];
                identity_sig.copy_from_slice(take(64)?);
                if !rd.is_empty() {
                    return Err(MeshError::Frame("Confirm dư byte".into()));
                }
                Ok(HandshakeMessage::Confirm { version, node_id, identity_sig })
            }
            // Đã chặn discriminant lạ ở trên — nếu gặp thì dữ liệu được sửa
            // giữa hai lần đọc: từ chối, không panic (quy tắc dự án).
            _ => Err(MeshError::Frame("discriminant bắt tay lạ".into()))?,
        }
    }
}

/// Payload chữ ký HelloAck (responder ký): bám version + role + CẢ HAI PK
/// ephemeral + CẢ HAI node_id — MITM thay PK nào cũng vỡ. **Công khai** vì
/// là một phần của wire format (plan Phụ lục A) — test tích hợp dựng ack
/// lệch version để kiểm chứng gate phía initiator.
pub fn ack_sig_payload(
    version: u32,
    initiator_pk: &[u8; 32],
    responder_pk: &[u8; 32],
    responder_id: &NodeId,
    initiator_id: &NodeId,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + 1 + 64 + 64);
    b.extend_from_slice(DOMAIN_MESH_HANDSHAKE);
    b.push(0x00);
    b.extend_from_slice(&version.to_be_bytes());
    b.push(Role::Responder.as_u8());
    b.extend_from_slice(initiator_pk);
    b.extend_from_slice(responder_pk);
    b.extend_from_slice(responder_id);
    b.extend_from_slice(initiator_id);
    b
}

/// Payload chữ ký Confirm (initiator ký) — thứ tự PK đảo chiều, role riêng.
/// Công khai cùng lý do với `ack_sig_payload` (wire format, plan Phụ lục A).
pub fn confirm_sig_payload(
    version: u32,
    initiator_pk: &[u8; 32],
    responder_pk: &[u8; 32],
    responder_id: &NodeId,
    initiator_id: &NodeId,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + 1 + 64 + 64);
    b.extend_from_slice(DOMAIN_MESH_HANDSHAKE);
    b.push(0x00);
    b.extend_from_slice(&version.to_be_bytes());
    b.push(Role::Initiator.as_u8());
    b.extend_from_slice(responder_pk);
    b.extend_from_slice(initiator_pk);
    b.extend_from_slice(responder_id);
    b.extend_from_slice(initiator_id);
    b
}

/// Transcript hash cho HKDF salt — bám version + cả hai PK.
fn transcript_hash(
    initiator_pk: &[u8; 32],
    responder_pk: &[u8; 32],
    version: u32,
) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(DOMAIN_MESH_SESSION);
    h.update([0x00]);
    h.update(version.to_be_bytes());
    h.update(initiator_pk);
    h.update(responder_pk);
    let out = h.finalize();
    let mut t = [0u8; 64];
    t.copy_from_slice(&out);
    t
}

/// HKDF-SHA512 → (khoá initiator→responder, khoá responder→initiator).
/// Hai khóa riêng hai chiều: nonce = sequence per-chiều, không đụng nhau.
fn derive_session_keys(
    shared: &[u8],
    initiator_pk: &[u8; 32],
    responder_pk: &[u8; 32],
    version: u32,
) -> ([u8; 32], [u8; 32]) {
    let salt = transcript_hash(initiator_pk, responder_pk, version);
    let hk = Hkdf::<Sha512>::new(Some(&salt), shared);
    let mut i2r = [0u8; 32];
    let mut r2i = [0u8; 32];
    let mut info_i2r = DOMAIN_MESH_SESSION.to_vec();
    info_i2r.extend_from_slice(b"i2r");
    let mut info_r2i = DOMAIN_MESH_SESSION.to_vec();
    info_r2i.extend_from_slice(b"r2i");
    hk.expand(&info_i2r, &mut i2r).expect("HKDF output 32B luôn hợp lệ");
    hk.expand(&info_r2i, &mut r2i).expect("HKDF output 32B luôn hợp lệ");
    (i2r, r2i)
}

/// Đầu khởi tạo — phát Hello, xử lý HelloAck.
pub struct Initiator<'a> {
    cfg: HandshakeConfig<'a>,
    eph_secret: StaticSecret,
    eph_pk: [u8; 32],
}

impl<'a> Initiator<'a> {
    pub fn new(cfg: HandshakeConfig<'a>, rng: &mut impl SecureRandom) -> Result<Self, MeshError> {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed)
            .map_err(|e| MeshError::HandshakeFailed(format!("RNG: {e}")))?;
        let eph_secret = StaticSecret::from(seed);
        let eph_pk = PublicKey::from(&eph_secret).to_bytes();
        Ok(Self { cfg, eph_secret, eph_pk })
    }

    pub fn hello(&self) -> HandshakeMessage {
        HandshakeMessage::Hello {
            version: self.cfg.version,
            node_id: self.cfg.local_node_id(),
            pk_ephemeral: self.eph_pk,
        }
    }

    /// Xử lý HelloAck: verify neo + chữ ký bám transcript → phiên + Confirm.
    pub fn handle_ack(self, ack: &HandshakeMessage) -> Result<(MeshSession, HandshakeMessage), MeshError> {
        let HandshakeMessage::HelloAck { version, node_id, pk_ephemeral, identity_sig } = ack
        else {
            return Err(MeshError::HandshakeFailed(
                "kỳ vọng HelloAck nhưng nhận message khác (reflection?)".into(),
            ));
        };
        if *version != self.cfg.version {
            return Err(MeshError::HandshakeFailed(format!(
                "version lệch: peer {version} ≠ cục bộ {}",
                self.cfg.version
            )));
        }
        self.cfg.check_peer(*node_id)?;
        // Chữ ký phải bám đúng PK ephemeral CỦA CHÚNG TÔI (chống MITM thay PK).
        let payload =
            ack_sig_payload(*version, &self.eph_pk, pk_ephemeral, node_id, &self.cfg.local_node_id());
        DeviceIdentityKey::verify(&self.cfg.peer_vk, &payload, identity_sig).map_err(|e| {
            MeshError::HandshakeFailed(format!("chữ ký HelloAck không khớp (MITM?): {e}"))
        })?;

        let shared = self.eph_secret.diffie_hellman(&PublicKey::from(*pk_ephemeral));
        let (k_i2r, k_r2i) = derive_session_keys(shared.as_bytes(), &self.eph_pk, pk_ephemeral, *version);
        let session = MeshSession::new(Role::Initiator, &k_i2r, &k_r2i);

        let confirm_payload = confirm_sig_payload(
            *version,
            &self.eph_pk,
            pk_ephemeral,
            node_id,
            &self.cfg.local_node_id(),
        );
        let sig = self.cfg.identity.sign(&confirm_payload);
        let confirm = HandshakeMessage::Confirm {
            version: *version,
            node_id: self.cfg.local_node_id(),
            identity_sig: sig,
        };
        Ok((session, confirm))
    }
}

/// Đầu phản hồi — nhận Hello, phát HelloAck, verify Confirm.
pub struct Responder<'a> {
    cfg: HandshakeConfig<'a>,
    eph_secret: StaticSecret,
    eph_pk: [u8; 32],
    peer: Option<(NodeId, [u8; 32])>, // (initiator node_id, initiator pk)
}

impl<'a> Responder<'a> {
    pub fn new(cfg: HandshakeConfig<'a>, rng: &mut impl SecureRandom) -> Result<Self, MeshError> {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed)
            .map_err(|e| MeshError::HandshakeFailed(format!("RNG: {e}")))?;
        let eph_secret = StaticSecret::from(seed);
        let eph_pk = PublicKey::from(&eph_secret).to_bytes();
        Ok(Self { cfg, eph_secret, eph_pk, peer: None })
    }

    pub fn handle_hello(&mut self, hello: &HandshakeMessage) -> Result<HandshakeMessage, MeshError> {
        let HandshakeMessage::Hello { version, node_id, pk_ephemeral } = hello else {
            return Err(MeshError::HandshakeFailed(
                "kỳ vọng Hello nhưng nhận message khác".into(),
            ));
        };
        if *version != self.cfg.version {
            return Err(MeshError::HandshakeFailed(format!(
                "version lệch: peer {version} ≠ cục bộ {} (downgrade?)",
                self.cfg.version
            )));
        }
        self.cfg.check_peer(*node_id)?;
        self.peer = Some((*node_id, *pk_ephemeral));

        let payload =
            ack_sig_payload(*version, pk_ephemeral, &self.eph_pk, &self.cfg.local_node_id(), node_id);
        let identity_sig = self.cfg.identity.sign(&payload);
        Ok(HandshakeMessage::HelloAck {
            version: *version,
            node_id: self.cfg.local_node_id(),
            pk_ephemeral: self.eph_pk,
            identity_sig,
        })
    }

    /// Verify Confirm (chứng minh initiator giữ đúng khóa identity đã pin +
    /// đúng transcript) → phiên AEAD sẵn sàng.
    pub fn handle_confirm(&mut self, confirm: &HandshakeMessage) -> Result<MeshSession, MeshError> {
        let (initiator_id, initiator_pk) = self
            .peer
            .ok_or_else(|| MeshError::HandshakeFailed("chưa nhận Hello".into()))?;
        let HandshakeMessage::Confirm { version, node_id, identity_sig } = confirm else {
            return Err(MeshError::HandshakeFailed(
                "kỳ vọng Confirm nhưng nhận message khác (reflection?)".into(),
            ));
        };
        if *version != self.cfg.version {
            return Err(MeshError::HandshakeFailed(format!(
                "version lệch ở Confirm: {version}"
            )));
        }
        self.cfg.check_peer(*node_id)?;
        if *node_id != initiator_id {
            return Err(MeshError::HandshakeFailed(
                "node_id Confirm đổi giữa chừng".into(),
            ));
        }
        let payload = confirm_sig_payload(*version, &initiator_pk, &self.eph_pk, &self.cfg.local_node_id(), &initiator_id);
        DeviceIdentityKey::verify(&self.cfg.peer_vk, &payload, identity_sig).map_err(|e| {
            MeshError::HandshakeFailed(format!("chữ ký Confirm không khớp: {e}"))
        })?;

        let shared = self.eph_secret.diffie_hellman(&PublicKey::from(initiator_pk));
        let (k_i2r, k_r2i) = derive_session_keys(shared.as_bytes(), &initiator_pk, &self.eph_pk, *version);
        Ok(MeshSession::new(Role::Responder, &k_i2r, &k_r2i))
    }
}

/// Phiên AEAD đã thiết lập: seal/open theo chiều riêng, replay window 128,
/// window CHỈ commit sau khi tag AEAD xác thực thành công.
pub struct MeshSession {
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
    send_seq: u64,
    recv_highest: u64,
    recv_bitmap: u128,
}

impl std::fmt::Debug for MeshSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // KHÔNG BAO GIỜ in khóa/chỉ số nội bộ mật mã qua Debug (tinh thần INV-008).
        f.debug_struct("MeshSession")
            .field("send_seq", &self.send_seq)
            .field("recv_highest", &self.recv_highest)
            .finish_non_exhaustive()
    }
}

impl MeshSession {
    pub(crate) fn new(role: Role, k_i2r: &[u8; 32], k_r2i: &[u8; 32]) -> Self {
        let (send, recv) = match role {
            Role::Initiator => (k_i2r, k_r2i),
            Role::Responder => (k_r2i, k_i2r),
        };
        Self {
            send_cipher: ChaCha20Poly1305::new(Key::from_slice(send)),
            recv_cipher: ChaCha20Poly1305::new(Key::from_slice(recv)),
            send_seq: 0,
            recv_highest: 0,
            recv_bitmap: 0,
        }
    }

    fn nonce(seq: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&seq.to_be_bytes());
        *Nonce::from_slice(&n)
    }

    fn aad(version: u32, frame_type: u8, seq: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&version.to_be_bytes());
        aad.push(frame_type);
        aad.extend_from_slice(&seq.to_be_bytes());
        aad
    }

    /// Mã hóa + đóng khung wire: `len(u32) || version(4) || type(1) || seq(8) || ct`.
    pub fn seal(&mut self, frame_type: u8, payload: &[u8]) -> Result<Vec<u8>, MeshError> {
        if payload.len().saturating_add(DATA_HEADER_LEN + TAG_LEN) > MAX_FRAME_SIZE {
            return Err(MeshError::Frame(format!(
                "payload vượt giới hạn frame: {}",
                payload.len()
            )));
        }
        if self.send_seq == u64::MAX {
            return Err(MeshError::Crypto("sequence phiên đã cạn".into()));
        }
        let seq = self.send_seq;
        self.send_seq = self.send_seq.saturating_add(1);
        let aad = Self::aad(MESH_WIRE_VERSION, frame_type, seq);
        let ct = self
            .send_cipher
            .encrypt(&Self::nonce(seq), Payload { msg: payload, aad: &aad })
            .map_err(|e| MeshError::Crypto(format!("mã hóa thất bại: {e}")))?;

        let body_len = (DATA_HEADER_LEN + ct.len()) as u32;
        let mut frame = Vec::with_capacity(4 + body_len as usize);
        frame.extend_from_slice(&body_len.to_be_bytes());
        frame.extend_from_slice(&MESH_WIRE_VERSION.to_be_bytes());
        frame.push(frame_type);
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&ct);
        Ok(frame)
    }

    /// Giải mã khung wire. Replay window chỉ commit SAU khi tag verify —
    /// frame giả không thể đẩy frame thật ra khỏi cửa sổ.
    pub fn open(&mut self, frame: &[u8]) -> Result<(u8, Vec<u8>), MeshError> {
        if frame.len() < 4 {
            return Err(MeshError::Frame("frame ngắn hơn length prefix".into()));
        }
        let body_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        if body_len > MAX_FRAME_SIZE {
            return Err(MeshError::Frame(format!("frame vượt giới hạn: {body_len}")));
        }
        if frame.len() != 4 + body_len {
            return Err(MeshError::Frame(format!(
                "độ dài frame lệch prefix: {} ≠ {}",
                frame.len(),
                4 + body_len
            )));
        }
        if body_len < DATA_HEADER_LEN + TAG_LEN {
            return Err(MeshError::Frame("thân frame ngắn bất thường".into()));
        }
        let body = &frame[4..];
        let version = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        if version != MESH_WIRE_VERSION {
            return Err(MeshError::UnsupportedVersion(version));
        }
        let frame_type = body[4];
        let seq = u64::from_be_bytes(
            body[5..13]
                .try_into()
                .map_err(|_| MeshError::Frame("sequence cắt cụt".into()))?,
        );
        let aad = Self::aad(version, frame_type, seq);

        // Cửa sổ replay — tính trạng thái mới nhưng CHƯA commit.
        let fresh = seq > self.recv_highest;
        let in_window = !fresh
            && self.recv_highest.saturating_sub(seq) < REPLAY_WINDOW
            && self.recv_highest.saturating_sub(seq) < 128;
        let bit = if fresh {
            0u128
        } else {
            1u128 << (self.recv_highest - seq)
        };
        let already_seen = !fresh && in_window && (self.recv_bitmap & bit) != 0;
        if already_seen {
            return Err(MeshError::Crypto(format!("frame replay (seq {seq})")));
        }
        if !fresh && !in_window {
            return Err(MeshError::Crypto(format!(
                "frame quá cũ so với cửa sổ (seq {seq})"
            )));
        }

        let payload = self
            .recv_cipher
            .decrypt(&Self::nonce(seq), Payload { msg: &body[13..], aad: &aad })
            .map_err(|e| MeshError::Crypto(format!("giải mã thất bại (tag/AAD): {e}")))?;

        // Tag đã verify — commit cửa sổ.
        if fresh {
            let shift = seq.saturating_sub(self.recv_highest).min(127);
            self.recv_bitmap = if shift >= 128 { 0 } else { (self.recv_bitmap << shift) | 1 };
            self.recv_highest = seq;
        } else {
            self.recv_bitmap |= bit;
        }
        Ok((frame_type, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::rng::OsCryptoRng;

    fn make_pair() -> (DeviceIdentityKey, DeviceIdentityKey) {
        (
            DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap(),
            DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap(),
        )
    }

    fn full_handshake() -> (MeshSession, MeshSession) {
        let (ka, kb) = make_pair();
        let init = Initiator::new(
            HandshakeConfig {
                identity: &ka,
                peer_vk: *kb.verifying_key(),
                peer_node_id: kb.verifying_key().to_bytes(),
                version: MESH_WIRE_VERSION,
            },
            &mut OsCryptoRng,
        )
        .unwrap();
        let mut resp = Responder::new(
            HandshakeConfig {
                identity: &kb,
                peer_vk: *ka.verifying_key(),
                peer_node_id: ka.verifying_key().to_bytes(),
                version: MESH_WIRE_VERSION,
            },
            &mut OsCryptoRng,
        )
        .unwrap();
        let hello = init.hello();
        let ack = resp.handle_hello(&hello).unwrap();
        let (session_i, confirm) = init.handle_ack(&ack).unwrap();
        let session_r = resp.handle_confirm(&confirm).unwrap();
        (session_i, session_r)
    }

    #[test]
    fn seal_open_roundtrip_both_directions() {
        let (mut a, mut r) = full_handshake();
        let frame = a.seal(7, b"ping").unwrap();
        let (t, p) = r.open(&frame).unwrap();
        assert_eq!((t, p.as_slice()), (7, b"ping".as_slice()));
        let reply = r.seal(8, b"pong").unwrap();
        let (t, p) = a.open(&reply).unwrap();
        assert_eq!((t, p.as_slice()), (8, b"pong".as_slice()));
    }

    #[test]
    fn replayed_frame_rejected() {
        let (mut a, mut r) = full_handshake();
        let frame = a.seal(1, b"x").unwrap();
        r.open(&frame).unwrap();
        let err = r.open(&frame).unwrap_err();
        assert!(matches!(err, MeshError::Crypto(_)));
    }

    #[test]
    fn out_of_window_frame_rejected() {
        let (mut a, mut r) = full_handshake();
        let old = a.seal(1, b"old").unwrap();
        // Đẩy hơn 128 frame — frame cũ rơi ra ngoài cửa sổ.
        for i in 0..200u8 {
            let f = a.seal(1, &[i]).unwrap();
            r.open(&f).unwrap();
        }
        let err = r.open(&old).unwrap_err();
        assert!(matches!(err, MeshError::Crypto(_)));
    }

    #[test]
    fn tampered_ciphertext_and_aad_rejected() {
        let (mut a, mut r) = full_handshake();
        let mut frame = a.seal(1, b"secret").unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert!(r.open(&frame).is_err());

        let mut frame2 = a.seal(1, b"secret").unwrap();
        frame2[8] ^= 0x01; // đụng header (AAD) — phải vỡ tag
        assert!(r.open(&frame2).is_err());
    }

    #[test]
    fn oversized_frame_rejected() {
        let (mut a, _r) = full_handshake();
        let big = vec![0u8; MAX_FRAME_SIZE];
        assert!(matches!(
            a.seal(1, &big),
            Err(MeshError::Frame(_))
        ));
    }

    #[test]
    fn frame_length_prefix_mismatch_rejected() {
        let (mut a, mut r) = full_handshake();
        let mut frame = a.seal(1, b"data").unwrap();
        frame[0] = 0xFF; // prefix gian lận
        assert!(r.open(&frame).is_err());
    }

    #[test]
    fn hello_message_decode_rejects_garbage() {
        let junk = [0u8; 10];
        assert!(HandshakeMessage::decode(&junk).is_err());
        let mut truncated = HandshakeMessage::Hello {
            version: 1,
            node_id: [0; 32],
            pk_ephemeral: [1; 32],
        }
        .encode();
        truncated.truncate(truncated.len() - 4);
        assert!(HandshakeMessage::decode(&truncated).is_err());
    }
}

