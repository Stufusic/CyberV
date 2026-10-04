"""
Pipe Session cho CyberV UI (P1-1b) — bắt tay 2 bước + phiên AEAD ChaCha20-Poly1305.

Ref: Docs/PHASE1_2_IMPLEMENTATION_PLAN.md P1-1b; đối xứng với
`agent/src/mesh/pipe_session.rs` + `mesh/session.rs`. Cross-language
compatibility được neo bằng GOLDEN VECTORS (test cả hai phía phải khớp
byte-for-byte — đổi bên nào cũng vỡ test bên kia).

Ranh giới trung thực (INV-012): client KHÔNG có khóa identity — xác thực
client dựa vào PID do kernel xác nhận (server_seen_client_pid) + DACL pipe;
server được client xác thực bằng khóa đã PIN (`pinned_agent_pub`). Không pin
khóa = không kết nối (fail-closed), không downgrade về plaintext.
"""

import hashlib
import os
from typing import Optional, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PIPE_HANDSHAKE_DOMAIN = b"CYBERV/PIPE/HANDSHAKE/v1"
PIPE_SESSION_DOMAIN = b"CYBERV/PIPE/SESSION/v1"
MESH_WIRE_VERSION = 1
MAX_FRAME_BODY = 65536 + 128  # envelope 64KB + header AEAD + tag (khớp server)

ROLE_RESPONDER = 2  # khớp mesh::session::Role::Responder.as_u8()

DEFAULT_PIN_PATH = os.path.join(
    os.environ.get("PROGRAMDATA", ""), "CyberV", "agent_public_key.hex"
)


class PipeSessionError(Exception):
    """Lỗi cơ sở của phiên pipe — mọi nhánh lỗi đều là nhánh TỪ CHỐI."""


class PipeHandshakeError(PipeSessionError):
    pass


class PipeFrameError(PipeSessionError):
    pass


def pipe_ack_sig_payload(version: int, client_pk: bytes, server_pk: bytes) -> bytes:
    """Payload chữ ký ServerHelloAck — khớp `pipe_ack_sig_payload` Rust."""
    return (
        PIPE_HANDSHAKE_DOMAIN
        + b"\x00"
        + version.to_bytes(4, "big")
        + bytes([ROLE_RESPONDER])
        + client_pk
        + server_pk
    )


def derive_pipe_session_keys(
    shared: bytes, client_pk: bytes, server_pk: bytes, version: int
) -> Tuple[bytes, bytes]:
    """HKDF-SHA512 → (k_c2s, k_s2c) — khớp `derive_pipe_session_keys` Rust."""
    transcript = hashlib.sha512(
        PIPE_SESSION_DOMAIN
        + b"\x00"
        + version.to_bytes(4, "big")
        + client_pk
        + server_pk
    ).digest()
    k_c2s = HKDF(
        algorithm=hashes.SHA512(), length=32, salt=transcript,
        info=PIPE_SESSION_DOMAIN + b"c2s",
    ).derive(shared)
    k_s2c = HKDF(
        algorithm=hashes.SHA512(), length=32, salt=transcript,
        info=PIPE_SESSION_DOMAIN + b"s2c",
    ).derive(shared)
    return k_c2s, k_s2c


def encode_pipe_hello(version: int, client_pk: bytes) -> bytes:
    """PipeHello wire: len(4 BE) || DOMAIN || 0x00 || version(4) || pk(32)."""
    body = (
        PIPE_HANDSHAKE_DOMAIN
        + b"\x00"
        + version.to_bytes(4, "big")
        + client_pk
    )
    return len(body).to_bytes(4, "big") + body


def decode_pipe_hello_ack(raw: bytes) -> Tuple[int, bytes, bytes]:
    """Parse PipeHelloAck: len || DOMAIN || 0x00 || version(4) || pk(32) || sig(64)."""
    if len(raw) < 4:
        raise PipeFrameError("thiếu length prefix")
    body_len = int.from_bytes(raw[:4], "big")
    if len(raw) != 4 + body_len:
        raise PipeFrameError("độ dài frame lệch prefix")
    body = raw[4:]
    dlen = len(PIPE_HANDSHAKE_DOMAIN)
    if body_len != dlen + 1 + 4 + 32 + 64:
        raise PipeFrameError("thân PipeHelloAck lệch chuẩn")
    if body[:dlen] != PIPE_HANDSHAKE_DOMAIN or body[dlen] != 0x00:
        raise PipeFrameError("domain bắt tay pipe sai")
    version = int.from_bytes(body[dlen + 1 : dlen + 5], "big")
    server_pk = body[dlen + 5 : dlen + 37]
    sig = body[dlen + 37 :]
    return version, server_pk, sig


def client_finish_pipe_handshake(
    ack_raw: bytes,
    pinned_agent_pub: bytes,
    client_priv: X25519PrivateKey,
    client_pk: bytes,
) -> "PipeSession":
    """Verify chữ ký ack bằng khóa agent ĐÃ PIN → phiên AEAD. Sai khóa /
    sai version / MITM thay PK → PipeHandshakeError (fail-closed)."""
    version, server_pk, sig = decode_pipe_hello_ack(ack_raw)
    if version != MESH_WIRE_VERSION:
        raise PipeHandshakeError(
            f"version pipe lệch ở ack: {version} != {MESH_WIRE_VERSION}"
        )
    payload = pipe_ack_sig_payload(version, client_pk, server_pk)
    try:
        Ed25519PublicKey.from_public_bytes(pinned_agent_pub).verify(sig, payload)
    except InvalidSignature as e:
        raise PipeHandshakeError(
            f"chữ ký ServerHelloAck không khớp khóa đã pin (MITM?): {e}"
        ) from e
    shared = client_priv.exchange(X25519PublicKey.from_public_bytes(server_pk))
    k_c2s, k_s2c = derive_pipe_session_keys(shared, client_pk, server_pk, version)
    return PipeSession(k_c2s, k_s2c)


def server_handle_pipe_hello(
    hello_raw: bytes,
    identity_priv: Ed25519PrivateKey,
    server_priv: X25519PrivateKey,
    server_pk: bytes,
) -> Tuple[bytes, "PipeSession"]:
    """Phía SERVER (dùng cho fake server trong test): trả (ack_bytes, session)."""
    if len(hello_raw) < 4:
        raise PipeFrameError("thiếu length prefix")
    body_len = int.from_bytes(hello_raw[:4], "big")
    body = hello_raw[4:]
    dlen = len(PIPE_HANDSHAKE_DOMAIN)
    if len(body) != body_len or body_len != dlen + 1 + 4 + 32:
        raise PipeFrameError("thân PipeHello lệch chuẩn")
    if body[:dlen] != PIPE_HANDSHAKE_DOMAIN or body[dlen] != 0x00:
        raise PipeFrameError("domain bắt tay pipe sai")
    version = int.from_bytes(body[dlen + 1 : dlen + 5], "big")
    if version != MESH_WIRE_VERSION:
        raise PipeHandshakeError(
            f"version pipe lệch: {version} != {MESH_WIRE_VERSION} (downgrade?)"
        )
    client_pk = body[dlen + 5 :]
    payload = pipe_ack_sig_payload(version, client_pk, server_pk)
    sig = identity_priv.sign(payload)
    ack_body = (
        PIPE_HANDSHAKE_DOMAIN
        + b"\x00"
        + version.to_bytes(4, "big")
        + server_pk
        + sig
    )
    ack = len(ack_body).to_bytes(4, "big") + ack_body
    shared = server_priv.exchange(X25519PublicKey.from_public_bytes(client_pk))
    k_c2s, k_s2c = derive_pipe_session_keys(shared, client_pk, server_pk, version)
    return ack, PipeSession(k_s2c, k_c2s)  # server: send=s2c, recv=c2s


class PipeSession:
    """Phiên AEAD hai chiều — khớp `mesh::session::MeshSession`:
    nonce = 4 byte 0 || seq(8 BE), AAD = version(4) || type(1) || seq(8),
    replay window 128 CHỈ commit sau khi tag verify thành công."""

    def __init__(self, send_key: bytes, recv_key: bytes):
        self._send = ChaCha20Poly1305(send_key)
        self._recv = ChaCha20Poly1305(recv_key)
        self._send_seq = 0
        self._recv_highest = -1
        self._recv_bitmap = 0

    @staticmethod
    def _nonce(seq: int) -> bytes:
        return b"\x00" * 4 + seq.to_bytes(8, "big")

    @staticmethod
    def _aad(version: int, frame_type: int, seq: int) -> bytes:
        return version.to_bytes(4, "big") + bytes([frame_type]) + seq.to_bytes(8, "big")

    def seal(self, frame_type: int, payload: bytes) -> bytes:
        if self._send_seq >= 2**64 - 1:
            raise PipeSessionError("sequence phiên đã cạn")
        seq = self._send_seq
        self._send_seq += 1
        ct = self._send.encrypt(self._nonce(seq), payload, self._aad(MESH_WIRE_VERSION, frame_type, seq))
        body = (
            MESH_WIRE_VERSION.to_bytes(4, "big")
            + bytes([frame_type])
            + seq.to_bytes(8, "big")
            + ct
        )
        return len(body).to_bytes(4, "big") + body

    def open(self, frame: bytes) -> Tuple[int, bytes]:
        if len(frame) < 4:
            raise PipeFrameError("frame ngắn hơn length prefix")
        body_len = int.from_bytes(frame[:4], "big")
        if body_len > MAX_FRAME_BODY:
            raise PipeFrameError(f"frame vượt giới hạn: {body_len}")
        if len(frame) != 4 + body_len:
            raise PipeFrameError("độ dài frame lệch prefix")
        if body_len < 13 + 16:
            raise PipeFrameError("thân frame ngắn bất thường")
        body = frame[4:]
        version = int.from_bytes(body[0:4], "big")
        if version != MESH_WIRE_VERSION:
            raise PipeFrameError(f"phiên bản wire không hỗ trợ: {version}")
        frame_type = body[4]
        seq = int.from_bytes(body[5:13], "big")
        aad = self._aad(version, frame_type, seq)

        # Cửa sổ replay — tính trạng thái mới NHƯNG CHƯA commit (commit-sau-tag).
        fresh = seq > self._recv_highest
        delta = self._recv_highest - seq if not fresh else 0
        in_window = fresh or delta < 128
        if not in_window:
            raise PipeSessionError(f"frame quá cũ so với cửa sổ (seq {seq})")
        bit = 1 if fresh else 1 << delta
        already_seen = (not fresh) and (self._recv_bitmap & bit) != 0
        if already_seen:
            raise PipeSessionError(f"frame replay (seq {seq})")

        try:
            payload = self._recv.decrypt(self._nonce(seq), body[13:], aad)
        except InvalidTag as e:
            raise PipeSessionError(f"giải mã thất bại (tag/AAD): {e}") from e

        # Tag đã verify — commit cửa sổ.
        if fresh:
            shift = min(seq - self._recv_highest, 127)
            self._recv_bitmap = (self._recv_bitmap << shift) | 1
            self._recv_highest = seq
        else:
            self._recv_bitmap |= bit
        return frame_type, payload


def load_pinned_agent_key(path: Optional[str] = None) -> Optional[bytes]:
    """Đọc khóa agent đã pin từ file hex (mặc định
    %PROGRAMDATA%\\CyberV\\agent_public_key.hex do agent service ghi).
    Thiếu/sai định dạng → None (caller phải fail-closed, KHÔNG downgrade)."""
    target = path or DEFAULT_PIN_PATH
    try:
        with open(target, "r", encoding="ascii") as f:
            hex_str = f.read().strip()
        if len(hex_str) != 64:
            return None
        return bytes.fromhex(hex_str)
    except (OSError, ValueError):
        return None


def generate_client_ephemeral() -> Tuple[X25519PrivateKey, bytes]:
    """Sinh cặp ephemeral của client — trả (priv, pk_raw_32B)."""
    priv = X25519PrivateKey.generate()
    pk = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pk
