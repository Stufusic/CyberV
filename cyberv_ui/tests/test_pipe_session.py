"""
P1-1b — Pipe Session Tests: bắt tay 2 bước + phiên AEAD phía Python.

Cross-language golden vectors: các giá trị MUST khớp byte-for-byte với
`agent/src/mesh/pipe_session.rs` (test `pipe_golden_vectors_are_stable`) —
đổi implementation bên nào cũng vỡ test bên kia, chặn lệch giao thức.

Adversarial: MITM thay PK, pin sai khóa, replay frame, frame quá hạn mức,
version downgrade — tất cả phải TỪ CHỐI (fail-closed).
"""

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from cyberv_ui.ipc.pipe_session import (
    MESH_WIRE_VERSION,
    PipeFrameError,
    PipeHandshakeError,
    PipeSession,
    PipeSessionError,
    client_finish_pipe_handshake,
    encode_pipe_hello,
    load_pinned_agent_key,
    pipe_ack_sig_payload,
    server_handle_pipe_hello,
)

# ---- Golden vectors sinh bởi Rust `generate_pipe_golden_vectors`
# (client seed 0x42*32, server seed 0x43*32, identity seed 0x42*32, version 1) ----
GOLD_CLIENT_PK = (
    "132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472"
)
GOLD_SERVER_PK = (
    "cdefd8783a91b446640e2e1f95599db35e484a0071bd2182b3b60d0812c10c70"
)
GOLD_ACK_SIG = (
    "e23e84e827e8258f5092cc76645c421382eb34083e994caed90a0b3d1eda0c4d"
    "fade275f8ec3f77bd46b6e861d9261fc7c0e3a2c81482d8fa0ff46daaa296a05"
)
GOLD_FRAME = (
    "0000002900000001010000000000000000f85797135398f3e3db9e5e2529dbd2"
    "56389c1e105c6c008355d80914"
)


def hex_of(b: bytes) -> str:
    return b.hex()


class TestPipeGoldenVectors(unittest.TestCase):
    """Cross-language neo: Python phải tái tạo CHÍNH XÁC output của Rust."""

    def test_01_client_pk_matches_rust(self):
        client_priv = X25519PrivateKey.from_private_bytes(b"\x42" * 32)
        client_pk = client_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.assertEqual(hex_of(client_pk), GOLD_CLIENT_PK)

    def test_02_server_pk_matches_rust(self):
        server_priv = X25519PrivateKey.from_private_bytes(b"\x43" * 32)
        server_pk = server_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.assertEqual(hex_of(server_pk), GOLD_SERVER_PK)

    def test_03_ack_signature_matches_rust(self):
        identity = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
        client_pk = bytes.fromhex(GOLD_CLIENT_PK)
        server_pk = bytes.fromhex(GOLD_SERVER_PK)
        sig = identity.sign(pipe_ack_sig_payload(MESH_WIRE_VERSION, client_pk, server_pk))
        self.assertEqual(hex_of(sig), GOLD_ACK_SIG)

    def test_04_sealed_frame_matches_rust(self):
        # Key derivation + AEAD seal phải byte-for-byte khớp Rust.
        client_priv = X25519PrivateKey.from_private_bytes(b"\x42" * 32)
        client_pk = bytes.fromhex(GOLD_CLIENT_PK)
        server_pk = bytes.fromhex(GOLD_SERVER_PK)
        identity = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)

        hello = encode_pipe_hello(MESH_WIRE_VERSION, client_pk)
        # Server phía Rust: server_handle_pipe_hello — dùng bản Python đối xứng
        # (cùng spec) để có ack + session; assert chữ ký khớp vector Rust.
        ack_raw, _server_session = server_handle_pipe_hello(
            hello,
            identity,
            X25519PrivateKey.from_private_bytes(b"\x43" * 32),
            server_pk,
        )
        version, ack_pk, ack_sig = None, None, None
        # Parse ack để lấy sig (decode nội bộ của test — không phụ thuộc client).
        dlen = len(b"CYBERV/PIPE/HANDSHAKE/v1")
        body = ack_raw[4:]
        version = int.from_bytes(body[dlen + 1 : dlen + 5], "big")
        ack_pk = body[dlen + 5 : dlen + 37]
        ack_sig = body[dlen + 37 :]
        self.assertEqual(hex_of(ack_sig), GOLD_ACK_SIG)
        self.assertEqual(hex_of(ack_pk), GOLD_SERVER_PK)
        self.assertEqual(version, 1)

        client_session = client_finish_pipe_handshake(
            ack_raw, identity.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            client_priv, client_pk,
        )
        frame = client_session.seal(1, b"gold-vectors")
        self.assertEqual(hex_of(frame), GOLD_FRAME)


class TestPipeHandshakeAdversarial(unittest.TestCase):

    def setUp(self):
        self.identity = Ed25519PrivateKey.from_private_bytes(b"\xAA" * 32)
        self.client_priv = X25519PrivateKey.generate()
        self.client_pk = self.client_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.server_priv = X25519PrivateKey.generate()
        self.server_pk = self.server_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.pinned = self.identity.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    def test_05_mitm_substituted_client_pk_rejected(self):
        # Attacker thay client_pk trong Hello — ack ký bám PK giả; client thật
        # verify bằng PK của chính mình → vỡ.
        attacker_pk = X25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        forged_hello = encode_pipe_hello(MESH_WIRE_VERSION, attacker_pk)
        ack, _ = server_handle_pipe_hello(
            forged_hello, self.identity, self.server_priv, self.server_pk
        )
        with self.assertRaises(PipeHandshakeError):
            client_finish_pipe_handshake(
                ack, self.pinned, self.client_priv, self.client_pk
            )

    def test_06_wrong_pinned_key_rejected(self):
        hello = encode_pipe_hello(MESH_WIRE_VERSION, self.client_pk)
        ack, _ = server_handle_pipe_hello(
            hello, self.identity, self.server_priv, self.server_pk
        )
        impostor = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        with self.assertRaises(PipeHandshakeError):
            client_finish_pipe_handshake(
                ack, impostor, self.client_priv, self.client_pk
            )

    def test_07_hello_version_downgrade_rejected(self):
        with self.assertRaises(PipeHandshakeError):
            server_handle_pipe_hello(
                encode_pipe_hello(MESH_WIRE_VERSION - 1, self.client_pk),
                self.identity,
                self.server_priv,
                self.server_pk,
            )


class TestPipeSessionFrames(unittest.TestCase):

    def setUp(self):
        self.identity = Ed25519PrivateKey.from_private_bytes(b"\xBB" * 32)
        self.client_priv = X25519PrivateKey.generate()
        self.client_pk = self.client_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.server_priv = X25519PrivateKey.generate()
        self.server_pk = self.server_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        hello = encode_pipe_hello(MESH_WIRE_VERSION, self.client_pk)
        ack, server_session = server_handle_pipe_hello(
            hello, self.identity, self.server_priv, self.server_pk
        )
        self.client_session = client_finish_pipe_handshake(
            ack, self.pinned_key(), self.client_priv, self.client_pk
        )
        self.server_session = server_session

    def pinned_key(self) -> bytes:
        return self.identity.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def test_08_seal_open_roundtrip_both_directions(self):
        f = self.client_session.seal(1, b"ping")
        t, p = self.server_session.open(f)
        self.assertEqual((t, p), (1, b"ping"))
        r = self.server_session.seal(2, b"pong")
        t, p = self.client_session.open(r)
        self.assertEqual((t, p), (2, b"pong"))

    def test_09_replayed_frame_rejected(self):
        f = self.client_session.seal(1, b"x")
        self.server_session.open(f)
        with self.assertRaises(PipeSessionError):
            self.server_session.open(f)

    def test_10_tampered_frame_rejected(self):
        f = bytearray(self.client_session.seal(1, b"secret"))
        f[-1] ^= 0x01
        with self.assertRaises(PipeSessionError):
            self.server_session.open(bytes(f))

    def test_11_out_of_window_frame_rejected(self):
        old = self.client_session.seal(1, b"old")
        for i in range(200):
            self.server_session.open(self.client_session.seal(1, bytes([i % 256])))
        with self.assertRaises(PipeSessionError):
            self.server_session.open(old)

    def test_12_oversized_frame_rejected(self):
        with self.assertRaises(PipeFrameError):
            self.server_session.open((65536 + 129).to_bytes(4, "big"))


class TestPinnedKeyLoading(unittest.TestCase):

    def test_13_missing_pin_file_returns_none(self):
        self.assertIsNone(load_pinned_agent_key("Z:/khong-ton-tai/x.hex"))


if __name__ == "__main__":
    unittest.main()
