r"""
Named Pipe IPC Client for CyberV UI (P1-1b — secure session)
Connects to the Rust Core Agent via Windows Named Pipe: \\.\pipe\CyberVIPC

P1-1: mọi envelope được phục vụ qua PHIÊN AEAD (bắt tay 2 bước X25519, agent
ký identity — client PIN khóa agent). Không pin khóa / thiếu package
cryptography / bắt tay thất bại → fail-closed: KHÔNG downgrade về plaintext,
client báo lỗi cho tầng trên (UI hiển thị UNKNOWN).
"""

import ctypes
import os
import sys
from typing import Any, Dict, Optional, Union

from .protocol import (
    MAX_IPC_MESSAGE_SIZE,
    IpcMessageEnvelope,
    IpcProtocolError,
    IpcResponseEnvelope,
)
from .pipe_session import (
    MESH_WIRE_VERSION,
    PipeFrameError,
    PipeHandshakeError,
    PipeSession,
    PipeSessionError,
    client_finish_pipe_handshake,
    encode_pipe_hello,
    generate_client_ephemeral,
)

PIPE_NAME = r"\\.\pipe\CyberVIPC"
DEFAULT_TIMEOUT_MS = 3000

# Windows API constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = -1
ERROR_PIPE_BUSY = 231
ERROR_FILE_NOT_FOUND = 2

FRAME_TYPE_ENVELOPE = 1
PIPE_HANDSHAKE_MAX = 512
MAX_FRAME_BOUND = MAX_IPC_MESSAGE_SIZE + 128


class NamedPipeClient:
    def __init__(
        self,
        pipe_name: str = PIPE_NAME,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        agent_public_key: Optional[bytes] = None,
    ):
        self.pipe_name = pipe_name
        self.timeout_ms = timeout_ms
        # Khóa agent ĐÃ PIN (32 byte raw) — bắt buộc cho phiên AEAD.
        self.agent_public_key = agent_public_key
        self._handle = INVALID_HANDLE_VALUE
        self._is_windows = sys.platform == "win32"
        self.is_authenticated = False
        self._session: Optional[PipeSession] = None
        self.last_error: Optional[str] = None

    @property
    def is_connected(self) -> bool:
        return (
            self._handle != INVALID_HANDLE_VALUE
            and self._handle is not None
            and self.is_authenticated
        )

    def connect(self) -> bool:
        self.last_error = None
        if not self._is_windows:
            self.last_error = "Named pipe chỉ khả dụng trên Windows"
            return False
        if self.agent_public_key is None or len(self.agent_public_key) != 32:
            # Fail-closed: không pin khóa agent = không có phiên nào cả.
            self.last_error = "Agent public key chưa được pin — từ chối kết nối (fail-closed)"
            return False

        kernel32 = ctypes.windll.kernel32
        handle = self._open_pipe(kernel32)
        if handle == INVALID_HANDLE_VALUE:
            self._handle = INVALID_HANDLE_VALUE
            self.is_authenticated = False
            return False

        self._handle = handle

        # P1-1: bắt tay 2 bước X25519 + pin khóa agent (thay Handshake nonce cũ).
        if not self._establish_session():
            self.disconnect()
            return False

        return True

    def _open_pipe(self, kernel32) -> int:
        handle = kernel32.CreateFileW(
            self.pipe_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            last_err = kernel32.GetLastError()
            if last_err == ERROR_PIPE_BUSY:
                # Wait for pipe
                if kernel32.WaitNamedPipeW(self.pipe_name, self.timeout_ms):
                    handle = kernel32.CreateFileW(
                        self.pipe_name,
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        None,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        None,
                    )
        return handle

    def _establish_session(self) -> bool:
        """Bắt tay 2 bước: PipeHello → verify PipeHelloAck bằng khóa đã pin →
        phiên AEAD. Mọi thất bại = fail-closed (không downgrade)."""
        try:
            client_priv, client_pk = generate_client_ephemeral()
            self._write_all(encode_pipe_hello(MESH_WIRE_VERSION, client_pk))
            ack_raw = self._read_frame(PIPE_HANDSHAKE_MAX)
            self._session = client_finish_pipe_handshake(
                ack_raw, self.agent_public_key, client_priv, client_pk
            )
            self.is_authenticated = True
            return True
        except (PipeSessionError, OSError) as e:
            self.last_error = f"Bắt tay pipe thất bại: {e}"
            self.is_authenticated = False
            self._session = None
            return False

    def disconnect(self):
        self.is_authenticated = False
        self._session = None
        if self._handle != INVALID_HANDLE_VALUE and self._handle is not None and self._is_windows:
            kernel32 = ctypes.windll.kernel32
            kernel32.CloseHandle(self._handle)
        self._handle = INVALID_HANDLE_VALUE

    # ---- Wire I/O helpers (ctypes) ----

    def _write_all(self, data: bytes) -> bool:
        """Ghi HẾT data qua pipe — WriteFile có thể ghi một phần, lặp cho hết."""
        kernel32 = ctypes.windll.kernel32
        view = memoryview(data)
        while view:
            written = ctypes.c_ulong(0)
            ok = kernel32.WriteFile(
                self._handle, view, len(view), ctypes.byref(written), None
            )
            if not ok or written.value == 0:
                return False
            view = view[written.value:]
        return True

    def _read_exact(self, n: int) -> Optional[bytes]:
        """Đọc ĐỦ n byte — ReadFile trên pipe byte-mode có thể trả ít hơn."""
        kernel32 = ctypes.windll.kernel32
        out = bytearray()
        while len(out) < n:
            want = min(n - len(out), MAX_FRAME_BOUND)
            buffer = ctypes.create_string_buffer(want)
            bytes_read = ctypes.c_ulong(0)
            ok = kernel32.ReadFile(
                self._handle, buffer, want, ctypes.byref(bytes_read), None
            )
            if not ok or bytes_read.value == 0:
                return None  # EOF / lỗi pipe
            out.extend(buffer.raw[: bytes_read.value])
        return bytes(out)

    def _read_frame(self, max_body: int) -> bytes:
        """Đọc 1 frame wire: len(4 BE) || body — chặn bound trước cấp phát."""
        prefix = self._read_exact(4)
        if prefix is None:
            raise PipeFrameError("pipe đóng khi đọc length prefix")
        body_len = int.from_bytes(prefix, "big")
        if body_len > max_body:
            raise PipeFrameError(f"frame vượt giới hạn: {body_len}")
        body = self._read_exact(body_len)
        if body is None:
            raise PipeFrameError("pipe đóng giữa frame")
        return prefix + body

    # ---- Phiên AEAD ----

    def _send_envelope_secure(self, envelope: IpcMessageEnvelope) -> IpcResponseEnvelope:
        try:
            payload = envelope.to_json_bytes()
        except IpcProtocolError as e:
            return IpcResponseEnvelope(
                message_id=envelope.message_id,
                success=False,
                error=f"Protocol encoding error: {e}",
            )
        if self._session is None:
            return IpcResponseEnvelope(
                message_id=envelope.message_id,
                success=False,
                error="Phiên AEAD chưa thiết lập",
            )
        try:
            frame = self._session.seal(FRAME_TYPE_ENVELOPE, payload)
        except PipeSessionError as e:
            self.disconnect()
            return IpcResponseEnvelope(
                message_id=envelope.message_id,
                success=False,
                error=f"Seal thất bại: {e}",
            )
        if not self._write_all(frame):
            self.disconnect()
            return IpcResponseEnvelope(
                message_id=envelope.message_id,
                success=False,
                error="Failed to write to pipe",
            )
        try:
            resp_frame = self._read_frame(MAX_FRAME_BOUND)
            _, resp_payload = self._session.open(resp_frame)
        except PipeSessionError as e:
            # Replay/tamper/bound — server cũng đã đóng; không retry mù.
            self.disconnect()
            return IpcResponseEnvelope(
                message_id=envelope.message_id,
                success=False,
                error=f"Frame phản hồi không hợp lệ: {e}",
            )
        try:
            resp = IpcResponseEnvelope.from_bytes(resp_payload)
        except IpcProtocolError as e:
            return IpcResponseEnvelope(
                message_id=envelope.message_id,
                success=False,
                error=f"Protocol parsing error: {e}",
            )
        # P1-1: PID client do KERNEL xác nhận phải khớp chính mình (khi có).
        if isinstance(resp.data, dict) and "server_seen_client_pid" in resp.data:
            if resp.data["server_seen_client_pid"] != os.getpid():
                return IpcResponseEnvelope(
                    message_id=resp.message_id,
                    success=False,
                    error="Kernel-reported client PID mismatch (pipe squatting?)",
                    data=resp.data,
                )
        return resp

    def send_command(
        self, command: Union[str, Dict[str, Any]]
    ) -> IpcResponseEnvelope:
        """Sends a command envelope to the Core Agent and receives a response."""
        envelope = IpcMessageEnvelope.create(command)
        if not self.is_connected:
            if not self.connect():
                detail = self.last_error or "Pipe unavailable"
                return IpcResponseEnvelope(
                    message_id=envelope.message_id,
                    success=False,
                    error=f"Cannot connect to CyberV Core Agent ({detail})",
                )
        return self._send_envelope_secure(envelope)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
