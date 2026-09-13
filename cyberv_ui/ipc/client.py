r"""
Named Pipe IPC Client for CyberV UI
Connects to the Rust Core Agent via Windows Named Pipe: \\.\pipe\CyberVIPC
Implements strict timeout, bounding, and fail-closed error handling.
"""

import ctypes
import os
import sys
import time
from typing import Any, Dict, Optional, Union

from .protocol import (
    MAX_IPC_MESSAGE_SIZE,
    IpcMessageEnvelope,
    IpcProtocolError,
    IpcResponseEnvelope,
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


class NamedPipeClient:
    def __init__(self, pipe_name: str = PIPE_NAME, timeout_ms: int = DEFAULT_TIMEOUT_MS):
        self.pipe_name = pipe_name
        self.timeout_ms = timeout_ms
        self._handle = INVALID_HANDLE_VALUE
        self._is_windows = sys.platform == "win32"
        self.is_authenticated = False

    @property
    def is_connected(self) -> bool:
        return self._handle != INVALID_HANDLE_VALUE and self._handle is not None and self.is_authenticated

    def connect(self) -> bool:
        if not self._is_windows:
            return False

        kernel32 = ctypes.windll.kernel32
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
            if handle == INVALID_HANDLE_VALUE:
                self._handle = INVALID_HANDLE_VALUE
                self.is_authenticated = False
                return False

        self._handle = handle

        # Docs/rvnew.md Section 4: Authenticate pipe via cryptographic Handshake
        if not self._verify_handshake():
            self.disconnect()
            return False

        return True

    def _verify_handshake(self) -> bool:
        """Sends Handshake challenge to verify server identity and protocol version."""
        envelope = IpcMessageEnvelope.create_handshake()
        resp = self._raw_send_envelope(envelope)
        if resp.success and resp.data and resp.data.get("status") == "HANDSHAKE_OK":
            self.is_authenticated = True
            return True
        return False

    def disconnect(self):
        self.is_authenticated = False
        if self._handle != INVALID_HANDLE_VALUE and self._handle is not None and self._is_windows:
            kernel32 = ctypes.windll.kernel32
            kernel32.CloseHandle(self._handle)
        self._handle = INVALID_HANDLE_VALUE

    def _raw_send_envelope(self, envelope: IpcMessageEnvelope) -> IpcResponseEnvelope:
        try:
            payload = envelope.to_json_bytes()
        except IpcProtocolError as e:
            return IpcResponseEnvelope(
                message_id=envelope.message_id,
                success=False,
                error=f"Protocol encoding error: {e}",
            )

        if self._handle == INVALID_HANDLE_VALUE or self._handle is None:
            return IpcResponseEnvelope(
                message_id=envelope.message_id,
                success=False,
                error="Pipe handle is invalid",
            )

        kernel32 = ctypes.windll.kernel32
        bytes_written = ctypes.c_ulong(0)
        success = kernel32.WriteFile(
            self._handle,
            payload,
            len(payload),
            ctypes.byref(bytes_written),
            None,
        )

        if not success:
            return IpcResponseEnvelope(
                message_id=envelope.message_id,
                success=False,
                error="Failed to write to pipe",
            )

        buffer = ctypes.create_string_buffer(MAX_IPC_MESSAGE_SIZE)
        bytes_read = ctypes.c_ulong(0)
        success = kernel32.ReadFile(
            self._handle,
            buffer,
            MAX_IPC_MESSAGE_SIZE,
            ctypes.byref(bytes_read),
            None,
        )

        if not success or bytes_read.value == 0:
            return IpcResponseEnvelope(
                message_id=envelope.message_id,
                success=False,
                error="Failed to read from pipe",
            )

        raw_resp = buffer.raw[: bytes_read.value]
        try:
            return IpcResponseEnvelope.from_bytes(raw_resp)
        except IpcProtocolError as e:
            return IpcResponseEnvelope(
                message_id=envelope.message_id,
                success=False,
                error=f"Protocol parsing error: {e}",
            )

    def send_command(
        self, command: Union[str, Dict[str, Any]]
    ) -> IpcResponseEnvelope:
        """Sends a command envelope to the Core Agent and receives a response."""
        envelope = IpcMessageEnvelope.create(command)
        if not self.is_connected:
            if not self.connect():
                return IpcResponseEnvelope(
                    message_id=envelope.message_id,
                    success=False,
                    error="Cannot connect to CyberV Core Agent (Pipe unavailable)",
                )

        return self._raw_send_envelope(envelope)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
