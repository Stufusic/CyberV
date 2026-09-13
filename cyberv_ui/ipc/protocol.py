"""
IPC Protocol Definitions for CyberV UI <-> Rust Core Agent
Conforms to:
- Docs/rv13.md Section 5 (Hardened IPC, <= 64KB, strict schema)
- Docs/ui.md & Docs/ủiv.md (No arbitrary commands, Fail-closed)
"""

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Union

MAX_IPC_MESSAGE_SIZE = 65536  # 64 KB Safe Limit


class IpcProtocolError(Exception):
    pass


class MessageTooLargeError(IpcProtocolError):
    pass


class EmptyPayloadError(IpcProtocolError):
    pass


class DeserializationError(IpcProtocolError):
    pass


CLIENT_VERSION = "1.0.0"


def create_handshake(nonce_hex: Optional[str] = None) -> Dict[str, Any]:
    """Generates the dictionary payload for a Handshake command."""
    if nonce_hex is None:
        nonce_hex = uuid.uuid4().hex
    return {
        "command": "Handshake",
        "client_version": CLIENT_VERSION,
        "nonce_hex": nonce_hex,
    }


def parse_ipc_response(raw_text_or_bytes: Union[str, bytes]) -> "IpcResponseEnvelope":
    """Parses raw text or bytes into an IpcResponseEnvelope, handling errors safely."""
    if isinstance(raw_text_or_bytes, str):
        raw_bytes = raw_text_or_bytes.encode("utf-8")
    else:
        raw_bytes = raw_text_or_bytes
    try:
        return IpcResponseEnvelope.from_bytes(raw_bytes)
    except Exception as e:
        return IpcResponseEnvelope(
            message_id="",
            success=False,
            data=None,
            error=f"Malformed JSON: {e}",
        )


@dataclass
class IpcMessageEnvelope:
    message_id: str
    command: Union[str, Dict[str, Any]]
    sender_pid: int
    timestamp: int

    @classmethod
    def create(cls, command: Union[str, Dict[str, Any]]) -> "IpcMessageEnvelope":
        return cls(
            message_id=str(uuid.uuid4()),
            command=command,
            sender_pid=os.getpid(),
            timestamp=int(time.time()),
        )

    @classmethod
    def create_handshake(cls, nonce_hex: str = None) -> "IpcMessageEnvelope":
        if nonce_hex is None:
            nonce_hex = uuid.uuid4().hex
        return cls.create({
            "Handshake": {
                "client_version": CLIENT_VERSION,
                "nonce_hex": nonce_hex,
            }
        })

    def to_json_bytes(self) -> bytes:
        payload = json.dumps(asdict(self)).encode("utf-8")
        if len(payload) > MAX_IPC_MESSAGE_SIZE:
            raise MessageTooLargeError(
                f"Message payload exceeds {MAX_IPC_MESSAGE_SIZE} bytes: {len(payload)}"
            )
        return payload

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> "IpcMessageEnvelope":
        if not raw_bytes:
            raise EmptyPayloadError("Received empty IPC payload")
        if len(raw_bytes) > MAX_IPC_MESSAGE_SIZE:
            raise MessageTooLargeError(
                f"Payload size {len(raw_bytes)} exceeds maximum limit {MAX_IPC_MESSAGE_SIZE}"
            )
        try:
            data = json.loads(raw_bytes.decode("utf-8"))
            return cls(
                message_id=data["message_id"],
                command=data["command"],
                sender_pid=data.get("sender_pid", 0),
                timestamp=data.get("timestamp", 0),
            )
        except Exception as e:
            raise DeserializationError(f"Failed to parse IPC message: {e}") from e


@dataclass
class IpcResponseEnvelope:
    message_id: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: int = 0

    def to_json_bytes(self) -> bytes:
        payload = json.dumps(asdict(self)).encode("utf-8")
        if len(payload) > MAX_IPC_MESSAGE_SIZE:
            raise MessageTooLargeError(
                f"Response payload exceeds {MAX_IPC_MESSAGE_SIZE} bytes: {len(payload)}"
            )
        return payload

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> "IpcResponseEnvelope":
        if not raw_bytes:
            raise EmptyPayloadError("Received empty IPC response")
        if len(raw_bytes) > MAX_IPC_MESSAGE_SIZE:
            raise MessageTooLargeError(
                f"Response size {len(raw_bytes)} exceeds maximum limit {MAX_IPC_MESSAGE_SIZE}"
            )
        try:
            data = json.loads(raw_bytes.decode("utf-8"))
            return cls(
                message_id=data.get("message_id", ""),
                success=bool(data.get("success", False)),
                data=data.get("data"),
                error=data.get("error"),
                timestamp=data.get("timestamp", int(time.time())),
            )
        except Exception as e:
            raise DeserializationError(f"Failed to parse IPC response: {e}") from e
