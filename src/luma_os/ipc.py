"""Bounded authenticated local-IPC envelope framing contract."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import struct
from types import MappingProxyType
from typing import Final


IPC_SCHEMA_VERSION: Final[int] = 1
DEFAULT_MAX_FRAME_BYTES: Final[int] = 1024 * 1024


class IpcError(RuntimeError):
    """Base class for an expected local-IPC rejection."""


class IpcMalformed(IpcError):
    """The frame or envelope violated the wire contract."""


class IpcPeerMismatch(IpcError):
    """The authenticated OS peer differs from the asserted caller."""


class IpcDeadlineExceeded(IpcError):
    """The envelope deadline elapsed before dispatch."""


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 256:
        raise IpcMalformed(f"{field} must be a non-empty trimmed string")
    if "\x00" in value:
        raise IpcMalformed(f"{field} cannot contain NUL")
    return value


def _positive_integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > (1 << 63) - 1:
        raise IpcMalformed(f"{field} must be a positive signed 64-bit integer")
    return value


@dataclass(frozen=True, slots=True)
class IpcEnvelope:
    request_id: str
    caller: str
    method: str
    deadline_unix_ms: int
    payload: Mapping[str, object]
    idempotency_key: str | None = None
    lease_id: str | None = None
    lease_generation: int | None = None
    schema_version: int = IPC_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != IPC_SCHEMA_VERSION:
            raise IpcMalformed("unsupported IPC schema version")
        for field in ("request_id", "caller", "method"):
            _identifier(getattr(self, field), field)
        _positive_integer(self.deadline_unix_ms, "deadline_unix_ms")
        if not isinstance(self.payload, dict):
            raise IpcMalformed("payload must be a JSON object")
        if self.idempotency_key is not None:
            _identifier(self.idempotency_key, "idempotency_key")
        if (self.lease_id is None) != (self.lease_generation is None):
            raise IpcMalformed("lease_id and lease_generation must be supplied together")
        if self.lease_id is not None:
            _identifier(self.lease_id, "lease_id")
            _positive_integer(self.lease_generation, "lease_generation")
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))

    def as_dict(self) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "caller": self.caller,
            "method": self.method,
            "deadline_unix_ms": self.deadline_unix_ms,
            "payload": dict(self.payload),
        }
        if self.idempotency_key is not None:
            document["idempotency_key"] = self.idempotency_key
        if self.lease_id is not None:
            document["lease_id"] = self.lease_id
            document["lease_generation"] = self.lease_generation
        return document


def encode_frame(
    envelope: IpcEnvelope,
    *,
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
) -> bytes:
    maximum = _positive_integer(max_frame_bytes, "max_frame_bytes")
    try:
        body = json.dumps(
            envelope.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IpcMalformed("payload is not bounded JSON data") from exc
    if not body or len(body) > maximum:
        raise IpcMalformed("IPC frame exceeds its configured maximum")
    return struct.pack(">I", len(body)) + body


def decode_frame(
    frame: bytes,
    *,
    peer_identity: str,
    now_unix_ms: int,
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
) -> IpcEnvelope:
    _identifier(peer_identity, "peer_identity")
    if not isinstance(now_unix_ms, int) or isinstance(now_unix_ms, bool) or now_unix_ms < 0:
        raise IpcMalformed("now_unix_ms must be a non-negative integer")
    maximum = _positive_integer(max_frame_bytes, "max_frame_bytes")
    if not isinstance(frame, bytes) or len(frame) < 4:
        raise IpcMalformed("IPC frame is truncated")
    (declared_length,) = struct.unpack(">I", frame[:4])
    if declared_length == 0 or declared_length > maximum:
        raise IpcMalformed("IPC frame length is invalid")
    if len(frame) != declared_length + 4:
        raise IpcMalformed("IPC frame length does not match its payload")
    try:
        document = json.loads(frame[4:].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise IpcMalformed("IPC payload is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise IpcMalformed("IPC envelope must be an object")
    required = {
        "schema_version",
        "request_id",
        "caller",
        "method",
        "deadline_unix_ms",
        "payload",
    }
    optional = {"idempotency_key", "lease_id", "lease_generation"}
    if not required.issubset(document) or set(document) - required - optional:
        raise IpcMalformed("IPC envelope has missing or unknown fields")
    try:
        envelope = IpcEnvelope(**document)
    except TypeError as exc:
        raise IpcMalformed("IPC envelope fields are invalid") from exc
    if envelope.caller != peer_identity:
        raise IpcPeerMismatch("authenticated peer does not match asserted caller")
    if now_unix_ms >= envelope.deadline_unix_ms:
        raise IpcDeadlineExceeded("IPC request deadline has elapsed")
    return envelope
