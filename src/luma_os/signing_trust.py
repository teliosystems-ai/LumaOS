"""Root-signed, rollback-aware public signing-trust distribution.

This module contains no private-key operation.  A trust bundle is useful only
after an external root verifies its canonical bytes and an independently
protected monotonic anchor commits its sequence and digest.  The in-repository
anchor fake is explicitly development-only; native production storage remains
a platform responsibility.  Module-private tokens and Python object identity
are trusted-composition guards, not an authorization boundary against hostile
code in the same process.  Untrusted plugins, models, and IPC peers must submit
raw signed artifacts to an isolated trusted service instead of receiving these
objects.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
import base64
import binascii
import hashlib
import json
from types import MappingProxyType
from typing import Protocol

from .model_pack import (
    PurposeBoundEd25519Verifier,
    SigningPurpose,
    SigningRole,
    TrustKeyRecord,
)
from .monotonic_anchor import DigestCheckpoint, ExternalDigestAnchor


JSON_SAFE_INTEGER_MAX = (1 << 53) - 1
MAX_TRUST_BUNDLE_BYTES = 1024 * 1024
MAX_TRUST_KEYS = 256
MAX_ROOT_ANCHORS = 32
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 8192
TRUST_ENVIRONMENTS = frozenset({"lab", "production"})

_PURPOSE_ROLES = {
    SigningPurpose.MODEL_PACK_MANIFEST: SigningRole.MODEL_PACK_SIGNER,
    SigningPurpose.EXECUTION_CERTIFICATION: SigningRole.CERTIFICATION_SIGNER,
    SigningPurpose.INTERACTIVE_CERTIFICATION: SigningRole.CERTIFICATION_SIGNER,
    SigningPurpose.MODEL_PROFILE_CATALOG_LAB: SigningRole.LAB_CATALOG_SIGNER,
    SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION: (
        SigningRole.PRODUCTION_CATALOG_SIGNER
    ),
}
_LAB_ONLY_PURPOSES = frozenset({SigningPurpose.MODEL_PROFILE_CATALOG_LAB})
_PRODUCTION_ONLY_PURPOSES = frozenset(
    {SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION}
)
_PREPARED_TOKEN = object()
_ANCHORED_TOKEN = object()


class SigningTrustError(ValueError):
    """A trust artifact or trusted configuration is malformed."""


class TrustBundleVerificationDenied(RuntimeError):
    """A structurally valid bundle failed trust, lifecycle, or rollback policy."""


class TrustBundleAnchorConflict(TrustBundleVerificationDenied):
    """The external anchor changed or rejected the prepared update."""


class PublicEd25519Verifier(Protocol):
    """Public-only Ed25519 primitive; key selection remains in this module."""

    def verify(
        self,
        message: bytes,
        signature: bytes,
        *,
        public_key: bytes,
    ) -> bool: ...


def _ascii_text(value: object, field_name: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        raise SigningTrustError(
            f"{field_name} must be non-empty trimmed printable ASCII"
        )
    return value


def _sha256(value: object, field_name: str) -> str:
    digest = _ascii_text(value, field_name, maximum=64)
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise SigningTrustError(
            f"{field_name} must be a lowercase SHA-256 digest"
        )
    return digest


def _positive_integer(value: object, field_name: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > JSON_SAFE_INTEGER_MAX
    ):
        raise SigningTrustError(
            f"{field_name} must be a positive JSON-safe integer"
        )
    return value


def _aware_utc(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SigningTrustError(f"{field_name} must be timezone-aware")
    normalized = value.astimezone(UTC)
    if normalized.microsecond:
        raise SigningTrustError(f"{field_name} must use second precision")
    return normalized


def _timestamp(value: datetime) -> str:
    return _aware_utc(value, "timestamp").strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: object, field_name: str) -> datetime:
    text = _ascii_text(value, field_name, maximum=20)
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise SigningTrustError(
            f"{field_name} must use second-precision UTC form YYYY-MM-DDTHH:MM:SSZ"
        ) from exc
    return parsed


def _strict_mapping(
    value: object,
    *,
    required: frozenset[str],
    field_name: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise SigningTrustError(f"{field_name} must be an object with string keys")
    keys = set(value)
    if keys != required:
        raise SigningTrustError(
            f"{field_name} fields differ; missing={sorted(required - keys)}, "
            f"unexpected={sorted(keys - required)}"
        )
    return value


def _validate_json_domain(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise SigningTrustError("trust bundle exceeds structural JSON limits")
        if current is None or isinstance(current, bool):
            continue
        if isinstance(current, int) and not isinstance(current, bool):
            if abs(current) > JSON_SAFE_INTEGER_MAX:
                raise SigningTrustError("trust bundle integer is outside the JSON-safe range")
            continue
        if isinstance(current, str):
            if any(ord(character) < 0x20 or ord(character) > 0x7E for character in current):
                raise SigningTrustError("trust bundle strings must use printable ASCII")
            continue
        if isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
            continue
        if isinstance(current, Mapping):
            if any(not isinstance(key, str) for key in current):
                raise SigningTrustError("trust bundle object keys must be strings")
            stack.extend((key, depth + 1) for key in current)
            stack.extend((item, depth + 1) for item in current.values())
            continue
        raise SigningTrustError("trust bundle contains an unsupported JSON value")


def canonical_trust_json_bytes(value: Mapping[str, object]) -> bytes:
    """Return the bounded canonical ASCII representation for trust artifacts."""

    _validate_json_domain(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise SigningTrustError("trust artifact cannot be canonically encoded") from exc
    if len(encoded) > MAX_TRUST_BUNDLE_BYTES:
        raise SigningTrustError("trust artifact exceeds its byte limit")
    return encoded


def _load_canonical_json(raw: bytes) -> Mapping[str, object]:
    if not isinstance(raw, bytes) or not raw:
        raise SigningTrustError("trust bundle must be non-empty bytes")
    if len(raw) > MAX_TRUST_BUNDLE_BYTES:
        raise SigningTrustError("trust bundle exceeds its byte limit")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise SigningTrustError("trust bundle contains a duplicate key")
            result[key] = value
        return result

    def parse_integer(token: str) -> int:
        if len(token.lstrip("-")) > 16:
            raise SigningTrustError("trust bundle integer token is too long")
        value = int(token)
        if abs(value) > JSON_SAFE_INTEGER_MAX:
            raise SigningTrustError("trust bundle integer is outside the JSON-safe range")
        return value

    def reject_number(token: str) -> object:
        raise SigningTrustError(f"trust bundle contains unsupported number {token!r}")

    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=unique_object,
            parse_int=parse_integer,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except SigningTrustError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise SigningTrustError("trust bundle is not strict ASCII JSON") from exc
    if not isinstance(value, Mapping):
        raise SigningTrustError("trust bundle must contain a JSON object")
    if raw != canonical_trust_json_bytes(value):
        raise SigningTrustError("trust bundle is not in canonical form")
    return value


def _decode_base64(value: object, field_name: str, *, size: int) -> bytes:
    encoded = _ascii_text(value, field_name, maximum=((size + 2) // 3) * 4)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SigningTrustError(f"{field_name} is not canonical base64") from exc
    if len(decoded) != size or base64.b64encode(decoded).decode("ascii") != encoded:
        raise SigningTrustError(
            f"{field_name} must canonically encode exactly {size} bytes"
        )
    return decoded


@dataclass(frozen=True, slots=True)
class RootTrustAnchor:
    """Out-of-band root public key; never sourced from a trust bundle."""

    key_id: str
    environment: str
    trust_domain: str
    public_key: bytes
    not_before: datetime
    not_after: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        _ascii_text(self.key_id, "root key_id")
        if self.environment not in TRUST_ENVIRONMENTS:
            raise SigningTrustError("root environment must be lab or production")
        _ascii_text(self.trust_domain, "root trust_domain")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise SigningTrustError("root public_key must contain exactly 32 bytes")
        not_before = _aware_utc(self.not_before, "root not_before")
        not_after = _aware_utc(self.not_after, "root not_after")
        if not_after <= not_before:
            raise SigningTrustError("root not_after must be later than not_before")
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "not_after", not_after)
        if self.revoked_at is not None:
            revoked = _aware_utc(self.revoked_at, "root revoked_at")
            if not not_before <= revoked < not_after:
                raise SigningTrustError("root revoked_at must fall within root validity")
            object.__setattr__(self, "revoked_at", revoked)

    def permits(self, *, at: datetime) -> bool:
        observed = _aware_utc(at, "root verification time")
        return (
            self.not_before <= observed < self.not_after
            and (self.revoked_at is None or observed < self.revoked_at)
        )


@dataclass(frozen=True, slots=True)
class TrustBundlePolicy:
    """Trusted local expectations, kept outside the signed bundle."""

    environment: str
    trust_domain: str
    anchor_namespace: str
    accepted_policy_versions: tuple[str, ...]
    forbidden_public_keys: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        if self.environment not in TRUST_ENVIRONMENTS:
            raise SigningTrustError("policy environment must be lab or production")
        _ascii_text(self.trust_domain, "policy trust_domain")
        _ascii_text(self.anchor_namespace, "policy anchor_namespace")
        if not isinstance(self.accepted_policy_versions, (list, tuple)):
            raise SigningTrustError("accepted_policy_versions must be an array")
        versions = tuple(
            sorted(
                {
                    _ascii_text(item, "accepted policy version")
                    for item in self.accepted_policy_versions
                }
            )
        )
        if not versions:
            raise SigningTrustError("at least one policy version must be accepted")
        object.__setattr__(self, "accepted_policy_versions", versions)
        if not isinstance(self.forbidden_public_keys, (list, tuple)):
            raise SigningTrustError("forbidden_public_keys must be an array")
        forbidden = tuple(self.forbidden_public_keys)
        if any(not isinstance(item, bytes) or len(item) != 32 for item in forbidden):
            raise SigningTrustError(
                "forbidden public keys must each contain exactly 32 bytes"
            )
        if len(forbidden) != len(set(forbidden)):
            raise SigningTrustError("forbidden public keys must be unique")
        object.__setattr__(self, "forbidden_public_keys", tuple(sorted(forbidden)))


@dataclass(frozen=True, slots=True)
class SigningTrustKey:
    key_id: str
    environment: str
    public_key: bytes
    role: SigningRole
    purposes: tuple[SigningPurpose, ...]
    not_before: datetime
    not_after: datetime
    revoked_at: datetime | None = None
    revocation_reason: str | None = None

    def __post_init__(self) -> None:
        _ascii_text(self.key_id, "trust key_id")
        if self.environment not in TRUST_ENVIRONMENTS:
            raise SigningTrustError("trust-key environment must be lab or production")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise SigningTrustError("trust-key public_key must contain exactly 32 bytes")
        if not isinstance(self.role, SigningRole):
            raise SigningTrustError("trust-key role is unsupported")
        if not isinstance(self.purposes, (list, tuple)) or not self.purposes:
            raise SigningTrustError("trust-key purposes must be a non-empty array")
        if any(not isinstance(item, SigningPurpose) for item in self.purposes):
            raise SigningTrustError("trust-key purpose is unsupported")
        purposes = tuple(sorted(set(self.purposes), key=lambda item: item.value))
        if any(_PURPOSE_ROLES[item] is not self.role for item in purposes):
            raise SigningTrustError("trust-key role does not exactly match its purposes")
        if self.environment == "lab" and any(
            item in _PRODUCTION_ONLY_PURPOSES for item in purposes
        ):
            raise SigningTrustError("lab keys cannot carry production catalog purpose")
        if self.environment == "production" and any(
            item in _LAB_ONLY_PURPOSES for item in purposes
        ):
            raise SigningTrustError("production keys cannot carry lab catalog purpose")
        object.__setattr__(self, "purposes", purposes)
        not_before = _aware_utc(self.not_before, "trust-key not_before")
        not_after = _aware_utc(self.not_after, "trust-key not_after")
        if not_after <= not_before:
            raise SigningTrustError("trust-key not_after must be later than not_before")
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "not_after", not_after)
        paired = (self.revoked_at is None) == (self.revocation_reason is None)
        if not paired:
            raise SigningTrustError(
                "trust-key revoked_at and revocation_reason must both be null or present"
            )
        if self.revoked_at is not None:
            revoked = _aware_utc(self.revoked_at, "trust-key revoked_at")
            if not not_before <= revoked < not_after:
                raise SigningTrustError(
                    "trust-key revoked_at must fall within key validity"
                )
            object.__setattr__(self, "revoked_at", revoked)
            _ascii_text(self.revocation_reason, "trust-key revocation_reason")

    @classmethod
    def from_mapping(cls, value: object) -> "SigningTrustKey":
        data = _strict_mapping(
            value,
            required=frozenset(
                {
                    "environment",
                    "key_id",
                    "not_after",
                    "not_before",
                    "public_key",
                    "public_key_encoding",
                    "purposes",
                    "revocation_reason",
                    "revoked_at",
                    "role",
                }
            ),
            field_name="trust key",
        )
        raw_purposes = data["purposes"]
        if not isinstance(raw_purposes, list) or not raw_purposes:
            raise SigningTrustError("trust-key purposes must be a non-empty array")
        try:
            purposes = tuple(SigningPurpose(item) for item in raw_purposes)
            role = SigningRole(data["role"])
        except (TypeError, ValueError) as exc:
            raise SigningTrustError("trust key contains an unsupported role or purpose") from exc
        canonical_purposes = [item.value for item in sorted(set(purposes), key=lambda x: x.value)]
        if raw_purposes != canonical_purposes:
            raise SigningTrustError("trust-key purposes must be unique and canonically ordered")
        if data["public_key_encoding"] != "raw-ed25519-base64":
            raise SigningTrustError("trust-key public_key_encoding is unsupported")
        revoked_at = data["revoked_at"]
        reason = data["revocation_reason"]
        if revoked_at is not None and not isinstance(revoked_at, str):
            raise SigningTrustError("trust-key revoked_at must be a timestamp or null")
        if reason is not None and not isinstance(reason, str):
            raise SigningTrustError("trust-key revocation_reason must be a string or null")
        return cls(
            key_id=data["key_id"],  # type: ignore[arg-type]
            environment=data["environment"],  # type: ignore[arg-type]
            public_key=_decode_base64(data["public_key"], "trust-key public_key", size=32),
            role=role,
            purposes=purposes,
            not_before=_parse_timestamp(data["not_before"], "trust-key not_before"),
            not_after=_parse_timestamp(data["not_after"], "trust-key not_after"),
            revoked_at=(
                _parse_timestamp(revoked_at, "trust-key revoked_at")
                if revoked_at is not None
                else None
            ),
            revocation_reason=reason,
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "environment": self.environment,
            "key_id": self.key_id,
            "not_after": _timestamp(self.not_after),
            "not_before": _timestamp(self.not_before),
            "public_key": base64.b64encode(self.public_key).decode("ascii"),
            "public_key_encoding": "raw-ed25519-base64",
            "purposes": [item.value for item in self.purposes],
            "revocation_reason": self.revocation_reason,
            "revoked_at": (
                _timestamp(self.revoked_at) if self.revoked_at is not None else None
            ),
            "role": self.role.value,
        }


@dataclass(frozen=True, slots=True)
class SignedTrustBundle:
    environment: str
    trust_domain: str
    bundle_sequence: int
    previous_bundle_sha256: str | None
    policy_version: str
    root_key_id: str
    issued_at: datetime
    not_before: datetime
    not_after: datetime
    keys: tuple[SigningTrustKey, ...]
    signature: bytes
    schema_version: int = 1
    artifact_type: str = "luma-os-signing-trust-bundle"
    signature_algorithm: str = "Ed25519"
    signature_encoding: str = "base64"

    def __post_init__(self) -> None:
        if self.schema_version != 1 or isinstance(self.schema_version, bool):
            raise SigningTrustError("trust-bundle schema_version must be 1")
        if self.artifact_type != "luma-os-signing-trust-bundle":
            raise SigningTrustError("trust-bundle artifact_type is unsupported")
        if self.signature_algorithm != "Ed25519":
            raise SigningTrustError("trust-bundle signature_algorithm must be Ed25519")
        if self.signature_encoding != "base64":
            raise SigningTrustError("trust-bundle signature_encoding must be base64")
        if self.environment not in TRUST_ENVIRONMENTS:
            raise SigningTrustError("trust-bundle environment must be lab or production")
        _ascii_text(self.trust_domain, "trust-bundle trust_domain")
        sequence = _positive_integer(self.bundle_sequence, "trust-bundle sequence")
        if sequence == 1:
            if self.previous_bundle_sha256 is not None:
                raise SigningTrustError(
                    "sequence-one trust bundle cannot have a predecessor"
                )
        else:
            _sha256(
                self.previous_bundle_sha256,
                "trust-bundle previous_bundle_sha256",
            )
        _ascii_text(self.policy_version, "trust-bundle policy_version")
        _ascii_text(self.root_key_id, "trust-bundle root_key_id")
        issued_at = _aware_utc(self.issued_at, "trust-bundle issued_at")
        not_before = _aware_utc(self.not_before, "trust-bundle not_before")
        not_after = _aware_utc(self.not_after, "trust-bundle not_after")
        if not_after <= not_before:
            raise SigningTrustError("trust-bundle not_after must follow not_before")
        if not not_before <= issued_at < not_after:
            raise SigningTrustError("trust-bundle issued_at must fall within validity")
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "not_after", not_after)
        if not isinstance(self.keys, (list, tuple)) or not self.keys:
            raise SigningTrustError("trust bundle must contain at least one key")
        keys = tuple(self.keys)
        if len(keys) > MAX_TRUST_KEYS:
            raise SigningTrustError(
                f"trust bundle contains more than {MAX_TRUST_KEYS} keys"
            )
        if any(not isinstance(item, SigningTrustKey) for item in keys):
            raise SigningTrustError("trust bundle contains an invalid key record")
        if any(item.environment != self.environment for item in keys):
            raise SigningTrustError("trust-key environment differs from its bundle")
        if any(
            item.not_before < not_before or item.not_after > not_after
            for item in keys
        ):
            raise SigningTrustError(
                "trust-key validity must be contained by bundle validity"
            )
        key_ids = [item.key_id for item in keys]
        public_keys = [item.public_key for item in keys]
        if len(key_ids) != len(set(key_ids)):
            raise SigningTrustError("trust-bundle key IDs must be unique")
        if len(public_keys) != len(set(public_keys)):
            raise SigningTrustError("trust-bundle public keys must be unique")
        ordered = tuple(sorted(keys, key=lambda item: item.key_id))
        if keys != ordered:
            raise SigningTrustError("trust-bundle keys must be canonically ordered")
        object.__setattr__(self, "keys", ordered)
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise SigningTrustError("trust-bundle Ed25519 signature must be exactly 64 bytes")

    @classmethod
    def parse(cls, raw: bytes) -> "SignedTrustBundle":
        root = _strict_mapping(
            _load_canonical_json(raw),
            required=frozenset(
                {
                    "bundle",
                    "schema_version",
                    "signature",
                    "signature_algorithm",
                    "signature_encoding",
                }
            ),
            field_name="signed trust bundle",
        )
        if root["schema_version"] != 1:
            raise SigningTrustError("signed trust-bundle schema_version must be 1")
        if root["signature_algorithm"] != "Ed25519":
            raise SigningTrustError("signed trust-bundle algorithm must be Ed25519")
        if root["signature_encoding"] != "base64":
            raise SigningTrustError("signed trust-bundle encoding must be base64")
        bundle = _strict_mapping(
            root["bundle"],
            required=frozenset(
                {
                    "artifact_type",
                    "bundle_sequence",
                    "environment",
                    "issued_at",
                    "keys",
                    "not_after",
                    "not_before",
                    "policy_version",
                    "previous_bundle_sha256",
                    "root_key_id",
                    "schema_version",
                    "trust_domain",
                }
            ),
            field_name="trust-bundle payload",
        )
        raw_keys = bundle["keys"]
        if not isinstance(raw_keys, list):
            raise SigningTrustError("trust-bundle keys must be an array")
        if len(raw_keys) > MAX_TRUST_KEYS:
            raise SigningTrustError(
                f"trust bundle contains more than {MAX_TRUST_KEYS} keys"
            )
        previous = bundle["previous_bundle_sha256"]
        if previous is not None and not isinstance(previous, str):
            raise SigningTrustError(
                "trust-bundle previous_bundle_sha256 must be a digest or null"
            )
        parsed = cls(
            environment=bundle["environment"],  # type: ignore[arg-type]
            trust_domain=bundle["trust_domain"],  # type: ignore[arg-type]
            bundle_sequence=bundle["bundle_sequence"],  # type: ignore[arg-type]
            previous_bundle_sha256=previous,
            policy_version=bundle["policy_version"],  # type: ignore[arg-type]
            root_key_id=bundle["root_key_id"],  # type: ignore[arg-type]
            issued_at=_parse_timestamp(bundle["issued_at"], "trust-bundle issued_at"),
            not_before=_parse_timestamp(
                bundle["not_before"], "trust-bundle not_before"
            ),
            not_after=_parse_timestamp(bundle["not_after"], "trust-bundle not_after"),
            keys=tuple(SigningTrustKey.from_mapping(item) for item in raw_keys),
            signature=_decode_base64(
                root["signature"], "trust-bundle signature", size=64
            ),
            schema_version=bundle["schema_version"],  # type: ignore[arg-type]
            artifact_type=bundle["artifact_type"],  # type: ignore[arg-type]
            signature_algorithm=root["signature_algorithm"],  # type: ignore[arg-type]
            signature_encoding=root["signature_encoding"],  # type: ignore[arg-type]
        )
        if raw != parsed.canonical_bytes:
            raise SigningTrustError("trust bundle is not in canonical form")
        return parsed

    def signed_payload(self) -> dict[str, object]:
        return {
            "artifact_type": self.artifact_type,
            "bundle_sequence": self.bundle_sequence,
            "environment": self.environment,
            "issued_at": _timestamp(self.issued_at),
            "keys": [item.canonical_payload() for item in self.keys],
            "not_after": _timestamp(self.not_after),
            "not_before": _timestamp(self.not_before),
            "policy_version": self.policy_version,
            "previous_bundle_sha256": self.previous_bundle_sha256,
            "root_key_id": self.root_key_id,
            "schema_version": self.schema_version,
            "trust_domain": self.trust_domain,
        }

    @property
    def signed_bytes(self) -> bytes:
        return canonical_trust_json_bytes(self.signed_payload())

    def canonical_payload(self) -> dict[str, object]:
        return {
            "bundle": self.signed_payload(),
            "schema_version": self.schema_version,
            "signature": base64.b64encode(self.signature).decode("ascii"),
            "signature_algorithm": self.signature_algorithm,
            "signature_encoding": self.signature_encoding,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_trust_json_bytes(self.canonical_payload())

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustBundleAdmissionPlan:
    """Root-verified candidate that is not yet authority for signature checks."""

    bundle: SignedTrustBundle
    root_anchor: RootTrustAnchor
    expected_checkpoint: DigestCheckpoint | None
    replacement_checkpoint: DigestCheckpoint | None
    prepared_at: datetime
    _anchor: ExternalDigestAnchor = field(repr=False, compare=False)
    _context: "_TrustVerificationContext" = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _PREPARED_TOKEN:
            raise SigningTrustError(
                "trust admission plans can only be created by prepare_trust_bundle"
            )

    @property
    def is_idempotent(self) -> bool:
        return self.replacement_checkpoint is None


@dataclass(frozen=True, slots=True)
class _TrustVerificationContext:
    raw_bundle: bytes
    root_anchors: tuple[RootTrustAnchor, ...]
    policy: TrustBundlePolicy
    crypto: PublicEd25519Verifier
    clock: Callable[[], datetime]


class _BoundPublicKeyVerifier:
    def __init__(
        self,
        crypto: PublicEd25519Verifier,
        keys: Mapping[str, bytes],
    ) -> None:
        self._crypto = crypto
        self._keys = MappingProxyType(dict(keys))

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        public_key = self._keys.get(key_id)
        if public_key is None:
            return False
        try:
            return bool(
                self._crypto.verify(
                    message,
                    signature,
                    public_key=public_key,
                )
            )
        except Exception:
            return False


class _AnchoredPurposeBoundEd25519Verifier(PurposeBoundEd25519Verifier):
    """Recheck the complete anchored chain for every signature verification."""

    def __init__(
        self,
        raw: _BoundPublicKeyVerifier,
        records: tuple[TrustKeyRecord, ...],
        *,
        trust_bundle: "AnchoredTrustBundle",
        clock: Callable[[], datetime],
    ) -> None:
        super().__init__(raw, records, clock=clock)
        self._anchored_trust_bundle = trust_bundle
        self._anchored_clock = clock

    def verify(
        self,
        message: bytes,
        signature: bytes,
        *,
        key_id: str,
        purpose: SigningPurpose,
    ) -> bool:
        return self.verify_at(
            message,
            signature,
            key_id=key_id,
            purpose=purpose,
            at=self._anchored_clock(),
        )

    def verify_at(
        self,
        message: bytes,
        signature: bytes,
        *,
        key_id: str,
        purpose: SigningPurpose,
        at: datetime,
    ) -> bool:
        try:
            self._anchored_trust_bundle.ensure_current()
        except (SigningTrustError, TrustBundleVerificationDenied):
            return False
        return super().verify_at(
            message,
            signature,
            key_id=key_id,
            purpose=purpose,
            at=at,
        )


class AnchoredTrustBundle:
    """A root-verified bundle whose exact sequence/digest was CAS-committed."""

    __slots__ = (
        "_bundle",
        "_checkpoint",
        "_root_anchor",
        "_anchor",
        "_keys_by_id",
        "_context",
    )

    def __init__(
        self,
        bundle: SignedTrustBundle,
        checkpoint: DigestCheckpoint,
        root_anchor: RootTrustAnchor,
        anchor: ExternalDigestAnchor,
        *,
        _token: object,
        _context: _TrustVerificationContext | None = None,
    ) -> None:
        if _token is not _ANCHORED_TOKEN:
            raise SigningTrustError(
                "anchored trust bundles can only be created by commit_trust_bundle"
            )
        if not isinstance(_context, _TrustVerificationContext):
            raise SigningTrustError(
                "anchored trust bundle lost its live verification context"
            )
        self._bundle = bundle
        self._checkpoint = checkpoint
        self._root_anchor = root_anchor
        self._anchor = anchor
        self._keys_by_id = MappingProxyType(
            {item.key_id: item for item in bundle.keys}
        )
        self._context = _context

    @property
    def environment(self) -> str:
        return self._bundle.environment

    @property
    def trust_domain(self) -> str:
        return self._bundle.trust_domain

    @property
    def bundle_sequence(self) -> int:
        return self._bundle.bundle_sequence

    @property
    def bundle_sha256(self) -> str:
        return self._bundle.digest

    @property
    def policy_version(self) -> str:
        return self._bundle.policy_version

    @property
    def keys(self) -> tuple[SigningTrustKey, ...]:
        return self._bundle.keys

    @property
    def checkpoint(self) -> DigestCheckpoint:
        return self._checkpoint

    def key_record(self, key_id: str) -> SigningTrustKey | None:
        return self._keys_by_id.get(_ascii_text(key_id, "key_id"))

    def ensure_current(self) -> None:
        """Revalidate against the trusted live clock retained at admission."""

        observed = _trust_clock_value(self._context.clock)
        try:
            revalidated = prepare_trust_bundle(
                self._context.raw_bundle,
                root_anchors=self._context.root_anchors,
                policy=self._context.policy,
                crypto=self._context.crypto,
                anchor=self._anchor,
                clock=lambda: observed,
            )
        except Exception as exc:
            raise TrustBundleVerificationDenied(
                "anchored trust bundle no longer passes live root, policy, "
                "lifecycle, signature, or checkpoint verification"
            ) from exc
        if (
            revalidated.bundle != self._bundle
            or revalidated.root_anchor != self._root_anchor
            or revalidated.expected_checkpoint != self._checkpoint
            or revalidated.replacement_checkpoint is not None
        ):
            raise TrustBundleVerificationDenied(
                "anchored trust bundle is no longer the exact current checkpoint"
            )

    def create_verifier(
        self,
        crypto: PublicEd25519Verifier,
    ) -> PurposeBoundEd25519Verifier:
        """Create the supported verifier from this CAS-committed key set."""

        if not callable(getattr(crypto, "verify", None)):
            raise SigningTrustError("public Ed25519 verifier lacks verify()")
        if crypto is not self._context.crypto:
            raise SigningTrustError(
                "public Ed25519 verifier differs from the provider bound at trust admission"
            )
        self.ensure_current()
        raw = _BoundPublicKeyVerifier(
            crypto,
            {item.key_id: item.public_key for item in self._bundle.keys},
        )
        records = tuple(
            TrustKeyRecord(
                key_id=item.key_id,
                role=item.role,
                purposes=item.purposes,
                not_before=item.not_before,
                not_after=item.not_after,
                revoked_at=item.revoked_at,
            )
            for item in self._bundle.keys
        )
        return _AnchoredPurposeBoundEd25519Verifier(
            raw,
            records,
            trust_bundle=self,
            clock=self._context.clock,
        )


def _validate_root_set(root_anchors: tuple[RootTrustAnchor, ...]) -> None:
    if (
        not isinstance(root_anchors, (list, tuple))
        or not root_anchors
        or len(root_anchors) > MAX_ROOT_ANCHORS
        or any(not isinstance(item, RootTrustAnchor) for item in root_anchors)
    ):
        raise SigningTrustError(
            f"root_anchors must contain one to {MAX_ROOT_ANCHORS} root anchors"
        )
    key_ids = [item.key_id for item in root_anchors]
    public_keys = [item.public_key for item in root_anchors]
    if len(key_ids) != len(set(key_ids)):
        raise SigningTrustError("root key IDs must be globally unique")
    if len(public_keys) != len(set(public_keys)):
        raise SigningTrustError(
            "lab and production roots must not reuse public keys"
        )


def _read_checkpoint(
    anchor: ExternalDigestAnchor,
    namespace: str,
) -> DigestCheckpoint | None:
    if not callable(getattr(anchor, "read", None)) or not callable(
        getattr(anchor, "compare_and_swap", None)
    ):
        raise SigningTrustError("anchor lacks read/compare_and_swap methods")
    try:
        checkpoint = anchor.read(namespace)
    except Exception as exc:
        raise TrustBundleVerificationDenied("external trust anchor is unavailable") from exc
    if checkpoint is not None and not isinstance(checkpoint, DigestCheckpoint):
        raise TrustBundleVerificationDenied(
            "external trust anchor returned an invalid checkpoint"
        )
    if checkpoint is not None and checkpoint.namespace != namespace:
        raise TrustBundleVerificationDenied(
            "external trust anchor returned the wrong namespace"
        )
    return checkpoint


def _trust_clock_value(clock: Callable[[], datetime]) -> datetime:
    try:
        value = clock()
    except Exception as exc:
        raise TrustBundleVerificationDenied(
            "trust authority clock is unavailable"
        ) from exc
    return _aware_utc(value, "trust verification time")


def prepare_trust_bundle(
    raw_bundle: bytes,
    *,
    root_anchors: tuple[RootTrustAnchor, ...],
    policy: TrustBundlePolicy,
    crypto: PublicEd25519Verifier,
    anchor: ExternalDigestAnchor,
    clock: Callable[[], datetime] | None = None,
) -> TrustBundleAdmissionPlan:
    """Verify a candidate and freeze the exact external-anchor CAS precondition.

    ``clock`` is trusted composition input and must be a protected live time
    source, never artifact data or an untrusted request parameter.
    """

    if not isinstance(policy, TrustBundlePolicy):
        raise SigningTrustError("policy must be a TrustBundlePolicy")
    _validate_root_set(root_anchors)
    if not callable(getattr(crypto, "verify", None)):
        raise SigningTrustError("public Ed25519 verifier lacks verify()")
    if clock is not None and not callable(clock):
        raise SigningTrustError("clock must be callable")
    authority_clock = clock or (lambda: datetime.now(UTC))
    observed_at = _trust_clock_value(authority_clock)
    bundle = SignedTrustBundle.parse(raw_bundle)
    if bundle.environment != policy.environment:
        raise TrustBundleVerificationDenied(
            "trust-bundle environment does not match trusted policy"
        )
    if bundle.trust_domain != policy.trust_domain:
        raise TrustBundleVerificationDenied(
            "trust-bundle domain does not match trusted policy"
        )
    if bundle.policy_version not in policy.accepted_policy_versions:
        raise TrustBundleVerificationDenied("trust-bundle policy version is not accepted")
    if not bundle.not_before <= observed_at < bundle.not_after:
        raise TrustBundleVerificationDenied("trust bundle is not currently valid")
    if bundle.issued_at > observed_at:
        raise TrustBundleVerificationDenied("trust-bundle issue time is in the future")

    matching = tuple(
        item
        for item in root_anchors
        if item.key_id == bundle.root_key_id
        and item.environment == bundle.environment
        and item.trust_domain == bundle.trust_domain
    )
    if len(matching) != 1:
        raise TrustBundleVerificationDenied(
            "trust bundle does not select exactly one external root anchor"
        )
    root_anchor = matching[0]
    root_effective_not_after = min(
        root_anchor.not_after,
        root_anchor.revoked_at or root_anchor.not_after,
    )
    if (
        bundle.not_before < root_anchor.not_before
        or bundle.not_after > root_effective_not_after
    ):
        raise TrustBundleVerificationDenied(
            "trust-bundle validity must be contained by root effective validity"
        )
    if not root_anchor.permits(at=bundle.issued_at) or not root_anchor.permits(
        at=observed_at
    ):
        raise TrustBundleVerificationDenied(
            "trust root is not permitted at issue and verification time"
        )
    forbidden = set(policy.forbidden_public_keys)
    all_root_keys = {item.public_key for item in root_anchors}
    if root_anchor.public_key in forbidden:
        raise TrustBundleVerificationDenied(
            "trust root violates environment key separation"
        )
    if any(item.public_key in forbidden for item in bundle.keys):
        raise TrustBundleVerificationDenied(
            "trust key is reused across separated environments"
        )
    if any(item.public_key in all_root_keys for item in bundle.keys):
        raise TrustBundleVerificationDenied(
            "a trust-bundle leaf key cannot reuse a root public key"
        )
    try:
        signature_valid = bool(
            crypto.verify(
                bundle.signed_bytes,
                bundle.signature,
                public_key=root_anchor.public_key,
            )
        )
    except Exception as exc:
        raise TrustBundleVerificationDenied(
            "public Ed25519 provider is unavailable"
        ) from exc
    if not signature_valid:
        raise TrustBundleVerificationDenied("trust-bundle root signature is invalid")

    current = _read_checkpoint(anchor, policy.anchor_namespace)
    replacement: DigestCheckpoint | None
    if current is None:
        if bundle.bundle_sequence != 1 or bundle.previous_bundle_sha256 is not None:
            raise TrustBundleVerificationDenied(
                "trust anchor genesis requires sequence one without a predecessor"
            )
        replacement = DigestCheckpoint(
            namespace=policy.anchor_namespace,
            generation=1,
            sequence=1,
            artifact_sha256=bundle.digest,
        )
    elif bundle.bundle_sequence < current.sequence:
        raise TrustBundleVerificationDenied(
            "trust-bundle sequence is below the external rollback checkpoint"
        )
    elif bundle.bundle_sequence == current.sequence:
        if bundle.digest != current.artifact_sha256:
            raise TrustBundleVerificationDenied(
                "trust-bundle digest forks the externally anchored sequence"
            )
        replacement = None
    else:
        if bundle.bundle_sequence != current.sequence + 1:
            raise TrustBundleVerificationDenied(
                "trust-bundle sequence must advance exactly once"
            )
        if bundle.previous_bundle_sha256 != current.artifact_sha256:
            raise TrustBundleVerificationDenied(
                "trust-bundle predecessor differs from the external checkpoint"
            )
        replacement = DigestCheckpoint(
            namespace=policy.anchor_namespace,
            generation=current.generation + 1,
            sequence=bundle.bundle_sequence,
            artifact_sha256=bundle.digest,
        )
    context = _TrustVerificationContext(
        raw_bundle=raw_bundle,
        root_anchors=tuple(root_anchors),
        policy=policy,
        crypto=crypto,
        clock=authority_clock,
    )
    return TrustBundleAdmissionPlan(
        bundle=bundle,
        root_anchor=root_anchor,
        expected_checkpoint=current,
        replacement_checkpoint=replacement,
        prepared_at=observed_at,
        _anchor=anchor,
        _context=context,
        _token=_PREPARED_TOKEN,
    )


def commit_trust_bundle(
    plan: TrustBundleAdmissionPlan,
    *,
    anchor: ExternalDigestAnchor,
) -> AnchoredTrustBundle:
    """CAS-commit a prepared bundle and return the supported verifier type."""

    if not isinstance(plan, TrustBundleAdmissionPlan) or plan._token is not _PREPARED_TOKEN:
        raise SigningTrustError("plan was not produced by prepare_trust_bundle")
    if anchor is not plan._anchor:
        raise TrustBundleVerificationDenied(
            "trust bundle must commit to the anchor used during preparation"
        )
    if not isinstance(plan._context, _TrustVerificationContext):
        raise SigningTrustError("trust plan lost its live verification context")
    namespace = plan._context.policy.anchor_namespace
    before_revalidation = _read_checkpoint(anchor, namespace)
    if before_revalidation != plan.expected_checkpoint:
        raise TrustBundleAnchorConflict(
            "external trust checkpoint changed after preparation"
        )
    observed_at = _trust_clock_value(plan._context.clock)
    try:
        revalidated = prepare_trust_bundle(
            plan._context.raw_bundle,
            root_anchors=plan._context.root_anchors,
            policy=plan._context.policy,
            crypto=plan._context.crypto,
            anchor=anchor,
            clock=lambda: observed_at,
        )
    except Exception as exc:
        try:
            after_failure = _read_checkpoint(anchor, namespace)
        except Exception:
            after_failure = plan.expected_checkpoint
        if after_failure != plan.expected_checkpoint:
            raise TrustBundleAnchorConflict(
                "external trust checkpoint changed during live verification"
            ) from exc
        raise TrustBundleVerificationDenied(
            "trust bundle no longer passes live verification at commit"
        ) from exc
    after_revalidation = _read_checkpoint(anchor, namespace)
    if after_revalidation != plan.expected_checkpoint:
        raise TrustBundleAnchorConflict(
            "external trust checkpoint changed during live verification"
        )
    if (
        revalidated.bundle != plan.bundle
        or revalidated.root_anchor != plan.root_anchor
        or revalidated.expected_checkpoint != plan.expected_checkpoint
        or revalidated.replacement_checkpoint != plan.replacement_checkpoint
    ):
        raise TrustBundleVerificationDenied(
            "live trust verification differs from the prepared candidate"
        )

    if plan.replacement_checkpoint is None:
        current = _read_checkpoint(anchor, plan.expected_checkpoint.namespace)  # type: ignore[union-attr]
        if current != plan.expected_checkpoint:
            raise TrustBundleAnchorConflict(
                "external trust checkpoint changed after preparation"
            )
        committed = current
    else:
        try:
            changed = anchor.compare_and_swap(
                expected=plan.expected_checkpoint,
                replacement=plan.replacement_checkpoint,
            )
        except Exception as exc:
            raise TrustBundleAnchorConflict(
                "external trust checkpoint rejected the update"
            ) from exc
        if not changed:
            raise TrustBundleAnchorConflict(
                "external trust checkpoint changed after preparation"
            )
        committed = _read_checkpoint(
            anchor, plan.replacement_checkpoint.namespace
        )
        if committed != plan.replacement_checkpoint:
            raise TrustBundleAnchorConflict(
                "external trust checkpoint did not retain the committed value"
            )
    if committed is None or committed.artifact_sha256 != plan.bundle.digest:
        raise TrustBundleAnchorConflict(
            "external trust checkpoint does not bind the verified bundle"
        )
    anchored = AnchoredTrustBundle(
        plan.bundle,
        committed,
        plan.root_anchor,
        anchor,
        _token=_ANCHORED_TOKEN,
        _context=plan._context,
    )
    anchored.ensure_current()
    return anchored
