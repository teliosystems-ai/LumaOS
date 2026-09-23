"""Detached signing contract for install-time model-profile catalogs.

Private keys are deliberately absent.  An offline signer or HSM signs the
canonical :class:`CatalogSignatureStatement`; this module verifies the public
artifact, current Admin assignments, trust-key purpose/lifecycle policy, and
the exact certified model-pack tuples before a catalog can be selected.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import base64
import binascii
import hashlib
import json
from typing import Protocol

from .model_pack import (
    ModelPackState,
    ModelPackVerification,
    PurposeBoundEd25519Verifier,
    SigningPurpose,
)
from .model_selection import ModelProfile, ModelProfileCatalog, ModelSelectionError


JSON_SAFE_INTEGER_MAX = (1 << 53) - 1
MAX_CATALOG_BYTES = 4 * 1024 * 1024
MAX_ENVELOPE_BYTES = 1024 * 1024
MAX_APPROVAL_SET_BYTES = 1024 * 1024
MAX_STATEMENT_BYTES = 64 * 1024
MAX_RAW_SIGNATURE_READ_BYTES = 65
CATALOG_ENVIRONMENTS = frozenset({"lab", "production"})
CATALOG_PURPOSES = {
    "lab": SigningPurpose.MODEL_PROFILE_CATALOG_LAB,
    "production": SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
}
CATALOG_SIGNING_ACTIVITIES = {
    "lab": "model-catalog.sign.lab",
    "production": "model-catalog.sign.production",
}
CATALOG_APPROVAL_ACTIVITIES = {
    "lab": frozenset({"model-catalog.approve.lab-release"}),
    "production": frozenset(
        {
            "model-catalog.approve.license",
            "model-catalog.approve.release",
            "model-catalog.approve.security",
        }
    ),
}


class ModelCatalogSigningError(ValueError):
    """A signed catalog artifact is malformed or violates signing policy."""


class ModelCatalogVerificationDenied(RuntimeError):
    """A structurally valid artifact failed authorization or trust checks."""


def _ascii_text(value: object, field: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        raise ModelCatalogSigningError(
            f"{field} must be non-empty trimmed printable ASCII"
        )
    return value


def _sha256(value: object, field: str) -> str:
    digest = _ascii_text(value, field, maximum=64)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ModelCatalogSigningError(f"{field} must be a lowercase SHA-256 digest")
    return digest


def _positive_integer(value: object, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > JSON_SAFE_INTEGER_MAX
    ):
        raise ModelCatalogSigningError(f"{field} must be a positive JSON-safe integer")
    return value


def _non_negative_integer(value: object, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > JSON_SAFE_INTEGER_MAX
    ):
        raise ModelCatalogSigningError(
            f"{field} must be a non-negative JSON-safe integer"
        )
    return value


def _utc_timestamp(value: object, field: str) -> datetime:
    text = _ascii_text(value, field, maximum=20)
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ModelCatalogSigningError(
            f"{field} must use second-precision UTC form YYYY-MM-DDTHH:MM:SSZ"
        ) from exc
    return parsed


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ModelCatalogSigningError("timestamp must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _strict_mapping(
    value: object,
    *,
    required: frozenset[str],
    field: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ModelCatalogSigningError(f"{field} must be an object with string keys")
    keys = set(value)
    if keys != required:
        raise ModelCatalogSigningError(
            f"{field} fields differ; missing={sorted(required - keys)}, "
            f"unexpected={sorted(keys - required)}"
        )
    return value


def canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    """Return the bounded ASCII canonical form used by this signing contract."""

    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ModelCatalogSigningError("artifact cannot be canonically encoded") from exc


def _load_canonical_json(
    raw: bytes,
    field: str,
    *,
    maximum_bytes: int,
) -> Mapping[str, object]:
    if not isinstance(raw, bytes) or not raw:
        raise ModelCatalogSigningError(f"{field} must be non-empty bytes")
    if len(raw) > maximum_bytes:
        raise ModelCatalogSigningError(
            f"{field} exceeds the {maximum_bytes}-byte input limit"
        )

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ModelCatalogSigningError(f"{field} contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=unique_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ModelCatalogSigningError(f"{field} contains {token}")
            ),
        )
    except ModelCatalogSigningError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ModelCatalogSigningError(f"{field} is not strict ASCII JSON") from exc
    if not isinstance(value, Mapping):
        raise ModelCatalogSigningError(f"{field} must contain a JSON object")
    if raw != canonical_json_bytes(value):
        raise ModelCatalogSigningError(f"{field} is not in canonical form")
    return value


@dataclass(frozen=True, slots=True)
class CatalogReleaseRequest:
    """Canonical scope approved before any human catalog decision is recorded."""

    environment: str
    release_id: str
    catalog_id: str
    catalog_sha256: str
    catalog_sequence: int
    policy_version: str
    signer_key_id: str
    signing_principal_id: str
    signing_activity: str
    signing_assignment_id: str
    signing_assignment_receipt_sha256: str
    not_before: datetime
    not_after: datetime
    schema_version: int = 1
    artifact_type: str = "model-profile-catalog-release-request"
    signature_algorithm: str = "Ed25519"

    def __post_init__(self) -> None:
        if self.schema_version != 1 or isinstance(self.schema_version, bool):
            raise ModelCatalogSigningError("release-request schema_version must be 1")
        if self.artifact_type != "model-profile-catalog-release-request":
            raise ModelCatalogSigningError("unsupported release-request artifact type")
        if self.signature_algorithm != "Ed25519":
            raise ModelCatalogSigningError("catalog signatures must use Ed25519")
        if not isinstance(self.environment, str) or self.environment not in CATALOG_ENVIRONMENTS:
            raise ModelCatalogSigningError("catalog environment must be lab or production")
        _ascii_text(self.release_id, "request release_id")
        _ascii_text(self.catalog_id, "request catalog_id")
        _sha256(self.catalog_sha256, "request catalog_sha256")
        _positive_integer(self.catalog_sequence, "request catalog_sequence")
        _ascii_text(self.policy_version, "request policy_version")
        _ascii_text(self.signer_key_id, "request signer_key_id")
        _ascii_text(self.signing_principal_id, "request signing_principal_id")
        _ascii_text(self.signing_assignment_id, "request signing_assignment_id")
        _sha256(
            self.signing_assignment_receipt_sha256,
            "request signing_assignment_receipt_sha256",
        )
        if self.signing_activity != CATALOG_SIGNING_ACTIVITIES[self.environment]:
            raise ModelCatalogSigningError(
                "request signing activity does not match its environment"
            )
        not_before = _utc_timestamp(_timestamp(self.not_before), "request not_before")
        not_after = _utc_timestamp(_timestamp(self.not_after), "request not_after")
        if not_after <= not_before:
            raise ModelCatalogSigningError("request not_after must be later than not_before")
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "not_after", not_after)

    @property
    def purpose(self) -> SigningPurpose:
        return CATALOG_PURPOSES[self.environment]

    @classmethod
    def from_mapping(cls, value: object) -> "CatalogReleaseRequest":
        data = _strict_mapping(
            value,
            required=frozenset(
                {
                    "artifact_type",
                    "catalog_id",
                    "catalog_sequence",
                    "catalog_sha256",
                    "environment",
                    "not_after",
                    "not_before",
                    "policy_version",
                    "purpose",
                    "release_id",
                    "schema_version",
                    "signature_algorithm",
                    "signer_key_id",
                    "signing_activity",
                    "signing_assignment_id",
                    "signing_assignment_receipt_sha256",
                    "signing_principal_id",
                }
            ),
            field="catalog release request",
        )
        environment = data["environment"]
        if not isinstance(environment, str) or environment not in CATALOG_ENVIRONMENTS:
            raise ModelCatalogSigningError("catalog environment must be lab or production")
        if data["purpose"] != CATALOG_PURPOSES[environment].value:
            raise ModelCatalogSigningError("release-request purpose does not match environment")
        return cls(
            environment=environment,
            release_id=data["release_id"],  # type: ignore[arg-type]
            catalog_id=data["catalog_id"],  # type: ignore[arg-type]
            catalog_sha256=data["catalog_sha256"],  # type: ignore[arg-type]
            catalog_sequence=data["catalog_sequence"],  # type: ignore[arg-type]
            policy_version=data["policy_version"],  # type: ignore[arg-type]
            signer_key_id=data["signer_key_id"],  # type: ignore[arg-type]
            signing_principal_id=data["signing_principal_id"],  # type: ignore[arg-type]
            signing_activity=data["signing_activity"],  # type: ignore[arg-type]
            signing_assignment_id=data["signing_assignment_id"],  # type: ignore[arg-type]
            signing_assignment_receipt_sha256=data[
                "signing_assignment_receipt_sha256"
            ],  # type: ignore[arg-type]
            not_before=_utc_timestamp(data["not_before"], "request not_before"),
            not_after=_utc_timestamp(data["not_after"], "request not_after"),
            schema_version=data["schema_version"],  # type: ignore[arg-type]
            artifact_type=data["artifact_type"],  # type: ignore[arg-type]
            signature_algorithm=data["signature_algorithm"],  # type: ignore[arg-type]
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "artifact_type": self.artifact_type,
            "catalog_id": self.catalog_id,
            "catalog_sequence": self.catalog_sequence,
            "catalog_sha256": self.catalog_sha256,
            "environment": self.environment,
            "not_after": _timestamp(self.not_after),
            "not_before": _timestamp(self.not_before),
            "policy_version": self.policy_version,
            "purpose": self.purpose.value,
            "release_id": self.release_id,
            "schema_version": self.schema_version,
            "signature_algorithm": self.signature_algorithm,
            "signer_key_id": self.signer_key_id,
            "signing_activity": self.signing_activity,
            "signing_assignment_id": self.signing_assignment_id,
            "signing_assignment_receipt_sha256": self.signing_assignment_receipt_sha256,
            "signing_principal_id": self.signing_principal_id,
        }

    @property
    def canonical_bytes(self) -> bytes:
        result = canonical_json_bytes(self.canonical_payload())
        if len(result) > MAX_STATEMENT_BYTES:
            raise ModelCatalogSigningError("catalog release request exceeds its size limit")
        return result

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


def parse_canonical_release_request(raw: bytes) -> CatalogReleaseRequest:
    request = CatalogReleaseRequest.from_mapping(
        _load_canonical_json(
            raw,
            "catalog release request",
            maximum_bytes=MAX_STATEMENT_BYTES,
        )
    )
    if raw != request.canonical_bytes:
        raise ModelCatalogSigningError("catalog release request is not canonical")
    return request


@dataclass(frozen=True, slots=True)
class CatalogApproval:
    activity: str
    principal_id: str
    assignment_id: str
    assignment_receipt_sha256: str
    approval_decision_receipt_sha256: str
    release_request_sha256: str
    release_id: str
    catalog_sha256: str
    approved_at: datetime
    decision: str = "approved"

    def __post_init__(self) -> None:
        _ascii_text(self.activity, "approval activity")
        _ascii_text(self.principal_id, "approval principal_id")
        _ascii_text(self.assignment_id, "approval assignment_id")
        _sha256(self.assignment_receipt_sha256, "approval assignment_receipt_sha256")
        _sha256(
            self.approval_decision_receipt_sha256,
            "approval approval_decision_receipt_sha256",
        )
        _sha256(self.release_request_sha256, "approval release_request_sha256")
        _ascii_text(self.release_id, "approval release_id")
        _sha256(self.catalog_sha256, "approval catalog_sha256")
        if self.decision != "approved":
            raise ModelCatalogSigningError("catalog approvals must be explicit approved decisions")
        object.__setattr__(
            self,
            "approved_at",
            _utc_timestamp(_timestamp(self.approved_at), "approval approved_at"),
        )

    @classmethod
    def from_mapping(cls, value: object) -> "CatalogApproval":
        data = _strict_mapping(
            value,
            required=frozenset(
                {
                    "activity",
                    "approved_at",
                    "approval_decision_receipt_sha256",
                    "assignment_id",
                    "assignment_receipt_sha256",
                    "catalog_sha256",
                    "decision",
                    "principal_id",
                    "release_request_sha256",
                    "release_id",
                }
            ),
            field="catalog approval",
        )
        return cls(
            activity=data["activity"],  # type: ignore[arg-type]
            principal_id=data["principal_id"],  # type: ignore[arg-type]
            assignment_id=data["assignment_id"],  # type: ignore[arg-type]
            assignment_receipt_sha256=data["assignment_receipt_sha256"],  # type: ignore[arg-type]
            approval_decision_receipt_sha256=data[
                "approval_decision_receipt_sha256"
            ],  # type: ignore[arg-type]
            release_request_sha256=data["release_request_sha256"],  # type: ignore[arg-type]
            release_id=data["release_id"],  # type: ignore[arg-type]
            catalog_sha256=data["catalog_sha256"],  # type: ignore[arg-type]
            approved_at=_utc_timestamp(data["approved_at"], "approval approved_at"),
            decision=data["decision"],  # type: ignore[arg-type]
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "activity": self.activity,
            "approved_at": _timestamp(self.approved_at),
            "approval_decision_receipt_sha256": self.approval_decision_receipt_sha256,
            "assignment_id": self.assignment_id,
            "assignment_receipt_sha256": self.assignment_receipt_sha256,
            "catalog_sha256": self.catalog_sha256,
            "decision": self.decision,
            "principal_id": self.principal_id,
            "release_request_sha256": self.release_request_sha256,
            "release_id": self.release_id,
        }


def canonical_approval_set_bytes(approvals: tuple[CatalogApproval, ...]) -> bytes:
    ordered = tuple(sorted(approvals, key=lambda item: (item.activity, item.principal_id)))
    result = canonical_json_bytes(
        {
            "approvals": [item.canonical_payload() for item in ordered],
            "schema_version": 1,
        }
    )
    if len(result) > MAX_APPROVAL_SET_BYTES:
        raise ModelCatalogSigningError("catalog approval set exceeds its size limit")
    return result


def parse_canonical_approval_set(raw: bytes) -> tuple[CatalogApproval, ...]:
    root = _strict_mapping(
        _load_canonical_json(
            raw,
            "catalog approval set",
            maximum_bytes=MAX_APPROVAL_SET_BYTES,
        ),
        required=frozenset({"approvals", "schema_version"}),
        field="catalog approval set",
    )
    if root["schema_version"] != 1:
        raise ModelCatalogSigningError("approval-set schema_version must be 1")
    raw_approvals = root["approvals"]
    if not isinstance(raw_approvals, list):
        raise ModelCatalogSigningError("approval-set approvals must be an array")
    approvals = tuple(CatalogApproval.from_mapping(item) for item in raw_approvals)
    if raw != canonical_approval_set_bytes(approvals):
        raise ModelCatalogSigningError("catalog approval set is not in canonical order")
    return approvals


@dataclass(frozen=True, slots=True)
class CatalogSignatureStatement:
    environment: str
    release_id: str
    catalog_id: str
    catalog_sha256: str
    catalog_sequence: int
    policy_version: str
    release_request_sha256: str
    approval_set_sha256: str
    signer_key_id: str
    signing_principal_id: str
    signing_activity: str
    signing_assignment_id: str
    signing_assignment_receipt_sha256: str
    signed_at: datetime
    not_before: datetime
    not_after: datetime
    schema_version: int = 1
    artifact_type: str = "model-profile-catalog"
    signature_algorithm: str = "Ed25519"

    def __post_init__(self) -> None:
        if self.schema_version != 1 or isinstance(self.schema_version, bool):
            raise ModelCatalogSigningError("statement schema_version must be 1")
        if self.artifact_type != "model-profile-catalog":
            raise ModelCatalogSigningError("unsupported signed artifact type")
        if self.signature_algorithm != "Ed25519":
            raise ModelCatalogSigningError("catalog signatures must use Ed25519")
        if not isinstance(self.environment, str) or self.environment not in CATALOG_ENVIRONMENTS:
            raise ModelCatalogSigningError("catalog environment must be lab or production")
        _ascii_text(self.release_id, "statement release_id")
        _ascii_text(self.catalog_id, "statement catalog_id")
        _sha256(self.catalog_sha256, "statement catalog_sha256")
        _positive_integer(self.catalog_sequence, "statement catalog_sequence")
        _ascii_text(self.policy_version, "statement policy_version")
        _sha256(self.release_request_sha256, "statement release_request_sha256")
        _sha256(self.approval_set_sha256, "statement approval_set_sha256")
        _ascii_text(self.signer_key_id, "statement signer_key_id")
        _ascii_text(self.signing_principal_id, "statement signing_principal_id")
        _ascii_text(self.signing_assignment_id, "statement signing_assignment_id")
        _sha256(
            self.signing_assignment_receipt_sha256,
            "statement signing_assignment_receipt_sha256",
        )
        if self.signing_activity != CATALOG_SIGNING_ACTIVITIES[self.environment]:
            raise ModelCatalogSigningError(
                "signing activity does not match the catalog environment"
            )
        signed_at = _utc_timestamp(_timestamp(self.signed_at), "statement signed_at")
        not_before = _utc_timestamp(_timestamp(self.not_before), "statement not_before")
        not_after = _utc_timestamp(_timestamp(self.not_after), "statement not_after")
        if not_after <= not_before:
            raise ModelCatalogSigningError("statement not_after must be later than not_before")
        if not (not_before <= signed_at < not_after):
            raise ModelCatalogSigningError("statement signed_at must fall within its validity")
        object.__setattr__(self, "signed_at", signed_at)
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "not_after", not_after)
        if self.release_request.digest != self.release_request_sha256:
            raise ModelCatalogSigningError(
                "statement metadata does not match its pre-approval release request"
            )

    @property
    def purpose(self) -> SigningPurpose:
        return CATALOG_PURPOSES[self.environment]

    @property
    def release_request(self) -> CatalogReleaseRequest:
        return CatalogReleaseRequest(
            environment=self.environment,
            release_id=self.release_id,
            catalog_id=self.catalog_id,
            catalog_sha256=self.catalog_sha256,
            catalog_sequence=self.catalog_sequence,
            policy_version=self.policy_version,
            signer_key_id=self.signer_key_id,
            signing_principal_id=self.signing_principal_id,
            signing_activity=self.signing_activity,
            signing_assignment_id=self.signing_assignment_id,
            signing_assignment_receipt_sha256=self.signing_assignment_receipt_sha256,
            not_before=self.not_before,
            not_after=self.not_after,
        )

    @classmethod
    def from_mapping(cls, value: object) -> "CatalogSignatureStatement":
        data = _strict_mapping(
            value,
            required=frozenset(
                {
                    "approval_set_sha256",
                    "artifact_type",
                    "catalog_id",
                    "catalog_sequence",
                    "catalog_sha256",
                    "environment",
                    "not_after",
                    "not_before",
                    "policy_version",
                    "purpose",
                    "release_id",
                    "release_request_sha256",
                    "schema_version",
                    "signature_algorithm",
                    "signed_at",
                    "signer_key_id",
                    "signing_activity",
                    "signing_assignment_id",
                    "signing_assignment_receipt_sha256",
                    "signing_principal_id",
                }
            ),
            field="catalog signature statement",
        )
        environment = data["environment"]
        if environment not in CATALOG_ENVIRONMENTS:
            raise ModelCatalogSigningError("catalog environment must be lab or production")
        expected_purpose = CATALOG_PURPOSES[environment].value  # type: ignore[index]
        if data["purpose"] != expected_purpose:
            raise ModelCatalogSigningError("statement purpose does not match environment")
        return cls(
            environment=environment,  # type: ignore[arg-type]
            release_id=data["release_id"],  # type: ignore[arg-type]
            catalog_id=data["catalog_id"],  # type: ignore[arg-type]
            catalog_sha256=data["catalog_sha256"],  # type: ignore[arg-type]
            catalog_sequence=data["catalog_sequence"],  # type: ignore[arg-type]
            policy_version=data["policy_version"],  # type: ignore[arg-type]
            release_request_sha256=data["release_request_sha256"],  # type: ignore[arg-type]
            approval_set_sha256=data["approval_set_sha256"],  # type: ignore[arg-type]
            signer_key_id=data["signer_key_id"],  # type: ignore[arg-type]
            signing_principal_id=data["signing_principal_id"],  # type: ignore[arg-type]
            signing_activity=data["signing_activity"],  # type: ignore[arg-type]
            signing_assignment_id=data["signing_assignment_id"],  # type: ignore[arg-type]
            signing_assignment_receipt_sha256=data[
                "signing_assignment_receipt_sha256"
            ],  # type: ignore[arg-type]
            signed_at=_utc_timestamp(data["signed_at"], "statement signed_at"),
            not_before=_utc_timestamp(data["not_before"], "statement not_before"),
            not_after=_utc_timestamp(data["not_after"], "statement not_after"),
            schema_version=data["schema_version"],  # type: ignore[arg-type]
            artifact_type=data["artifact_type"],  # type: ignore[arg-type]
            signature_algorithm=data["signature_algorithm"],  # type: ignore[arg-type]
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "approval_set_sha256": self.approval_set_sha256,
            "artifact_type": self.artifact_type,
            "catalog_id": self.catalog_id,
            "catalog_sequence": self.catalog_sequence,
            "catalog_sha256": self.catalog_sha256,
            "environment": self.environment,
            "not_after": _timestamp(self.not_after),
            "not_before": _timestamp(self.not_before),
            "policy_version": self.policy_version,
            "purpose": self.purpose.value,
            "release_id": self.release_id,
            "release_request_sha256": self.release_request_sha256,
            "schema_version": self.schema_version,
            "signature_algorithm": self.signature_algorithm,
            "signed_at": _timestamp(self.signed_at),
            "signer_key_id": self.signer_key_id,
            "signing_activity": self.signing_activity,
            "signing_assignment_id": self.signing_assignment_id,
            "signing_assignment_receipt_sha256": self.signing_assignment_receipt_sha256,
            "signing_principal_id": self.signing_principal_id,
        }

    @property
    def canonical_bytes(self) -> bytes:
        result = canonical_json_bytes(self.canonical_payload())
        if len(result) > MAX_STATEMENT_BYTES:
            raise ModelCatalogSigningError("catalog signature statement exceeds its size limit")
        return result

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


def parse_canonical_statement(raw: bytes) -> CatalogSignatureStatement:
    statement = CatalogSignatureStatement.from_mapping(
        _load_canonical_json(
            raw,
            "catalog signature statement",
            maximum_bytes=MAX_STATEMENT_BYTES,
        )
    )
    if raw != statement.canonical_bytes:
        raise ModelCatalogSigningError("catalog signature statement is not canonical")
    return statement


@dataclass(frozen=True, slots=True)
class CatalogSignatureEnvelope:
    statement: CatalogSignatureStatement
    approvals: tuple[CatalogApproval, ...]
    signature: bytes
    schema_version: int = 1
    signature_encoding: str = "base64"

    def __post_init__(self) -> None:
        if self.schema_version != 1 or isinstance(self.schema_version, bool):
            raise ModelCatalogSigningError("envelope schema_version must be 1")
        if self.signature_encoding != "base64":
            raise ModelCatalogSigningError("catalog signature encoding must be base64")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise ModelCatalogSigningError("an Ed25519 signature must contain exactly 64 bytes")
        if not isinstance(self.statement, CatalogSignatureStatement):
            raise ModelCatalogSigningError("envelope statement has an invalid type")
        if not isinstance(self.approvals, (list, tuple)) or any(
            not isinstance(item, CatalogApproval) for item in self.approvals
        ):
            raise ModelCatalogSigningError("catalog envelope must contain approval records")
        approvals = tuple(
            sorted(self.approvals, key=lambda item: (item.activity, item.principal_id))
        )
        if not approvals:
            raise ModelCatalogSigningError("catalog envelope must contain approvals")
        if len({item.activity for item in approvals}) != len(approvals):
            raise ModelCatalogSigningError("approval activities must be unique")
        if len({item.principal_id for item in approvals}) != len(approvals):
            raise ModelCatalogSigningError("approval principals must be distinct")
        if self.statement.signing_principal_id in {item.principal_id for item in approvals}:
            raise ModelCatalogSigningError(
                "the signing custodian must be distinct from every catalog approver"
            )
        expected = CATALOG_APPROVAL_ACTIVITIES[self.statement.environment]
        if {item.activity for item in approvals} != expected:
            raise ModelCatalogSigningError(
                "approval quorum does not match the catalog environment"
            )
        approval_digest = hashlib.sha256(canonical_approval_set_bytes(approvals)).hexdigest()
        if approval_digest != self.statement.approval_set_sha256:
            raise ModelCatalogSigningError("approval set digest does not match the statement")
        for approval in approvals:
            if approval.release_request_sha256 != self.statement.release_request_sha256:
                raise ModelCatalogSigningError(
                    "approval does not bind the statement's release request"
                )
            if approval.release_id != self.statement.release_id:
                raise ModelCatalogSigningError("approval release does not match the statement")
            if approval.catalog_sha256 != self.statement.catalog_sha256:
                raise ModelCatalogSigningError("approval catalog does not match the statement")
            if approval.approved_at > self.statement.signed_at:
                raise ModelCatalogSigningError("catalog approval cannot postdate signing")
        object.__setattr__(self, "approvals", approvals)

    @classmethod
    def parse(cls, raw: bytes) -> "CatalogSignatureEnvelope":
        root = _strict_mapping(
            _load_canonical_json(
                raw,
                "catalog signature envelope",
                maximum_bytes=MAX_ENVELOPE_BYTES,
            ),
            required=frozenset(
                {"approvals", "schema_version", "signature", "signature_encoding", "statement"}
            ),
            field="catalog signature envelope",
        )
        raw_approvals = root["approvals"]
        if not isinstance(raw_approvals, list):
            raise ModelCatalogSigningError("envelope approvals must be an array")
        encoded = _ascii_text(root["signature"], "catalog signature", maximum=128)
        try:
            signature = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ModelCatalogSigningError("catalog signature is not canonical base64") from exc
        if base64.b64encode(signature).decode("ascii") != encoded:
            raise ModelCatalogSigningError("catalog signature is not canonical base64")
        envelope = cls(
            statement=CatalogSignatureStatement.from_mapping(root["statement"]),
            approvals=tuple(CatalogApproval.from_mapping(item) for item in raw_approvals),
            signature=signature,
            schema_version=root["schema_version"],  # type: ignore[arg-type]
            signature_encoding=root["signature_encoding"],  # type: ignore[arg-type]
        )
        if raw != envelope.canonical_bytes:
            raise ModelCatalogSigningError("catalog signature envelope is not canonical")
        return envelope

    def canonical_payload(self) -> dict[str, object]:
        return {
            "approvals": [item.canonical_payload() for item in self.approvals],
            "schema_version": self.schema_version,
            "signature": base64.b64encode(self.signature).decode("ascii"),
            "signature_encoding": self.signature_encoding,
            "statement": self.statement.canonical_payload(),
        }

    @property
    def canonical_bytes(self) -> bytes:
        result = canonical_json_bytes(self.canonical_payload())
        if len(result) > MAX_ENVELOPE_BYTES:
            raise ModelCatalogSigningError("catalog signature envelope exceeds its size limit")
        return result


class CatalogAuthorizationVerifier(Protocol):
    """Authenticate exact Admin events, assignments, and decision receipts.

    The caller invokes approval verification at both ``approved_at`` and the
    current verification time, and signer verification at both ``signed_at``
    and the current time.  An adapter must bind the complete approval record,
    including its release-request and decision-receipt digests; checking only
    an assignment identifier is insufficient.
    """

    def approval_is_authorized(self, approval: CatalogApproval, *, at: datetime) -> bool: ...

    def signer_is_authorized(
        self, statement: CatalogSignatureStatement, *, at: datetime
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class CatalogVerificationReceipt:
    environment: str
    release_id: str
    catalog_id: str
    catalog_sha256: str
    catalog_sequence: int
    statement_sha256: str
    signature_sha256: str
    approval_set_sha256: str
    signer_key_id: str
    policy_version: str
    verified_at: datetime
    schema_version: int = 1
    result: str = "verified"

    def canonical_payload(self) -> dict[str, object]:
        return {
            "approval_set_sha256": self.approval_set_sha256,
            "catalog_id": self.catalog_id,
            "catalog_sequence": self.catalog_sequence,
            "catalog_sha256": self.catalog_sha256,
            "environment": self.environment,
            "policy_version": self.policy_version,
            "release_id": self.release_id,
            "result": self.result,
            "schema_version": self.schema_version,
            "signature_sha256": self.signature_sha256,
            "signer_key_id": self.signer_key_id,
            "statement_sha256": self.statement_sha256,
            "verified_at": _timestamp(self.verified_at),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.canonical_payload())

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifiedModelCatalog:
    catalog: ModelProfileCatalog
    statement: CatalogSignatureStatement
    receipt: CatalogVerificationReceipt


def parse_canonical_catalog(raw: bytes) -> ModelProfileCatalog:
    document = _load_canonical_json(
        raw,
        "model profile catalog",
        maximum_bytes=MAX_CATALOG_BYTES,
    )
    try:
        catalog = ModelProfileCatalog.from_mapping(document)
    except ModelSelectionError as exc:
        raise ModelCatalogSigningError(str(exc)) from exc
    if raw != canonical_json_bytes(catalog.canonical_payload()):
        raise ModelCatalogSigningError("model profile catalog is not in canonical order")
    return catalog


def _verify_available_profiles(
    catalog: ModelProfileCatalog,
    *,
    environment: str,
    pack_verifications: Mapping[str, ModelPackVerification],
) -> None:
    available = tuple(
        profile
        for profile in catalog.profiles
        if isinstance(profile, ModelProfile) and profile.availability == "available"
    )
    if not available:
        raise ModelCatalogVerificationDenied(
            "a signed model catalog must contain at least one available model profile"
        )
    for profile in available:
        if profile.verification_state != "verified" or profile.development_state != "development-tested":
            raise ModelCatalogVerificationDenied(
                f"available profile {profile.profile_id!r} is not verified and development-tested"
            )
        verification = pack_verifications.get(profile.model_pack_manifest_sha256)
        if (
            verification is None
            or verification.manifest_sha256 != profile.model_pack_manifest_sha256
            or verification.runtime_tuple.digest != profile.runtime_tuple_sha256
            or verification.state < ModelPackState.LOADABLE
        ):
            raise ModelCatalogVerificationDenied(
                f"available profile {profile.profile_id!r} lacks an exact loadable pack tuple"
            )
        if environment == "production":
            required_state = {
                "execution-certified": ModelPackState.EXECUTION_CERTIFIED,
                "interactive-certified": ModelPackState.INTERACTIVE_CERTIFIED,
            }.get(profile.certification_state)
            if required_state is None or verification.state < required_state:
                raise ModelCatalogVerificationDenied(
                    f"production profile {profile.profile_id!r} lacks its claimed certification"
                )


def verify_signed_catalog(
    raw_catalog: bytes,
    raw_envelope: bytes,
    *,
    expected_environment: str,
    expected_release_id: str,
    minimum_catalog_sequence: int,
    minimum_catalog_sha256: str | None,
    pack_verifications: Mapping[str, ModelPackVerification],
    signature_verifier: PurposeBoundEd25519Verifier,
    authorization_verifier: CatalogAuthorizationVerifier,
    now: datetime | None = None,
) -> VerifiedModelCatalog:
    """Verify a catalog without reading, receiving, or representing a private key."""

    if not isinstance(expected_environment, str) or expected_environment not in CATALOG_ENVIRONMENTS:
        raise ModelCatalogSigningError("expected_environment must be lab or production")
    expected_release = _ascii_text(expected_release_id, "expected_release_id")
    minimum_sequence = _non_negative_integer(
        minimum_catalog_sequence, "minimum_catalog_sequence"
    )
    if minimum_sequence == 0:
        if minimum_catalog_sha256 is not None:
            raise ModelCatalogSigningError(
                "an initial zero rollback floor cannot carry a catalog digest"
            )
        minimum_digest = None
    else:
        minimum_digest = _sha256(
            minimum_catalog_sha256, "minimum_catalog_sha256"
        )
    raw_now = now or datetime.now(UTC)
    if raw_now.tzinfo is None:
        raise ModelCatalogSigningError("verification time must be timezone-aware")
    observed_at = raw_now.astimezone(UTC)
    catalog = parse_canonical_catalog(raw_catalog)
    envelope = CatalogSignatureEnvelope.parse(raw_envelope)
    statement = envelope.statement
    catalog_sha256 = hashlib.sha256(raw_catalog).hexdigest()

    if statement.environment != expected_environment:
        raise ModelCatalogVerificationDenied("catalog environment does not match policy")
    if statement.release_id != expected_release:
        raise ModelCatalogVerificationDenied("catalog release does not match the requested release")
    if statement.catalog_id != catalog.catalog_id or statement.catalog_sha256 != catalog_sha256:
        raise ModelCatalogVerificationDenied("catalog identity or digest does not match the statement")
    if statement.catalog_sequence < minimum_sequence:
        raise ModelCatalogVerificationDenied("catalog sequence is below the trusted rollback floor")
    if statement.catalog_sequence == minimum_sequence and minimum_digest not in {
        None,
        catalog_sha256,
    }:
        raise ModelCatalogVerificationDenied(
            "catalog digest conflicts with the trusted sequence checkpoint"
        )
    if not (statement.not_before <= observed_at < statement.not_after):
        raise ModelCatalogVerificationDenied("catalog signature statement is not currently valid")
    if statement.signed_at > observed_at:
        raise ModelCatalogVerificationDenied("catalog signing time is in the future")
    if any(approval.approved_at > observed_at for approval in envelope.approvals):
        raise ModelCatalogVerificationDenied("a catalog approval time is in the future")
    if not all(
        authorization_verifier.approval_is_authorized(
            approval, at=approval.approved_at
        )
        and authorization_verifier.approval_is_authorized(
            approval, at=observed_at
        )
        for approval in envelope.approvals
    ):
        raise ModelCatalogVerificationDenied(
            "an exact catalog approval event is not authorized at approval and verification time"
        )
    if not authorization_verifier.signer_is_authorized(
        statement, at=statement.signed_at
    ) or not authorization_verifier.signer_is_authorized(
        statement, at=observed_at
    ):
        raise ModelCatalogVerificationDenied("the catalog signing custodian is not authorized")
    if not signature_verifier.verify_at(
        statement.canonical_bytes,
        envelope.signature,
        key_id=statement.signer_key_id,
        purpose=statement.purpose,
        at=statement.signed_at,
    ) or not signature_verifier.verify_at(
        statement.canonical_bytes,
        envelope.signature,
        key_id=statement.signer_key_id,
        purpose=statement.purpose,
        at=observed_at,
    ):
        raise ModelCatalogVerificationDenied("catalog signature is not trusted")

    _verify_available_profiles(
        catalog,
        environment=statement.environment,
        pack_verifications=pack_verifications,
    )
    receipt = CatalogVerificationReceipt(
        environment=statement.environment,
        release_id=statement.release_id,
        catalog_id=statement.catalog_id,
        catalog_sha256=catalog_sha256,
        catalog_sequence=statement.catalog_sequence,
        statement_sha256=statement.digest,
        signature_sha256=hashlib.sha256(envelope.signature).hexdigest(),
        approval_set_sha256=statement.approval_set_sha256,
        signer_key_id=statement.signer_key_id,
        policy_version=statement.policy_version,
        verified_at=observed_at,
    )
    return VerifiedModelCatalog(catalog=catalog, statement=statement, receipt=receipt)
