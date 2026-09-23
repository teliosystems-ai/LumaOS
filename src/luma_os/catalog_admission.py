"""Rollback-safe admission for signed model-profile catalogs.

Catalog signature verification is necessary but is not an authority to use a
catalog.  This module deliberately splits admission into two phases: prepare
verifies a candidate against the rollback floor read from an external anchor,
while commit publishes that candidate with compare-and-swap.  Only the object
returned by commit exposes the verified catalog as an authoritative value.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
from types import MappingProxyType

from .model_catalog_signing import (
    CatalogAuthorizationVerifier,
    CatalogSignatureStatement,
    CatalogVerificationReceipt,
    VerifiedModelCatalog,
    canonical_json_bytes,
    verify_signed_catalog,
)
from .model_pack import ModelPackVerification, PurposeBoundEd25519Verifier
from .model_selection import ModelProfileCatalog
from .monotonic_anchor import DigestCheckpoint, ExternalDigestAnchor
from .signing_trust import AnchoredTrustBundle, PublicEd25519Verifier


LAB_CATALOG_ANCHOR_NAMESPACE = "luma-os/model-profile-catalog/lab/v1"
PRODUCTION_CATALOG_ANCHOR_NAMESPACE = (
    "luma-os/model-profile-catalog/production/v1"
)
CATALOG_ANCHOR_NAMESPACES: Mapping[str, str] = MappingProxyType(
    {
        "lab": LAB_CATALOG_ANCHOR_NAMESPACE,
        "production": PRODUCTION_CATALOG_ANCHOR_NAMESPACE,
    }
)

_PLAN_SEAL = object()
_AUTHORITY_SEAL = object()


class CatalogAdmissionError(ValueError):
    """A catalog admission request or plan is malformed."""


class CatalogAdmissionDenied(RuntimeError):
    """A well-formed catalog cannot be admitted under current policy."""


class CatalogAdmissionConflict(CatalogAdmissionDenied):
    """The external rollback anchor changed or rejected an admission."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _checkpoint_payload(checkpoint: DigestCheckpoint | None) -> object:
    if checkpoint is None:
        return None
    return {
        "artifact_sha256": checkpoint.artifact_sha256,
        "generation": checkpoint.generation,
        "namespace": checkpoint.namespace,
        "sequence": checkpoint.sequence,
    }


def _policy_versions(values: Collection[str]) -> frozenset[str]:
    if isinstance(values, (str, bytes)) or not isinstance(
        values, (tuple, list, set, frozenset)
    ):
        raise CatalogAdmissionError(
            "accepted_catalog_policy_versions must be a finite collection"
        )
    copied = tuple(values)
    if not copied:
        raise CatalogAdmissionError(
            "accepted_catalog_policy_versions must not be empty"
        )
    if any(
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 256
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
        for value in copied
    ):
        raise CatalogAdmissionError(
            "catalog policy versions must be non-empty printable ASCII identifiers"
        )
    return frozenset(copied)


def _plan_payload(
    *,
    environment: str,
    release_id: str,
    catalog_id: str,
    catalog_sequence: int,
    catalog_policy_version: str,
    anchor_namespace: str,
    expected_checkpoint: DigestCheckpoint | None,
    replacement_checkpoint: DigestCheckpoint,
    catalog_sha256: str,
    envelope_sha256: str,
    trust_bundle_sha256: str,
    verification_receipt_sha256: str,
) -> dict[str, object]:
    return {
        "anchor_namespace": anchor_namespace,
        "artifact_type": "model-profile-catalog-admission-plan",
        "catalog_id": catalog_id,
        "catalog_policy_version": catalog_policy_version,
        "catalog_sequence": catalog_sequence,
        "catalog_sha256": catalog_sha256,
        "environment": environment,
        "envelope_sha256": envelope_sha256,
        "expected_checkpoint": _checkpoint_payload(expected_checkpoint),
        "release_id": release_id,
        "replacement_checkpoint": _checkpoint_payload(replacement_checkpoint),
        "schema_version": 1,
        "trust_bundle_sha256": trust_bundle_sha256,
        "verification_receipt_sha256": verification_receipt_sha256,
    }


@dataclass(frozen=True, slots=True)
class CatalogAdmissionPlan:
    """Verified but deliberately non-authoritative catalog admission plan.

    The candidate and anchor are private implementation state.  In particular,
    this type has no ``catalog`` or ``verified_catalog`` accessor; consumers
    must require :class:`AnchoredCatalogAdmission` instead.
    """

    environment: str
    release_id: str
    catalog_id: str
    catalog_sequence: int
    catalog_policy_version: str
    anchor_namespace: str
    expected_checkpoint: DigestCheckpoint | None
    replacement_checkpoint: DigestCheckpoint
    catalog_sha256: str
    envelope_sha256: str
    trust_bundle_sha256: str
    verification_receipt_sha256: str
    plan_sha256: str
    _candidate: VerifiedModelCatalog = field(repr=False, compare=False)
    _anchor: ExternalDigestAnchor = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _PLAN_SEAL:
            raise CatalogAdmissionError(
                "catalog admission plans can only be created by "
                "prepare_catalog_admission"
            )

    @property
    def committed(self) -> bool:
        return False


@dataclass(frozen=True, slots=True, init=False)
class AnchoredCatalogAdmission:
    """Authority token for one catalog committed to the rollback anchor."""

    environment: str
    release_id: str
    catalog_id: str
    catalog_sequence: int
    catalog_policy_version: str
    anchor_checkpoint: DigestCheckpoint
    catalog_sha256: str
    envelope_sha256: str
    trust_bundle_sha256: str
    verification_receipt_sha256: str
    admission_plan_sha256: str
    _verified: VerifiedModelCatalog = field(repr=False, compare=False)
    _anchor: ExternalDigestAnchor = field(repr=False, compare=False)

    def __init__(self) -> None:
        raise CatalogAdmissionError(
            "anchored admissions can only be created by commit_catalog_admission"
        )

    @property
    def committed(self) -> bool:
        return True

    @property
    def catalog(self) -> ModelProfileCatalog:
        self.ensure_current()
        return self._verified.catalog

    @property
    def statement(self) -> CatalogSignatureStatement:
        self.ensure_current()
        return self._verified.statement

    @property
    def verification_receipt(self) -> CatalogVerificationReceipt:
        self.ensure_current()
        return self._verified.receipt

    def ensure_current(self) -> None:
        """Deny use once the exact committed checkpoint is no longer current."""

        current = _read_checkpoint(
            self._anchor,
            self.anchor_checkpoint.namespace,
        )
        if current != self.anchor_checkpoint:
            raise CatalogAdmissionConflict(
                "the admitted catalog checkpoint is no longer current"
            )

    @classmethod
    def _from_plan(
        cls,
        plan: CatalogAdmissionPlan,
        *,
        _seal: object,
    ) -> "AnchoredCatalogAdmission":
        if _seal is not _AUTHORITY_SEAL:
            raise CatalogAdmissionError(
                "anchored admissions can only be created by commit_catalog_admission"
            )
        result = object.__new__(cls)
        for name, value in (
            ("environment", plan.environment),
            ("release_id", plan.release_id),
            ("catalog_id", plan.catalog_id),
            ("catalog_sequence", plan.catalog_sequence),
            ("catalog_policy_version", plan.catalog_policy_version),
            ("anchor_checkpoint", plan.replacement_checkpoint),
            ("catalog_sha256", plan.catalog_sha256),
            ("envelope_sha256", plan.envelope_sha256),
            ("trust_bundle_sha256", plan.trust_bundle_sha256),
            (
                "verification_receipt_sha256",
                plan.verification_receipt_sha256,
            ),
            ("admission_plan_sha256", plan.plan_sha256),
            ("_verified", plan._candidate),
            ("_anchor", plan._anchor),
        ):
            object.__setattr__(result, name, value)
        return result


def _read_checkpoint(
    anchor: ExternalDigestAnchor,
    namespace: str,
) -> DigestCheckpoint | None:
    if not callable(getattr(anchor, "read", None)) or not callable(
        getattr(anchor, "compare_and_swap", None)
    ):
        raise CatalogAdmissionError(
            "anchor must provide read and compare_and_swap operations"
        )
    try:
        checkpoint = anchor.read(namespace)
    except Exception as exc:
        raise CatalogAdmissionDenied(
            "the trusted catalog rollback checkpoint could not be read"
        ) from exc
    if checkpoint is not None and not isinstance(checkpoint, DigestCheckpoint):
        raise CatalogAdmissionDenied(
            "the trusted catalog rollback checkpoint has an invalid type"
        )
    if checkpoint is not None and checkpoint.namespace != namespace:
        raise CatalogAdmissionDenied(
            "the trusted catalog rollback checkpoint uses the wrong namespace"
        )
    return checkpoint


def prepare_catalog_admission(
    raw_catalog: bytes,
    raw_envelope: bytes,
    *,
    expected_environment: str,
    expected_release_id: str,
    accepted_catalog_policy_versions: Collection[str],
    pack_verifications: Mapping[str, ModelPackVerification],
    trust_bundle: AnchoredTrustBundle,
    crypto: PublicEd25519Verifier,
    authorization_verifier: CatalogAuthorizationVerifier,
    anchor: ExternalDigestAnchor,
    now: datetime | None = None,
) -> CatalogAdmissionPlan:
    """Verify a candidate against the externally read rollback checkpoint.

    The rollback floor and namespace are intentionally not caller parameters.
    Successful preparation does not authorize selection or execution.
    """

    if expected_environment not in CATALOG_ANCHOR_NAMESPACES:
        raise CatalogAdmissionError(
            "expected_environment must be exactly lab or production"
        )
    policies = _policy_versions(accepted_catalog_policy_versions)
    if not isinstance(trust_bundle, AnchoredTrustBundle):
        raise CatalogAdmissionDenied(
            "catalog admission requires an anchored trust bundle"
        )
    if expected_environment == "production" and trust_bundle.environment != "production":
        raise CatalogAdmissionDenied(
            "lab trust cannot admit a production catalog"
        )
    if trust_bundle.environment != expected_environment:
        raise CatalogAdmissionDenied(
            "trust-bundle environment does not match the catalog environment"
        )

    namespace = CATALOG_ANCHOR_NAMESPACES[expected_environment]
    checkpoint = _read_checkpoint(anchor, namespace)
    minimum_sequence = 0 if checkpoint is None else checkpoint.sequence
    minimum_digest = None if checkpoint is None else checkpoint.artifact_sha256

    verification_time = now or datetime.now(UTC).replace(microsecond=0)
    signature_verifier = trust_bundle.create_verifier(
        crypto,
        clock=lambda: verification_time,
    )
    if not isinstance(signature_verifier, PurposeBoundEd25519Verifier):
        raise CatalogAdmissionDenied(
            "anchored trust did not create a purpose-bound verifier"
        )
    verified = verify_signed_catalog(
        raw_catalog,
        raw_envelope,
        expected_environment=expected_environment,
        expected_release_id=expected_release_id,
        minimum_catalog_sequence=minimum_sequence,
        minimum_catalog_sha256=minimum_digest,
        pack_verifications=pack_verifications,
        signature_verifier=signature_verifier,
        authorization_verifier=authorization_verifier,
        now=verification_time,
    )
    receipt = verified.receipt
    if receipt.policy_version not in policies:
        raise CatalogAdmissionDenied(
            "catalog policy version is not accepted for this admission"
        )

    if checkpoint is None:
        if receipt.catalog_sequence != 1:
            raise CatalogAdmissionDenied(
                "a new catalog anchor namespace must begin at sequence one"
            )
        replacement = DigestCheckpoint(
            namespace=namespace,
            generation=1,
            sequence=receipt.catalog_sequence,
            artifact_sha256=receipt.catalog_sha256,
        )
    elif receipt.catalog_sequence == checkpoint.sequence:
        # verify_signed_catalog already rejected a different digest at this
        # sequence.  Preserve the exact checkpoint for an idempotent commit.
        replacement = checkpoint
    else:
        replacement = DigestCheckpoint(
            namespace=namespace,
            generation=checkpoint.generation + 1,
            sequence=receipt.catalog_sequence,
            artifact_sha256=receipt.catalog_sha256,
        )

    values = {
        "environment": receipt.environment,
        "release_id": receipt.release_id,
        "catalog_id": receipt.catalog_id,
        "catalog_sequence": receipt.catalog_sequence,
        "catalog_policy_version": receipt.policy_version,
        "anchor_namespace": namespace,
        "expected_checkpoint": checkpoint,
        "replacement_checkpoint": replacement,
        "catalog_sha256": receipt.catalog_sha256,
        "envelope_sha256": _sha256(raw_envelope),
        "trust_bundle_sha256": trust_bundle.bundle_sha256,
        "verification_receipt_sha256": receipt.digest,
    }
    plan_sha256 = _sha256(canonical_json_bytes(_plan_payload(**values)))
    return CatalogAdmissionPlan(
        **values,
        plan_sha256=plan_sha256,
        _candidate=verified,
        _anchor=anchor,
        _seal=_PLAN_SEAL,
    )


def _validate_plan(plan: CatalogAdmissionPlan, anchor: ExternalDigestAnchor) -> None:
    if not isinstance(plan, CatalogAdmissionPlan) or plan._seal is not _PLAN_SEAL:
        raise CatalogAdmissionError(
            "commit requires a plan returned by prepare_catalog_admission"
        )
    if anchor is not plan._anchor:
        raise CatalogAdmissionDenied(
            "catalog admission must commit to the anchor used during preparation"
        )
    if CATALOG_ANCHOR_NAMESPACES.get(plan.environment) != plan.anchor_namespace:
        raise CatalogAdmissionError("admission plan uses an untrusted namespace")
    if plan.replacement_checkpoint.namespace != plan.anchor_namespace:
        raise CatalogAdmissionError("replacement checkpoint namespace differs")
    if (
        plan.expected_checkpoint is not None
        and plan.expected_checkpoint.namespace != plan.anchor_namespace
    ):
        raise CatalogAdmissionError("expected checkpoint namespace differs")

    expected_plan_sha256 = _sha256(
        canonical_json_bytes(
            _plan_payload(
                environment=plan.environment,
                release_id=plan.release_id,
                catalog_id=plan.catalog_id,
                catalog_sequence=plan.catalog_sequence,
                catalog_policy_version=plan.catalog_policy_version,
                anchor_namespace=plan.anchor_namespace,
                expected_checkpoint=plan.expected_checkpoint,
                replacement_checkpoint=plan.replacement_checkpoint,
                catalog_sha256=plan.catalog_sha256,
                envelope_sha256=plan.envelope_sha256,
                trust_bundle_sha256=plan.trust_bundle_sha256,
                verification_receipt_sha256=plan.verification_receipt_sha256,
            )
        )
    )
    if expected_plan_sha256 != plan.plan_sha256:
        raise CatalogAdmissionError("admission plan digest does not match its fields")

    candidate = plan._candidate
    receipt = candidate.receipt
    if (
        receipt.environment != plan.environment
        or receipt.release_id != plan.release_id
        or receipt.catalog_id != plan.catalog_id
        or receipt.catalog_sequence != plan.catalog_sequence
        or receipt.policy_version != plan.catalog_policy_version
        or receipt.catalog_sha256 != plan.catalog_sha256
        or receipt.digest != plan.verification_receipt_sha256
        or candidate.catalog.digest != plan.catalog_sha256
        or plan.replacement_checkpoint.sequence != plan.catalog_sequence
        or plan.replacement_checkpoint.artifact_sha256 != plan.catalog_sha256
    ):
        raise CatalogAdmissionError(
            "admission plan candidate or digest bindings are inconsistent"
        )


def commit_catalog_admission(
    plan: CatalogAdmissionPlan,
    *,
    anchor: ExternalDigestAnchor,
) -> AnchoredCatalogAdmission:
    """Atomically anchor a prepared candidate and return its authority token.

    A failed CAS is always a conflict, even if a subsequent read would show
    the same digest.  Callers must prepare again against that new trusted
    checkpoint to use the explicit idempotent path.
    """

    _validate_plan(plan, anchor)
    if plan.expected_checkpoint == plan.replacement_checkpoint:
        current = _read_checkpoint(anchor, plan.anchor_namespace)
        if current != plan.replacement_checkpoint:
            raise CatalogAdmissionConflict(
                "the idempotent catalog checkpoint is no longer current"
            )
    else:
        try:
            committed = anchor.compare_and_swap(
                expected=plan.expected_checkpoint,
                replacement=plan.replacement_checkpoint,
            )
        except Exception as exc:
            raise CatalogAdmissionConflict(
                "the catalog rollback checkpoint rejected the admission"
            ) from exc
        if committed is not True:
            raise CatalogAdmissionConflict(
                "the catalog rollback checkpoint changed before commit"
            )
        retained = _read_checkpoint(anchor, plan.anchor_namespace)
        if retained != plan.replacement_checkpoint:
            raise CatalogAdmissionConflict(
                "the catalog rollback checkpoint did not retain the committed value"
            )
    return AnchoredCatalogAdmission._from_plan(plan, _seal=_AUTHORITY_SEAL)
