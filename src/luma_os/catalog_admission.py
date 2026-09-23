"""Rollback-safe admission for signed model-profile catalogs.

Catalog signature verification is necessary but is not an authority to use a
catalog.  This module deliberately splits admission into two phases: prepare
verifies a candidate against the rollback floor read from an external anchor,
while commit publishes that candidate with compare-and-swap.  Only the object
returned by commit exposes the verified catalog as an authoritative value to
trusted application code, and every access repeats live trust, signature,
Admin, policy, lifecycle, and rollback checks.  The injected clock, public-key
verifier, authorization verifier, and external anchors are trusted composition
dependencies.  Python private fields and object identity are not a sandbox;
an untrusted component must cross an isolated service boundary rather than
supply admission objects directly.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
from types import MappingProxyType

from .model_catalog_signing import (
    CatalogAuthorizationVerifier,
    CatalogSignatureStatement,
    CatalogVerificationReceipt,
    MAX_CATALOG_BYTES,
    MAX_ENVELOPE_BYTES,
    VerifiedModelCatalog,
    canonical_json_bytes,
    verify_signed_catalog,
)
from .model_pack import ModelPackVerification, PurposeBoundEd25519Verifier
from .model_selection import MAX_CATALOG_PROFILES, ModelProfileCatalog
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


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    """Read one trusted verification instant from the retained live clock."""

    try:
        observed = clock()
    except Exception as exc:
        raise CatalogAdmissionDenied("the catalog authority clock is unavailable") from exc
    if not isinstance(observed, datetime) or observed.tzinfo is None:
        raise CatalogAdmissionDenied(
            "the catalog authority clock must return a timezone-aware datetime"
        )
    return observed.astimezone(UTC)


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


def _bounded_pack_verifications(
    values: Mapping[str, ModelPackVerification],
) -> Mapping[str, ModelPackVerification]:
    if not isinstance(values, Mapping):
        raise CatalogAdmissionError("pack_verifications must be a mapping")
    copied: dict[str, ModelPackVerification] = {}
    try:
        for index, (key, value) in enumerate(values.items(), start=1):
            if index > MAX_CATALOG_PROFILES:
                raise CatalogAdmissionError(
                    "pack_verifications exceeds the model-profile bound"
                )
            copied[key] = value
    except CatalogAdmissionError:
        raise
    except Exception as exc:
        raise CatalogAdmissionError("pack_verifications cannot be bounded") from exc
    return MappingProxyType(copied)


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
class _CatalogVerificationContext:
    """Trusted composition inputs retained for live authority revalidation."""

    raw_catalog: bytes
    raw_envelope: bytes
    pack_verifications: Mapping[str, ModelPackVerification]
    crypto: PublicEd25519Verifier
    authorization_verifier: CatalogAuthorizationVerifier
    accepted_policy_versions: frozenset[str]


def _receipt_identity(receipt: CatalogVerificationReceipt) -> dict[str, object]:
    payload = receipt.canonical_payload()
    payload.pop("verified_at", None)
    return payload


def _same_verified_artifact(
    first: VerifiedModelCatalog,
    second: VerifiedModelCatalog,
) -> bool:
    return (
        first.catalog == second.catalog
        and first.statement == second.statement
        and _receipt_identity(first.receipt) == _receipt_identity(second.receipt)
    )


def _verify_with_current_policy(
    context: _CatalogVerificationContext,
    *,
    expected_environment: str,
    expected_release_id: str,
    checkpoint: DigestCheckpoint | None,
    trust_bundle: AnchoredTrustBundle,
    clock: Callable[[], datetime],
) -> VerifiedModelCatalog:
    """Re-run signatures, Admin decisions, lifecycle, and pack bindings now."""

    observed_at = _clock_value(clock)
    signature_verifier = trust_bundle.create_verifier(context.crypto)
    if not isinstance(signature_verifier, PurposeBoundEd25519Verifier):
        raise CatalogAdmissionDenied(
            "anchored trust did not create a purpose-bound verifier"
        )
    verified = verify_signed_catalog(
        context.raw_catalog,
        context.raw_envelope,
        expected_environment=expected_environment,
        expected_release_id=expected_release_id,
        minimum_catalog_sequence=(0 if checkpoint is None else checkpoint.sequence),
        minimum_catalog_sha256=(
            None if checkpoint is None else checkpoint.artifact_sha256
        ),
        pack_verifications=context.pack_verifications,
        signature_verifier=signature_verifier,
        authorization_verifier=context.authorization_verifier,
        now=observed_at,
    )
    if verified.receipt.policy_version not in context.accepted_policy_versions:
        raise CatalogAdmissionDenied(
            "catalog policy version is not accepted for this admission"
        )
    return verified


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
    _trust_bundle: AnchoredTrustBundle = field(repr=False, compare=False)
    _clock: Callable[[], datetime] = field(repr=False, compare=False)
    _context: _CatalogVerificationContext = field(repr=False, compare=False)
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
    """Live-revalidated catalog authority inside the trusted composition root."""

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
    _trust_bundle: AnchoredTrustBundle = field(repr=False, compare=False)
    _clock: Callable[[], datetime] = field(repr=False, compare=False)
    _context: _CatalogVerificationContext = field(repr=False, compare=False)

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
        """Revalidate the exact checkpoint and every live authority dependency."""

        current = _read_checkpoint(
            self._anchor,
            self.anchor_checkpoint.namespace,
        )
        if current != self.anchor_checkpoint:
            raise CatalogAdmissionConflict(
                "the admitted catalog checkpoint is no longer current"
            )
        try:
            verified_now = _verify_with_current_policy(
                self._context,
                expected_environment=self.environment,
                expected_release_id=self.release_id,
                checkpoint=self.anchor_checkpoint,
                trust_bundle=self._trust_bundle,
                clock=self._clock,
            )
        except Exception as exc:
            raise CatalogAdmissionDenied(
                "the catalog no longer passes live signature, trust, Admin, or "
                "lifecycle verification"
            ) from exc
        retained = _read_checkpoint(
            self._anchor,
            self.anchor_checkpoint.namespace,
        )
        if retained != self.anchor_checkpoint:
            raise CatalogAdmissionConflict(
                "the admitted catalog checkpoint changed during live revalidation"
            )
        if not _same_verified_artifact(self._verified, verified_now):
            raise CatalogAdmissionDenied(
                "live catalog verification returned different bound evidence"
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
            ("_trust_bundle", plan._trust_bundle),
            ("_clock", plan._clock),
            ("_context", plan._context),
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
    clock: Callable[[], datetime] | None = None,
) -> CatalogAdmissionPlan:
    """Verify a candidate against the externally read rollback checkpoint.

    The rollback floor and namespace are intentionally not caller parameters.
    Successful preparation does not authorize selection or execution.  The
    optional clock is trusted-composition input and must be a protected live
    time source, never an artifact field or untrusted request parameter.
    """

    if expected_environment not in CATALOG_ANCHOR_NAMESPACES:
        raise CatalogAdmissionError(
            "expected_environment must be exactly lab or production"
        )
    if not isinstance(raw_catalog, bytes) or not isinstance(raw_envelope, bytes):
        raise CatalogAdmissionError(
            "catalog and envelope must be immutable bytes"
        )
    if not raw_catalog or len(raw_catalog) > MAX_CATALOG_BYTES:
        raise CatalogAdmissionError("catalog bytes exceed the bounded input contract")
    if not raw_envelope or len(raw_envelope) > MAX_ENVELOPE_BYTES:
        raise CatalogAdmissionError("envelope bytes exceed the bounded input contract")
    policies = _policy_versions(accepted_catalog_policy_versions)
    retained_pack_verifications = _bounded_pack_verifications(pack_verifications)
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
    if clock is not None and not callable(clock):
        raise CatalogAdmissionError("clock must be callable")

    namespace = CATALOG_ANCHOR_NAMESPACES[expected_environment]
    checkpoint = _read_checkpoint(anchor, namespace)
    authority_clock = clock or (
        lambda: datetime.now(UTC).replace(microsecond=0)
    )
    context = _CatalogVerificationContext(
        raw_catalog=raw_catalog,
        raw_envelope=raw_envelope,
        pack_verifications=retained_pack_verifications,
        crypto=crypto,
        authorization_verifier=authorization_verifier,
        accepted_policy_versions=policies,
    )
    verified = _verify_with_current_policy(
        context,
        expected_environment=expected_environment,
        expected_release_id=expected_release_id,
        checkpoint=checkpoint,
        trust_bundle=trust_bundle,
        clock=authority_clock,
    )
    receipt = verified.receipt

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
        _trust_bundle=trust_bundle,
        _clock=authority_clock,
        _context=context,
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

    context = plan._context
    if not isinstance(context, _CatalogVerificationContext):
        raise CatalogAdmissionError("admission plan lost its verification context")
    if (
        _sha256(context.raw_catalog) != plan.catalog_sha256
        or _sha256(context.raw_envelope) != plan.envelope_sha256
        or plan.catalog_policy_version not in context.accepted_policy_versions
    ):
        raise CatalogAdmissionError(
            "admission plan verification inputs differ from its digest bindings"
        )

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
        or plan._trust_bundle.bundle_sha256 != plan.trust_bundle_sha256
        or plan._trust_bundle.environment != plan.environment
        or not callable(plan._clock)
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
    current = _read_checkpoint(anchor, plan.anchor_namespace)
    if current != plan.expected_checkpoint:
        raise CatalogAdmissionConflict(
            "the catalog rollback checkpoint changed after preparation"
        )
    try:
        verified_now = _verify_with_current_policy(
            plan._context,
            expected_environment=plan.environment,
            expected_release_id=plan.release_id,
            checkpoint=current,
            trust_bundle=plan._trust_bundle,
            clock=plan._clock,
        )
    except Exception as exc:
        raise CatalogAdmissionDenied(
            "catalog admission no longer passes live verification at commit"
        ) from exc
    if not _same_verified_artifact(plan._candidate, verified_now):
        raise CatalogAdmissionDenied(
            "live commit verification returned different bound evidence"
        )

    if plan.expected_checkpoint == plan.replacement_checkpoint:
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
    admission = AnchoredCatalogAdmission._from_plan(plan, _seal=_AUTHORITY_SEAL)
    admission.ensure_current()
    return admission
