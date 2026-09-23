from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.catalog_admission import (  # noqa: E402
    AnchoredCatalogAdmission,
    CatalogAdmissionConflict,
    CatalogAdmissionDenied,
    CatalogAdmissionError,
    PRODUCTION_CATALOG_ANCHOR_NAMESPACE,
    commit_catalog_admission,
    prepare_catalog_admission,
)
from luma_os.model_catalog_signing import (  # noqa: E402
    MAX_CATALOG_BYTES,
    ModelCatalogVerificationDenied,
    verify_signed_catalog,
)
from luma_os.model_pack import SigningPurpose, SigningRole  # noqa: E402
from luma_os.model_selection import MAX_CATALOG_PROFILES  # noqa: E402
from luma_os.monotonic_anchor import DigestCheckpoint  # noqa: E402
from luma_os.signing_trust import (  # noqa: E402
    RootTrustAnchor,
    SignedTrustBundle,
    SigningTrustKey,
    TrustBundlePolicy,
    commit_trust_bundle,
    prepare_trust_bundle,
)
from tests import test_model_catalog_signing as signing_fixtures  # noqa: E402


class PublicVerifier:
    def __init__(self) -> None:
        self.signatures: dict[bytes, bytes] = {
            b"R" * 32: b"r" * 64,
            b"C" * 32: b"s" * 64,
            b"L" * 32: b"l" * 64,
            b"K" * 32: b"s" * 64,
        }

    def verify(
        self,
        message: bytes,
        signature: bytes,
        *,
        public_key: bytes,
    ) -> bool:
        return bool(message) and self.signatures.get(public_key) == signature


class RecordingAnchor:
    def __init__(
        self,
        checkpoint: DigestCheckpoint | None = None,
        *,
        race_with_identical_replacement: bool = False,
    ) -> None:
        self.checkpoint = checkpoint
        self.race_with_identical_replacement = race_with_identical_replacement
        self.fail_reads = False
        self.invalid_reads = False
        self.read_namespaces: list[str] = []
        self.cas_calls: list[
            tuple[DigestCheckpoint | None, DigestCheckpoint]
        ] = []

    def read(self, namespace: str) -> DigestCheckpoint | None:
        if self.fail_reads:
            raise OSError("anchor unavailable")
        if self.invalid_reads:
            return {"forged": "checkpoint"}  # type: ignore[return-value]
        self.read_namespaces.append(namespace)
        return self.checkpoint

    def compare_and_swap(
        self,
        *,
        expected: DigestCheckpoint | None,
        replacement: DigestCheckpoint,
    ) -> bool:
        self.cas_calls.append((expected, replacement))
        if self.race_with_identical_replacement:
            self.checkpoint = replacement
            return False
        if self.checkpoint != expected:
            return False
        self.checkpoint = replacement
        return True


class CatalogAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = signing_fixtures.ModelCatalogSigningTests()
        fixture.setUp()
        self.fixture = fixture
        self.now = fixture.now
        self.raw_catalog = fixture.catalog_bytes()
        self.crypto = PublicVerifier()

    def anchored_trust(
        self,
        environment: str = "production",
        *,
        with_context: bool = False,
    ):
        production = environment == "production"
        root_public_key = (b"R" if production else b"L") * 32
        leaf_public_key = (b"C" if production else b"K") * 32
        root_signature = (b"r" if production else b"l") * 64
        purpose = (
            SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION
            if production
            else SigningPurpose.MODEL_PROFILE_CATALOG_LAB
        )
        role = (
            SigningRole.PRODUCTION_CATALOG_SIGNER
            if production
            else SigningRole.LAB_CATALOG_SIGNER
        )
        domain = f"luma-os-{environment}-test"
        root = RootTrustAnchor(
            key_id=f"{environment}-root",
            environment=environment,
            trust_domain=domain,
            public_key=root_public_key,
            not_before=self.now - timedelta(days=30),
            not_after=self.now + timedelta(days=365),
        )
        key = SigningTrustKey(
            key_id="catalog-key-1",
            environment=environment,
            public_key=leaf_public_key,
            role=role,
            purposes=(purpose,),
            not_before=self.now - timedelta(hours=12),
            not_after=self.now + timedelta(days=20),
        )
        bundle = SignedTrustBundle(
            environment=environment,
            trust_domain=domain,
            bundle_sequence=1,
            previous_bundle_sha256=None,
            policy_version="trust-policy-v1",
            root_key_id=root.key_id,
            issued_at=self.now - timedelta(hours=3),
            not_before=self.now - timedelta(days=1),
            not_after=self.now + timedelta(days=30),
            keys=(key,),
            signature=root_signature,
        )
        trust_anchor = RecordingAnchor()
        policy = TrustBundlePolicy(
            environment=environment,
            trust_domain=domain,
            anchor_namespace=f"tests/signing-trust/{environment}",
            accepted_policy_versions=("trust-policy-v1",),
        )
        trust_plan = prepare_trust_bundle(
            bundle.canonical_bytes,
            root_anchors=(root,),
            policy=policy,
            crypto=self.crypto,
            anchor=trust_anchor,
            clock=lambda: self.now,
        )
        anchored = commit_trust_bundle(
            trust_plan,
            anchor=trust_anchor,
        )
        if with_context:
            return anchored, trust_anchor, root, bundle, policy
        return anchored

    def advance_trust(self, context):
        _, trust_anchor, root, bundle, policy = context
        replacement = replace(
            bundle,
            bundle_sequence=bundle.bundle_sequence + 1,
            previous_bundle_sha256=bundle.digest,
            issued_at=self.now - timedelta(hours=2),
        )
        plan = prepare_trust_bundle(
            replacement.canonical_bytes,
            root_anchors=(root,),
            policy=policy,
            crypto=self.crypto,
            anchor=trust_anchor,
            clock=lambda: self.now,
        )
        return commit_trust_bundle(
            plan,
            anchor=trust_anchor,
        )

    def prepare(
        self,
        *,
        anchor: RecordingAnchor | None = None,
        sequence: int = 1,
        trust_bundle=None,
        accepted_policies: tuple[str, ...] = ("catalog-policy-v1",),
        environment: str = "production",
        release_id: str = "0.1.0",
        clock=None,
        authorization_verifier=None,
        raw_catalog=None,
        raw_envelope=None,
        pack_verifications=None,
    ):
        selected_anchor = anchor or RecordingAnchor()
        envelope = self.fixture.envelope(
            self.raw_catalog,
            environment=environment,
            catalog_sequence=sequence,
        )
        plan = prepare_catalog_admission(
            self.raw_catalog if raw_catalog is None else raw_catalog,
            envelope.canonical_bytes if raw_envelope is None else raw_envelope,
            expected_environment=environment,
            expected_release_id=release_id,
            accepted_catalog_policy_versions=accepted_policies,
            pack_verifications=(
                self.fixture.pack_verifications()
                if pack_verifications is None
                else pack_verifications
            ),
            trust_bundle=trust_bundle or self.anchored_trust(environment),
            crypto=self.crypto,
            authorization_verifier=(
                authorization_verifier
                or signing_fixtures.AuthorizationVerifier()
            ),
            anchor=selected_anchor,
            clock=clock or (lambda: self.now),
        )
        return plan, selected_anchor, envelope

    def test_prepare_is_non_authoritative_and_commit_binds_all_evidence(self) -> None:
        trust = self.anchored_trust()
        plan, anchor, envelope = self.prepare(trust_bundle=trust)

        self.assertFalse(plan.committed)
        self.assertFalse(hasattr(plan, "catalog"))
        self.assertFalse(hasattr(plan, "verified_catalog"))
        self.assertEqual(PRODUCTION_CATALOG_ANCHOR_NAMESPACE, plan.anchor_namespace)
        self.assertEqual(hashlib.sha256(self.raw_catalog).hexdigest(), plan.catalog_sha256)
        self.assertEqual(
            hashlib.sha256(envelope.canonical_bytes).hexdigest(),
            plan.envelope_sha256,
        )
        self.assertEqual(trust.bundle_sha256, plan.trust_bundle_sha256)
        self.assertEqual(64, len(plan.verification_receipt_sha256))
        self.assertEqual(64, len(plan.plan_sha256))
        self.assertIsNone(anchor.checkpoint)
        with self.assertRaises(CatalogAdmissionError):
            AnchoredCatalogAdmission()
        with self.assertRaises(CatalogAdmissionError):
            AnchoredCatalogAdmission._from_plan(plan, _seal=object())

        admission = commit_catalog_admission(plan, anchor=anchor)

        self.assertIsInstance(admission, AnchoredCatalogAdmission)
        self.assertTrue(admission.committed)
        self.assertEqual(plan.replacement_checkpoint, anchor.checkpoint)
        self.assertEqual(plan.catalog_sha256, admission.catalog.digest)
        self.assertEqual(
            plan.verification_receipt_sha256,
            admission.verification_receipt.digest,
        )
        self.assertEqual(plan.envelope_sha256, admission.envelope_sha256)
        self.assertEqual(plan.trust_bundle_sha256, admission.trust_bundle_sha256)
        self.assertEqual(plan.plan_sha256, admission.admission_plan_sha256)

    def test_prepare_reads_exact_floor_and_has_no_caller_floor(self) -> None:
        digest = hashlib.sha256(self.raw_catalog).hexdigest()
        checkpoint = DigestCheckpoint(
            PRODUCTION_CATALOG_ANCHOR_NAMESPACE,
            4,
            7,
            digest,
        )
        anchor = RecordingAnchor(checkpoint)
        trust = self.anchored_trust()
        with patch(
            "luma_os.catalog_admission.verify_signed_catalog",
            wraps=verify_signed_catalog,
        ) as verifier:
            plan, _, _ = self.prepare(
                anchor=anchor,
                sequence=7,
                trust_bundle=trust,
            )

        self.assertEqual(7, verifier.call_args.kwargs["minimum_catalog_sequence"])
        self.assertEqual(
            digest,
            verifier.call_args.kwargs["minimum_catalog_sha256"],
        )
        self.assertEqual([PRODUCTION_CATALOG_ANCHOR_NAMESPACE], anchor.read_namespaces)
        self.assertEqual(checkpoint, plan.expected_checkpoint)

    def test_exact_same_sequence_and_digest_is_idempotent(self) -> None:
        digest = hashlib.sha256(self.raw_catalog).hexdigest()
        checkpoint = DigestCheckpoint(
            PRODUCTION_CATALOG_ANCHOR_NAMESPACE,
            3,
            7,
            digest,
        )
        anchor = RecordingAnchor(checkpoint)
        plan, _, _ = self.prepare(anchor=anchor, sequence=7)

        admission = commit_catalog_admission(plan, anchor=anchor)

        self.assertEqual(checkpoint, admission.anchor_checkpoint)
        self.assertEqual([], anchor.cas_calls)
        self.assertEqual(checkpoint, anchor.checkpoint)

    def test_lower_sequence_and_same_sequence_fork_are_denied_during_prepare(self) -> None:
        digest = hashlib.sha256(self.raw_catalog).hexdigest()
        lower_anchor = RecordingAnchor(
            DigestCheckpoint(
                PRODUCTION_CATALOG_ANCHOR_NAMESPACE,
                2,
                2,
                digest,
            )
        )
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.prepare(anchor=lower_anchor, sequence=1)

        fork_anchor = RecordingAnchor(
            DigestCheckpoint(
                PRODUCTION_CATALOG_ANCHOR_NAMESPACE,
                2,
                7,
                "f" * 64,
            )
        )
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.prepare(anchor=fork_anchor, sequence=7)

    def test_cas_race_fails_even_when_racer_installs_identical_checkpoint(self) -> None:
        anchor = RecordingAnchor(race_with_identical_replacement=True)
        plan, _, _ = self.prepare(anchor=anchor)

        with self.assertRaises(CatalogAdmissionConflict):
            commit_catalog_admission(plan, anchor=anchor)

        self.assertEqual(plan.replacement_checkpoint, anchor.checkpoint)
        self.assertEqual(1, len(anchor.cas_calls))

    def test_reprepare_after_commit_allows_explicit_idempotent_admission(self) -> None:
        plan, anchor, _ = self.prepare()
        first = commit_catalog_admission(plan, anchor=anchor)
        with self.assertRaises(CatalogAdmissionConflict):
            commit_catalog_admission(plan, anchor=anchor)

        repeated, _, _ = self.prepare(anchor=anchor)
        second = commit_catalog_admission(repeated, anchor=anchor)

        self.assertEqual(first.catalog_sha256, second.catalog_sha256)
        self.assertEqual(first.anchor_checkpoint, second.anchor_checkpoint)

    def test_authority_token_denies_catalog_after_newer_checkpoint(self) -> None:
        first_plan, anchor, _ = self.prepare()
        first = commit_catalog_admission(first_plan, anchor=anchor)
        second_plan, _, _ = self.prepare(anchor=anchor, sequence=2)
        second = commit_catalog_admission(second_plan, anchor=anchor)

        self.assertEqual(
            self.raw_catalog,
            signing_fixtures.canonical_json_bytes(second.catalog.canonical_payload()),
        )
        with self.assertRaises(CatalogAdmissionConflict):
            first.ensure_current()
        with self.assertRaises(CatalogAdmissionConflict):
            _ = first.catalog
        with self.assertRaises(CatalogAdmissionConflict):
            _ = first.statement
        with self.assertRaises(CatalogAdmissionConflict):
            _ = first.verification_receipt

    def test_authority_access_denies_anchor_read_error_or_invalid_type(self) -> None:
        class FailingReadAnchor(RecordingAnchor):
            failing = False

            def read(self, namespace: str):
                if self.failing:
                    raise OSError("anchor unavailable")
                return super().read(namespace)

        class InvalidReadAnchor(RecordingAnchor):
            invalid = False

            def read(self, namespace: str):
                if self.invalid:
                    return {"forged": "checkpoint"}
                return super().read(namespace)

        invalid_anchor = InvalidReadAnchor()
        plan, _, _ = self.prepare(anchor=invalid_anchor)
        admission = commit_catalog_admission(plan, anchor=invalid_anchor)
        invalid_anchor.invalid = True
        with self.assertRaises(CatalogAdmissionDenied):
            _ = admission.catalog

        failing_anchor = FailingReadAnchor()
        plan, _, _ = self.prepare(anchor=failing_anchor)
        admission = commit_catalog_admission(plan, anchor=failing_anchor)
        failing_anchor.failing = True
        with self.assertRaises(CatalogAdmissionDenied):
            _ = admission.catalog

    def test_authority_stales_after_trust_bundle_advances(self) -> None:
        context = self.anchored_trust(with_context=True)
        trust = context[0]
        plan, anchor, _ = self.prepare(trust_bundle=trust)
        admission = commit_catalog_admission(plan, anchor=anchor)
        self.assertEqual(
            self.raw_catalog,
            signing_fixtures.canonical_json_bytes(
                admission.catalog.canonical_payload()
            ),
        )

        self.advance_trust(context)

        for access in (
            lambda: admission.catalog,
            lambda: admission.statement,
            lambda: admission.verification_receipt,
            admission.ensure_current,
        ):
            with self.subTest(access=access):
                with self.assertRaises(CatalogAdmissionDenied):
                    access()

    def test_authority_stales_on_trust_anchor_outage_or_expiry(self) -> None:
        context = self.anchored_trust(with_context=True)
        trust, trust_anchor, _, _, _ = context
        clock_value = [self.now]
        plan, anchor, _ = self.prepare(
            trust_bundle=trust,
            clock=lambda: clock_value[0],
        )
        admission = commit_catalog_admission(plan, anchor=anchor)

        trust_anchor.fail_reads = True
        with self.assertRaises(CatalogAdmissionDenied):
            _ = admission.catalog
        trust_anchor.fail_reads = False
        clock_value[0] = self.now + timedelta(days=31)
        with self.assertRaises(CatalogAdmissionDenied):
            _ = admission.catalog

    def test_commit_and_every_access_recheck_live_admin_authorization(self) -> None:
        authorizer = signing_fixtures.AuthorizationVerifier()
        plan, anchor, _ = self.prepare(authorization_verifier=authorizer)

        authorizer.approvals = False
        with self.assertRaises(CatalogAdmissionDenied):
            commit_catalog_admission(plan, anchor=anchor)
        self.assertIsNone(anchor.checkpoint)

        authorizer.approvals = True
        admission = commit_catalog_admission(plan, anchor=anchor)
        self.assertEqual(plan.catalog_sha256, admission.catalog.digest)

        authorizer.signer = False
        for access in (
            lambda: admission.catalog,
            lambda: admission.statement,
            lambda: admission.verification_receipt,
            admission.ensure_current,
        ):
            with self.subTest(access=access):
                with self.assertRaises(CatalogAdmissionDenied):
                    access()

    def test_authority_rechecks_catalog_anchor_after_live_admin_verification(self) -> None:
        anchor = RecordingAnchor()

        class AdvancingAuthorizationVerifier(
            signing_fixtures.AuthorizationVerifier
        ):
            enabled = False
            advanced = False

            def approval_is_authorized(self, approval, *, at):
                allowed = super().approval_is_authorized(approval, at=at)
                if self.enabled and not self.advanced:
                    checkpoint = anchor.checkpoint
                    if checkpoint is None:
                        raise AssertionError("catalog checkpoint must be committed")
                    anchor.checkpoint = DigestCheckpoint(
                        namespace=checkpoint.namespace,
                        generation=checkpoint.generation + 1,
                        sequence=checkpoint.sequence + 1,
                        artifact_sha256="f" * 64,
                    )
                    self.advanced = True
                return allowed

        authorizer = AdvancingAuthorizationVerifier()
        plan, _, _ = self.prepare(
            anchor=anchor,
            authorization_verifier=authorizer,
        )
        admission = commit_catalog_admission(plan, anchor=anchor)

        authorizer.enabled = True
        with self.assertRaisesRegex(CatalogAdmissionConflict, "during"):
            admission.ensure_current()
        self.assertTrue(authorizer.advanced)

    def test_commit_uses_retained_live_clock_not_a_preparation_timestamp(self) -> None:
        clock_value = [self.now]
        plan, anchor, _ = self.prepare(clock=lambda: clock_value[0])

        clock_value[0] = self.now + timedelta(days=31)
        with self.assertRaises(CatalogAdmissionDenied):
            commit_catalog_admission(plan, anchor=anchor)
        self.assertIsNone(anchor.checkpoint)

    def test_only_anchored_matching_environment_trust_is_accepted(self) -> None:
        envelope = self.fixture.envelope(self.raw_catalog, catalog_sequence=1)
        with self.assertRaises(CatalogAdmissionDenied):
            prepare_catalog_admission(
                self.raw_catalog,
                envelope.canonical_bytes,
                expected_environment="production",
                expected_release_id="0.1.0",
                accepted_catalog_policy_versions=("catalog-policy-v1",),
                pack_verifications=self.fixture.pack_verifications(),
                trust_bundle=object(),  # type: ignore[arg-type]
                crypto=self.crypto,
                authorization_verifier=signing_fixtures.AuthorizationVerifier(),
                anchor=RecordingAnchor(),
                clock=lambda: self.now,
            )

        with self.assertRaisesRegex(CatalogAdmissionDenied, "lab trust"):
            self.prepare(trust_bundle=self.anchored_trust("lab"))

    def test_expected_release_and_accepted_catalog_policy_are_enforced(self) -> None:
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.prepare(release_id="0.2.0")
        with self.assertRaises(CatalogAdmissionDenied):
            self.prepare(accepted_policies=("catalog-policy-v2",))
        with self.assertRaises(CatalogAdmissionError):
            self.prepare(accepted_policies=())

    def test_retained_live_context_is_bounded_before_copying(self) -> None:
        for raw in (bytearray(self.raw_catalog), memoryview(self.raw_catalog)):
            with self.subTest(raw_type=type(raw).__name__):
                with self.assertRaises(CatalogAdmissionError):
                    self.prepare(raw_catalog=raw)

        with self.assertRaises(CatalogAdmissionError):
            self.prepare(raw_catalog=b"x" * (MAX_CATALOG_BYTES + 1))

        verification = next(iter(self.fixture.pack_verifications().values()))
        oversized = {
            f"{index:064x}": verification
            for index in range(MAX_CATALOG_PROFILES + 1)
        }
        with self.assertRaises(CatalogAdmissionError):
            self.prepare(pack_verifications=oversized)

    def test_genesis_must_be_sequence_one(self) -> None:
        with self.assertRaisesRegex(CatalogAdmissionDenied, "begin at sequence one"):
            self.prepare(sequence=7)

    def test_checkpoint_from_any_nonfixed_namespace_is_denied(self) -> None:
        anchor = RecordingAnchor(
            DigestCheckpoint(
                "attacker-selected/catalog",
                1,
                1,
                hashlib.sha256(self.raw_catalog).hexdigest(),
            )
        )
        with self.assertRaisesRegex(CatalogAdmissionDenied, "wrong namespace"):
            self.prepare(anchor=anchor)

    def test_wrong_or_changed_anchor_and_tampered_plan_never_return_authority(self) -> None:
        plan, anchor, _ = self.prepare()
        with self.assertRaises(CatalogAdmissionDenied):
            commit_catalog_admission(plan, anchor=RecordingAnchor())
        self.assertIsNone(anchor.checkpoint)

        tampered = replace(plan, envelope_sha256="f" * 64)
        with self.assertRaises(CatalogAdmissionError):
            commit_catalog_admission(tampered, anchor=anchor)
        self.assertIsNone(anchor.checkpoint)

    def test_commit_rechecks_retained_checkpoint(self) -> None:
        class NonRetainingAnchor(RecordingAnchor):
            def compare_and_swap(
                self,
                *,
                expected: DigestCheckpoint | None,
                replacement: DigestCheckpoint,
            ) -> bool:
                self.cas_calls.append((expected, replacement))
                return True

        anchor = NonRetainingAnchor()
        plan, _, _ = self.prepare(anchor=anchor)
        with self.assertRaises(CatalogAdmissionConflict):
            commit_catalog_admission(plan, anchor=anchor)


if __name__ == "__main__":
    unittest.main()
