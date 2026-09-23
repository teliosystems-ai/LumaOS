from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.model_pack import SigningPurpose, SigningRole  # noqa: E402
from luma_os.monotonic_anchor import (  # noqa: E402
    DigestCheckpoint,
    InMemoryDigestAnchor,
    MonotonicAnchorValidationError,
)
from luma_os.signing_trust import (  # noqa: E402
    MAX_TRUST_BUNDLE_BYTES,
    MAX_TRUST_KEYS,
    AnchoredTrustBundle,
    RootTrustAnchor,
    SignedTrustBundle,
    SigningTrustError,
    SigningTrustKey,
    TrustBundleAnchorConflict,
    TrustBundlePolicy,
    TrustBundleVerificationDenied,
    canonical_trust_json_bytes,
    commit_trust_bundle,
    prepare_trust_bundle,
)


class TestOnlyPublicVerifier:
    """Deterministic test double, deliberately not a cryptographic signer."""

    @staticmethod
    def signature(message: bytes, public_key: bytes) -> bytes:
        return hashlib.sha512(b"test-only\x00" + public_key + message).digest()

    def verify(
        self,
        message: bytes,
        signature: bytes,
        *,
        public_key: bytes,
    ) -> bool:
        return signature == self.signature(message, public_key)


class KeyIdOnlyVerifier:
    """Old key-ID lookup shape that must not satisfy the public-key boundary."""

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        return True


class SwitchablePublicVerifier(TestOnlyPublicVerifier):
    def __init__(self) -> None:
        self.fail = False
        self.reject = False

    def verify(
        self,
        message: bytes,
        signature: bytes,
        *,
        public_key: bytes,
    ) -> bool:
        if self.fail:
            raise OSError("simulated public-verifier outage")
        if self.reject:
            return False
        return super().verify(message, signature, public_key=public_key)


class SwitchableAnchor(InMemoryDigestAnchor):
    def __init__(self) -> None:
        super().__init__()
        self.fail_reads = False
        self.invalid_reads = False

    def read(self, namespace: str):
        if self.fail_reads:
            raise OSError("simulated external-anchor outage")
        if self.invalid_reads:
            return object()
        return super().read(namespace)


class SigningTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 23, 12, tzinfo=UTC)
        self.root_key = bytes(range(32))
        self.leaf_key = bytes(range(32, 64))
        self.crypto = TestOnlyPublicVerifier()
        self.root = RootTrustAnchor(
            key_id="production-root-1",
            environment="production",
            trust_domain="luma-models",
            public_key=self.root_key,
            not_before=self.now - timedelta(days=30),
            not_after=self.now + timedelta(days=365),
        )
        self.policy = TrustBundlePolicy(
            environment="production",
            trust_domain="luma-models",
            anchor_namespace="luma/signing-trust/production",
            accepted_policy_versions=("trust-policy-v1",),
        )

    def key(self, **changes: object) -> SigningTrustKey:
        values: dict[str, object] = {
            "key_id": "catalog-production-1",
            "environment": "production",
            "public_key": self.leaf_key,
            "role": SigningRole.PRODUCTION_CATALOG_SIGNER,
            "purposes": (SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,),
            "not_before": self.now - timedelta(days=1),
            "not_after": self.now + timedelta(days=30),
        }
        values.update(changes)
        return SigningTrustKey(**values)  # type: ignore[arg-type]

    def bundle(
        self,
        *,
        sequence: int = 1,
        previous: str | None = None,
        keys: tuple[SigningTrustKey, ...] | None = None,
        **changes: object,
    ) -> SignedTrustBundle:
        values: dict[str, object] = {
            "environment": "production",
            "trust_domain": "luma-models",
            "bundle_sequence": sequence,
            "previous_bundle_sha256": previous,
            "policy_version": "trust-policy-v1",
            "root_key_id": "production-root-1",
            "issued_at": self.now - timedelta(hours=1),
            "not_before": self.now - timedelta(days=1),
            "not_after": self.now + timedelta(days=30),
            "signature": b"\x00" * 64,
        }
        values.update(changes)
        values["keys"] = keys or (
            self.key(
                not_before=values["not_before"],
                not_after=values["not_after"],
            ),
        )
        unsigned = SignedTrustBundle(**values)  # type: ignore[arg-type]
        return replace(
            unsigned,
            signature=self.crypto.signature(unsigned.signed_bytes, self.root_key),
        )

    def prepare(
        self,
        bundle: SignedTrustBundle,
        anchor: InMemoryDigestAnchor,
        **changes: object,
    ):
        values: dict[str, object] = {
            "root_anchors": (self.root,),
            "policy": self.policy,
            "crypto": self.crypto,
            "anchor": anchor,
            "clock": lambda: self.now,
        }
        values.update(changes)
        return prepare_trust_bundle(
            bundle.canonical_bytes,
            **values,  # type: ignore[arg-type]
        )

    def anchor_bundle(
        self,
        bundle: SignedTrustBundle | None = None,
        anchor: InMemoryDigestAnchor | None = None,
    ) -> tuple[SignedTrustBundle, InMemoryDigestAnchor, AnchoredTrustBundle]:
        candidate = bundle or self.bundle()
        store = anchor or InMemoryDigestAnchor()
        plan = self.prepare(candidate, store)
        anchored = commit_trust_bundle(plan, anchor=store)
        return candidate, store, anchored

    def test_genesis_commit_is_required_before_public_keys_can_verify(self) -> None:
        bundle = self.bundle()
        anchor = InMemoryDigestAnchor()
        plan = self.prepare(bundle, anchor)
        self.assertFalse(hasattr(plan, "create_verifier"))
        with self.assertRaises(SigningTrustError):
            AnchoredTrustBundle(  # type: ignore[call-arg]
                bundle,
                DigestCheckpoint(
                    self.policy.anchor_namespace, 1, 1, bundle.digest
                ),
                self.root,
                anchor,
                _token=object(),
            )
        anchored = commit_trust_bundle(plan, anchor=anchor)
        self.assertEqual(bundle.digest, anchored.bundle_sha256)
        self.assertEqual(1, anchored.bundle_sequence)
        self.assertEqual(anchor.read(self.policy.anchor_namespace), anchored.checkpoint)

        verifier = anchored.create_verifier(self.crypto)
        message = b"catalog statement"
        signature = self.crypto.signature(message, self.leaf_key)
        self.assertTrue(
            verifier.verify_at(
                message,
                signature,
                key_id="catalog-production-1",
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=self.now,
            )
        )
        self.assertFalse(
            verifier.verify_at(
                message,
                signature,
                key_id="unknown-key",
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=self.now,
            )
        )
        with self.assertRaisesRegex(SigningTrustError, "differs"):
            anchored.create_verifier(
                KeyIdOnlyVerifier(),  # type: ignore[arg-type]
            )

    def test_parser_rejects_noncanonical_duplicate_unknown_and_oversized_input(self) -> None:
        raw = self.bundle().canonical_bytes
        with self.assertRaises(SigningTrustError):
            SignedTrustBundle.parse(raw + b"\n")
        duplicate = raw.replace(
            b'{"bundle":', b'{"schema_version":1,"bundle":', 1
        )
        with self.assertRaisesRegex(SigningTrustError, "duplicate"):
            SignedTrustBundle.parse(duplicate)
        document = json.loads(raw)
        document["unexpected"] = True
        with self.assertRaisesRegex(SigningTrustError, "unexpected"):
            SignedTrustBundle.parse(canonical_trust_json_bytes(document))
        with self.assertRaisesRegex(SigningTrustError, "byte limit"):
            SignedTrustBundle.parse(b"x" * (MAX_TRUST_BUNDLE_BYTES + 1))

    def test_root_is_external_and_signature_key_is_exact(self) -> None:
        bundle = self.bundle()
        anchor = InMemoryDigestAnchor()
        unknown_root = replace(self.root, key_id="another-root")
        with self.assertRaises(TrustBundleVerificationDenied):
            self.prepare(
                bundle,
                anchor,
                root_anchors=(unknown_root,),
            )
        wrong_public_key = replace(self.root, public_key=b"r" * 32)
        with self.assertRaises(TrustBundleVerificationDenied):
            self.prepare(
                bundle,
                anchor,
                root_anchors=(wrong_public_key,),
            )
        tampered = replace(bundle, signature=b"x" * 64)
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "signature"):
            self.prepare(tampered, anchor)

    def test_bundle_root_and_leaf_lifecycle_fail_closed(self) -> None:
        anchor = InMemoryDigestAnchor()
        for bundle in (
            self.bundle(
                not_before=self.now + timedelta(seconds=1),
                issued_at=self.now + timedelta(seconds=1),
            ),
            self.bundle(not_after=self.now),
            self.bundle(issued_at=self.now + timedelta(seconds=1), not_before=self.now),
        ):
            with self.subTest(bundle=bundle), self.assertRaises(
                TrustBundleVerificationDenied
            ):
                self.prepare(bundle, anchor)

        expired_root = replace(
            self.root,
            not_before=self.now - timedelta(days=2),
            not_after=self.now,
        )
        with self.assertRaises(TrustBundleVerificationDenied):
            self.prepare(self.bundle(), anchor, root_anchors=(expired_root,))
        revoked_leaf = self.key(
            revoked_at=self.now - timedelta(seconds=1),
            revocation_reason="compromised",
        )
        _, _, anchored = self.anchor_bundle(self.bundle(keys=(revoked_leaf,)))
        verifier = anchored.create_verifier(self.crypto)
        self.assertFalse(
            verifier.verify_at(
                b"message",
                self.crypto.signature(b"message", self.leaf_key),
                key_id=revoked_leaf.key_id,
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=self.now,
            )
        )

    def test_lifetimes_are_nested_and_cached_verifier_rechecks_full_chain(self) -> None:
        with self.assertRaisesRegex(SigningTrustError, "contained by bundle"):
            self.bundle(
                keys=(
                    self.key(
                        not_before=self.now - timedelta(days=2),
                    ),
                )
            )
        short_root = replace(
            self.root,
            not_after=self.now + timedelta(days=20),
        )
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "contained by root"):
            self.prepare(
                self.bundle(),
                InMemoryDigestAnchor(),
                root_anchors=(short_root,),
            )
        scheduled_revocation = replace(
            self.root,
            revoked_at=self.now + timedelta(seconds=2),
        )
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "contained by root"):
            self.prepare(
                self.bundle(not_after=self.now + timedelta(seconds=3)),
                InMemoryDigestAnchor(),
                root_anchors=(scheduled_revocation,),
            )

        bundle_expiry = self.now + timedelta(seconds=1)
        expiring_bundle = self.bundle(not_after=bundle_expiry)
        _, _, anchored_bundle = self.anchor_bundle(expiring_bundle)
        bundle_verifier = anchored_bundle.create_verifier(self.crypto)
        message = b"cached-verifier"
        signature = self.crypto.signature(message, self.leaf_key)
        self.assertTrue(
            bundle_verifier.verify_at(
                message,
                signature,
                key_id="catalog-production-1",
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=self.now,
            )
        )
        self.assertFalse(
            bundle_verifier.verify_at(
                message,
                signature,
                key_id="catalog-production-1",
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=bundle_expiry,
            )
        )

        root_expiry = self.now + timedelta(seconds=2)
        expiring_root = replace(self.root, not_after=root_expiry)
        root_bound_bundle = self.bundle(not_after=root_expiry)
        root_anchor_store = InMemoryDigestAnchor()
        root_plan = self.prepare(
            root_bound_bundle,
            root_anchor_store,
            root_anchors=(expiring_root,),
        )
        anchored_root = commit_trust_bundle(
            root_plan,
            anchor=root_anchor_store,
        )
        cached = anchored_root.create_verifier(self.crypto)
        self.assertFalse(
            cached.verify_at(
                message,
                signature,
                key_id="catalog-production-1",
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=root_expiry,
            )
        )

    def test_currentness_uses_retained_live_clock_not_artifact_time(self) -> None:
        expiry = self.now + timedelta(seconds=1)
        clock_value = [self.now]
        bundle = self.bundle(not_after=expiry)
        anchor = InMemoryDigestAnchor()
        plan = self.prepare(bundle, anchor, clock=lambda: clock_value[0])
        anchored = commit_trust_bundle(plan, anchor=anchor)
        verifier = anchored.create_verifier(self.crypto)
        message = b"historical-artifact-time"
        signature = self.crypto.signature(message, self.leaf_key)

        clock_value[0] = expiry
        with self.assertRaises(TrustBundleVerificationDenied):
            anchored.ensure_current()
        self.assertFalse(
            verifier.verify_at(
                message,
                signature,
                key_id="catalog-production-1",
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=self.now,
            )
        )

    def test_role_purpose_and_environment_are_exact(self) -> None:
        with self.assertRaisesRegex(SigningTrustError, "role"):
            self.key(role=SigningRole.MODEL_PACK_SIGNER)
        with self.assertRaisesRegex(SigningTrustError, "production"):
            self.key(
                environment="lab",
                role=SigningRole.PRODUCTION_CATALOG_SIGNER,
            )
        lab_key = self.key(
            environment="lab",
            role=SigningRole.LAB_CATALOG_SIGNER,
            purposes=(SigningPurpose.MODEL_PROFILE_CATALOG_LAB,),
        )
        with self.assertRaisesRegex(SigningTrustError, "differs"):
            self.bundle(keys=(lab_key,))
        with self.assertRaises(TrustBundleVerificationDenied):
            self.prepare(
                self.bundle(),
                InMemoryDigestAnchor(),
                policy=replace(self.policy, environment="lab"),
            )

    def test_lab_and_production_root_and_leaf_keys_must_be_disjoint(self) -> None:
        lab_root_same_key = RootTrustAnchor(
            key_id="lab-root-1",
            environment="lab",
            trust_domain="luma-models",
            public_key=self.root_key,
            not_before=self.root.not_before,
            not_after=self.root.not_after,
        )
        with self.assertRaisesRegex(SigningTrustError, "must not reuse"):
            self.prepare(
                self.bundle(),
                InMemoryDigestAnchor(),
                root_anchors=(self.root, lab_root_same_key),
            )
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "reused"):
            self.prepare(
                self.bundle(),
                InMemoryDigestAnchor(),
                policy=replace(
                    self.policy,
                    forbidden_public_keys=(self.leaf_key,),
                ),
            )
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "root public key"):
            self.prepare(
                self.bundle(keys=(self.key(public_key=self.root_key),)),
                InMemoryDigestAnchor(),
            )

    def test_sequence_advance_predecessor_and_idempotent_reopen(self) -> None:
        first, anchor, anchored_first = self.anchor_bundle()
        same_plan = self.prepare(first, anchor)
        self.assertTrue(same_plan.is_idempotent)
        reopened = commit_trust_bundle(same_plan, anchor=anchor)
        self.assertEqual(anchored_first.checkpoint, reopened.checkpoint)

        second = self.bundle(sequence=2, previous=first.digest)
        second_plan = self.prepare(second, anchor)
        self.assertFalse(second_plan.is_idempotent)
        anchored_second = commit_trust_bundle(second_plan, anchor=anchor)
        self.assertEqual(2, anchored_second.bundle_sequence)
        self.assertEqual(2, anchored_second.checkpoint.generation)

    def test_cached_verifier_is_invalidated_by_new_checkpoint_and_anchor_failure(self) -> None:
        first = self.bundle()
        anchor = SwitchableAnchor()
        first_plan = self.prepare(first, anchor)
        anchored_first = commit_trust_bundle(first_plan, anchor=anchor)
        old_verifier = anchored_first.create_verifier(self.crypto)
        message = b"catalog"
        old_signature = self.crypto.signature(message, self.leaf_key)
        self.assertTrue(
            old_verifier.verify_at(
                message,
                old_signature,
                key_id="catalog-production-1",
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=self.now,
            )
        )

        replacement_public_key = b"N" * 32
        revoked = self.key(
            revoked_at=self.now,
            revocation_reason="rotated",
        )
        replacement = self.key(
            key_id="catalog-production-2",
            public_key=replacement_public_key,
        )
        second = self.bundle(
            sequence=2,
            previous=first.digest,
            keys=(revoked, replacement),
        )
        second_plan = self.prepare(second, anchor)
        anchored_second = commit_trust_bundle(second_plan, anchor=anchor)
        self.assertFalse(
            old_verifier.verify_at(
                message,
                old_signature,
                key_id="catalog-production-1",
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=self.now,
            )
        )
        new_verifier = anchored_second.create_verifier(self.crypto)
        new_signature = self.crypto.signature(message, replacement_public_key)
        self.assertTrue(
            new_verifier.verify_at(
                message,
                new_signature,
                key_id="catalog-production-2",
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=self.now,
            )
        )

        anchor.fail_reads = True
        self.assertFalse(
            new_verifier.verify_at(
                message,
                new_signature,
                key_id="catalog-production-2",
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=self.now,
            )
        )
        anchor.fail_reads = False
        anchor.invalid_reads = True
        self.assertFalse(
            new_verifier.verify_at(
                message,
                new_signature,
                key_id="catalog-production-2",
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=self.now,
            )
        )

    def test_rollback_fork_skip_and_wrong_predecessor_are_denied(self) -> None:
        first, anchor, _ = self.anchor_bundle()
        second = self.bundle(sequence=2, previous=first.digest)
        second_plan = self.prepare(second, anchor)
        commit_trust_bundle(second_plan, anchor=anchor)
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "below"):
            self.prepare(first, anchor)

        fork = self.bundle(
            sequence=2,
            previous=first.digest,
            keys=(self.key(public_key=b"z" * 32),),
        )
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "forks"):
            self.prepare(fork, anchor)
        skipped = self.bundle(sequence=4, previous=second.digest)
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "exactly once"):
            self.prepare(skipped, anchor)
        wrong_previous = self.bundle(sequence=3, previous="f" * 64)
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "predecessor"):
            self.prepare(wrong_previous, anchor)

    def test_compare_and_swap_race_prevents_commit(self) -> None:
        first, anchor, _ = self.anchor_bundle()
        second = self.bundle(sequence=2, previous=first.digest)
        plan = self.prepare(second, anchor)
        current = anchor.read(self.policy.anchor_namespace)
        self.assertTrue(
            anchor.compare_and_swap(
                expected=current,
                replacement=DigestCheckpoint(
                    self.policy.anchor_namespace,
                    2,
                    2,
                    "f" * 64,
                ),
            )
        )
        with self.assertRaises(TrustBundleAnchorConflict):
            commit_trust_bundle(plan, anchor=anchor)

    def test_live_root_verification_is_repeated_at_commit_and_use(self) -> None:
        provider = SwitchablePublicVerifier()
        first_anchor = InMemoryDigestAnchor()
        first_plan = self.prepare(self.bundle(), first_anchor, crypto=provider)
        provider.fail = True
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "commit"):
            commit_trust_bundle(first_plan, anchor=first_anchor)
        self.assertIsNone(first_anchor.read(self.policy.anchor_namespace))

        provider.fail = False
        second_anchor = InMemoryDigestAnchor()
        second_plan = self.prepare(self.bundle(), second_anchor, crypto=provider)
        anchored = commit_trust_bundle(second_plan, anchor=second_anchor)
        verifier = anchored.create_verifier(provider)
        message = b"live-root-revalidation"
        signature = provider.signature(message, self.leaf_key)
        provider.reject = True
        self.assertFalse(
            verifier.verify_at(
                message,
                signature,
                key_id="catalog-production-1",
                purpose=SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,
                at=self.now,
            )
        )

    def test_prepared_bundle_cannot_be_redirected_to_another_anchor(self) -> None:
        source = InMemoryDigestAnchor()
        plan = self.prepare(self.bundle(), source)
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "used during"):
            commit_trust_bundle(
                plan,
                anchor=InMemoryDigestAnchor(),
            )

    def test_in_memory_anchor_enforces_generation_and_is_not_production_evidence(self) -> None:
        anchor = InMemoryDigestAnchor()
        first = DigestCheckpoint("test/anchor", 1, 1, "a" * 64)
        self.assertTrue(anchor.compare_and_swap(expected=None, replacement=first))
        self.assertFalse(anchor.compare_and_swap(expected=None, replacement=first))
        with self.assertRaises(MonotonicAnchorValidationError):
            anchor.compare_and_swap(
                expected=first,
                replacement=DigestCheckpoint("test/anchor", 3, 2, "b" * 64),
            )
        self.assertIn("never production", (InMemoryDigestAnchor.__doc__ or "").lower())

    def test_key_count_public_key_and_canonical_order_limits(self) -> None:
        with self.assertRaisesRegex(SigningTrustError, "32 bytes"):
            self.key(public_key=b"short")
        key_records = tuple(
            self.key(
                key_id=f"model-key-{index:03d}",
                public_key=index.to_bytes(32, "big"),
            )
            for index in range(MAX_TRUST_KEYS)
        )
        maximum = self.bundle(keys=key_records)
        self.assertEqual(MAX_TRUST_KEYS, len(maximum.keys))
        with self.assertRaisesRegex(SigningTrustError, "canonically ordered"):
            self.bundle(keys=tuple(reversed(key_records)))
        overflow = (*key_records, self.key(key_id="overflow", public_key=b"q" * 32))
        with self.assertRaisesRegex(SigningTrustError, "more than"):
            self.bundle(keys=overflow)

    def test_policy_version_commit_lifecycle_and_schema_contract(self) -> None:
        bundle = self.bundle()
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "policy version"):
            self.prepare(
                bundle,
                InMemoryDigestAnchor(),
                policy=replace(
                    self.policy,
                    accepted_policy_versions=("trust-policy-v2",),
                ),
            )
        anchor = InMemoryDigestAnchor()
        expiring = self.bundle(not_after=self.now + timedelta(seconds=1))
        clock_value = [self.now]
        plan = self.prepare(expiring, anchor, clock=lambda: clock_value[0])
        clock_value[0] = self.now + timedelta(seconds=1)
        with self.assertRaisesRegex(TrustBundleVerificationDenied, "commit"):
            commit_trust_bundle(plan, anchor=anchor)
        schema = json.loads(
            Path("schemas/signing-trust-bundle.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(256, schema["$defs"]["bundle"]["properties"]["keys"]["maxItems"])
        self.assertEqual("Ed25519", schema["properties"]["signature_algorithm"]["const"])


if __name__ == "__main__":
    unittest.main()
