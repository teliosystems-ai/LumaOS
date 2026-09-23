from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.model_catalog_signing import (  # noqa: E402
    CATALOG_APPROVAL_ACTIVITIES,
    MAX_APPROVAL_SET_BYTES,
    MAX_CATALOG_BYTES,
    MAX_ENVELOPE_BYTES,
    MAX_RAW_SIGNATURE_READ_BYTES,
    MAX_STATEMENT_BYTES,
    CatalogApproval,
    CatalogReleaseRequest,
    CatalogSignatureEnvelope,
    CatalogSignatureStatement,
    ModelCatalogSigningError,
    ModelCatalogVerificationDenied,
    canonical_approval_set_bytes,
    canonical_json_bytes,
    parse_canonical_approval_set,
    parse_canonical_catalog,
    parse_canonical_statement,
    verify_signed_catalog,
)
from luma_os.model_pack import (  # noqa: E402
    ModelPackState,
    ModelPackVerification,
    PurposeBoundEd25519Verifier,
    RuntimeTuple,
    SigningPurpose,
    SigningRole,
    TrustKeyRecord,
)
from luma_os.model_selection import (  # noqa: E402
    MAX_CATALOG_PROFILES,
    ManualOnlyProfile,
    ModelProfile,
    ModelProfileCatalog,
    ResourceReservation,
)
from scripts.model_catalog_ceremony import main as ceremony_main  # noqa: E402


GIB = 1024**3


class RawVerifier:
    def __init__(self, *, accepted_signature: bytes = b"s" * 64) -> None:
        self.accepted_signature = accepted_signature

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        return bool(message) and key_id == "catalog-key-1" and signature == self.accepted_signature


class AuthorizationVerifier:
    def __init__(
        self,
        *,
        approvals: bool = True,
        signer: bool = True,
        decision_receipts: frozenset[str] | None = None,
    ) -> None:
        self.approvals = approvals
        self.signer = signer
        self.decision_receipts = decision_receipts
        self.approval_checks: list[tuple[str, datetime]] = []
        self.signer_checks: list[datetime] = []

    def approval_is_authorized(self, approval: CatalogApproval, *, at: datetime) -> bool:
        self.approval_checks.append((approval.approval_decision_receipt_sha256, at))
        return (
            self.approvals
            and approval.assignment_id.startswith("assignment-")
            and at.tzinfo is not None
            and (
                self.decision_receipts is None
                or approval.approval_decision_receipt_sha256 in self.decision_receipts
            )
        )

    def signer_is_authorized(
        self, statement: CatalogSignatureStatement, *, at: datetime
    ) -> bool:
        self.signer_checks.append(at)
        return self.signer and statement.signing_assignment_id == "assignment-custodian"


class ModelCatalogSigningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 23, 12, tzinfo=UTC)
        self.runtime = RuntimeTuple("linux", "x86_64", "llama.cpp", "b11100", "cuda")
        self.manifest_sha256 = "a" * 64

    def profile(self, **changes: object) -> ModelProfile:
        values: dict[str, object] = {
            "profile_id": "qwen3-4b-q4-cuda",
            "parameter_total": 4_000_000_000,
            "parameter_active_min": 4_000_000_000,
            "parameter_active_max": 4_000_000_000,
            "model_pack_manifest_sha256": self.manifest_sha256,
            "runtime_tuple_sha256": self.runtime.digest,
            "install_bytes": 3 * GIB,
            "storage_peak_bytes": 7 * GIB,
            "minimum_host_ram_bytes": 8 * GIB,
            "minimum_accelerator_memory_bytes": 4 * GIB,
            "load_reservations": (
                ResourceReservation("accelerator", 4 * GIB),
                ResourceReservation("host", 6 * GIB),
            ),
            "serve_reservations": (
                ResourceReservation("accelerator", 3 * GIB),
                ResourceReservation("host", 8 * GIB),
            ),
            "context_tokens": 4096,
            "execution_mode": "cuda",
            "availability": "available",
            "verification_state": "verified",
            "development_state": "development-tested",
            "certification_state": "execution-certified",
        }
        values.update(changes)
        return ModelProfile(**values)  # type: ignore[arg-type]

    def catalog_bytes(self, profile: ModelProfile | None = None) -> bytes:
        catalog = ModelProfileCatalog(
            1,
            "luma-production-0.1.0",
            (ManualOnlyProfile(), profile or self.profile()),
        )
        return canonical_json_bytes(catalog.canonical_payload())

    def release_request(
        self,
        raw_catalog: bytes,
        *,
        environment: str = "production",
        signer_key_id: str = "catalog-key-1",
        catalog_sequence: int = 7,
    ) -> CatalogReleaseRequest:
        return CatalogReleaseRequest(
            environment=environment,
            release_id="0.1.0",
            catalog_id="luma-production-0.1.0",
            catalog_sha256=hashlib.sha256(raw_catalog).hexdigest(),
            catalog_sequence=catalog_sequence,
            policy_version="catalog-policy-v1",
            signer_key_id=signer_key_id,
            signing_principal_id="person-custodian",
            signing_activity=f"model-catalog.sign.{environment}",
            signing_assignment_id="assignment-custodian",
            signing_assignment_receipt_sha256="d" * 64,
            not_before=self.now - timedelta(days=1),
            not_after=self.now + timedelta(days=30),
        )

    def approvals(
        self,
        request: CatalogReleaseRequest,
    ) -> tuple[CatalogApproval, ...]:
        return tuple(
            CatalogApproval(
                activity=activity,
                principal_id=f"person-{index}",
                assignment_id=f"assignment-{index}",
                assignment_receipt_sha256=f"{index}" * 64,
                approval_decision_receipt_sha256=f"{index + 3}" * 64,
                release_request_sha256=request.digest,
                release_id=request.release_id,
                catalog_sha256=request.catalog_sha256,
                approved_at=self.now - timedelta(hours=2),
            )
            for index, activity in enumerate(
                sorted(CATALOG_APPROVAL_ACTIVITIES[request.environment]), start=1
            )
        )

    def envelope(
        self,
        raw_catalog: bytes,
        *,
        environment: str = "production",
        signature: bytes = b"s" * 64,
        signer_key_id: str = "catalog-key-1",
        catalog_sequence: int = 7,
    ) -> CatalogSignatureEnvelope:
        request = self.release_request(
            raw_catalog,
            environment=environment,
            signer_key_id=signer_key_id,
            catalog_sequence=catalog_sequence,
        )
        approvals = self.approvals(request)
        statement = CatalogSignatureStatement(
            environment=request.environment,
            release_id=request.release_id,
            catalog_id=request.catalog_id,
            catalog_sha256=request.catalog_sha256,
            catalog_sequence=request.catalog_sequence,
            policy_version=request.policy_version,
            release_request_sha256=request.digest,
            approval_set_sha256=hashlib.sha256(
                canonical_approval_set_bytes(approvals)
            ).hexdigest(),
            signer_key_id=request.signer_key_id,
            signing_principal_id=request.signing_principal_id,
            signing_activity=request.signing_activity,
            signing_assignment_id=request.signing_assignment_id,
            signing_assignment_receipt_sha256=request.signing_assignment_receipt_sha256,
            signed_at=self.now - timedelta(hours=1),
            not_before=request.not_before,
            not_after=request.not_after,
        )
        return CatalogSignatureEnvelope(statement, approvals, signature)

    def signature_verifier(
        self,
        *,
        environment: str = "production",
        role: SigningRole | None = None,
        revoked: bool = False,
    ) -> PurposeBoundEd25519Verifier:
        purpose = (
            SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION
            if environment == "production"
            else SigningPurpose.MODEL_PROFILE_CATALOG_LAB
        )
        expected_role = (
            SigningRole.PRODUCTION_CATALOG_SIGNER
            if environment == "production"
            else SigningRole.LAB_CATALOG_SIGNER
        )
        record = TrustKeyRecord(
            key_id="catalog-key-1",
            role=role or expected_role,
            purposes=(purpose,),
            not_before=self.now - timedelta(days=2),
            not_after=self.now + timedelta(days=90),
            revoked_at=self.now - timedelta(seconds=1) if revoked else None,
        )
        return PurposeBoundEd25519Verifier(
            RawVerifier(),
            (record,),
            clock=lambda: self.now,
        )

    def pack_verifications(
        self,
        *,
        state: ModelPackState = ModelPackState.EXECUTION_CERTIFIED,
        runtime: RuntimeTuple | None = None,
    ) -> dict[str, ModelPackVerification]:
        return {
            self.manifest_sha256: ModelPackVerification(
                "qwen3-4b-q4-k-m",
                "1",
                self.manifest_sha256,
                runtime or self.runtime,
                state,
                evidence_sha256="e" * 64 if state > ModelPackState.LOADABLE else None,
            )
        }

    def verify(
        self,
        raw_catalog: bytes,
        envelope: CatalogSignatureEnvelope,
        **changes: object,
    ):
        values: dict[str, object] = {
            "expected_environment": envelope.statement.environment,
            "expected_release_id": "0.1.0",
            "minimum_catalog_sequence": 7,
            "minimum_catalog_sha256": hashlib.sha256(raw_catalog).hexdigest(),
            "pack_verifications": self.pack_verifications(),
            "signature_verifier": self.signature_verifier(
                environment=envelope.statement.environment
            ),
            "authorization_verifier": AuthorizationVerifier(),
            "now": self.now,
        }
        values.update(changes)
        return verify_signed_catalog(
            raw_catalog,
            envelope.canonical_bytes,
            **values,  # type: ignore[arg-type]
        )

    def test_production_catalog_verifies_and_emits_digest_bound_receipt(self) -> None:
        raw_catalog = self.catalog_bytes()
        envelope = self.envelope(raw_catalog)
        authorizer = AuthorizationVerifier()
        verified = self.verify(
            raw_catalog,
            envelope,
            authorization_verifier=authorizer,
        )
        self.assertEqual(hashlib.sha256(raw_catalog).hexdigest(), verified.catalog.digest)
        self.assertEqual(envelope.statement.digest, verified.receipt.statement_sha256)
        self.assertEqual("production", verified.receipt.environment)
        self.assertEqual(7, verified.receipt.catalog_sequence)
        self.assertEqual(64, len(verified.receipt.digest))
        self.assertEqual(2 * len(envelope.approvals), len(authorizer.approval_checks))
        self.assertEqual(2, len(authorizer.signer_checks))
        for approval in envelope.approvals:
            times = [
                at
                for receipt, at in authorizer.approval_checks
                if receipt == approval.approval_decision_receipt_sha256
            ]
            self.assertEqual([approval.approved_at, self.now], times)

    def test_noncanonical_catalog_and_envelope_or_digest_tampering_fail_closed(self) -> None:
        raw_catalog = self.catalog_bytes()
        envelope = self.envelope(raw_catalog)
        with self.assertRaises(ModelCatalogSigningError):
            verify_signed_catalog(
                raw_catalog + b"\n",
                envelope.canonical_bytes,
                expected_environment="production",
                expected_release_id="0.1.0",
                minimum_catalog_sequence=0,
                minimum_catalog_sha256=None,
                pack_verifications=self.pack_verifications(),
                signature_verifier=self.signature_verifier(),
                authorization_verifier=AuthorizationVerifier(),
                now=self.now,
            )
        with self.assertRaises(ModelCatalogSigningError):
            verify_signed_catalog(
                raw_catalog,
                envelope.canonical_bytes + b"\n",
                expected_environment="production",
                expected_release_id="0.1.0",
                minimum_catalog_sequence=0,
                minimum_catalog_sha256=None,
                pack_verifications=self.pack_verifications(),
                signature_verifier=self.signature_verifier(),
                authorization_verifier=AuthorizationVerifier(),
                now=self.now,
            )

        changed_catalog = self.catalog_bytes(self.profile(context_tokens=2048))
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(changed_catalog, envelope)

    def test_production_quorum_and_custodian_separation_are_structural(self) -> None:
        raw_catalog = self.catalog_bytes()
        envelope = self.envelope(raw_catalog)
        with self.assertRaises(ModelCatalogSigningError):
            CatalogSignatureEnvelope(
                replace(
                    envelope.statement,
                    approval_set_sha256=hashlib.sha256(
                        canonical_approval_set_bytes(envelope.approvals[:-1])
                    ).hexdigest(),
                ),
                envelope.approvals[:-1],
                envelope.signature,
            )
        with self.assertRaises(ModelCatalogSigningError):
            conflicting = replace(
                envelope.statement,
                signing_principal_id=envelope.approvals[0].principal_id,
            )
            CatalogSignatureEnvelope(conflicting, envelope.approvals, envelope.signature)

    def test_release_request_binds_all_preapproval_metadata(self) -> None:
        raw_catalog = self.catalog_bytes()
        envelope = self.envelope(raw_catalog)
        statement = envelope.statement
        self.assertEqual(statement.release_request.digest, statement.release_request_sha256)
        cases = (
            {"environment": "lab"},
            {"release_id": "0.2.0"},
            {"catalog_id": "forged-catalog"},
            {"catalog_sha256": "f" * 64},
            {"catalog_sequence": 8},
            {"policy_version": "forged-policy"},
            {"signature_algorithm": "Ed25519ph"},
            {"not_after": self.now + timedelta(days=31)},
            {"signer_key_id": "forged-key"},
            {"signing_principal_id": "forged-custodian"},
            {"signing_activity": "model-catalog.sign.lab"},
            {"signing_assignment_id": "forged-assignment"},
            {"signing_assignment_receipt_sha256": "f" * 64},
            {"release_request_sha256": "f" * 64},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ModelCatalogSigningError):
                replace(statement, **changes)

        mismatched = replace(
            envelope.approvals[0],
            release_request_sha256="f" * 64,
        )
        approvals = (mismatched, *envelope.approvals[1:])
        with self.assertRaises(ModelCatalogSigningError):
            CatalogSignatureEnvelope(
                replace(
                    statement,
                    approval_set_sha256=hashlib.sha256(
                        canonical_approval_set_bytes(approvals)
                    ).hexdigest(),
                ),
                approvals,
                envelope.signature,
            )

    def test_forged_approval_decision_receipt_is_rejected_by_authorization_adapter(self) -> None:
        raw_catalog = self.catalog_bytes()
        envelope = self.envelope(raw_catalog)
        trusted_receipts = frozenset(
            approval.approval_decision_receipt_sha256
            for approval in envelope.approvals
        )
        forged = replace(
            envelope.approvals[0],
            approval_decision_receipt_sha256="f" * 64,
        )
        approvals = (forged, *envelope.approvals[1:])
        forged_envelope = CatalogSignatureEnvelope(
            replace(
                envelope.statement,
                approval_set_sha256=hashlib.sha256(
                    canonical_approval_set_bytes(approvals)
                ).hexdigest(),
            ),
            approvals,
            envelope.signature,
        )
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(
                raw_catalog,
                forged_envelope,
                authorization_verifier=AuthorizationVerifier(
                    decision_receipts=trusted_receipts
                ),
            )

    def test_future_signing_time_is_rejected_even_with_valid_key_and_signature(self) -> None:
        raw_catalog = self.catalog_bytes()
        envelope = self.envelope(raw_catalog)
        future_statement = replace(
            envelope.statement,
            signed_at=self.now + timedelta(hours=1),
        )
        future_envelope = CatalogSignatureEnvelope(
            future_statement,
            envelope.approvals,
            envelope.signature,
        )
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(raw_catalog, future_envelope)

    def test_untrusted_input_limits_and_profile_count_fail_at_boundary_plus_one(self) -> None:
        with self.assertRaises(ModelCatalogSigningError):
            parse_canonical_catalog(b"x" * (MAX_CATALOG_BYTES + 1))
        with self.assertRaises(ModelCatalogSigningError):
            CatalogSignatureEnvelope.parse(b"x" * (MAX_ENVELOPE_BYTES + 1))
        with self.assertRaises(ModelCatalogSigningError):
            parse_canonical_approval_set(b"x" * (MAX_APPROVAL_SET_BYTES + 1))
        with self.assertRaises(ModelCatalogSigningError):
            parse_canonical_statement(b"x" * (MAX_STATEMENT_BYTES + 1))

        profiles = tuple(
            self.profile(profile_id=f"profile-{index}")
            for index in range(MAX_CATALOG_PROFILES - 1)
        )
        accepted = ModelProfileCatalog(
            1,
            "maximum-profile-catalog",
            (ManualOnlyProfile(), *profiles),
        )
        self.assertEqual(MAX_CATALOG_PROFILES, len(accepted.profiles))
        with self.assertRaisesRegex(ValueError, "more than 256"):
            ModelProfileCatalog(
                1,
                "oversized-profile-catalog",
                (
                    ManualOnlyProfile(),
                    *profiles,
                    self.profile(profile_id="profile-overflow"),
                ),
            )
        schema = json.loads(
            Path("schemas/model-profile.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(256, schema["properties"]["profiles"]["maxItems"])

    def test_environment_specific_key_role_validity_and_revocation_fail_closed(self) -> None:
        raw_catalog = self.catalog_bytes()
        envelope = self.envelope(raw_catalog)
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(
                raw_catalog,
                envelope,
                signature_verifier=self.signature_verifier(
                    role=SigningRole.LAB_CATALOG_SIGNER
                ),
            )
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(
                raw_catalog,
                envelope,
                signature_verifier=self.signature_verifier(revoked=True),
            )
        not_valid_when_signed = PurposeBoundEd25519Verifier(
            RawVerifier(),
            (
                TrustKeyRecord(
                    key_id="catalog-key-1",
                    role=SigningRole.PRODUCTION_CATALOG_SIGNER,
                    purposes=(SigningPurpose.MODEL_PROFILE_CATALOG_PRODUCTION,),
                    not_before=self.now - timedelta(minutes=30),
                    not_after=self.now + timedelta(days=1),
                ),
            ),
            clock=lambda: self.now,
        )
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(
                raw_catalog,
                envelope,
                signature_verifier=not_valid_when_signed,
            )
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(raw_catalog, envelope, expected_environment="lab")

    def test_current_admin_authorization_release_sequence_and_time_are_required(self) -> None:
        raw_catalog = self.catalog_bytes()
        envelope = self.envelope(raw_catalog)
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(
                raw_catalog,
                envelope,
                authorization_verifier=AuthorizationVerifier(approvals=False),
            )
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(
                raw_catalog,
                envelope,
                authorization_verifier=AuthorizationVerifier(signer=False),
            )
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(raw_catalog, envelope, expected_release_id="0.2.0")
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(
                raw_catalog,
                envelope,
                minimum_catalog_sequence=8,
                minimum_catalog_sha256="f" * 64,
            )
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(
                raw_catalog,
                envelope,
                minimum_catalog_sha256="f" * 64,
            )
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(raw_catalog, envelope, now=self.now + timedelta(days=31))
        with self.assertRaises(ModelCatalogSigningError):
            self.verify(raw_catalog, envelope, now=datetime(2026, 9, 23, 12))

    def test_available_profile_requires_exact_pack_tuple_and_claimed_certification(self) -> None:
        raw_catalog = self.catalog_bytes()
        envelope = self.envelope(raw_catalog)
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(raw_catalog, envelope, pack_verifications={})
        changed_runtime = RuntimeTuple("linux", "x86_64", "llama.cpp", "b11101", "cuda")
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(
                raw_catalog,
                envelope,
                pack_verifications=self.pack_verifications(runtime=changed_runtime),
            )
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(
                raw_catalog,
                envelope,
                pack_verifications=self.pack_verifications(state=ModelPackState.LOADABLE),
            )

        uncertified_catalog = self.catalog_bytes(
            self.profile(certification_state="not-certified")
        )
        uncertified_envelope = self.envelope(uncertified_catalog)
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(uncertified_catalog, uncertified_envelope)

    def test_lab_catalog_is_explicit_and_cannot_use_production_purpose(self) -> None:
        raw_catalog = self.catalog_bytes(
            self.profile(certification_state="not-certified")
        )
        envelope = self.envelope(raw_catalog, environment="lab")
        verified = self.verify(
            raw_catalog,
            envelope,
            pack_verifications=self.pack_verifications(state=ModelPackState.LOADABLE),
        )
        self.assertEqual("lab", verified.statement.environment)
        self.assertEqual(SigningPurpose.MODEL_PROFILE_CATALOG_LAB, verified.statement.purpose)
        with self.assertRaises(ModelCatalogVerificationDenied):
            self.verify(
                raw_catalog,
                envelope,
                signature_verifier=self.signature_verifier(environment="production"),
            )

    def test_operator_cli_prepares_and_assembles_without_private_key_input(self) -> None:
        raw_catalog = self.catalog_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog_path = root / "catalog.json"
            request_path = root / "request.json"
            approvals_path = root / "approvals.json"
            statement_path = root / "statement.json"
            signature_path = root / "statement.sig"
            envelope_path = root / "catalog.sig.json"
            catalog_path.write_bytes(raw_catalog)
            with redirect_stdout(io.StringIO()):
                result = ceremony_main(
                    [
                        "request",
                        "--catalog",
                        str(catalog_path),
                        "--request-out",
                        str(request_path),
                        "--environment",
                        "production",
                        "--release-id",
                        "0.1.0",
                        "--catalog-sequence",
                        "7",
                        "--policy-version",
                        "catalog-policy-v1",
                        "--signer-key-id",
                        "catalog-key-1",
                        "--signing-principal-id",
                        "person-custodian",
                        "--signing-assignment-id",
                        "assignment-custodian",
                        "--signing-assignment-receipt-sha256",
                        "d" * 64,
                        "--not-before",
                        "2026-09-22T12:00:00Z",
                        "--not-after",
                        "2026-10-23T12:00:00Z",
                    ]
                )
            self.assertEqual(0, result)
            request = self.release_request(raw_catalog)
            self.assertEqual(request.canonical_bytes, request_path.read_bytes())
            approvals_path.write_bytes(
                canonical_approval_set_bytes(self.approvals(request))
            )
            with redirect_stdout(io.StringIO()):
                result = ceremony_main(
                    [
                        "prepare",
                        "--catalog",
                        str(catalog_path),
                        "--request",
                        str(request_path),
                        "--approvals",
                        str(approvals_path),
                        "--statement-out",
                        str(statement_path),
                        "--signed-at",
                        "2026-09-23T11:00:00Z",
                    ]
                )
            self.assertEqual(0, result)
            signature_path.write_bytes(b"s" * 64)
            with redirect_stdout(io.StringIO()):
                result = ceremony_main(
                    [
                        "assemble",
                        "--catalog",
                        str(catalog_path),
                        "--approvals",
                        str(approvals_path),
                        "--statement",
                        str(statement_path),
                        "--signature",
                        str(signature_path),
                        "--envelope-out",
                        str(envelope_path),
                    ]
                )
            self.assertEqual(0, result)
            self.assertEqual(
                "production",
                CatalogSignatureEnvelope.parse(envelope_path.read_bytes()).statement.environment,
            )
            oversized_signature = root / "oversized.sig"
            oversized_envelope = root / "oversized-envelope.json"
            oversized_signature.write_bytes(
                b"x" * (MAX_RAW_SIGNATURE_READ_BYTES + 1)
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                result = ceremony_main(
                    [
                        "assemble",
                        "--catalog",
                        str(catalog_path),
                        "--approvals",
                        str(approvals_path),
                        "--statement",
                        str(statement_path),
                        "--signature",
                        str(oversized_signature),
                        "--envelope-out",
                        str(oversized_envelope),
                    ]
                )
            self.assertEqual(2, result)
            self.assertFalse(oversized_envelope.exists())


if __name__ == "__main__":
    unittest.main()
