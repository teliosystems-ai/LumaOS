from __future__ import annotations

from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.administration import RoleAssignment  # noqa: E402
from luma_os.durable_administration import (  # noqa: E402
    ADMIN_AUTHORIZATION_ANCHOR_NAMESPACE,
    MAX_ACTIVITIES_PER_ASSIGNMENT,
    MAX_CATALOG_AUTHORIZATION_BATCH_APPROVALS,
    MAX_EVENTS,
    AdminAuthorizationEventReceipt,
    DurableAdministrationAnchorConflict,
    DurableAdministrationCapacityExceeded,
    DurableAdministrationClockRollback,
    DurableAdministrationDenied,
    DurableAdministrationIntegrityError,
    DurableAdministrationReconciliationRequired,
    DurableAdministrationValidationError,
    DurableAdminAuthorizationStore,
    DurableCatalogAuthorizationVerifier,
    canonical_admin_event_bytes,
)
from luma_os.model_catalog_signing import (  # noqa: E402
    ModelCatalogVerificationDenied,
    verify_signed_catalog,
)
from luma_os.monotonic_anchor import (  # noqa: E402
    DigestCheckpoint,
    InMemoryDigestAnchor,
)
from tests import test_model_catalog_signing as catalog_fixtures  # noqa: E402


SECRET = b"durable-admin-test-secret-material" * 2


class LabOnlyAllowingWriterAuthorizer:
    """Permissive fake for isolated tests; never a production identity check."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, object, datetime]] = []

    def assignment_grant_is_authorized(
        self,
        assignment: RoleAssignment,
        *,
        assignment_receipt_sha256: str,
        at: datetime,
    ) -> bool:
        self.calls.append(
            ("grant", (assignment, assignment_receipt_sha256), at)
        )
        return True

    def assignment_revoke_is_authorized(
        self,
        assignment: RoleAssignment,
        *,
        revocation_receipt_sha256: str,
        revoked_by: str,
        at: datetime,
    ) -> bool:
        self.calls.append(
            (
                "revoke",
                (assignment, revocation_receipt_sha256, revoked_by),
                at,
            )
        )
        return True

    def catalog_approval_is_authorized(
        self,
        approval,
        *,
        at: datetime,
    ) -> bool:
        self.calls.append(("approval", approval, at))
        return True

    def catalog_signing_is_authorized(
        self,
        statement,
        *,
        at: datetime,
    ) -> bool:
        self.calls.append(("signing", statement, at))
        return True


class RejectingAnchor:
    def __init__(self) -> None:
        self.checkpoint: DigestCheckpoint | None = None
        self.cas_calls = 0
        self.fail_reads = False
        self.invalid_reads = False

    def read(self, namespace: str):
        del namespace
        if self.fail_reads:
            raise OSError("anchor unavailable")
        if self.invalid_reads:
            return {"forged": "checkpoint"}
        return self.checkpoint

    def compare_and_swap(
        self,
        *,
        expected: DigestCheckpoint | None,
        replacement: DigestCheckpoint,
    ) -> bool:
        del expected, replacement
        self.cas_calls += 1
        return False


class CountingReplayStore(DurableAdminAuthorizationStore):
    def __init__(self, *args, **kwargs) -> None:
        self.verified_state_loads = 0
        super().__init__(*args, **kwargs)

    def _load_verified_state(self, connection):
        self.verified_state_loads += 1
        return super()._load_verified_state(connection)


class AdvancingOnSecondReadAnchor:
    def __init__(self) -> None:
        self._anchor = InMemoryDigestAnchor()
        self._armed = False
        self._armed_reads = 0

    def arm(self) -> None:
        self._armed = True
        self._armed_reads = 0

    def read(self, namespace: str):
        current = self._anchor.read(namespace)
        if self._armed:
            self._armed_reads += 1
            if self._armed_reads == 2 and current is not None:
                replacement = DigestCheckpoint(
                    namespace=current.namespace,
                    generation=current.generation + 1,
                    sequence=current.sequence + 1,
                    artifact_sha256="f" * 64,
                )
                self._anchor.compare_and_swap(
                    expected=current,
                    replacement=replacement,
                )
                return replacement
        return current

    def compare_and_swap(
        self,
        *,
        expected: DigestCheckpoint | None,
        replacement: DigestCheckpoint,
    ) -> bool:
        return self._anchor.compare_and_swap(
            expected=expected,
            replacement=replacement,
        )


class DurableAdministrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.database = self.root / "admin-authorization.sqlite3"
        fixture = catalog_fixtures.ModelCatalogSigningTests()
        fixture.setUp()
        self.fixture = fixture
        self.now = fixture.now
        self.clock_value = [self.now]
        self.anchor = InMemoryDigestAnchor()
        self.writer = LabOnlyAllowingWriterAuthorizer()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def store(
        self,
        *,
        path: Path | None = None,
        secret: bytes = SECRET,
        anchor=None,
        writer_authorizer=None,
        capacity: int = MAX_EVENTS,
    ) -> DurableAdminAuthorizationStore:
        return DurableAdminAuthorizationStore(
            path or self.database,
            integrity_secret=secret,
            anchor=anchor or self.anchor,
            writer_authorizer=(
                self.writer if writer_authorizer is None else writer_authorizer
            ),
            clock=lambda: self.clock_value[0],
            capacity=capacity,
        )

    def catalog_material(self):
        raw_catalog = self.fixture.catalog_bytes()
        envelope = self.fixture.envelope(raw_catalog, catalog_sequence=1)
        return raw_catalog, envelope

    def assignment(
        self,
        *,
        assignment_id: str,
        subject: str,
        activity: str,
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> RoleAssignment:
        return RoleAssignment(
            assignment_id=assignment_id,
            subject=subject,
            role="CatalogCustody",
            role_version=1,
            activities=(activity,),
            assigned_by="primary-admin",
            issued_at=issued_at or self.now - timedelta(days=1),
            expires_at=expires_at or self.now + timedelta(days=30),
        )

    def provision_catalog_events(self, store: DurableAdminAuthorizationStore):
        raw_catalog, envelope = self.catalog_material()
        assignments: dict[str, RoleAssignment] = {}
        grant_receipts: list[AdminAuthorizationEventReceipt] = []
        for approval in envelope.approvals:
            assignment = self.assignment(
                assignment_id=approval.assignment_id,
                subject=approval.principal_id,
                activity=approval.activity,
            )
            assignments[assignment.assignment_id] = assignment
            grant_receipts.append(
                store.record_assignment_grant(
                    assignment,
                    assignment_receipt_sha256=(
                        approval.assignment_receipt_sha256
                    ),
                )
            )
        statement = envelope.statement
        signer = self.assignment(
            assignment_id=statement.signing_assignment_id,
            subject=statement.signing_principal_id,
            activity=statement.signing_activity,
        )
        assignments[signer.assignment_id] = signer
        grant_receipts.append(
            store.record_assignment_grant(
                signer,
                assignment_receipt_sha256=(
                    statement.signing_assignment_receipt_sha256
                ),
            )
        )
        approval_receipts = tuple(
            store.record_catalog_approval_authorization(approval)
            for approval in envelope.approvals
        )
        signing_receipt = store.record_catalog_signing_authorization(statement)
        return (
            raw_catalog,
            envelope,
            assignments,
            tuple(grant_receipts),
            approval_receipts,
            signing_receipt,
        )

    def test_exact_events_survive_restart_and_drive_catalog_verification(self) -> None:
        store = self.store()
        (
            raw_catalog,
            envelope,
            _,
            grants,
            approvals,
            signing,
        ) = self.provision_catalog_events(store)

        all_receipts = (*grants, *approvals, signing)
        self.assertEqual(list(range(1, 9)), [item.sequence for item in all_receipts])
        self.assertEqual(
            ["grant", "grant", "grant", "grant", "approval", "approval", "approval", "signing"],
            [item[0] for item in self.writer.calls],
        )
        self.assertIsNone(all_receipts[0].previous_event_sha256)
        for previous, current in zip(all_receipts, all_receipts[1:]):
            self.assertEqual(previous.event_sha256, current.previous_event_sha256)
        checkpoint = store.checkpoint
        self.assertIsNotNone(checkpoint)
        self.assertEqual(8, checkpoint.sequence)  # type: ignore[union-attr]
        self.assertEqual(signing.event_sha256, checkpoint.artifact_sha256)  # type: ignore[union-attr]
        store.close()

        reopened = self.store()
        verifier = reopened.authorization_verifier()
        self.assertIsInstance(verifier, DurableCatalogAuthorizationVerifier)
        verified = verify_signed_catalog(
            raw_catalog,
            envelope.canonical_bytes,
            expected_environment="production",
            expected_release_id="0.1.0",
            minimum_catalog_sequence=0,
            minimum_catalog_sha256=None,
            pack_verifications=self.fixture.pack_verifications(),
            signature_verifier=self.fixture.signature_verifier(),
            authorization_verifier=verifier,
            now=self.now,
        )
        self.assertEqual(hashlib.sha256(raw_catalog).hexdigest(), verified.catalog.digest)
        reopened.integrity_check()

        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual("wal", connection.execute("PRAGMA journal_mode").fetchone()[0])
            self.assertEqual(2, connection.execute("PRAGMA synchronous").fetchone()[0])

    def test_catalog_batch_performs_one_bounded_replay_per_verification(self) -> None:
        store = CountingReplayStore(
            self.root / "batch-replay.sqlite3",
            integrity_secret=SECRET,
            anchor=self.anchor,
            writer_authorizer=self.writer,
            clock=lambda: self.clock_value[0],
        )
        raw_catalog, envelope, *_ = self.provision_catalog_events(store)
        store.verified_state_loads = 0
        verifier = store.authorization_verifier()
        verified = verify_signed_catalog(
            raw_catalog,
            envelope.canonical_bytes,
            expected_environment="production",
            expected_release_id="0.1.0",
            minimum_catalog_sequence=0,
            minimum_catalog_sha256=None,
            pack_verifications=self.fixture.pack_verifications(),
            signature_verifier=self.fixture.signature_verifier(),
            authorization_verifier=verifier,
            now=self.now,
        )
        self.assertEqual(envelope.statement.digest, verified.statement.digest)
        self.assertEqual(1, store.verified_state_loads)

        oversized = (
            envelope.approvals[0],
        ) * (MAX_CATALOG_AUTHORIZATION_BATCH_APPROVALS + 1)
        self.assertFalse(
            verifier.catalog_is_authorized(
                oversized,
                envelope.statement,
                at=self.now,
            )
        )
        self.assertEqual(1, store.verified_state_loads)

        verify_signed_catalog(
            raw_catalog,
            envelope.canonical_bytes,
            expected_environment="production",
            expected_release_id="0.1.0",
            minimum_catalog_sequence=0,
            minimum_catalog_sha256=None,
            pack_verifications=self.fixture.pack_verifications(),
            signature_verifier=self.fixture.signature_verifier(),
            authorization_verifier=verifier,
            now=self.now,
        )
        self.assertEqual(2, store.verified_state_loads)

    def test_catalog_batch_reuse_invalidates_after_durable_revocation(self) -> None:
        store = CountingReplayStore(
            self.root / "batch-revocation.sqlite3",
            integrity_secret=SECRET,
            anchor=self.anchor,
            writer_authorizer=self.writer,
            clock=lambda: self.clock_value[0],
        )
        raw_catalog, envelope, assignments, *_ = self.provision_catalog_events(store)
        verifier = store.authorization_verifier()
        self.assertTrue(
            verifier.catalog_is_authorized(
                envelope.approvals,
                envelope.statement,
                at=self.now,
            )
        )
        signer = assignments[envelope.statement.signing_assignment_id]
        store.record_assignment_revoke(
            replace(signer, version=2, revoked_at=self.now),
            revocation_receipt_sha256="9" * 64,
            revoked_by="primary-admin",
        )
        store.verified_state_loads = 0
        with self.assertRaises(ModelCatalogVerificationDenied):
            verify_signed_catalog(
                raw_catalog,
                envelope.canonical_bytes,
                expected_environment="production",
                expected_release_id="0.1.0",
                minimum_catalog_sequence=0,
                minimum_catalog_sha256=None,
                pack_verifications=self.fixture.pack_verifications(),
                signature_verifier=self.fixture.signature_verifier(),
                authorization_verifier=verifier,
                now=self.now,
            )
        self.assertEqual(1, store.verified_state_loads)

    def test_catalog_batch_denies_anchor_advance_during_snapshot(self) -> None:
        anchor = AdvancingOnSecondReadAnchor()
        store = CountingReplayStore(
            self.root / "batch-anchor-race.sqlite3",
            integrity_secret=SECRET,
            anchor=anchor,
            writer_authorizer=self.writer,
            clock=lambda: self.clock_value[0],
        )
        _, envelope, *_ = self.provision_catalog_events(store)
        store.verified_state_loads = 0
        anchor.arm()
        self.assertFalse(
            store.authorization_verifier().catalog_is_authorized(
                envelope.approvals,
                envelope.statement,
                at=self.now,
            )
        )
        self.assertEqual(1, store.verified_state_loads)

    def test_rows_are_canonical_ascii_and_schema_is_closed(self) -> None:
        store = self.store()
        assignment = self.assignment(
            assignment_id="assignment-1",
            subject="person-1",
            activity="model-catalog.approve.release",
        )
        receipt = store.record_assignment_grant(
            assignment,
            assignment_receipt_sha256="a" * 64,
        )
        with closing(sqlite3.connect(self.database)) as connection:
            raw = connection.execute(
                "SELECT event_json FROM admin_authorization_events WHERE sequence=1"
            ).fetchone()[0]
        document = json.loads(raw)
        self.assertEqual(raw.encode("ascii"), canonical_admin_event_bytes(document))
        self.assertEqual(receipt.event_sha256, hashlib.sha256(raw.encode("ascii")).hexdigest())

        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas"
                / "admin-authorization-event.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
        self.assertEqual(
            "https://luma-os.invalid/schemas/admin-authorization-event.schema.json",
            schema["$id"],
        )
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual("^[!-~]+$", schema["$defs"]["identifier"]["pattern"])
        self.assertEqual(
            "\\*",
            schema["$defs"]["identifier"]["not"]["pattern"],
        )
        self.assertEqual(128, schema["$defs"]["assignment"]["properties"]["activities"]["maxItems"])
        self.assertEqual(MAX_ACTIVITIES_PER_ASSIGNMENT, 128)

    def test_wrong_secret_and_row_tampering_fail_closed(self) -> None:
        store = self.store()
        assignment = self.assignment(
            assignment_id="assignment-1",
            subject="person-1",
            activity="model-catalog.approve.release",
        )
        store.record_assignment_grant(
            assignment,
            assignment_receipt_sha256="a" * 64,
        )
        store.close()
        with self.assertRaises(DurableAdministrationIntegrityError):
            self.store(secret=b"x" * 32)

        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "UPDATE admin_authorization_events SET auth_tag=? WHERE sequence=1",
                ("f" * 64,),
            )
            connection.commit()
        with self.assertRaises(DurableAdministrationIntegrityError):
            self.store()

    def test_sqlite_schema_rejects_every_unexpected_object_kind(self) -> None:
        cases = {
            "table": "CREATE TABLE unexpected_table(value TEXT)",
            "view": (
                "CREATE VIEW unexpected_view AS "
                "SELECT sequence FROM admin_authorization_events"
            ),
            "trigger": (
                "CREATE TRIGGER unexpected_trigger AFTER INSERT "
                "ON admin_authorization_events BEGIN SELECT 1; END"
            ),
            "index": (
                "CREATE INDEX unexpected_index "
                "ON admin_authorization_events(recorded_at)"
            ),
        }
        for object_kind, statement in cases.items():
            with self.subTest(object_kind=object_kind):
                path = self.root / f"unexpected-{object_kind}.sqlite3"
                anchor = InMemoryDigestAnchor()
                self.store(path=path, anchor=anchor).close()
                with closing(sqlite3.connect(path)) as connection:
                    connection.execute(statement)
                    connection.commit()
                with self.assertRaises(DurableAdministrationIntegrityError):
                    self.store(path=path, anchor=anchor)

    def test_trigger_mutation_after_initial_verification_is_never_anchored(self) -> None:
        class TriggerMutatingStore(DurableAdminAuthorizationStore):
            def __init__(self, *args, **kwargs) -> None:
                self.load_count = 0
                super().__init__(*args, **kwargs)

            def _load_verified_state(self, connection):
                state = super()._load_verified_state(connection)
                self.load_count += 1
                if self.load_count == 2:
                    connection.execute(
                        "CREATE TEMP TRIGGER mutate_committed_admin_event "
                        "AFTER INSERT ON main.admin_authorization_events BEGIN "
                        "UPDATE admin_authorization_events "
                        "SET event_type='assignment-revoke' "
                        "WHERE sequence=NEW.sequence; END"
                    )
                return state

        anchor = InMemoryDigestAnchor()
        store = TriggerMutatingStore(
            self.root / "trigger-mutation.sqlite3",
            integrity_secret=SECRET,
            anchor=anchor,
            writer_authorizer=self.writer,
            clock=lambda: self.clock_value[0],
        )
        assignment = self.assignment(
            assignment_id="assignment-1",
            subject="person-1",
            activity="model-catalog.approve.release",
        )
        with self.assertRaises(DurableAdministrationReconciliationRequired):
            store.record_assignment_grant(
                assignment,
                assignment_receipt_sha256="a" * 64,
            )
        self.assertIsNone(anchor.read(ADMIN_AUTHORIZATION_ANCHOR_NAMESPACE))
        with self.assertRaises(DurableAdministrationReconciliationRequired):
            store.integrity_check()
        with closing(sqlite3.connect(store.path)) as connection:
            event_type = connection.execute(
                "SELECT event_type FROM admin_authorization_events WHERE sequence=1"
            ).fetchone()[0]
        self.assertEqual("assignment-revoke", event_type)

    def test_deletion_gap_and_anchor_rollback_are_detected(self) -> None:
        store = self.store()
        first = self.assignment(
            assignment_id="assignment-1",
            subject="person-1",
            activity="model-catalog.approve.release",
        )
        second = self.assignment(
            assignment_id="assignment-2",
            subject="person-2",
            activity="model-catalog.approve.security",
        )
        store.record_assignment_grant(first, assignment_receipt_sha256="a" * 64)
        store.record_assignment_grant(second, assignment_receipt_sha256="b" * 64)
        store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DELETE FROM admin_authorization_events WHERE sequence=1")
            connection.commit()
        with self.assertRaises(DurableAdministrationIntegrityError):
            self.store()

        rolled_back = self.root / "rolled-back.sqlite3"
        other_anchor = InMemoryDigestAnchor()
        other = self.store(path=rolled_back, anchor=other_anchor)
        other.record_assignment_grant(first, assignment_receipt_sha256="a" * 64)
        other.close()
        with closing(sqlite3.connect(rolled_back)) as connection:
            connection.execute("DELETE FROM admin_authorization_events")
            connection.commit()
        with self.assertRaises(DurableAdministrationReconciliationRequired):
            self.store(path=rolled_back, anchor=other_anchor)

    def test_exact_approval_and_signing_fields_are_not_substitutable(self) -> None:
        store = self.store()
        _, envelope, _, _, _, _ = self.provision_catalog_events(store)
        verifier = store.authorization_verifier()
        approval = envelope.approvals[0]
        self.assertTrue(verifier.approval_is_authorized(approval, at=self.now))
        self.assertTrue(verifier.signer_is_authorized(envelope.statement, at=self.now))

        approval_cases = (
            {"principal_id": "other-person"},
            {"activity": "model-catalog.approve.release"},
            {"assignment_id": "other-assignment"},
            {"assignment_receipt_sha256": "f" * 64},
            {"approval_decision_receipt_sha256": "f" * 64},
            {"release_request_sha256": "f" * 64},
            {"catalog_sha256": "f" * 64},
            {"release_id": "0.2.0"},
        )
        for changes in approval_cases:
            with self.subTest(changes=changes):
                changed = replace(approval, **changes)
                self.assertFalse(
                    verifier.approval_is_authorized(changed, at=self.now)
                )

        statement_cases = (
            {"signing_principal_id": "other-person"},
            {"signing_assignment_id": "other-assignment"},
            {"signing_assignment_receipt_sha256": "f" * 64},
            {"release_id": "0.2.0"},
            {"catalog_sha256": "f" * 64},
        )
        for changes in statement_cases:
            with self.subTest(changes=changes):
                try:
                    changed = replace(envelope.statement, **changes)
                except Exception:
                    continue
                self.assertFalse(
                    verifier.signer_is_authorized(changed, at=self.now)
                )

    def test_expired_or_revoked_assignment_fails_current_authorization(self) -> None:
        store = self.store()
        _, envelope, assignments, _, _, _ = self.provision_catalog_events(store)
        verifier = store.authorization_verifier()
        signer = assignments[envelope.statement.signing_assignment_id]
        self.assertTrue(
            verifier.signer_is_authorized(envelope.statement, at=self.now)
        )
        self.assertFalse(
            verifier.signer_is_authorized(
                envelope.statement,
                at=signer.expires_at,
            )
        )

        revoked = replace(signer, version=2, revoked_at=self.now)
        store.record_assignment_revoke(
            revoked,
            revocation_receipt_sha256="9" * 64,
            revoked_by="primary-admin",
        )
        self.assertTrue(
            verifier.signer_is_authorized(
                envelope.statement,
                at=envelope.statement.signed_at,
            )
        )
        self.assertFalse(
            verifier.signer_is_authorized(envelope.statement, at=self.now)
        )
        with self.assertRaises(ModelCatalogVerificationDenied):
            verify_signed_catalog(
                self.fixture.catalog_bytes(),
                envelope.canonical_bytes,
                expected_environment="production",
                expected_release_id="0.1.0",
                minimum_catalog_sequence=0,
                minimum_catalog_sha256=None,
                pack_verifications=self.fixture.pack_verifications(),
                signature_verifier=self.fixture.signature_verifier(),
                authorization_verifier=verifier,
                now=self.now,
            )

    def test_unauthorized_decision_is_not_appended(self) -> None:
        store = self.store()
        _, envelope = self.catalog_material()
        approval = envelope.approvals[0]
        before = store.checkpoint
        with self.assertRaises(DurableAdministrationDenied):
            store.record_catalog_approval_authorization(approval)
        self.assertEqual(before, store.checkpoint)

    def test_writer_authorizer_denial_wrong_actor_and_exception_fail_closed(self) -> None:
        assignment = self.assignment(
            assignment_id="assignment-1",
            subject="person-1",
            activity="model-catalog.approve.release",
        )

        class DenyGrant(LabOnlyAllowingWriterAuthorizer):
            def assignment_grant_is_authorized(self, *args, **kwargs) -> bool:
                del args, kwargs
                return False

        denied_path = self.root / "writer-denied.sqlite3"
        denied_anchor = InMemoryDigestAnchor()
        denied = self.store(
            path=denied_path,
            anchor=denied_anchor,
            writer_authorizer=DenyGrant(),
        )
        with self.assertRaises(DurableAdministrationDenied):
            denied.record_assignment_grant(
                assignment,
                assignment_receipt_sha256="a" * 64,
            )
        self.assertIsNone(denied.checkpoint)

        class RaisingGrant(LabOnlyAllowingWriterAuthorizer):
            def assignment_grant_is_authorized(self, *args, **kwargs) -> bool:
                del args, kwargs
                raise OSError("Admin service unavailable")

        error_path = self.root / "writer-error.sqlite3"
        error_store = self.store(
            path=error_path,
            anchor=InMemoryDigestAnchor(),
            writer_authorizer=RaisingGrant(),
        )
        with self.assertRaises(DurableAdministrationDenied):
            error_store.record_assignment_grant(
                assignment,
                assignment_receipt_sha256="a" * 64,
            )
        self.assertIsNone(error_store.checkpoint)

        class ExactRevokeActor(LabOnlyAllowingWriterAuthorizer):
            def assignment_revoke_is_authorized(
                self,
                assignment: RoleAssignment,
                *,
                revocation_receipt_sha256: str,
                revoked_by: str,
                at: datetime,
            ) -> bool:
                del assignment, revocation_receipt_sha256, at
                return revoked_by == "trusted-admin-service"

        revoke_path = self.root / "writer-revoke.sqlite3"
        revoke_store = self.store(
            path=revoke_path,
            anchor=InMemoryDigestAnchor(),
            writer_authorizer=ExactRevokeActor(),
        )
        revoke_store.record_assignment_grant(
            assignment,
            assignment_receipt_sha256="a" * 64,
        )
        revoked = replace(assignment, version=2, revoked_at=self.now)
        checkpoint = revoke_store.checkpoint
        with self.assertRaises(DurableAdministrationDenied):
            revoke_store.record_assignment_revoke(
                revoked,
                revocation_receipt_sha256="b" * 64,
                revoked_by="claimed-admin",
            )
        self.assertEqual(checkpoint, revoke_store.checkpoint)

        class DenyApproval(LabOnlyAllowingWriterAuthorizer):
            def catalog_approval_is_authorized(self, *args, **kwargs) -> bool:
                del args, kwargs
                return False

        approval_path = self.root / "writer-approval-denied.sqlite3"
        approval_store = self.store(
            path=approval_path,
            anchor=InMemoryDigestAnchor(),
            writer_authorizer=DenyApproval(),
        )
        _, envelope = self.catalog_material()
        approval = envelope.approvals[0]
        approval_store.record_assignment_grant(
            self.assignment(
                assignment_id=approval.assignment_id,
                subject=approval.principal_id,
                activity=approval.activity,
            ),
            assignment_receipt_sha256=approval.assignment_receipt_sha256,
        )
        checkpoint = approval_store.checkpoint
        with self.assertRaises(DurableAdministrationDenied):
            approval_store.record_catalog_approval_authorization(approval)
        self.assertEqual(checkpoint, approval_store.checkpoint)

        class RaisingSigning(LabOnlyAllowingWriterAuthorizer):
            def catalog_signing_is_authorized(self, *args, **kwargs) -> bool:
                del args, kwargs
                raise OSError("Admin signing service unavailable")

        signing_path = self.root / "writer-signing-error.sqlite3"
        signing_store = self.store(
            path=signing_path,
            anchor=InMemoryDigestAnchor(),
            writer_authorizer=RaisingSigning(),
        )
        statement = envelope.statement
        signing_store.record_assignment_grant(
            self.assignment(
                assignment_id=statement.signing_assignment_id,
                subject=statement.signing_principal_id,
                activity=statement.signing_activity,
            ),
            assignment_receipt_sha256=(
                statement.signing_assignment_receipt_sha256
            ),
        )
        checkpoint = signing_store.checkpoint
        with self.assertRaises(DurableAdministrationDenied):
            signing_store.record_catalog_signing_authorization(statement)
        self.assertEqual(checkpoint, signing_store.checkpoint)

    def test_clock_rollback_fails_integrity_and_adapter_closed(self) -> None:
        store = self.store()
        assignment = self.assignment(
            assignment_id="assignment-1",
            subject="person-1",
            activity="model-catalog.approve.release",
        )
        store.record_assignment_grant(
            assignment,
            assignment_receipt_sha256="a" * 64,
        )
        self.clock_value[0] = self.now - timedelta(seconds=1)
        with self.assertRaises(DurableAdministrationClockRollback):
            store.integrity_check()
        self.assertFalse(
            store.authorization_verifier().approval_is_authorized(
                self.catalog_material()[1].approvals[0],
                at=self.now,
            )
        )
        with self.assertRaises(DurableAdministrationClockRollback):
            self.store()

    def test_sqlite_external_cas_window_is_typed_and_never_authorizes(self) -> None:
        anchor = RejectingAnchor()
        store = self.store(anchor=anchor)
        assignment = self.assignment(
            assignment_id="assignment-1",
            subject="person-1",
            activity="model-catalog.approve.release",
        )
        with self.assertRaises(DurableAdministrationReconciliationRequired):
            store.record_assignment_grant(
                assignment,
                assignment_receipt_sha256="a" * 64,
            )
        self.assertEqual(1, anchor.cas_calls)
        with self.assertRaises(DurableAdministrationReconciliationRequired):
            store.integrity_check()
        self.assertFalse(
            store.authorization_verifier().approval_is_authorized(
                self.catalog_material()[1].approvals[0],
                at=self.now,
            )
        )
        with self.assertRaises(DurableAdministrationReconciliationRequired):
            self.store(anchor=anchor)

    def test_anchor_outage_invalid_value_and_anchor_ahead_fail_closed(self) -> None:
        anchor = RejectingAnchor()
        store = self.store(anchor=anchor)
        anchor.fail_reads = True
        with self.assertRaises(DurableAdministrationAnchorConflict):
            store.integrity_check()
        anchor.fail_reads = False
        anchor.invalid_reads = True
        with self.assertRaises(DurableAdministrationAnchorConflict):
            store.integrity_check()

        ahead_path = self.root / "anchor-ahead.sqlite3"
        ahead_anchor = InMemoryDigestAnchor()
        checkpoint = DigestCheckpoint(
            ADMIN_AUTHORIZATION_ANCHOR_NAMESPACE,
            1,
            1,
            "a" * 64,
        )
        self.assertTrue(
            ahead_anchor.compare_and_swap(expected=None, replacement=checkpoint)
        )
        with self.assertRaises(DurableAdministrationReconciliationRequired):
            self.store(path=ahead_path, anchor=ahead_anchor)

    def test_capacity_timestamp_secret_and_path_bounds_are_strict(self) -> None:
        with self.assertRaises(DurableAdministrationValidationError):
            DurableAdminAuthorizationStore(
                self.database,
                integrity_secret=b"short",
                anchor=self.anchor,
                writer_authorizer=self.writer,
            )
        with self.assertRaises(DurableAdministrationValidationError):
            DurableAdminAuthorizationStore(
                Path("relative.sqlite3"),
                integrity_secret=SECRET,
                anchor=self.anchor,
                writer_authorizer=self.writer,
            )
        with self.assertRaises(DurableAdministrationValidationError):
            DurableAdminAuthorizationStore(
                self.database,
                integrity_secret=SECRET,
                anchor=self.anchor,
                writer_authorizer=object(),  # type: ignore[arg-type]
            )
        store = self.store(capacity=1)
        first = self.assignment(
            assignment_id="assignment-1",
            subject="person-1",
            activity="model-catalog.approve.release",
        )
        second = self.assignment(
            assignment_id="assignment-2",
            subject="person-2",
            activity="model-catalog.approve.security",
        )
        store.record_assignment_grant(first, assignment_receipt_sha256="a" * 64)
        with self.assertRaises(DurableAdministrationCapacityExceeded):
            store.record_assignment_grant(second, assignment_receipt_sha256="b" * 64)

        microsecond = replace(
            second,
            issued_at=second.issued_at.replace(microsecond=1),
        )
        with self.assertRaises(DurableAdministrationValidationError):
            store.record_assignment_grant(
                microsecond,
                assignment_receipt_sha256="c" * 64,
            )

    def test_closed_store_adapter_fails_closed(self) -> None:
        store = self.store()
        verifier = store.authorization_verifier()
        store.close()
        approval = self.catalog_material()[1].approvals[0]
        self.assertFalse(verifier.approval_is_authorized(approval, at=self.now))


if __name__ == "__main__":
    unittest.main()
