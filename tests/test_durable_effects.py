from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.durable_effects import (  # noqa: E402
    DurableCapacityExceeded,
    DurableClockRollback,
    DurableEffectConflict,
    DurableEffectInProgress,
    DurableEffectUnknown,
    DurableStoreUnavailable,
    DurableValidationError,
    EffectAdapterReconciliation,
    EffectLedgerState,
    SQLiteIdempotentEffectExecutor,
    SQLiteRequestJournal,
    canonical_effect_document,
)
from luma_os.privileged_helper import (  # noqa: E402
    ActivateReleaseParameters,
    AuthenticatedPeer,
    AuthorizedEffect,
    AuthorityDecision,
    BoundDevice,
    ConfinementAttestation,
    ConfinementMode,
    DeviceCapability,
    DeviceType,
    EffectReceipt,
    EffectResult,
    ExecutorCompletion,
    GeneratedCodeKind,
    HelperAction,
    HelperEffectNotApplied,
    HelperReplayConflict,
    JournalState,
    PeerTransport,
    ReconciliationState,
    RecoverySlot,
    RecoveryBootParameters,
    AssignDeviceParameters,
)


KEY = b"durable-effects-test-integrity-key-v1"


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value
        self.lock = threading.Lock()

    def __call__(self) -> datetime:
        with self.lock:
            return self.value

    def advance(self, delta: timedelta) -> None:
        with self.lock:
            self.value += delta

    def rewind(self, delta: timedelta) -> None:
        with self.lock:
            self.value -= delta


class RecordingAdapter:
    def __init__(self, clock: MutableClock) -> None:
        self.clock = clock
        self.calls = 0
        self.effects = []
        self.lock = threading.Lock()
        self.apply_error = False
        self.reconciliation = EffectAdapterReconciliation(ReconciliationState.UNKNOWN)
        self.entered: threading.Event | None = None
        self.release: threading.Event | None = None

    def apply(self, effect):
        with self.lock:
            self.calls += 1
            self.effects.append(effect)
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            self.release.wait(timeout=5)
        if self.apply_error:
            raise RuntimeError("simulated ambiguous adapter failure")
        return EffectResult("completed", "e" * 64)

    def reconcile(self, effect):
        return self.reconciliation


class DurableEffectsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.database = self.root / "privileged-effects.sqlite3"
        self.now = datetime(2026, 9, 22, 12, tzinfo=UTC)
        self.clock = MutableClock(self.now)
        self.adapter = RecordingAdapter(self.clock)

    def journal(self, **changes) -> SQLiteRequestJournal:
        options = {
            "integrity_key": KEY,
            "capacity": 32,
            "retention": timedelta(hours=1),
            "clock": self.clock,
            "busy_timeout": timedelta(milliseconds=100),
        }
        options.update(changes)
        return SQLiteRequestJournal(self.database, **options)

    def executor(self, **changes) -> SQLiteIdempotentEffectExecutor:
        options = {
            "integrity_key": KEY,
            "adapters": {HelperAction.ACTIVATE_STAGED_RELEASE: self.adapter},
            "dispatch_validator": lambda effect, observed_at: True,
            "capacity": 32,
            "preparation_lease": timedelta(seconds=5),
            "clock": self.clock,
            "busy_timeout": timedelta(milliseconds=100),
        }
        options.update(changes)
        return SQLiteIdempotentEffectExecutor(self.database, **options)

    def effect(
        self,
        request_id: str = "request-1",
        *,
        request_sha256: str = "1" * 64,
        idempotency_key: str | None = None,
        release_sha256: str = "3" * 64,
        action: HelperAction = HelperAction.ACTIVATE_STAGED_RELEASE,
    ) -> AuthorizedEffect:
        peer = AuthenticatedPeer(
            "worker-service",
            PeerTransport.UNIX_PEER_CREDENTIALS,
            "uid:1001;gid:1001;pid:4455",
            "session-1",
            "4" * 64,
            True,
        )
        confinement = ConfinementAttestation(
            "attestation-1",
            request_sha256,
            peer.identity_sha256,
            action,
            None,
            None,
            ConfinementMode.KVM_MICROVM,
            "profile-1",
            3,
            "5" * 64,
            True,
            "qualification-1",
            self.now - timedelta(seconds=1),
            self.now + timedelta(minutes=5),
            "attestation-key-1",
            b"a" * 64,
        )
        capability_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "confinement_attestation_sha256": confinement.digest,
                    "device_capability_sha256": None,
                    "driver_certificate_sha256": None,
                    "request_sha256": request_sha256,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        authority = AuthorityDecision(
            "decision-1",
            True,
            "grant-1",
            7,
            peer.principal,
            peer.identity_sha256,
            action,
            request_sha256,
            capability_sha256,
            self.now + timedelta(minutes=5),
            False,
        )
        parameters = (
            ActivateReleaseParameters(release_sha256)
            if action is HelperAction.ACTIVATE_STAGED_RELEASE
            else RecoveryBootParameters(slot=RecoverySlot.A)
        )
        return AuthorizedEffect(
            request_id,
            request_sha256,
            idempotency_key
            or hashlib.sha256(
                f"luma-helper-v1:{request_id}:{request_sha256}".encode("ascii")
            ).hexdigest(),
            peer.principal,
            action,
            parameters,
            peer,
            authority,
            confinement,
            None,
            None,
        )

    def receipt(self, request_id="request-1", request_sha256="1" * 64):
        return EffectReceipt(
            request_id,
            request_sha256,
            hashlib.sha256(
                f"luma-helper-v1:{request_id}:{request_sha256}".encode("ascii")
            ).hexdigest(),
            "worker-service",
            HelperAction.ACTIVATE_STAGED_RELEASE,
            "decision-1",
            7,
            "6" * 64,
            "completed",
            "e" * 64,
            self.clock(),
        )

    def device_effect(
        self,
        token: str,
        *,
        request_id: str = "device-request",
        request_sha256: str = "7" * 64,
    ) -> AuthorizedEffect:
        peer = AuthenticatedPeer(
            "worker-service",
            PeerTransport.UNIX_PEER_CREDENTIALS,
            "uid:1001;gid:1001;pid:4455",
            "session-1",
            "4" * 64,
            True,
        )
        action = HelperAction.ASSIGN_MODEL_DEVICE
        confinement = ConfinementAttestation(
            "attestation-device",
            request_sha256,
            peer.identity_sha256,
            action,
            "worker-7",
            None,
            ConfinementMode.KVM_MICROVM,
            "profile-1",
            3,
            "5" * 64,
            True,
            "qualification-1",
            self.now - timedelta(seconds=1),
            self.now + timedelta(minutes=5),
            "attestation-key-1",
            b"a" * 64,
        )
        host = "8" * 64
        stable = hashlib.sha256(
            json.dumps(
                {
                    "device_type": DeviceType.DRM_RENDER.value,
                    "host_identity_sha256": host,
                    "major": 226,
                    "minor": 128,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        capability = DeviceCapability(
            "device-capability-1",
            request_sha256,
            peer.identity_sha256,
            "assignment-4",
            3,
            "worker-7",
            True,
            (BoundDevice(DeviceType.DRM_RENDER, 226, 128, host, stable, token),),
            self.now - timedelta(seconds=1),
            self.now + timedelta(minutes=5),
        )
        certificate_sha256 = "9" * 64
        capability_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "confinement_attestation_sha256": confinement.digest,
                    "device_capability_sha256": capability.digest,
                    "driver_certificate_sha256": certificate_sha256,
                    "request_sha256": request_sha256,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        authority = AuthorityDecision(
            "decision-device",
            True,
            "grant-1",
            7,
            peer.principal,
            peer.identity_sha256,
            action,
            request_sha256,
            capability_sha256,
            self.now + timedelta(minutes=5),
            False,
        )
        return AuthorizedEffect(
            request_id,
            request_sha256,
            hashlib.sha256(
                f"luma-helper-v1:{request_id}:{request_sha256}".encode("ascii")
            ).hexdigest(),
            peer.principal,
            action,
            AssignDeviceParameters("worker-7", "assignment-4"),
            peer,
            authority,
            confinement,
            capability,
            certificate_sha256,
        )

    def test_journal_persists_replay_and_immutable_completion(self) -> None:
        journal = self.journal()
        reservation = journal.reserve(
            "request-1",
            "1" * 64,
            "owner-token-0001",
            self.clock(),
            self.clock() + timedelta(seconds=30),
        )
        self.assertTrue(reservation.acquired)
        self.assertEqual(JournalState.PENDING, reservation.record.state)

        reopened = self.journal()
        duplicate = reopened.reserve(
            "request-1",
            "1" * 64,
            "owner-token-0002",
            self.clock(),
            self.clock() + timedelta(seconds=30),
        )
        self.assertFalse(duplicate.acquired)
        receipt = self.receipt()
        reopened.complete("request-1", "1" * 64, "owner-token-0001", 1, receipt)

        replay = self.journal().reserve(
            "request-1",
            "1" * 64,
            "owner-token-0003",
            self.clock(),
            self.clock() + timedelta(seconds=30),
        )
        self.assertFalse(replay.acquired)
        self.assertEqual(receipt, replay.record.receipt)
        self.journal().complete("request-1", "1" * 64, None, 1, receipt)

        changed = self.receipt()
        object.__setattr__(changed, "evidence_sha256", "f" * 64)
        with self.assertRaises(DurableStoreUnavailable):
            self.journal().complete("request-1", "1" * 64, None, 1, changed)

    def test_journal_digest_conflict_is_permanent(self) -> None:
        journal = self.journal()
        journal.reserve(
            "conflict", "1" * 64, "owner-token-0001", self.clock(),
            self.clock() + timedelta(seconds=10),
        )
        with self.assertRaises(HelperReplayConflict):
            self.journal().reserve(
                "conflict", "9" * 64, "owner-token-0002", self.clock(),
                self.clock() + timedelta(seconds=10),
            )

    def test_journal_expired_lease_fences_reused_owner_by_generation(self) -> None:
        journal = self.journal()
        journal.reserve(
            "takeover", "1" * 64, "owner-token-reused", self.clock(),
            self.clock() + timedelta(seconds=2),
        )
        self.clock.advance(timedelta(seconds=3))
        takeover = self.journal().reserve(
            "takeover", "1" * 64, "owner-token-reused", self.clock(),
            self.clock() + timedelta(seconds=10),
        )
        self.assertTrue(takeover.acquired)
        self.assertEqual(2, takeover.record.generation)
        with self.assertRaises(DurableStoreUnavailable):
            journal.complete(
                "takeover", "1" * 64, "owner-token-reused", 1,
                self.receipt("takeover"),
            )
        with self.assertRaises(DurableStoreUnavailable):
            journal.mark_failed_unknown(
                "takeover", "1" * 64, "owner-token-reused", 1
            )
        self.journal().complete(
            "takeover", "1" * 64, "owner-token-reused", 2, self.receipt("takeover")
        )

    def test_failed_unknown_is_durable_and_only_reconciliation_can_complete(self) -> None:
        journal = self.journal()
        journal.reserve(
            "unknown", "1" * 64, "owner-token-0001", self.clock(),
            self.clock() + timedelta(seconds=10),
        )
        journal.mark_failed_unknown("unknown", "1" * 64, "owner-token-0001", 1)
        record = self.journal().reserve(
            "unknown", "1" * 64, "owner-token-0002", self.clock(),
            self.clock() + timedelta(seconds=10),
        ).record
        self.assertEqual(JournalState.FAILED_UNKNOWN, record.state)
        with self.assertRaises(DurableStoreUnavailable):
            self.journal().complete(
                "unknown", "1" * 64, "owner-token-0002", 1, self.receipt("unknown")
            )
        self.journal().complete("unknown", "1" * 64, None, 1, self.receipt("unknown"))

    def test_capacity_and_clock_rollback_fail_closed(self) -> None:
        journal = self.journal(capacity=1)
        journal.reserve(
            "first", "1" * 64, "owner-token-0001", self.clock(),
            self.clock() + timedelta(seconds=10),
        )
        with self.assertRaises(DurableCapacityExceeded):
            journal.reserve(
                "second", "2" * 64, "owner-token-0002", self.clock(),
                self.clock() + timedelta(seconds=10),
            )
        self.clock.rewind(timedelta(seconds=1))
        with self.assertRaises(DurableClockRollback):
            journal.reserve(
                "first", "1" * 64, "owner-token-0003", self.clock(),
                self.clock() + timedelta(seconds=10),
            )

    def test_store_rejects_relative_link_newer_schema_busy_and_tampering(self) -> None:
        with self.assertRaises(DurableValidationError):
            SQLiteRequestJournal(
                "relative.sqlite3", integrity_key=KEY, capacity=1,
                retention=timedelta(minutes=1),
            )
        link = self.root / "database-link.sqlite3"
        try:
            link.symlink_to(self.database)
        except (OSError, NotImplementedError):
            link = None
        if link is not None:
            with self.assertRaises(DurableValidationError):
                SQLiteRequestJournal(
                    link, integrity_key=KEY, capacity=1,
                    retention=timedelta(minutes=1),
                )

        journal = self.journal()
        journal.reserve(
            "tamper", "1" * 64, "owner-token-0001", self.clock(),
            self.clock() + timedelta(seconds=10),
        )
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "UPDATE request_journal SET request_sha256=? WHERE request_id='tamper'",
                ("9" * 64,),
            )
            connection.commit()
        with self.assertRaises(DurableStoreUnavailable):
            journal.integrity_check()

        other_database = self.root / "newer.sqlite3"
        newer = SQLiteRequestJournal(
            other_database, integrity_key=KEY, capacity=2,
            retention=timedelta(minutes=1), clock=self.clock,
        )
        newer.close()
        with closing(sqlite3.connect(other_database)) as connection:
            connection.execute("PRAGMA user_version = 99")
            connection.commit()
        with self.assertRaises(DurableStoreUnavailable):
            SQLiteRequestJournal(
                other_database, integrity_key=KEY, capacity=2,
                retention=timedelta(minutes=1), clock=self.clock,
            )

        busy_database = self.root / "busy.sqlite3"
        busy = SQLiteRequestJournal(
            busy_database, integrity_key=KEY, capacity=2,
            retention=timedelta(minutes=1), clock=self.clock,
            busy_timeout=timedelta(milliseconds=10),
        )
        locker = sqlite3.connect(busy_database, isolation_level=None)
        try:
            locker.execute("BEGIN IMMEDIATE")
            with self.assertRaises(DurableStoreUnavailable):
                busy.reserve(
                    "busy", "1" * 64, "owner-token-0001", self.clock(),
                    self.clock() + timedelta(seconds=10),
                )
        finally:
            locker.execute("ROLLBACK")
            locker.close()

    def test_executor_persists_completion_and_replays_without_adapter(self) -> None:
        effect = self.effect()
        first = self.executor().execute(effect)
        self.assertEqual("completed", first.result.result_code)
        self.assertEqual(1, self.adapter.calls)

        reopened_adapter = RecordingAdapter(self.clock)
        reopened = self.executor(
            adapters={HelperAction.ACTIVATE_STAGED_RELEASE: reopened_adapter}
        )
        second = reopened.execute(effect)
        self.assertEqual(first, second)
        self.assertEqual(0, reopened_adapter.calls)
        outcome = reopened.reconcile(effect.idempotency_key, effect.request_sha256)
        self.assertEqual(ReconciliationState.COMPLETED, outcome.state)
        self.assertIsNotNone(outcome.completion)

    def test_executor_rejects_conflicting_effect_and_unregistered_action(self) -> None:
        executor = self.executor()
        effect = self.effect()
        document = executor._effect_document(effect)
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
        executor._prepare(
            effect,
            encoded.decode("ascii"),
            hashlib.sha256(encoded).hexdigest(),
            "owner-token-conflict",
        )
        changed = self.effect(release_sha256="8" * 64)
        with self.assertRaises(DurableEffectConflict):
            executor.execute(changed)

        recovery = self.effect(
            "recovery-request",
            request_sha256="7" * 64,
            action=HelperAction.SET_RECOVERY_BOOT_ONCE,
        )
        with self.assertRaises(HelperEffectNotApplied):
            executor.execute(recovery)
        self.assertFalse(any(hasattr(executor, name) for name in ("command", "argv", "shell")))

    def test_prepared_restart_can_apply_but_applying_failure_never_redispatches(self) -> None:
        effect = self.effect()
        executor = self.executor(owner_token_factory=lambda: "owner-token-first")
        document = canonical_effect_document(effect)
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
        stale_generation, _ = executor._prepare(
            effect,
            encoded.decode("ascii"),
            hashlib.sha256(encoded).hexdigest(),
            "owner-token-first",
        )
        refreshed_confinement = replace(
            effect.confinement,
            attestation_id="attestation-after-restart",
            attested_at=self.now,
            valid_until=self.now + timedelta(minutes=5),
            signature=b"b" * 64,
        )
        refreshed_capability_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "confinement_attestation_sha256": refreshed_confinement.digest,
                    "device_capability_sha256": None,
                    "driver_certificate_sha256": None,
                    "request_sha256": effect.request_sha256,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        refreshed = replace(
            effect,
            confinement=refreshed_confinement,
            authority=replace(
                effect.authority,
                decision_id="decision-after-restart",
                capability_sha256=refreshed_capability_sha256,
            ),
        )
        result = self.executor(owner_token_factory=lambda: "owner-token-second").execute(
            refreshed
        )
        self.assertEqual("completed", result.result.result_code)
        self.assertEqual("decision-after-restart", result.decision_id)
        self.assertEqual(1, self.adapter.calls)
        with self.assertRaises(DurableEffectInProgress):
            executor._begin_apply(
                effect.idempotency_key,
                effect.request_sha256,
                "owner-token-first",
                stale_generation,
                self.clock(),
            )

        failing_effect = self.effect(
            "ambiguous", request_sha256="7" * 64
        )
        self.adapter.apply_error = True
        with self.assertRaises(DurableEffectUnknown):
            self.executor().execute(failing_effect)
        self.adapter.apply_error = False
        with self.assertRaises(DurableEffectUnknown):
            self.executor().execute(failing_effect)
        self.assertEqual(2, self.adapter.calls)  # one prior success plus one ambiguous call

    def test_preapply_clock_race_is_safely_retryable(self) -> None:
        effect = self.effect()
        executor = self.executor(owner_token_factory=lambda: "owner-before-clock-race")
        document = executor._effect_document(effect)
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":"))
        generation, _ = executor._prepare(
            effect,
            encoded,
            hashlib.sha256(encoded.encode("ascii")).hexdigest(),
            "owner-before-clock-race",
        )
        stale_validation_at = self.clock()

        self.clock.advance(timedelta(seconds=1))
        second_writer = self.journal()
        second_writer.reserve(
            "concurrent-request",
            "b" * 64,
            "concurrent-owner-token",
            self.clock(),
            self.clock() + timedelta(seconds=10),
        )

        with self.assertRaises(HelperEffectNotApplied):
            executor._begin_apply(
                effect.idempotency_key,
                effect.request_sha256,
                "owner-before-clock-race",
                generation,
                stale_validation_at,
            )
        self.assertEqual(0, self.adapter.calls)
        self.assertEqual(
            ReconciliationState.NOT_FOUND,
            executor.reconcile(effect.idempotency_key, effect.request_sha256).state,
        )

        result = self.executor(
            owner_token_factory=lambda: "owner-after-clock-race"
        ).execute(effect)
        self.assertEqual("completed", result.result.result_code)
        self.assertEqual(1, self.adapter.calls)

    def test_preapply_writer_contention_is_fail_fast_and_retryable(self) -> None:
        effect = self.effect()
        executor = self.executor(owner_token_factory=lambda: "owner-before-contention")
        document = executor._effect_document(effect)
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":"))
        generation, _ = executor._prepare(
            effect,
            encoded,
            hashlib.sha256(encoded.encode("ascii")).hexdigest(),
            "owner-before-contention",
        )

        locker = sqlite3.connect(self.database, timeout=1, isolation_level=None)
        try:
            locker.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            with self.assertRaises(HelperEffectNotApplied):
                executor._begin_apply(
                    effect.idempotency_key,
                    effect.request_sha256,
                    "owner-before-contention",
                    generation,
                    self.clock(),
                )
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            locker.execute("ROLLBACK")
            locker.close()

        self.assertEqual(0, self.adapter.calls)
        result = self.executor(
            owner_token_factory=lambda: "owner-after-contention"
        ).execute(effect)
        self.assertEqual("completed", result.result.result_code)
        self.assertEqual(1, self.adapter.calls)

    def test_ambiguous_effect_reconciles_to_completion_across_restart(self) -> None:
        effect = self.effect()
        self.adapter.apply_error = True
        with self.assertRaises(DurableEffectUnknown):
            self.executor().execute(effect)
        self.adapter.apply_error = False
        result = EffectResult("reconciled", "9" * 64)
        self.adapter.reconciliation = EffectAdapterReconciliation(
            ReconciliationState.COMPLETED, result, self.clock()
        )
        outcome = self.executor().reconcile(effect.idempotency_key, effect.request_sha256)
        self.assertEqual(ReconciliationState.COMPLETED, outcome.state)
        self.assertEqual(result, outcome.completion.result)
        self.assertEqual(result, self.executor().execute(effect).result)
        self.assertEqual(1, self.adapter.calls)

    def test_unknown_reconciliation_stays_fenced(self) -> None:
        effect = self.effect()
        self.adapter.apply_error = True
        with self.assertRaises(DurableEffectUnknown):
            self.executor().execute(effect)
        self.adapter.reconciliation = EffectAdapterReconciliation(ReconciliationState.NOT_FOUND)
        outcome = self.executor().reconcile(effect.idempotency_key, effect.request_sha256)
        self.assertEqual(ReconciliationState.UNKNOWN, outcome.state)
        with self.assertRaises(DurableEffectUnknown):
            self.executor().execute(effect)
        self.assertEqual(1, self.adapter.calls)

    def test_concurrent_duplicate_invokes_typed_adapter_once(self) -> None:
        effect = self.effect()
        self.adapter.entered = threading.Event()
        self.adapter.release = threading.Event()
        executors = [self.executor() for _ in range(8)]
        outcomes = []

        def invoke(index):
            try:
                return executors[index].execute(effect)
            except (
                DurableEffectInProgress,
                DurableEffectUnknown,
                DurableStoreUnavailable,
                HelperEffectNotApplied,
            ):
                return None

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(invoke, index) for index in range(8)]
            self.assertTrue(self.adapter.entered.wait(timeout=5))
            time.sleep(0.05)
            self.adapter.release.set()
            outcomes = [future.result(timeout=5) for future in futures]
        self.assertEqual(1, self.adapter.calls)
        completed = [item for item in outcomes if item is not None]
        self.assertGreaterEqual(len(completed), 1)
        self.assertTrue(all(item.result.result_code == "completed" for item in completed))
        self.assertEqual(
            "completed", self.executor().execute(effect).result.result_code
        )

    def test_static_and_current_dispatch_validation_fail_before_adapter(self) -> None:
        effect = self.effect()
        denied = replace(effect, authority=replace(effect.authority, allowed=False))
        with self.assertRaises(HelperEffectNotApplied):
            self.executor().execute(denied)
        mismatched = replace(effect, subject="different-subject")
        with self.assertRaises(HelperEffectNotApplied):
            self.executor().execute(mismatched)
        expired = replace(
            effect,
            authority=replace(
                effect.authority, expires_at=self.now - timedelta(seconds=1)
            ),
        )
        with self.assertRaises(HelperEffectNotApplied):
            self.executor().execute(expired)
        self.assertEqual(0, self.adapter.calls)

        validator_calls = 0

        def deny_final(effect, observed_at):
            nonlocal validator_calls
            validator_calls += 1
            return validator_calls == 1

        with self.assertRaises(HelperEffectNotApplied):
            self.executor(dispatch_validator=deny_final).execute(effect)
        self.assertEqual(2, validator_calls)
        self.assertEqual(0, self.adapter.calls)
        self.assertEqual("completed", self.executor().execute(effect).result.result_code)

        exception_effect = self.effect(
            "validator-exception", request_sha256="a" * 64
        )
        exception_calls = 0

        def raise_final(effect, observed_at):
            nonlocal exception_calls
            exception_calls += 1
            if exception_calls == 2:
                raise RuntimeError("current-state source unavailable")
            return True

        with self.assertRaises(HelperEffectNotApplied):
            self.executor(dispatch_validator=raise_final).execute(exception_effect)
        self.assertEqual(2, exception_calls)
        self.assertEqual(1, self.adapter.calls)
        self.assertEqual(
            "completed", self.executor().execute(exception_effect).result.result_code
        )

    def test_safe_handle_is_committed_not_persisted_and_refresh_is_state_bound(self) -> None:
        token = "luma-handle-v1_" + "a" * 64
        effect = self.device_effect(token)
        device_adapter = RecordingAdapter(self.clock)
        executor = self.executor(
            adapters={HelperAction.ASSIGN_MODEL_DEVICE: device_adapter}
        )
        executor.execute(effect)
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.database) + suffix)
            if candidate.exists():
                self.assertNotIn(token.encode("ascii"), candidate.read_bytes())
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.database) + suffix)
            if candidate.exists():
                self.assertNotIn(token.encode("ascii"), candidate.read_bytes())
        replay = self.executor(
            adapters={HelperAction.ASSIGN_MODEL_DEVICE: RecordingAdapter(self.clock)}
        ).execute(effect)
        self.assertEqual("decision-device", replay.decision_id)
        changed = self.device_effect("luma-handle-v1_" + "b" * 64)
        with self.assertRaises(DurableEffectConflict):
            executor.execute(changed)

        conflict_database = self.root / "handle-conflict.sqlite3"
        original = SQLiteIdempotentEffectExecutor(
            conflict_database,
            integrity_key=KEY,
            adapters={HelperAction.ASSIGN_MODEL_DEVICE: RecordingAdapter(self.clock)},
            dispatch_validator=lambda candidate, observed_at: True,
            clock=self.clock,
        )
        document = original._effect_document(effect)
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":"))
        original._prepare(
            effect,
            encoded,
            hashlib.sha256(encoded.encode("ascii")).hexdigest(),
            "owner-handle-original",
        )
        refreshed_adapter = RecordingAdapter(self.clock)
        refreshed = SQLiteIdempotentEffectExecutor(
            conflict_database,
            integrity_key=KEY,
            adapters={HelperAction.ASSIGN_MODEL_DEVICE: refreshed_adapter},
            dispatch_validator=lambda candidate, observed_at: True,
            clock=self.clock,
        ).execute(changed)
        self.assertEqual("decision-device", refreshed.decision_id)
        self.assertEqual(1, refreshed_adapter.calls)

    def test_semantic_binding_rejects_resigned_row_and_forged_completion(self) -> None:
        effect = self.effect()
        executor = self.executor(owner_token_factory=lambda: "owner-semantic")
        document = executor._effect_document(effect)
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":"))
        generation, _ = executor._prepare(
            effect,
            encoded,
            hashlib.sha256(encoded.encode("ascii")).hexdigest(),
            "owner-semantic",
        )
        executor._begin_apply(
            effect.idempotency_key,
            effect.request_sha256,
            "owner-semantic",
            generation,
            self.clock(),
        )
        forged = ExecutorCompletion(
            effect.request_id,
            effect.request_sha256,
            effect.idempotency_key,
            effect.subject,
            effect.action,
            "different-decision",
            effect.authority.authority_generation,
            effect.authority.capability_sha256,
            EffectResult("completed", "e" * 64),
            self.clock(),
        )
        with self.assertRaises(DurableStoreUnavailable):
            executor._complete_effect(
                effect.idempotency_key,
                effect.request_sha256,
                "owner-semantic",
                generation,
                forged,
                (EffectLedgerState.APPLYING,),
            )

        resigned_database = self.root / "resigned.sqlite3"
        resigned = SQLiteIdempotentEffectExecutor(
            resigned_database,
            integrity_key=KEY,
            adapters={HelperAction.ACTIVATE_STAGED_RELEASE: RecordingAdapter(self.clock)},
            dispatch_validator=lambda candidate, observed_at: True,
            clock=self.clock,
        )
        body = resigned._effect_document(effect)
        body_text = json.dumps(body, sort_keys=True, separators=(",", ":"))
        resigned._prepare(
            effect,
            body_text,
            hashlib.sha256(body_text.encode("ascii")).hexdigest(),
            "owner-resigned",
        )
        with closing(sqlite3.connect(resigned_database)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM effect_ledger").fetchone()
            row_document = resigned._effect_document_from_row(row)
            changed_body = json.loads(row_document["effect_json"])
            changed_body["request_id"] = "different-request"
            changed_text = json.dumps(
                changed_body, sort_keys=True, separators=(",", ":")
            )
            row_document["effect_json"] = changed_text
            row_document["effect_sha256"] = hashlib.sha256(
                changed_text.encode("ascii")
            ).hexdigest()
            connection.execute(
                "UPDATE effect_ledger SET effect_json=?,effect_sha256=?,auth_tag=?",
                (
                    changed_text,
                    row_document["effect_sha256"],
                    resigned._tag("effect", row_document),
                ),
            )
            connection.commit()
        with self.assertRaises(DurableStoreUnavailable):
            resigned.integrity_check()

    def test_effect_row_tampering_and_wrong_integrity_key_fail_closed(self) -> None:
        effect = self.effect()
        executor = self.executor()
        executor.execute(effect)
        with self.assertRaises(DurableStoreUnavailable):
            SQLiteIdempotentEffectExecutor(
                self.database,
                integrity_key=b"different-integrity-key-material-000",
                adapters={HelperAction.ACTIVATE_STAGED_RELEASE: self.adapter},
                dispatch_validator=lambda effect, observed_at: True,
                clock=self.clock,
            )

        tamper_database = self.root / "tamper-effect.sqlite3"
        tamper_executor = SQLiteIdempotentEffectExecutor(
            tamper_database,
            integrity_key=KEY,
            adapters={HelperAction.ACTIVATE_STAGED_RELEASE: self.adapter},
            dispatch_validator=lambda effect, observed_at: True,
            clock=self.clock,
        )
        tamper_effect = self.effect(
            "tamper-effect", request_sha256="7" * 64
        )
        document = canonical_effect_document(tamper_effect)
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
        tamper_executor._prepare(
            tamper_effect,
            encoded.decode("ascii"),
            hashlib.sha256(encoded).hexdigest(),
            "owner-token-tamper",
        )
        with closing(sqlite3.connect(tamper_database)) as connection:
            connection.execute(
                "UPDATE effect_ledger SET request_sha256=?",
                ("0" * 64,),
            )
            connection.commit()
        with self.assertRaises(DurableStoreUnavailable):
            tamper_executor.integrity_check()


if __name__ == "__main__":
    unittest.main()
