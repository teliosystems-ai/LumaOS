from __future__ import annotations

from pathlib import Path
import sys
import threading
import time
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.fake_inference import (  # noqa: E402
    DeterministicFakeInferenceBackend,
    FakeInferenceError,
    InferenceReplayConflict,
    InferenceRequest,
)
from luma_os.resources import (  # noqa: E402
    MAX_U64,
    AdmissionDenied,
    ByteArithmeticError,
    DomainState,
    FakeTelemetryAdapter,
    IdempotencyConflict,
    LeaseOwnershipError,
    LeaseStatus,
    MemoryDomain,
    MemoryReservation,
    ResourceLedger,
    ResourceLedgerError,
    ResourceLease,
    ResourceValidationError,
    StaleLeaseError,
    StaleTelemetryError,
    TelemetrySample,
    checked_add_bytes,
    checked_sub_bytes,
    checked_sum_bytes,
    checked_u64,
)


class CheckedByteArithmeticTests(unittest.TestCase):
    def test_unsigned_boundaries_and_bool_rejection(self) -> None:
        self.assertEqual(checked_u64(0), 0)
        self.assertEqual(checked_u64(MAX_U64), MAX_U64)
        for invalid in (-1, MAX_U64 + 1, True, False, 1.0, "1"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ResourceValidationError):
                    checked_u64(invalid)  # type: ignore[arg-type]

    def test_add_subtract_and_sum_never_wrap(self) -> None:
        self.assertEqual(checked_add_bytes(MAX_U64 - 1, 1), MAX_U64)
        self.assertEqual(checked_sub_bytes(MAX_U64, MAX_U64), 0)
        self.assertEqual(checked_sum_bytes((1, 2, 3)), 6)
        with self.assertRaises(ByteArithmeticError):
            checked_add_bytes(MAX_U64, 1)
        with self.assertRaises(ByteArithmeticError):
            checked_sub_bytes(0, 1)
        with self.assertRaises(ByteArithmeticError):
            checked_sum_bytes((MAX_U64, 1))


class MemoryDomainContractTests(unittest.TestCase):
    def test_budget_reservation_and_watermark_contract(self) -> None:
        domain = MemoryDomain(
            "gpu0",
            budget_bytes=1_000,
            reserved_bytes=100,
            pressure_enter_bytes=800,
            pressure_exit_bytes=600,
        )
        self.assertEqual(domain.allocatable_bytes, 900)
        self.assertEqual(domain.as_dict()["pressure_exit_bytes"], 600)

        invalid_arguments = (
            {"domain_id": "", "budget_bytes": 10},
            {"domain_id": "gpu0", "budget_bytes": 0},
            {"domain_id": "gpu0", "budget_bytes": 10, "reserved_bytes": 10},
            {
                "domain_id": "gpu0",
                "budget_bytes": 10,
                "reserved_bytes": 2,
                "pressure_enter_bytes": 2,
            },
            {
                "domain_id": "gpu0",
                "budget_bytes": 10,
                "reserved_bytes": 2,
                "pressure_enter_bytes": 8,
                "pressure_exit_bytes": 9,
            },
        )
        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                with self.assertRaises(ResourceValidationError):
                    MemoryDomain(**arguments)  # type: ignore[arg-type]


class ResourceLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = ResourceLedger(
            (
                MemoryDomain("host", budget_bytes=1_000, reserved_bytes=100),
                MemoryDomain("gpu0", budget_bytes=500, reserved_bytes=50),
            )
        )

    def test_multi_domain_admission_release_and_snapshots(self) -> None:
        lease = self.ledger.admit(
            "alice", {"gpu0": 200, "host": 300}, idempotency_key="load-model-1"
        )
        self.assertEqual([item.domain_id for item in lease.reservations], ["gpu0", "host"])
        self.assertEqual(lease.total_bytes, 500)
        self.assertEqual(self.ledger.domain_snapshot("host").allocated_bytes, 300)
        self.assertEqual(self.ledger.domain_snapshot("gpu0").available_bytes, 250)
        snapshots = self.ledger.snapshots()
        with self.assertRaises(TypeError):
            snapshots["host"] = snapshots["gpu0"]  # type: ignore[index]

        self.assertTrue(self.ledger.release(lease, owner_id="alice"))
        self.assertFalse(self.ledger.release(lease, owner_id="alice"))
        self.assertEqual(self.ledger.lease_status(lease), LeaseStatus.RELEASED)
        self.assertEqual(self.ledger.domain_snapshot("host").allocated_bytes, 0)
        with self.assertRaises(StaleLeaseError):
            self.ledger.assert_active(lease)

    def test_failed_multi_domain_admission_is_atomic(self) -> None:
        existing = self.ledger.admit(
            "alice", {"gpu0": 400}, idempotency_key="existing"
        )
        before = {key: value.as_dict() for key, value in self.ledger.snapshots().items()}
        with self.assertRaises(AdmissionDenied) as raised:
            self.ledger.admit(
                "bob", {"host": 800, "gpu0": 100}, idempotency_key="too-large"
            )
        self.assertEqual(raised.exception.domain_id, "gpu0")
        after = {key: value.as_dict() for key, value in self.ledger.snapshots().items()}
        self.assertEqual(after, before)
        self.assertEqual(self.ledger.lease_status(existing), LeaseStatus.ACTIVE)

    def test_idempotency_is_owner_scoped_and_does_not_reacquire(self) -> None:
        first = self.ledger.admit("alice", {"host": 100}, idempotency_key="same")
        replay = self.ledger.admit("alice", {"host": 100}, idempotency_key="same")
        self.assertIs(first, replay)
        self.assertEqual(self.ledger.domain_snapshot("host").allocated_bytes, 100)
        with self.assertRaises(IdempotencyConflict):
            self.ledger.admit("alice", {"host": 101}, idempotency_key="same")

        other_owner = self.ledger.admit("bob", {"host": 100}, idempotency_key="same")
        self.assertNotEqual(other_owner.lease_id, first.lease_id)
        self.ledger.release(first)
        terminal_replay = self.ledger.admit(
            "alice", {"host": 100}, idempotency_key="same"
        )
        self.assertIs(terminal_replay, first)
        self.assertEqual(self.ledger.lease_status(terminal_replay), LeaseStatus.RELEASED)
        self.assertEqual(self.ledger.domain_snapshot("host").allocated_bytes, 100)

    def test_generation_owner_and_complete_token_are_fenced(self) -> None:
        lease = self.ledger.admit("alice", {"host": 100}, idempotency_key="fence")
        with self.assertRaises(StaleLeaseError):
            self.ledger.assert_active(lease.lease_id, lease.generation + 1)
        with self.assertRaises(LeaseOwnershipError):
            self.ledger.assert_active(lease, owner_id="bob")
        forged = ResourceLease(
            lease_id=lease.lease_id,
            generation=lease.generation,
            owner_id=lease.owner_id,
            idempotency_key=lease.idempotency_key,
            reservations=(MemoryReservation("host", 99),),
        )
        with self.assertRaises(StaleLeaseError):
            self.ledger.assert_active(forged)
        with self.assertRaises(ResourceValidationError):
            self.ledger.assert_active(lease.lease_id)

    def test_generation_exhaustion_fails_without_accounting_mutation(self) -> None:
        ledger = ResourceLedger(
            (MemoryDomain("host", 10),), initial_generation=MAX_U64
        )
        lease = ledger.admit("alice", {"host": 1}, idempotency_key="last")
        self.assertEqual(lease.generation, MAX_U64)
        with self.assertRaises(ByteArithmeticError):
            ledger.admit("bob", {"host": 1}, idempotency_key="overflow")
        self.assertEqual(ledger.domain_snapshot("host").allocated_bytes, 1)

    def test_lease_total_overflow_is_rejected_before_admission(self) -> None:
        ledger = ResourceLedger(
            (MemoryDomain("a", MAX_U64), MemoryDomain("b", MAX_U64))
        )
        with self.assertRaises(ByteArithmeticError):
            ledger.admit(
                "alice", {"a": MAX_U64, "b": 1}, idempotency_key="overflow"
            )
        self.assertEqual(ledger.domain_snapshot("a").allocated_bytes, 0)
        self.assertEqual(ledger.domain_snapshot("b").allocated_bytes, 0)

    def test_hold_serializes_release_against_operation_start(self) -> None:
        lease = self.ledger.admit("alice", {"host": 100}, idempotency_key="held")
        entered = threading.Event()
        allow_exit = threading.Event()
        released = threading.Event()
        release_started = threading.Event()

        def holder() -> None:
            with self.ledger.hold(lease):
                entered.set()
                allow_exit.wait(timeout=2)

        def releaser() -> None:
            release_started.set()
            self.ledger.release(lease)
            released.set()

        holder_thread = threading.Thread(target=holder)
        holder_thread.start()
        self.assertTrue(entered.wait(timeout=2))
        release_thread = threading.Thread(target=releaser)
        release_thread.start()
        self.assertTrue(release_started.wait(timeout=2))
        time.sleep(0.03)
        self.assertFalse(released.is_set())
        allow_exit.set()
        holder_thread.join(timeout=2)
        release_thread.join(timeout=2)
        self.assertTrue(released.is_set())

    def test_concurrent_admission_never_overcommits(self) -> None:
        ledger = ResourceLedger((MemoryDomain("host", budget_bytes=100),))
        workers = 40
        barrier = threading.Barrier(workers)
        lock = threading.Lock()
        admitted: list[ResourceLease] = []
        denied: list[AdmissionDenied] = []

        def attempt(index: int) -> None:
            barrier.wait(timeout=5)
            try:
                lease = ledger.admit(
                    f"owner-{index}", {"host": 10}, idempotency_key="allocation"
                )
            except AdmissionDenied as exc:
                with lock:
                    denied.append(exc)
            else:
                with lock:
                    admitted.append(lease)

        threads = [threading.Thread(target=attempt, args=(index,)) for index in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=6)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(admitted), 10)
        self.assertEqual(len(denied), workers - 10)
        self.assertEqual(ledger.domain_snapshot("host").allocated_bytes, 100)
        self.assertEqual(len({lease.lease_id for lease in admitted}), 10)
        self.assertEqual(len({lease.generation for lease in admitted}), 10)

        release_barrier = threading.Barrier(len(admitted))
        release_errors: list[BaseException] = []

        def release_twice(lease: ResourceLease) -> None:
            try:
                release_barrier.wait(timeout=5)
                if not ledger.release(lease):
                    raise AssertionError("first release did not transition the lease")
                if ledger.release(lease):
                    raise AssertionError("duplicate release transitioned the lease")
            except BaseException as exc:
                with lock:
                    release_errors.append(exc)

        release_threads = [
            threading.Thread(target=release_twice, args=(lease,)) for lease in admitted
        ]
        for thread in release_threads:
            thread.start()
        for thread in release_threads:
            thread.join(timeout=6)
        self.assertTrue(all(not thread.is_alive() for thread in release_threads))
        self.assertEqual(release_errors, [])
        self.assertEqual(ledger.domain_snapshot("host").allocated_bytes, 0)

    def test_concurrent_idempotent_replay_allocates_once(self) -> None:
        ledger = ResourceLedger((MemoryDomain("host", budget_bytes=1_000),))
        workers = 24
        barrier = threading.Barrier(workers)
        lock = threading.Lock()
        leases: list[ResourceLease] = []

        def replay() -> None:
            barrier.wait(timeout=5)
            lease = ledger.admit(
                "alice", {"host": 100}, idempotency_key="one-logical-operation"
            )
            with lock:
                leases.append(lease)

        threads = [threading.Thread(target=replay) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=6)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(leases), workers)
        self.assertEqual(len({lease.lease_id for lease in leases}), 1)
        self.assertEqual(ledger.domain_snapshot("host").allocated_bytes, 100)


class PressureAndQuarantineTests(unittest.TestCase):
    def test_telemetry_capacity_below_budget_quarantines_domain(self) -> None:
        ledger = ResourceLedger((MemoryDomain("gpu0", 1000),))
        snapshot = ledger.update_telemetry(TelemetrySample("gpu0", 1, 100, 900))
        self.assertEqual(DomainState.QUARANTINED, snapshot.state)
        with self.assertRaises(AdmissionDenied):
            ledger.admit("owner", {"gpu0": 1}, idempotency_key="too-small")

    def test_telemetry_pressure_has_hysteresis_and_rejects_stale_samples(self) -> None:
        domain = MemoryDomain(
            "gpu0",
            budget_bytes=100,
            reserved_bytes=10,
            pressure_enter_bytes=80,
            pressure_exit_bytes=50,
        )
        ledger = ResourceLedger((domain,))
        adapter = FakeTelemetryAdapter(
            {
                "gpu0": (
                    TelemetrySample("gpu0", 1, used_bytes=85, total_bytes=100),
                    TelemetrySample("gpu0", 2, used_bytes=60, total_bytes=100),
                    TelemetrySample("gpu0", 3, used_bytes=50, total_bytes=100),
                )
            }
        )
        self.assertEqual(
            ledger.refresh_telemetry(adapter)["gpu0"].state, DomainState.PRESSURE
        )
        with self.assertRaises(AdmissionDenied):
            ledger.admit("alice", {"gpu0": 1}, idempotency_key="pressure")
        self.assertEqual(
            ledger.refresh_telemetry(adapter)["gpu0"].state, DomainState.PRESSURE
        )
        self.assertEqual(
            ledger.refresh_telemetry(adapter)["gpu0"].state, DomainState.HEALTHY
        )
        lease = ledger.admit("alice", {"gpu0": 1}, idempotency_key="recovered")
        self.assertEqual(ledger.lease_status(lease), LeaseStatus.ACTIVE)

        # Repeating the exact final sample is idempotent; changing or moving its
        # sequence backwards is rejected.
        ledger.refresh_telemetry(adapter)
        with self.assertRaises(StaleTelemetryError):
            ledger.update_telemetry(
                TelemetrySample("gpu0", 3, used_bytes=49, total_bytes=100)
            )
        with self.assertRaises(StaleTelemetryError):
            ledger.update_telemetry(
                TelemetrySample("gpu0", 2, used_bytes=40, total_bytes=100)
            )

    def test_quarantine_revokes_whole_placement_and_is_epoch_fenced(self) -> None:
        ledger = ResourceLedger(
            (MemoryDomain("host", 1_000), MemoryDomain("gpu0", 500))
        )
        placement = ledger.admit(
            "alice", {"host": 200, "gpu0": 200}, idempotency_key="placement"
        )
        host_only = ledger.admit("bob", {"host": 100}, idempotency_key="host-only")
        revoked = ledger.quarantine("gpu0", reason="driver reset")
        self.assertEqual(revoked, (placement,))
        self.assertEqual(ledger.lease_status(placement), LeaseStatus.REVOKED)
        self.assertEqual(ledger.lease_status(host_only), LeaseStatus.ACTIVE)
        self.assertEqual(ledger.domain_snapshot("host").allocated_bytes, 100)
        quarantined = ledger.domain_snapshot("gpu0")
        self.assertEqual(quarantined.state, DomainState.QUARANTINED)
        self.assertEqual(quarantined.allocated_bytes, 0)
        self.assertEqual(ledger.quarantine("gpu0", reason="duplicate"), ())
        with self.assertRaises(StaleLeaseError):
            ledger.release(placement)
        with self.assertRaises(AdmissionDenied):
            ledger.admit("carol", {"gpu0": 1}, idempotency_key="blocked")
        with self.assertRaises(StaleLeaseError):
            ledger.clear_quarantine("gpu0", expected_epoch=0)

        recovered = ledger.clear_quarantine(
            "gpu0", expected_epoch=quarantined.quarantine_epoch
        )
        self.assertEqual(recovered.state, DomainState.HEALTHY)
        replacement = ledger.admit(
            "carol", {"gpu0": 200}, idempotency_key="replacement"
        )
        self.assertGreater(replacement.generation, placement.generation)

    def test_device_error_telemetry_quarantines_and_revokes(self) -> None:
        ledger = ResourceLedger((MemoryDomain("gpu0", 100),))
        lease = ledger.admit("alice", {"gpu0": 25}, idempotency_key="run")
        snapshot = ledger.update_telemetry(
            TelemetrySample(
                "gpu0", 1, used_bytes=25, total_bytes=100, device_error=True
            )
        )
        self.assertEqual(snapshot.state, DomainState.QUARANTINED)
        self.assertEqual(ledger.lease_status(lease), LeaseStatus.REVOKED)
        self.assertEqual(snapshot.allocated_bytes, 0)

    def test_non_repeating_fake_telemetry_exhaustion_is_explicit(self) -> None:
        adapter = FakeTelemetryAdapter(
            {"host": (TelemetrySample("host", 1, 0, 100),)}, repeat_last=False
        )
        self.assertEqual(adapter.sample("host").sequence, 1)
        with self.assertRaises(ResourceLedgerError):
            adapter.sample("host")


class DeterministicFakeInferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = ResourceLedger(
            (MemoryDomain("host", 1_000), MemoryDomain("gpu0", 1_000))
        )
        self.backend = DeterministicFakeInferenceBackend(
            self.ledger,
            required_reservations={"host": 100, "gpu0": 200},
            responses={"known prompt": "one two three four"},
            failing_request_ids=frozenset({"fail"}),
        )

    def test_result_is_deterministic_idempotent_and_labeled_simulated(self) -> None:
        lease = self.ledger.admit(
            "alice", {"host": 100, "gpu0": 200}, idempotency_key="model"
        )
        request = InferenceRequest("req-1", "known prompt", max_output_tokens=3)
        first = self.backend.infer(lease, request)
        second = self.backend.infer(lease, request)
        self.assertIs(first, second)
        self.assertEqual(first.text, "one two three")
        self.assertEqual(first.output_tokens, 3)
        self.assertTrue(first.simulated)
        self.assertEqual(first.lease_generation, lease.generation)
        self.assertEqual(len(first.prompt_sha256), 64)

    def test_generated_response_is_stable_across_backends(self) -> None:
        lease = self.ledger.admit(
            "alice", {"host": 100, "gpu0": 200}, idempotency_key="stable"
        )
        request = InferenceRequest("stable-1", "unconfigured prompt")
        first = self.backend.infer(lease, request)
        equivalent = DeterministicFakeInferenceBackend(
            self.ledger,
            required_reservations={"host": 100, "gpu0": 200},
        )
        second = equivalent.infer(lease, request)
        self.assertEqual(first, second)

    def test_resource_requirement_failure_replay_conflict_and_scripted_failure(self) -> None:
        insufficient = self.ledger.admit(
            "alice", {"host": 100, "gpu0": 199}, idempotency_key="small"
        )
        with self.assertRaises(FakeInferenceError):
            self.backend.infer(insufficient, InferenceRequest("small", "prompt"))

        lease = self.ledger.admit(
            "alice", {"host": 100, "gpu0": 200}, idempotency_key="enough"
        )
        self.backend.infer(lease, InferenceRequest("request", "first"))
        with self.assertRaises(InferenceReplayConflict):
            self.backend.infer(lease, InferenceRequest("request", "changed"))
        with self.assertRaises(FakeInferenceError):
            self.backend.infer(lease, InferenceRequest("fail", "prompt"))

    def test_released_and_quarantined_leases_cannot_infer(self) -> None:
        released = self.ledger.admit(
            "alice", {"host": 100, "gpu0": 200}, idempotency_key="released"
        )
        self.ledger.release(released)
        with self.assertRaises(StaleLeaseError):
            self.backend.infer(released, InferenceRequest("after-release", "prompt"))

        revoked = self.ledger.admit(
            "alice", {"host": 100, "gpu0": 200}, idempotency_key="revoked"
        )
        self.ledger.quarantine("gpu0", reason="test")
        with self.assertRaises(StaleLeaseError):
            self.backend.infer(revoked, InferenceRequest("after-revoke", "prompt"))

    def test_inference_request_rejects_invalid_token_limit(self) -> None:
        with self.assertRaises(ResourceValidationError):
            InferenceRequest("request", "prompt", max_output_tokens=0)
        with self.assertRaises(ResourceValidationError):
            InferenceRequest("request", "prompt", max_output_tokens=MAX_U64 + 1)


if __name__ == "__main__":
    unittest.main()
