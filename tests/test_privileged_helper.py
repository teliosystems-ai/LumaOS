from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import sys
import threading
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.privileged_helper import (  # noqa: E402
    AuthenticatedPeer,
    AuthorityDecision,
    BoundDevice,
    ConfinementAttestation,
    ConfinementMode,
    DenialReason,
    DeviceCapability,
    DeviceType,
    EffectResult,
    ExecutorCompletion,
    ExecutorReconciliation,
    GeneratedCodeKind,
    HelperAction,
    HelperDenied,
    HelperExecutionError,
    HelperReplayConflict,
    HelperValidationError,
    JournalRecord,
    JournalReservation,
    JournalState,
    PeerTransport,
    PrivilegedHelper,
    ReconciliationState,
    calculate_request_sha256,
    parse_helper_request,
)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class MemoryPersistentJournal:
    """Thread-safe test double whose state survives helper reconstruction."""

    persistent = True
    capacity = 128
    retention = timedelta(hours=1)

    def __init__(self) -> None:
        self.records: dict[str, JournalRecord] = {}
        self.leases: dict[str, datetime] = {}
        self.lock = threading.Lock()

    def reserve(self, request_id, request_sha256, owner_token, observed_at, lease_until):
        with self.lock:
            current = self.records.get(request_id)
            if current is None:
                if len(self.records) >= self.capacity:
                    raise RuntimeError("journal full")
                current = JournalRecord(
                    request_id, request_sha256, JournalState.PENDING, owner_token, None
                )
                self.records[request_id] = current
                self.leases[request_id] = lease_until
                return JournalReservation(current, True)
            if current.request_sha256 != request_sha256:
                return JournalReservation(current, False)
            if current.state is JournalState.PENDING and self.leases[request_id] <= observed_at:
                current = JournalRecord(
                    request_id, request_sha256, JournalState.PENDING, owner_token, None
                )
                self.records[request_id] = current
                self.leases[request_id] = lease_until
                return JournalReservation(current, True)
            return JournalReservation(current, False)

    def complete(self, request_id, request_sha256, owner_token, receipt):
        with self.lock:
            current = self.records[request_id]
            if current.request_sha256 != request_sha256:
                raise RuntimeError("digest changed")
            if owner_token is not None and current.owner_token != owner_token:
                raise RuntimeError("owner changed")
            self.records[request_id] = JournalRecord(
                request_id, request_sha256, JournalState.COMPLETED, None, receipt
            )
            self.leases.pop(request_id, None)

    def mark_failed_unknown(self, request_id, request_sha256, owner_token):
        with self.lock:
            current = self.records[request_id]
            if current.request_sha256 != request_sha256 or current.owner_token != owner_token:
                raise RuntimeError("owner or digest changed")
            self.records[request_id] = JournalRecord(
                request_id, request_sha256, JournalState.FAILED_UNKNOWN, None, None
            )
            self.leases.pop(request_id, None)


class RecordingExecutor:
    def __init__(self, clock) -> None:
        self.clock = clock
        self.effects = []
        self.completions: dict[str, ExecutorCompletion] = {}
        self.reconciliation = ReconciliationState.NOT_FOUND
        self.raise_after_completion = False
        self.raise_unknown = False
        self.reenter = None
        self.reentrant_error = None

    def completion_for(self, effect, result=None):
        result = result or EffectResult("completed", "e" * 64)
        return ExecutorCompletion(
            effect.request_id,
            effect.request_sha256,
            effect.idempotency_key,
            effect.subject,
            effect.action,
            effect.authority.decision_id,
            effect.authority.authority_generation,
            effect.authority.capability_sha256,
            result,
            self.clock(),
        )

    def execute(self, effect):
        self.effects.append(effect)
        if self.reenter is not None:
            try:
                self.reenter()
            except Exception as exc:  # recorded for the outer test
                self.reentrant_error = exc
        if self.raise_unknown:
            self.reconciliation = ReconciliationState.UNKNOWN
            raise RuntimeError("transport lost with unknown outcome")
        result = EffectResult("completed", "e" * 64)
        self.completions[effect.idempotency_key] = self.completion_for(effect, result)
        if self.raise_after_completion:
            raise RuntimeError("reply lost after committed effect")
        return result

    def reconcile(self, idempotency_key, request_sha256):
        completion = self.completions.get(idempotency_key)
        if completion is not None:
            return ExecutorReconciliation(ReconciliationState.COMPLETED, completion)
        return ExecutorReconciliation(self.reconciliation)


class PrivilegedHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 22, 12, tzinfo=UTC)
        self.peer = AuthenticatedPeer(
            "worker-service",
            PeerTransport.UNIX_PEER_CREDENTIALS,
            "uid:1001;gid:1001;pid:4455",
            "session-1",
            "1" * 64,
            True,
        )
        self.journal = MemoryPersistentJournal()
        self.executor = RecordingExecutor(lambda: self.now)
        self.flags = {
            "peer": True,
            "enforcing": True,
            "confinement_valid": True,
            "confinement_invalidated": False,
            "certificate_valid": True,
            "certificate_invalidated": False,
            "allowed": True,
            "revoked": False,
        }
        self.overrides: dict[str, object] = {}
        self.calls: list[str] = []
        self.helper = self.make_helper()

    def stamp(self, value: datetime) -> str:
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    def stable_device(self, device_type=DeviceType.DRM_RENDER, major=226, minor=128):
        host = "8" * 64
        stable = hashlib.sha256(
            canonical(
                {
                    "device_type": device_type.value,
                    "host_identity_sha256": host,
                    "major": major,
                    "minor": minor,
                }
            )
        ).hexdigest()
        return BoundDevice(
            device_type, major, minor, host, stable, "OpaqueHandleToken_1234567890"
        )

    def make_helper(self, *, clock=None, journal=None, executor=None):
        def peer_authenticator(peer, at):
            self.calls.append("peer")
            return self.flags["peer"]

        def attestor(peer, request, at):
            self.calls.append("attest")
            return ConfinementAttestation(
                "attestation-1",
                self.overrides.get("attestation_request", request.request_sha256),
                self.overrides.get("attestation_peer", peer.identity_sha256),
                self.overrides.get("attestation_action", request.action),
                self.overrides.get("attestation_worker", request.worker_id),
                self.overrides.get("attestation_artifact", request.artifact_sha256),
                self.overrides.get("attestation_mode", request.confinement.mode),
                request.confinement.profile_id,
                request.confinement.profile_version,
                request.confinement.profile_sha256,
                self.flags["enforcing"],
                request.confinement.qualification_id,
                at,
                at + timedelta(seconds=30),
                "attestation-key-1",
                b"a" * 64,
            )

        def confinement_verifier(evidence, at):
            self.calls.append("verify-confinement")
            self.assertIn(b'"enforcing":true', evidence.signed_bytes)
            return self.flags["confinement_valid"]

        def confinement_invalidated(evidence):
            self.calls.append("invalidate-confinement")
            return self.flags["confinement_invalidated"]

        def binder(assignment, peer, request, at):
            self.calls.append("bind-device")
            device = self.overrides.get("bound_device", self.stable_device())
            return DeviceCapability(
                "device-capability-1",
                self.overrides.get("device_request", request.request_sha256),
                self.overrides.get("device_peer", peer.identity_sha256),
                self.overrides.get("device_assignment", assignment.assignment_id),
                self.overrides.get("device_generation", assignment.generation),
                self.overrides.get("device_worker", assignment.worker_id),
                True,
                (device,),
                at,
                at + timedelta(seconds=30),
            )

        def certificate_verifier(certificate, at):
            self.calls.append("verify-certificate")
            return self.flags["certificate_valid"] and bool(certificate.signed_bytes)

        def certificate_invalidated(certificate):
            self.calls.append("invalidate-certificate")
            return self.flags["certificate_invalidated"]

        def authorizer(peer, request, capability_sha256, at):
            self.calls.append("authorize")
            return AuthorityDecision(
                "decision-1",
                self.flags["allowed"],
                self.overrides.get("authority_id", request.authority_id),
                self.overrides.get("authority_generation", request.authority_generation),
                self.overrides.get("authority_subject", request.subject),
                self.overrides.get("authority_peer", peer.identity_sha256),
                self.overrides.get("authority_action", request.action),
                self.overrides.get("authority_request", request.request_sha256),
                self.overrides.get("authority_capability", capability_sha256),
                at + timedelta(seconds=30),
                self.flags["revoked"],
            )

        return PrivilegedHelper(
            peer_authenticator=peer_authenticator,
            confinement_attestor=attestor,
            confinement_verifier=confinement_verifier,
            confinement_invalidated=confinement_invalidated,
            device_binder=binder,
            driver_certificate_verifier=certificate_verifier,
            driver_certificate_invalidated=certificate_invalidated,
            policy_authorizer=authorizer,
            journal=journal or self.journal,
            executor=executor or self.executor,
            clock=clock or (lambda: self.now),
            owner_token_factory=lambda: "owner-token-1234567890",
        )

    def unsigned(self, request_id="request-1", *, action=None, parameters=None, mode=None):
        action = action or HelperAction.ACTIVATE_STAGED_RELEASE.value
        parameters = parameters or {"release_sha256": "a" * 64}
        return {
            "schema_version": 1,
            "request_id": request_id,
            "subject": self.peer.principal,
            "peer_identity_sha256": self.peer.identity_sha256,
            "action": action,
            "issued_at": self.stamp(self.now - timedelta(seconds=10)),
            "deadline": self.stamp(self.now + timedelta(minutes=1)),
            "authority": {"id": "grant-1", "generation": 7},
            "parameters": parameters,
            "confinement": {
                "mode": mode or ConfinementMode.KVM_MICROVM.value,
                "profile_id": "profile-1",
                "profile_version": 3,
                "profile_sha256": "b" * 64,
                "qualification_id": "qualification-1",
                "signer_key_id": "profile-key-1",
                "signature": "c" * 128,
            },
            "device_assignment": None,
            "driver_runtime_certificate": None,
        }

    def device_request(self, request_id="device-request", *, generated=False, mode=None):
        device = self.stable_device()
        if generated:
            action = HelperAction.START_GENERATED_WORKER.value
            parameters = {
                "worker_id": "worker-7",
                "workload_id": "workload-9",
                "artifact_sha256": "9" * 64,
                "code_kind": GeneratedCodeKind.NATIVE.value,
                "assignment_id": "assignment-4",
            }
        else:
            action = HelperAction.ASSIGN_MODEL_DEVICE.value
            parameters = {"worker_id": "worker-7", "assignment_id": "assignment-4"}
        value = self.unsigned(
            request_id, action=action, parameters=parameters, mode=mode
        )
        value["device_assignment"] = {
            "assignment_id": "assignment-4",
            "worker_id": "worker-7",
            "selectors": [{"device_type": "drm_render", "path": "/dev/dri/renderD128"}],
            "exclusive": True,
            "generation": 11,
        }
        value["driver_runtime_certificate"] = {
            "certificate_id": "certificate-5",
            "device_identity_sha256s": [device.stable_identity_sha256],
            "driver_name": "nvidia",
            "driver_version": "566.07",
            "driver_module_sha256": "d" * 64,
            "runtime_name": "cuda",
            "runtime_version": "12.8",
            "runtime_sha256": "f" * 64,
            "qualification_id": "driver-qualification-2",
            "signer_key_id": "driver-key-1",
            "not_before": self.stamp(self.now - timedelta(days=1)),
            "not_after": self.stamp(self.now + timedelta(days=1)),
            "signature": "2" * 128,
        }
        return value

    @staticmethod
    def seal(value):
        unsigned = deepcopy(value)
        unsigned.pop("request_sha256", None)
        document = deepcopy(unsigned)
        document["request_sha256"] = calculate_request_sha256(unsigned)
        return canonical(document)

    def denied(self, reason, value, *, helper=None, peer=None):
        with self.assertRaises(HelperDenied) as raised:
            (helper or self.helper).handle(self.seal(value), peer=peer or self.peer)
        self.assertEqual(reason, raised.exception.reason)

    def test_happy_path_revalidates_all_mutable_trust_and_passes_only_opaque_device(self):
        receipt = self.helper.handle(self.seal(self.device_request()), peer=self.peer)
        self.assertEqual("completed", receipt.result_code)
        self.assertEqual(2, self.calls.count("attest"))
        self.assertEqual(2, self.calls.count("bind-device"))
        self.assertEqual(2, self.calls.count("verify-certificate"))
        self.assertEqual(2, self.calls.count("authorize"))
        effect = self.executor.effects[0]
        self.assertIsNotNone(effect.device_capability)
        self.assertEqual(226, effect.device_capability.devices[0].major)
        self.assertFalse(hasattr(effect, "request"))
        self.assertNotIn("/dev/", repr(effect))
        self.assertNotIn("OpaqueHandleToken", repr(effect))
        for name in ("command", "shell", "argv", "executable", "register"):
            self.assertFalse(hasattr(effect, name))

    def test_wire_cannot_assert_enforcement_and_trusted_attestor_must_enforce(self):
        value = self.unsigned()
        value["confinement"]["enforcing"] = True
        with self.assertRaises(HelperValidationError):
            parse_helper_request(self.seal(value))
        self.flags["enforcing"] = False
        self.denied(DenialReason.CONFINEMENT_NOT_ENFORCING, self.unsigned("not-enforcing"))

    def test_attestation_binds_peer_pid_worker_artifact_profile_action_and_request(self):
        cases = (
            ("attestation_request", "0" * 64),
            ("attestation_peer", "0" * 64),
            ("attestation_worker", "other-worker"),
            ("attestation_artifact", "0" * 64),
            ("attestation_action", HelperAction.ACTIVATE_STAGED_RELEASE),
            ("attestation_mode", ConfinementMode.PROCESS_SANDBOX),
        )
        for index, (field, value) in enumerate(cases):
            with self.subTest(field=field):
                self.overrides[field] = value
                self.denied(
                    DenialReason.CONFINEMENT_BINDING_MISMATCH,
                    self.device_request(f"attestation-{index}", generated=True),
                )
                self.overrides.clear()

    def test_authority_structurally_binds_every_security_dimension(self):
        cases = (
            ("authority_subject", "another-subject"),
            ("authority_peer", "0" * 64),
            ("authority_action", HelperAction.SET_RECOVERY_BOOT_ONCE),
            ("authority_request", "0" * 64),
            ("authority_capability", "0" * 64),
        )
        for index, (field, value) in enumerate(cases):
            with self.subTest(field=field):
                self.overrides[field] = value
                self.denied(
                    DenialReason.AUTHORITY_BINDING_MISMATCH,
                    self.unsigned(f"authority-binding-{index}"),
                )
                self.overrides.clear()

    def test_argument_substitution_with_recomputed_request_checksum_is_denied(self):
        original = parse_helper_request(self.seal(self.unsigned("substitution")))
        changed = self.unsigned("substitution")
        changed["parameters"]["release_sha256"] = "0" * 64
        self.overrides["authority_request"] = original.request_sha256
        self.denied(DenialReason.AUTHORITY_BINDING_MISMATCH, changed)
        self.assertEqual([], self.executor.effects)

    def test_second_pass_revocation_invalidation_and_binding_changes_block_dispatch(self):
        authorization_calls = 0

        def flip_authority(peer, request, capability, at):
            nonlocal authorization_calls
            authorization_calls += 1
            self.flags["revoked"] = authorization_calls == 2
            return AuthorityDecision(
                "decision-1", True, request.authority_id, request.authority_generation,
                request.subject, peer.identity_sha256, request.action, request.request_sha256,
                capability, at + timedelta(seconds=30), self.flags["revoked"],
            )

        helper = self.make_helper()
        helper._policy_authorizer = flip_authority
        self.denied(DenialReason.AUTHORITY_REVOKED, self.unsigned("revoked-second"), helper=helper)
        self.assertEqual(2, authorization_calls)
        self.assertEqual([], self.executor.effects)
        self.flags["revoked"] = False

        certificate_calls = 0

        def invalidate_second(certificate):
            nonlocal certificate_calls
            certificate_calls += 1
            return certificate_calls == 2

        helper = self.make_helper(journal=MemoryPersistentJournal())
        helper._certificate_invalidated = invalidate_second
        self.denied(
            DenialReason.DRIVER_CERTIFICATE_INVALIDATED,
            self.device_request("certificate-invalidated-second"),
            helper=helper,
        )
        self.assertEqual(2, certificate_calls)

        attestation_calls = 0
        helper = self.make_helper(journal=MemoryPersistentJournal())
        original_attestor = helper._confinement_attestor

        def disable_second(peer, request, at):
            nonlocal attestation_calls
            attestation_calls += 1
            self.flags["enforcing"] = attestation_calls != 2
            return original_attestor(peer, request, at)

        helper._confinement_attestor = disable_second
        self.denied(
            DenialReason.CONFINEMENT_NOT_ENFORCING,
            self.unsigned("confinement-disabled-second"),
            helper=helper,
        )
        self.flags["enforcing"] = True

        binder_calls = 0
        helper = self.make_helper(journal=MemoryPersistentJournal())
        original_binder = helper._device_binder

        def substitute_second(assignment, peer, request, at):
            nonlocal binder_calls
            binder_calls += 1
            if binder_calls == 2:
                self.overrides["device_request"] = "0" * 64
            return original_binder(assignment, peer, request, at)

        helper._device_binder = substitute_second
        self.denied(
            DenialReason.DEVICE_BINDING_MISMATCH,
            self.device_request("device-substituted-second"),
            helper=helper,
        )
        self.overrides.clear()

    def test_clock_is_resampled_and_deadline_rechecked_immediately_before_dispatch(self):
        calls = 0

        def clock():
            nonlocal calls
            calls += 1
            return self.now if calls < 5 else self.now + timedelta(minutes=2)

        helper = self.make_helper(clock=clock, journal=MemoryPersistentJournal())
        self.denied(DenialReason.REQUEST_EXPIRED, self.unsigned("late-dispatch"), helper=helper)
        self.assertGreaterEqual(calls, 5)
        self.assertEqual([], self.executor.effects)

    def test_peer_is_reauthenticated_immediately_before_dispatch(self):
        authentications = 0
        helper = self.make_helper(journal=MemoryPersistentJournal())

        def revoked_after_first_check(peer, at):
            nonlocal authentications
            authentications += 1
            return authentications == 1

        helper._peer_authenticator = revoked_after_first_check
        self.denied(
            DenialReason.PEER_AUTHENTICATION_FAILED,
            self.unsigned("peer-revoked-during-hooks"),
            helper=helper,
        )
        self.assertEqual(2, authentications)
        self.assertEqual([], self.executor.effects)

    def test_peer_revoked_during_final_snapshot_is_denied_before_dispatch(self):
        attestations = 0
        helper = self.make_helper(journal=MemoryPersistentJournal())
        original_attestor = helper._confinement_attestor

        def revoke_during_final_snapshot(peer, request, at):
            nonlocal attestations
            attestations += 1
            evidence = original_attestor(peer, request, at)
            if attestations == 2:
                self.flags["peer"] = False
            return evidence

        helper._confinement_attestor = revoke_during_final_snapshot
        self.denied(
            DenialReason.PEER_AUTHENTICATION_FAILED,
            self.unsigned("peer-revoked-in-final-snapshot"),
            helper=helper,
        )
        self.assertEqual(2, attestations)
        self.assertEqual([], self.executor.effects)
        self.flags["peer"] = True

    def test_guard_precedes_reentrant_clock_and_authenticator_callbacks(self):
        nested = self.seal(self.unsigned("nested-from-clock"))
        clock_errors = []
        clock_entered = False
        holder = {}

        def reentrant_clock():
            nonlocal clock_entered
            if not clock_entered:
                clock_entered = True
                try:
                    holder["helper"].handle(nested, peer=self.peer)
                except Exception as exc:
                    clock_errors.append(exc)
            return self.now

        clock_helper = self.make_helper(
            clock=reentrant_clock, journal=MemoryPersistentJournal()
        )
        holder["helper"] = clock_helper
        receipt = clock_helper.handle(
            self.seal(self.unsigned("outer-clock-request")), peer=self.peer
        )
        self.assertEqual("completed", receipt.result_code)
        self.assertEqual(DenialReason.REENTRANT_DISPATCH, clock_errors[0].reason)

        auth_errors = []
        auth_entered = False
        auth_helper = self.make_helper(journal=MemoryPersistentJournal())
        nested_auth = self.seal(self.unsigned("nested-from-authenticator"))

        def reentrant_authenticator(peer, at):
            nonlocal auth_entered
            if not auth_entered:
                auth_entered = True
                try:
                    auth_helper.handle(nested_auth, peer=peer)
                except Exception as exc:
                    auth_errors.append(exc)
            return True

        auth_helper._peer_authenticator = reentrant_authenticator
        receipt = auth_helper.handle(
            self.seal(self.unsigned("outer-auth-request")), peer=self.peer
        )
        self.assertEqual("completed", receipt.result_code)
        self.assertEqual(DenialReason.REENTRANT_DISPATCH, auth_errors[0].reason)

    def test_receipt_records_post_executor_completion_time(self):
        original_execute = self.executor.execute

        def delayed_execute(effect):
            result = original_execute(effect)
            self.now += timedelta(seconds=2)
            return result

        self.executor.execute = delayed_execute
        receipt = self.helper.handle(
            self.seal(self.unsigned("completion-time")), peer=self.peer
        )
        self.assertEqual(self.now, receipt.executed_at)

    def test_native_code_requires_trusted_microvm_or_constrained_runtime(self):
        value = self.device_request(
            "native-process", generated=True, mode=ConfinementMode.PROCESS_SANDBOX.value
        )
        self.denied(DenialReason.NATIVE_CODE_CONFINEMENT_REQUIRED, value)
        for index, mode in enumerate(
            (ConfinementMode.KVM_MICROVM.value, ConfinementMode.QUALIFIED_CONSTRAINED_RUNTIME.value)
        ):
            helper = self.make_helper(journal=MemoryPersistentJournal())
            receipt = helper.handle(
                self.seal(self.device_request(f"native-{index}", generated=True, mode=mode)),
                peer=self.peer,
            )
            self.assertEqual("completed", receipt.result_code)

    def test_alias_traversal_and_type_confused_device_paths_are_rejected(self):
        paths = (
            "//dev/dri/renderD128",
            "/dev/dri/../renderD128",
            "/dev/dri/by-path/pci-0000:01:00.0",
            "/dev/dri/card0",
            "/dev/nvidia0",
            "C:\\Device\\GPU0",
        )
        for index, path in enumerate(paths):
            with self.subTest(path=path):
                value = self.device_request(f"bad-path-{index}")
                value["device_assignment"]["selectors"][0]["path"] = path
                with self.assertRaises(HelperValidationError):
                    parse_helper_request(self.seal(value))

    def test_device_capability_and_signed_certificate_are_exactly_bound(self):
        self.overrides["device_request"] = "0" * 64
        self.denied(DenialReason.DEVICE_BINDING_MISMATCH, self.device_request("bad-device-binding"))
        self.overrides.clear()
        self.flags["certificate_valid"] = False
        self.denied(
            DenialReason.DRIVER_CERTIFICATE_UNTRUSTED,
            self.device_request("untrusted-certificate"),
            helper=self.make_helper(journal=MemoryPersistentJournal()),
        )
        self.flags["certificate_valid"] = True
        value = self.device_request("wrong-certificate-device")
        value["driver_runtime_certificate"]["device_identity_sha256s"] = ["0" * 64]
        self.denied(
            DenialReason.DRIVER_CERTIFICATE_MISMATCH,
            value,
            helper=self.make_helper(journal=MemoryPersistentJournal()),
        )

    def test_completed_replay_survives_restart_and_expiry_without_new_effect(self):
        raw = self.seal(self.unsigned("durable-replay"))
        first = self.helper.handle(raw, peer=self.peer)
        self.now += timedelta(minutes=10)
        calls_before = len(self.calls)
        restarted = self.make_helper()
        second = restarted.handle(raw, peer=self.peer)
        self.assertEqual(first, second)
        self.assertEqual(1, len(self.executor.effects))
        self.assertEqual(calls_before + 1, len(self.calls))  # peer auth only

    def test_changed_replay_conflicts_even_with_recomputed_digest(self):
        original = self.unsigned("changed-replay")
        self.helper.handle(self.seal(original), peer=self.peer)
        changed = deepcopy(original)
        changed["parameters"]["release_sha256"] = "0" * 64
        with self.assertRaises(HelperReplayConflict):
            self.helper.handle(self.seal(changed), peer=self.peer)
        self.assertEqual(1, len(self.executor.effects))

    def test_pending_and_failed_unknown_are_reconciled_across_restart(self):
        self.executor.raise_after_completion = True
        raw = self.seal(self.unsigned("lost-reply"))
        receipt = self.helper.handle(raw, peer=self.peer)
        self.assertEqual("completed", receipt.result_code)
        self.assertEqual(JournalState.COMPLETED, self.journal.records["lost-reply"].state)

        unknown_executor = RecordingExecutor(lambda: self.now)
        unknown_executor.raise_unknown = True
        journal = MemoryPersistentJournal()
        helper = self.make_helper(journal=journal, executor=unknown_executor)
        unknown_raw = self.seal(self.unsigned("unknown-effect"))
        with self.assertRaises(HelperExecutionError):
            helper.handle(unknown_raw, peer=self.peer)
        self.assertEqual(JournalState.FAILED_UNKNOWN, journal.records["unknown-effect"].state)
        restarted = self.make_helper(journal=journal, executor=unknown_executor)
        self.denied(DenialReason.FAILED_UNKNOWN, self.unsigned("unknown-effect"), helper=restarted)
        self.assertEqual(1, len(unknown_executor.effects))

    def test_persistent_pending_record_reconciles_executor_completion_after_restart(self):
        raw = self.seal(self.unsigned("restart-reconcile"))
        source_journal = MemoryPersistentJournal()
        source = self.make_helper(journal=source_journal)
        expected = source.handle(raw, peer=self.peer)
        parsed = parse_helper_request(raw)

        restarted_journal = MemoryPersistentJournal()
        restarted_journal.reserve(
            parsed.request_id,
            parsed.request_sha256,
            "crashed-owner-1234567890",
            self.now,
            self.now + timedelta(minutes=1),
        )
        restarted = self.make_helper(journal=restarted_journal)
        actual = restarted.handle(raw, peer=self.peer)
        self.assertEqual(expected, actual)
        self.assertEqual(JournalState.COMPLETED, restarted_journal.records[parsed.request_id].state)
        self.assertEqual(1, len(self.executor.effects))

    def test_active_pending_request_is_not_executed_concurrently(self):
        raw = self.seal(self.unsigned("pending-request"))
        parsed = parse_helper_request(raw)
        self.journal.reserve(
            parsed.request_id,
            parsed.request_sha256,
            "another-owner-1234567890",
            self.now,
            self.now + timedelta(minutes=1),
        )
        self.denied(DenialReason.REQUEST_IN_PROGRESS, self.unsigned("pending-request"))
        self.assertEqual([], self.executor.effects)

    def test_reentrant_executor_dispatch_is_explicitly_denied_without_deadlock(self):
        raw = self.seal(self.unsigned("reentrant-request"))
        nested = self.seal(self.unsigned("different-nested-request"))
        self.executor.reenter = lambda: self.helper.handle(nested, peer=self.peer)
        receipt = self.helper.handle(raw, peer=self.peer)
        self.assertEqual("completed", receipt.result_code)
        self.assertIsInstance(self.executor.reentrant_error, HelperDenied)
        self.assertEqual(DenialReason.REENTRANT_DISPATCH, self.executor.reentrant_error.reason)

    def test_closed_schema_malformed_and_deep_json_fail_without_effects(self):
        for index, field in enumerate(("command", "shell", "argv", "executable", "register")):
            value = self.unsigned(f"unknown-{index}")
            value["parameters"][field] = "attacker-input"
            with self.assertRaises(HelperValidationError):
                parse_helper_request(self.seal(value))
        value = self.unsigned("float-schema")
        value["schema_version"] = 1.0
        with self.assertRaises(HelperValidationError):
            parse_helper_request(self.seal(value))
        raw = self.seal(self.unsigned("duplicate"))
        duplicate = raw.replace(
            b'"request_id":"duplicate"', b'"request_id":"duplicate","request_id":"other"'
        )
        with self.assertRaises(HelperValidationError):
            parse_helper_request(duplicate)
        nested: object = "x"
        for _ in range(100):
            nested = {"x": nested}
        with self.assertRaises(HelperValidationError):
            parse_helper_request(json.dumps(nested).encode())
        noncanonical_time = self.unsigned("noncanonical-time")
        noncanonical_time["issued_at"] = "2026-9-22T12:00:00Z"
        with self.assertRaises(HelperValidationError):
            parse_helper_request(self.seal(noncanonical_time))
        oversized_integer = b'{"value":' + (b"9" * 5000) + b"}"
        with self.assertRaises(HelperValidationError):
            parse_helper_request(oversized_integer)
        self.assertEqual([], self.executor.effects)


if __name__ == "__main__":
    unittest.main()
