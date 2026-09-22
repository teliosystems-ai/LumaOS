from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import hmac
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.boot_control import (  # noqa: E402
    MAX_TRIAL_FAILURES,
    BootCommand,
    BootControlValidationError,
    BootObservation,
    CommandKind,
    DataCheckpoint,
    ExternalEvidenceRejected,
    FallbackReadabilityRejected,
    FenceRejected,
    IdempotencyConflict,
    IntegrityStatus,
    InvalidTransition,
    MonotonicAnchorRejected,
    ReleaseArtifact,
    ReleaseIdentity,
    SignatureStatus,
    SlotName,
    SlotStatus,
    StaleGeneration,
    StateAuthenticationRejected,
    TamperRejected,
    TransitionGuards,
    UpdatePhase,
    initial_boot_state,
    transition,
)


class StubAuthenticator:
    def __init__(self) -> None:
        self.key = b"test-only-state-authentication-key"

    def seal(self, payload: bytes) -> str:
        return hmac.new(self.key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, authentication_tag: str) -> bool:
        return hmac.compare_digest(self.seal(payload), authentication_tag)


class StubAnchor:
    def __init__(self) -> None:
        self.values: dict[str, tuple[int, str]] = {}

    def enroll(self, state) -> None:
        self.values[state.controller_id] = (state.generation, state.commitment_sha256)

    def is_current(self, *, controller_id, generation, state_commitment_sha256) -> bool:
        return self.values.get(controller_id) == (generation, state_commitment_sha256)

    def commit(self, update) -> None:
        if update is None:
            return
        expected = (update.expected_generation, update.expected_commitment_sha256)
        if self.values.get(update.controller_id) != expected:
            raise AssertionError("test anchor compare-and-swap failed")
        self.values[update.controller_id] = (
            update.new_generation,
            update.new_commitment_sha256,
        )


class StubBootVerifier:
    def __init__(self) -> None:
        self.receipts: set[str] = set()

    def verify_persisted(self, observation: BootObservation) -> bool:
        return observation.persistence_receipt_sha256 in self.receipts


class StubCheckpointOracle:
    def __init__(self) -> None:
        self.receipts: set[str] = set()
        self.unreadable_manifests: set[str] = set()

    def verify_durable(self, checkpoint: DataCheckpoint) -> bool:
        return checkpoint.durability_receipt_sha256 in self.receipts

    def is_readable(self, checkpoint: DataCheckpoint, release: ReleaseIdentity) -> bool:
        return (
            release.manifest_sha256 not in self.unreadable_manifests
            and checkpoint.schema_id == release.data_compatibility_id
        )


class BootControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authenticator = StubAuthenticator()
        self.anchor = StubAnchor()
        self.boot_verifier = StubBootVerifier()
        self.checkpoint_oracle = StubCheckpointOracle()
        self.guards = TransitionGuards(
            self.authenticator,
            self.anchor,
            self.boot_verifier,
            self.checkpoint_oracle,
        )

    def artifact(
        self,
        name: str,
        digit: str,
        *,
        sequence: int,
        signature: SignatureStatus = SignatureStatus.TRUSTED,
        integrity: IntegrityStatus = IntegrityStatus.VERIFIED,
        compatibility: str = "data-v1",
    ) -> ReleaseArtifact:
        return ReleaseArtifact(
            ReleaseIdentity(
                release_id=name,
                version=f"1.0.{sequence}",
                release_sequence=sequence,
                manifest_sha256=digit * 64,
                root_sha256=("f" if digit != "f" else "e") * 64,
                signer_key_id="release-key-1",
                data_compatibility_id=compatibility,
            ),
            signature,
            integrity,
        )

    def initial(self):
        release = self.artifact("release-1", "1", sequence=1)
        checkpoint = DataCheckpoint(
            7,
            "a" * 64,
            "data-v1",
            release.identity.manifest_sha256,
            1,
            "controller-owner-1",
            "d" * 64,
        )
        self.checkpoint_oracle.receipts.add("d" * 64)
        state = initial_boot_state(
            release,
            controller_id="boot-controller",
            data_checkpoint=checkpoint,
            fence_epoch=1,
            fence_owner_token="controller-owner-1",
            guards=self.guards,
            essential_services=("state-store", "control-plane"),
        )
        self.anchor.enroll(state)
        return state

    def command(self, state, kind: CommandKind, operation_id: str, **values):
        return BootCommand(
            kind,
            operation_id,
            state.generation,
            state.fence_epoch,
            state.fence_owner_token,
            **values,
        )

    def execute(self, state, command):
        result = transition(state, command, guards=self.guards)
        self.anchor.commit(result.anchor_update)
        return result

    def apply(self, state, kind: CommandKind, operation_id: str, **values):
        return self.execute(state, self.command(state, kind, operation_id, **values)).state

    def stage(self, state=None, artifact=None, *, prefix=""):
        state = state or self.initial()
        artifact = artifact or self.artifact("release-2", "2", sequence=2)
        target = SlotName.B if state.active_slot is SlotName.A else SlotName.A
        state = self.apply(
            state,
            CommandKind.BEGIN_DOWNLOAD,
            f"{prefix}begin",
            target_slot=target,
            artifact=replace(
                artifact,
                signature_status=SignatureStatus.MISSING,
                integrity_status=IntegrityStatus.UNKNOWN,
            ),
        )
        state = self.apply(state, CommandKind.DOWNLOAD_COMPLETE, f"{prefix}downloaded")
        state = self.apply(
            state,
            CommandKind.VERIFY_COMPLETE,
            f"{prefix}verified",
            artifact=artifact,
        )
        state = self.apply(state, CommandKind.WRITE_COMPLETE, f"{prefix}written")
        return state, artifact

    def first_boot(self, state=None, artifact=None, *, nonce="boot-attempt-1", prefix=""):
        state, artifact = self.stage(state, artifact, prefix=prefix)
        state = self.apply(state, CommandKind.SELECT_TRIAL, f"{prefix}selected")
        state = self.apply(
            state,
            CommandKind.BEGIN_FIRST_BOOT,
            f"{prefix}booted",
            attempt_nonce=nonce,
        )
        return state, artifact

    def observation(
        self,
        state,
        artifact,
        *,
        nonce=None,
        slot=None,
        manifest=None,
        root=None,
        epoch=None,
        owner=None,
        signature=SignatureStatus.TRUSTED,
        integrity=IntegrityStatus.VERIFIED,
        receipt_digit="9",
        trusted=True,
    ) -> BootObservation:
        receipt = receipt_digit * 64
        if trusted:
            self.boot_verifier.receipts.add(receipt)
        return BootObservation(
            nonce or state.current_attempt_nonce,
            slot or state.target_slot,
            manifest or artifact.identity.manifest_sha256,
            root or artifact.identity.root_sha256,
            signature,
            integrity,
            epoch or state.fence_epoch,
            owner or state.fence_owner_token,
            receipt,
        )

    def attest(self, state, artifact, *, operation="observed", **values):
        observation = self.observation(state, artifact, **values)
        state = self.apply(
            state,
            CommandKind.RECORD_BOOT_OBSERVATION,
            operation,
            boot_observation=observation,
        )
        return state, observation

    def checkpoint(self, state, release, *, generation=8, digest="b", receipt="e"):
        return DataCheckpoint(
            generation,
            digest * 64,
            release.data_compatibility_id,
            release.manifest_sha256,
            state.fence_epoch,
            state.fence_owner_token,
            receipt * 64,
        )

    def test_physical_slot_ids_cannot_alias_and_identities_are_immutable(self) -> None:
        release = self.artifact("release-1", "1", sequence=1)
        checkpoint = DataCheckpoint(
            0, "a" * 64, "data-v1", "1" * 64, 1, "owner", "d" * 64
        )
        with self.assertRaises(BootControlValidationError):
            initial_boot_state(
                release,
                controller_id="controller",
                slot_a_stable_id="same-device",
                slot_b_stable_id="same-device",
                data_checkpoint=checkpoint,
                fence_epoch=1,
                fence_owner_token="owner",
                guards=self.guards,
            )
        state = self.initial()
        with self.assertRaises(FrozenInstanceError):
            state.slot(SlotName.A).identity.stable_id = "changed"  # type: ignore[misc]

    def test_initial_checkpoint_must_be_durable_bound_and_readable(self) -> None:
        release = self.artifact("release-1", "1", sequence=1)
        valid = DataCheckpoint(
            7,
            "a" * 64,
            "data-v1",
            release.identity.manifest_sha256,
            1,
            "controller-owner-1",
            "d" * 64,
        )
        self.checkpoint_oracle.receipts.add("d" * 64)

        variants = (
            replace(valid, writer_release_manifest_sha256="2" * 64),
            replace(valid, schema_id="data-v2"),
            replace(valid, writer_fence_epoch=2),
            replace(valid, writer_owner_token="other-owner"),
            replace(valid, durability_receipt_sha256="e" * 64),
        )
        for index, checkpoint in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ExternalEvidenceRejected):
                initial_boot_state(
                    release,
                    controller_id=f"invalid-initial-{index}",
                    data_checkpoint=checkpoint,
                    fence_epoch=1,
                    fence_owner_token="controller-owner-1",
                    guards=self.guards,
                )

        self.checkpoint_oracle.unreadable_manifests.add(release.identity.manifest_sha256)
        with self.assertRaises(ExternalEvidenceRejected):
            initial_boot_state(
                release,
                controller_id="unreadable-initial",
                data_checkpoint=valid,
                fence_epoch=1,
                fence_owner_token="controller-owner-1",
                guards=self.guards,
            )

    def test_production_module_contains_no_runtime_assert_statements(self) -> None:
        source = (
            Path(__file__).resolve().parents[1] / "src" / "luma_os" / "boot_control.py"
        ).read_text(encoding="utf-8")
        self.assertFalse(
            any(line.lstrip().startswith("assert ") for line in source.splitlines())
        )

    def test_every_transition_requires_authenticated_current_anchored_state(self) -> None:
        state = self.initial()
        command = self.command(state, CommandKind.RECONCILE_POWER_LOSS, "auth-check")
        with self.assertRaises(StateAuthenticationRejected):
            transition(replace(state, authentication_tag="0" * 64), command, guards=self.guards)
        result = self.execute(state, command)
        with self.assertRaises(MonotonicAnchorRejected):
            transition(
                state,
                self.command(state, CommandKind.RECONCILE_POWER_LOSS, "restored-old"),
                guards=self.guards,
            )
        fork = replace(result.state, authentication_tag="pending")
        fork = replace(fork, authentication_tag=self.authenticator.seal(fork.authenticated_bytes))
        self.anchor.values[fork.controller_id] = (fork.generation, "f" * 64)
        with self.assertRaises(MonotonicAnchorRejected):
            transition(
                fork,
                self.command(fork, CommandKind.RECONCILE_POWER_LOSS, "fork"),
                guards=self.guards,
            )

    def test_operation_hash_chain_idempotency_and_generation(self) -> None:
        state = self.initial()
        command = self.command(state, CommandKind.RECONCILE_POWER_LOSS, "replay")
        result = self.execute(state, command)
        replay = transition(result.state, command, guards=self.guards)
        self.assertTrue(replay.receipt.replayed)
        self.assertIsNone(replay.anchor_update)
        record = result.state.operations[0]
        self.assertEqual("0" * 64, record.previous_record_sha256)
        self.assertNotEqual("0" * 64, record.record_sha256)
        with self.assertRaises(BootControlValidationError):
            replace(record, outcome="altered")
        with self.assertRaises(IdempotencyConflict):
            transition(
                result.state,
                replace(command, fence_owner_token="different"),
                guards=self.guards,
            )

    def test_fence_epoch_is_monotonic_and_owner_cannot_aba(self) -> None:
        state = self.initial()
        with self.assertRaises(FenceRejected):
            self.apply(
                state,
                CommandKind.ROTATE_FENCE,
                "skip",
                new_fence_epoch=3,
                new_fence_owner_token="controller-owner-2",
            )
        state = self.apply(
            state,
            CommandKind.ROTATE_FENCE,
            "rotate-2",
            new_fence_epoch=2,
            new_fence_owner_token="controller-owner-2",
        )
        with self.assertRaises(FenceRejected):
            transition(
                state,
                BootCommand(
                    CommandKind.RECONCILE_POWER_LOSS,
                    "stale",
                    state.generation,
                    1,
                    "controller-owner-1",
                ),
                guards=self.guards,
            )
        with self.assertRaises(FenceRejected):
            self.apply(
                state,
                CommandKind.ROTATE_FENCE,
                "aba",
                new_fence_epoch=3,
                new_fence_owner_token="controller-owner-1",
            )

    def test_inactive_slot_only_and_anti_downgrade_sequence(self) -> None:
        state = self.initial()
        with self.assertRaises(InvalidTransition):
            self.apply(
                state,
                CommandKind.BEGIN_DOWNLOAD,
                "active-target",
                target_slot=SlotName.A,
                artifact=self.artifact("release-2", "2", sequence=2),
            )
        staged, _ = self.stage(state)
        self.assertEqual(SlotStatus.ACTIVE, staged.slot(SlotName.A).status)
        self.assertEqual(SlotStatus.STAGED, staged.slot(SlotName.B).status)

        downgrade = self.artifact("release-old", "3", sequence=1)
        downgrade = replace(downgrade, identity=replace(downgrade.identity, version="99.0"))
        state = self.initial()
        state = self.apply(
            state,
            CommandKind.BEGIN_DOWNLOAD,
            "down-begin",
            target_slot=SlotName.B,
            artifact=replace(
                downgrade,
                signature_status=SignatureStatus.MISSING,
                integrity_status=IntegrityStatus.UNKNOWN,
            ),
        )
        state = self.apply(state, CommandKind.DOWNLOAD_COMPLETE, "down-download")
        result = self.execute(
            state,
            self.command(
                state,
                CommandKind.VERIFY_COMPLETE,
                "down-verify",
                artifact=downgrade,
            ),
        )
        self.assertEqual(UpdatePhase.IDLE, result.state.phase)
        self.assertIn("downgrade", result.receipt.outcome)

    def test_observation_must_be_trusted_persisted_and_precede_health(self) -> None:
        state, artifact = self.first_boot()
        untrusted = self.observation(state, artifact, receipt_digit="8", trusted=False)
        with self.assertRaises(ExternalEvidenceRejected):
            self.apply(
                state,
                CommandKind.RECORD_BOOT_OBSERVATION,
                "untrusted",
                boot_observation=untrusted,
            )
        with self.assertRaises(InvalidTransition):
            self.apply(
                state,
                CommandKind.ACK_ESSENTIAL_HEALTH,
                "early-health",
                healthy_services=state.essential_services,
            )
        state, observation = self.attest(state, artifact)
        state = self.apply(
            state,
            CommandKind.ACK_ESSENTIAL_HEALTH,
            "health",
            healthy_services=state.essential_services,
        )
        self.assertEqual(observation.attempt_nonce, state.health_acknowledgement.attempt_nonce)
        self.assertEqual(
            observation.persistence_receipt_sha256,
            state.health_acknowledgement.observation_receipt_sha256,
        )

    def test_boot_nonce_is_unique_and_commit_is_attempt_bound(self) -> None:
        state, artifact = self.first_boot()
        state = self.apply(state, CommandKind.TRIAL_FAILURE, "failure-1")
        with self.assertRaises(InvalidTransition):
            self.apply(
                state,
                CommandKind.BEGIN_FIRST_BOOT,
                "nonce-reuse",
                attempt_nonce="boot-attempt-1",
            )
        state = self.apply(
            state,
            CommandKind.BEGIN_FIRST_BOOT,
            "retry",
            attempt_nonce="boot-attempt-2",
        )
        state, observation = self.attest(state, artifact, receipt_digit="7")
        state = self.apply(
            state,
            CommandKind.ACK_ESSENTIAL_HEALTH,
            "healthy-retry",
            healthy_services=state.essential_services,
        )
        committed = self.apply(state, CommandKind.COMMIT_TRIAL, "commit")
        self.assertEqual("boot-attempt-2", observation.attempt_nonce)
        self.assertEqual(("boot-attempt-1", "boot-attempt-2"), committed.used_attempt_nonces)
        self.assertEqual(SlotName.B, committed.active_slot)
        self.assertEqual(2, committed.minimum_release_sequence)

    def test_attestation_slot_release_and_fence_mismatch_records_tamper(self) -> None:
        variants = (
            {"slot": SlotName.A},
            {"manifest": "e" * 64},
            {"root": "d" * 64},
            {"epoch": 2},
            {"owner": "other-owner"},
            {"nonce": "other-attempt"},
            {"integrity": IntegrityStatus.MISMATCH},
        )
        for index, values in enumerate(variants):
            with self.subTest(values=values):
                state, staged = self.first_boot(prefix=f"m{index}-")
                observed = self.observation(state, staged, receipt_digit=str(index + 1), **values)
                result = self.execute(
                    state,
                    self.command(
                        state,
                        CommandKind.RECORD_BOOT_OBSERVATION,
                        f"tamper-{index}",
                        boot_observation=observed,
                    ),
                )
                recovered = result.state
                self.assertEqual(UpdatePhase.IDLE, recovered.phase)
                self.assertEqual(SlotName.A, recovered.selected_slot)
                self.assertEqual(staged, recovered.slot(SlotName.B).artifact)
                self.assertEqual(SlotStatus.REJECTED, recovered.slot(SlotName.B).status)
                self.assertEqual(1, len(recovered.tamper_observations))

    def test_checkpoint_requires_receipt_writer_release_schema_and_fence(self) -> None:
        state = self.initial()
        active = state.slot(state.active_slot).artifact.identity
        checkpoint = self.checkpoint(state, active)
        with self.assertRaises(ExternalEvidenceRejected):
            self.apply(
                state,
                CommandKind.ACK_DATA_CHECKPOINT,
                "unreceipted",
                data_checkpoint=checkpoint,
            )
        self.checkpoint_oracle.receipts.add("e" * 64)
        variants = (
            replace(checkpoint, writer_fence_epoch=2),
            replace(checkpoint, writer_owner_token="other"),
            replace(checkpoint, writer_release_manifest_sha256="f" * 64),
            replace(checkpoint, schema_id="data-v2"),
        )
        for index, changed in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ExternalEvidenceRejected):
                self.apply(
                    state,
                    CommandKind.ACK_DATA_CHECKPOINT,
                    f"bad-binding-{index}",
                    data_checkpoint=changed,
                )
        state = self.apply(
            state,
            CommandKind.ACK_DATA_CHECKPOINT,
            "checkpoint-ok",
            data_checkpoint=checkpoint,
        )
        with self.assertRaises(StaleGeneration):
            self.apply(
                state,
                CommandKind.ACK_DATA_CHECKPOINT,
                "regression",
                data_checkpoint=replace(checkpoint, generation=7, sha256="a" * 64),
            )
        with self.assertRaises(TamperRejected):
            self.apply(
                state,
                CommandKind.ACK_DATA_CHECKPOINT,
                "conflict",
                data_checkpoint=replace(checkpoint, sha256="c" * 64),
            )

    def test_trial_checkpoint_requires_attestation_and_fallback_readability(self) -> None:
        state, artifact = self.first_boot()
        checkpoint = self.checkpoint(state, artifact.identity)
        self.checkpoint_oracle.receipts.add("e" * 64)
        with self.assertRaises(InvalidTransition):
            self.apply(
                state,
                CommandKind.ACK_DATA_CHECKPOINT,
                "data-before-observation",
                data_checkpoint=checkpoint,
            )
        state, _ = self.attest(state, artifact)
        active_manifest = state.slot(SlotName.A).artifact.identity.manifest_sha256
        self.checkpoint_oracle.unreadable_manifests.add(active_manifest)
        with self.assertRaises(FallbackReadabilityRejected):
            self.apply(
                state,
                CommandKind.ACK_DATA_CHECKPOINT,
                "checkpoint-would-break-fallback",
                data_checkpoint=checkpoint,
            )
        self.checkpoint_oracle.unreadable_manifests.clear()
        state = self.apply(
            state,
            CommandKind.ACK_DATA_CHECKPOINT,
            "trial-data",
            data_checkpoint=checkpoint,
        )
        self.checkpoint_oracle.unreadable_manifests.add(active_manifest)
        for failure in range(1, MAX_TRIAL_FAILURES):
            state = self.apply(state, CommandKind.TRIAL_FAILURE, f"failure-{failure}")
            state = self.apply(
                state,
                CommandKind.BEGIN_FIRST_BOOT,
                f"retry-{failure}",
                attempt_nonce=f"boot-attempt-{failure + 1}",
            )
        with self.assertRaises(FallbackReadabilityRejected):
            self.apply(state, CommandKind.TRIAL_FAILURE, "unreadable-fallback")
        self.checkpoint_oracle.unreadable_manifests.clear()
        state = self.apply(state, CommandKind.TRIAL_FAILURE, "readable-fallback")
        self.assertEqual(UpdatePhase.IDLE, state.phase)
        self.assertEqual(checkpoint, state.data_checkpoint)
        self.assertEqual(MAX_TRIAL_FAILURES, state.trial_failures)

    def test_power_loss_reconciliation_covers_all_boundaries(self) -> None:
        def interrupted(phase):
            state = self.initial()
            candidate = self.artifact("release-2", "2", sequence=2)
            state = self.apply(
                state,
                CommandKind.BEGIN_DOWNLOAD,
                f"{phase.value}-begin",
                target_slot=SlotName.B,
                artifact=replace(
                    candidate,
                    signature_status=SignatureStatus.MISSING,
                    integrity_status=IntegrityStatus.UNKNOWN,
                ),
            )
            if phase is UpdatePhase.DOWNLOAD:
                return state
            state = self.apply(state, CommandKind.DOWNLOAD_COMPLETE, f"{phase.value}-download")
            if phase is UpdatePhase.VERIFY:
                return state
            state = self.apply(
                state,
                CommandKind.VERIFY_COMPLETE,
                f"{phase.value}-verify",
                artifact=candidate,
            )
            if phase is UpdatePhase.WRITE:
                return state
            state = self.apply(state, CommandKind.WRITE_COMPLETE, f"{phase.value}-write")
            return state

        for phase in (
            UpdatePhase.DOWNLOAD,
            UpdatePhase.VERIFY,
            UpdatePhase.WRITE,
            UpdatePhase.SELECT,
        ):
            with self.subTest(phase=phase):
                state = interrupted(phase)
                checkpoint = state.data_checkpoint
                state = self.apply(
                    state,
                    CommandKind.RECONCILE_POWER_LOSS,
                    f"{phase.value}-recover",
                )
                self.assertEqual(UpdatePhase.IDLE, state.phase)
                self.assertEqual(SlotName.A, state.selected_slot)
                self.assertEqual(checkpoint, state.data_checkpoint)

        state, _ = self.first_boot(prefix="power-")
        for failure in range(1, MAX_TRIAL_FAILURES + 1):
            state = self.apply(
                state,
                CommandKind.RECONCILE_POWER_LOSS,
                f"power-loss-{failure}",
            )
            if failure < MAX_TRIAL_FAILURES:
                state = self.apply(
                    state,
                    CommandKind.BEGIN_FIRST_BOOT,
                    f"power-retry-{failure}",
                    attempt_nonce=f"power-attempt-{failure + 1}",
                )
        self.assertEqual(UpdatePhase.IDLE, state.phase)
        self.assertEqual(SlotName.A, state.selected_slot)


if __name__ == "__main__":
    unittest.main()
