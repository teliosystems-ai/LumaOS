from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sys
import threading
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.installer import (  # noqa: E402
    AuthorizationContext,
    ConfirmationDenied,
    ConfirmationReplay,
    DiskRecord,
    EditionSpec,
    HardwareDevice,
    HardwareInventory,
    InstallationAttempt,
    InstallationConfirmation,
    InstallerContract,
    InstallerValidationError,
    InventoryChanged,
    InventoryStale,
    PartitionSpec,
    PreflightDenied,
    VerifiedDeviceCapability,
)


MIB = 1024 * 1024


class OpaqueHandle:
    pass


class MemoryAttemptJournal:
    """Test double whose state persists when a contract is reconstructed."""

    def __init__(self) -> None:
        self.records: dict[str, InstallationAttempt] = {}
        self._lock = threading.Lock()

    def load(self, plan_digest: str) -> InstallationAttempt | None:
        with self._lock:
            return self.records.get(plan_digest)

    def begin(self, attempt: InstallationAttempt) -> bool:
        with self._lock:
            if attempt.plan_digest in self.records:
                return False
            self.records[attempt.plan_digest] = attempt
            return True

    def complete(
        self, plan_digest: str, confirmation_id: str, completed_at: datetime
    ) -> None:
        with self._lock:
            current = self.records[plan_digest]
            if current.confirmation_id != confirmation_id or current.state != "in_doubt":
                raise RuntimeError("attempt journal completion conflict")
            self.records[plan_digest] = replace(
                current, state="completed", completed_at=completed_at
            )


class TestAuthorizer:
    def __init__(self, principal: str, session: str, generation: int) -> None:
        self.principal = principal
        self.session = session
        self.generation = generation
        self.allow = True
        self.calls: list[tuple[AuthorizationContext, str]] = []
        self.before_return = lambda: None

    def __call__(self, authorization: AuthorizationContext, activity: str) -> int:
        self.calls.append((authorization, activity))
        if (
            not self.allow
            or authorization.principal_id != self.principal
            or authorization.session_id != self.session
        ):
            raise PermissionError("Admin activity denied")
        self.before_return()
        return self.generation


class TestBinder:
    def __init__(self) -> None:
        self.calls: list[tuple[object, object]] = []
        self.swap_identity = False
        self.before_return = lambda: None

    def __call__(self, plan, inventory) -> VerifiedDeviceCapability:
        self.calls.append((plan, inventory))
        self.before_return()
        return VerifiedDeviceCapability(
            capability_id="capability-1",
            plan_digest=plan.digest,
            disk_stable_id=plan.selected_disk.stable_id,
            disk_identity_sha256=(
                "f" * 64 if self.swap_identity else plan.selected_disk.identity_sha256
            ),
            inventory_snapshot_id=inventory.snapshot_id,
            opaque_handle=OpaqueHandle(),
        )


class InstallerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
        self.clock_value = self.now
        self.authorization = AuthorizationContext("admin-user", "session-1", 7)
        self.authorizer = TestAuthorizer("admin-user", "session-1", 7)
        self.binder = TestBinder()
        self.journal = MemoryAttemptJournal()
        self.contract = self.make_contract()
        self.disk = DiskRecord(
            stable_id="wwn:5000c500aabbccdd",
            device_fingerprint="d" * 64,
            capacity_bytes=64 * MIB,
            logical_sector_bytes=4096,
            layout_sha256="1" * 64,
        )
        self.accelerator = HardwareDevice(
            stable_id="pci:0000_01_00.0",
            device_class="accelerator",
            support_status="certified",
            memory_bytes=4 * 1024 * MIB,
        )
        self.edition = EditionSpec(
            edition_id="luma-compact",
            policy_version=3,
            payload_sha256="b" * 64,
            release_sha256="c" * 64,
            supported_architectures=("x86_64",),
            minimum_ram_bytes=8 * 1024 * MIB,
            partitions=(
                PartitionSpec("boot", "LUMA_BOOT", "fat32", 4 * MIB),
                PartitionSpec("system", "LUMA_SYSTEM", "ext4", 8 * MIB),
                PartitionSpec("recovery", "LUMA_RECOVERY", "ext4", 4 * MIB),
                PartitionSpec("models", "LUMA_MODELS", "ext4", 16 * MIB),
            ),
            required_device_classes=("accelerator",),
            minimum_accelerator_memory_bytes=2 * 1024 * MIB,
        )

    def make_contract(
        self,
        *,
        journal: MemoryAttemptJournal | None = None,
        issuer_id: str = "installer-a",
        policy_version: int = 5,
    ) -> InstallerContract:
        return InstallerContract(
            issuer_id=issuer_id,
            contract_policy_version=policy_version,
            effect_authorizer=self.authorizer,
            device_binder=self.binder,
            attempt_journal=journal or self.journal,
            clock=lambda: self.clock_value,
        )

    def inventory(
        self,
        *,
        snapshot_id: str = "scan-1",
        captured_at: datetime | None = None,
        disk: DiskRecord | None = None,
        devices: tuple[HardwareDevice, ...] | None = None,
        architecture: str = "x86_64",
        usable_ram_bytes: int = 16 * 1024 * MIB,
        hardware_fingerprint: str = "a" * 64,
    ) -> HardwareInventory:
        return HardwareInventory(
            snapshot_id=snapshot_id,
            hardware_fingerprint=hardware_fingerprint,
            architecture=architecture,
            usable_ram_bytes=usable_ram_bytes,
            disks=(disk or self.disk,),
            devices=devices if devices is not None else (self.accelerator,),
            captured_at=captured_at or self.now,
        )

    def preflight(self, *, contract: InstallerContract | None = None, edition=None):
        return (contract or self.contract).preflight(
            self.inventory(), edition or self.edition, selected_disk_id=self.disk.stable_id
        )

    def confirmation(
        self,
        plan,
        *,
        contract: InstallerContract | None = None,
        confirmation_id: str = "confirm-1",
        authorization: AuthorizationContext | None = None,
    ):
        return (contract or self.contract).confirm(
            plan,
            confirmation_id=confirmation_id,
            authorization=authorization or self.authorization,
            acknowledged_plan_digest=plan.digest,
            acknowledged_disk_id=plan.selected_disk.stable_id,
            acknowledged_disk_identity_sha256=plan.selected_disk.identity_sha256,
            expires_at=self.clock_value + timedelta(seconds=60),
        )

    def fresh_inventory(self, **changes) -> HardwareInventory:
        values = {
            "snapshot_id": "scan-2",
            "captured_at": self.now + timedelta(seconds=1),
        }
        values.update(changes)
        return self.inventory(**values)

    def execute(self, plan, confirmation, *, inventory_provider=None, executor=None):
        return self.contract.execute(
            plan,
            confirmation,
            authorization=self.authorization,
            inventory_provider=inventory_provider or self.fresh_inventory,
            executor=executor or (lambda _plan, _capability: "installed"),
        )

    def test_strict_decoders_and_numeric_types_fail_closed(self) -> None:
        disk_payload = {
            "stable_id": self.disk.stable_id,
            "device_fingerprint": "d" * 64,
            "capacity_bytes": 64 * MIB,
            "logical_sector_bytes": 4096,
            "layout_sha256": "1" * 64,
        }
        self.assertEqual(self.disk, DiskRecord.from_mapping(disk_payload))
        with self.assertRaisesRegex(InstallerValidationError, "unknown fields"):
            DiskRecord.from_mapping({**disk_payload, "device_path": "/dev/sda"})
        with self.assertRaises(InstallerValidationError):
            DiskRecord.from_mapping({**disk_payload, "stable_id": "/dev/sda"})
        with self.assertRaises(InstallerValidationError):
            replace(self.disk, capacity_bytes=True)
        with self.assertRaises(InstallerValidationError):
            replace(self.edition, policy_version=True)
        with self.assertRaises(InstallerValidationError):
            AuthorizationContext("admin-user", "session-1", True)

    def test_duplicate_or_aliased_disk_identities_are_rejected(self) -> None:
        with self.assertRaisesRegex(InstallerValidationError, "stable identities"):
            HardwareInventory(
                "duplicates",
                "a" * 64,
                "x86_64",
                1,
                (self.disk, replace(self.disk, stable_id="wwn:5000C500AABBCCDD")),
                (),
                self.now,
            )
        with self.assertRaisesRegex(InstallerValidationError, "fingerprints"):
            HardwareInventory(
                "aliases",
                "a" * 64,
                "x86_64",
                1,
                (self.disk, replace(self.disk, stable_id="serial:another-disk")),
                (),
                self.now,
            )

    def test_preflight_binds_effects_release_payload_and_policy_versions(self) -> None:
        first = self.preflight()
        self.assertEqual("certified", first.assessment.support_status)
        self.assertEqual(34 * MIB, first.plan.required_disk_bytes)
        self.assertEqual(self.edition.payload_sha256, first.plan.payload_sha256)
        self.assertEqual(self.edition.release_sha256, first.plan.release_sha256)
        self.assertEqual((3, 5), (first.plan.edition_policy_version, first.plan.contract_policy_version))
        self.assertEqual(
            [1 * MIB, 5 * MIB, 13 * MIB, 17 * MIB],
            [effect.start_bytes for effect in first.plan.effects[1:]],
        )
        for variant in (
            replace(self.edition, payload_sha256="e" * 64),
            replace(self.edition, release_sha256="f" * 64),
            replace(self.edition, policy_version=4),
        ):
            self.assertNotEqual(first.plan.digest, self.preflight(edition=variant).plan.digest)

    def test_unissued_cloned_foreign_and_wrong_policy_plans_are_denied(self) -> None:
        plan = self.preflight().plan
        with self.assertRaisesRegex(ConfirmationDenied, "not issued"):
            self.confirmation(replace(plan))
        for contract in (
            self.make_contract(issuer_id="installer-b"),
            self.make_contract(policy_version=4),
        ):
            foreign_plan = self.preflight(contract=contract).plan
            with self.assertRaises(ConfirmationDenied):
                self.confirmation(foreign_plan)

    def test_exact_capacity_and_platform_failures_are_reported(self) -> None:
        required = self.edition.required_disk_bytes
        exact = replace(self.disk, capacity_bytes=required)
        result = self.contract.preflight(
            self.inventory(disk=exact), self.edition, selected_disk_id=exact.stable_id
        )
        self.assertEqual(required, result.plan.selected_disk.capacity_bytes)
        cases = (
            (
                self.inventory(
                    disk=replace(
                        self.disk,
                        capacity_bytes=required - self.disk.logical_sector_bytes,
                    )
                ),
                "disk:insufficient-capacity",
            ),
            (self.inventory(architecture="aarch64"), "architecture:unsupported"),
            (self.inventory(usable_ram_bytes=4 * 1024 * MIB), "memory:insufficient"),
            (self.inventory(devices=()), "accelerator-memory:insufficient-or-unsupported"),
            (self.inventory(disk=replace(self.disk, read_only=True)), "disk:read-only"),
        )
        for inventory, reason in cases:
            with self.subTest(reason=reason), self.assertRaises(PreflightDenied) as caught:
                self.contract.preflight(
                    inventory, self.edition, selected_disk_id=self.disk.stable_id
                )
            self.assertIn(reason, caught.exception.assessment.reasons)

    def test_accelerator_support_and_capacity_are_from_the_same_device(self) -> None:
        certified_small = replace(
            self.accelerator,
            stable_id="pci:small-certified",
            memory_bytes=1 * 1024 * MIB,
        )
        degraded_large = replace(
            self.accelerator,
            stable_id="pci:large-degraded",
            support_status="degraded",
        )
        inventory = self.inventory(devices=(certified_small, degraded_large))
        assessment = self.contract.assess(
            inventory, self.edition, selected_disk_id=self.disk.stable_id
        )
        self.assertEqual("degraded", assessment.support_status)
        self.assertFalse(assessment.installation_permitted)
        with self.assertRaises(PreflightDenied):
            self.contract.preflight(
                inventory, self.edition, selected_disk_id=self.disk.stable_id
            )
        allowed = replace(self.edition, allow_degraded_devices=True)
        self.assertEqual(
            "degraded",
            self.contract.preflight(
                inventory, allowed, selected_disk_id=self.disk.stable_id
            ).assessment.support_status,
        )

    def test_stale_and_future_inventory_never_create_a_plan(self) -> None:
        for captured_at in (
            self.now - timedelta(seconds=301),
            self.now + timedelta(microseconds=1),
        ):
            with self.assertRaises(InventoryStale):
                self.contract.preflight(
                    self.inventory(captured_at=captured_at),
                    self.edition,
                    selected_disk_id=self.disk.stable_id,
                )

    def test_confirmation_and_execution_bind_authenticated_context(self) -> None:
        plan = self.preflight().plan
        confirmation = self.confirmation(plan)
        self.assertEqual(self.authorization, confirmation.authorization)
        self.assertEqual("installer.plan.confirm", self.authorizer.calls[-1][1])
        for context in (
            AuthorizationContext("other-admin", "session-1", 7),
            AuthorizationContext("admin-user", "other-session", 7),
            AuthorizationContext("admin-user", "session-1", 8),
        ):
            with self.subTest(context=context), self.assertRaises(ConfirmationDenied):
                self.contract.execute(
                    plan,
                    confirmation,
                    authorization=context,
                    inventory_provider=self.fresh_inventory,
                    executor=lambda _plan, _cap: None,
                )

    def test_effect_time_revocation_prevents_executor_and_leaves_in_doubt(self) -> None:
        plan = self.preflight().plan
        confirmation = self.confirmation(plan)
        self.clock_value += timedelta(seconds=2)
        self.authorizer.allow = False
        calls: list[object] = []
        with self.assertRaises(PermissionError):
            self.execute(
                plan,
                confirmation,
                executor=lambda _plan, capability: calls.append(capability),
            )
        self.assertEqual([], calls)
        self.assertEqual("in_doubt", self.journal.load(plan.digest).state)  # type: ignore[union-attr]

    def test_slow_discovery_and_binder_cannot_bypass_expiry(self) -> None:
        plan = self.preflight().plan
        confirmation = self.confirmation(plan)
        executor_calls: list[object] = []

        def slow_provider() -> HardwareInventory:
            self.clock_value += timedelta(seconds=61)
            return self.fresh_inventory(captured_at=self.clock_value)

        with self.assertRaises(ConfirmationDenied):
            self.execute(
                plan,
                confirmation,
                inventory_provider=slow_provider,
                executor=lambda _plan, cap: executor_calls.append(cap),
            )
        self.assertEqual([], self.binder.calls)
        self.assertIsNone(self.journal.load(plan.digest))

        self.clock_value = self.now
        journal = MemoryAttemptJournal()
        contract = self.make_contract(journal=journal)
        plan = self.preflight(contract=contract).plan
        confirmation = self.confirmation(plan, contract=contract)
        self.clock_value += timedelta(seconds=1)
        self.binder.before_return = lambda: setattr(
            self, "clock_value", self.clock_value + timedelta(seconds=60)
        )
        with self.assertRaises(ConfirmationDenied):
            contract.execute(
                plan,
                confirmation,
                authorization=self.authorization,
                inventory_provider=self.fresh_inventory,
                executor=lambda _plan, cap: executor_calls.append(cap),
            )
        self.assertEqual([], executor_calls)
        self.assertEqual("in_doubt", journal.load(plan.digest).state)  # type: ignore[union-attr]

        self.clock_value = self.now
        self.binder.before_return = lambda: None
        journal = MemoryAttemptJournal()
        contract = self.make_contract(journal=journal)
        plan = self.preflight(contract=contract).plan
        confirmation = self.confirmation(plan, contract=contract)
        self.clock_value += timedelta(seconds=1)
        self.authorizer.before_return = lambda: setattr(
            self, "clock_value", self.clock_value + timedelta(seconds=60)
        )
        with self.assertRaises(ConfirmationDenied):
            contract.execute(
                plan,
                confirmation,
                authorization=self.authorization,
                inventory_provider=self.fresh_inventory,
                executor=lambda _plan, cap: executor_calls.append(cap),
            )
        self.assertEqual([], executor_calls)
        self.assertEqual("in_doubt", journal.load(plan.digest).state)  # type: ignore[union-attr]

    def test_capability_rejects_paths_and_simulated_identity_swap(self) -> None:
        with self.assertRaises(InstallerValidationError):
            VerifiedDeviceCapability(
                "bad-capability",
                "a" * 64,
                self.disk.stable_id,
                self.disk.identity_sha256,
                "scan-2",
                Path("/dev/sda"),
            )
        plan = self.preflight().plan
        confirmation = self.confirmation(plan)
        self.clock_value += timedelta(seconds=2)
        self.binder.swap_identity = True
        calls: list[object] = []
        with self.assertRaises(InventoryChanged):
            self.execute(
                plan,
                confirmation,
                executor=lambda _plan, cap: calls.append(cap),
            )
        self.assertEqual([], calls)
        self.assertIsNone(self.journal.load(plan.digest))

    def test_executor_receives_capability_and_journal_is_completed(self) -> None:
        plan = self.preflight().plan
        confirmation = self.confirmation(plan)
        self.clock_value += timedelta(seconds=2)
        received: list[object] = []

        def execute(received_plan, capability) -> str:
            self.assertIs(plan, received_plan)
            self.assertIsInstance(capability, VerifiedDeviceCapability)
            self.assertNotIsInstance(capability.opaque_handle, (str, Path))
            received.append(capability)
            return "installed"

        self.assertEqual("installed", self.execute(plan, confirmation, executor=execute))
        self.assertEqual(1, len(received))
        self.assertEqual("completed", self.journal.load(plan.digest).state)  # type: ignore[union-attr]
        with self.assertRaises(ConfirmationReplay):
            self.execute(plan, confirmation)

    def test_in_doubt_attempt_survives_contract_reinstantiation(self) -> None:
        plan = self.preflight().plan
        confirmation = self.confirmation(plan)
        self.clock_value += timedelta(seconds=2)

        def fail(_plan, _capability):
            raise OSError("injected write failure")

        with self.assertRaisesRegex(OSError, "injected write failure"):
            self.execute(plan, confirmation, executor=fail)
        self.assertEqual("in_doubt", self.journal.load(plan.digest).state)  # type: ignore[union-attr]

        self.clock_value = self.now
        reconstructed = self.make_contract(journal=self.journal)
        reproduced = self.preflight(contract=reconstructed).plan
        self.assertEqual(plan.digest, reproduced.digest)
        with self.assertRaises(ConfirmationReplay):
            self.confirmation(
                reproduced,
                contract=reconstructed,
                confirmation_id="confirm-reconstructed",
            )

    def test_revalidation_rejects_reused_stale_or_changed_inventory(self) -> None:
        cases = (
            (self.inventory(), InventoryChanged),
            (
                self.inventory(
                    snapshot_id="scan-old",
                    captured_at=self.now - timedelta(seconds=301),
                ),
                InventoryStale,
            ),
            (self.fresh_inventory(hardware_fingerprint="e" * 64), InventoryChanged),
            (
                self.fresh_inventory(disk=replace(self.disk, layout_sha256="2" * 64)),
                InventoryChanged,
            ),
        )
        for number, (fresh, error) in enumerate(cases, 1):
            with self.subTest(number=number):
                journal = MemoryAttemptJournal()
                contract = self.make_contract(journal=journal)
                plan = self.preflight(contract=contract).plan
                confirmation = self.confirmation(
                    plan, contract=contract, confirmation_id=f"confirm-change-{number}"
                )
                self.clock_value += timedelta(seconds=2)
                calls: list[object] = []
                with self.assertRaises(error):
                    contract.execute(
                        plan,
                        confirmation,
                        authorization=self.authorization,
                        inventory_provider=lambda fresh=fresh: fresh,
                        executor=lambda _plan, cap: calls.append(cap),
                    )
                self.assertEqual([], calls)
                self.clock_value = self.now

    def test_forged_or_expired_confirmation_never_discovers_hardware(self) -> None:
        plan = self.preflight().plan
        confirmation = self.confirmation(plan)
        forged = InstallationConfirmation(
            "not-issued",
            plan.digest,
            plan.selected_disk.stable_id,
            plan.selected_disk.identity_sha256,
            self.authorization,
            self.now,
            self.now + timedelta(seconds=30),
        )
        calls: list[str] = []
        with self.assertRaises(ConfirmationDenied):
            self.execute(
                plan,
                forged,
                inventory_provider=lambda: calls.append("inventory"),  # type: ignore[arg-type]
            )
        self.clock_value = confirmation.expires_at
        with self.assertRaises(ConfirmationDenied):
            self.execute(
                plan,
                confirmation,
                inventory_provider=lambda: calls.append("inventory"),  # type: ignore[arg-type]
            )
        self.assertEqual([], calls)


if __name__ == "__main__":
    unittest.main()
