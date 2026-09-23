from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.catalog_admission import commit_catalog_admission  # noqa: E402
from luma_os.installation_source import (  # noqa: E402
    ValidatedInstallationSource,
    validate_installation_source,
)
from luma_os.installer import (  # noqa: E402
    ConfirmationDenied,
    InstallationSourceChanged,
    InstallationSourceDenied,
    InstallationSourceInput,
    InstallerContract,
    InstallerValidationError,
    InventoryChanged,
)
from luma_os.model_selection import (  # noqa: E402
    AcceleratorDevice,
    ModelHardwareSnapshot,
    ModelProfile,
)
from tests import test_catalog_admission as catalog_fixtures  # noqa: E402
from tests import test_installer as installer_fixtures  # noqa: E402


GIB = 1024**3


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


class RecordingSourceProvider:
    def __init__(self, factory, *, before_call=None) -> None:
        self.factory = factory
        self.before_call = before_call or (lambda _count: None)
        self.calls = 0

    def __call__(self):
        self.calls += 1
        self.before_call(self.calls)
        return self.factory(self.calls)


class InstallerSourceV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.installer = installer_fixtures.InstallerContractTests()
        self.installer.setUp()
        self.catalog_fixture = catalog_fixtures.CatalogAdmissionTests()
        self.catalog_fixture.setUp()
        plan, self.catalog_anchor, _ = self.catalog_fixture.prepare()
        self.catalog_admission = commit_catalog_admission(
            plan,
            anchor=self.catalog_anchor,
        )
        self.profile = next(
            profile
            for profile in self.catalog_admission.catalog.profiles
            if isinstance(profile, ModelProfile)
        )
        self.model_hardware = self.hardware_for_profile(self.profile)
        self.raw_descriptor = canonical_bytes(self.descriptor())
        self.expected_digest = hashlib.sha256(self.raw_descriptor).hexdigest()

    def descriptor(self, **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": 1,
            "source_kind": "offline-ubuntu-installation-source",
            "environment": "production",
            "release_id": "0.1.0",
            "ubuntu_release": "24.04",
            "target_architecture": "amd64",
            "base_image_sha256": "a" * 64,
            "os_payload_sha256": self.installer.edition.payload_sha256,
            "release_metadata_sha256": self.installer.edition.release_sha256,
            "offline_package_lock_sha256": "d" * 64,
            "sbom_sha256": "e" * 64,
            "packages": [
                {
                    "name": "base-files",
                    "version": "13ubuntu10.2",
                    "architecture": "amd64",
                    "size_bytes": 8192,
                    "sha256": "1" * 64,
                }
            ],
        }
        value.update(changes)
        return value

    @staticmethod
    def hardware_for_profile(
        profile: ModelProfile,
        *,
        accelerator_memory_bytes: int = 16 * GIB,
    ) -> ModelHardwareSnapshot:
        return ModelHardwareSnapshot(
            effective_host_ram_bytes=64 * GIB,
            model_storage_bytes=64 * GIB,
            supported_runtime_tuple_digests=(profile.runtime_tuple_sha256,),
            accelerators=(
                AcceleratorDevice(
                    "gpu-source-test",
                    accelerator_memory_bytes,
                    (profile.runtime_tuple_sha256,),
                    verified=True,
                    available=True,
                ),
            ),
        )

    def source_input(
        self,
        *,
        raw: bytes | None = None,
        expected_sha256: str | None = None,
        environment: str = "production",
        catalog_admission=None,
    ) -> InstallationSourceInput:
        return InstallationSourceInput(
            raw_descriptor=raw if raw is not None else self.raw_descriptor,
            expected_descriptor_sha256=(
                expected_sha256
                if expected_sha256 is not None
                else self.expected_digest
            ),
            expected_environment=environment,
            catalog_admission=catalog_admission or self.catalog_admission,
        )

    def preflight(
        self,
        *,
        contract: InstallerContract | None = None,
        edition=None,
        inventory=None,
        raw: bytes | None = None,
        expected_sha256: str | None = None,
        environment: str = "production",
        catalog_admission=None,
        model_hardware: ModelHardwareSnapshot | None = None,
        profile_id: str | None = None,
        model_catalog=None,
    ):
        return (contract or self.installer.contract).preflight(
            inventory or self.installer.inventory(),
            edition or self.installer.edition,
            selected_disk_id=self.installer.disk.stable_id,
            model_catalog=model_catalog,
            model_hardware=model_hardware or self.model_hardware,
            selected_model_profile_id=profile_id or self.profile.profile_id,
            installation_source_descriptor=(
                raw if raw is not None else self.raw_descriptor
            ),
            installation_source_expected_sha256=(
                expected_sha256
                if expected_sha256 is not None
                else self.expected_digest
            ),
            installation_source_expected_environment=environment,
            installation_source_catalog_admission=(
                catalog_admission or self.catalog_admission
            ),
        )

    def execute(
        self,
        plan,
        confirmation,
        *,
        contract: InstallerContract | None = None,
        source_provider=None,
        model_hardware_provider=None,
        executor=None,
    ):
        selected = contract or self.installer.contract
        if self.installer.clock_value <= self.installer.now:
            self.installer.clock_value = self.installer.now + timedelta(seconds=2)
        return selected.execute(
            plan,
            confirmation,
            authorization=self.installer.authorization,
            inventory_provider=self.installer.fresh_inventory,
            executor=executor or (lambda _plan, _capability: "installed"),
            model_hardware_provider=(
                model_hardware_provider or (lambda: self.model_hardware)
            ),
            installation_source_provider=(
                source_provider
                or RecordingSourceProvider(lambda _count: self.source_input())
            ),
        )

    def test_schema_v3_binds_source_catalog_model_and_confirmation(self) -> None:
        result = self.preflight()
        plan = result.plan
        self.assertEqual(3, plan.schema_version)
        self.assertIsNotNone(plan.model_selection)
        self.assertEqual(
            plan.installation_source_catalog_sha256,
            plan.model_selection.catalog_sha256,  # type: ignore[union-attr]
        )
        self.assertEqual(self.expected_digest, plan.installation_source_expected_sha256)
        self.assertEqual(self.expected_digest, plan.installation_source_descriptor_sha256)
        self.assertEqual("production", plan.installation_source_environment)
        source_payload = plan.canonical_payload()["installation_source"]
        self.assertIs(source_payload["authority"], False)  # type: ignore[index]
        self.assertIs(source_payload["governed_pin_evidence"], False)  # type: ignore[index]
        self.assertIs(source_payload["artifact_bytes_verified"], False)  # type: ignore[index]

        confirmation = self.installer.confirmation(plan)
        self.assertEqual(
            plan.installation_source_validation_receipt_sha256,
            confirmation.installation_source_validation_receipt_sha256,
        )
        self.assertEqual(
            plan.installation_source_expected_sha256,
            confirmation.installation_source_expected_sha256,
        )
        self.assertEqual("production", confirmation.installation_source_environment)

        provider = RecordingSourceProvider(lambda _count: self.source_input())
        effects: list[str] = []
        installed = self.execute(
            plan,
            confirmation,
            source_provider=provider,
            executor=lambda _plan, _capability: effects.append("effect") or "ok",
        )
        self.assertEqual("ok", installed)
        self.assertEqual(2, provider.calls)
        self.assertEqual(["effect"], effects)

    def test_v3_rejects_model_disabled_mode_and_separate_catalog(self) -> None:
        with self.assertRaisesRegex(InstallerValidationError, "requires model"):
            self.installer.contract.preflight(
                self.installer.inventory(),
                self.installer.edition,
                selected_disk_id=self.installer.disk.stable_id,
                installation_source_descriptor=self.raw_descriptor,
                installation_source_expected_sha256=self.expected_digest,
                installation_source_expected_environment="production",
                installation_source_catalog_admission=self.catalog_admission,
            )
        with self.assertRaisesRegex(InstallerValidationError, "derives model catalog"):
            self.preflight(model_catalog=self.catalog_admission.catalog)
        with self.assertRaisesRegex(InstallerValidationError, "require model selection"):
            replace(self.preflight().plan, model_selection=None)

    def test_preflight_never_accepts_inert_validation_snapshot_as_raw_authority(self) -> None:
        snapshot = validate_installation_source(
            self.raw_descriptor,
            expected_descriptor_sha256=self.expected_digest,
            expected_environment="production",
            edition=self.installer.edition,
            catalog_admission=self.catalog_admission,
        )
        self.assertIsInstance(snapshot, ValidatedInstallationSource)
        with self.assertRaises(InstallationSourceDenied):
            self.preflight(raw=snapshot)  # type: ignore[arg-type]

    def test_first_provider_failure_substitution_or_snapshot_precedes_mutation(self) -> None:
        malicious_raw = canonical_bytes(
            self.descriptor(base_image_sha256="f" * 64)
        )
        malicious_digest = hashlib.sha256(malicious_raw).hexdigest()
        snapshot = validate_installation_source(
            self.raw_descriptor,
            expected_descriptor_sha256=self.expected_digest,
            expected_environment="production",
            edition=self.installer.edition,
            catalog_admission=self.catalog_admission,
        )
        providers = (
            RecordingSourceProvider(
                lambda _count: self.source_input(raw=malicious_raw)
            ),
            RecordingSourceProvider(
                lambda _count: self.source_input(
                    raw=malicious_raw,
                    expected_sha256=malicious_digest,
                )
            ),
            RecordingSourceProvider(lambda _count: snapshot),
            RecordingSourceProvider(
                lambda _count: (_ for _ in ()).throw(OSError("provider failed"))
            ),
        )
        for provider in providers:
            with self.subTest(provider=provider):
                contract = self.installer.make_contract(
                    journal=installer_fixtures.MemoryAttemptJournal()
                )
                plan = self.preflight(contract=contract).plan
                confirmation = self.installer.confirmation(plan, contract=contract)
                binder_count = len(self.installer.binder.calls)
                with self.assertRaises(InstallationSourceChanged):
                    self.execute(
                        plan,
                        confirmation,
                        contract=contract,
                        source_provider=provider,
                    )
                self.assertEqual(binder_count, len(self.installer.binder.calls))
                self.assertIsNone(
                    contract._attempt_journal.load(plan.digest)  # type: ignore[attr-defined]
                )

    def test_second_provider_substitution_fails_before_executor(self) -> None:
        malicious_raw = canonical_bytes(
            self.descriptor(base_image_sha256="f" * 64)
        )
        provider = RecordingSourceProvider(
            lambda count: (
                self.source_input()
                if count == 1
                else self.source_input(raw=malicious_raw)
            )
        )
        plan = self.preflight().plan
        confirmation = self.installer.confirmation(plan)
        effects: list[str] = []
        with self.assertRaises(InstallationSourceChanged):
            self.execute(
                plan,
                confirmation,
                source_provider=provider,
                executor=lambda _plan, _capability: effects.append("effect"),
            )
        self.assertEqual(2, provider.calls)
        self.assertEqual([], effects)
        self.assertEqual("in_doubt", self.installer.journal.records[plan.digest].state)

    def test_catalog_advance_denies_before_binder_or_journal(self) -> None:
        plan = self.preflight().plan
        confirmation = self.installer.confirmation(plan)
        second_plan, _, _ = self.catalog_fixture.prepare(
            anchor=self.catalog_anchor,
            sequence=2,
        )
        commit_catalog_admission(second_plan, anchor=self.catalog_anchor)
        binder_count = len(self.installer.binder.calls)
        with self.assertRaises(InstallationSourceChanged):
            self.execute(plan, confirmation)
        self.assertEqual(binder_count, len(self.installer.binder.calls))
        self.assertNotIn(plan.digest, self.installer.journal.records)

    def test_trust_advance_denies_before_binder_or_journal(self) -> None:
        trust_context = self.catalog_fixture.anchored_trust(with_context=True)
        first_trust = trust_context[0]
        catalog_plan, catalog_anchor, _ = self.catalog_fixture.prepare(
            trust_bundle=first_trust,
        )
        admission = commit_catalog_admission(
            catalog_plan,
            anchor=catalog_anchor,
        )
        plan = self.preflight(catalog_admission=admission).plan
        confirmation = self.installer.confirmation(plan)
        self.catalog_fixture.advance_trust(trust_context)
        binder_count = len(self.installer.binder.calls)
        provider = RecordingSourceProvider(
            lambda _count: self.source_input(catalog_admission=admission)
        )
        with self.assertRaises(InstallationSourceChanged):
            self.execute(plan, confirmation, source_provider=provider)
        self.assertEqual(binder_count, len(self.installer.binder.calls))
        self.assertNotIn(plan.digest, self.installer.journal.records)

    def test_final_provider_revocation_is_seen_by_effect_time_authorization(self) -> None:
        def revoke_on_final(count: int) -> None:
            if count == 2:
                self.installer.authorizer.generation += 1

        provider = RecordingSourceProvider(
            lambda _count: self.source_input(),
            before_call=revoke_on_final,
        )
        plan = self.preflight().plan
        confirmation = self.installer.confirmation(plan)
        effects: list[str] = []
        with self.assertRaises(ConfirmationDenied):
            self.execute(
                plan,
                confirmation,
                source_provider=provider,
                executor=lambda _plan, _capability: effects.append("effect"),
            )
        self.assertEqual([], effects)

    def test_final_currentness_check_catches_revocation_during_authorization(self) -> None:
        plan = self.preflight().plan
        confirmation = self.installer.confirmation(plan)
        advanced = False

        def advance_catalog_during_authorization() -> None:
            nonlocal advanced
            if advanced:
                return
            advanced = True
            replacement, _, _ = self.catalog_fixture.prepare(
                anchor=self.catalog_anchor,
                sequence=2,
            )
            commit_catalog_admission(replacement, anchor=self.catalog_anchor)

        self.installer.authorizer.before_return = advance_catalog_during_authorization
        effects: list[str] = []
        with self.assertRaises(InstallationSourceChanged):
            self.execute(
                plan,
                confirmation,
                executor=lambda _plan, _capability: effects.append("effect"),
            )
        self.assertTrue(advanced)
        self.assertEqual([], effects)

    def test_final_source_call_precedes_fresh_model_hardware_sample(self) -> None:
        hardware_state = {"value": self.model_hardware}

        def mutate_hardware_on_final(count: int) -> None:
            if count == 2:
                hardware_state["value"] = self.hardware_for_profile(
                    self.profile,
                    accelerator_memory_bytes=1,
                )

        provider = RecordingSourceProvider(
            lambda _count: self.source_input(),
            before_call=mutate_hardware_on_final,
        )
        plan = self.preflight().plan
        confirmation = self.installer.confirmation(plan)
        effects: list[str] = []
        with self.assertRaises(InventoryChanged):
            self.execute(
                plan,
                confirmation,
                source_provider=provider,
                model_hardware_provider=lambda: hardware_state["value"],
                executor=lambda _plan, _capability: effects.append("effect"),
            )
        self.assertEqual([], effects)

    def test_closed_architecture_mapping_accepts_both_pairs_and_denies_mismatch(self) -> None:
        amd64_plan = self.preflight().plan
        self.assertEqual("x86_64", amd64_plan.architecture)

        arm_edition = replace(
            self.installer.edition,
            supported_architectures=("aarch64",),
        )
        arm_descriptor = self.descriptor(
            target_architecture="arm64",
            packages=[
                {
                    "name": "base-files",
                    "version": "13ubuntu10.2",
                    "architecture": "arm64",
                    "size_bytes": 8192,
                    "sha256": "1" * 64,
                }
            ],
        )
        arm_raw = canonical_bytes(arm_descriptor)
        arm_plan = self.preflight(
            edition=arm_edition,
            inventory=self.installer.inventory(architecture="aarch64"),
            raw=arm_raw,
            expected_sha256=hashlib.sha256(arm_raw).hexdigest(),
        ).plan
        self.assertEqual("aarch64", arm_plan.architecture)

        with self.assertRaises(InstallationSourceDenied):
            self.preflight(
                edition=arm_edition,
                inventory=self.installer.inventory(architecture="aarch64"),
            )

    def test_contract_environment_policy_rejects_lab_unless_explicit(self) -> None:
        lab_plan, lab_anchor, _ = self.catalog_fixture.prepare(environment="lab")
        lab_admission = commit_catalog_admission(lab_plan, anchor=lab_anchor)
        lab_descriptor = self.descriptor(environment="lab")
        lab_raw = canonical_bytes(lab_descriptor)
        lab_digest = hashlib.sha256(lab_raw).hexdigest()
        with self.assertRaises(InstallationSourceDenied):
            self.preflight(
                raw=lab_raw,
                expected_sha256=lab_digest,
                environment="lab",
                catalog_admission=lab_admission,
            )

        lab_contract = InstallerContract(
            issuer_id="installer-lab",
            contract_policy_version=5,
            effect_authorizer=self.installer.authorizer,
            device_binder=self.installer.binder,
            attempt_journal=installer_fixtures.MemoryAttemptJournal(),
            clock=lambda: self.installer.clock_value,
            installation_source_environment="lab",
        )
        lab_result = self.preflight(
            contract=lab_contract,
            raw=lab_raw,
            expected_sha256=lab_digest,
            environment="lab",
            catalog_admission=lab_admission,
        )
        self.assertEqual("lab", lab_result.plan.installation_source_environment)

    def test_confirmation_source_binding_tamper_is_denied(self) -> None:
        plan = self.preflight().plan
        confirmation = self.installer.confirmation(plan)
        tampered = replace(
            confirmation,
            installation_source_expected_sha256="f" * 64,
        )
        with self.assertRaises(ConfirmationDenied):
            self.execute(plan, tampered)


if __name__ == "__main__":
    unittest.main()
