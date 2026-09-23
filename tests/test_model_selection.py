from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import json
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.model_selection import (  # noqa: E402
    JSON_SAFE_INTEGER_MAX,
    AcceleratorDevice,
    ManualOnlyProfile,
    ModelHardwareSnapshot,
    ModelProfile,
    ModelProfileCatalog,
    ModelSelectionDenied,
    ModelSelectionError,
    ResourceReservation,
    assess_model_selection,
    select_model_profile,
)


GIB = 1024**3


class ModelSelectionContractTests(unittest.TestCase):
    runtime_digest = "b" * 64

    def profile(self, **changes: object) -> ModelProfile:
        values: dict[str, object] = {
            "profile_id": "qwen3-4b-q4-cuda",
            "parameter_total": 4_000_000_000,
            "parameter_active_min": 4_000_000_000,
            "parameter_active_max": 4_000_000_000,
            "model_pack_manifest_sha256": "a" * 64,
            "runtime_tuple_sha256": self.runtime_digest,
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
            "certification_state": "not-certified",
        }
        values.update(changes)
        return ModelProfile(**values)  # type: ignore[arg-type]

    def catalog(self, *profiles: ModelProfile) -> ModelProfileCatalog:
        return ModelProfileCatalog(
            1,
            "development-catalog-v1",
            (ManualOnlyProfile(), *profiles),
        )

    def hardware(self, **changes: object) -> ModelHardwareSnapshot:
        values: dict[str, object] = {
            "effective_host_ram_bytes": 8 * GIB,
            "model_storage_bytes": 7 * GIB,
            "supported_runtime_tuple_digests": (self.runtime_digest,),
            "accelerators": (
                AcceleratorDevice(
                    "gpu0",
                    4 * GIB,
                    (self.runtime_digest,),
                    verified=True,
                    available=True,
                ),
            ),
        }
        values.update(changes)
        return ModelHardwareSnapshot(**values)  # type: ignore[arg-type]

    def test_strict_decoding_and_canonical_digests(self) -> None:
        profile = self.profile()
        document = {
            "schema_version": 1,
            "catalog_id": "development-catalog-v1",
            "profiles": [
                ManualOnlyProfile().canonical_payload(),
                profile.canonical_payload(),
            ],
        }
        decoded = ModelProfileCatalog.from_mapping(
            json.loads(json.dumps(document, sort_keys=False))
        )
        reordered = ModelProfileCatalog.from_mapping(
            {
                "profiles": list(reversed(document["profiles"])),
                "catalog_id": document["catalog_id"],
                "schema_version": document["schema_version"],
            }
        )
        self.assertEqual(decoded.digest, reordered.digest)
        self.assertEqual(profile.digest, decoded.profile(profile.profile_id).digest)  # type: ignore[union-attr]
        self.assertEqual(64, len(decoded.digest))

        invalid = dict(profile.canonical_payload())
        invalid["unexpected"] = True
        with self.assertRaises(ModelSelectionError):
            ModelProfile.from_mapping(invalid)
        invalid = dict(profile.canonical_payload())
        invalid["model_pack_manifest_sha256"] = "A" * 64
        with self.assertRaises(ModelSelectionError):
            ModelProfile.from_mapping(invalid)
        snapshot = self.hardware().canonical_payload()
        snapshot["swap_bytes"] = 128 * GIB
        with self.assertRaises(ModelSelectionError):
            ModelHardwareSnapshot.from_mapping(snapshot)

    def test_parameter_boundaries_405b_bools_and_overflow(self) -> None:
        sparse = self.profile(
            profile_id="recognized-405b",
            parameter_total=405_000_000_000,
            parameter_active_min=20_000_000_000,
            parameter_active_max=40_000_000_000,
        )
        self.assertEqual(405_000_000_000, sparse.parameter_total)
        for field in (
            "parameter_total",
            "parameter_active_min",
            "parameter_active_max",
            "install_bytes",
            "storage_peak_bytes",
            "minimum_host_ram_bytes",
            "minimum_accelerator_memory_bytes",
            "context_tokens",
        ):
            with self.subTest(field=field), self.assertRaises(ModelSelectionError):
                self.profile(**{field: True})
        with self.assertRaises(ModelSelectionError):
            self.profile(parameter_total=JSON_SAFE_INTEGER_MAX + 1)
        with self.assertRaises(ModelSelectionError):
            self.profile(parameter_active_min=5, parameter_active_max=4)
        with self.assertRaises(ModelSelectionError):
            self.profile(parameter_total=4, parameter_active_max=5)

    def test_exact_resource_thresholds_and_selection_binding(self) -> None:
        profile = self.profile()
        catalog = self.catalog(profile)
        hardware = self.hardware()
        assessment = assess_model_selection(
            catalog, hardware, profile_id=profile.profile_id
        )
        self.assertTrue(assessment.selection_permitted)
        self.assertEqual("gpu0", assessment.selected_accelerator_id)
        selection = select_model_profile(
            catalog, hardware, profile_id=profile.profile_id
        )
        self.assertEqual(profile.digest, selection.profile_sha256)
        self.assertEqual(catalog.digest, selection.catalog_sha256)
        self.assertEqual(hardware.digest, selection.hardware_snapshot_sha256)
        self.assertEqual(64, len(selection.digest))

        cases = (
            (
                self.hardware(effective_host_ram_bytes=8 * GIB - 1),
                "host-memory:insufficient",
            ),
            (
                self.hardware(model_storage_bytes=7 * GIB - 1),
                "model-storage:insufficient",
            ),
            (
                self.hardware(
                    accelerators=(
                        replace(self.hardware().accelerators[0], memory_bytes=4 * GIB - 1),
                    )
                ),
                "accelerator-memory:insufficient",
            ),
        )
        for snapshot, reason in cases:
            with self.subTest(reason=reason):
                denied = assess_model_selection(
                    catalog, snapshot, profile_id=profile.profile_id
                )
                self.assertFalse(denied.selection_permitted)
                self.assertIn(reason, denied.reasons)

    def test_cpu_and_cuda_profiles_have_distinct_device_requirements(self) -> None:
        cpu = self.profile(
            profile_id="qwen3-4b-q4-cpu",
            execution_mode="cpu",
            minimum_accelerator_memory_bytes=0,
            load_reservations=(ResourceReservation("host", 6 * GIB),),
            serve_reservations=(ResourceReservation("host", 8 * GIB),),
        )
        cuda = self.profile()
        catalog = self.catalog(cpu, cuda)
        no_gpu = self.hardware(accelerators=())
        self.assertTrue(
            assess_model_selection(catalog, no_gpu, profile_id=cpu.profile_id).selection_permitted
        )
        denied = assess_model_selection(
            catalog, no_gpu, profile_id=cuda.profile_id
        )
        self.assertEqual(
            ("accelerator:unavailable", "accelerator:no-single-qualifying-device"),
            denied.reasons,
        )

    def test_cuda_requires_one_same_verified_available_device(self) -> None:
        profile = self.profile()
        catalog = self.catalog(profile)
        split_capabilities = (
            AcceleratorDevice(
                "gpu-memory-only",
                8 * GIB,
                ("c" * 64,),
                verified=True,
                available=True,
            ),
            AcceleratorDevice(
                "gpu-runtime-only",
                2 * GIB,
                (self.runtime_digest,),
                verified=True,
                available=True,
            ),
        )
        denied = assess_model_selection(
            catalog,
            self.hardware(accelerators=split_capabilities),
            profile_id=profile.profile_id,
        )
        self.assertFalse(denied.selection_permitted)
        self.assertIn("accelerator-memory:insufficient", denied.reasons)
        self.assertIn("accelerator:no-single-qualifying-device", denied.reasons)

    def test_storage_peak_includes_staging_and_rollback(self) -> None:
        with self.assertRaises(ModelSelectionError):
            self.profile(install_bytes=7 * GIB, storage_peak_bytes=7 * GIB - 1)
        profile = self.profile()
        assessment = assess_model_selection(
            self.catalog(profile),
            self.hardware(model_storage_bytes=profile.install_bytes),
            profile_id=profile.profile_id,
        )
        self.assertEqual(("model-storage:insufficient",), assessment.reasons)

    def test_manual_only_needs_no_runtime_memory_storage_or_accelerator(self) -> None:
        catalog = self.catalog(self.profile())
        empty = ModelHardwareSnapshot(0, 0, (), ())
        assessment = assess_model_selection(
            catalog, empty, profile_id="manual-only"
        )
        self.assertTrue(assessment.selection_permitted)
        selection = select_model_profile(catalog, empty, profile_id="manual-only")
        self.assertEqual("manual-only", selection.execution_mode)
        self.assertIsNone(selection.model_pack_manifest_sha256)
        self.assertIsNone(selection.runtime_tuple_sha256)

    def test_unknown_unverified_and_unavailable_profiles_are_denied(self) -> None:
        verified = self.profile()
        unverified = self.profile(
            profile_id="unverified", verification_state="unverified"
        )
        unavailable = self.profile(
            profile_id="unavailable", availability="unavailable"
        )
        catalog = self.catalog(verified, unverified, unavailable)
        expected = {
            "missing": "profile:unknown",
            "unverified": "profile:unverified",
            "unavailable": "profile:unavailable",
        }
        for profile_id, reason in expected.items():
            with self.subTest(profile_id=profile_id):
                assessment = assess_model_selection(
                    catalog, self.hardware(), profile_id=profile_id
                )
                self.assertEqual((reason,), assessment.reasons)
                with self.assertRaises(ModelSelectionDenied) as caught:
                    select_model_profile(
                        catalog, self.hardware(), profile_id=profile_id
                    )
                self.assertEqual(assessment, caught.exception.assessment)

    def test_requested_cuda_profile_never_falls_back_to_cpu(self) -> None:
        cpu = self.profile(
            profile_id="qwen3-4b-q4-cpu",
            execution_mode="cpu",
            minimum_accelerator_memory_bytes=0,
            load_reservations=(ResourceReservation("host", 6 * GIB),),
            serve_reservations=(ResourceReservation("host", 8 * GIB),),
        )
        cuda = self.profile()
        catalog = self.catalog(cpu, cuda)
        denied = assess_model_selection(
            catalog, self.hardware(accelerators=()), profile_id=cuda.profile_id
        )
        self.assertFalse(denied.selection_permitted)
        self.assertEqual(cuda.profile_id, denied.requested_profile_id)
        self.assertEqual("cuda", denied.execution_mode)
        self.assertNotEqual(cpu.digest, denied.profile_sha256)

    def test_profile_invariants_reject_remote_fallback_and_phase_mismatch(self) -> None:
        with self.assertRaises(ModelSelectionError):
            self.profile(remote_fallback=True)
        with self.assertRaises(ModelSelectionError):
            self.profile(
                minimum_host_ram_bytes=5 * GIB,
                serve_reservations=(ResourceReservation("host", 6 * GIB),),
            )
        with self.assertRaises(ModelSelectionError):
            self.profile(
                execution_mode="cpu",
                minimum_accelerator_memory_bytes=0,
            )


if __name__ == "__main__":
    unittest.main()
