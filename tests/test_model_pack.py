from __future__ import annotations

import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.model_pack import (  # noqa: E402
    CertificationRecord,
    ModelManifest,
    ModelManifestError,
    ModelPackCompatibilityError,
    ModelPackIntegrityError,
    ModelPackState,
    ModelPackVerification,
    PurposeBoundEd25519Verifier,
    RuntimeTuple,
    SigningPurpose,
    SigningRole,
    TrustKeyRecord,
    apply_certification,
    canonical_manifest_bytes,
    verify_model_pack,
)
from luma_os.model_selection import (  # noqa: E402
    ModelSelectionError,
    ResourceReservation,
    model_profile_from_verified_pack,
)


class StubVerifier:
    def verify(
        self,
        message: bytes,
        signature: bytes,
        *,
        key_id: str,
        purpose: SigningPurpose,
    ) -> bool:
        return (
            bool(message)
            and signature == b"trusted-signature"
            and key_id == "lab-ed25519-1"
            and isinstance(purpose, SigningPurpose)
        )


class StubRawVerifier:
    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        return bool(message) and signature == b"trusted-signature" and key_id == "lab-ed25519-1"


class ModelPackTests(unittest.TestCase):
    runtime = RuntimeTuple("linux", "x86_64", "llama.cpp", "1.2.3", "cuda:0")

    def build_pack(
        self,
        root: Path,
        *,
        model_contents: tuple[bytes, ...] = (b"small-test-model",),
    ) -> dict[str, object]:
        contents = [
            *(("model", content) for content in model_contents),
            ("tokenizer", b'{"type":"test"}'),
            ("template", b"{{ prompt }}"),
            ("license", b"test license"),
        ]
        declarations = []
        model_shard_index = 0
        for role, content in contents:
            digest = hashlib.sha256(content).hexdigest()
            relative = f"licenses/{digest}.txt" if role == "license" else f"blobs/sha256/{digest}"
            path = root.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            declaration = {
                "role": role,
                "path": relative,
                "sha256": digest,
                "size_bytes": len(content),
            }
            if role == "model":
                declaration["shard_index"] = model_shard_index
                model_shard_index += 1
            declarations.append(declaration)
        template = next(item for item in declarations if item["role"] == "template")
        license_blob = next(item for item in declarations if item["role"] == "license")
        manifest: dict[str, object] = {
            "schema_version": 2,
            "canonicalization": "RFC8785-ASCII-v1",
            "signature_algorithm": "Ed25519",
            "pack_id": "test-compact",
            "pack_version": "1.0.0",
            "model": {
                "architecture": "test-transformer",
                "identity": "test-only/no-weights",
                "parameter_class": "4B",
                "total_parameters": 4_000_000_000,
                "active_parameters_min": 4_000_000_000,
                "active_parameters_max": 4_000_000_000,
                "quantization": "none",
                "required_features": ["chat-completion", "text-generation"],
                "source": "local-test-fixture",
            },
            "context": {"maximum_tokens": 1024, "template_sha256": template["sha256"]},
            "blobs": declarations,
            "runtime_tuples": [
                {
                    "os_family": self.runtime.os_family,
                    "architecture": self.runtime.architecture,
                    "backend": self.runtime.backend,
                    "backend_version": self.runtime.backend_version,
                    "device": self.runtime.device,
                }
            ],
            "installation_profiles": [
                {
                    "profile_id": "test-cuda",
                    "runtime_tuple_sha256": self.runtime.digest,
                    "execution_mode": "cuda",
                    "minimum_host_ram_bytes": 8 * 1024 * 1024 * 1024,
                    "minimum_accelerator_memory_bytes": 4 * 1024 * 1024 * 1024,
                    "minimum_model_storage_bytes": sum(len(content) for _, content in contents),
                    "maximum_context_tokens": 1024,
                }
            ],
            "license": {
                "identifier": "LicenseRef-Test-Only",
                "evaluation": "approved",
                "redistribution": "not-applicable",
                "files": [license_blob["path"]],
            },
            "network_default": "deny",
            "signer_key_id": "lab-ed25519-1",
        }
        (root / "manifest.json").write_bytes(canonical_manifest_bytes(manifest))
        (root / "manifest.sig").write_bytes(b"trusted-signature")
        return manifest

    def test_signed_inventory_reaches_loadable_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_pack(root)
            result = verify_model_pack(root, verifier=StubVerifier(), runtime_tuple=self.runtime)
            self.assertEqual(ModelPackState.LOADABLE, result.state)
            self.assertEqual("test-compact", result.pack_id)

    def test_parameter_counts_cover_governed_boundaries_without_truncation(self) -> None:
        boundaries = (
            4_000_000_000,
            6_000_000_000,
            32_000_000_000,
            70_000_000_000,
            120_000_000_000,
            200_000_000_000,
            400_000_000_000,
            405_000_000_000,
        )
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.build_pack(Path(temporary))
            for parameter_count in boundaries:
                with self.subTest(parameter_count=parameter_count):
                    candidate = copy.deepcopy(manifest)
                    model = candidate["model"]  # type: ignore[assignment]
                    model["total_parameters"] = parameter_count  # type: ignore[index]
                    model["active_parameters_min"] = parameter_count  # type: ignore[index]
                    model["active_parameters_max"] = parameter_count  # type: ignore[index]
                    parsed = ModelManifest.parse(canonical_manifest_bytes(candidate))
                    self.assertEqual(parameter_count, parsed.total_parameters)
                    self.assertEqual(parameter_count, parsed.active_parameters_min)
                    self.assertEqual(parameter_count, parsed.active_parameters_max)

            for field, value in (
                ("total_parameters", True),
                ("active_parameters_min", False),
                ("total_parameters", 0),
            ):
                with self.subTest(field=field, value=value):
                    candidate = copy.deepcopy(manifest)
                    candidate["model"][field] = value  # type: ignore[index]
                    with self.assertRaises(ModelManifestError):
                        ModelManifest.parse(canonical_manifest_bytes(candidate))

            for active_min, active_max, total in (
                (5, 4, 6),
                (4, 7, 6),
            ):
                with self.subTest(active_min=active_min, active_max=active_max, total=total):
                    candidate = copy.deepcopy(manifest)
                    model = candidate["model"]  # type: ignore[assignment]
                    model["total_parameters"] = total  # type: ignore[index]
                    model["active_parameters_min"] = active_min  # type: ignore[index]
                    model["active_parameters_max"] = active_max  # type: ignore[index]
                    with self.assertRaises(ModelManifestError):
                        ModelManifest.parse(canonical_manifest_bytes(candidate))

            overflow = copy.deepcopy(manifest)
            overflow["model"]["total_parameters"] = 1 << 53  # type: ignore[index]
            overflow["model"]["active_parameters_min"] = 1 << 53  # type: ignore[index]
            overflow["model"]["active_parameters_max"] = 1 << 53  # type: ignore[index]
            overflow_raw = json.dumps(
                overflow,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            with self.assertRaises(ModelManifestError):
                ModelManifest.parse(overflow_raw)

    def test_model_shards_are_required_contiguous_unique_and_ordered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.build_pack(
                root,
                model_contents=(b"model-shard-zero", b"model-shard-one", b"model-shard-two"),
            )
            parsed = ModelManifest.parse(canonical_manifest_bytes(manifest))
            self.assertEqual(
                [0, 1, 2],
                [blob.shard_index for blob in parsed.blobs if blob.role == "model"],
            )
            verified = verify_model_pack(
                root, verifier=StubVerifier(), runtime_tuple=self.runtime
            )
            self.assertEqual(ModelPackState.LOADABLE, verified.state)

            model_positions = [
                index
                for index, blob in enumerate(manifest["blobs"])  # type: ignore[arg-type]
                if blob["role"] == "model"
            ]
            malformed = []

            out_of_order = copy.deepcopy(manifest)
            first, second = model_positions[:2]
            out_of_order["blobs"][first], out_of_order["blobs"][second] = (  # type: ignore[index]
                out_of_order["blobs"][second],  # type: ignore[index]
                out_of_order["blobs"][first],  # type: ignore[index]
            )
            malformed.append(out_of_order)

            duplicate = copy.deepcopy(manifest)
            duplicate["blobs"][model_positions[1]]["shard_index"] = 0  # type: ignore[index]
            malformed.append(duplicate)

            gap = copy.deepcopy(manifest)
            gap["blobs"][model_positions[1]]["shard_index"] = 3  # type: ignore[index]
            malformed.append(gap)

            missing = copy.deepcopy(manifest)
            del missing["blobs"][model_positions[0]]["shard_index"]  # type: ignore[index]
            malformed.append(missing)

            for index, candidate in enumerate(malformed):
                with self.subTest(malformed_case=index), self.assertRaises(ModelManifestError):
                    ModelManifest.parse(canonical_manifest_bytes(candidate))

    def test_installation_profiles_bind_runtime_and_validate_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.build_pack(Path(temporary))
            parsed = ModelManifest.parse(canonical_manifest_bytes(manifest))
            profile = parsed.installation_profiles[0]
            self.assertEqual("test-cuda", profile.profile_id)
            self.assertEqual(self.runtime.digest, profile.runtime_tuple_sha256)
            self.assertEqual(
                ("chat-completion", "text-generation"), parsed.required_features
            )
            verification = verify_model_pack(
                Path(temporary), verifier=StubVerifier(), runtime_tuple=self.runtime
            )
            selected = model_profile_from_verified_pack(
                parsed,
                verification,
                installation_profile_id="test-cuda",
                storage_peak_bytes=8 * 1024 * 1024 * 1024,
                load_reservations=(
                    ResourceReservation("host", 8 * 1024 * 1024 * 1024),
                    ResourceReservation("accelerator", 4 * 1024 * 1024 * 1024),
                ),
                serve_reservations=(
                    ResourceReservation("host", 8 * 1024 * 1024 * 1024),
                    ResourceReservation("accelerator", 4 * 1024 * 1024 * 1024),
                ),
                context_tokens=1024,
                development_state="development-tested",
            )
            self.assertEqual(parsed.total_parameters, selected.parameter_total)
            self.assertEqual(verification.manifest_sha256, selected.model_pack_manifest_sha256)
            self.assertEqual(self.runtime.digest, selected.runtime_tuple_sha256)

            with self.assertRaises(ModelSelectionError):
                model_profile_from_verified_pack(
                    parsed,
                    replace(verification, manifest_sha256="f" * 64),
                    installation_profile_id="test-cuda",
                    storage_peak_bytes=8 * 1024 * 1024 * 1024,
                    load_reservations=selected.load_reservations,
                    serve_reservations=selected.serve_reservations,
                    context_tokens=1024,
                    development_state="development-tested",
                )

            with self.assertRaises(ModelManifestError):
                ModelPackVerification(
                    verification.pack_id,
                    verification.pack_version,
                    verification.manifest_sha256,
                    verification.runtime_tuple,
                    2,  # type: ignore[arg-type]
                )

            with self.assertRaises(ModelSelectionError):
                model_profile_from_verified_pack(
                    parsed,
                    verification,
                    installation_profile_id="test-cuda",
                    storage_peak_bytes=8 * 1024 * 1024 * 1024,
                    load_reservations=(
                        ResourceReservation("host", 8 * 1024 * 1024 * 1024),
                        ResourceReservation("accelerator", 4 * 1024 * 1024 * 1024),
                    ),
                    serve_reservations=(
                        ResourceReservation("host", 8 * 1024 * 1024 * 1024),
                        ResourceReservation("accelerator", 4 * 1024 * 1024 * 1024),
                    ),
                    context_tokens=1025,
                    development_state="development-tested",
                )

            field_cases = (
                ("execution_mode", "metal"),
                ("minimum_host_ram_bytes", True),
                ("minimum_host_ram_bytes", 0),
                ("minimum_accelerator_memory_bytes", 0),
                ("minimum_model_storage_bytes", 1),
                ("maximum_context_tokens", 1025),
                ("runtime_tuple_sha256", "f" * 64),
            )
            for field, value in field_cases:
                with self.subTest(field=field, value=value):
                    candidate = copy.deepcopy(manifest)
                    candidate["installation_profiles"][0][field] = value  # type: ignore[index]
                    with self.assertRaises(ModelManifestError):
                        ModelManifest.parse(canonical_manifest_bytes(candidate))

            cpu_with_accelerator = copy.deepcopy(manifest)
            cpu_with_accelerator["installation_profiles"][0]["execution_mode"] = "cpu"  # type: ignore[index]
            with self.assertRaises(ModelManifestError):
                ModelManifest.parse(canonical_manifest_bytes(cpu_with_accelerator))

            duplicate_profile = copy.deepcopy(manifest)
            duplicate_profile["installation_profiles"].append(  # type: ignore[union-attr]
                copy.deepcopy(duplicate_profile["installation_profiles"][0])  # type: ignore[index]
            )
            with self.assertRaises(ModelManifestError):
                ModelManifest.parse(canonical_manifest_bytes(duplicate_profile))

            for required_features in ([], ["text-generation", "text-generation"], ["z", "a"]):
                with self.subTest(required_features=required_features):
                    invalid_features = copy.deepcopy(manifest)
                    invalid_features["model"]["required_features"] = required_features  # type: ignore[index]
                    with self.assertRaises(ModelManifestError):
                        ModelManifest.parse(canonical_manifest_bytes(invalid_features))

            for field in ("architecture", "identity", "parameter_class", "quantization"):
                with self.subTest(overlong_model_field=field):
                    overlong = copy.deepcopy(manifest)
                    overlong["model"][field] = "x" * 513  # type: ignore[index]
                    with self.assertRaises(ModelManifestError):
                        ModelManifest.parse(canonical_manifest_bytes(overlong))

            overflow = copy.deepcopy(manifest)
            overflow["installation_profiles"][0]["minimum_host_ram_bytes"] = 1 << 53  # type: ignore[index]
            overflow_raw = json.dumps(
                overflow,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            with self.assertRaises(ModelManifestError):
                ModelManifest.parse(overflow_raw)

    def test_tampering_undeclared_files_and_runtime_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.build_pack(root)
            model = next(item for item in manifest["blobs"] if item["role"] == "model")  # type: ignore[index]
            root.joinpath(*model["path"].split("/")).write_bytes(b"tampered")  # type: ignore[union-attr]
            with self.assertRaises(ModelPackIntegrityError):
                verify_model_pack(root, verifier=StubVerifier(), runtime_tuple=self.runtime)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_pack(root)
            (root / "undeclared.txt").write_text("no", encoding="ascii")
            with self.assertRaises(ModelPackIntegrityError):
                verify_model_pack(root, verifier=StubVerifier(), runtime_tuple=self.runtime)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_pack(root)
            changed = replace(self.runtime, backend_version="9.9.9")
            with self.assertRaises(ModelPackCompatibilityError):
                verify_model_pack(root, verifier=StubVerifier(), runtime_tuple=changed)

    def test_noncanonical_unknown_and_unsigned_manifests_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.build_pack(root)
            raw = json.dumps(manifest, indent=2).encode("utf-8")
            with self.assertRaises(ModelManifestError):
                ModelManifest.parse(raw)
            legacy = copy.deepcopy(manifest)
            legacy["schema_version"] = 1
            with self.assertRaises(ModelManifestError):
                ModelManifest.parse(canonical_manifest_bytes(legacy))
            manifest["unknown"] = "rejected"
            with self.assertRaises(ModelManifestError):
                ModelManifest.parse(canonical_manifest_bytes(manifest))
            (root / "manifest.sig").write_bytes(b"wrong")
            with self.assertRaises(ModelPackIntegrityError):
                verify_model_pack(root, verifier=StubVerifier(), runtime_tuple=self.runtime)

    def test_unsafe_path_and_unapproved_license_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.build_pack(root)
            manifest["blobs"][0]["path"] = "../escape"  # type: ignore[index]
            with self.assertRaises(ModelManifestError):
                ModelManifest.parse(canonical_manifest_bytes(manifest))

        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.build_pack(Path(temporary))
            model_blob = next(
                item for item in manifest["blobs"] if item["role"] == "model"  # type: ignore[index]
            )
            model_blob["path"] = f"licenses/{model_blob['sha256']}.bin"
            with self.assertRaises(ModelManifestError):
                ModelManifest.parse(canonical_manifest_bytes(manifest))

        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.build_pack(Path(temporary))
            license_blob = next(
                item for item in manifest["blobs"] if item["role"] == "license"  # type: ignore[index]
            )
            license_blob["path"] = f"blobs/sha256/{license_blob['sha256']}"
            manifest["license"]["files"] = [license_blob["path"]]  # type: ignore[index]
            with self.assertRaises(ModelManifestError):
                ModelManifest.parse(canonical_manifest_bytes(manifest))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.build_pack(root)
            manifest["license"]["evaluation"] = "pending"  # type: ignore[index]
            (root / "manifest.json").write_bytes(canonical_manifest_bytes(manifest))
            with self.assertRaises(ModelPackCompatibilityError):
                verify_model_pack(root, verifier=StubVerifier(), runtime_tuple=self.runtime)

    def test_certification_advances_only_with_exact_signed_tuple(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_pack(root)
            loaded = verify_model_pack(root, verifier=StubVerifier(), runtime_tuple=self.runtime)
            execution = CertificationRecord(
                level="execution",
                pack_manifest_sha256=loaded.manifest_sha256,
                runtime_tuple_sha256=self.runtime.digest,
                evidence_sha256="a" * 64,
                signer_key_id="lab-ed25519-1",
            )
            executed = apply_certification(
                loaded, execution, b"trusted-signature", verifier=StubVerifier()
            )
            self.assertEqual(ModelPackState.EXECUTION_CERTIFIED, executed.state)
            interactive = replace(execution, level="interactive", evidence_sha256="b" * 64)
            final = apply_certification(
                executed, interactive, b"trusted-signature", verifier=StubVerifier()
            )
            self.assertEqual(ModelPackState.INTERACTIVE_CERTIFIED, final.state)
            with self.assertRaises(ModelPackIntegrityError):
                apply_certification(loaded, interactive, b"trusted-signature", verifier=StubVerifier())

    def test_trust_keys_are_purpose_bound_time_bounded_and_revocable(self) -> None:
        now = datetime(2026, 9, 22, 12, tzinfo=UTC)
        manifest_only = TrustKeyRecord(
            key_id="lab-ed25519-1",
            role=SigningRole.MODEL_PACK_SIGNER,
            purposes=(SigningPurpose.MODEL_PACK_MANIFEST,),
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=1),
        )
        verifier = PurposeBoundEd25519Verifier(
            StubRawVerifier(), (manifest_only,), clock=lambda: now
        )
        self.assertTrue(
            verifier.verify(
                b"manifest",
                b"trusted-signature",
                key_id="lab-ed25519-1",
                purpose=SigningPurpose.MODEL_PACK_MANIFEST,
            )
        )
        self.assertFalse(
            verifier.verify(
                b"certificate",
                b"trusted-signature",
                key_id="lab-ed25519-1",
                purpose=SigningPurpose.EXECUTION_CERTIFICATION,
            )
        )

        for restricted in (
            replace(manifest_only, not_before=now + timedelta(seconds=1)),
            replace(manifest_only, not_before=now - timedelta(days=2), not_after=now),
            replace(manifest_only, revoked_at=now - timedelta(seconds=1)),
            replace(manifest_only, role=SigningRole.CERTIFICATION_SIGNER),
        ):
            restricted_verifier = PurposeBoundEd25519Verifier(
                StubRawVerifier(), (restricted,), clock=lambda: now
            )
            self.assertFalse(
                restricted_verifier.verify(
                    b"manifest",
                    b"trusted-signature",
                    key_id="lab-ed25519-1",
                    purpose=SigningPurpose.MODEL_PACK_MANIFEST,
                )
            )

    def test_manifest_signer_cannot_issue_certification_without_that_usage(self) -> None:
        now = datetime(2026, 9, 22, 12, tzinfo=UTC)
        verifier = PurposeBoundEd25519Verifier(
            StubRawVerifier(),
            (
                TrustKeyRecord(
                    key_id="lab-ed25519-1",
                    role=SigningRole.MODEL_PACK_SIGNER,
                    purposes=(SigningPurpose.MODEL_PACK_MANIFEST,),
                    not_before=now - timedelta(days=1),
                    not_after=now + timedelta(days=1),
                ),
            ),
            clock=lambda: now,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_pack(root)
            loaded = verify_model_pack(root, verifier=verifier, runtime_tuple=self.runtime)
            certificate = CertificationRecord(
                level="execution",
                pack_manifest_sha256=loaded.manifest_sha256,
                runtime_tuple_sha256=self.runtime.digest,
                evidence_sha256="c" * 64,
                signer_key_id="lab-ed25519-1",
            )
            with self.assertRaises(ModelPackIntegrityError):
                apply_certification(
                    loaded,
                    certificate,
                    b"trusted-signature",
                    verifier=verifier,
                )


if __name__ == "__main__":
    unittest.main()
