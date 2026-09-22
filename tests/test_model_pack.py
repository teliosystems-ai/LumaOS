from __future__ import annotations

from dataclasses import replace
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
    RuntimeTuple,
    apply_certification,
    canonical_manifest_bytes,
    verify_model_pack,
)


class StubVerifier:
    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        return bool(message) and signature == b"trusted-signature" and key_id == "lab-ed25519-1"


class ModelPackTests(unittest.TestCase):
    runtime = RuntimeTuple("linux", "x86_64", "llama.cpp", "1.2.3", "cuda:0")

    def build_pack(self, root: Path) -> dict[str, object]:
        contents = {
            "model": b"small-test-model",
            "tokenizer": b'{"type":"test"}',
            "template": b"{{ prompt }}",
            "license": b"test license",
        }
        declarations = []
        for role, content in contents.items():
            digest = hashlib.sha256(content).hexdigest()
            relative = f"licenses/{digest}.txt" if role == "license" else f"blobs/sha256/{digest}"
            path = root.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            declarations.append(
                {"role": role, "path": relative, "sha256": digest, "size_bytes": len(content)}
            )
        template = next(item for item in declarations if item["role"] == "template")
        license_blob = next(item for item in declarations if item["role"] == "license")
        manifest: dict[str, object] = {
            "schema_version": 1,
            "canonicalization": "RFC8785-ASCII-v1",
            "signature_algorithm": "Ed25519",
            "pack_id": "test-compact",
            "pack_version": "1.0.0",
            "model": {
                "architecture": "test-transformer",
                "identity": "test-only/no-weights",
                "parameter_class": "fixture",
                "quantization": "none",
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


if __name__ == "__main__":
    unittest.main()
