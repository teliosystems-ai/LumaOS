from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os import LumaConfig, LumaService


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_release import (
    ReleaseProvenanceError,
    build_tar,
    build_zip,
    included_files,
    release_snapshot,
)


class ContractFileTests(unittest.TestCase):
    def test_json_schemas_are_valid_json_and_have_stable_ids(self) -> None:
        schema_dir = ROOT / "schemas"
        expected = {
            "artifact.schema.json",
            "grant.schema.json",
            "model-pack.schema.json",
            "receipt.schema.json",
            "workflow.schema.json",
        }
        self.assertEqual(expected, {path.name for path in schema_dir.glob("*.schema.json")})
        for path in schema_dir.glob("*.schema.json"):
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", document["$schema"])
            self.assertTrue(document["$id"].endswith(path.name))

    def test_release_manifest_contains_runtime_inputs(self) -> None:
        manifest = json.loads((ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
        inputs = set(manifest["release_inputs"])
        self.assertTrue(
            {"src", "web", "schemas", "examples", "tests", "requirements"}.issubset(inputs)
        )
        required = set(manifest["required_release_files"])
        self.assertIn("docs/DEVELOPMENT_PLAN.md", required)
        self.assertIn("docs/GOVERNING_REQUIREMENTS_SOURCES.md", required)
        self.assertIn("docs/RELEASE.md", required)
        self.assertIn("docs/GATE_REPORT.md", required)
        self.assertIn("requirements/registry.json", required)
        self.assertTrue(required.issubset(set(manifest["release_files"])))
        executable_files = {
            "packaging/systemd/install-user-service.sh",
            "scripts/build_release.py",
            "scripts/check.py",
            "scripts/install-user.sh",
            "scripts/run.sh",
            "scripts/uninstall-user.sh",
        }
        self.assertEqual(executable_files, set(manifest["executable_release_files"]))
        self.assertTrue(executable_files.issubset(set(manifest["release_files"])))
        self.assertFalse(manifest["external_assets"]["model_weights_included"])
        self.assertEqual("0.1.0", manifest["version"])

    def test_release_builder_uses_inventory_without_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docs = root / "docs"
            docs.mkdir()
            (docs / "tracked.md").write_bytes(b"released\n")
            tool = docs / "tool.sh"
            tool.write_bytes(b"#!/bin/sh\nexit 0\n")
            tool.chmod(0o644)
            (docs / "scratch.md").write_text("local only\n", encoding="utf-8")
            manifest = {
                "release_inputs": ["docs"],
                "release_files": ["docs/tracked.md", "docs/tool.sh"],
                "executable_release_files": ["docs/tool.sh"],
                "required_release_files": ["docs/tracked.md"],
                "excluded_from_release": [],
            }

            selected = included_files(root=root, manifest=manifest)
            entries, source_commit = release_snapshot(
                selected,
                root=root,
                manifest=manifest,
                tracked=None,
            )
            tar_path = root / "fixture.tar.gz"
            zip_path = root / "fixture.zip"
            build_tar(tar_path, entries, 0, archive_root="fixture")
            build_zip(zip_path, entries, 0, archive_root="fixture")

            self.assertEqual([docs / "tracked.md", docs / "tool.sh"], selected)
            self.assertIsNone(source_commit)
            with tarfile.open(tar_path, "r:gz") as archive:
                tracked_member = archive.getmember("fixture/docs/tracked.md")
                tool_member = archive.getmember("fixture/docs/tool.sh")
                self.assertEqual(0o644, tracked_member.mode)
                self.assertEqual(0o755, tool_member.mode)
                self.assertEqual(b"released\n", archive.extractfile(tracked_member).read())
            with zipfile.ZipFile(zip_path) as archive:
                tracked_info = archive.getinfo("fixture/docs/tracked.md")
                tool_info = archive.getinfo("fixture/docs/tool.sh")
                self.assertEqual(zipfile.ZIP_STORED, tracked_info.compress_type)
                self.assertEqual(zipfile.ZIP_STORED, tool_info.compress_type)
                self.assertEqual(0o644, (tracked_info.external_attr >> 16) & 0o777)
                self.assertEqual(0o755, (tool_info.external_attr >> 16) & 0o777)
                self.assertEqual(b"released\n", archive.read(tracked_info))

            extracted_root = root / "extracted"
            with tarfile.open(tar_path, "r:gz") as archive:
                archive.extractall(extracted_root, filter="data")
            canonical_root = extracted_root / "fixture"
            (canonical_root / "docs" / "tracked.md").chmod(0o755)
            (canonical_root / "docs" / "tool.sh").chmod(0o644)
            rebuilt_files = included_files(root=canonical_root, manifest=manifest)
            rebuilt_entries, rebuilt_commit = release_snapshot(
                rebuilt_files,
                root=canonical_root,
                manifest=manifest,
                tracked=None,
            )
            rebuilt_tar = root / "rebuilt.tar.gz"
            rebuilt_zip = root / "rebuilt.zip"
            build_tar(rebuilt_tar, rebuilt_entries, 0, archive_root="fixture")
            build_zip(rebuilt_zip, rebuilt_entries, 0, archive_root="fixture")
            self.assertIsNone(rebuilt_commit)
            self.assertEqual(tar_path.read_bytes(), rebuilt_tar.read_bytes())
            self.assertEqual(zip_path.read_bytes(), rebuilt_zip.read_bytes())

        if shutil.which("git"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / ".gitattributes").write_bytes(b"*.txt text eol=lf\n")
                payload = root / "payload.txt"
                payload.write_bytes(b"committed\n")
                tool = root / "tool.sh"
                tool.write_bytes(b"#!/bin/sh\nexit 0\n")
                commands = (
                    ("init", "--quiet"),
                    ("config", "user.email", "release-test@example.invalid"),
                    ("config", "user.name", "Release Test"),
                    ("add", ".gitattributes", "payload.txt", "tool.sh"),
                    ("update-index", "--chmod=+x", "tool.sh"),
                    ("commit", "--quiet", "-m", "fixture"),
                )
                for command in commands:
                    subprocess.run(
                        ["git", *command],
                        cwd=root,
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                payload.write_bytes(b"committed\r\n")
                manifest = {
                    "release_inputs": ["payload.txt", "tool.sh"],
                    "release_files": ["payload.txt", "tool.sh"],
                    "executable_release_files": ["tool.sh"],
                    "required_release_files": ["payload.txt"],
                    "excluded_from_release": [],
                }
                selected = included_files(root=root, manifest=manifest)
                entries, source_commit = release_snapshot(
                    selected,
                    root=root,
                    manifest=manifest,
                    tracked={
                        PurePosixPath(".gitattributes"),
                        PurePosixPath("payload.txt"),
                        PurePosixPath("tool.sh"),
                    },
                )

                self.assertRegex(source_commit or "", r"^[0-9a-f]{40}$")
                self.assertEqual(b"committed\n", entries[0].data)
                self.assertEqual((0o644, 0o755), tuple(entry.mode for entry in entries))
                subprocess.run(
                    ["git", "update-index", "--chmod=-x", "tool.sh"],
                    cwd=root,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                with self.assertRaisesRegex(
                    ReleaseProvenanceError,
                    "staged or unstaged content changes",
                ):
                    release_snapshot(
                        selected,
                        root=root,
                        manifest=manifest,
                        tracked={
                            PurePosixPath(".gitattributes"),
                            PurePosixPath("payload.txt"),
                            PurePosixPath("tool.sh"),
                        },
                    )

    def test_release_builder_rejects_an_explicit_untracked_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text("release notes\n", encoding="utf-8")
            manifest = {
                "release_inputs": ["README.md"],
                "release_files": ["README.md"],
                "executable_release_files": [],
                "required_release_files": ["README.md"],
                "excluded_from_release": [],
            }

            with self.assertRaisesRegex(ReleaseProvenanceError, "not tracked by Git"):
                included_files(root=root, manifest=manifest, tracked=set())

    def test_release_builder_rejects_an_intermediate_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "checkout"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "tracked.md").write_text("outside\n", encoding="utf-8")
            try:
                (root / "docs").symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")
            manifest = {
                "release_inputs": ["docs"],
                "release_files": ["docs/tracked.md"],
                "executable_release_files": [],
                "required_release_files": ["docs/tracked.md"],
                "excluded_from_release": [],
            }

            with self.assertRaisesRegex(ReleaseProvenanceError, "contains a symlink"):
                included_files(root=root, manifest=manifest, tracked=set())

    def test_openapi_describes_prepare_then_run(self) -> None:
        contract = (ROOT / "schemas" / "openapi.yaml").read_text(encoding="utf-8")
        self.assertIn("/api/workflows:", contract)
        self.assertIn("/api/workflows/{workflow_id}/run:", contract)
        self.assertIn("Loopback-only", contract)

    def test_example_is_fictional_and_parseable(self) -> None:
        rows = (ROOT / "examples" / "invoices.csv").read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            "invoice_id,vendor,invoice_date,category,amount,currency",
            rows[0],
        )
        self.assertGreaterEqual(len(rows), 3)

    def test_runtime_objects_include_every_required_contract_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = root / "inputs"
            inputs.mkdir()
            service = LumaService(LumaConfig.from_env({}, data_dir=root / "state"))
            grant = service.grants.enroll("contract-user", inputs)
            workflow = service.workflows.submit(
                "contract-user",
                source_text="invoice_date,amount,currency\n2026-09-01,10.00,USD\n",
                source_format="csv",
                source_name="contract.csv",
                idempotency_key="contract-workflow",
            )
            workflow = service.workflows.run("contract-user", workflow["workflow_id"])
            artifact = workflow["result"]["artifacts"][0]
            receipt = service.receipts.list("contract-user")[0]

            values = {
                "grant.schema.json": grant,
                "workflow.schema.json": workflow,
                "artifact.schema.json": artifact,
                "receipt.schema.json": receipt,
            }
            for filename, value in values.items():
                contract = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
                self.assertTrue(set(contract["required"]).issubset(value), filename)
            step_contract = json.loads(
                (ROOT / "schemas" / "workflow.schema.json").read_text(encoding="utf-8")
            )["properties"]["steps"]["items"]
            self.assertTrue(set(step_contract["required"]).issubset(workflow["steps"][0]))


if __name__ == "__main__":
    unittest.main()
