from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
import sqlite3


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os import LumaConfig, LumaService, LumaStore, ValidationError  # noqa: E402
from luma_os.db import MIGRATION_1  # noqa: E402
from luma_os.state_transfer import (  # noqa: E402
    export_state,
    inspect_state_archive,
    prune_unreferenced_objects,
    restore_state,
)


class StateTransferTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = LumaConfig.from_env({}, data_dir=self.root / "state")
        self.service = LumaService(self.config)
        workflow = self.service.workflows.submit(
            "alice",
            source_text="date,amount,currency\n2026-09-01,12.50,USD\n",
            source_format="csv",
            source_name="input.csv",
            idempotency_key="state-transfer",
        )
        self.completed = self.service.workflows.run("alice", workflow["workflow_id"])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_export_and_clean_restore_preserve_state_and_content(self) -> None:
        archive = self.root / "backup.luma.zip"
        exported = export_state(self.config, archive)
        manifest = inspect_state_archive(archive)

        self.assertEqual("luma-state-export.v1", exported["format"])
        self.assertEqual(2, manifest["counts"]["artifacts"])
        restored_dir = self.root / "restored"
        restored = restore_state(archive, restored_dir)
        reopened = LumaService(LumaConfig.from_env({}, data_dir=restored_dir))

        self.assertEqual(self.service.status()["counts"], reopened.status()["counts"])
        artifact_id = self.completed["result"]["artifacts"][0]["artifact_id"]
        original = self.service.artifacts.read("alice", artifact_id)[1]
        recovered = reopened.artifacts.read("alice", artifact_id)[1]
        self.assertEqual(original, recovered)
        self.assertEqual(exported["sha256"], restored["source_archive_sha256"])

    def test_restore_rejects_tampered_and_nonempty_targets(self) -> None:
        archive = self.root / "backup.luma.zip"
        export_state(self.config, archive)
        tampered = self.root / "tampered.luma.zip"
        with zipfile.ZipFile(archive, "r") as source, zipfile.ZipFile(tampered, "w") as target:
            for info in source.infolist():
                content = source.read(info.filename)
                if info.filename == "luma.sqlite3":
                    content += b"tamper"
                target.writestr(info, content)
        with self.assertRaisesRegex(ValidationError, "size|digest"):
            inspect_state_archive(tampered)

        existing = self.root / "existing"
        existing.mkdir()
        with self.assertRaisesRegex(ValidationError, "must not already exist"):
            restore_state(archive, existing)

    def test_retention_prunes_only_unreferenced_objects(self) -> None:
        referenced = next((self.config.objects_dir / "sha256").rglob("*"))
        while referenced.is_dir():
            referenced = next(referenced.rglob("*"))
        orphan_hash = "f" * 64
        orphan = self.config.objects_dir / "sha256" / "ff" / orphan_hash
        orphan.parent.mkdir(parents=True, exist_ok=True)
        orphan.write_bytes(b"orphan")

        preview = prune_unreferenced_objects(self.config)
        self.assertEqual("dry_run", preview["mode"])
        self.assertEqual(1, preview["object_count"])
        self.assertTrue(orphan.exists())
        applied = prune_unreferenced_objects(self.config, apply=True)

        self.assertEqual("applied", applied["mode"])
        self.assertFalse(orphan.exists())
        self.assertTrue(referenced.exists())
        with self.service.store.transaction() as connection:
            runs = connection.execute(
                "SELECT mode,object_count FROM state_maintenance_runs ORDER BY created_at"
            ).fetchall()
        self.assertEqual([("dry_run", 1), ("applied", 1)], [(row[0], row[1]) for row in runs])

    def test_archive_rejects_unlisted_content(self) -> None:
        archive = self.root / "backup.luma.zip"
        export_state(self.config, archive)
        unexpected = self.root / "unexpected.luma.zip"
        with zipfile.ZipFile(archive, "r") as source, zipfile.ZipFile(unexpected, "w") as target:
            for info in source.infolist():
                target.writestr(info, source.read(info.filename))
            target.writestr("unexpected.txt", json.dumps({"not": "listed"}))
        with self.assertRaisesRegex(ValidationError, "unlisted"):
            inspect_state_archive(unexpected)

    def test_version_one_database_migrates_atomically_to_version_two(self) -> None:
        database = self.root / "version-one.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            connection.executescript(
                "BEGIN IMMEDIATE;\n"
                + MIGRATION_1
                + "\nINSERT INTO schema_migrations(version, applied_at) VALUES (1, '2026-09-22T00:00:00Z');\n"
                + "COMMIT;"
            )
        finally:
            connection.close()

        store = LumaStore(database)
        with store.transaction() as migrated:
            versions = [row[0] for row in migrated.execute("SELECT version FROM schema_migrations ORDER BY version")]
            table = migrated.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='state_maintenance_runs'"
            ).fetchone()

        self.assertEqual([1, 2], versions)
        self.assertIsNotNone(table)


if __name__ == "__main__":
    unittest.main()
