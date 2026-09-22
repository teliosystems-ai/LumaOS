from __future__ import annotations

from contextlib import redirect_stderr
import http.client
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os import ConflictError, LumaConfig, LumaService, ValidationError  # noqa: E402
from luma_os.cli import main as cli_main  # noqa: E402
from luma_os.db import LumaStore, MIGRATION_1, utc_now  # noqa: E402
from luma_os.errors import AuthorizationError  # noqa: E402
from luma_os.server import create_server  # noqa: E402


class StageOneHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.service = LumaService(LumaConfig.from_env({}, data_dir=self.root / "state"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_grant_revocation_is_idempotent_and_blocks_new_reads(self) -> None:
        source = self.root / "source"
        source.mkdir()
        (source / "invoice.csv").write_text("date,amount\n2026-09-01,1.00\n", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "read-only"):
            self.service.grants.enroll("alice", source, scope="read_write")
        grant = self.service.grants.enroll("alice", source)
        first = self.service.grants.revoke("alice", str(grant["grant_id"]))
        replay = self.service.grants.revoke("alice", str(grant["grant_id"]))
        self.assertEqual(first["revoked_at"], replay["revoked_at"])
        with self.assertRaises(AuthorizationError):
            self.service.grants.read_file("alice", str(grant["grant_id"]), "invoice.csv")

    def test_revoke_and_receipt_are_atomic_when_recording_fails(self) -> None:
        source = self.root / "atomic-source"
        source.mkdir()
        grant = self.service.grants.enroll("alice", source)

        with patch.object(
            self.service.grants.receipts,
            "record_in_transaction",
            side_effect=RuntimeError("injected receipt failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected receipt failure"):
                self.service.grants.revoke_with_receipt(
                    "alice",
                    str(grant["grant_id"]),
                    idempotency_key="atomic-revoke",
                )

        current = self.service.grants.get("alice", str(grant["grant_id"]))
        self.assertIsNone(current["revoked_at"])
        self.assertEqual(self.service.receipts.list("alice"), [])

    def test_receipt_collision_cannot_revoke_and_reactivation_advances_generation(self) -> None:
        source = self.root / "generation-source"
        source.mkdir()
        grant = self.service.grants.enroll("alice", source)
        self.assertEqual(grant["generation"], 1)
        self.service.receipts.record(
            "alice",
            idempotency_key="occupied-key",
            effect_type="artifact.commit",
            target="artifact:unrelated:1",
            status="SUCCEEDED",
            result={"artifact_id": "unrelated", "version": 1},
        )

        with self.assertRaises(ConflictError):
            self.service.grants.revoke_with_receipt(
                "alice",
                str(grant["grant_id"]),
                idempotency_key="occupied-key",
            )
        self.assertIsNone(self.service.grants.get("alice", str(grant["grant_id"]))["revoked_at"])

        first, first_receipt = self.service.grants.revoke_with_receipt(
            "alice",
            str(grant["grant_id"]),
            idempotency_key="generation-one",
        )
        replay, replay_receipt = self.service.grants.revoke_with_receipt(
            "alice",
            str(grant["grant_id"]),
            idempotency_key="generation-one",
        )
        self.assertEqual(first["revoked_at"], replay["revoked_at"])
        self.assertEqual(first_receipt["receipt_id"], replay_receipt["receipt_id"])
        self.assertEqual(first_receipt["result"]["generation"], 1)

        reactivated = self.service.grants.enroll("alice", source)
        self.assertEqual(reactivated["grant_id"], grant["grant_id"])
        self.assertEqual(reactivated["generation"], 2)
        self.assertIsNone(reactivated["revoked_at"])
        with self.assertRaises(ConflictError):
            self.service.grants.revoke_with_receipt(
                "alice",
                str(grant["grant_id"]),
                idempotency_key="generation-one",
            )
        self.assertIsNone(self.service.grants.get("alice", str(grant["grant_id"]))["revoked_at"])

        second, second_receipt = self.service.grants.revoke_with_receipt(
            "alice", str(grant["grant_id"])
        )
        self.assertEqual(second["generation"], 2)
        self.assertEqual(second_receipt["result"]["generation"], 2)
        self.assertNotEqual(first_receipt["receipt_id"], second_receipt["receipt_id"])

    def test_schema_v1_store_migrates_grants_to_generation_one(self) -> None:
        database = self.root / "legacy" / "luma.db"
        database.parent.mkdir()
        with sqlite3.connect(database) as connection:
            connection.execute(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            connection.executescript(MIGRATION_1)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?)",
                (utc_now(),),
            )
            connection.execute(
                "INSERT INTO folder_grants("
                "grant_id,owner,root_path,root_device,root_inode,display_name,scope,created_at"
                ") VALUES ('legacy-grant','alice','/legacy',1,2,'Legacy','read',?)",
                (utc_now(),),
            )
        store = LumaStore(database)
        with store.transaction() as connection:
            version = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            columns = {row[1] for row in connection.execute("PRAGMA table_info(folder_grants)").fetchall()}
            generation = connection.execute(
                "SELECT generation FROM folder_grants WHERE grant_id='legacy-grant'"
            ).fetchone()[0]
        self.assertEqual(version, 2)
        self.assertIn("generation", columns)
        self.assertEqual(generation, 1)

    def test_artifact_history_exposes_real_immutable_versions(self) -> None:
        artifact = self.service.artifacts.create_text(
            "alice",
            "version one",
            filename="report.txt",
            idempotency_key="history-1",
        )
        second = self.service.artifacts.add_version(
            "alice",
            str(artifact["artifact_id"]),
            b"version two",
            expected_current_version=1,
            idempotency_key="history-2",
        )
        versions = self.service.artifacts.versions("alice", str(artifact["artifact_id"]))
        self.assertEqual([item["version"] for item in versions], [1, 2])
        self.assertEqual(versions[-1]["content_hash"], second["content_hash"])
        _, first_content = self.service.artifacts.read("alice", str(artifact["artifact_id"]), version=1)
        _, second_content = self.service.artifacts.read("alice", str(artifact["artifact_id"]), version=2)
        self.assertEqual(first_content, b"version one")
        self.assertEqual(second_content, b"version two")

    def test_cli_rejects_a_write_claim_for_read_only_source_grants(self) -> None:
        source = self.root / "cli-source"
        source.mkdir()
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = cli_main(
                [
                    "enroll",
                    str(source),
                    "--data-dir",
                    str(self.root / "cli-state"),
                    "--read-write",
                ]
            )
        self.assertEqual(result, 2)
        self.assertIn("unsupported_scope", errors.getvalue())

    def test_http_revoke_and_version_history_contract(self) -> None:
        source = self.root / "http-source"
        source.mkdir()
        artifact = self.service.artifacts.create_text(
            "local-user", "one", filename="history.txt", idempotency_key="http-history-1"
        )
        self.service.artifacts.add_version(
            "local-user",
            str(artifact["artifact_id"]),
            b"two",
            expected_current_version=1,
            idempotency_key="http-history-2",
        )
        try:
            server = create_server(
                self.service,
                port=0,
                web_root=Path(__file__).resolve().parents[1] / "web",
            )
        except PermissionError:
            self.skipTest("Loopback sockets are disabled by the test sandbox")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.local_port, timeout=3)
        host = f"127.0.0.1:{server.local_port}"
        try:
            connection.request("GET", "/", headers={"Host": host})
            response = connection.getresponse()
            response.read()
            cookie = response.getheader("Set-Cookie").split(";", 1)[0]
            headers = {
                "Host": host,
                "Origin": f"http://{host}",
                "Cookie": cookie,
                "Content-Type": "application/json",
            }
            connection.request(
                "POST",
                "/api/grants/enroll",
                body=json.dumps({"path": str(source), "permissions": ["read", "index"]}),
                headers=headers,
            )
            unsupported_response = connection.getresponse()
            unsupported_response.read()
            self.assertEqual(unsupported_response.status, 422)

            connection.request(
                "POST",
                "/api/grants/enroll",
                body=json.dumps({"path": str(source), "scope": "read_write", "permissions": ["read"]}),
                headers=headers,
            )
            conflicting_scope_response = connection.getresponse()
            conflicting_scope_response.read()
            self.assertEqual(conflicting_scope_response.status, 422)

            connection.request(
                "POST",
                "/api/grants/enroll",
                body=json.dumps({"path": str(source), "permissions": ["read"]}),
                headers=headers,
            )
            enrolled_response = connection.getresponse()
            enrolled = json.loads(enrolled_response.read())
            self.assertEqual(enrolled_response.status, 201)

            revoke_path = f"/api/grants/{enrolled['grant_id']}/revoke"
            connection.request(
                "POST",
                revoke_path,
                body=json.dumps({"unexpected": True}),
                headers=headers,
            )
            unknown_field_response = connection.getresponse()
            unknown_field_response.read()
            self.assertEqual(unknown_field_response.status, 422)
            self.assertIsNone(
                self.service.grants.get("local-user", str(enrolled["grant_id"]))["revoked_at"]
            )

            body = json.dumps({"idempotency_key": "http-revoke"})
            connection.request("POST", revoke_path, body=body, headers=headers)
            first_response = connection.getresponse()
            first = json.loads(first_response.read())
            self.assertEqual(first_response.status, 200)
            self.assertEqual(first["generation"], 1)
            connection.request("POST", revoke_path, body=body, headers=headers)
            replay_response = connection.getresponse()
            replay = json.loads(replay_response.read())
            self.assertEqual(replay_response.status, 200)
            self.assertEqual(first["receipt_id"], replay["receipt_id"])

            artifact_id = str(artifact["artifact_id"])
            connection.request(
                "GET",
                f"/api/artifacts/{artifact_id}",
                headers={"Host": host, "Cookie": cookie},
            )
            detail_response = connection.getresponse()
            detail = json.loads(detail_response.read())
            self.assertEqual(detail_response.status, 200)
            self.assertEqual([item["version"] for item in detail["versions"]], [1, 2])

            connection.request(
                "GET",
                f"/api/artifacts/{artifact_id}/content?version=1",
                headers={"Host": host, "Cookie": cookie},
            )
            content_response = connection.getresponse()
            self.assertEqual(content_response.read(), b"one")
            self.assertEqual(content_response.getheader("X-Luma-Artifact-Version"), "1")
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
