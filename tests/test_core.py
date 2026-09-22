from __future__ import annotations

import http.client
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os import (  # noqa: E402
    ConflictError,
    LumaConfig,
    LumaService,
    LumaStore,
    ValidationError,
)
from luma_os.server import create_server  # noqa: E402


class CoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.input_dir = self.root / "invoices"
        self.input_dir.mkdir()
        self.config = LumaConfig.from_env({}, data_dir=self.root / "state")
        self.service = LumaService(self.config)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_configuration_and_schema_are_durable(self) -> None:
        self.assertTrue(self.config.db_path.is_file())
        self.assertEqual(self.config.data_dir.stat().st_mode & 0o777, 0o700)
        with self.service.store.transaction() as connection:
            version = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(version, self.service.store.latest_schema_version)
        self.assertEqual(journal_mode.lower(), "wal")
        reopened = LumaService(self.config)
        self.assertEqual(reopened.status()["counts"], self.service.status()["counts"])

    def test_store_closes_migration_connection(self) -> None:
        class TrackingStore(LumaStore):
            def __init__(self, db_path: str | Path) -> None:
                self.opened_connections: list[sqlite3.Connection] = []
                super().__init__(db_path)

            def _connect(self) -> sqlite3.Connection:
                connection = super()._connect()
                self.opened_connections.append(connection)
                return connection

        store = TrackingStore(self.root / "tracked.sqlite3")

        self.assertEqual(len(store.opened_connections), 1)
        with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed database"):
            store.opened_connections[0].execute("SELECT 1")

    def test_grants_block_escape_and_symlinks(self) -> None:
        source = self.input_dir / "invoice.txt"
        source.write_text("Date: 2026-03-01\nAmount: USD 25.00\n", encoding="utf-8")
        outside = self.root / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        grant = self.service.grants.enroll("alice", self.input_dir)
        safe = self.service.grants.read_file("alice", grant["grant_id"], "invoice.txt")
        self.assertIn(b"25.00", safe.content)
        with self.assertRaises(ValidationError):
            self.service.grants.read_file("alice", grant["grant_id"], "../outside.txt")
        link = self.input_dir / "outside-link.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Symbolic links unavailable")
        with self.assertRaises(Exception) as raised:
            self.service.grants.read_file("alice", grant["grant_id"], "outside-link.txt")
        self.assertIn("symbolic links", str(raised.exception).lower())

    def test_artifact_versions_and_receipts_are_immutable(self) -> None:
        artifact = self.service.artifacts.create_text(
            "alice",
            "first",
            filename="report.txt",
            idempotency_key="commit-one",
        )
        replay = self.service.artifacts.create_text(
            "alice",
            "first",
            filename="report.txt",
            idempotency_key="commit-one",
        )
        self.assertEqual(artifact["artifact_id"], replay["artifact_id"])
        second = self.service.artifacts.add_version(
            "alice", artifact["artifact_id"], b"second", expected_current_version=1
        )
        self.assertEqual(second["version"], 2)
        _, old_content = self.service.artifacts.read("alice", artifact["artifact_id"], version=1)
        _, new_content = self.service.artifacts.read("alice", artifact["artifact_id"])
        self.assertEqual(old_content, b"first")
        self.assertEqual(new_content, b"second")
        with self.assertRaises(ConflictError):
            self.service.artifacts.add_version(
                "alice", artifact["artifact_id"], b"third", expected_current_version=1
            )
        with self.assertRaises(sqlite3.IntegrityError):
            with self.service.store.transaction(write=True) as connection:
                connection.execute("UPDATE effect_receipts SET status='CHANGED'")
        with self.assertRaises(sqlite3.IntegrityError):
            with self.service.store.transaction(write=True) as connection:
                connection.execute("DELETE FROM effect_receipts")

    def test_invoice_workflow_is_actual_deterministic_and_idempotent(self) -> None:
        (self.input_dir / "jan.csv").write_text(
            "invoice_date,vendor,total,currency\n"
            "2026-01-02,Acme,120.25,USD\n"
            "2026-01-21,Northwind,79.75,USD\n",
            encoding="utf-8",
        )
        (self.input_dir / "feb.txt").write_text(
            "Vendor: Contoso\nDate: 2026-02-10\nAmount: $50.00\n",
            encoding="utf-8",
        )
        grant = self.service.grants.enroll("alice", self.input_dir)
        created = self.service.workflows.submit(
            "alice",
            grant_id=grant["grant_id"],
            files=["jan.csv", "feb.txt"],
            idempotency_key="invoice-batch-1",
        )
        self.assertEqual(created["state"], "VALIDATED")
        completed = self.service.workflows.run("alice", created["workflow_id"])
        self.assertEqual(completed["state"], "SUCCEEDED")
        self.assertEqual(
            completed["result"]["summary"],
            [
                {"currency": "USD", "invoice_count": 2, "month": "2026-01", "total": "200.00"},
                {"currency": "USD", "invoice_count": 1, "month": "2026-02", "total": "50.00"},
            ],
        )
        artifact_ids = [item["artifact_id"] for item in completed["result"]["artifacts"]]
        self.assertEqual(len(self.service.receipts.list("alice")), 2)

        reopened = LumaService(self.config)
        replay = reopened.workflows.run("alice", created["workflow_id"])
        self.assertEqual([item["artifact_id"] for item in replay["result"]["artifacts"]], artifact_ids)
        self.assertEqual(len(reopened.receipts.list("alice")), 2)
        duplicate = reopened.workflows.submit(
            "alice",
            grant_id=grant["grant_id"],
            files=["jan.csv", "feb.txt"],
            idempotency_key="invoice-batch-1",
        )
        self.assertEqual(duplicate["workflow_id"], created["workflow_id"])
        with self.assertRaises(ConflictError):
            reopened.workflows.submit(
                "alice",
                grant_id=grant["grant_id"],
                files=["jan.csv"],
                idempotency_key="invoice-batch-1",
            )

    def test_manual_fallback_recovers_unparseable_input(self) -> None:
        (self.input_dir / "scan.txt").write_text("This scan has no reliable fields.", encoding="utf-8")
        grant = self.service.grants.enroll("alice", self.input_dir)
        workflow = self.service.workflows.submit(
            "alice", grant_id=grant["grant_id"], files=["scan.txt"], idempotency_key="scan"
        )
        waiting = self.service.workflows.run("alice", workflow["workflow_id"])
        self.assertEqual(waiting["state"], "WAITING_USER")
        self.assertIn("manual_fallback", waiting["result"])
        prepared = self.service.workflows.provide_manual_rows(
            "alice",
            workflow["workflow_id"],
            [{"date": "2026-04-03", "amount": "14.20", "currency": "EUR", "vendor": "Example"}],
        )
        self.assertEqual(prepared["state"], "VALIDATED")
        completed = self.service.workflows.run("alice", workflow["workflow_id"])
        self.assertEqual(completed["state"], "SUCCEEDED")
        self.assertEqual(completed["result"]["summary"][0]["total"], "14.20")

    def test_inline_csv_requires_no_model_or_folder(self) -> None:
        workflow = self.service.workflows.submit(
            "alice",
            source_text="date,amount,currency\n2026-05-01,9.99,GBP\n",
            source_format="csv",
            source_name="pasted.csv",
            idempotency_key="inline",
        )
        completed = self.service.workflows.run("alice", workflow["workflow_id"])
        self.assertEqual(completed["state"], "SUCCEEDED")
        self.assertFalse(self.service.models.status(probe=False)["configured"])
        provenance = completed["result"]["artifacts"][0]["provenance"]
        self.assertEqual(provenance["source_refs"][0]["inline_name"], "pasted.csv")

    def test_interrupted_workflow_is_recovered_for_safe_replay(self) -> None:
        source = self.input_dir / "recover.csv"
        source.write_text("date,amount\n2026-06-01,10.00\n", encoding="utf-8")
        grant = self.service.grants.enroll("alice", self.input_dir)
        workflow = self.service.workflows.submit(
            "alice", grant_id=grant["grant_id"], files=[source.name], idempotency_key="recover"
        )
        with self.service.store.transaction(write=True) as connection:
            connection.execute("UPDATE workflows SET state='RUNNING' WHERE workflow_id=?", (workflow["workflow_id"],))
            connection.execute(
                "UPDATE workflow_steps SET state='RUNNING' WHERE workflow_id=? AND step_id='extract_rows'",
                (workflow["workflow_id"],),
            )
        restarted = LumaService(self.config)
        recovered = restarted.workflows.get("alice", workflow["workflow_id"])
        self.assertEqual(recovered["state"], "VALIDATED")
        self.assertEqual(recovered["error"]["code"], "interrupted")
        completed = restarted.workflows.run("alice", workflow["workflow_id"])
        self.assertEqual(completed["state"], "SUCCEEDED")

    def test_http_session_same_origin_and_denial_receipt(self) -> None:
        invoice_path = self.input_dir / "web.csv"
        invoice_path.write_text("date,vendor,amount,currency\n2026-07-01,Web,42.00,USD\n", encoding="utf-8")
        try:
            server = create_server(self.service, port=0, web_root=Path(__file__).resolve().parents[1] / "web")
        except PermissionError:
            self.skipTest("Loopback sockets are disabled by the test sandbox")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host = f"127.0.0.1:{server.local_port}"
            connection = http.client.HTTPConnection("127.0.0.1", server.local_port, timeout=3)
            connection.request("GET", "/", headers={"Host": host})
            response = connection.getresponse()
            response.read()
            self.assertEqual(response.status, 200)
            cookie = response.getheader("Set-Cookie").split(";", 1)[0]

            payload = json.dumps({"path": str(self.input_dir), "permissions": ["read", "index"]})
            headers = {
                "Host": host,
                "Origin": "http://malicious.invalid",
                "Cookie": cookie,
                "Content-Type": "application/json",
            }
            connection.request("POST", "/api/grants/enroll", body=payload, headers=headers)
            denied = connection.getresponse()
            denied.read()
            self.assertEqual(denied.status, 403)
            self.assertEqual(self.service.receipts.list("_system")[0]["status"], "DENIED")

            headers["Origin"] = f"http://{host}"
            connection.request("POST", "/api/grants/enroll", body=payload, headers=headers)
            allowed = connection.getresponse()
            grant = json.loads(allowed.read())
            self.assertEqual(allowed.status, 201)
            self.assertIn("read", grant["permissions"])

            workflow_payload = json.dumps(
                {
                    "kind": "invoice_report.v1",
                    "source_path": str(invoice_path),
                    "idempotency_key": "http-e2e",
                }
            )
            connection.request("POST", "/api/workflows", body=workflow_payload, headers=headers)
            created_response = connection.getresponse()
            created = json.loads(created_response.read())
            self.assertEqual(created_response.status, 201)
            self.assertEqual(created["state"], "VALIDATED")

            connection.request(
                "POST",
                f"/api/workflows/{created['workflow_id']}/run",
                body="{}",
                headers=headers,
            )
            run_response = connection.getresponse()
            completed = json.loads(run_response.read())
            self.assertEqual(run_response.status, 200)
            self.assertEqual(completed["state"], "SUCCEEDED")
            artifact_id = completed["result"]["artifacts"][0]["artifact_id"]

            connection.request(
                "GET",
                f"/api/artifacts/{artifact_id}/content",
                headers={"Host": host, "Cookie": cookie},
            )
            content_response = connection.getresponse()
            content = content_response.read().decode("utf-8")
            self.assertEqual(content_response.status, 200)
            self.assertIn("2026-07,USD,1,42.00", content)
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
