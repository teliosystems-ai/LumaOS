from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os import (  # noqa: E402
    ConflictError,
    LumaConfig,
    LumaService,
    NotFoundError,
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

    def test_cancel_during_calculation_fences_all_artifact_effects(self) -> None:
        workflow = self.service.workflows.submit(
            "alice",
            source_text="date,amount,currency\n2026-08-01,18.00,USD\n",
            source_format="csv",
            source_name="cancel-before-effects.csv",
            idempotency_key="cancel-before-effects",
        )
        workflow_id = workflow["workflow_id"]
        aggregate_entered = threading.Event()
        release_aggregate = threading.Event()
        original_aggregate = self.service.workflows._aggregate

        def blocked_aggregate(rows: object) -> object:
            aggregate_entered.set()
            if not release_aggregate.wait(timeout=3):
                raise AssertionError("test did not release the aggregate boundary")
            return original_aggregate(rows)  # type: ignore[arg-type]

        self.service.workflows._aggregate = blocked_aggregate  # type: ignore[method-assign]
        run_results: list[dict[str, object]] = []
        run_errors: list[BaseException] = []
        cancel_results: list[dict[str, object]] = []
        cancel_errors: list[BaseException] = []

        def execute() -> None:
            try:
                run_results.append(self.service.workflows.run("alice", workflow_id))
            except BaseException as exc:  # pragma: no cover - surfaced by assertion below
                run_errors.append(exc)

        def cancel() -> None:
            try:
                cancel_results.append(self.service.workflows.cancel("alice", workflow_id))
            except BaseException as exc:  # pragma: no cover - surfaced by assertion below
                cancel_errors.append(exc)

        run_thread = threading.Thread(target=execute, daemon=True)
        run_thread.start()
        self.assertTrue(aggregate_entered.wait(timeout=3), "workflow never reached aggregate boundary")
        cancel_thread = threading.Thread(target=cancel, daemon=True)
        cancel_thread.start()
        signal = self.service.workflows._cancellation_signal(workflow_id)
        self.assertTrue(signal.wait(timeout=3), "cancellation signal was not raised")
        cancel_thread.join(timeout=3)
        self.assertFalse(cancel_thread.is_alive(), "cancel waited for non-effect computation to drain")
        self.assertEqual(cancel_errors, [])
        self.assertEqual(cancel_results[0]["state"], "CANCELLED")
        release_aggregate.set()
        run_thread.join(timeout=3)

        self.assertFalse(run_thread.is_alive(), "workflow thread did not stop after cancellation")
        self.assertEqual(run_errors, [])
        self.assertEqual(run_results[0]["state"], "CANCELLED")
        self.assertEqual(self.service.artifacts.list("alice"), [])
        self.assertEqual(self.service.receipts.list("alice"), [])
        final = self.service.workflows.get("alice", workflow_id)
        self.assertEqual(final["state"], "CANCELLED")
        self.assertTrue(
            all(step["state"] == "CANCELLED" for step in final["steps"] if step["step_id"].startswith("publish_"))
        )
        with self.assertRaises(ConflictError):
            self.service.workflows.run("alice", workflow_id)

    def test_cancel_during_first_commit_allows_no_later_artifact(self) -> None:
        workflow = self.service.workflows.submit(
            "alice",
            source_text="date,amount,currency\n2026-08-02,21.00,USD\n",
            source_format="csv",
            source_name="cancel-during-effect.csv",
            idempotency_key="cancel-during-effect",
        )
        workflow_id = workflow["workflow_id"]
        commit_entered = threading.Event()
        release_commit = threading.Event()
        original_create = self.service.artifacts.create_text

        def blocked_create(*args: object, **kwargs: object) -> dict[str, object]:
            if kwargs.get("step_id") == "publish_csv":
                commit_entered.set()
                if not release_commit.wait(timeout=3):
                    raise AssertionError("test did not release the artifact boundary")
            return original_create(*args, **kwargs)  # type: ignore[arg-type]

        self.service.artifacts.create_text = blocked_create  # type: ignore[method-assign]
        run_results: list[dict[str, object]] = []
        run_errors: list[BaseException] = []
        cancel_results: list[dict[str, object]] = []
        cancel_errors: list[BaseException] = []

        def execute() -> None:
            try:
                run_results.append(self.service.workflows.run("alice", workflow_id))
            except BaseException as exc:  # pragma: no cover - surfaced by assertion below
                run_errors.append(exc)

        def cancel() -> None:
            try:
                cancel_results.append(self.service.workflows.cancel("alice", workflow_id))
            except BaseException as exc:  # pragma: no cover - surfaced by assertion below
                cancel_errors.append(exc)

        run_thread = threading.Thread(target=execute, daemon=True)
        run_thread.start()
        self.assertTrue(commit_entered.wait(timeout=3), "workflow never reached the first artifact commit")
        cancel_thread = threading.Thread(target=cancel, daemon=True)
        cancel_thread.start()
        signal = self.service.workflows._cancellation_signal(workflow_id)
        self.assertTrue(signal.wait(timeout=3), "cancellation signal was not raised")
        self.assertTrue(cancel_thread.is_alive(), "cancel did not wait for the in-flight effect fence")
        release_commit.set()
        run_thread.join(timeout=3)
        cancel_thread.join(timeout=3)

        self.assertFalse(run_thread.is_alive())
        self.assertFalse(cancel_thread.is_alive())
        self.assertEqual(run_errors, [])
        self.assertEqual(cancel_errors, [])
        self.assertEqual(run_results[0]["state"], "CANCELLED")
        self.assertEqual(cancel_results[0]["state"], "CANCELLED")
        artifacts = self.service.artifacts.list("alice")
        self.assertEqual([item["filename"] for item in artifacts], ["invoice-summary.csv"])
        self.assertEqual(len(self.service.receipts.list("alice")), 1)
        final = self.service.workflows.get("alice", workflow_id)
        step_states = {step["step_id"]: step["state"] for step in final["steps"]}
        self.assertEqual(step_states["publish_csv"], "SUCCEEDED")
        self.assertEqual(step_states["publish_report"], "CANCELLED")
        with self.assertRaises(ConflictError):
            self.service.workflows.run("alice", workflow_id)
        self.assertEqual(len(self.service.artifacts.list("alice")), 1)

    def test_concurrent_run_attempts_have_one_effectful_owner(self) -> None:
        workflow = self.service.workflows.submit(
            "alice",
            source_text="date,amount,currency\n2026-08-03,34.00,USD\n",
            source_format="csv",
            source_name="concurrent.csv",
            idempotency_key="concurrent-run",
        )
        workflow_id = workflow["workflow_id"]
        aggregate_entered = threading.Event()
        release_aggregate = threading.Event()
        original_aggregate = self.service.workflows._aggregate

        def blocked_aggregate(rows: object) -> object:
            aggregate_entered.set()
            if not release_aggregate.wait(timeout=3):
                raise AssertionError("test did not release the concurrent run")
            return original_aggregate(rows)  # type: ignore[arg-type]

        self.service.workflows._aggregate = blocked_aggregate  # type: ignore[method-assign]
        first_results: list[dict[str, object]] = []
        first_errors: list[BaseException] = []

        def first_run() -> None:
            try:
                first_results.append(self.service.workflows.run("alice", workflow_id))
            except BaseException as exc:  # pragma: no cover - surfaced by assertion below
                first_errors.append(exc)

        first_thread = threading.Thread(target=first_run, daemon=True)
        first_thread.start()
        self.assertTrue(aggregate_entered.wait(timeout=3), "first run did not reach its deterministic boundary")
        concurrent_service = LumaService(self.config)
        with self.assertRaisesRegex(ConflictError, "already running"):
            concurrent_service.workflows.run("alice", workflow_id)
        release_aggregate.set()
        first_thread.join(timeout=3)

        self.assertFalse(first_thread.is_alive())
        self.assertEqual(first_errors, [])
        self.assertEqual(first_results[0]["state"], "SUCCEEDED")
        completed = self.service.workflows.get("alice", workflow_id)
        self.assertEqual(completed["attempt"], 1)
        self.assertEqual(len(self.service.artifacts.list("alice")), 2)
        self.assertEqual(len(self.service.receipts.list("alice")), 2)
        self.assertTrue(all(step["attempt"] == 1 for step in completed["steps"]))

    def test_service_in_another_process_does_not_recover_a_live_run(self) -> None:
        workflow = self.service.workflows.submit(
            "alice",
            source_text="date,amount,currency\n2026-08-04,55.00,USD\n",
            source_format="csv",
            source_name="cross-process.csv",
            idempotency_key="cross-process-live-run",
        )
        workflow_id = workflow["workflow_id"]
        aggregate_entered = threading.Event()
        release_aggregate = threading.Event()
        original_aggregate = self.service.workflows._aggregate

        def blocked_aggregate(rows: object) -> object:
            aggregate_entered.set()
            if not release_aggregate.wait(timeout=5):
                raise AssertionError("test did not release the cross-process run")
            return original_aggregate(rows)  # type: ignore[arg-type]

        self.service.workflows._aggregate = blocked_aggregate  # type: ignore[method-assign]
        run_results: list[dict[str, object]] = []
        run_errors: list[BaseException] = []

        def execute() -> None:
            try:
                run_results.append(self.service.workflows.run("alice", workflow_id))
            except BaseException as exc:  # pragma: no cover - surfaced by assertion below
                run_errors.append(exc)

        run_thread = threading.Thread(target=execute, daemon=True)
        run_thread.start()
        self.assertTrue(aggregate_entered.wait(timeout=3), "workflow never reached the cross-process boundary")
        repo_root = Path(__file__).resolve().parents[1]
        environment = os.environ.copy()
        python_path = str(repo_root / "src")
        if environment.get("PYTHONPATH"):
            python_path += os.pathsep + environment["PYTHONPATH"]
        environment["PYTHONPATH"] = python_path
        child_code = (
            "import sys; "
            "from luma_os import LumaConfig,LumaService; "
            "service=LumaService(LumaConfig.from_env({},data_dir=sys.argv[1])); "
            "print(service.workflows.get('alice',sys.argv[2])['state'])"
        )
        try:
            child = subprocess.run(
                [sys.executable, "-c", child_code, str(self.config.data_dir), workflow_id],
                cwd=repo_root,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(child.stdout.strip(), "RUNNING")
            self.assertEqual(self.service.workflows.get("alice", workflow_id)["state"], "RUNNING")
        finally:
            release_aggregate.set()
            run_thread.join(timeout=3)

        self.assertFalse(run_thread.is_alive())
        self.assertEqual(run_errors, [])
        self.assertEqual(run_results[0]["state"], "SUCCEEDED")

    def test_wrong_owner_cannot_signal_or_cancel_an_active_workflow(self) -> None:
        workflow = self.service.workflows.submit(
            "alice",
            source_text="date,amount,currency\n2026-08-05,89.00,USD\n",
            source_format="csv",
            source_name="owner-isolation.csv",
            idempotency_key="owner-isolation",
        )
        workflow_id = workflow["workflow_id"]
        commit_entered = threading.Event()
        release_commit = threading.Event()
        original_create = self.service.artifacts.create_text

        def blocked_create(*args: object, **kwargs: object) -> dict[str, object]:
            if kwargs.get("step_id") == "publish_csv":
                commit_entered.set()
                if not release_commit.wait(timeout=3):
                    raise AssertionError("test did not release the owner-isolation boundary")
            return original_create(*args, **kwargs)  # type: ignore[arg-type]

        self.service.artifacts.create_text = blocked_create  # type: ignore[method-assign]
        run_results: list[dict[str, object]] = []
        run_errors: list[BaseException] = []

        def execute() -> None:
            try:
                run_results.append(self.service.workflows.run("alice", workflow_id))
            except BaseException as exc:  # pragma: no cover - surfaced by assertion below
                run_errors.append(exc)

        run_thread = threading.Thread(target=execute, daemon=True)
        run_thread.start()
        self.assertTrue(commit_entered.wait(timeout=3), "workflow never reached the owner-isolation boundary")
        try:
            with self.assertRaises(NotFoundError):
                self.service.workflows.cancel("bob", workflow_id)
            self.assertFalse(self.service.workflows._cancellation_signal(workflow_id).is_set())
        finally:
            release_commit.set()
            run_thread.join(timeout=3)

        self.assertFalse(run_thread.is_alive())
        self.assertEqual(run_errors, [])
        self.assertEqual(run_results[0]["state"], "SUCCEEDED")

    def test_manual_rows_cannot_replace_inputs_after_a_durable_effect(self) -> None:
        workflow = self.service.workflows.submit(
            "alice",
            source_text="date,amount,currency\n2026-08-06,144.00,USD\n",
            source_format="csv",
            source_name="partial-effect.csv",
            idempotency_key="partial-effect",
        )
        workflow_id = workflow["workflow_id"]
        original_create = self.service.artifacts.create_text
        failed_once = False

        def fail_first_report(*args: object, **kwargs: object) -> dict[str, object]:
            nonlocal failed_once
            if kwargs.get("step_id") == "publish_report" and not failed_once:
                failed_once = True
                raise RuntimeError("injected report failure")
            return original_create(*args, **kwargs)  # type: ignore[arg-type]

        self.service.artifacts.create_text = fail_first_report  # type: ignore[method-assign]
        with self.assertRaisesRegex(RuntimeError, "injected report failure"):
            self.service.workflows.run("alice", workflow_id)
        self.assertEqual(self.service.workflows.get("alice", workflow_id)["state"], "FAILED")
        self.assertEqual(len(self.service.receipts.list("alice")), 1)

        with self.assertRaisesRegex(ConflictError, "durable workflow effect"):
            self.service.workflows.provide_manual_rows(
                "alice",
                workflow_id,
                [{"date": "2026-08-06", "amount": "233.00", "currency": "USD"}],
            )

        completed = self.service.workflows.run("alice", workflow_id)
        self.assertEqual(completed["state"], "SUCCEEDED")
        self.assertEqual(completed["result"]["summary"][0]["total"], "144.00")

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

            payload = json.dumps({"path": str(self.input_dir), "permissions": ["read"]})
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
