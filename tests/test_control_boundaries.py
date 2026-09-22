from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import threading
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os import AuthorizationError, ConflictError, LumaConfig, LumaService  # noqa: E402


class ControlBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.input_dir = self.root / "input"
        self.input_dir.mkdir()
        self.source = self.input_dir / "invoices.csv"
        self.source.write_text(
            "date,vendor,amount,currency\n2026-09-01,Example,10.00,USD\n",
            encoding="utf-8",
        )
        self.service = LumaService(LumaConfig.from_env({}, data_dir=self.root / "state"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _prepared(self, key: str = "control-boundary") -> tuple[dict[str, object], dict[str, object]]:
        grant = self.service.grants.enroll("alice", self.input_dir)
        workflow = self.service.workflows.submit(
            "alice",
            grant_id=str(grant["grant_id"]),
            files=[self.source.name],
            idempotency_key=key,
        )
        return grant, workflow

    def test_revocation_between_prepare_and_run_denies_all_effects(self) -> None:
        grant, workflow = self._prepared("revoked-before-run")
        self.service.grants.revoke("alice", str(grant["grant_id"]))

        with self.assertRaises(AuthorizationError):
            self.service.workflows.run("alice", str(workflow["workflow_id"]))

        failed = self.service.workflows.get("alice", str(workflow["workflow_id"]))
        self.assertEqual(failed["state"], "FAILED")
        self.assertEqual([], self.service.artifacts.list("alice"))
        self.assertEqual([], self.service.receipts.list("alice"))

    def test_cancelled_prepared_workflow_cannot_run(self) -> None:
        _, workflow = self._prepared("cancel-prepared")
        cancelled = self.service.workflows.cancel("alice", str(workflow["workflow_id"]))

        self.assertEqual(cancelled["state"], "CANCELLED")
        with self.assertRaises(ConflictError):
            self.service.workflows.run("alice", str(workflow["workflow_id"]))
        self.assertEqual([], self.service.artifacts.list("alice"))

    def test_cancel_during_execution_fences_later_effects(self) -> None:
        _, workflow = self._prepared("cancel-running")
        entered = threading.Event()
        resume = threading.Event()
        original_report = self.service.workflows._report_csv

        def blocking_report(rows: list[dict[str, object]]) -> str:
            entered.set()
            if not resume.wait(timeout=5):
                raise TimeoutError("test did not release workflow")
            return original_report(rows)  # type: ignore[arg-type]

        self.service.workflows._report_csv = blocking_report  # type: ignore[method-assign]
        result: dict[str, object] = {}
        failure: list[BaseException] = []

        def run() -> None:
            try:
                result.update(self.service.workflows.run("alice", str(workflow["workflow_id"])))
            except BaseException as exc:  # pragma: no cover - reported by the assertion below
                failure.append(exc)

        worker = threading.Thread(target=run)
        worker.start()
        self.assertTrue(entered.wait(timeout=5), "workflow did not reach the controlled boundary")
        cancelled = self.service.workflows.cancel("alice", str(workflow["workflow_id"]))
        resume.set()
        worker.join(timeout=5)

        self.assertFalse(worker.is_alive())
        self.assertEqual([], failure)
        self.assertEqual("CANCELLED", cancelled["state"])
        self.assertEqual("CANCELLED", result["state"])
        self.assertEqual([], self.service.artifacts.list("alice"))
        self.assertEqual([], self.service.receipts.list("alice"))

    def test_concurrent_run_is_rejected_without_duplicate_effects(self) -> None:
        _, workflow = self._prepared("concurrent-run")
        entered = threading.Event()
        resume = threading.Event()
        original_read = self.service.workflows._read_sources

        def blocking_read(owner: str, request: dict[str, object]) -> list[dict[str, object]]:
            entered.set()
            if not resume.wait(timeout=5):
                raise TimeoutError("test did not release workflow")
            return original_read(owner, request)  # type: ignore[arg-type,return-value]

        self.service.workflows._read_sources = blocking_read  # type: ignore[method-assign]
        first_result: dict[str, object] = {}
        first_failure: list[BaseException] = []

        def first_run() -> None:
            try:
                first_result.update(self.service.workflows.run("alice", str(workflow["workflow_id"])))
            except BaseException as exc:  # pragma: no cover - reported below
                first_failure.append(exc)

        worker = threading.Thread(target=first_run)
        worker.start()
        self.assertTrue(entered.wait(timeout=5), "first run did not reach the controlled boundary")
        with self.assertRaises(ConflictError):
            self.service.workflows.run("alice", str(workflow["workflow_id"]))
        resume.set()
        worker.join(timeout=5)

        self.assertFalse(worker.is_alive())
        self.assertEqual([], first_failure)
        self.assertEqual("SUCCEEDED", first_result["state"])
        self.assertEqual(2, len(self.service.artifacts.list("alice")))
        self.assertEqual(2, len(self.service.receipts.list("alice")))


if __name__ == "__main__":
    unittest.main()
