"""Synthetic protocol fixtures, never a held-out500task product result."""
from __future__ import annotations

import copy
from datetime import datetime, timezone, timedelta
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("g3_quality", ROOT / "scripts/g3_quality.py")
quality = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(quality)


class Fixture:
    def __init__(self, root):
        self.root = root
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.input = self.put("input.txt", b"Synthetic protocol test; not a product evaluation.\n")
        self.answer = self.put("answer.json", b'{"value":7}')
        self.memory = self.put("memory.txt", b"1000000\n")
        self.rubric = self.put("rubric.txt", b"External human must inspect the complete retained artifact.")
        self.corpus = dict(schema_version=1, corpus_id="synthetic-unit-fixture", classification="external-held-out", tasks=[])
        for index in range(500):
            input_pin = self.put(f"input-{index:03}.txt", f"Synthetic protocol-only task fixture{index}; no product evaluation.\n".encode())
            self.corpus["tasks"].append(dict(task_id=f"task-{index:03}", expected="complete", inputs=[dict(name="input", file=input_pin)],
                 oracle=dict(kind="json-exact", artifact="result", expected=self.answer)))
        self.statuses = {}
        self.human = {}

    def put(self, name, data):
        if type(data) is dict:
            data = quality.canonical(data)
        (self.root / name).write_bytes(data)
        return dict(path=name, bytes=len(data), sha256=quality.sha(data))

    def build(self):
        self.corpus_pin = self.put("corpus.json", self.corpus)
        self.manifest = dict(schema_version=1, run_id="run-unit", profile="compact", corpus_sha256=self.corpus_pin["sha256"],
                             tuple={key: "a" * 64 for key in quality.TUPLE_KEYS},
                             started_utc=(self.now-timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                             finished_utc=(self.now-timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.manifest_pin = self.put("manifest.json", self.manifest)
        self.context = dict(run_id="run-unit", corpus_sha256=self.corpus_pin["sha256"],
                            current_manifest_sha256=self.manifest_pin["sha256"], tuple=self.manifest["tuple"])
        self.context_hash = quality.sha(quality.canonical(self.context))
        self.run = dict(schema_version=1, context=self.context, observations=[])
        self.adjudications = dict(schema_version=1, context_sha256=self.context_hash, origin="external-human", decisions=[])
        clock = 0
        for index, task in enumerate(self.corpus["tasks"]):
            name = task["task_id"]
            inputs_hash = quality.sha(quality.canonical(task["inputs"]))
            entry = dict(task_id=name, input_set_sha256=inputs_hash, attempts=[])
            for sequence, status in enumerate(self.statuses.get(index, ["completed"]), 1):
                artifacts = [dict(name="result", file=self.answer)] if status == "completed" else []
                artifact_hash = quality.sha(quality.canonical(artifacts))
                receipt = self.put(f"receipt-{index:03}-{sequence}.json", dict(schema_version=1, run_id="run-unit",
                    task_id=name, attempt=sequence, context_sha256=self.context_hash, input_set_sha256=inputs_hash,
                    artifact_set_sha256=artifact_hash, status=status, authority_returned=False))
                energy = self.put(f"energy-{index:03}-{sequence}.json", dict(schema_version=1, run_id="run-unit",
                    task_id=name, attempt=sequence, context_sha256=self.context_hash, method="kernel-counter", domain="fixture-only",
                    started_ns=clock, finished_ns=clock+1000000, start_microjoules=100, end_microjoules=110))
                observation = self.put(f"metric-{index:03}-{sequence}.json", dict(schema_version=1, run_id="run-unit", task_id=name,
                    attempt=sequence, context_sha256=self.context_hash, clock="run-relative-monotonic-ns", started_ns=clock,
                    finished_ns=clock+1000000, ack_ns=clock+100, first_result_ns=clock+500 if status == "completed" else None,
                    cancel_requested_ns=clock+200 if status == "cancelled" else None,
                    cancel_ack_ns=clock+300 if status == "cancelled" else None, peak_memory_bytes=1000000,
                    peak_memory_evidence=self.memory, energy_evidence=energy))
                clock += 1000000
                entry["attempts"].append(dict(attempt=sequence, status=status, reason="" if status == "completed" else "fixture disposition",
                                               artifacts=artifacts, receipt=receipt, measurement=observation))
                if task["oracle"]["kind"] == "human-rubric" and status == "completed":
                    self.adjudications["decisions"].append(dict(task_id=name, attempt=sequence, artifact_set_sha256=artifact_hash,
                        rubric_sha256=self.rubric["sha256"], reviewer="external-unit-reviewer", decision=self.human.get(index, "pass"),
                        reason="Synthetic fixture only; no actual product review."))
            self.run["observations"].append(entry)
        self.refresh()

    def refresh(self):
        self.run_pin = self.put("run.json", self.run)
        self.adjudications["run_sha256"] = self.run_pin["sha256"]
        self.adjudications_pin = self.put("adjudications.json", self.adjudications)

    def replace_metric(self, index, changes):
        attempt = self.run["observations"][index]["attempts"][0]
        pin = attempt["measurement"]
        record = json.loads((self.root / pin["path"]).read_bytes())
        record.update(changes)
        attempt["measurement"] = self.put(pin["path"], record)
        self.refresh()

    def evaluate(self, **options):
        return quality.evaluate(quality.Files(self.root), self.corpus_pin["path"], self.corpus_pin["sha256"],
            self.run_pin["path"], self.run_pin["sha256"], self.manifest_pin["path"], self.manifest_pin["sha256"],
            self.adjudications_pin["path"], self.adjudications_pin["sha256"], now=options.pop("now", self.now), **options)


class QualityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="luma-quality-protocol-")
        self.addCleanup(self.directory.cleanup)
        self.fixture = Fixture(Path(self.directory.name))

    def test_complete_fixture_reports_all_attempts_and_no_gate(self):
        self.fixture.build()
        result = self.fixture.evaluate()
        self.assertEqual(result["initial_successes"], 500)
        self.assertEqual(result["metrics"]["energy_microjoules_by_method_and_domain"], {"kernel-counter:fixture-only": 5000})
        self.assertEqual(result["metrics"]["p95_elapsed_ns"], 1000000)
        self.assertEqual(result["q10"]["required_successes"], 425)
        self.assertTrue(result["q10"]["initial_threshold_met"])
        self.assertTrue(all(value is False for value in result["claims"].values()))

    def test_false_refusal_repairs_failures_cancellations_not_hidden(self):
        self.fixture.statuses = {0: ["refused", "completed"], 1: ["failed"], 2: ["cancelled"], 3: ["completed", "failed"]}
        self.fixture.build()
        result = self.fixture.evaluate()
        self.assertEqual(result["initial_successes"], 497)
        self.assertEqual(result["final_successes"], 497)
        self.assertEqual(result["false_refusal_attempts"], 1)
        self.assertEqual(result["repaired_tasks"], 1)
        self.assertEqual(result["retried_tasks"], 2)
        self.assertEqual(result["attempts"], 502)
        self.assertEqual(result["status_counts"], dict(completed=498, refused=1, failed=2, cancelled=1))
        self.assertEqual(result["oracle_failed_attempts"], 4)

    def test_exact_expected_refusal_is_not_false_refusal(self):
        self.fixture.corpus["tasks"][0].update(expected="refuse", oracle={"kind": "must-refuse"})
        self.fixture.statuses[0] = ["refused"]
        self.fixture.build()
        result = self.fixture.evaluate()
        self.assertEqual(result["initial_successes"], 500)
        self.assertEqual(result["false_refusal_attempts"], 0)

    def test_model_answer_does_not_override_actual_json_oracle(self):
        self.fixture.answer = self.fixture.put("actual.json", b'{"model_claim":"success","value":9}')
        self.fixture.build()
        result = self.fixture.evaluate()
        self.assertEqual(result["final_successes"], 0)
        self.assertFalse(result["q10"]["final_threshold_met"])

    def test_external_human_decision_requires_exact_rubric_and_artifacts(self):
        self.fixture.corpus["tasks"][0]["oracle"] = dict(kind="human-rubric", rubric=self.fixture.rubric)
        self.fixture.human[0] = "fail"
        self.fixture.build()
        self.assertEqual(self.fixture.evaluate()["final_successes"], 499)
        self.fixture.adjudications["decisions"][0]["artifact_set_sha256"] = "b" * 64
        self.fixture.refresh()
        with self.assertRaisesRegex(quality.Invalid, "artifacts differ"):
            self.fixture.evaluate()

    def test_missing_duplicate_and_unmatched_human_decisions_refuse(self):
        self.fixture.corpus["tasks"][0]["oracle"] = dict(kind="human-rubric", rubric=self.fixture.rubric)
        self.fixture.build()
        original = copy.deepcopy(self.fixture.adjudications["decisions"])
        for decisions in ([], original + original, [dict(original[0], task_id="task-001")]):
            with self.subTest(decisions=decisions):
                self.fixture.adjudications["decisions"] = decisions
                self.fixture.refresh()
                with self.assertRaises(quality.Invalid):
                    self.fixture.evaluate()

    def test_exact500_sorted_unique_tasks_required(self):
        for mode in ("missing", "extra", "duplicate", "unordered"):
            with self.subTest(mode=mode):
                corpus = copy.deepcopy(self.fixture.corpus)
                if mode == "missing":
                    corpus["tasks"].pop()
                elif mode == "extra":
                    corpus["tasks"].append(copy.deepcopy(corpus["tasks"][-1]))
                elif mode == "duplicate":
                    corpus["tasks"][1]["task_id"] = corpus["tasks"][0]["task_id"]
                else:
                    corpus["tasks"][:2] = reversed(corpus["tasks"][:2])
                with self.assertRaises(quality.Invalid):
                    quality.validate_corpus(quality.Files(self.fixture.root), corpus)

    def test_complete_sorted_matching_observations_required(self):
        self.fixture.build()
        original = copy.deepcopy(self.fixture.run["observations"])
        for value in (original[:-1], original + original[:1], [original[1], original[0], *original[2:]]):
            self.fixture.run["observations"] = value
            self.fixture.refresh()
            with self.assertRaises(quality.Invalid):
                self.fixture.evaluate()

    def test_different_ids_cannot_pad_corpus_with_duplicate_task_content(self):
        self.fixture.corpus["tasks"][1]["inputs"] = copy.deepcopy(self.fixture.corpus["tasks"][0]["inputs"])
        with self.assertRaisesRegex(quality.Invalid, "duplicate task content"):
            quality.validate_corpus(quality.Files(self.fixture.root), self.fixture.corpus)

    def test_empty_literal_output_is_preserved_without_fabricated_content(self):
        empty = self.fixture.put("empty.txt", b"")
        self.fixture.answer = empty
        for task in self.fixture.corpus["tasks"]:
            task["oracle"] = dict(kind="bytes-exact", artifact="result", expected=empty)
        self.fixture.build()
        self.assertEqual(self.fixture.evaluate()["final_successes"], 500)

    def test_shared_large_oracle_is_validated_once_and_only_metadata_is_retained(self):
        large = self.fixture.put("large-oracle.bin", b"x" * (2 * 1024 * 1024))
        for task in self.fixture.corpus["tasks"]:
            task["oracle"] = dict(kind="bytes-exact", artifact="result", expected=large)
        files = quality.Files(self.fixture.root)
        original = files.read
        observed = []
        def read(pin, maximum=quality.MAX_ARTIFACT):
            if pin["path"] == large["path"]:
                observed.append(pin["bytes"])
            return original(pin, maximum)
        with patch.object(files, "read", side_effect=read):
            tasks = quality.validate_corpus(files, self.fixture.corpus)
        self.assertEqual(observed, [2 * 1024 * 1024])
        self.assertEqual(len(tasks), 500)
        self.assertTrue(all(type(item[2]) is dict and set(item[2]) == {"kind", "artifact", "bytes", "sha256"}
                            for item in tasks.values()))
        self.assertLess(files.total, 3 * 1024 * 1024)

    def test_input_projection_verifies_bytes_without_retaining_them(self):
        files = quality.Files(self.fixture.root)
        entries = [dict(name="input", file=self.fixture.input)]
        committed, values = quality.projection(files, entries, retain=False)
        self.assertEqual(committed, quality.sha(quality.canonical(entries)))
        self.assertEqual(values, {})
        self.assertIn("input.txt", files.seen)

    def test_malformed_expected_oracles_refuse_before_execution(self):
        for kind, value in (("json-exact", b'{"bad":'), ("decimal-csv-exact", b"=1+2\n")):
            with self.subTest(kind=kind):
                pin = self.fixture.put("bad-expected.txt", value)
                self.fixture.corpus["tasks"][0]["oracle"] = dict(kind=kind, artifact="result", expected=pin)
                with self.assertRaises(quality.Invalid):
                    quality.validate_corpus(quality.Files(self.fixture.root), self.fixture.corpus)

    def test_document_path_is_validated_before_any_metadata_observation(self):
        files = quality.Files(self.fixture.root)
        for path in ("../outside.json", "/outside.json", "folder\\file.json", None, [], "file:stream"):
            with self.subTest(path=path), patch.object(Path, "lstat", side_effect=AssertionError("no metadata read")):
                with self.assertRaises(quality.Invalid):
                    quality.document(files, path, "a" * 64)

    def test_malformed_actual_json_and_csv_are_counted_failures_not_aborted_ingestion(self):
        for kind, expected, actual in (("json-exact", b'{"value":7}', b'{"broken":'),
                                       ("decimal-csv-exact", b"1,2\n", b"=MODEL_CLAIMS_PASS,2\n")):
            with self.subTest(kind=kind):
                # Only this task's oracle expects the extra actual artifact;
                # all499 other deterministic results still compare normally.
                self.fixture = Fixture(Path(self.directory.name))
                expected_pin = self.fixture.put("expected-special.txt", expected)
                self.fixture.corpus["tasks"][0]["oracle"] = dict(kind=kind, artifact="invalid", expected=expected_pin)
                self.fixture.build()
                attempt = self.fixture.run["observations"][0]["attempts"][0]
                bad_pin = self.fixture.put("actual-invalid.txt", actual)
                attempt["artifacts"].insert(0, dict(name="invalid", file=bad_pin))
                artifact_hash = quality.sha(quality.canonical(attempt["artifacts"]))
                receipt = json.loads((self.fixture.root / attempt["receipt"]["path"]).read_bytes())
                receipt["artifact_set_sha256"] = artifact_hash
                attempt["receipt"] = self.fixture.put(attempt["receipt"]["path"], receipt)
                self.fixture.refresh()
                result = self.fixture.evaluate()
                self.assertEqual(result["final_successes"], 499)
                self.assertEqual(result["oracle_failed_attempts"], 1)
                self.assertEqual(result["attempts"], 500)

    def test_wrong_current_run_tuple_and_receipt_refuse(self):
        self.fixture.build()
        self.fixture.run["context"]["tuple"] = dict(self.fixture.context["tuple"], model_sha256="b" * 64)
        self.fixture.refresh()
        with self.assertRaisesRegex(quality.Invalid, "manifest"):
            self.fixture.evaluate()

    def test_stale_future_and_reversed_run_refuse(self):
        self.fixture.build()
        for now in (self.fixture.now + timedelta(days=8), self.fixture.now - timedelta(hours=2)):
            with self.subTest(now=now), self.assertRaisesRegex(quality.Invalid, "run interval"):
                self.fixture.evaluate(now=now)
        with self.assertRaises(quality.Invalid):
            self.fixture.evaluate(max_age_seconds=604801)

    def test_missing_oracle_artifact_is_incomplete_not_success(self):
        self.fixture.build()
        self.fixture.run["observations"][0]["attempts"][0]["artifacts"][0]["name"] = "wrong"
        self.fixture.refresh()
        with self.assertRaises(quality.Invalid):
            self.fixture.evaluate()

    def test_bools_negative_metrics_clock_overlap_and_mismatched_counters_refuse(self):
        self.fixture.build()
        original = json.loads((self.fixture.root / "metric-000-1.json").read_bytes())
        for changes in ({"started_ns": True}, {"finished_ns": -1}, {"peak_memory_bytes": 999999},
                        {"ack_ns": 2000000}, {"first_result_ns": 1000001}, {"cancel_requested_ns": 200},
                        {"context_sha256": "b" * 64}):
            with self.subTest(changes=changes):
                self.fixture.put("metric-000-1.json", original)
                self.fixture.replace_metric(0, changes)
                with self.assertRaises(quality.Invalid):
                    self.fixture.evaluate()

    def test_energy_wrap_or_estimate_not_accepted_as_measured_energy(self):
        self.fixture.build()
        original = json.loads((self.fixture.root / "energy-000-1.json").read_bytes())
        for changes in ({"end_microjoules": 99}, {"method": "model-estimate"}, {"started_ns": True}):
            energy = self.fixture.put("energy-000-1.json", dict(original, **changes))
            self.fixture.replace_metric(0, {"energy_evidence": energy})
            with self.assertRaises(quality.Invalid):
                self.fixture.evaluate()

    def test_receipt_cannot_claim_authority_or_other_run(self):
        self.fixture.build()
        attempt = self.fixture.run["observations"][0]["attempts"][0]
        original = json.loads((self.fixture.root / attempt["receipt"]["path"]).read_bytes())
        for change in ({"authority_returned": True}, {"run_id": "older-run"}, {"attempt": True}):
            attempt["receipt"] = self.fixture.put("receipt-000-1.json", dict(original, **change))
            self.fixture.refresh()
            with self.assertRaises(quality.Invalid):
                self.fixture.evaluate()

    def test_strict_json_duplicate_nonfinite_type_and_depth(self):
        for value in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'[' * 26 + b'0' + b']' * 26):
            with self.subTest(value=value), self.assertRaises(quality.Invalid):
                quality.strict_json(value)
        self.assertFalse(quality.same_json(True, 1))
        self.assertFalse(quality.same_json(1.0, 1))

    def test_numeric_csv_is_exact_decimal_data_not_formulas_or_floats(self):
        self.assertEqual(quality.decimal_csv(b"1.000000000000000001,2\n"),
                         quality.decimal_csv(b'"1.000000000000000001",2.0\n'))
        self.assertNotEqual(quality.decimal_csv(b"1.000000000000000001\n"), quality.decimal_csv(b"1\n"))
        for value in (b"=1+2\n", b"NaN\n", b"1e2\n", b"1,2\n3\n", b"1\n\n", b"01\n"):
            with self.subTest(value=value), self.assertRaises(quality.Invalid):
                quality.decimal_csv(value)

    def test_json_oracle_numbers_never_round_or_underflow_to_false_matches(self):
        parse = lambda data: quality.strict_json(data, exact_numbers=True)
        self.assertFalse(quality.same_json(parse(b'{"n":0.0}'), parse(b'{"n":1e-1000}')))
        self.assertFalse(quality.same_json(parse(b'{"n":1.000000000000000001}'), parse(b'{"n":1.0}')))
        self.assertTrue(quality.same_json(parse(b'{"n":1e2}'), parse(b'{"n":100.0}')))
        self.assertFalse(quality.same_json(parse(b'{"n":1}'), parse(b'{"n":1.0}')))
        with self.assertRaises(quality.Invalid):
            parse(b'{"n":1e9999999999999999999999999999999999999999999999999999999}')

    def test_bytes_and_decimal_csv_oracles_use_actual_retained_bytes(self):
        expected = self.fixture.put("expected.csv", b"1.00,2\n")
        self.fixture.answer = self.fixture.put("actual.csv", b"1,2.0\n")
        self.fixture.corpus["tasks"][0]["oracle"] = dict(kind="decimal-csv-exact", artifact="result", expected=expected)
        self.fixture.corpus["tasks"][1]["oracle"] = dict(kind="bytes-exact", artifact="result", expected=expected)
        for task in self.fixture.corpus["tasks"][2:]:
            task["oracle"] = dict(kind="bytes-exact", artifact="result", expected=self.fixture.answer)
        self.fixture.build()
        self.assertEqual(self.fixture.evaluate()["final_successes"], 499)

    def test_changed_bytes_oversized_pin_and_arbitrary_paths_refuse(self):
        pin = self.fixture.input
        for change in ({"sha256": "b" * 64}, {"bytes": quality.MAX_ARTIFACT + 1}, {"path": "../input.txt"},
                       {"path": "input.txt:stream"}, {"path": "/input.txt"}, {"path": "a\\input.txt"}):
            with self.subTest(change=change), self.assertRaises(quality.Invalid):
                quality.Files(self.fixture.root).read(dict(pin, **change))

    def test_real_symlink_hardlink_and_parent_alias_refuse(self):
        # Actual Linux proof exercises symlinks and hardlinks. Windows takes
        # the hardlink branch only; no Windows reparse qualification is implied.
        target = self.fixture.root / "input.txt"
        hard = self.fixture.root / "hard.txt"
        os.link(target, hard)
        with self.assertRaises(quality.Invalid):
            quality.Files(self.fixture.root).read(self.fixture.input)
        hard.unlink()
        if os.name == "posix":
            alias = self.fixture.root / "alias.txt"
            alias.symlink_to(target)
            with self.assertRaises(quality.Invalid):
                quality.Files(self.fixture.root).read(dict(self.fixture.input, path="alias.txt"))
            directory = self.fixture.root / "alias-dir"
            directory.symlink_to(self.fixture.root, target_is_directory=True)
            with self.assertRaises(quality.Invalid):
                quality.Files(directory)

    def test_final_reobservation_detects_replacement(self):
        files = quality.Files(self.fixture.root)
        files.read(self.fixture.input)
        (self.fixture.root / "input.txt").write_bytes(b"changed")
        with self.assertRaises(quality.Invalid):
            files.finish()

    def test_cli_no_arbitrary_command_and_closed_failure(self):
        self.fixture.build()
        command = [sys.executable, "-B", "-W", "error", str(ROOT / "scripts/g3_quality.py"), "aggregate", "--evidence-root", str(self.fixture.root)]
        for name, pin in (("corpus", self.fixture.corpus_pin), ("run", self.fixture.run_pin),
                          ("current-manifest", self.fixture.manifest_pin), ("adjudications", self.fixture.adjudications_pin)):
            command.extend(["--"+name, pin["path"], "--"+name+"-sha256", pin["sha256"]])
        success = subprocess.run(command, capture_output=True, timeout=30, check=False)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(json.loads(success.stdout)["tasks"], 500)
        command[command.index("--run-sha256")+1] = "b" * 64
        result = subprocess.run(command, capture_output=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"evidence refused", result.stderr)

    def test_corpus_cli_is_read_only_and_reports_no_execution(self):
        self.fixture.build()
        result = subprocess.run([sys.executable, "-B", "-W", "error", str(ROOT / "scripts/g3_quality.py"),
            "validate-corpus", "--evidence-root", str(self.fixture.root), "--corpus", "corpus.json",
            "--corpus-sha256", self.fixture.corpus_pin["sha256"]], capture_output=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIs(json.loads(result.stdout)["task_execution_performed"], False)

    def test_schema_defs_and_runtime_supported_oracles_are_consistent(self):
        schema = json.loads((ROOT / "schemas/g3_quality.schema.json").read_bytes())
        self.assertEqual(schema["$defs"]["corpus"]["properties"]["tasks"]["minItems"], 500)
        pattern = quality.re.compile(schema["$defs"]["text"]["pattern"])
        self.assertIsNotNone(pattern.fullmatch("Literal human evidence"))
        self.assertIsNone(pattern.fullmatch("hidden\ncontrol"))
        refs = []
        stack = [schema]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                if "$ref" in value:
                    refs.append(value["$ref"])
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
        self.assertTrue(all(ref.startswith("#/$defs/") and ref[8:] in schema["$defs"] for ref in refs))


if __name__ == "__main__":
    unittest.main()
