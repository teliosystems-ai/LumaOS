from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "requirements_report.py"


def load_module():
    spec = importlib.util.spec_from_file_location("requirements_report", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load requirements report module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RequirementsCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.catalog = json.loads((ROOT / "requirements" / "catalog.json").read_text(encoding="utf-8"))

    def test_every_controlling_and_heritage_requirement_has_one_primary_stage(self) -> None:
        result = self.module.validate(self.catalog)
        self.assertEqual(result["requirement_count"], 288)
        identifiers = [record["requirement_id"] for record in result["records"]]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertIn("FR01", identifiers)
        self.assertIn("A140", identifiers)
        self.assertIn("W044", identifiers)
        self.assertIn("QW06", identifiers)

    def test_current_reference_evidence_never_claims_product_completion(self) -> None:
        result = self.module.validate(self.catalog)
        statuses = {record["current_status"] for record in result["records"]}
        self.assertEqual(statuses, {"planned", "reference_partial"})
        self.assertNotIn("passed", statuses)
        self.assertNotIn("complete", statuses)

    def test_invalid_duplicate_assignment_fails_closed(self) -> None:
        modified = json.loads(json.dumps(self.catalog))
        modified["stages"][1]["primary_requirements"].append("A077")
        with self.assertRaisesRegex(ValueError, "two primary stages"):
            self.module.validate(modified)

    def test_invalid_source_digest_fails_closed(self) -> None:
        modified = json.loads(json.dumps(self.catalog))
        modified["sources"][0]["sha256"] = "not-a-digest"
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.module.validate(modified)

    def test_strict_source_verification_works_without_external_workspace_files(self) -> None:
        modified = json.loads(json.dumps(self.catalog))
        with tempfile.TemporaryDirectory() as directory:
            source_base = Path(directory)
            for index, source in enumerate(modified["sources"], start=1):
                content = f"synthetic governing source {index}".encode()
                filename = f"source-{index}.docx"
                (source_base / filename).write_bytes(content)
                source["filename"] = filename
                source["workspace_path"] = filename
                source["sha256"] = hashlib.sha256(content).hexdigest()
            result = self.module.validate(
                modified,
                source_base=source_base,
                require_source_files=True,
            )
            self.assertEqual(result["verified_source_count"], 3)
            (source_base / "source-3.docx").unlink()
            with self.assertRaisesRegex(ValueError, "unavailable"):
                self.module.validate(
                    modified,
                    source_base=source_base,
                    require_source_files=True,
                )

    def test_catalog_loader_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema_version": 1, "schema_version": 1}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
                self.module.load(path)

    def test_cli_check_and_stage_report(self) -> None:
        checked = subprocess.run(
            [sys.executable, str(SCRIPT), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("288 requirements", checked.stdout)
        self.assertRegex(checked.stdout, r"[0-3]/3 source documents verified")
        report = subprocess.run(
            [sys.executable, str(SCRIPT), "--stage", "G0"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(report.returncode, 0, report.stderr)
        self.assertIn("## G0 Engineering baseline", report.stdout)
        self.assertNotIn("## G1 ", report.stdout)

    def test_every_catalog_stage_has_a_named_plan_test_phase_and_exit_gate(self) -> None:
        plan = (ROOT / "docs" / "DEVELOPMENT_PLAN.md").read_text(encoding="utf-8")
        folded = plan.casefold()
        for stage in self.catalog["stages"]:
            heading = f"## {stage['id']} {stage['name']}"
            start = folded.find(heading.casefold())
            self.assertGreaterEqual(start, 0, heading)
            end = folded.find("\n## ", start + len(heading))
            section = folded[start : end if end >= 0 else len(folded)]
            self.assertIn("**deliverables:**", section, stage["id"])
            self.assertIn("**dependencies:**", section, stage["id"])
            self.assertIn("testing phase", section, stage["id"])
            self.assertIn("**exit gate:**", section, stage["id"])

            planned_tests: set[str] = set()
            for expression in re.findall(
                r"\b(?:T|V)\d{2}(?:[\-–](?:(?:T|V))?\d{2})?\b",
                section.upper(),
            ):
                planned_tests.update(self.module.expand(expression.replace("–", "-")))
            expected_tests = set(self.module.expand_many(stage["verification"]))
            self.assertTrue(
                expected_tests.issubset(planned_tests),
                f"{stage['id']} plan omits {sorted(expected_tests - planned_tests)}",
            )


if __name__ == "__main__":
    unittest.main()
