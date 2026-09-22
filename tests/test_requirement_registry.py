from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_requirement_registry import (  # noqa: E402
    build_registry,
    extract_governing_requirements,
    load_source_record,
    serialize_registry,
)
from gate_report import RegistryError, render_report, validate_registry  # noqa: E402


REGISTRY_PATH = ROOT / "requirements" / "registry.json"
SCHEMA_PATH = ROOT / "requirements" / "registry.schema.json"
REPORT_PATH = ROOT / "docs" / "GATE_REPORT.md"
SOURCES_PATH = ROOT / "docs" / "governing_sources.json"


def numbered(prefix: str, width: int, first: int, last: int) -> set[str]:
    return {f"{prefix}{number:0{width}d}" for number in range(first, last + 1)}


class RequirementRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.sources = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
        cls.by_id = {item["id"]: item for item in cls.registry["requirements"]}

    def test_catalog_contains_exactly_all_288_ids(self) -> None:
        expected = set()
        expected |= numbered("FR", 2, 1, 60)
        expected |= numbered("NF", 2, 1, 18)
        expected |= numbered("A", 3, 1, 140)
        expected |= numbered("Q", 2, 1, 20)
        expected |= numbered("W", 3, 1, 44)
        expected |= numbered("QW", 2, 1, 6)

        ids = [item["id"] for item in self.registry["requirements"]]

        self.assertEqual(288, len(ids))
        self.assertEqual(288, len(set(ids)))
        self.assertEqual(expected, set(ids))

    def test_every_entry_has_required_planning_and_evidence_fields(self) -> None:
        required = {
            "id",
            "family",
            "release",
            "closure_gate",
            "profile_applicability",
            "profile_mapping_status",
            "owner",
            "owner_status",
            "dependencies",
            "implementation_status",
            "test_ids",
            "test_mapping_status",
            "test_mapping_note",
            "environments",
            "environment_mapping_status",
            "source_ids",
            "source_traceability",
            "source_requirement_title",
            "source_release_scope",
            "source_profile_applicability",
            "source_locator",
            "normative_text",
            "acceptance_reference_text",
            "source_test_ids",
            "source_field_status",
            "mapping_status",
            "latest_evidence",
        }
        owners = set(self.registry["owners"])
        environments = set(self.registry["environments"])
        source_ids = {source["id"] for source in self.sources["sources"]}
        for item in self.registry["requirements"]:
            self.assertTrue(required.issubset(item), item["id"])
            self.assertIn(item["owner"], owners, item["id"])
            self.assertTrue(item["profile_applicability"], item["id"])
            self.assertTrue(item["dependencies"], item["id"])
            self.assertTrue(item["environments"], item["id"])
            self.assertTrue(set(item["environments"]).issubset(environments), item["id"])
            self.assertTrue(set(item["source_ids"]).issubset(source_ids), item["id"])
            self.assertEqual(
                {"state", "reason", "owner", "as_of", "evidence_ids"},
                set(item["latest_evidence"]),
                item["id"],
            )

    def test_gate_assignments_match_the_development_plan_catalog(self) -> None:
        expected = {
            "G1": 88,
            "G2": 34,
            "G3": 45,
            "G4": 31,
            "G5": 2,
            "G6": 18,
            "G7": 19,
            "RX": 1,
            "GWIN0": 17,
            "GWIN1": 20,
            "GWIN2": 13,
        }
        actual = Counter(item["closure_gate"] for item in self.registry["requirements"])

        self.assertEqual(expected, dict(actual))
        self.assertEqual("G1", self.by_id["A077"]["closure_gate"])
        self.assertEqual(["T40"], self.by_id["A077"]["test_ids"])
        self.assertEqual("explicit_in_plan", self.by_id["A077"]["test_mapping_status"])

    def test_verified_sources_are_traced_without_claiming_product_evidence(self) -> None:
        self.assertEqual("resolved", self.sources["g0_impact"]["status"])
        self.assertEqual(
            {"verified"},
            {source["status"] for source in self.sources["sources"]},
        )
        self.assertEqual(
            {"GOV-FEA-001"},
            {self.by_id[requirement_id]["source_ids"][0] for requirement_id in ("FR01", "NF18")},
        )
        self.assertEqual(
            {"GOV-UBU-001"},
            {self.by_id[requirement_id]["source_ids"][0] for requirement_id in ("A001", "Q20")},
        )
        self.assertEqual(
            {"GOV-WIN-001"},
            {self.by_id[requirement_id]["source_ids"][0] for requirement_id in ("W001", "QW06")},
        )
        for item in self.registry["requirements"]:
            self.assertEqual("provisional", item["mapping_status"], item["id"])
            self.assertEqual("verified", item["source_traceability"], item["id"])
            self.assertEqual("verified_structural", item["source_field_status"], item["id"])
            self.assertTrue(item["source_locator"], item["id"])
            self.assertTrue(item["normative_text"], item["id"])
            self.assertTrue(item["acceptance_reference_text"], item["id"])
            self.assertEqual("blocked", item["latest_evidence"]["state"], item["id"])
            self.assertTrue(item["latest_evidence"]["reason"], item["id"])
            self.assertTrue(item["latest_evidence"]["owner"], item["id"])

    def test_docx_extraction_matches_all_source_verified_registry_fields(self) -> None:
        extracted = extract_governing_requirements(self.sources)
        self.assertEqual(288, len(extracted))
        for requirement_id, item in self.by_id.items():
            source = extracted[requirement_id]
            self.assertEqual(item["source_ids"], [source["source_id"]])
            for field in (
                "source_requirement_title",
                "source_release_scope",
                "source_profile_applicability",
                "source_locator",
                "normative_text",
                "acceptance_reference_text",
                "source_test_ids",
                "source_field_status",
            ):
                self.assertEqual(item[field], source[field], f"{requirement_id}: {field}")

    def test_source_release_profiles_and_explicit_tests_are_exact(self) -> None:
        self.assertEqual("R1", self.by_id["FR01"]["source_release_scope"])
        self.assertEqual("RX", self.by_id["FR54"]["source_release_scope"])
        self.assertEqual("A2", self.by_id["A088"]["source_release_scope"])
        self.assertEqual(["T43"], self.by_id["A088"]["source_test_ids"])
        self.assertEqual(["N", "D", "W", "V"], self.by_id["W001"]["source_profile_applicability"])
        self.assertEqual(["V01", "T45"], self.by_id["W001"]["source_test_ids"])
        self.assertEqual(
            ["V01", "V12", "V13", "V14", "V15"],
            self.by_id["QW05"]["source_test_ids"],
        )

    def test_fr54_records_the_missing_numbered_rx_test_without_inventing_one(self) -> None:
        item = self.by_id["FR54"]
        self.assertEqual([], item["test_ids"])
        self.assertEqual("blocked_pending_change_control", item["test_mapping_status"])
        self.assertIn("change control", item["test_mapping_note"])
        self.assertEqual(
            ["FR54"],
            [item["id"] for item in self.registry["requirements"] if not item["test_ids"]],
        )

    def test_registry_schema_is_valid_json_and_pins_catalog_size(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
        requirements = schema["properties"]["requirements"]
        self.assertEqual(288, requirements["minItems"])
        self.assertEqual(288, requirements["maxItems"])
        schema_required = set(schema["$defs"]["requirement"]["required"])
        for item in self.registry["requirements"]:
            self.assertTrue(schema_required.issubset(item), item["id"])

    def test_checked_in_registry_is_deterministic(self) -> None:
        expected = serialize_registry(build_registry(load_source_record(SOURCES_PATH)))
        self.assertEqual(expected, REGISTRY_PATH.read_text(encoding="utf-8"))

    def test_checked_in_gate_report_is_deterministic_and_keeps_product_evidence_blocked(self) -> None:
        rendered = render_report(self.registry, self.sources)
        self.assertEqual(rendered, REPORT_PATH.read_text(encoding="utf-8"))
        self.assertIn("G0 governing-source traceability status: **VERIFIED**", rendered)
        self.assertIn("| G1 | 88 | 88 | 0 | 0 | 0 | 88 | BLOCKED |", rendered)
        self.assertIn("| G2 | 34 | 34 | 0 | 0 | 0 | 34 | BLOCKED |", rendered)
        self.assertIn("No product requirement is closed by this report.", rendered)

    def test_report_validation_rejects_duplicate_ids(self) -> None:
        invalid = deepcopy(self.registry)
        invalid["requirements"][1]["id"] = invalid["requirements"][0]["id"]
        with self.assertRaisesRegex(RegistryError, "unique"):
            validate_registry(invalid, self.sources)


if __name__ == "__main__":
    unittest.main()
