from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os import LumaConfig, LumaService


ROOT = Path(__file__).resolve().parents[1]


class ContractFileTests(unittest.TestCase):
    def test_json_schemas_are_valid_json_and_have_stable_ids(self) -> None:
        schema_dir = ROOT / "schemas"
        expected = {
            "artifact.schema.json",
            "grant.schema.json",
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
        self.assertTrue({"src", "web", "schemas", "examples", "tests"}.issubset(inputs))
        self.assertFalse(manifest["external_assets"]["model_weights_included"])
        self.assertEqual("0.1.0", manifest["version"])

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
