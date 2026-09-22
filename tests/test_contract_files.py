from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os import LumaConfig, LumaService


ROOT = Path(__file__).resolve().parents[1]


class SchemaValidationError(AssertionError):
    """Small dependency-free validator for the schema features used here."""


def _matches_type(value: object, expected: str) -> bool:
    checks = {
        "array": lambda item: isinstance(item, list),
        "boolean": lambda item: isinstance(item, bool),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "null": lambda item: item is None,
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "object": lambda item: isinstance(item, dict),
        "string": lambda item: isinstance(item, str),
    }
    if expected not in checks:
        raise SchemaValidationError(f"unsupported schema type in test validator: {expected}")
    return checks[expected](value)


def validate_schema(value: object, schema: dict[str, object], path: str = "$") -> None:
    """Validate one value against the dependency-free DTO schema subset."""

    expected_type = schema.get("type")
    if expected_type is not None:
        accepted = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_matches_type(value, str(candidate)) for candidate in accepted):
            raise SchemaValidationError(f"{path}: expected type {accepted}, got {type(value).__name__}")

    if "const" in schema and value != schema["const"]:
        raise SchemaValidationError(f"{path}: value does not match const")
    if "enum" in schema and value not in schema["enum"]:  # type: ignore[operator]
        raise SchemaValidationError(f"{path}: value is not in enum")

    if isinstance(value, str):
        if len(value) < int(schema.get("minLength", 0)):
            raise SchemaValidationError(f"{path}: string is shorter than minLength")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            raise SchemaValidationError(f"{path}: string is longer than maxLength")
        pattern = schema.get("pattern")
        if pattern is not None and re.search(str(pattern), value) is None:
            raise SchemaValidationError(f"{path}: string does not match pattern")
        if schema.get("format") == "date-time":
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise SchemaValidationError(f"{path}: invalid date-time") from exc
            if parsed.tzinfo is None:
                raise SchemaValidationError(f"{path}: date-time lacks an offset")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:  # type: ignore[operator]
            raise SchemaValidationError(f"{path}: number is below minimum")

    if isinstance(value, list):
        if len(value) < int(schema.get("minItems", 0)):
            raise SchemaValidationError(f"{path}: array is shorter than minItems")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise SchemaValidationError(f"{path}: array is longer than maxItems")
        if schema.get("uniqueItems"):
            canonical = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(canonical) != len(set(canonical)):
                raise SchemaValidationError(f"{path}: array items are not unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                validate_schema(item, item_schema, f"{path}[{index}]")

    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = set(required) - set(value)  # type: ignore[arg-type]
        if missing:
            raise SchemaValidationError(f"{path}: missing required fields {sorted(missing)}")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise SchemaValidationError(f"{path}: schema properties must be an object")
        if schema.get("additionalProperties") is False:
            unexpected = set(value) - set(properties)
            if unexpected:
                raise SchemaValidationError(f"{path}: additional properties {sorted(unexpected)}")
        for name, item in value.items():
            child_schema = properties.get(name)
            if isinstance(child_schema, dict):
                validate_schema(item, child_schema, f"{path}.{name}")


def openapi_operations(contract: str) -> set[tuple[str, str]]:
    """Extract operations from the deliberately conventional paths block."""

    operations: set[tuple[str, str]] = set()
    current_path: str | None = None
    in_paths = False
    for line in contract.splitlines():
        if line == "paths:":
            in_paths = True
            continue
        if in_paths and line and not line.startswith(" "):
            break
        path_match = re.fullmatch(r"  (/api/[^:]+):", line)
        if path_match:
            current_path = path_match.group(1)
            continue
        method_match = re.fullmatch(r"    (get|post|put|patch|delete):", line)
        if current_path and method_match:
            operations.add((method_match.group(1).upper(), current_path))
    return operations


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

    def test_openapi_exactly_covers_the_implemented_api_routes(self) -> None:
        contract = (ROOT / "schemas" / "openapi.yaml").read_text(encoding="utf-8")
        expected = {
            ("GET", "/api/health"),
            ("GET", "/api/status"),
            ("GET", "/api/models/status"),
            ("GET", "/api/grants"),
            ("POST", "/api/grants/enroll"),
            ("POST", "/api/grants/{grant_id}/revoke"),
            ("GET", "/api/workflows"),
            ("POST", "/api/workflows"),
            ("GET", "/api/workflows/{workflow_id}"),
            ("POST", "/api/workflows/{workflow_id}/run"),
            ("POST", "/api/workflows/{workflow_id}/manual"),
            ("POST", "/api/workflows/{workflow_id}/cancel"),
            ("GET", "/api/artifacts"),
            ("GET", "/api/artifacts/{artifact_id}"),
            ("GET", "/api/artifacts/{artifact_id}/content"),
            ("GET", "/api/receipts"),
        }
        self.assertEqual(expected, openapi_operations(contract))
        self.assertIn("Loopback-only", contract)
        self.assertIn("name: version", contract)
        self.assertIn("Omit to download the current version", contract)
        for filename in ("artifact", "grant", "receipt", "workflow"):
            self.assertIn(f'./{filename}.schema.json', contract)

    def test_example_is_fictional_and_parseable(self) -> None:
        rows = (ROOT / "examples" / "invoices.csv").read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            "invoice_id,vendor,invoice_date,category,amount,currency",
            rows[0],
        )
        self.assertGreaterEqual(len(rows), 3)

    def test_runtime_objects_fully_validate_against_closed_schemas(self) -> None:
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
            artifact_detail = {
                **artifact,
                "versions": service.artifacts.versions("contract-user", artifact["artifact_id"]),
            }

            values = {
                "grant.schema.json": grant,
                "workflow.schema.json": workflow,
                "artifact.schema.json": artifact_detail,
                "receipt.schema.json": receipt,
            }
            for filename, value in values.items():
                contract = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
                validate_schema(value, contract)

            self.assertEqual(grant["grant_id"], grant["id"])
            self.assertEqual(grant["root_path"], grant["root"])
            self.assertEqual(workflow["workflow_id"], workflow["id"])
            self.assertEqual(workflow["type"], workflow["kind"])
            self.assertEqual(artifact["artifact_id"], artifact["id"])
            self.assertEqual(receipt["receipt_id"], receipt["id"])

    def test_closed_schemas_reject_unknown_and_invalid_fields(self) -> None:
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
                idempotency_key="contract-negative",
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
                schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
                invalid = {**value, "undeclared_contract_field": True}
                with self.assertRaisesRegex(SchemaValidationError, "additional properties", msg=filename):
                    validate_schema(invalid, schema)

            workflow_schema = json.loads((ROOT / "schemas" / "workflow.schema.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(SchemaValidationError, "enum"):
                validate_schema({**workflow, "state": "MADE_UP"}, workflow_schema)

            artifact_schema = json.loads((ROOT / "schemas" / "artifact.schema.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(SchemaValidationError, "pattern"):
                validate_schema({**artifact, "content_hash": "not-a-sha256"}, artifact_schema)

            receipt_schema = json.loads((ROOT / "schemas" / "receipt.schema.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(SchemaValidationError, "minimum"):
                validate_schema({**receipt, "sequence": 0}, receipt_schema)

            grant_schema = json.loads((ROOT / "schemas" / "grant.schema.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(SchemaValidationError, "not unique"):
                validate_schema({**grant, "permissions": ["read", "read"]}, grant_schema)
            with self.assertRaisesRegex(SchemaValidationError, "minimum"):
                validate_schema({**grant, "generation": 0}, grant_schema)


if __name__ == "__main__":
    unittest.main()
