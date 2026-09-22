#!/usr/bin/env python3
"""Render the deterministic requirement and gate-readiness report."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "requirements" / "registry.json"
DEFAULT_SOURCES = ROOT / "docs" / "governing_sources.json"
DEFAULT_REPORT = ROOT / "docs" / "GATE_REPORT.md"

FAMILY_ORDER = ["FR", "NF", "A", "Q", "W", "QW"]
GATE_ORDER = ["G0", "G1", "G2", "G3", "G4", "G5", "G6", "G7", "RX", "GWIN0", "GWIN1", "GWIN2"]
EXPECTED_FAMILY_COUNTS = {"FR": 60, "NF": 18, "A": 140, "Q": 20, "W": 44, "QW": 6}


class RegistryError(ValueError):
    """The registry cannot support a reliable report."""


def _load(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RegistryError(f"missing input: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RegistryError(f"invalid JSON in {path}: {exc}") from exc


def _escape(value: Any) -> str:
    if value is None or value == "":
        return "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def validate_registry(registry: dict[str, Any], sources: dict[str, Any]) -> None:
    requirements = registry.get("requirements")
    if not isinstance(requirements, list):
        raise RegistryError("requirements must be an array")
    ids = [item.get("id") for item in requirements if isinstance(item, dict)]
    if len(ids) != len(requirements) or len(ids) != len(set(ids)):
        raise RegistryError("requirement IDs must be present and unique")
    family_counts = Counter(item.get("family") for item in requirements)
    if family_counts != Counter(EXPECTED_FAMILY_COUNTS):
        raise RegistryError(
            f"expected family counts {EXPECTED_FAMILY_COUNTS}, got {dict(family_counts)}"
        )
    source_ids = {source.get("id") for source in sources.get("sources", [])}
    owner_ids = set(registry.get("owners", {}))
    environment_ids = set(registry.get("environments", {}))
    required_fields = {
        "release",
        "closure_gate",
        "profile_applicability",
        "owner",
        "dependencies",
        "implementation_status",
        "test_ids",
        "environments",
        "latest_evidence",
        "source_locator",
        "normative_text",
        "acceptance_reference_text",
        "source_test_ids",
    }
    for item in requirements:
        missing = sorted(required_fields - set(item))
        if missing:
            raise RegistryError(f"{item['id']} is missing fields: {', '.join(missing)}")
        if item["owner"] not in owner_ids:
            raise RegistryError(f"{item['id']} refers to unknown owner {item['owner']}")
        unknown_sources = set(item.get("source_ids", [])) - source_ids
        if unknown_sources:
            raise RegistryError(f"{item['id']} refers to unknown sources {sorted(unknown_sources)}")
        unknown_environments = set(item["environments"]) - environment_ids
        if unknown_environments:
            raise RegistryError(
                f"{item['id']} refers to unknown environments {sorted(unknown_environments)}"
            )
        if item.get("source_traceability") != "verified":
            raise RegistryError(f"{item['id']} does not have verified source traceability")
        if item.get("source_field_status") != "verified_structural":
            raise RegistryError(f"{item['id']} source fields are not structurally verified")
        if not item["source_locator"] or not item["normative_text"] or not item["acceptance_reference_text"]:
            raise RegistryError(f"{item['id']} has incomplete source fields")


def _gate_status(requirements: list[dict[str, Any]]) -> str:
    states = {item["latest_evidence"]["state"] for item in requirements}
    if "fail" in states:
        return "FAIL"
    if "blocked" in states:
        return "BLOCKED"
    if states <= {"pass", "not_applicable"}:
        return "PASS"
    return "INCOMPLETE"


def render_report(registry: dict[str, Any], sources: dict[str, Any]) -> str:
    validate_registry(registry, sources)
    requirements = registry["requirements"]
    by_gate: dict[str, list[dict[str, Any]]] = {
        gate: [item for item in requirements if item["closure_gate"] == gate]
        for gate in GATE_ORDER
        if gate != "G0"
    }
    family_counts = Counter(item["family"] for item in requirements)
    evidence_counts = Counter(item["latest_evidence"]["state"] for item in requirements)
    implementation_counts = Counter(item["implementation_status"] for item in requirements)
    mapping_counts = Counter(item["mapping_status"] for item in requirements)
    no_numbered_test = [item["id"] for item in requirements if not item["test_ids"]]
    g0_status = "VERIFIED" if sources["g0_impact"]["status"] == "resolved" else "BLOCKED"
    traced_count = sum(item.get("source_traceability") == "verified" for item in requirements)

    lines = [
        "# Requirement and gate report",
        "",
        "> Deterministic report generated from `requirements/registry.json` and "
        "`docs/governing_sources.json`. It reports requirement-register readiness; "
        "it is not by itself a product gate certificate.",
        "",
        "## Outcome",
        "",
        f"- Registry state: **{registry['status'].upper()}**.",
        f"- Explicit catalog entries: **{len(requirements)} / 288**.",
        f"- G0 governing-source traceability status: **{g0_status}**.",
        f"- Requirements with verified structural source fields: **{traced_count} / 288**.",
        f"- Requirements with blocked latest evidence: **{evidence_counts.get('blocked', 0)}**.",
        f"- Requirements with provisional mappings: **{mapping_counts.get('provisional', 0)}**.",
        "- No product requirement is closed by this report.",
        "",
        "The three pinned governing sources and the complete 288-ID structural traceability "
        "catalog are verified. This resolves the governing-source prerequisite only. The broader "
        "G0 gate is not certified by this report, plan-derived mappings remain provisional, and "
        "G1 and G2 cannot close while their required runtime, hardware, security, recovery, and "
        "performance evidence remains unavailable.",
        "",
        "## Catalog coverage",
        "",
        "| Family | Expected | Registered |",
        "| --- | ---: | ---: |",
    ]
    for family in FAMILY_ORDER:
        lines.append(
            f"| {family} | {EXPECTED_FAMILY_COUNTS[family]} | {family_counts.get(family, 0)} |"
        )

    lines.extend(
        [
            "",
            "## Governing sources",
            "",
            "| Source | Precedence | Revision | Date | Availability | Validation | SHA-256 |",
            "| --- | ---: | --- | --- | --- | --- | --- |",
        ]
    )
    for source in sorted(sources["sources"], key=lambda item: item["precedence"]):
        lines.append(
            "| "
            + " | ".join(
                [
                    _escape(source["id"]),
                    _escape(source["precedence"]),
                    _escape(source["revision"]),
                    _escape(source["document_date"]),
                    _escape(source["availability"]),
                    _escape(source["status"]),
                    _escape(source["sha256"]),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Gate register status",
            "",
            "| Gate | Requirements | In progress | Not started | Pass | Fail | Blocked | Status |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
            "| G0 | 0 | 0 | 0 | 0 | 0 | 0 | SOURCE-VERIFIED; BROADER GATE OPEN |",
        ]
    )
    for gate in GATE_ORDER:
        if gate == "G0":
            continue
        items = by_gate[gate]
        impl = Counter(item["implementation_status"] for item in items)
        evidence = Counter(item["latest_evidence"]["state"] for item in items)
        lines.append(
            f"| {gate} | {len(items)} | {impl.get('in_progress', 0)} | "
            f"{impl.get('not_started', 0)} | {evidence.get('pass', 0)} | "
            f"{evidence.get('fail', 0)} | {evidence.get('blocked', 0)} | "
            f"{_gate_status(items)} |"
        )

    lines.extend(
        [
            "",
            "## Assignment readiness",
            "",
            f"- Planned gate owner assigned: **{sum(bool(item['owner']) for item in requirements)} / 288**.",
            f"- Provisional profile applicability assigned: **{sum(bool(item['profile_applicability']) for item in requirements)} / 288**.",
            f"- Provisional environment assignment present: **{sum(bool(item['environments']) for item in requirements)} / 288**.",
            f"- Numbered planned test IDs present: **{len(requirements) - len(no_numbered_test)} / 288**.",
            "- Exact A077 test mapping recorded: **T40**.",
        ]
    )
    if no_numbered_test:
        lines.append(
            "- Missing numbered procedure: **"
            + ", ".join(no_numbered_test)
            + "** (the plan requires RX requirements change control before execution)."
        )

    lines.extend(
        [
            "",
            "Implementation status is a stage-level planning signal, not semantic requirement "
            "completion. `source_test_ids` contains only explicit source-row references; planned "
            "gate suites remain attached separately and provisionally unless the development plan "
            "states an exact mapping.",
            "",
            "## Open blockers",
            "",
            "| Blocker | State | Owner | Decision date | Affects | Reason |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for blocker in registry["blockers"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    _escape(blocker["id"]),
                    _escape(blocker["state"]),
                    _escape(blocker["owner"]),
                    _escape(blocker["decision_date"]),
                    _escape(", ".join(blocker["affects"])),
                    _escape(blocker["reason"]),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Status totals",
            "",
            "| Dimension | State | Count |",
            "| --- | --- | ---: |",
        ]
    )
    for state, count in sorted(implementation_counts.items()):
        lines.append(f"| Implementation | {_escape(state)} | {count} |")
    for state, count in sorted(evidence_counts.items()):
        lines.append(f"| Latest evidence | {_escape(state)} | {count} |")
    for state, count in sorted(mapping_counts.items()):
        lines.append(f"| Mapping | {_escape(state)} | {count} |")
    lines.append("")
    return "\n".join(lines)


def _check(path: Path, expected: str) -> int:
    try:
        actual = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"missing generated gate report: {path}", file=sys.stderr)
        return 1
    if actual != expected:
        print(f"generated gate report is stale: {path}", file=sys.stderr)
        return 1
    print(f"gate report is current: {path}")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--output", type=Path, help="write the report to this path")
    action.add_argument(
        "--check",
        nargs="?",
        type=Path,
        const=DEFAULT_REPORT,
        help="fail if the report path (default: docs/GATE_REPORT.md) is stale",
    )
    args = parser.parse_args(argv)
    try:
        rendered = render_report(_load(args.registry), _load(args.sources))
    except RegistryError as exc:
        print(f"gate report error: {exc}", file=sys.stderr)
        return 2
    if args.check is not None:
        return _check(args.check, rendered)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"wrote {args.output}")
        return 0
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
