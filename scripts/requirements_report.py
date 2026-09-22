#!/usr/bin/env python3
"""Validate and report Luma OS requirement ownership and current evidence."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "requirements" / "catalog.json"
RANGE_RE = re.compile(r"^([A-Z]+)(\d+)(?:-([A-Z]+)?(\d+))?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def expand(spec: str) -> list[str]:
    """Expand one identifier or an inclusive same-prefix range."""

    match = RANGE_RE.fullmatch(spec)
    if match is None:
        raise ValueError(f"invalid requirement/test identifier expression: {spec!r}")
    prefix, first_raw, end_prefix, last_raw = match.groups()
    if last_raw is None:
        return [f"{prefix}{first_raw}"]
    if end_prefix and end_prefix != prefix:
        raise ValueError(f"range prefixes differ: {spec!r}")
    first = int(first_raw)
    last = int(last_raw)
    if last < first:
        raise ValueError(f"range is descending: {spec!r}")
    width = max(len(first_raw), len(last_raw))
    return [f"{prefix}{value:0{width}d}" for value in range(first, last + 1)]


def expand_many(specs: Iterable[str]) -> list[str]:
    values: list[str] = []
    for spec in specs:
        values.extend(expand(spec))
    return values


def series_ids(series: Iterable[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for item in series:
        prefix = str(item["prefix"])
        width = int(item["width"])
        values.extend(
            f"{prefix}{number:0{width}d}"
            for number in range(int(item["first"]), int(item["last"]) + 1)
        )
    return values


def validate(
    catalog: dict[str, Any],
    *,
    source_base: Path | None = None,
    require_source_files: bool = False,
) -> dict[str, Any]:
    if catalog.get("schema_version") != 1:
        raise ValueError("catalog schema_version must be 1")

    source_values = [str(item["id"]) for item in catalog.get("sources", [])]
    source_ids = set(source_values)
    if len(source_values) != len(source_ids):
        raise ValueError("source IDs must be unique")
    precedence = [str(item) for item in catalog.get("source_precedence", [])]
    if len(precedence) != len(set(precedence)) or set(precedence) != source_ids:
        raise ValueError("source_precedence must contain every source exactly once")

    verified_sources = 0
    for source in catalog.get("sources", []):
        filename = str(source.get("filename", ""))
        workspace_path = str(source.get("workspace_path", ""))
        digest = str(source.get("sha256", ""))
        if not filename or Path(filename).name != filename:
            raise ValueError(f"source {source.get('id')} must have a simple filename")
        if not workspace_path or Path(workspace_path).is_absolute():
            raise ValueError(f"source {source.get('id')} must have a relative workspace_path")
        if SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"source {source.get('id')} must have a lowercase SHA-256 digest")
        if source_base is not None:
            candidate = (source_base / workspace_path).resolve()
            if candidate.exists():
                if not candidate.is_file():
                    raise ValueError(f"source {source.get('id')} workspace path is not a file")
                observed = hashlib.sha256(candidate.read_bytes()).hexdigest()
                if observed != digest:
                    raise ValueError(f"source {source.get('id')} digest does not match {candidate}")
                verified_sources += 1
            elif require_source_files:
                raise ValueError(f"source {source.get('id')} is unavailable at {candidate}")

    for series_kind in ("requirement_series", "test_series"):
        for item in catalog.get(series_kind, []):
            if str(item.get("source")) not in source_ids:
                raise ValueError(f"{series_kind} references unknown source {item.get('source')}")

    requirements = series_ids(catalog.get("requirement_series", []))
    expected = set(requirements)
    if len(expected) != len(requirements):
        raise ValueError("requirement series overlap")

    test_values = series_ids(catalog.get("test_series", []))
    tests = set(test_values)
    if len(tests) != len(test_values):
        raise ValueError("test series overlap")
    stages = catalog.get("stages", [])
    stage_ids = [str(stage["id"]) for stage in stages]
    if len(stage_ids) != len(set(stage_ids)):
        raise ValueError("stage IDs must be unique")

    ownership: dict[str, str] = {}
    for stage in stages:
        stage_id = str(stage["id"])
        for dependency in stage.get("dependencies", []):
            if dependency not in stage_ids:
                raise ValueError(f"{stage_id} depends on unknown stage {dependency}")
        for requirement_id in expand_many(stage.get("primary_requirements", [])):
            if requirement_id not in expected:
                raise ValueError(f"{stage_id} references unknown requirement {requirement_id}")
            if requirement_id in ownership:
                raise ValueError(
                    f"{requirement_id} has two primary stages: {ownership[requirement_id]} and {stage_id}"
                )
            ownership[requirement_id] = stage_id
        for test_id in expand_many(stage.get("verification", [])):
            if test_id not in tests:
                raise ValueError(f"{stage_id} references unknown verification procedure {test_id}")
        if not stage.get("verification") and not str(stage.get("verification_note", "")).strip():
            raise ValueError(f"{stage_id} must define verification procedures or a verification_note")

    missing = sorted(expected - set(ownership))
    if missing:
        raise ValueError(f"requirements without a primary development stage: {', '.join(missing)}")

    # Detect dependency cycles with a small depth-first walk.
    dependencies = {str(stage["id"]): list(stage.get("dependencies", [])) for stage in stages}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(stage_id: str) -> None:
        if stage_id in visiting:
            raise ValueError(f"stage dependency cycle includes {stage_id}")
        if stage_id in visited:
            return
        visiting.add(stage_id)
        for dependency in dependencies[stage_id]:
            visit(dependency)
        visiting.remove(stage_id)
        visited.add(stage_id)

    for stage_id in stage_ids:
        visit(stage_id)

    current_status = {requirement_id: "planned" for requirement_id in requirements}
    current_evidence: dict[str, str] = {}
    for evidence in catalog.get("current_reference_evidence", []):
        status = str(evidence["status"])
        statement = str(evidence["evidence"])
        for requirement_id in expand_many(evidence.get("requirements", [])):
            if requirement_id not in expected:
                raise ValueError(f"current evidence references unknown requirement {requirement_id}")
            if requirement_id in current_evidence:
                raise ValueError(f"current evidence is duplicated for {requirement_id}")
            current_status[requirement_id] = status
            current_evidence[requirement_id] = statement

    source_by_requirement: dict[str, str] = {}
    for item in catalog["requirement_series"]:
        for requirement_id in series_ids([item]):
            source_by_requirement[requirement_id] = str(item["source"])

    records = [
        {
            "requirement_id": requirement_id,
            "source": source_by_requirement[requirement_id],
            "primary_stage": ownership[requirement_id],
            "current_status": current_status[requirement_id],
            "evidence": current_evidence.get(requirement_id),
        }
        for requirement_id in requirements
    ]
    return {
        "catalog_version": catalog["catalog_version"],
        "requirement_count": len(records),
        "stage_count": len(stages),
        "source_count": len(source_ids),
        "verified_source_count": verified_sources,
        "records": records,
        "status_counts": dict(sorted(Counter(record["current_status"] for record in records).items())),
    }


def markdown(catalog: dict[str, Any], validated: dict[str, Any], stage_filter: str | None) -> str:
    stages = catalog["stages"]
    if stage_filter:
        stages = [stage for stage in stages if stage["id"] == stage_filter]
        if not stages:
            raise ValueError(f"unknown stage: {stage_filter}")
    records = validated["records"]
    lines = [
        "# Luma OS requirement ownership report",
        "",
        f"Catalog version: `{validated['catalog_version']}`",
        "",
        f"Requirements: **{validated['requirement_count']}**  ",
        f"Stages: **{validated['stage_count']}**",
        f"Source documents verified in this workspace: **{validated['verified_source_count']} / {validated['source_count']}**",
        "",
    ]
    for stage in stages:
        stage_records = [record for record in records if record["primary_stage"] == stage["id"]]
        lines.extend(
            [
                f"## {stage['id']} {stage['name']}",
                "",
                f"Window: {stage['window']}",
                "",
                f"Primary requirement count: {len(stage_records)}",
                "",
                f"Verification: {', '.join(stage['verification']) or stage['verification_note']}",
                "",
                f"Exit gate: {stage['exit_gate']}",
                "",
                "| Requirement | Source | Current evidence state |",
                "| --- | --- | --- |",
            ]
        )
        lines.extend(
            f"| {record['requirement_id']} | {record['source']} | {record['current_status']} |"
            for record in stage_records
        )
        lines.append("")
    return "\n".join(lines)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(value, dict):
        raise ValueError("catalog root must be a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--check", action="store_true", help="validate without emitting the full report")
    parser.add_argument(
        "--require-source-files",
        action="store_true",
        help="fail unless every external governing document is present and matches its recorded digest",
    )
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--stage", help="emit only one stage in Markdown output")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        catalog = load(args.catalog)
        validated = validate(
            catalog,
            source_base=args.catalog.resolve().parent,
            require_source_files=args.require_source_files,
        )
        if args.check:
            print(
                f"requirements catalog valid: {validated['requirement_count']} requirements, "
                f"{validated['stage_count']} stages, "
                f"{validated['verified_source_count']}/{validated['source_count']} source documents verified"
            )
            return 0
        if args.format == "json":
            output = json.dumps(validated, indent=2, sort_keys=True) + "\n"
        else:
            output = markdown(catalog, validated, args.stage) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"requirements catalog invalid: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
