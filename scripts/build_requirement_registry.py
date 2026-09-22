#!/usr/bin/env python3
"""Build the provisional Luma OS requirement registry deterministically.

The governing DOCX inputs are not present in this checkout.  Consequently this
builder records the complete identifier catalog and the assignments that are
explicit in docs/DEVELOPMENT_PLAN.md, but deliberately marks source
traceability, profile mappings, test mappings, and evidence as provisional or
blocked.  It must not be used to infer normative requirement text.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "requirements" / "registry.json"
GOVERNING_SOURCES = ROOT / "docs" / "governing_sources.json"


def _numbered(prefix: str, width: int, *ranges: tuple[int, int]) -> list[str]:
    return [
        f"{prefix}{number:0{width}d}"
        for first, last in ranges
        for number in range(first, last + 1)
    ]


def _tests(prefix: str, width: int, *ranges: tuple[int, int]) -> list[str]:
    return _numbered(prefix, width, *ranges)


GATE_REQUIREMENTS: dict[str, list[str]] = {
    "G1": (
        _numbered("FR", 2, (9, 21), (41, 42), (44, 49), (57, 59))
        + _numbered("NF", 2, (2, 7), (10, 11), (16, 17))
        + _numbered("A", 3, (9, 28), (30, 37), (39, 47), (49, 56), (77, 77), (79, 86))
    ),
    "G2": (
        _numbered("FR", 2, (1, 7))
        + _numbered("NF", 2, (18, 18))
        + _numbered("A", 3, (1, 8), (101, 116), (118, 118))
        + _numbered("Q", 2, (15, 15))
    ),
    "G3": (
        _numbered("FR", 2, (22, 35), (37, 40), (50, 53), (55, 55))
        + _numbered("NF", 2, (1, 1), (8, 8), (12, 12), (14, 14))
        + _numbered("A", 3, (57, 71), (73, 75))
    ),
    "G4": (
        _numbered("FR", 2, (60, 60))
        + _numbered("NF", 2, (9, 9), (13, 13), (15, 15))
        + _numbered("A", 3, (93, 96), (98, 100), (131, 135), (138, 138), (140, 140))
        + _numbered("Q", 2, (1, 3), (6, 13), (17, 18))
    ),
    "G5": _numbered("A", 3, (97, 97)) + _numbered("Q", 2, (14, 14)),
    "G6": (
        _numbered("FR", 2, (8, 8), (36, 36), (43, 43), (56, 56))
        + _numbered("A", 3, (29, 29), (38, 38), (48, 48), (72, 72), (76, 76), (78, 78), (87, 90), (117, 117), (119, 119))
        + _numbered("Q", 2, (4, 5))
    ),
    "G7": (
        _numbered("A", 3, (91, 92), (120, 130), (136, 137), (139, 139))
        + _numbered("Q", 2, (16, 16), (19, 20))
    ),
    "RX": _numbered("FR", 2, (54, 54)),
    "GWIN0": _numbered("W", 3, (5, 12), (21, 22), (30, 32), (35, 36), (42, 43)),
    "GWIN1": (
        _numbered("W", 3, (13, 20), (23, 24), (34, 34), (37, 40))
        + _numbered("QW", 2, (1, 4), (6, 6))
    ),
    "GWIN2": (
        _numbered("W", 3, (1, 4), (25, 29), (33, 33), (41, 41), (44, 44))
        + _numbered("QW", 2, (5, 5))
    ),
}


GATE_DATA: dict[str, dict[str, Any]] = {
    "G1": {
        "release": "A1",
        "owner": "g1-p0-team",
        "dependencies": ["G0", "E1", "E2", "large-model-test-host", "legal-asset-permission"],
        "environments": ["E1", "E2", "LARGE_MODEL_HOST"],
        "tests": _tests("T", 2, (6, 16), (18, 20), (22, 33), (40, 42)),
    },
    "G2": {
        "release": "A1",
        "owner": "g2-cross-functional-team",
        "dependencies": ["G1", "lab-signing-and-recovery-keys", "disposable-installation-disks", "qualified-kernel-driver-candidates"],
        "environments": ["E1", "E2"],
        "tests": _tests("T", 2, (1, 16), (27, 30), (33, 33), (40, 40), (45, 51), (62, 62)),
    },
    "G3": {
        "release": "A1",
        "owner": "g3-cross-functional-team",
        "dependencies": ["G2"],
        "environments": ["E1", "E2"],
        "tests": _tests("T", 2, (20, 20), (29, 29), (31, 42), (56, 56), (58, 59)),
    },
    "G4": {
        "release": "A1",
        "owner": "g4-hardening-team",
        "dependencies": ["G3"],
        "environments": ["E1", "E2"],
        "tests": _tests("T", 2, (1, 42), (45, 51), (56, 59), (62, 62)),
    },
    "G5": {
        "release": "A1",
        "owner": "g5-release-team",
        "dependencies": ["G4", "production-signing-custody", "release-hosting", "redistribution-approvals"],
        "environments": ["E1", "E2"],
        "tests": _tests("T", 2, (1, 42), (45, 51), (56, 59), (62, 62)),
    },
    "G6": {
        "release": "A2",
        "owner": "g6-large-model-team",
        "dependencies": ["G5", "E3", "E4", "E5", "E6", "model-distribution-rights"],
        "environments": ["E3", "E4", "E5", "E6"],
        "tests": _tests("T", 2, (1, 1), (5, 5), (17, 17), (21, 21), (25, 26), (31, 31), (37, 37), (43, 43), (51, 52), (54, 54)),
    },
    "G7": {
        "release": "A3",
        "owner": "g7-distributed-systems-team",
        "dependencies": ["G6", "E7", "E9", "E10", "pki", "storage-network-ownership", "funded-scale-access"],
        "environments": ["E7", "E9", "E10"],
        "tests": _tests("T", 2, (41, 41), (44, 44), (52, 55), (58, 58), (60, 62)),
    },
    "RX": {
        "release": "RX",
        "owner": "rx-research-team",
        "dependencies": ["G3", "separate-authorization", "separate-funding"],
        "environments": ["RX_REFERENCE_BOARD"],
        "tests": [],
    },
    "GWIN0": {
        "release": "A1-WINDOWS",
        "owner": "gwin0-cross-functional-team",
        "dependencies": ["G1", "windows-11-x64-host", "wsl2", "hyper-v-pro-enterprise-host"],
        "environments": ["WIN11_WSL2", "WIN11_HYPERV"],
        "tests": (
            _tests("V", 2, (1, 1), (3, 6), (8, 10), (15, 16), (18, 18))
            + _tests("T", 2, (2, 2), (13, 13), (24, 25), (29, 30), (40, 40), (42, 42), (45, 45), (51, 51), (62, 62))
        ),
    },
    "GWIN1": {
        "release": "A1-WINDOWS",
        "owner": "gwin1-cross-functional-team",
        "dependencies": ["GWIN0", "G3"],
        "environments": ["WIN11_WSL2"],
        "tests": (
            _tests("V", 2, (1, 1), (3, 12), (16, 18))
            + _tests("T", 2, (4, 4), (32, 36), (41, 42), (56, 57), (59, 59))
        ),
    },
    "GWIN2": {
        "release": "A1-WINDOWS",
        "owner": "gwin2-qualification-team",
        "dependencies": ["GWIN1", "G5", "encrypted-windows-disk-fixtures", "firmware-key-recovery-lab"],
        "environments": ["WIN11_DUAL_BOOT", "WIN11_HYPERV"],
        "tests": (
            _tests("V", 2, (1, 18))
            + _tests("T", 2, (1, 1), (5, 5), (39, 40), (45, 47), (49, 49), (51, 51))
        ),
    },
}


OWNERS = {
    "requirements-and-release-owner": "Accepts controlled governing sources and coordinates traceability reconciliation.",
    "g1-p0-team": "G1 platform, systems/inference, workflow/storage, security, and UI integration owners.",
    "g2-cross-functional-team": "G2 platform, systems/inference, agent/workflow, storage, security, QA, and release owners.",
    "g3-cross-functional-team": "G3 storage, desktop/application, inference, compatibility, security, QA, and product/UX owners.",
    "g4-hardening-team": "G4 component owners under QA, security, release, and architecture leadership.",
    "g5-release-team": "G5 release, QA, security, platform, product/UX, and support owners.",
    "g6-large-model-team": "G6 A2 team with multi-GPU inference and qualification specialists.",
    "g7-distributed-systems-team": "G7 distributed-systems, SRE/storage, PKI, and test owners.",
    "rx-research-team": "Separately authorized RX kernel/platform, driver, security, compatibility, and inference researchers.",
    "gwin0-cross-functional-team": "GWIN0 architecture/platform, Windows/release, storage/security, and inference owners.",
    "gwin1-cross-functional-team": "GWIN1 Windows storage, lifecycle, QA, and operations owners.",
    "gwin2-qualification-team": "GWIN2 platform, Windows, security, QA, release, and support owners.",
}


ENVIRONMENTS = {
    "E0": "Initial environment named by G0; exact governed definition unavailable.",
    "E1": "First named x86-64 A1 reference machine established by G0.",
    "E2": "Second named x86-64 A1 reference machine established by G0.",
    "E3": "A2 environment named by the G6 dependency set; exact governed definition unavailable.",
    "E4": "A2 environment named by the G6 dependency set; exact governed definition unavailable.",
    "E5": "A2 environment named by the G6 dependency set; exact governed definition unavailable.",
    "E6": "Physical ARM64 board required by G6.",
    "E7": "Distributed lab environment named by G7; exact governed definition unavailable.",
    "E8": "Initial environment named by G0; exact governed definition unavailable.",
    "E9": "Distributed lab environment named by G7; exact governed definition unavailable.",
    "E10": "Distributed lab environment named by G7; exact governed definition unavailable.",
    "LARGE_MODEL_HOST": "Suitable real-hardware host for the G1 placement/load experiment.",
    "RX_REFERENCE_BOARD": "One documented physical reference board for RX research.",
    "WIN11_WSL2": "Supported Windows 11 x64 host with WSL2.",
    "WIN11_HYPERV": "Windows 11 Pro/Enterprise host with Hyper-V and a qualified guest.",
    "WIN11_DUAL_BOOT": "Disposable Windows 11 dual-boot fixture with firmware-key recovery capability.",
}


SOURCE_BY_FAMILY = {
    "FR": "GOV-FEA-001",
    "NF": "GOV-FEA-001",
    "A": "GOV-UBU-001",
    "Q": "GOV-UBU-001",
    "W": "GOV-WIN-001",
    "QW": "GOV-WIN-001",
}


def _family(requirement_id: str) -> str:
    for prefix in ("QW", "FR", "NF", "A", "Q", "W"):
        if requirement_id.startswith(prefix):
            return prefix
    raise ValueError(f"unrecognized requirement ID: {requirement_id}")


def _profile_applicability(requirement_id: str, gate: str) -> list[str]:
    """Return only applicability directly supported by the development plan.

    Ubuntu-source requirements receive the explicit native baseline.  Adapted
    applicability to Windows profiles remains unresolved until source
    reconciliation.  Windows gate profiles are gate-level plans rather than
    verified requirement semantics.
    """

    family = _family(requirement_id)
    if family not in {"W", "QW"}:
        return ["N"]
    if gate == "GWIN1":
        return ["W"]
    if gate == "GWIN0":
        if requirement_id in set(_numbered("W", 3, (30, 32))):
            return ["V"]
        return ["W", "V"]
    if requirement_id in set(_numbered("W", 3, (1, 4), (41, 41), (44, 44))):
        return ["N", "D", "W", "V"]
    if requirement_id in set(_numbered("W", 3, (25, 29))):
        return ["D"]
    if requirement_id == "W033":
        return ["V"]
    if requirement_id == "QW05":
        return ["D", "V"]
    raise AssertionError(f"profile mapping missing for {requirement_id}")


def _expected_ids() -> set[str]:
    return set(
        _numbered("FR", 2, (1, 60))
        + _numbered("NF", 2, (1, 18))
        + _numbered("A", 3, (1, 140))
        + _numbered("Q", 2, (1, 20))
        + _numbered("W", 3, (1, 44))
        + _numbered("QW", 2, (1, 6))
    )


def _validate_gate_catalog() -> None:
    assigned = [item for requirements in GATE_REQUIREMENTS.values() for item in requirements]
    if len(assigned) != len(set(assigned)):
        duplicates = sorted(item for item in set(assigned) if assigned.count(item) > 1)
        raise AssertionError(f"requirements assigned to multiple gates: {duplicates}")
    expected = _expected_ids()
    actual = set(assigned)
    if actual != expected:
        raise AssertionError(
            f"requirement catalog mismatch; missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def _sort_key(requirement_id: str) -> tuple[int, int]:
    family = _family(requirement_id)
    order = {"FR": 0, "NF": 1, "A": 2, "Q": 3, "W": 4, "QW": 5}
    return order[family], int(requirement_id[len(family) :])


def build_registry(source_record: dict[str, Any]) -> dict[str, Any]:
    _validate_gate_catalog()
    source_by_id = {source["id"]: source for source in source_record["sources"]}
    gate_for = {
        requirement_id: gate
        for gate, requirement_ids in GATE_REQUIREMENTS.items()
        for requirement_id in requirement_ids
    }
    requirements: list[dict[str, Any]] = []
    for requirement_id in sorted(_expected_ids(), key=_sort_key):
        family = _family(requirement_id)
        gate = gate_for[requirement_id]
        gate_data = GATE_DATA[gate]
        source_id = SOURCE_BY_FAMILY[family]
        source = source_by_id[source_id]
        if requirement_id == "A077":
            test_ids = ["T40"]
            test_mapping_status = "explicit_in_plan"
            test_mapping_note = "DEVELOPMENT_PLAN.md explicitly assigns A077/T40 to G1."
        elif requirement_id == "FR54":
            test_ids = []
            test_mapping_status = "blocked_pending_change_control"
            test_mapping_note = "The RX section requires a new numbered procedure through requirements change control."
        else:
            test_ids = list(gate_data["tests"])
            test_mapping_status = "provisional_gate_suite"
            test_mapping_note = "Gate-level suite only; exact one-to-one mapping requires governing-source reconciliation."
        requirements.append(
            {
                "id": requirement_id,
                "family": family,
                "release": gate_data["release"],
                "closure_gate": gate,
                "profile_applicability": _profile_applicability(requirement_id, gate),
                "profile_mapping_status": "provisional_plan_assignment",
                "owner": gate_data["owner"],
                "owner_status": "planned_gate_owner",
                "dependencies": [source_id, *gate_data["dependencies"]],
                "implementation_status": "in_progress" if gate == "G1" else "not_started",
                "test_ids": test_ids,
                "test_mapping_status": test_mapping_status,
                "test_mapping_note": test_mapping_note,
                "environments": list(gate_data["environments"]),
                "environment_mapping_status": "provisional_gate_assignment",
                "source_ids": [source_id],
                "source_traceability": "blocked",
                "mapping_status": "provisional",
                "latest_evidence": {
                    "state": "blocked",
                    "reason": (
                        f"{source_id} is {source['status']}; exact normative text and semantic "
                        "traceability are unavailable."
                    ),
                    "owner": "requirements-and-release-owner",
                    "as_of": source_record["recorded_at"],
                    "evidence_ids": [],
                },
            }
        )
    return {
        "schema_version": 1,
        "catalog_version": "development-plan-2026-09-22-provisional",
        "recorded_at": source_record["recorded_at"],
        "status": "provisional_blocked",
        "normative_boundary": (
            "This registry enumerates plan-derived IDs and provisional assignments only. "
            "It does not reproduce or replace absent governing requirement text."
        ),
        "source_files": [
            "docs/DEVELOPMENT_PLAN.md",
            "docs/governing_sources.json",
        ],
        "governing_source_state": source_record["g0_impact"],
        "profiles": {
            "N": "Native Ubuntu",
            "D": "Dual boot",
            "W": "Windows 11 with WSL2",
            "V": "Windows 11 with Hyper-V VM",
        },
        "owners": OWNERS,
        "environments": ENVIRONMENTS,
        "blockers": [
            {
                "id": "BLK-GOVERNING-SOURCES",
                "state": "blocked",
                "owner": "requirements-and-release-owner",
                "decision_date": None,
                "reason": "All three governing DOCX inputs are absent and lack immutable digests.",
                "affects": ["G0", "G1", "G2", "G3", "G4", "G5", "G6", "G7", "RX", "GWIN0", "GWIN1", "GWIN2"],
            },
            {
                "id": "BLK-RX-TEST-PROCEDURE",
                "state": "blocked",
                "owner": "rx-research-team",
                "decision_date": None,
                "reason": "FR54 has no source-numbered RX verification procedure; change control is required before RX execution.",
                "affects": ["RX"],
            },
        ],
        "requirements": requirements,
    }


def serialize_registry(registry: dict[str, Any]) -> str:
    return json.dumps(registry, indent=2, ensure_ascii=False) + "\n"


def load_source_record(path: Path = GOVERNING_SOURCES) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _check(output: Path, expected: str) -> int:
    try:
        actual = output.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"missing generated registry: {output}")
        return 1
    if actual != expected:
        print(f"generated registry is stale: {output}")
        return 1
    print(f"requirement registry is current: {output}")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="fail if the output is not current")
    args = parser.parse_args(argv)
    rendered = serialize_registry(build_registry(load_source_record()))
    if args.check:
        return _check(args.output, rendered)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
