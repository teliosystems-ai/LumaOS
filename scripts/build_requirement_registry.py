#!/usr/bin/env python3
"""Build the Luma OS requirement registry deterministically.

The builder reads the three pinned governing DOCX packages directly with the
Python standard library.  It verifies their immutable metadata, extracts the
288 source requirements, and keeps source-verified fields separate from the
gate, owner, profile, and environment assignments derived from the development
plan.  Source traceability is not product acceptance evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from pathlib import PurePosixPath
import re
from typing import Any, Iterable
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "requirements" / "registry.json"
GOVERNING_SOURCES = ROOT / "docs" / "governing_sources.json"
WORD_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


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


def _word_text(element: ET.Element) -> str:
    """Return visible Word text while preserving the package's character data."""

    return "".join(node.text or "" for node in element.iter(WORD_NS + "t")).strip()


def _table_cells(row: ET.Element) -> list[str]:
    cells: list[str] = []
    for cell in row.findall(WORD_NS + "tc"):
        paragraphs = [_word_text(paragraph) for paragraph in cell.iter(WORD_NS + "p")]
        cells.append(" ".join(text for text in paragraphs if text).strip())
    return cells


def _source_path(locator: str) -> Path:
    relative = PurePosixPath(locator)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"governing source locator must be repository-relative: {locator!r}")
    path = ROOT.joinpath(*relative.parts)
    try:
        path.resolve().relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"governing source locator escapes repository: {locator!r}") from exc
    return path


def _read_docx(source: dict[str, Any]) -> tuple[ET.Element, dict[str, str], list[tuple[int, str]]]:
    locator = source.get("locator")
    if not isinstance(locator, str) or not locator:
        raise ValueError(f"{source.get('id')} has no controlled DOCX locator")
    path = _source_path(locator)
    payload = path.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if len(payload) != source.get("size_bytes"):
        raise ValueError(f"{source['id']} byte size does not match governing_sources.json")
    if digest != source.get("sha256"):
        raise ValueError(f"{source['id']} SHA-256 does not match governing_sources.json")

    try:
        with zipfile.ZipFile(path) as archive:
            damaged = archive.testzip()
            if damaged is not None:
                raise ValueError(f"{source['id']} DOCX contains a damaged member: {damaged}")
            document = ET.fromstring(archive.read("word/document.xml"))
            core = ET.fromstring(archive.read("docProps/core.xml"))
    except (KeyError, zipfile.BadZipFile, ET.ParseError) as exc:
        raise ValueError(f"{source['id']} is not a readable DOCX package: {exc}") from exc

    core_properties = {
        node.tag.split("}")[-1]: "".join(node.itertext())
        for node in core
    }
    if core_properties.get("title") != source.get("document_title"):
        raise ValueError(f"{source['id']} title metadata does not match governing_sources.json")
    paragraphs = [
        (index, text)
        for index, paragraph in enumerate(document.iter(WORD_NS + "p"), 1)
        if (text := _word_text(paragraph))
    ]
    revision_text = source.get("revision_text")
    if not isinstance(revision_text, str) or revision_text not in {text for _, text in paragraphs}:
        raise ValueError(f"{source['id']} revision/date line is absent from word/document.xml")
    return document, core_properties, paragraphs


def _explicit_test_ids(*texts: str) -> list[str]:
    """Expand explicit T/V references while preserving first source occurrence."""

    pattern = re.compile(
        r"\b(?P<prefix>[TV])(?P<first>[0-9]{2})"
        r"(?:\s*(?:to|[-–—])\s*(?:(?P=prefix))?(?P<last>[0-9]{2}))?"
    )
    result: list[str] = []
    for text in texts:
        for match in pattern.finditer(text):
            prefix = match.group("prefix")
            first = int(match.group("first"))
            last = int(match.group("last") or match.group("first"))
            if last < first:
                raise ValueError(f"descending test range in source text: {match.group(0)!r}")
            for number in range(first, last + 1):
                test_id = f"{prefix}{number:02d}"
                if test_id not in result:
                    result.append(test_id)
    return result


def _procedure_catalog(document: ET.Element, prefix: str) -> set[str]:
    pattern = re.compile(rf"^({re.escape(prefix)}[0-9]{{2}})(?:\b|\s)")
    identifiers: set[str] = set()
    for table in document.iter(WORD_NS + "tbl"):
        for row in table.iter(WORD_NS + "tr"):
            cells = _table_cells(row)
            if cells and (match := pattern.match(cells[0])):
                identifiers.add(match.group(1))
    for paragraph in document.iter(WORD_NS + "p"):
        if match := pattern.match(_word_text(paragraph)):
            identifiers.add(match.group(1))
    return identifiers


def _row_requirement(
    requirement_id: str,
    qualifier: str | None,
    cells: list[str],
    locator: str,
) -> dict[str, Any]:
    family = _family(requirement_id)
    if len(cells) < 3:
        raise ValueError(f"{requirement_id} source row has fewer than three cells")

    source_title: str | None = None
    release_scope: str | None = None
    source_profiles: list[str] = []
    if family == "FR":
        if qualifier not in {"R1", "R2", "RX"}:
            raise ValueError(f"{requirement_id} has invalid source release scope {qualifier!r}")
        release_scope = qualifier
        normative_text = cells[1]
        acceptance_text = cells[2]
    elif family == "NF":
        source_title = qualifier
        normative_text = cells[1]
        acceptance_text = cells[2]
    elif family == "A":
        if qualifier not in {"A1", "A2", "A3"}:
            raise ValueError(f"{requirement_id} has invalid source release scope {qualifier!r}")
        release_scope = qualifier
        normative_text = cells[1]
        acceptance_text = cells[2]
    elif family in {"Q", "QW"}:
        source_title = cells[1] if family == "Q" else qualifier
        normative_text = cells[2] if family == "Q" else cells[1]
        acceptance_text = cells[2]
    else:
        raise ValueError(f"unsupported table requirement family: {family}")

    if not normative_text or not acceptance_text:
        raise ValueError(f"{requirement_id} has an empty normative or acceptance/reference field")
    return {
        "source_requirement_title": source_title,
        "source_release_scope": release_scope,
        "source_profile_applicability": source_profiles,
        "source_locator": locator,
        "normative_text": normative_text,
        "acceptance_reference_text": acceptance_text,
        "source_test_ids": _explicit_test_ids(normative_text, acceptance_text),
        "source_field_status": "verified_structural",
    }


def _extract_table_requirements(
    source_id: str,
    document: ET.Element,
    expected: set[str],
) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    identifier = re.compile(r"^(FR[0-9]{2}|NF[0-9]{2}|A[0-9]{3}|QW[0-9]{2}|Q[0-9]{2})(?:\s+(.+))?$")
    for table_index, table in enumerate(document.iter(WORD_NS + "tbl"), 1):
        for row_index, row in enumerate(table.iter(WORD_NS + "tr"), 1):
            cells = _table_cells(row)
            if not cells or not (match := identifier.fullmatch(cells[0])):
                continue
            requirement_id = match.group(1)
            if requirement_id not in expected:
                continue
            if requirement_id in entries:
                raise ValueError(f"{source_id} defines {requirement_id} more than once")
            entries[requirement_id] = _row_requirement(
                requirement_id,
                match.group(2),
                cells,
                f"word/document.xml table {table_index} row {row_index}",
            )
    return entries


def _extract_windows_requirements(
    source_id: str,
    paragraphs: list[tuple[int, str]],
    expected: set[str],
) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    heading = re.compile(r"^(W[0-9]{3})\s+(.+)$")
    profile_prefix = re.compile(r"^Profiles?\s+((?:[NDWV](?:\s+|\.|$))+)")
    for offset, (paragraph_index, text) in enumerate(paragraphs):
        match = heading.fullmatch(text)
        if match is None or match.group(1) not in expected:
            continue
        if offset + 2 >= len(paragraphs):
            continue
        normative_text = paragraphs[offset + 1][1]
        acceptance_text = paragraphs[offset + 2][1]
        profile_match = profile_prefix.match(normative_text)
        if profile_match is None or not acceptance_text.startswith("References:"):
            continue
        requirement_id = match.group(1)
        if requirement_id in entries:
            raise ValueError(f"{source_id} defines {requirement_id} more than once")
        profiles = re.findall(r"[NDWV]", profile_match.group(1))
        entries[requirement_id] = {
            "source_requirement_title": match.group(2),
            "source_release_scope": None,
            "source_profile_applicability": profiles,
            "source_locator": f"word/document.xml paragraph {paragraph_index}",
            "normative_text": normative_text,
            "acceptance_reference_text": acceptance_text,
            "source_test_ids": _explicit_test_ids(normative_text, acceptance_text),
            "source_field_status": "verified_structural",
        }
    return entries


def extract_governing_requirements(source_record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Verify governing artifacts and return all source requirement fields by ID."""

    if source_record.get("repository_check", {}).get("result") != "verified":
        raise ValueError("governing source record is not in verified repository state")
    all_entries: dict[str, dict[str, Any]] = {}
    for source in source_record.get("sources", []):
        source_id = source.get("id")
        if source.get("availability") != "present" or source.get("status") != "verified":
            raise ValueError(f"{source_id} is not marked present and verified")
        expected = {
            requirement_id
            for requirement_id in _expected_ids()
            if SOURCE_BY_FAMILY[_family(requirement_id)] == source_id
        }
        expected_families = sorted({_family(requirement_id) for requirement_id in expected})
        if sorted(source.get("requirement_families", [])) != expected_families:
            raise ValueError(f"{source_id} requirement family metadata is stale")
        if source.get("package_validation") != "passed":
            raise ValueError(f"{source_id} DOCX package validation is not passed")
        document, _, paragraphs = _read_docx(source)
        entries = _extract_table_requirements(source_id, document, expected)
        if source_id == "GOV-WIN-001":
            entries.update(_extract_windows_requirements(source_id, paragraphs, expected))
        if set(entries) != expected:
            raise ValueError(
                f"{source_id} requirement catalog mismatch; "
                f"missing={sorted(expected - set(entries))}, "
                f"unexpected={sorted(set(entries) - expected)}"
            )
        if source.get("requirement_count") != len(entries):
            raise ValueError(f"{source_id} requirement_count metadata is stale")

        procedure = source.get("verification_procedure_catalog")
        if not isinstance(procedure, dict):
            raise ValueError(f"{source_id} has no verification procedure catalog metadata")
        prefix = procedure.get("prefix")
        first = procedure.get("first")
        last = procedure.get("last")
        if not isinstance(prefix, str) or not isinstance(first, str) or not isinstance(last, str):
            raise ValueError(f"{source_id} has invalid verification procedure catalog metadata")
        expected_procedures = set(
            _numbered(prefix, 2, (int(first[1:]), int(last[1:])))
        )
        actual_procedures = _procedure_catalog(document, prefix)
        if actual_procedures != expected_procedures or procedure.get("count") != len(actual_procedures):
            raise ValueError(f"{source_id} verification procedure catalog is incomplete or stale")

        for requirement_id, fields in entries.items():
            if requirement_id in all_entries:
                raise ValueError(f"requirement appears in multiple governing sources: {requirement_id}")
            all_entries[requirement_id] = {"source_id": source_id, **fields}

    if set(all_entries) != _expected_ids():
        raise ValueError("combined governing sources do not define the exact 288-ID catalog")
    return all_entries


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
    source_requirements = extract_governing_requirements(source_record)
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
        source_fields = source_requirements[requirement_id]
        if source_fields["source_id"] != source_id:
            raise AssertionError(f"{requirement_id} resolved to the wrong governing source")
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
                "source_traceability": "verified",
                "source_requirement_title": source_fields["source_requirement_title"],
                "source_release_scope": source_fields["source_release_scope"],
                "source_profile_applicability": source_fields["source_profile_applicability"],
                "source_locator": source_fields["source_locator"],
                "normative_text": source_fields["normative_text"],
                "acceptance_reference_text": source_fields["acceptance_reference_text"],
                "source_test_ids": source_fields["source_test_ids"],
                "source_field_status": source_fields["source_field_status"],
                "mapping_status": "provisional",
                "latest_evidence": {
                    "state": "blocked",
                    "reason": (
                        f"{source_id} source traceability is verified, but no product execution "
                        "or acceptance evidence is attached; plan-derived assignments do not "
                        "close the requirement."
                    ),
                    "owner": "requirements-and-release-owner",
                    "as_of": source_record["recorded_at"],
                    "evidence_ids": [],
                },
            }
        )
    return {
        "schema_version": 1,
        "catalog_version": "governing-docx-2026-09-22-structural-v1",
        "recorded_at": source_record["recorded_at"],
        "status": "source_verified_plan_mappings_provisional",
        "normative_boundary": (
            "Normative and acceptance/reference fields are deterministic structural extracts "
            "from the pinned governing DOCX artifacts. Gate, owner, profile, and environment "
            "assignments remain plan-derived, and source verification is not product evidence."
        ),
        "source_files": [
            "docs/DEVELOPMENT_PLAN.md",
            "docs/governing_sources.json",
            *[source["locator"] for source in sorted(source_by_id.values(), key=lambda item: item["precedence"])],
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
