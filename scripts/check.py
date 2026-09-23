#!/usr/bin/env python3
"""Dependency-free repository validation for local development and CI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import py_compile
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DOCS = (
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "docs/ARCHITECTURE.md",
    "docs/THREAT_MODEL.md",
    "docs/REQUIREMENTS_COVERAGE.md",
    "docs/ROADMAP.md",
    "docs/SUPPORT_MATRIX.md",
    "docs/OPERATIONS.md",
    "docs/PRODUCTION_SIGNING_CUSTODY.md",
    "docs/RELEASE.md",
    "docs/UBUNTU_QUALIFICATION.md",
    "docs/DEVELOPMENT_PLAN.md",
    "docs/GOVERNING_REQUIREMENTS_SOURCES.md",
    "docs/GATE_REPORT.md",
)
REQUIRED_SOURCE_DOCUMENTS = (
    "docs/Requirements/LLM OS requirements.md",
    "docs/Requirements/LLM_OS_Feasibility_HLD_LLD_Engineering_Requirements.docx",
    "docs/Requirements/LLM_OS_Practical_Implementation_Research_Paper.docx",
    "docs/Requirements/LLM_OS_Windows_Deployment_Requirements_Variation.docx",
    "docs/Requirements/LLM_OS_Windows_Deployment_Requirements_Variation.md",
    "docs/Requirements/Option_Ubuntu_LLM_OS_Functional_Requirements_Development_Testing_4B_to_400B.docx",
)
GOVERNING_SOURCE_RECORD = "docs/governing_sources.json"
HISTORICAL_G2_TEST_RUN = "docs/gates/g2/test_run_2026-09-23.json"
HISTORICAL_G2_ARCHIVE_ATTESTATION = (
    "docs/gates/g2/archive_attestation_2026-09-23.json"
)
PRIOR_G2_TEST_RUN = "docs/gates/g2/test_run_2026-09-23-002.json"
PRIOR_G2_ARCHIVE_ATTESTATION = (
    "docs/gates/g2/archive_attestation_2026-09-23-002.json"
)
G2_TEST_RUN = "docs/gates/g2/test_run_2026-09-23-003.json"
G2_ARCHIVE_ATTESTATION = "docs/gates/g2/archive_attestation_2026-09-23-003.json"
HISTORICAL_DETACHED_G2_EVIDENCE_FILES = (
    HISTORICAL_G2_TEST_RUN,
    HISTORICAL_G2_ARCHIVE_ATTESTATION,
    PRIOR_G2_TEST_RUN,
    PRIOR_G2_ARCHIVE_ATTESTATION,
)
CURRENT_DETACHED_G2_EVIDENCE_FILES = (G2_TEST_RUN, G2_ARCHIVE_ATTESTATION)
DETACHED_G2_EVIDENCE_FILES = (
    *HISTORICAL_DETACHED_G2_EVIDENCE_FILES,
    *CURRENT_DETACHED_G2_EVIDENCE_FILES,
)
HISTORICAL_DETACHED_G2_SHA256 = {
    HISTORICAL_G2_TEST_RUN: (
        "a5ccf0720b2bbcfcd443ea565364a628979afc51724c4f70eb69d8d88be9b628"
    ),
    HISTORICAL_G2_ARCHIVE_ATTESTATION: (
        "a15c067aabd89c69c01cae0ab8b68acecd91155149de8fe3be693db4c632002d"
    ),
    PRIOR_G2_TEST_RUN: (
        "ccfdb39205ffc3f1653308df2a9953c0b9020cade7bb9ccc2e9538c1cef815e0"
    ),
    PRIOR_G2_ARCHIVE_ATTESTATION: (
        "7160fcbf6b177f0ea8487b4b1857c0a0b3095f6ffbadd12c6d3df6c1136b5360"
    ),
}
REQUIRED_GATE_FILES = (
    "docs/adr/0001-python-reference-rust-production.md",
    "docs/adr/0002-service-boundaries-and-transport.md",
    "docs/adr/0003-artifact-storage.md",
    "docs/adr/0004-policy-model.md",
    "docs/adr/0005-model-pack-and-signing.md",
    "docs/adr/0006-supported-package-layout.md",
    "docs/adr/0007-admin-delegation-and-signing-custody.md",
    "docs/adr/0008-model-pack-v2-and-install-time-model-selection.md",
    "docs/gates/final_certification_deferrals.json",
    "docs/gates/g0/blockers.json",
    "docs/gates/g0/ci_lanes.json",
    "docs/gates/g0/evidence.json",
    "docs/gates/g0/lab_inventory.json",
    "docs/gates/g0/security_review.json",
    "docs/gates/g1/blockers.json",
    "docs/gates/g1/development_model_selection.json",
    "docs/gates/g1/evidence.json",
    "docs/gates/g1/hardware_smoke_2026-09-22.json",
    "docs/gates/g1/local_model_smoke_2026-09-22.json",
    "docs/gates/g1/model_candidate_smoke_2026-09-23.json",
    "docs/gates/g1/test_run_2026-09-22.json",
    "docs/gates/g2/blockers.json",
    "docs/gates/g2/evidence.json",
    "docs/gates/g2/OPERATOR_APPROVAL_AND_EXECUTION.md",
    "docs/gates/g2/PHYSICAL_QUALIFICATION_RUNBOOK.md",
    "docs/gates/g2/test_plan.json",
    "docs/gates/g2/test_run_2026-09-22.json",
    "docs/registers/adversarial.json",
    "docs/registers/failure_injection.json",
    "docs/registers/licenses.json",
    "docs/registers/workloads.json",
    "requirements/registry.json",
    "requirements/registry.schema.json",
)
REQUIRED_RELEASE_FILES = (
    *REQUIRED_DOCS,
    *REQUIRED_SOURCE_DOCUMENTS,
    GOVERNING_SOURCE_RECORD,
    *REQUIRED_GATE_FILES,
)
REQUIRED_INVENTORY_FILES = (
    *REQUIRED_RELEASE_FILES,
    ".gitattributes",
    "schemas/g2-host-inventory.schema.json",
    "schemas/model-catalog-signature.schema.json",
    "schemas/model-pack.schema.json",
    "schemas/model-profile.schema.json",
    "scripts/collect_g2_host.py",
    "scripts/model_catalog_ceremony.py",
    "scripts/smoke_local_model.py",
    "scripts/ubuntu_preflight.py",
    "src/luma_os/administration.py",
    "src/luma_os/boot_control.py",
    "src/luma_os/durable_effects.py",
    "src/luma_os/g2_host_inventory.py",
    "src/luma_os/installer.py",
    "src/luma_os/model_catalog_signing.py",
    "src/luma_os/model_pack.py",
    "src/luma_os/model_selection.py",
    "src/luma_os/privileged_helper.py",
    "src/luma_os/real_inference.py",
    "tests/test_administration.py",
    "tests/test_boot_control.py",
    "tests/test_durable_effects.py",
    "tests/test_g2_host_inventory.py",
    "tests/test_installer.py",
    "tests/test_model_catalog_signing.py",
    "tests/test_model_pack.py",
    "tests/test_model_selection.py",
    "tests/test_privileged_helper.py",
    "tests/test_real_inference.py",
    "tests/test_smoke_local_model.py",
    "tests/test_ubuntu_preflight.py",
)
GOVERNING_SOURCE_FILENAMES = {
    "LLM_OS_Windows_Deployment_Requirements_Variation.docx",
    "Option_Ubuntu_LLM_OS_Functional_Requirements_Development_Testing_4B_to_400B.docx",
    "LLM_OS_Feasibility_HLD_LLD_Engineering_Requirements.docx",
}
REQUIRED_RELEASE_INPUTS = {
    "src",
    "tests",
    "web",
    "schemas",
    "examples",
    "docs",
    "requirements",
    "scripts",
    "packaging",
}
FORBIDDEN_ASSET_SUFFIXES = {".gguf", ".safetensors", ".onnx", ".ckpt", ".pt", ".pth"}
SOURCE_ARCHIVE_PATH = PurePosixPath("docs/Requirements.zip")
EXPECTED_EXECUTABLE_RELEASE_FILES = {
    "packaging/systemd/install-user-service.sh",
    "scripts/build_release.py",
    "scripts/check.py",
    "scripts/install-user.sh",
    "scripts/run.sh",
    "scripts/uninstall-user.sh",
}


def report(label: str, detail: str = "") -> None:
    suffix = f" — {detail}" if detail else ""
    print(f"[ok] {label}{suffix}")


def compile_sources() -> None:
    sources = sorted((ROOT / "src").rglob("*.py"))
    if not sources:
        raise RuntimeError("no Python sources found under src/")
    with tempfile.TemporaryDirectory(prefix="luma-compile-") as target:
        target_dir = Path(target)
        for source in sources:
            relative = source.relative_to(ROOT / "src")
            output = target_dir / relative.with_suffix(".pyc")
            output.parent.mkdir(parents=True, exist_ok=True)
            py_compile.compile(str(source), cfile=str(output), doraise=True)
    report("Python compilation", f"{len(sources)} files")


def validate_metadata() -> None:
    manifest_path = ROOT / "RELEASE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("project") != "luma-os":
        raise RuntimeError("release manifest project must be luma-os")
    version = manifest.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise RuntimeError("release manifest version must be SemVer core format")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version_match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    if version_match is None or version_match.group(1) != version:
        raise RuntimeError("pyproject and release manifest versions differ")
    release_inputs = set(manifest.get("release_inputs", []))
    missing_inputs = REQUIRED_RELEASE_INPUTS - release_inputs
    if missing_inputs:
        raise RuntimeError(f"release manifest omits inputs: {sorted(missing_inputs)}")
    required_files = set(manifest.get("required_release_files", []))
    missing_required_files = set(REQUIRED_RELEASE_FILES) - required_files
    if missing_required_files:
        raise RuntimeError(
            f"release manifest omits required files: {sorted(missing_required_files)}"
        )
    release_files = manifest.get("release_files")
    if not isinstance(release_files, list) or not release_files:
        raise RuntimeError("release manifest must contain a non-empty release_files inventory")
    if any(not isinstance(path, str) or not path for path in release_files):
        raise RuntimeError("release manifest inventory entries must be non-empty strings")
    if len(set(release_files)) != len(release_files):
        raise RuntimeError("release manifest inventory must not contain duplicate paths")
    executable_files = manifest.get("executable_release_files")
    if (
        not isinstance(executable_files, list)
        or any(not isinstance(path, str) or not path for path in executable_files)
        or len(set(executable_files)) != len(executable_files)
        or set(executable_files) != EXPECTED_EXECUTABLE_RELEASE_FILES
        or not set(executable_files).issubset(release_files)
    ):
        raise RuntimeError(
            "release manifest must retain the exact executable release-file policy"
        )
    missing_inventory_files = set(REQUIRED_INVENTORY_FILES) - set(release_files)
    if missing_inventory_files:
        raise RuntimeError(
            f"release manifest omits inventory files: {sorted(missing_inventory_files)}"
        )
    if SOURCE_ARCHIVE_PATH.as_posix() in release_files:
        raise RuntimeError("the supplied requirements source ZIP must not enter release inventory")
    exclusions = manifest.get("excluded_from_release")
    if not isinstance(exclusions, list) or SOURCE_ARCHIVE_PATH.as_posix() not in exclusions:
        raise RuntimeError("release manifest must explicitly exclude docs/Requirements.zip")
    for detached_path in DETACHED_G2_EVIDENCE_FILES:
        if detached_path in release_files:
            raise RuntimeError("detached G2 evidence must not enter the release archive")
        if detached_path not in exclusions:
            raise RuntimeError(
                f"release manifest must explicitly exclude detached evidence: {detached_path}"
            )
    ignore_lines = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    if f"/{SOURCE_ARCHIVE_PATH.as_posix()}" not in ignore_lines:
        raise RuntimeError(
            ".gitignore must contain the exact /docs/Requirements.zip exclusion"
        )
    if manifest.get("runtime_dependencies") != []:
        raise RuntimeError("v0.1.0 runtime dependency list must remain empty")
    if manifest.get("external_assets", {}).get("model_weights_included") is not False:
        raise RuntimeError("release manifest must explicitly exclude model weights")
    if manifest.get("external_assets", {}).get("governing_source_archive_included") is not False:
        raise RuntimeError("release manifest must explicitly exclude the supplied source archive")
    supported_environments = manifest.get("supported_environments")
    if not isinstance(supported_environments, list):
        raise RuntimeError("release manifest must declare supported environments")
    development_lanes = {
        (environment.get("platform"), environment.get("version"))
        for environment in supported_environments
        if isinstance(environment, dict)
        and environment.get("level") == "active-development"
        and environment.get("certification") == "not-certified"
    }
    if development_lanes != {
        ("Windows", "11 build 26200 (native)"),
        ("Ubuntu under WSL2", "26.04 LTS"),
    }:
        raise RuntimeError("release manifest must retain the two observed development lanes")
    certification_targets = [
        environment
        for environment in supported_environments
        if isinstance(environment, dict)
        and environment.get("level") == "final-certification-target"
    ]
    if (
        len(certification_targets) != 1
        or certification_targets[0].get("platform") != "Ubuntu"
        or certification_targets[0].get("version") != "24.04 LTS on two physical A1 boards"
        or certification_targets[0].get("availability") != "not-present"
    ):
        raise RuntimeError("release manifest must keep the unavailable certification target distinct")
    json_schema_files = sorted((ROOT / "schemas").glob("*.json"))
    for schema in json_schema_files:
        json.loads(schema.read_text(encoding="utf-8"))
    report("Release metadata", f"version {version}; {len(json_schema_files)} JSON schemas")


def validate_governing_sources() -> None:
    record = json.loads((ROOT / GOVERNING_SOURCE_RECORD).read_text(encoding="utf-8"))
    if record.get("schema_version") != 1:
        raise RuntimeError("governing source record must use schema_version 1")
    repository_check = record.get("repository_check")
    if not isinstance(repository_check, dict) or repository_check.get("result") != "verified":
        raise RuntimeError("governing source record must report the verified repository state")
    sources = record.get("sources")
    if not isinstance(sources, list):
        raise RuntimeError("governing source record must contain a sources list")
    if any(not isinstance(source, dict) for source in sources):
        raise RuntimeError("every governing source entry must be an object")
    filenames = [source.get("filename") for source in sources]
    if len(filenames) != len(GOVERNING_SOURCE_FILENAMES) or set(filenames) != GOVERNING_SOURCE_FILENAMES:
        raise RuntimeError("governing source record must contain the three exact source filenames")
    if {source.get("precedence") for source in sources} != {1, 2, 3}:
        raise RuntimeError("governing source record must contain unique precedence values 1, 2, and 3")
    for source in sources:
        if source.get("availability") != "present" or source.get("status") != "verified":
            raise RuntimeError("every governing source must have present/verified status")
        locator = source.get("locator")
        source_path = ROOT.joinpath(*PurePosixPath(locator).parts) if isinstance(locator, str) else None
        if source_path is None or not source_path.is_file():
            raise RuntimeError(f"governing source is unavailable: {locator!r}")
        payload = source_path.read_bytes()
        if source.get("size_bytes") != len(payload):
            raise RuntimeError(f"governing source size mismatch: {locator}")
        if source.get("sha256") != hashlib.sha256(payload).hexdigest():
            raise RuntimeError(f"governing source digest mismatch: {locator}")
        required_metadata = (
            "document_title",
            "revision",
            "revision_text",
            "document_date",
            "requirement_count",
            "verification_procedure_catalog",
        )
        if any(not source.get(field) for field in required_metadata):
            raise RuntimeError(f"governing source metadata is incomplete: {source.get('id')}")
    g0_impact = record.get("g0_impact")
    if not isinstance(g0_impact, dict) or g0_impact.get("status") != "resolved":
        raise RuntimeError("governing source record must resolve the source-only G0 impact")

    from build_requirement_registry import extract_governing_requirements

    extracted = extract_governing_requirements(record)
    if len(extracted) != 288:
        raise RuntimeError("governing sources must yield exactly 288 requirement entries")

    narrative = (ROOT / "docs/GOVERNING_REQUIREMENTS_SOURCES.md").read_text(encoding="utf-8")
    for filename in GOVERNING_SOURCE_FILENAMES:
        if filename not in narrative:
            raise RuntimeError(f"governing source narrative omits exact filename: {filename}")
    if narrative.count("**Verified**") < len(GOVERNING_SOURCE_FILENAMES):
        raise RuntimeError("governing source narrative must explicitly mark all three sources Verified")
    report("Governing source record", "three pinned dependencies and 288 source entries verified")


def validate_two_axis_gate_record(document: object, label: str) -> dict[str, object]:
    """Require development acceptance and certification disposition to remain distinct."""

    if not isinstance(document, dict):
        raise RuntimeError(f"{label} must be an object")
    if document.get("development_assessment") != "complete-with-deferrals":
        raise RuntimeError(f"{label} must record development completion with deferrals")
    if document.get("certification_assessment") != "blocked":
        raise RuntimeError(f"{label} must keep formal certification blocked")
    if document.get("certification_disposition") != "deferred-to-final-os-testing-and-certification":
        raise RuntimeError(f"{label} must explicitly defer certification to final OS testing")
    for legacy_field in ("status", "assessment"):
        legacy_value = document.get(legacy_field)
        if isinstance(legacy_value, str) and legacy_value.casefold() in {
            "pass",
            "passed",
            "complete",
            "certified",
        }:
            raise RuntimeError(f"{label} must not encode a formal pass in {legacy_field}")
    return document


def is_repository_checkout() -> bool:
    """Return whether Git repository metadata is available."""

    return (ROOT / ".git").exists()


def detached_evidence_is_tracked() -> bool:
    """Require the current detached evidence only after both sidecars are staged."""

    if not is_repository_checkout():
        return False
    try:
        result = subprocess.run(
            [
                "git",
                "ls-files",
                "--cached",
                "--full-name",
                "-z",
                "--",
                *CURRENT_DETACHED_G2_EVIDENCE_FILES,
            ],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise RuntimeError(f"cannot inspect detached G2 evidence tracking: {exc}") from exc
    if result.returncode:
        detail = os.fsdecode(result.stderr).strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"cannot inspect detached G2 evidence tracking{suffix}")
    tracked = {
        os.fsdecode(path)
        for path in result.stdout.split(b"\0")
        if path
    }
    expected = set(CURRENT_DETACHED_G2_EVIDENCE_FILES)
    if tracked and tracked != expected:
        raise RuntimeError("current detached G2 test and archive records must be tracked together")
    return tracked == expected


def validate_historical_detached_evidence() -> None:
    """Keep the prior detached release snapshot immutable in repository checkouts."""

    if not is_repository_checkout():
        return
    for relative, expected_sha256 in HISTORICAL_DETACHED_G2_SHA256.items():
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"historical detached G2 evidence is missing: {relative}")
        actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_sha256 != expected_sha256:
            raise RuntimeError(
                f"historical detached G2 evidence changed: {relative}"
            )


def validate_repository_reference(reference: object, label: str) -> None:
    path = PurePosixPath(reference) if isinstance(reference, str) else None
    structurally_valid = (
        path is not None and not path.is_absolute() and ".." not in path.parts
    )
    if (
        structurally_valid
        and reference in CURRENT_DETACHED_G2_EVIDENCE_FILES
        and not detached_evidence_is_tracked()
    ):
        return
    if (
        structurally_valid
        and reference in HISTORICAL_DETACHED_G2_EVIDENCE_FILES
        and not is_repository_checkout()
    ):
        return
    if structurally_valid and ROOT.joinpath(*path.parts).is_file():
        return
    if not structurally_valid or not ROOT.joinpath(*path.parts).is_file():
        raise RuntimeError(f"{label} must reference an available repository file: {reference!r}")


def validate_gateway_smoke(
    integration: object,
    *,
    label: str,
    physical_host_id: object,
    artifact_sha256: object,
) -> dict[str, object]:
    """Validate a real local gateway observation without promoting it to certification."""

    if (
        not isinstance(integration, dict)
        or integration.get("status") != "pass"
        or integration.get("evidence_scope") != "development-smoke-only"
        or integration.get("gate_closing") is not False
        or integration.get("runtime_tuple_signed") is not False
        or integration.get("physical_host_id") != physical_host_id
        or integration.get("artifact_sha256") != artifact_sha256
        or integration.get("authenticated_gateway") is not True
        or integration.get("simulated") is not False
        or integration.get("remote_fallback_used") is not False
        or integration.get("response_text") != "LUMA_GATEWAY_OK"
        or integration.get("response_matched") is not True
    ):
        raise RuntimeError(f"{label} must remain local, real, and non-certifying")
    usage = integration.get("usage")
    if (
        not isinstance(usage, dict)
        or not isinstance(usage.get("prompt_tokens"), int)
        or not isinstance(usage.get("completion_tokens"), int)
        or usage.get("total_tokens")
        != usage.get("prompt_tokens") + usage.get("completion_tokens")
    ):
        raise RuntimeError(f"{label} must retain measured token usage")
    timings = integration.get("timings")
    required_timings = {
        "prompt_milliseconds",
        "prompt_tokens_per_second",
        "generation_milliseconds",
        "generation_tokens_per_second",
        "server_total_milliseconds",
        "end_to_end_harness_milliseconds",
    }
    if (
        not isinstance(timings, dict)
        or not required_timings.issubset(timings)
        or any(
            not isinstance(timings[field], (int, float)) or timings[field] <= 0
            for field in required_timings
        )
    ):
        raise RuntimeError(f"{label} must retain positive measured timings")
    return integration


def validate_gate_artifacts() -> None:
    json_paths = [
        path
        for path in REQUIRED_GATE_FILES
        if Path(path).suffix == ".json"
    ]
    documents: dict[str, object] = {}
    for relative in json_paths:
        documents[relative] = json.loads((ROOT / relative).read_text(encoding="utf-8"))

    for gate in ("g0", "g1"):
        blockers_path = f"docs/gates/{gate}/blockers.json"
        evidence_path = f"docs/gates/{gate}/evidence.json"
        blockers = validate_two_axis_gate_record(
            documents[blockers_path], f"{gate.upper()} blocker record"
        )
        evidence = validate_two_axis_gate_record(
            documents[evidence_path], f"{gate.upper()} evidence record"
        )
        if blockers.get("status") != "blocked":
            raise RuntimeError(f"{gate.upper()} blocker record must remain explicitly blocked")
        blocker_items = blockers.get("blockers")
        if not isinstance(blocker_items, list) or not blocker_items:
            raise RuntimeError(f"{gate.upper()} blocker record must contain blockers")
        blocker_statuses: set[str] = set()
        for item in blocker_items:
            if not isinstance(item, dict):
                raise RuntimeError(f"{gate.upper()} blocker entries must be objects")
            item_status = item.get("status")
            if item_status not in {
                "resolved-development",
                "deferred-to-final-certification",
            }:
                raise RuntimeError(
                    f"{gate.upper()} blocker status must distinguish development resolution "
                    "from certification deferral"
                )
            blocker_statuses.add(item_status)
            if not item.get("id") or not item.get("owner") or not item.get("resolution"):
                raise RuntimeError(f"{gate.upper()} blockers must carry id/owner/resolution")
            blocker_evidence = item.get("evidence")
            blocker_references = (
                [blocker_evidence]
                if isinstance(blocker_evidence, str)
                else blocker_evidence
            )
            if not isinstance(blocker_references, list) or not blocker_references:
                raise RuntimeError(f"{gate.upper()} blockers must reference evidence")
            for reference in blocker_references:
                validate_repository_reference(
                    reference, f"{gate.upper()} blocker evidence"
                )
        if "deferred-to-final-certification" not in blocker_statuses:
            raise RuntimeError(f"{gate.upper()} must retain explicit certification deferrals")
        if evidence.get("assessment") != "blocked":
            raise RuntimeError(f"{gate.upper()} evidence must not claim a passing gate")
        evidence_items = evidence.get("items")
        if not isinstance(evidence_items, list) or not evidence_items:
            raise RuntimeError(f"{gate.upper()} evidence must contain explicit items")
        if any(not isinstance(item, dict) or item.get("gate_closing") is not False for item in evidence_items):
            raise RuntimeError(f"{gate.upper()} development evidence must remain non-closing")
        for item in evidence_items:
            references = item.get("evidence")
            if not isinstance(references, list) or not references:
                raise RuntimeError(f"{gate.upper()} evidence items must reference repository files")
            for reference in references:
                validate_repository_reference(
                    reference, f"{gate.upper()} evidence reference"
                )

    g2_blockers = documents["docs/gates/g2/blockers.json"]
    g2_evidence = documents["docs/gates/g2/evidence.json"]
    for document, label in (
        (g2_blockers, "G2 blocker record"),
        (g2_evidence, "G2 evidence record"),
    ):
        if (
            not isinstance(document, dict)
            or document.get("development_assessment") != "in-progress"
            or document.get("certification_assessment") != "blocked"
        ):
            raise RuntimeError(f"{label} must record in-progress development and blocked certification")
    if g2_blockers.get("status") != "blocked":
        raise RuntimeError("G2 blocker record must remain explicitly blocked")
    g2_blocker_items = g2_blockers.get("blockers")
    if not isinstance(g2_blocker_items, list) or not g2_blocker_items:
        raise RuntimeError("G2 blocker record must contain explicit blockers")
    for item in g2_blocker_items:
        if (
            not isinstance(item, dict)
            or item.get("status") != "deferred-to-final-certification"
            or not item.get("id")
            or not item.get("owner")
            or not item.get("resolution")
        ):
            raise RuntimeError("G2 blockers must remain complete certification deferrals")
        reference = item.get("evidence")
        references = [reference] if isinstance(reference, str) else reference
        if not isinstance(references, list) or not references:
            raise RuntimeError("G2 blockers must reference repository evidence")
        for repository_reference in references:
            validate_repository_reference(repository_reference, "G2 blocker evidence")
    if g2_evidence.get("assessment") != "blocked":
        raise RuntimeError("G2 evidence must not claim a passing gate")
    implementation_commit = g2_evidence.get("implementation_commit")
    if not isinstance(implementation_commit, str) or not re.fullmatch(
        r"[0-9a-f]{40}", implementation_commit
    ):
        raise RuntimeError("G2 evidence must pin the implementation commit")
    g2_evidence_items = g2_evidence.get("items")
    if not isinstance(g2_evidence_items, list) or not g2_evidence_items:
        raise RuntimeError("G2 evidence must contain explicit items")
    evidence_item_ids: set[str] = set()
    prepared_evidence_by_requirement: dict[str, set[str]] = {}
    for item in g2_evidence_items:
        if not isinstance(item, dict) or item.get("gate_closing") is not False:
            raise RuntimeError("G2 development evidence must remain non-closing")
        evidence_id = item.get("id")
        if (
            not isinstance(evidence_id, str)
            or not evidence_id
            or evidence_id in evidence_item_ids
        ):
            raise RuntimeError("G2 development evidence IDs must be present and unique")
        evidence_item_ids.add(evidence_id)
        prepared_requirements = item.get("requirements_prepared")
        if not isinstance(prepared_requirements, list) or any(
            not isinstance(requirement_id, str) for requirement_id in prepared_requirements
        ):
            raise RuntimeError("G2 evidence must explicitly list prepared requirements")
        for requirement_id in prepared_requirements:
            prepared_evidence_by_requirement.setdefault(requirement_id, set()).add(evidence_id)
        references = item.get("evidence")
        if not isinstance(references, list) or not references:
            raise RuntimeError("G2 evidence items must reference repository files")
        for repository_reference in references:
            validate_repository_reference(repository_reference, "G2 evidence reference")
    if evidence_item_ids != {f"G2-EV-{index:03d}" for index in range(1, 10)}:
        raise RuntimeError("G2 evidence must retain the nine identified development items")
    durable_item = next(
        item for item in g2_evidence_items if item.get("id") == "G2-EV-005"
    )
    if (
        durable_item.get("requirements_prepared") != ["A115"]
        or durable_item.get("source_tests_prepared") != ["T62"]
        or g2_evidence.get("validation_record") != G2_TEST_RUN
    ):
        raise RuntimeError("G2 durable-ledger evidence mapping is inconsistent")
    model_selection_item = next(
        item for item in g2_evidence_items if item.get("id") == "G2-EV-006"
    )
    model_selection_artifacts = {
        "schemas/model-pack.schema.json",
        "schemas/model-profile.schema.json",
        "src/luma_os/model_pack.py",
        "src/luma_os/model_selection.py",
        "src/luma_os/installer.py",
        "tests/test_model_pack.py",
        "tests/test_model_selection.py",
        "tests/test_installer.py",
    }
    model_selection_evidence = {
        *model_selection_artifacts,
        "docs/gates/g1/model_candidate_smoke_2026-09-23.json",
    }
    if (
        model_selection_item.get("requirements_prepared")
        != ["A001", "A003", "A108"]
        or model_selection_item.get("source_tests_prepared")
        != ["T01", "T02", "T48"]
        or set(model_selection_item.get("evidence", [])) != model_selection_evidence
    ):
        raise RuntimeError("G2 model-selection evidence mapping is inconsistent")

    signed_catalog_item = next(
        item for item in g2_evidence_items if item.get("id") == "G2-EV-007"
    )
    signed_catalog_artifacts = {
        "src/luma_os/model_catalog_signing.py",
        "src/luma_os/model_pack.py",
        "src/luma_os/model_selection.py",
        "schemas/model-catalog-signature.schema.json",
        "schemas/model-profile.schema.json",
        "scripts/model_catalog_ceremony.py",
        "tests/test_model_catalog_signing.py",
        "docs/PRODUCTION_SIGNING_CUSTODY.md",
    }
    if (
        signed_catalog_item.get("subject")
        != "signed-model-catalog-verification-and-custody-contract"
        or signed_catalog_item.get("requirements_prepared") != ["A003"]
        or signed_catalog_item.get("source_tests_prepared") != ["T06"]
        or set(signed_catalog_item.get("evidence", [])) != signed_catalog_artifacts
    ):
        raise RuntimeError("G2 signed-model-catalog evidence mapping is inconsistent")

    host_inventory_item = next(
        item for item in g2_evidence_items if item.get("id") == "G2-EV-008"
    )
    host_inventory_artifacts = {
        "src/luma_os/g2_host_inventory.py",
        "scripts/collect_g2_host.py",
        "scripts/ubuntu_preflight.py",
        "schemas/g2-host-inventory.schema.json",
        "tests/test_g2_host_inventory.py",
        "tests/test_ubuntu_preflight.py",
        "docs/UBUNTU_QUALIFICATION.md",
    }
    if (
        host_inventory_item.get("subject")
        != "read-only-ubuntu-host-inventory-and-native-candidate-admission"
        or host_inventory_item.get("requirements_prepared") != ["A001"]
        or host_inventory_item.get("source_tests_prepared")
        != ["T01", "T45", "T50"]
        or set(host_inventory_item.get("evidence", [])) != host_inventory_artifacts
    ):
        raise RuntimeError("G2 Ubuntu host-inventory evidence mapping is inconsistent")

    operator_package_item = next(
        item for item in g2_evidence_items if item.get("id") == "G2-EV-009"
    )
    operator_package_artifacts = {
        "docs/gates/g2/OPERATOR_APPROVAL_AND_EXECUTION.md",
        "docs/gates/g2/PHYSICAL_QUALIFICATION_RUNBOOK.md",
        "docs/UBUNTU_QUALIFICATION.md",
        "docs/PRODUCTION_SIGNING_CUSTODY.md",
    }
    if (
        operator_package_item.get("subject")
        != "operator-approval-and-physical-qualification-package"
        or operator_package_item.get("requirements_prepared") != []
        or operator_package_item.get("source_tests_prepared")
        != ["T01-T16", "T27-T30", "T33", "T40", "T45-T51", "T62"]
        or set(operator_package_item.get("evidence", []))
        != operator_package_artifacts
    ):
        raise RuntimeError("G2 operator-qualification evidence mapping is inconsistent")

    g2_test_plan = documents["docs/gates/g2/test_plan.json"]
    if (
        not isinstance(g2_test_plan, dict)
        or g2_test_plan.get("status") != "development-in-progress"
        or g2_test_plan.get("gate_closing") is not False
        or not isinstance(g2_test_plan.get("contract_tranche"), list)
        or len(g2_test_plan["contract_tranche"]) != 7
        or not g2_test_plan.get("mandatory_physical_evidence")
        or not g2_test_plan.get("formal_exit_rule")
    ):
        raise RuntimeError("G2 test plan must preserve its development-only and physical-lab boundary")
    model_selection_tranches = [
        tranche
        for tranche in g2_test_plan["contract_tranche"]
        if isinstance(tranche, dict)
        and tranche.get("area") == "install-time-multi-model-selection"
    ]
    if (
        len(model_selection_tranches) != 1
        or model_selection_tranches[0].get("source_requirements")
        != ["A001", "A003", "A108"]
        or model_selection_tranches[0].get("source_tests")
        != ["T01", "T02", "T48"]
        or set(model_selection_tranches[0].get("artifacts", []))
        != model_selection_artifacts
    ):
        raise RuntimeError("G2 test plan must retain the model-selection contract tranche")
    signed_catalog_tranches = [
        tranche
        for tranche in g2_test_plan["contract_tranche"]
        if isinstance(tranche, dict)
        and tranche.get("area") == "signed-model-catalog-verification-and-custody"
    ]
    if (
        len(signed_catalog_tranches) != 1
        or signed_catalog_tranches[0].get("source_requirements")
        != ["A003"]
        or signed_catalog_tranches[0].get("source_tests") != ["T06"]
        or set(signed_catalog_tranches[0].get("artifacts", []))
        != signed_catalog_artifacts
    ):
        raise RuntimeError("G2 test plan must retain the signed-model-catalog tranche")
    host_inventory_tranches = [
        tranche
        for tranche in g2_test_plan["contract_tranche"]
        if isinstance(tranche, dict)
        and tranche.get("area")
        == "ubuntu-host-inventory-and-native-candidate-admission"
    ]
    if (
        len(host_inventory_tranches) != 1
        or host_inventory_tranches[0].get("source_requirements") != ["A001"]
        or host_inventory_tranches[0].get("source_tests")
        != ["T01", "T45", "T50"]
        or set(host_inventory_tranches[0].get("artifacts", []))
        != host_inventory_artifacts
    ):
        raise RuntimeError("G2 test plan must retain the Ubuntu host-inventory tranche")
    inventory = documents["docs/gates/g0/lab_inventory.json"]
    if not isinstance(inventory, dict):
        raise RuntimeError("G0 lab inventory must be an object")
    inventory_systems = inventory.get("systems")
    if not isinstance(inventory_systems, list) or not inventory_systems:
        raise RuntimeError("G0 lab inventory must identify the development host")
    physical_host_ids = {
        item.get("id")
        for item in inventory_systems
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    inventory_environment_ids = set(physical_host_ids)
    for item in inventory_systems:
        if not isinstance(item, dict):
            continue
        guests = item.get("guests")
        if isinstance(guests, list):
            inventory_environment_ids.update(
                guest.get("id")
                for guest in guests
                if isinstance(guest, dict) and isinstance(guest.get("id"), str)
            )
    development_lanes = g2_test_plan.get("development_lanes")
    if (
        not isinstance(development_lanes, list)
        or len(development_lanes) != 2
        or any(
            not isinstance(lane, dict)
            or lane.get("environment") not in inventory_environment_ids
            or lane.get("physical_machine") not in physical_host_ids
            for lane in development_lanes
        )
        or len({lane.get("physical_machine") for lane in development_lanes}) != 1
    ):
        raise RuntimeError("G2 development lanes must map to the inventoried single physical host")
    closure_rule = g2_test_plan.get("formal_exit_rule")
    evidence_closure_rule = g2_evidence.get("closure_rule")
    required_closure_tokens = (
        "T01-T16",
        "T27-T30",
        "T33",
        "T40",
        "T45-T51",
        "T62",
        "both physical A1 boards",
    )
    if any(
        not isinstance(rule, str)
        or any(token not in rule for token in required_closure_tokens)
        for rule in (closure_rule, evidence_closure_rule)
    ):
        raise RuntimeError("G2 closure rules must retain the complete numbered and two-board suite")

    registry_document = json.loads(
        (ROOT / "requirements/registry.json").read_text(encoding="utf-8")
    )
    registry_requirements = registry_document.get("requirements")
    if not isinstance(registry_requirements, list):
        raise RuntimeError("requirement registry must contain requirements")
    g2_registry = {
        item.get("id"): item
        for item in registry_requirements
        if isinstance(item, dict) and item.get("closure_gate") == "G2"
    }
    if len(g2_registry) != 34 or set(prepared_evidence_by_requirement) - set(g2_registry):
        raise RuntimeError("G2 evidence must reference exactly known G2 requirements")
    for requirement_id, registry_item in g2_registry.items():
        latest_evidence = registry_item.get("latest_evidence")
        expected_ids = prepared_evidence_by_requirement.get(requirement_id, set())
        if (
            not isinstance(latest_evidence, dict)
            or set(latest_evidence.get("evidence_ids", [])) != expected_ids
            or latest_evidence.get("state") != "blocked"
            or registry_item.get("implementation_status")
            != ("in_progress" if expected_ids else "not_started")
        ):
            raise RuntimeError(
                f"G2 registry progress/evidence mapping is inconsistent for {requirement_id}"
            )

    deferrals = documents["docs/gates/final_certification_deferrals.json"]
    if not isinstance(deferrals, dict):
        raise RuntimeError("final certification deferral record must be an object")
    if deferrals.get("development_assessment") != "complete-with-deferrals":
        raise RuntimeError("final certification record must preserve development disposition")
    if deferrals.get("certification_assessment") != "blocked":
        raise RuntimeError("final certification record must remain blocked")
    deferred_items = deferrals.get("deferrals")
    if not isinstance(deferred_items, list) or not deferred_items:
        raise RuntimeError("final certification record must contain explicit deferrals")
    required_deferral_fields = {
        "id",
        "gates",
        "scope",
        "reason",
        "required_environment",
        "required_evidence",
        "owner",
        "status",
    }
    for item in deferred_items:
        if (
            not isinstance(item, dict)
            or not required_deferral_fields.issubset(item)
            or item.get("status") != "deferred-to-final-certification"
        ):
            raise RuntimeError("every final certification deferral must be complete and explicit")
    if not deferrals.get("change_control"):
        raise RuntimeError("final certification deferrals must define change control")

    model_selection = documents["docs/gates/g1/development_model_selection.json"]
    if (
        not isinstance(model_selection, dict)
        or model_selection.get("purpose") != "development-smoke-baseline"
        or model_selection.get("status") != "selected-for-development-only"
        or model_selection.get("gate_closing") is not False
        or not isinstance(model_selection.get("selected_model"), dict)
        or not isinstance(model_selection.get("runtime"), dict)
        or not isinstance(model_selection.get("evidence_sources"), list)
        or not model_selection["evidence_sources"]
        or not isinstance(model_selection.get("governed_boundaries"), dict)
    ):
        raise RuntimeError("development model selection must be pinned and non-certifying")
    selected_model = model_selection["selected_model"]
    selected_runtime = model_selection["runtime"]
    if (
        not isinstance(selected_model.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", selected_model["sha256"])
        or selected_model.get("asset_location_policy")
        != "outside-git-under-operator-controlled-local-model-store"
        or any(
            not isinstance(source, str) or not source.startswith("https://")
            for source in model_selection["evidence_sources"]
        )
    ):
        raise RuntimeError("development model identity, storage policy, or sources are incomplete")
    governed_boundaries = model_selection["governed_boundaries"]
    compact_boundary = governed_boundaries.get("a1_compact_control_model")
    large_boundary = governed_boundaries.get("large_model_experiment")
    changed_scope = governed_boundaries.get("450b")
    if (
        not isinstance(compact_boundary, dict)
        or compact_boundary.get("satisfied_by_selection") is not False
        or compact_boundary.get("status") != "deferred-to-final-certification"
        or not isinstance(large_boundary, dict)
        or large_boundary.get("satisfied_by_selection") is not False
        or not isinstance(changed_scope, dict)
        or changed_scope.get("status") != "outside-current-governing-requirements"
        or changed_scope.get("change_control_required") is not True
    ):
        raise RuntimeError("development model record must preserve every governed model boundary")

    local_smoke = documents["docs/gates/g1/local_model_smoke_2026-09-22.json"]
    if (
        not isinstance(local_smoke, dict)
        or local_smoke.get("result") != "pass-development-smoke"
        or local_smoke.get("development_assessment") != "accepted"
        or local_smoke.get("certification_assessment") != "not-certified"
        or local_smoke.get("gate_closing") is not False
        or not isinstance(local_smoke.get("model"), dict)
        or not isinstance(local_smoke.get("runtime"), dict)
    ):
        raise RuntimeError("local model smoke must remain accepted development evidence only")
    smoke_model = local_smoke["model"]
    smoke_runtime = local_smoke["runtime"]
    for identity_field in ("repository", "revision", "artifact", "size_bytes", "sha256"):
        if smoke_model.get(identity_field) != selected_model.get(identity_field):
            raise RuntimeError(f"local smoke model {identity_field} differs from the selection")
    for identity_field in ("name", "release", "commit"):
        if smoke_runtime.get(identity_field) != selected_runtime.get(identity_field):
            raise RuntimeError(f"local smoke runtime {identity_field} differs from the selection")
    if smoke_model.get("signed_model_pack") is not False:
        raise RuntimeError("development smoke must not claim a signed model pack")
    smoke_environments = local_smoke.get("environments")
    if (
        not isinstance(smoke_environments, list)
        or len(smoke_environments) != 2
        or any(not isinstance(item, dict) for item in smoke_environments)
        or len({item.get("physical_host_id") for item in smoke_environments}) != 1
        or any(not item.get("physical_host_id") for item in smoke_environments)
    ):
        raise RuntimeError("local model smoke must identify two lanes on one physical host")
    smoke_summary = local_smoke.get("summary")
    if (
        not isinstance(smoke_summary, dict)
        or smoke_summary.get("real_model_execution_observed") is not True
        or smoke_summary.get("independent_physical_machines") != 1
        or smoke_summary.get("formal_4_6b_requirement_satisfied") is not False
        or smoke_summary.get("formal_g1_certification_satisfied") is not False
    ):
        raise RuntimeError("local model smoke summary must preserve its non-certifying boundary")
    physical_host_id = smoke_environments[0].get("physical_host_id")
    ubuntu_gateway = validate_gateway_smoke(
        local_smoke.get("gateway_integration"),
        label="Ubuntu WSL Luma gateway integration",
        physical_host_id=physical_host_id,
        artifact_sha256=selected_model.get("sha256"),
    )
    windows_gateway = validate_gateway_smoke(
        local_smoke.get("windows_gateway_integration"),
        label="native Windows CUDA Luma gateway integration",
        physical_host_id=physical_host_id,
        artifact_sha256=selected_model.get("sha256"),
    )
    if (
        ubuntu_gateway.get("environment_id") != "ubuntu-wsl-cpu"
        or windows_gateway.get("environment_id") != "windows-native-cuda"
        or windows_gateway.get("all_model_layers_assigned_to_device") is not True
        or smoke_summary.get("luma_gateway_integration_smoke") != "pass"
        or smoke_summary.get("windows_cuda_luma_gateway_integration_smoke") != "pass"
    ):
        raise RuntimeError("local model evidence must preserve both gateway smoke lanes")

    candidate_smoke = documents[
        "docs/gates/g1/model_candidate_smoke_2026-09-23.json"
    ]
    if (
        not isinstance(candidate_smoke, dict)
        or candidate_smoke.get("result") != "pass-development-smoke"
        or candidate_smoke.get("certification_assessment") != "blocked"
        or candidate_smoke.get("gate_closing") is not False
    ):
        raise RuntimeError("model candidate smoke must remain development-only evidence")
    candidate_items = candidate_smoke.get("candidates")
    if not isinstance(candidate_items, list) or any(
        not isinstance(item, dict) for item in candidate_items
    ):
        raise RuntimeError("model candidate smoke must retain candidate identities")
    candidates = {
        item.get("candidate_id"): item
        for item in candidate_items
        if isinstance(item.get("candidate_id"), str)
    }
    if set(candidates) != {
        "qwen3-4b-q4-k-m",
        "gemma-4-e2b-it-bf16",
        "gemma-4-e4b-it-bf16",
    }:
        raise RuntimeError("model candidate smoke must retain the governed candidate set")
    qwen_candidate = candidates["qwen3-4b-q4-k-m"]
    if (
        qwen_candidate.get("status") != "development-smoke-observed"
        or qwen_candidate.get("parameter_total") != 4_000_000_000
        or qwen_candidate.get("parameter_effective") != 4_000_000_000
        or qwen_candidate.get("signed_model_pack") is not False
        or not re.fullmatch(r"[0-9a-f]{40}", str(qwen_candidate.get("revision", "")))
        or not re.fullmatch(
            r"[0-9a-f]{64}", str(qwen_candidate.get("artifact_sha256", ""))
        )
    ):
        raise RuntimeError("Qwen3-4B candidate identity or trust boundary is inconsistent")
    if (
        candidates["gemma-4-e2b-it-bf16"].get("status")
        != "identified-not-acquired-or-tested"
        or candidates["gemma-4-e2b-it-bf16"].get("parameter_total")
        != 5_100_000_000
        or candidates["gemma-4-e4b-it-bf16"].get("status")
        != "identified-not-acquired-or-tested"
        or candidates["gemma-4-e4b-it-bf16"].get("parameter_total")
        != 8_000_000_000
        or any(item.get("signed_model_pack") is not False for item in candidates.values())
    ):
        raise RuntimeError("Gemma candidates must remain identified but unexecuted and unsigned")
    candidate_host = candidate_smoke.get("physical_host")
    candidate_observations = candidate_smoke.get("observations")
    required_observation_ids = {
        "QWEN3-4B-WINDOWS-DIRECT-2026-09-23",
        "QWEN3-4B-WINDOWS-GATEWAY-2026-09-23",
        "QWEN3-4B-WSL-DIRECT-2026-09-23",
        "QWEN3-4B-WSL-GATEWAY-2026-09-23",
    }
    if (
        not isinstance(candidate_host, dict)
        or candidate_host.get("independent_physical_machine_count") != 1
        or not isinstance(candidate_observations, list)
        or any(not isinstance(item, dict) for item in candidate_observations)
        or {item.get("observation_id") for item in candidate_observations}
        != required_observation_ids
        or any(
            item.get("physical_host_id") != candidate_host.get("id")
            or item.get("simulated") is not False
            or item.get("response_exact_match") is not True
            for item in candidate_observations
        )
    ):
        raise RuntimeError("Qwen3-4B smoke must retain four real observations on one host")
    candidate_summary = candidate_smoke.get("summary")
    if (
        not isinstance(candidate_summary, dict)
        or candidate_summary.get("qwen3_4b_real_model_execution_observed") is not True
        or candidate_summary.get("gemma_4_e2b_execution_observed") is not False
        or candidate_summary.get("gemma_4_e4b_execution_observed") is not False
        or candidate_summary.get("independent_physical_machines") != 1
        or candidate_summary.get("signed_model_pack_available") is not False
        or candidate_summary.get("formal_4_6b_requirement_satisfied") is not False
        or candidate_summary.get("formal_g1_certification_satisfied") is not False
    ):
        raise RuntimeError("model candidate summary must preserve its non-certifying boundary")
    license_register = documents["docs/registers/licenses.json"]
    workload_register = documents["docs/registers/workloads.json"]
    license_entries = license_register.get("entries") if isinstance(license_register, dict) else None
    workload_entries = (
        workload_register.get("workloads") if isinstance(workload_register, dict) else None
    )
    if not isinstance(license_entries, list) or not isinstance(workload_entries, list):
        raise RuntimeError("model candidate registers must contain entries")
    qwen_license = next(
        (item for item in license_entries if isinstance(item, dict) and item.get("id") == "LIC-005"),
        None,
    )
    qwen_workload = next(
        (item for item in workload_entries if isinstance(item, dict) and item.get("id") == "WL-003"),
        None,
    )
    qwen_license_identity = (
        qwen_license.get("version_or_digest") if isinstance(qwen_license, dict) else None
    )
    qwen_fixture = qwen_workload.get("fixture") if isinstance(qwen_workload, dict) else None
    if (
        not isinstance(qwen_license_identity, str)
        or qwen_candidate["revision"] not in qwen_license_identity
        or qwen_candidate["artifact_sha256"] not in qwen_license_identity
        or not isinstance(qwen_fixture, dict)
        or qwen_fixture.get("digest") != f"sha256:{qwen_candidate['artifact_sha256']}"
        or qwen_candidate["revision"] not in str(qwen_fixture.get("locator", ""))
    ):
        raise RuntimeError("Qwen3-4B smoke identity differs from license or workload registers")

    hardware = inventory.get("required_reference_hardware")
    if not isinstance(hardware, dict) or hardware.get("a1_x86_64_boards_designated") != 0:
        raise RuntimeError("lab inventory must not claim unverified A1 reference boards")

    test_run = documents["docs/gates/g1/test_run_2026-09-22.json"]
    if (
        not isinstance(test_run, dict)
        or test_run.get("result") != "pass"
        or test_run.get("gate_closing") is not False
    ):
        raise RuntimeError("G1 repository test record must be passing but non-closing")
    code_commit = test_run.get("code_commit")
    test_checks = test_run.get("checks")
    if (
        not isinstance(code_commit, str)
        or not re.fullmatch(r"[0-9a-f]{40}", code_commit)
        or not isinstance(test_checks, dict)
        or test_checks.get("unit_tests_failed") != 0
    ):
        raise RuntimeError("G1 repository test record is incomplete")
    declared_test_count = sum(
        len(
            re.findall(
                r"^\s+(?:async\s+)?def\s+test_[A-Za-z0-9_]*\s*\(",
                path.read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        )
        for path in (ROOT / "tests").glob("test_*.py")
    )
    release_manifest = json.loads((ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
    historical_evidence_counts = {
        "python_modules_compiled": 24,
        "unit_tests_run": 98,
        "requirement_entries_validated": 288,
        "release_files_validated": 120,
    }
    for field, expected_value in historical_evidence_counts.items():
        if test_checks.get(field) != expected_value:
            raise RuntimeError(
                f"G1 historical repository test record {field} is inconsistent: "
                f"expected {expected_value}, found {test_checks.get(field)!r}"
            )
    if (
        test_checks.get("governing_source_state") != "verified"
        or test_checks.get("gate_artifact_state")
        != "development-complete-with-deferrals; certification-blocked"
    ):
        raise RuntimeError("G1 repository test record carries stale source or gate dispositions")

    historical_g2_run = documents["docs/gates/g2/test_run_2026-09-22.json"]
    if (
        not isinstance(historical_g2_run, dict)
        or historical_g2_run.get("result") != "pass-development-contracts"
        or historical_g2_run.get("gate_closing") is not False
        or historical_g2_run.get("code_commit")
        != "4ec25b849b3db4363191532bdb06f42894e11253"
        or historical_g2_run.get("environment") != "DEV-WSL-UBUNTU-26-01"
        or historical_g2_run.get("additional_environments")
        != ["DEV-WIN-NATIVE-01"]
        or "archive_sha256" in historical_g2_run
    ):
        raise RuntimeError("historical G2 test record must remain pinned and non-closing")
    historical_g2_checks = historical_g2_run.get("checks")
    historical_g2_expected = {
        "python_modules_compiled": 27,
        "json_schemas_parsed": 5,
        "unit_tests_run": 147,
        "unit_test_lanes": 2,
        "unit_test_executions": 294,
        "unit_tests_failed": 0,
        "optimized_boundary_tests_run": 49,
        "optimized_boundary_tests_failed": 0,
        "requirement_entries_validated": 288,
        "g2_requirements_in_progress": 34,
        "g2_requirements_with_passing_product_evidence": 0,
        "release_files_validated": 130,
        "reproducible_source_builds": 2,
        "archive_checksum_verification": "pass",
        "governing_source_state": "verified",
        "gate_artifact_state": "development-in-progress; certification-blocked",
    }
    if not isinstance(historical_g2_checks, dict) or any(
        historical_g2_checks.get(field) != expected
        for field, expected in historical_g2_expected.items()
    ):
        raise RuntimeError("historical G2 test counts must remain an immutable snapshot")
    detached_expected = detached_evidence_is_tracked()
    detached_presence = [
        (ROOT / path).is_file() for path in CURRENT_DETACHED_G2_EVIDENCE_FILES
    ]
    if detached_expected and not all(detached_presence):
        raise RuntimeError("detached G2 test and archive records must be supplied together")
    detached_available = detached_expected and all(detached_presence)
    g2_test_run = (
        json.loads((ROOT / G2_TEST_RUN).read_text(encoding="utf-8"))
        if detached_available
        else None
    )
    if detached_available and (
        not isinstance(g2_test_run, dict)
        or g2_test_run.get("result") != "pass-development-contracts"
        or g2_test_run.get("development_assessment") != "in-progress"
        or g2_test_run.get("certification_assessment") != "blocked"
        or g2_test_run.get("gate_closing") is not False
        or g2_test_run.get("code_commit") != implementation_commit
        or g2_test_run.get("environment") != "DEV-WIN-WSL-GPU-01"
        or g2_test_run.get("additional_environments")
        != ["DEV-WSL-UBUNTU-26-01"]
        or g2_test_run.get("physical_host_count") != 1
        or g2_test_run.get("archive_attestation") != G2_ARCHIVE_ATTESTATION
    ):
        raise RuntimeError("current G2 test record must be passing, pinned, and non-closing")
    g2_checks = g2_test_run.get("checks") if isinstance(g2_test_run, dict) else {}
    if detached_available and not isinstance(g2_checks, dict):
        raise RuntimeError("current G2 repository test checks must be an object")
    g2_in_progress = sum(
        item.get("implementation_status") == "in_progress"
        for item in g2_registry.values()
    )
    g2_not_started = sum(
        item.get("implementation_status") == "not_started"
        for item in g2_registry.values()
    )
    g2_passing_product_evidence = sum(
        isinstance(item.get("latest_evidence"), dict)
        and item["latest_evidence"].get("state") == "pass"
        for item in g2_registry.values()
    )
    boundary_test_files = (
        "test_boot_control.py",
        "test_installer.py",
        "test_privileged_helper.py",
        "test_durable_effects.py",
        "test_model_pack.py",
        "test_model_selection.py",
        "test_g2_host_inventory.py",
        "test_model_catalog_signing.py",
        "test_ubuntu_preflight.py",
    )
    declared_boundary_count = sum(
        len(
            re.findall(
                r"^\s+(?:async\s+)?def\s+test_[A-Za-z0-9_]*\s*\(",
                (ROOT / "tests" / name).read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        )
        for name in boundary_test_files
    )
    current_evidence_counts = {
        "python_modules_compiled": len(list((ROOT / "src").rglob("*.py"))),
        "json_schemas_parsed": len(list((ROOT / "schemas").glob("*.json"))),
        "unit_tests_run_per_lane": declared_test_count,
        "unit_tests_run": declared_test_count,
        "requirement_entries_validated": 288,
        "g2_requirements_in_progress": g2_in_progress,
        "g2_requirements_not_started": g2_not_started,
        "g2_requirements_with_passing_product_evidence": g2_passing_product_evidence,
        "release_files_validated": len(release_manifest.get("release_files", [])),
        "optimized_boundary_tests_run_per_lane": declared_boundary_count,
        "optimized_boundary_tests_run": declared_boundary_count,
    }
    if (
        declared_test_count != 222
        or declared_boundary_count != 128
        or len(release_manifest.get("release_files", [])) != 153
    ):
        raise RuntimeError("current G2 repository test or release counts are stale")
    if detached_available and any(
            g2_checks.get(field) != expected
            for field, expected in current_evidence_counts.items()
    ):
        raise RuntimeError("detached G2 repository test counts are stale")
    if detached_available and (
        g2_checks.get("unit_test_lanes") != 2
        or g2_checks.get("unit_test_executions") != declared_test_count * 2
        or g2_checks.get("unit_tests_failed") != 0
        or g2_checks.get("unit_tests_skipped")
        != {"ubuntu_wsl": 1, "windows_native": 4}
        or g2_checks.get("optimized_boundary_test_lanes") != 2
        or g2_checks.get("optimized_boundary_test_executions")
        != declared_boundary_count * 2
        or g2_checks.get("optimized_boundary_tests_failed") != 0
        or g2_checks.get("warnings_as_errors") is not True
        or g2_checks.get("reproducible_source_builds") != 2
        or g2_checks.get("archive_checksum_verification")
        != "pass-detached-attestation"
        or g2_checks.get("governing_source_state") != "verified"
        or g2_checks.get("gate_artifact_state")
        != "development-in-progress; certification-blocked"
    ):
        raise RuntimeError("current G2 test record carries stale results or gate disposition")

    archive_attestation = (
        json.loads((ROOT / G2_ARCHIVE_ATTESTATION).read_text(encoding="utf-8"))
        if detached_available
        else {}
    )
    release_source_commit = (
        g2_test_run.get("release_source_commit")
        if isinstance(g2_test_run, dict)
        else None
    )
    if detached_available and (
        not isinstance(archive_attestation, dict)
        or archive_attestation.get("code_commit") != implementation_commit
        or not isinstance(release_source_commit, str)
        or not re.fullmatch(r"[0-9a-f]{40}", release_source_commit)
        or archive_attestation.get("release_source_commit")
        != release_source_commit
        or archive_attestation.get("release_archive_inclusion")
        != "excluded-to-prevent-self-referential-archive-hashes"
        or archive_attestation.get("file_count") != 153
        or archive_attestation.get("source_date_epoch") != 0
        or archive_attestation.get("builds") != 2
        or archive_attestation.get("checksum_verification") != "pass"
        or archive_attestation.get("status") != "verified-reproducible"
        or archive_attestation.get("gate_closing") is not False
    ):
        raise RuntimeError("detached G2 archive attestation is incomplete")
    build_hashes: list[tuple[str, str]] = []
    for build_name in (("first_build", "second_build") if detached_available else ()):
        build = archive_attestation.get(build_name)
        if not isinstance(build, dict):
            raise RuntimeError("detached G2 archive build identity is missing")
        hashes = tuple(build.get(field) for field in ("tar_gz_sha256", "zip_sha256"))
        if any(
            not isinstance(value, str)
            or not re.fullmatch(r"[0-9a-f]{64}", value)
            or value == "0" * 64
            for value in hashes
        ):
            raise RuntimeError("detached G2 archive hashes must be measured SHA-256 values")
        build_hashes.append(hashes)  # type: ignore[arg-type]
    if detached_available and build_hashes[0] != build_hashes[1]:
        raise RuntimeError("detached G2 archive builds are not reproducible")
    if detached_available and is_repository_checkout():
        release_paths = release_manifest.get("release_files", [])
        result = subprocess.run(
            [
                "git",
                "diff",
                "--quiet",
                release_source_commit,
                "HEAD",
                "--",
                *release_paths,
            ],
            cwd=ROOT,
            check=False,
        )
        if result.returncode == 1:
            raise RuntimeError(
                "release inventory differs from the detached release-source commit"
            )
        if result.returncode:
            raise RuntimeError("cannot compare HEAD with the detached release-source commit")

    hardware_smoke = documents["docs/gates/g1/hardware_smoke_2026-09-22.json"]
    if (
        not isinstance(hardware_smoke, dict)
        or hardware_smoke.get("result") != "pass-read-only-observation"
        or hardware_smoke.get("gate_closing") is not False
    ):
        raise RuntimeError("G1 hardware smoke must remain a passing non-closing observation")
    observations = hardware_smoke.get("observations")
    if (
        not isinstance(observations, list)
        or len(observations) != 2
        or any(not isinstance(item, dict) for item in observations)
        or {item.get("domain_id") for item in observations if isinstance(item, dict)}
        != {"host", "gpu0"}
        or any(
            item.get("device_error") is not False
            or not isinstance(item.get("total_bytes"), int)
            or item["total_bytes"] <= 0
            or not isinstance(item.get("used_bytes"), int)
            or not 0 <= item["used_bytes"] <= item["total_bytes"]
            for item in observations
            if isinstance(item, dict)
        )
    ):
        raise RuntimeError("G1 hardware smoke must contain host and GPU observations")

    from build_requirement_registry import build_registry, load_source_record, serialize_registry
    from gate_report import render_report, validate_registry

    registry_path = ROOT / "requirements/registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    sources = json.loads((ROOT / GOVERNING_SOURCE_RECORD).read_text(encoding="utf-8"))
    if not isinstance(registry, dict) or not isinstance(sources, dict):
        raise RuntimeError("registry and governing sources must be JSON objects")
    validate_registry(registry, sources)
    expected_registry = serialize_registry(build_registry(load_source_record()))
    if registry_path.read_text(encoding="utf-8") != expected_registry:
        raise RuntimeError("checked-in requirement registry is not deterministic/current")
    expected_report = render_report(registry, sources)
    if (ROOT / "docs/GATE_REPORT.md").read_text(encoding="utf-8") != expected_report:
        raise RuntimeError("checked-in gate report is not deterministic/current")
    json.loads((ROOT / "requirements/registry.schema.json").read_text(encoding="utf-8"))
    report(
        "Gate artifacts",
        "288 source-traced requirements; plan mappings provisional; product evidence blocked",
    )


def validate_repository() -> None:
    validate_historical_detached_evidence()
    detached_expected = detached_evidence_is_tracked()
    required_workspace_files = (
        *REQUIRED_RELEASE_FILES,
        *(HISTORICAL_DETACHED_G2_EVIDENCE_FILES if is_repository_checkout() else ()),
        *(CURRENT_DETACHED_G2_EVIDENCE_FILES if detached_expected else ()),
    )
    missing = [path for path in required_workspace_files if not (ROOT / path).is_file()]
    if missing:
        raise RuntimeError(f"required documentation is missing: {missing}")
    required_runtime_paths = (
        "src",
        "tests",
        "web/index.html",
        "schemas",
        "examples",
        "requirements",
    )
    missing_runtime = [path for path in required_runtime_paths if not (ROOT / path).exists()]
    if missing_runtime:
        raise RuntimeError(f"required runtime/release paths are missing: {missing_runtime}")
    from build_release import git_tracked_files, included_files

    tracked = git_tracked_files()
    if tracked is not None:
        if SOURCE_ARCHIVE_PATH in tracked:
            raise RuntimeError("docs/Requirements.zip must remain untracked and outside releases")
        untracked_files = [
            path for path in required_workspace_files if PurePosixPath(path) not in tracked
        ]
        if untracked_files:
            raise RuntimeError(f"required repository evidence files are not tracked by Git: {untracked_files}")
    release_files = included_files(tracked=tracked)
    forbidden = [
        path.relative_to(ROOT)
        for path in ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in FORBIDDEN_ASSET_SUFFIXES
    ]
    if forbidden:
        raise RuntimeError(f"model/binary weight files must remain external: {forbidden}")
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    for phrase in ("not a production", "model weights", "wsl2", "bootable iso"):
        if phrase not in readme:
            raise RuntimeError(f"README must state the release boundary: missing {phrase!r}")
    report(
        "Repository policy",
        f"{len(release_files)} inventoried release files; required docs/assets present; model weights absent",
    )


def run_tests() -> None:
    environment = dict(os.environ)
    current = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(ROOT / "src") + (os.pathsep + current if current else "")
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"],
        cwd=ROOT,
        env=environment,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"unit tests failed with exit code {result.returncode}")
    report("Unit tests")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile-only", action="store_true", help="only compile Python source")
    arguments = parser.parse_args()
    try:
        compile_sources()
        if not arguments.compile_only:
            validate_metadata()
            validate_governing_sources()
            validate_gate_artifacts()
            validate_repository()
            run_tests()
    except (OSError, ValueError, RuntimeError, py_compile.PyCompileError) as exc:
        print(f"[failed] {exc}", file=sys.stderr)
        return 1
    print("All requested checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
