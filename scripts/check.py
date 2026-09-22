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
    "docs/RELEASE.md",
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
REQUIRED_GATE_FILES = (
    "docs/adr/0001-python-reference-rust-production.md",
    "docs/adr/0002-service-boundaries-and-transport.md",
    "docs/adr/0003-artifact-storage.md",
    "docs/adr/0004-policy-model.md",
    "docs/adr/0005-model-pack-and-signing.md",
    "docs/adr/0006-supported-package-layout.md",
    "docs/adr/0007-admin-delegation-and-signing-custody.md",
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
    "docs/gates/g1/test_run_2026-09-22.json",
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
    "scripts/smoke_local_model.py",
    "src/luma_os/administration.py",
    "src/luma_os/real_inference.py",
    "tests/test_administration.py",
    "tests/test_real_inference.py",
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


def validate_repository_reference(reference: object, label: str) -> None:
    path = PurePosixPath(reference) if isinstance(reference, str) else None
    if (
        path is None
        or path.is_absolute()
        or ".." in path.parts
        or not ROOT.joinpath(*path.parts).is_file()
    ):
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

    inventory = documents["docs/gates/g0/lab_inventory.json"]
    if not isinstance(inventory, dict):
        raise RuntimeError("G0 lab inventory must be an object")
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
    missing = [path for path in REQUIRED_RELEASE_FILES if not (ROOT / path).is_file()]
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
        untracked_files = [path for path in REQUIRED_RELEASE_FILES if PurePosixPath(path) not in tracked]
        if untracked_files:
            raise RuntimeError(f"required release files are not tracked by Git: {untracked_files}")
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
