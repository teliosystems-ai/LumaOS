#!/usr/bin/env python3
"""Dependency-free repository validation for local development and CI."""

from __future__ import annotations

import argparse
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
GOVERNING_SOURCE_RECORD = "docs/governing_sources.json"
REQUIRED_GATE_FILES = (
    "docs/adr/0001-python-reference-rust-production.md",
    "docs/adr/0002-service-boundaries-and-transport.md",
    "docs/adr/0003-artifact-storage.md",
    "docs/adr/0004-policy-model.md",
    "docs/adr/0005-model-pack-and-signing.md",
    "docs/adr/0006-supported-package-layout.md",
    "docs/gates/g0/blockers.json",
    "docs/gates/g0/ci_lanes.json",
    "docs/gates/g0/evidence.json",
    "docs/gates/g0/lab_inventory.json",
    "docs/gates/g0/security_review.json",
    "docs/gates/g1/blockers.json",
    "docs/gates/g1/evidence.json",
    "docs/registers/adversarial.json",
    "docs/registers/failure_injection.json",
    "docs/registers/licenses.json",
    "docs/registers/workloads.json",
    "requirements/registry.json",
    "requirements/registry.schema.json",
)
REQUIRED_RELEASE_FILES = (*REQUIRED_DOCS, GOVERNING_SOURCE_RECORD, *REQUIRED_GATE_FILES)
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
    if manifest.get("runtime_dependencies") != []:
        raise RuntimeError("v0.1.0 runtime dependency list must remain empty")
    if manifest.get("external_assets", {}).get("model_weights_included") is not False:
        raise RuntimeError("release manifest must explicitly exclude model weights")
    json_schema_files = sorted((ROOT / "schemas").glob("*.json"))
    for schema in json_schema_files:
        json.loads(schema.read_text(encoding="utf-8"))
    report("Release metadata", f"version {version}; {len(json_schema_files)} JSON schemas")


def validate_governing_sources() -> None:
    record = json.loads((ROOT / GOVERNING_SOURCE_RECORD).read_text(encoding="utf-8"))
    if record.get("schema_version") != 1:
        raise RuntimeError("governing source record must use schema_version 1")
    repository_check = record.get("repository_check")
    if not isinstance(repository_check, dict) or repository_check.get("result") != "missing":
        raise RuntimeError("governing source record must report the current missing repository state")
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
        if source.get("availability") != "missing" or source.get("status") != "blocked":
            raise RuntimeError("every unavailable governing source must have missing/blocked status")
        nullable = ("locator", "revision", "size_bytes", "sha256")
        if any(source.get(field) is not None for field in nullable):
            raise RuntimeError(
                "missing governing sources must keep locator, revision, size, and digest null"
            )
    g0_impact = record.get("g0_impact")
    if not isinstance(g0_impact, dict) or g0_impact.get("status") != "blocked":
        raise RuntimeError("governing source record must mark G0 impact as blocked")

    narrative = (ROOT / "docs/GOVERNING_REQUIREMENTS_SOURCES.md").read_text(encoding="utf-8")
    for filename in GOVERNING_SOURCE_FILENAMES:
        if f"`{filename}`" not in narrative:
            raise RuntimeError(f"governing source narrative omits exact filename: {filename}")
    if narrative.count("**Blocked:") < len(GOVERNING_SOURCE_FILENAMES):
        raise RuntimeError("governing source narrative must explicitly mark all three sources Blocked")
    report("Governing source record", "three exact dependencies explicitly blocked")


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
        blockers = documents[blockers_path]
        evidence = documents[evidence_path]
        if not isinstance(blockers, dict) or blockers.get("status") != "blocked":
            raise RuntimeError(f"{gate.upper()} blocker record must remain explicitly blocked")
        blocker_items = blockers.get("blockers")
        if not isinstance(blocker_items, list) or not blocker_items:
            raise RuntimeError(f"{gate.upper()} blocker record must contain blockers")
        for item in blocker_items:
            if not isinstance(item, dict):
                raise RuntimeError(f"{gate.upper()} blocker entries must be objects")
            if item.get("status") != "open" or not item.get("owner") or not item.get("decision_due"):
                raise RuntimeError(
                    f"{gate.upper()} blockers must be open and carry owner/decision_due"
                )
            evidence_reference = item.get("evidence")
            evidence_path = PurePosixPath(evidence_reference) if isinstance(evidence_reference, str) else None
            if (
                evidence_path is None
                or evidence_path.is_absolute()
                or ".." in evidence_path.parts
                or not ROOT.joinpath(*evidence_path.parts).is_file()
            ):
                raise RuntimeError(f"{gate.upper()} blocker evidence must reference a repository file")
        if not isinstance(evidence, dict) or evidence.get("assessment") != "blocked":
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
                evidence_path = PurePosixPath(reference) if isinstance(reference, str) else None
                if (
                    evidence_path is None
                    or evidence_path.is_absolute()
                    or ".." in evidence_path.parts
                    or not ROOT.joinpath(*evidence_path.parts).is_file()
                ):
                    raise RuntimeError(
                        f"{gate.upper()} evidence reference is unavailable: {reference!r}"
                    )

    inventory = documents["docs/gates/g0/lab_inventory.json"]
    if not isinstance(inventory, dict):
        raise RuntimeError("G0 lab inventory must be an object")
    hardware = inventory.get("required_reference_hardware")
    if not isinstance(hardware, dict) or hardware.get("a1_x86_64_boards_designated") != 0:
        raise RuntimeError("lab inventory must not claim unverified A1 reference boards")

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
    report("Gate artifacts", "288 provisional requirements; G0/G1 explicitly blocked")


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
