#!/usr/bin/env python3
"""Dependency-free repository validation for local development and CI."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
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
)
REQUIRED_RELEASE_INPUTS = {
    "src",
    "tests",
    "web",
    "schemas",
    "examples",
    "docs",
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
    if manifest.get("runtime_dependencies") != []:
        raise RuntimeError("v0.1.0 runtime dependency list must remain empty")
    if manifest.get("external_assets", {}).get("model_weights_included") is not False:
        raise RuntimeError("release manifest must explicitly exclude model weights")
    json_schema_files = sorted((ROOT / "schemas").glob("*.json"))
    for schema in json_schema_files:
        json.loads(schema.read_text(encoding="utf-8"))
    report("Release metadata", f"version {version}; {len(json_schema_files)} JSON schemas")


def validate_repository() -> None:
    missing = [path for path in REQUIRED_DOCS if not (ROOT / path).is_file()]
    if missing:
        raise RuntimeError(f"required documentation is missing: {missing}")
    required_runtime_paths = ("src", "tests", "web/index.html", "schemas", "examples")
    missing_runtime = [path for path in required_runtime_paths if not (ROOT / path).exists()]
    if missing_runtime:
        raise RuntimeError(f"required runtime/release paths are missing: {missing_runtime}")
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
    report("Repository policy", "required docs/assets present; model weights absent")


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
            validate_repository()
            run_tests()
    except (OSError, ValueError, RuntimeError, py_compile.PyCompileError) as exc:
        print(f"[failed] {exc}", file=sys.stderr)
        return 1
    print("All requested checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
