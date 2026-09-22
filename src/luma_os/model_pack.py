"""Immutable model-pack recognition, integrity, and certification contracts.

This module verifies metadata and local files; it never imports model code or
starts a runtime.  Signature verification is injected through a narrow
Ed25519 verifier interface so private keys and trust policy remain outside the
model pack and this repository.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum
import hashlib
import json
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Protocol


class ModelPackError(RuntimeError):
    """Base class for model-pack rejection."""


class ModelManifestError(ValueError):
    """The manifest is malformed, non-canonical, or unsafe."""


class ModelPackIntegrityError(ModelPackError):
    """A signature, inventory, digest, or file invariant failed."""


class ModelPackCompatibilityError(ModelPackError):
    """The pack is not approved for the selected runtime tuple."""


class ModelPackState(IntEnum):
    RECOGNIZED = 1
    LOADABLE = 2
    EXECUTION_CERTIFIED = 3
    INTERACTIVE_CERTIFIED = 4


class Ed25519Verifier(Protocol):
    """Trust-store-backed detached Ed25519 verification boundary."""

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool: ...


def _ascii_text(value: object, field: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ModelManifestError(f"{field} must be a non-empty trimmed string")
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise ModelManifestError(f"{field} must use printable ASCII")
    return value


def _digest(value: object, field: str) -> str:
    text = _ascii_text(value, field)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ModelManifestError(f"{field} must be a lowercase SHA-256 digest")
    return text


def _positive_integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > (1 << 63) - 1:
        raise ModelManifestError(f"{field} must be a positive signed 64-bit integer")
    return value


def _expect_keys(value: object, field: str, required: set[str]) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ModelManifestError(f"{field} must be an object")
    if set(value) != required:
        missing = sorted(required - set(value))
        unknown = sorted(set(value) - required)
        raise ModelManifestError(f"{field} keys differ; missing={missing}, unknown={unknown}")
    return value


def _validate_canonical_domain(value: object, path: str = "$" ) -> None:
    """Restrict JSON to the dependency-free canonicalization profile.

    Printable ASCII strings and integers in the interoperable JSON range make
    Python's sorted compact serialization byte-equivalent for this manifest
    profile while excluding floating-point and Unicode ordering ambiguity.
    """

    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > (1 << 53) - 1:
            raise ModelManifestError(f"integer outside interoperable range at {path}")
        return
    if isinstance(value, str):
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
            raise ModelManifestError(f"non-ASCII canonical string at {path}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_canonical_domain(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ModelManifestError(f"non-string JSON key at {path}")
            _validate_canonical_domain(key, f"{path}.<key>")
            _validate_canonical_domain(item, f"{path}.{key}")
        return
    raise ModelManifestError(f"unsupported canonical JSON value at {path}")


def canonical_manifest_bytes(document: Mapping[str, object]) -> bytes:
    _validate_canonical_domain(document)
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _safe_relative_path(value: object, field: str) -> PurePosixPath:
    text = _ascii_text(value, field, maximum=1024)
    path = PurePosixPath(text)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ModelManifestError(f"{field} must be a normalized relative path")
    if "\\" in text or path.as_posix() != text:
        raise ModelManifestError(f"{field} must use normalized POSIX separators")
    return path


@dataclass(frozen=True, slots=True)
class BlobDeclaration:
    role: str
    path: PurePosixPath
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class RuntimeTuple:
    os_family: str
    architecture: str
    backend: str
    backend_version: str
    device: str

    def __post_init__(self) -> None:
        for field in ("os_family", "architecture", "backend", "backend_version", "device"):
            _ascii_text(getattr(self, field), field)

    @property
    def digest(self) -> str:
        document = {
            "architecture": self.architecture,
            "backend": self.backend,
            "backend_version": self.backend_version,
            "device": self.device,
            "os_family": self.os_family,
        }
        return hashlib.sha256(canonical_manifest_bytes(document)).hexdigest()


@dataclass(frozen=True, slots=True)
class ModelManifest:
    document: Mapping[str, object]
    canonical_bytes: bytes
    pack_id: str
    pack_version: str
    signer_key_id: str
    blobs: tuple[BlobDeclaration, ...]
    runtime_tuples: tuple[RuntimeTuple, ...]
    license_use: str
    redistribution: str
    network_default: str

    @classmethod
    def parse(cls, raw: bytes) -> "ModelManifest":
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ModelManifestError("manifest is not valid UTF-8 JSON") from exc
        root = _expect_keys(
            document,
            "manifest",
            {
                "schema_version",
                "canonicalization",
                "signature_algorithm",
                "pack_id",
                "pack_version",
                "model",
                "context",
                "blobs",
                "runtime_tuples",
                "license",
                "network_default",
                "signer_key_id",
            },
        )
        canonical = canonical_manifest_bytes(root)
        if raw != canonical:
            raise ModelManifestError("manifest bytes are not canonical")
        if root["schema_version"] != 1:
            raise ModelManifestError("unsupported manifest schema_version")
        if root["canonicalization"] != "RFC8785-ASCII-v1":
            raise ModelManifestError("unsupported canonicalization profile")
        if root["signature_algorithm"] != "Ed25519":
            raise ModelManifestError("signature_algorithm must be Ed25519")
        pack_id = _ascii_text(root["pack_id"], "pack_id")
        pack_version = _ascii_text(root["pack_version"], "pack_version")
        signer_key_id = _ascii_text(root["signer_key_id"], "signer_key_id")
        if root["network_default"] != "deny":
            raise ModelManifestError("network_default must be deny")

        model = _expect_keys(
            root["model"],
            "model",
            {"architecture", "identity", "parameter_class", "quantization", "source"},
        )
        for key, value in model.items():
            _ascii_text(value, f"model.{key}", maximum=1024)
        context = _expect_keys(root["context"], "context", {"maximum_tokens", "template_sha256"})
        _positive_integer(context["maximum_tokens"], "context.maximum_tokens")
        template_digest = _digest(context["template_sha256"], "context.template_sha256")

        raw_blobs = root["blobs"]
        if not isinstance(raw_blobs, list) or not raw_blobs:
            raise ModelManifestError("blobs must be a non-empty array")
        blobs: list[BlobDeclaration] = []
        paths: set[PurePosixPath] = set()
        roles: list[str] = []
        for index, value in enumerate(raw_blobs):
            blob = _expect_keys(value, f"blobs[{index}]", {"role", "path", "sha256", "size_bytes"})
            role = _ascii_text(blob["role"], f"blobs[{index}].role")
            if role not in {"model", "tokenizer", "template", "auxiliary", "license"}:
                raise ModelManifestError(f"unsupported blob role: {role}")
            path = _safe_relative_path(blob["path"], f"blobs[{index}].path")
            sha256 = _digest(blob["sha256"], f"blobs[{index}].sha256")
            if path.parts[0] == "blobs":
                if path.parts != ("blobs", "sha256", sha256):
                    raise ModelManifestError("content blobs must use blobs/sha256/<digest>")
            elif path.parts[0] != "licenses":
                raise ModelManifestError("declared files must be under blobs/sha256 or licenses")
            if path in paths:
                raise ModelManifestError(f"duplicate blob path: {path}")
            paths.add(path)
            roles.append(role)
            blobs.append(
                BlobDeclaration(
                    role=role,
                    path=path,
                    sha256=sha256,
                    size_bytes=_positive_integer(blob["size_bytes"], f"blobs[{index}].size_bytes"),
                )
            )
        if any(roles.count(required) != 1 for required in ("model", "tokenizer", "template")):
            raise ModelManifestError("exactly one model, tokenizer, and template blob is required")
        template_blobs = [blob for blob in blobs if blob.role == "template"]
        if template_blobs[0].sha256 != template_digest:
            raise ModelManifestError("context template digest does not match the template blob")

        raw_tuples = root["runtime_tuples"]
        if not isinstance(raw_tuples, list) or not raw_tuples:
            raise ModelManifestError("runtime_tuples must be a non-empty array")
        runtime_tuples: list[RuntimeTuple] = []
        for index, value in enumerate(raw_tuples):
            item = _expect_keys(
                value,
                f"runtime_tuples[{index}]",
                {"os_family", "architecture", "backend", "backend_version", "device"},
            )
            runtime_tuples.append(RuntimeTuple(**item))  # type: ignore[arg-type]
        if len(set(runtime_tuples)) != len(runtime_tuples):
            raise ModelManifestError("runtime_tuples must be unique")

        license_record = _expect_keys(
            root["license"],
            "license",
            {"identifier", "evaluation", "redistribution", "files"},
        )
        _ascii_text(license_record["identifier"], "license.identifier")
        if license_record["evaluation"] not in {"approved", "denied", "pending"}:
            raise ModelManifestError("license.evaluation has an unsupported value")
        if license_record["redistribution"] not in {"approved", "denied", "not-applicable", "pending"}:
            raise ModelManifestError("license.redistribution has an unsupported value")
        license_files = license_record["files"]
        if not isinstance(license_files, list) or not license_files:
            raise ModelManifestError("license.files must be a non-empty array")
        declared_license_paths = {blob.path.as_posix() for blob in blobs if blob.role == "license"}
        normalized_license_files = [
            _safe_relative_path(value, "license.files[]").as_posix() for value in license_files
        ]
        if len(normalized_license_files) != len(set(normalized_license_files)):
            raise ModelManifestError("license.files must not contain duplicates")
        if set(normalized_license_files) != declared_license_paths:
            raise ModelManifestError("license.files must exactly match license-role blobs")

        return cls(
            document=MappingProxyType(dict(root)),
            canonical_bytes=canonical,
            pack_id=pack_id,
            pack_version=pack_version,
            signer_key_id=signer_key_id,
            blobs=tuple(blobs),
            runtime_tuples=tuple(runtime_tuples),
            license_use=str(license_record["evaluation"]),
            redistribution=str(license_record["redistribution"]),
            network_default=str(root["network_default"]),
        )


@dataclass(frozen=True, slots=True)
class ModelPackVerification:
    pack_id: str
    pack_version: str
    manifest_sha256: str
    runtime_tuple: RuntimeTuple
    state: ModelPackState
    evidence_sha256: str | None = None


def verify_model_pack(
    root: str | Path,
    *,
    verifier: Ed25519Verifier,
    runtime_tuple: RuntimeTuple,
) -> ModelPackVerification:
    pack_root = Path(root)
    manifest_path = pack_root / "manifest.json"
    signature_path = pack_root / "manifest.sig"
    if pack_root.is_symlink() or not pack_root.is_dir():
        raise ModelPackIntegrityError("model pack root must be a real directory")
    try:
        raw_manifest = manifest_path.read_bytes()
        signature = signature_path.read_bytes()
    except OSError as exc:
        raise ModelPackIntegrityError("manifest and detached signature are required") from exc
    if not signature:
        raise ModelPackIntegrityError("detached signature is empty")
    manifest = ModelManifest.parse(raw_manifest)
    if not verifier.verify(raw_manifest, signature, key_id=manifest.signer_key_id):
        raise ModelPackIntegrityError("manifest signature is not trusted")
    if runtime_tuple not in manifest.runtime_tuples:
        raise ModelPackCompatibilityError("runtime tuple is not declared by the model pack")
    if manifest.license_use != "approved":
        raise ModelPackCompatibilityError("model evaluation license is not approved")

    expected = {PurePosixPath("manifest.json"), PurePosixPath("manifest.sig")}
    expected.update(blob.path for blob in manifest.blobs)
    observed: set[PurePosixPath] = set()
    for path in pack_root.rglob("*"):
        relative = PurePosixPath(path.relative_to(pack_root).as_posix())
        if path.is_symlink():
            raise ModelPackIntegrityError(f"symlinks are forbidden: {relative}")
        if path.is_file():
            if path.stat().st_nlink != 1:
                raise ModelPackIntegrityError(f"hard-linked files are forbidden: {relative}")
            observed.add(relative)
        elif not path.is_dir():
            raise ModelPackIntegrityError(f"special files are forbidden: {relative}")
    if observed != expected:
        raise ModelPackIntegrityError(
            f"pack inventory differs; missing={sorted(expected - observed, key=str)}, "
            f"undeclared={sorted(observed - expected, key=str)}"
        )
    for blob in manifest.blobs:
        path = pack_root.joinpath(*blob.path.parts)
        digest = hashlib.sha256()
        size = 0
        try:
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    size += len(chunk)
                    digest.update(chunk)
        except OSError as exc:
            raise ModelPackIntegrityError(f"cannot read declared blob: {blob.path}") from exc
        if size != blob.size_bytes or digest.hexdigest() != blob.sha256:
            raise ModelPackIntegrityError(f"declared blob failed integrity: {blob.path}")
    return ModelPackVerification(
        pack_id=manifest.pack_id,
        pack_version=manifest.pack_version,
        manifest_sha256=hashlib.sha256(raw_manifest).hexdigest(),
        runtime_tuple=runtime_tuple,
        state=ModelPackState.LOADABLE,
    )


@dataclass(frozen=True, slots=True)
class CertificationRecord:
    level: str
    pack_manifest_sha256: str
    runtime_tuple_sha256: str
    evidence_sha256: str
    signer_key_id: str

    def __post_init__(self) -> None:
        if self.level not in {"execution", "interactive"}:
            raise ModelManifestError("unsupported certification level")
        _digest(self.pack_manifest_sha256, "pack_manifest_sha256")
        _digest(self.runtime_tuple_sha256, "runtime_tuple_sha256")
        _digest(self.evidence_sha256, "evidence_sha256")
        _ascii_text(self.signer_key_id, "signer_key_id")

    @property
    def canonical_bytes(self) -> bytes:
        document = {
            "evidence_sha256": _digest(self.evidence_sha256, "evidence_sha256"),
            "level": self.level,
            "pack_manifest_sha256": _digest(
                self.pack_manifest_sha256, "pack_manifest_sha256"
            ),
            "runtime_tuple_sha256": _digest(
                self.runtime_tuple_sha256, "runtime_tuple_sha256"
            ),
            "signer_key_id": _ascii_text(self.signer_key_id, "signer_key_id"),
        }
        return canonical_manifest_bytes(document)


def apply_certification(
    verification: ModelPackVerification,
    record: CertificationRecord,
    signature: bytes,
    *,
    verifier: Ed25519Verifier,
) -> ModelPackVerification:
    target = (
        ModelPackState.EXECUTION_CERTIFIED
        if record.level == "execution"
        else ModelPackState.INTERACTIVE_CERTIFIED
    )
    if target is ModelPackState.INTERACTIVE_CERTIFIED and verification.state < ModelPackState.EXECUTION_CERTIFIED:
        raise ModelPackIntegrityError("interactive certification requires execution certification")
    if target <= verification.state:
        raise ModelPackIntegrityError("certification state must advance")
    if record.pack_manifest_sha256 != verification.manifest_sha256:
        raise ModelPackIntegrityError("certificate refers to another model pack")
    if record.runtime_tuple_sha256 != verification.runtime_tuple.digest:
        raise ModelPackIntegrityError("certificate refers to another runtime tuple")
    if not signature or not verifier.verify(
        record.canonical_bytes, signature, key_id=record.signer_key_id
    ):
        raise ModelPackIntegrityError("certification signature is not trusted")
    return ModelPackVerification(
        pack_id=verification.pack_id,
        pack_version=verification.pack_version,
        manifest_sha256=verification.manifest_sha256,
        runtime_tuple=verification.runtime_tuple,
        state=target,
        evidence_sha256=record.evidence_sha256,
    )
