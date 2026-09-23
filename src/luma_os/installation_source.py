"""Digest validation for an offline Ubuntu 24.04 source descriptor.

This module is deliberately a pure, non-destructive integrity boundary.  It
parses a bounded canonical ASCII JSON descriptor and binds that descriptor to
an externally supplied SHA-256 pin, an installer :class:`EditionSpec`, and a
currently anchored model catalog.  It does not download packages,
verify package bytes, write disks, authorize installation, establish a signed
Ubuntu release, or provide physical boot/certification evidence.

The returned object and receipt are explicitly inert data, not capability or
authority tokens.  A destructive boundary must call
:func:`validate_installation_source` again from the raw bytes, independently
governed pin, edition, and then-current catalog admission immediately before
the effect.  A production pin must ultimately come from an independently
authenticated, rollback-protected release record.  The consumed base image,
payload, package lock, packages, and SBOM still require byte hashing and the
applicable publisher/signature verification.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType

from .catalog_admission import AnchoredCatalogAdmission
from .installer import EditionSpec


SCHEMA_VERSION = 1
SOURCE_KIND = "offline-ubuntu-installation-source"
UBUNTU_RELEASE = "24.04"
SUPPORTED_TARGET_ARCHITECTURES = frozenset({"amd64", "arm64"})
TARGET_TO_SYSTEM_ARCHITECTURE: Mapping[str, str] = MappingProxyType(
    {
        "amd64": "x86_64",
        "arm64": "aarch64",
    }
)
MAX_DESCRIPTOR_BYTES = 4 * 1024 * 1024
MAX_PACKAGE_COUNT = 4096
U64_MAX = (1 << 64) - 1

_ENVIRONMENTS = frozenset({"lab", "production"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RELEASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}\Z")
_PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}\Z")
_PACKAGE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+:~\-]{0,255}\Z")
_PACKAGE_ARCHITECTURES = SUPPORTED_TARGET_ARCHITECTURES | {"all"}

_DESCRIPTOR_FIELDS = frozenset(
    {
        "schema_version",
        "source_kind",
        "environment",
        "release_id",
        "ubuntu_release",
        "target_architecture",
        "base_image_sha256",
        "os_payload_sha256",
        "release_metadata_sha256",
        "offline_package_lock_sha256",
        "sbom_sha256",
        "packages",
    }
)
_PACKAGE_FIELDS = frozenset(
    {"name", "version", "architecture", "size_bytes", "sha256"}
)


class InstallationSourceError(ValueError):
    """An offline installation-source descriptor or request is malformed."""


class InstallationSourceValidationDenied(RuntimeError):
    """A well-formed source does not match the supplied validation context."""


class InstallationSourceContextStale(InstallationSourceValidationDenied):
    """The catalog or trust checkpoint supplied for validation is not current."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def system_architecture_for_target(target_architecture: str) -> str:
    """Map the closed Debian source vocabulary to installer architecture names."""

    try:
        return TARGET_TO_SYSTEM_ARCHITECTURE[target_architecture]
    except (KeyError, TypeError) as exc:
        raise InstallationSourceError(
            "target_architecture must be exactly amd64 or arm64"
        ) from exc


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise InstallationSourceError("value is not canonical ASCII JSON") from exc


def _strict_mapping(
    value: object,
    *,
    fields: frozenset[str],
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InstallationSourceError(f"{label} must be an object")
    keys = set(value)
    if any(not isinstance(key, str) for key in keys):
        raise InstallationSourceError(f"{label} keys must be strings")
    missing = fields - keys
    unknown = keys - fields
    if missing:
        raise InstallationSourceError(
            f"{label} is missing fields: {sorted(missing)}"
        )
    if unknown:
        raise InstallationSourceError(
            f"{label} has unknown fields: {sorted(unknown)}"
        )
    return value


def _exact_string(value: object, expected: str, field: str) -> str:
    if value != expected or not isinstance(value, str):
        raise InstallationSourceError(f"{field} must be exactly {expected!r}")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise InstallationSourceError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _u64(value: object, field: str, *, positive: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InstallationSourceError(f"{field} must be an integer, not a boolean")
    if value < 0 or value > U64_MAX or (positive and value == 0):
        qualifier = "positive " if positive else ""
        raise InstallationSourceError(
            f"{field} must be a {qualifier}unsigned 64-bit integer"
        )
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InstallationSourceError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_float(value: str) -> object:
    raise InstallationSourceError(f"JSON floating-point value is forbidden: {value}")


def _reject_constant(value: str) -> object:
    raise InstallationSourceError(f"non-finite JSON value is forbidden: {value}")


@dataclass(frozen=True, slots=True)
class OfflinePackageEntry:
    """Immutable metadata for one package in an offline source inventory."""

    name: str
    version: str
    architecture: str
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _PACKAGE_NAME.fullmatch(self.name):
            raise InstallationSourceError("package name is not a canonical Debian name")
        if not isinstance(self.version, str) or not _PACKAGE_VERSION.fullmatch(
            self.version
        ):
            raise InstallationSourceError(
                "package version must be bounded path-free printable ASCII"
            )
        if self.architecture not in _PACKAGE_ARCHITECTURES:
            raise InstallationSourceError(
                "package architecture must be amd64, arm64, or all"
            )
        _u64(self.size_bytes, "package size_bytes", positive=True)
        _digest(self.sha256, "package sha256")

    @classmethod
    def from_mapping(cls, value: object) -> "OfflinePackageEntry":
        data = _strict_mapping(value, fields=_PACKAGE_FIELDS, label="package")
        return cls(
            name=data["name"],  # type: ignore[arg-type]
            version=data["version"],  # type: ignore[arg-type]
            architecture=data["architecture"],  # type: ignore[arg-type]
            size_bytes=data["size_bytes"],  # type: ignore[arg-type]
            sha256=data["sha256"],  # type: ignore[arg-type]
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "name": self.name,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class OfflineInstallationSource:
    """A parsed descriptor, not proof of package bytes or release authenticity."""

    schema_version: int
    source_kind: str
    environment: str
    release_id: str
    ubuntu_release: str
    target_architecture: str
    base_image_sha256: str
    os_payload_sha256: str
    release_metadata_sha256: str
    offline_package_lock_sha256: str
    sbom_sha256: str
    packages: tuple[OfflinePackageEntry, ...]

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION or isinstance(
            self.schema_version, bool
        ):
            raise InstallationSourceError("schema_version must be exactly 1")
        _exact_string(self.source_kind, SOURCE_KIND, "source_kind")
        if self.environment not in _ENVIRONMENTS:
            raise InstallationSourceError("environment must be exactly lab or production")
        if not isinstance(self.release_id, str) or not _RELEASE_ID.fullmatch(
            self.release_id
        ):
            raise InstallationSourceError("release_id must be a canonical safe identifier")
        _exact_string(self.ubuntu_release, UBUNTU_RELEASE, "ubuntu_release")
        if self.target_architecture not in SUPPORTED_TARGET_ARCHITECTURES:
            raise InstallationSourceError(
                "target_architecture must be exactly amd64 or arm64"
            )
        for field in (
            "base_image_sha256",
            "os_payload_sha256",
            "release_metadata_sha256",
            "offline_package_lock_sha256",
            "sbom_sha256",
        ):
            _digest(getattr(self, field), field)
        if not isinstance(self.packages, (tuple, list)):
            raise InstallationSourceError("packages must be an array")
        packages = tuple(self.packages)
        if not packages or len(packages) > MAX_PACKAGE_COUNT:
            raise InstallationSourceError(
                f"packages must contain 1 through {MAX_PACKAGE_COUNT} entries"
            )
        if any(not isinstance(item, OfflinePackageEntry) for item in packages):
            raise InstallationSourceError("packages contains an invalid entry")
        expected_order = tuple(
            sorted(packages, key=lambda item: (item.name, item.architecture, item.version))
        )
        if packages != expected_order:
            raise InstallationSourceError(
                "packages must be in canonical name/architecture/version order"
            )
        identities = tuple((item.name, item.architecture) for item in packages)
        if len(identities) != len(set(identities)):
            raise InstallationSourceError(
                "package name/architecture identities must be unique"
            )
        total_size = 0
        for package in packages:
            if package.architecture not in {self.target_architecture, "all"}:
                raise InstallationSourceError(
                    "package architecture does not match the target architecture"
                )
            total_size += package.size_bytes
            if total_size > U64_MAX:
                raise InstallationSourceError(
                    "aggregate package size exceeds unsigned 64-bit capacity"
                )
        object.__setattr__(self, "packages", packages)

    @classmethod
    def from_mapping(cls, value: object) -> "OfflineInstallationSource":
        data = _strict_mapping(
            value,
            fields=_DESCRIPTOR_FIELDS,
            label="installation source",
        )
        raw_packages = data["packages"]
        if not isinstance(raw_packages, (list, tuple)):
            raise InstallationSourceError("packages must be an array")
        if not raw_packages or len(raw_packages) > MAX_PACKAGE_COUNT:
            raise InstallationSourceError(
                f"packages must contain 1 through {MAX_PACKAGE_COUNT} entries"
            )
        return cls(
            schema_version=data["schema_version"],  # type: ignore[arg-type]
            source_kind=data["source_kind"],  # type: ignore[arg-type]
            environment=data["environment"],  # type: ignore[arg-type]
            release_id=data["release_id"],  # type: ignore[arg-type]
            ubuntu_release=data["ubuntu_release"],  # type: ignore[arg-type]
            target_architecture=data["target_architecture"],  # type: ignore[arg-type]
            base_image_sha256=data["base_image_sha256"],  # type: ignore[arg-type]
            os_payload_sha256=data["os_payload_sha256"],  # type: ignore[arg-type]
            release_metadata_sha256=data["release_metadata_sha256"],  # type: ignore[arg-type]
            offline_package_lock_sha256=data[
                "offline_package_lock_sha256"
            ],  # type: ignore[arg-type]
            sbom_sha256=data["sbom_sha256"],  # type: ignore[arg-type]
            packages=tuple(OfflinePackageEntry.from_mapping(item) for item in raw_packages),
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "base_image_sha256": self.base_image_sha256,
            "environment": self.environment,
            "offline_package_lock_sha256": self.offline_package_lock_sha256,
            "os_payload_sha256": self.os_payload_sha256,
            "packages": [package.canonical_payload() for package in self.packages],
            "release_id": self.release_id,
            "release_metadata_sha256": self.release_metadata_sha256,
            "sbom_sha256": self.sbom_sha256,
            "schema_version": self.schema_version,
            "source_kind": self.source_kind,
            "target_architecture": self.target_architecture,
            "ubuntu_release": self.ubuntu_release,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(self.canonical_payload())

    @property
    def digest(self) -> str:
        return _sha256(self.canonical_bytes)

    @property
    def aggregate_package_bytes(self) -> int:
        return sum(package.size_bytes for package in self.packages)


def parse_offline_installation_source(raw_descriptor: bytes) -> OfflineInstallationSource:
    """Parse only the exact bounded canonical ASCII representation."""

    if not isinstance(raw_descriptor, bytes):
        raise InstallationSourceError("descriptor must be immutable bytes")
    if not raw_descriptor:
        raise InstallationSourceError("descriptor must not be empty")
    if len(raw_descriptor) > MAX_DESCRIPTOR_BYTES:
        raise InstallationSourceError(
            f"descriptor exceeds the {MAX_DESCRIPTOR_BYTES}-byte limit"
        )
    try:
        text = raw_descriptor.decode("ascii")
    except UnicodeDecodeError as exc:
        raise InstallationSourceError("descriptor must contain ASCII only") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except InstallationSourceError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise InstallationSourceError("descriptor is not valid bounded JSON") from exc
    descriptor = OfflineInstallationSource.from_mapping(value)
    if descriptor.canonical_bytes != raw_descriptor:
        raise InstallationSourceError("descriptor is not canonical ASCII JSON")
    return descriptor


def _edition_payload(edition: EditionSpec) -> dict[str, object]:
    return edition.canonical_payload()


def edition_binding_sha256(edition: EditionSpec) -> str:
    """Digest every field of an already validated installer edition."""

    if not isinstance(edition, EditionSpec):
        raise InstallationSourceError("edition must be an EditionSpec")
    return _sha256(_canonical_json_bytes(_edition_payload(edition)))


@dataclass(frozen=True, slots=True)
class InstallationSourceValidationReceipt:
    """Inert digest-validation data; it is never installation authority."""

    environment: str
    release_id: str
    target_architecture: str
    descriptor_sha256: str
    edition_sha256: str
    catalog_id: str
    catalog_sequence: int
    catalog_sha256: str
    catalog_anchor_namespace: str
    catalog_anchor_generation: int
    catalog_admission_sha256: str
    trust_bundle_sha256: str
    catalog_verification_receipt_sha256: str
    base_image_sha256: str
    os_payload_sha256: str
    release_metadata_sha256: str
    offline_package_lock_sha256: str
    sbom_sha256: str

    def canonical_payload(self) -> dict[str, object]:
        return {
            "artifact_bytes_verified": False,
            "artifact_type": "offline-installation-source-validation-receipt",
            "authority": False,
            "authority_scope": "none-data-only-digest-validation",
            "base_image_sha256": self.base_image_sha256,
            "catalog_admission_sha256": self.catalog_admission_sha256,
            "catalog_anchor_generation": self.catalog_anchor_generation,
            "catalog_anchor_namespace": self.catalog_anchor_namespace,
            "catalog_id": self.catalog_id,
            "catalog_sequence": self.catalog_sequence,
            "catalog_sha256": self.catalog_sha256,
            "catalog_verification_receipt_sha256": self.catalog_verification_receipt_sha256,
            "certification_closing": False,
            "descriptor_sha256": self.descriptor_sha256,
            "edition_sha256": self.edition_sha256,
            "edition_governance_evidence": False,
            "environment": self.environment,
            "governed_pin_evidence": False,
            "installer_authorization": False,
            "offline_package_lock_sha256": self.offline_package_lock_sha256,
            "os_payload_sha256": self.os_payload_sha256,
            "physical_evidence": False,
            "release_id": self.release_id,
            "release_metadata_sha256": self.release_metadata_sha256,
            "sbom_sha256": self.sbom_sha256,
            "schema_version": 1,
            "signed_release_evidence": False,
            "target_architecture": self.target_architecture,
            "trust_bundle_sha256": self.trust_bundle_sha256,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(self.canonical_payload())

    @property
    def digest(self) -> str:
        return _sha256(self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class ValidatedInstallationSource:
    """Immutable historical data from one digest-validation pass.

    This object is intentionally public-constructible and replaceable.  It is
    not proof that its fields came from this module and must never be accepted
    as effect authority.  Consumers must re-run
    :func:`validate_installation_source` with the raw descriptor and independently
    obtained inputs at every authority boundary.
    """

    descriptor: OfflineInstallationSource
    receipt: InstallationSourceValidationReceipt

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, OfflineInstallationSource):
            raise InstallationSourceError(
                "validated source descriptor has an invalid type"
            )
        if not isinstance(self.receipt, InstallationSourceValidationReceipt):
            raise InstallationSourceError(
                "validated source receipt has an invalid type"
            )
        if self.descriptor.digest != self.receipt.descriptor_sha256:
            raise InstallationSourceError(
                "validated source data has inconsistent descriptor digests"
            )

    @property
    def receipt_sha256(self) -> str:
        return self.receipt.digest

    @property
    def canonical_descriptor_bytes(self) -> bytes:
        return self.descriptor.canonical_bytes


def validate_installation_source(
    raw_descriptor: bytes,
    *,
    expected_descriptor_sha256: str,
    expected_environment: str,
    edition: EditionSpec,
    catalog_admission: AnchoredCatalogAdmission,
) -> ValidatedInstallationSource:
    """Validate one descriptor against a pin and current catalog context.

    ``expected_descriptor_sha256`` must come from governance outside the
    descriptor for production use; merely passing a caller-selected digest does
    not prove governance approval.  The returned object is data only.  Success
    is explicitly not signed Ubuntu release verification, installer execution
    authorization, physical boot evidence, or final certification.
    """

    pinned_digest = _digest(
        expected_descriptor_sha256,
        "expected_descriptor_sha256",
    )
    if expected_environment not in _ENVIRONMENTS:
        raise InstallationSourceError(
            "expected_environment must be exactly lab or production"
        )
    if not isinstance(edition, EditionSpec):
        raise InstallationSourceError("edition must be an EditionSpec")
    if not isinstance(catalog_admission, AnchoredCatalogAdmission):
        raise InstallationSourceValidationDenied(
            "an AnchoredCatalogAdmission is required"
        )
    try:
        catalog_admission.ensure_current()
    except Exception as exc:
        raise InstallationSourceContextStale(
            "the supplied catalog admission is not current"
        ) from exc

    descriptor = parse_offline_installation_source(raw_descriptor)
    actual_digest = _sha256(raw_descriptor)
    if actual_digest != pinned_digest:
        raise InstallationSourceValidationDenied(
            "descriptor digest does not match the external SHA-256 pin"
        )
    if descriptor.environment != expected_environment:
        raise InstallationSourceValidationDenied(
            "descriptor environment does not match the requested environment"
        )
    if catalog_admission.environment != expected_environment:
        raise InstallationSourceValidationDenied(
            "catalog admission environment does not match the requested environment"
        )
    if descriptor.release_id != catalog_admission.release_id:
        raise InstallationSourceValidationDenied(
            "descriptor release_id does not match the catalog admission"
        )
    system_architecture = system_architecture_for_target(
        descriptor.target_architecture
    )
    if system_architecture not in edition.supported_architectures:
        raise InstallationSourceValidationDenied(
            "mapped descriptor architecture is not supported by the installer edition"
        )
    if descriptor.os_payload_sha256 != edition.payload_sha256:
        raise InstallationSourceValidationDenied(
            "descriptor OS payload digest does not match the installer edition"
        )
    if descriptor.release_metadata_sha256 != edition.release_sha256:
        raise InstallationSourceValidationDenied(
            "descriptor release metadata digest does not match the installer edition"
        )

    checkpoint = catalog_admission.anchor_checkpoint
    receipt = InstallationSourceValidationReceipt(
        environment=descriptor.environment,
        release_id=descriptor.release_id,
        target_architecture=descriptor.target_architecture,
        descriptor_sha256=actual_digest,
        edition_sha256=edition_binding_sha256(edition),
        catalog_id=catalog_admission.catalog_id,
        catalog_sequence=catalog_admission.catalog_sequence,
        catalog_sha256=catalog_admission.catalog_sha256,
        catalog_anchor_namespace=checkpoint.namespace,
        catalog_anchor_generation=checkpoint.generation,
        catalog_admission_sha256=catalog_admission.admission_plan_sha256,
        trust_bundle_sha256=catalog_admission.trust_bundle_sha256,
        catalog_verification_receipt_sha256=(
            catalog_admission.verification_receipt_sha256
        ),
        base_image_sha256=descriptor.base_image_sha256,
        os_payload_sha256=descriptor.os_payload_sha256,
        release_metadata_sha256=descriptor.release_metadata_sha256,
        offline_package_lock_sha256=descriptor.offline_package_lock_sha256,
        sbom_sha256=descriptor.sbom_sha256,
    )
    # Close the race across validation.  The returned data remains inert; an
    # effect owner must repeat this entire function immediately before use.
    try:
        catalog_admission.ensure_current()
    except Exception as exc:
        raise InstallationSourceContextStale(
            "the supplied catalog admission changed during validation"
        ) from exc
    return ValidatedInstallationSource(descriptor=descriptor, receipt=receipt)
