from __future__ import annotations

from copy import deepcopy
from dataclasses import fields, replace
import hashlib
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.catalog_admission import (  # noqa: E402
    CatalogAdmissionConflict,
    commit_catalog_admission,
)
from luma_os.installation_source import (  # noqa: E402
    MAX_DESCRIPTOR_BYTES,
    MAX_PACKAGE_COUNT,
    TARGET_TO_SYSTEM_ARCHITECTURE,
    U64_MAX,
    InstallationSourceContextStale,
    InstallationSourceError,
    InstallationSourceValidationDenied,
    ValidatedInstallationSource,
    edition_binding_sha256,
    parse_offline_installation_source,
    system_architecture_for_target,
    validate_installation_source,
)
from luma_os.installer import EditionSpec, PartitionSpec  # noqa: E402
from tests import test_catalog_admission as catalog_fixtures  # noqa: E402


MIB = 1024 * 1024


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


class InstallationSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog_fixture = catalog_fixtures.CatalogAdmissionTests()
        self.catalog_fixture.setUp()
        self.edition = EditionSpec(
            edition_id="luma-ubuntu-24.04",
            policy_version=1,
            payload_sha256="b" * 64,
            release_sha256="c" * 64,
            supported_architectures=("x86_64",),
            minimum_ram_bytes=8 * 1024 * MIB,
            partitions=(
                PartitionSpec("boot", "LUMA_BOOT", "fat32", 512 * MIB),
                PartitionSpec("system", "LUMA_SYSTEM", "ext4", 4096 * MIB),
                PartitionSpec("recovery", "LUMA_RECOVERY", "ext4", 2048 * MIB),
                PartitionSpec("models", "LUMA_MODELS", "ext4", 8192 * MIB),
            ),
            required_device_classes=("network",),
            minimum_accelerator_memory_bytes=0,
            allow_degraded_devices=True,
        )

    def descriptor(self, **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": 1,
            "source_kind": "offline-ubuntu-installation-source",
            "environment": "production",
            "release_id": "0.1.0",
            "ubuntu_release": "24.04",
            "target_architecture": "amd64",
            "base_image_sha256": "a" * 64,
            "os_payload_sha256": self.edition.payload_sha256,
            "release_metadata_sha256": self.edition.release_sha256,
            "offline_package_lock_sha256": "d" * 64,
            "sbom_sha256": "e" * 64,
            "packages": [
                {
                    "name": "base-files",
                    "version": "13ubuntu10.2",
                    "architecture": "amd64",
                    "size_bytes": 8192,
                    "sha256": "1" * 64,
                },
                {
                    "name": "ca-certificates",
                    "version": "20240203",
                    "architecture": "all",
                    "size_bytes": 16384,
                    "sha256": "2" * 64,
                },
            ],
        }
        value.update(changes)
        return value

    def committed_catalog(
        self,
        *,
        environment: str = "production",
        anchor=None,
        sequence: int = 1,
    ):
        plan, selected_anchor, _ = self.catalog_fixture.prepare(
            environment=environment,
            anchor=anchor,
            sequence=sequence,
        )
        return commit_catalog_admission(plan, anchor=selected_anchor), selected_anchor

    def validate(
        self,
        value: dict[str, object] | None = None,
        *,
        environment: str = "production",
        catalog=None,
        expected_sha256: str | None = None,
        edition: EditionSpec | None = None,
    ):
        raw = canonical_bytes(value or self.descriptor())
        if catalog is None:
            catalog, _ = self.committed_catalog(environment=environment)
        return validate_installation_source(
            raw,
            expected_descriptor_sha256=(
                expected_sha256 or hashlib.sha256(raw).hexdigest()
            ),
            expected_environment=environment,
            edition=edition or self.edition,
            catalog_admission=catalog,
        )

    def test_canonical_descriptor_validation_binds_every_input_digest(self) -> None:
        raw = canonical_bytes(self.descriptor())
        catalog, _ = self.committed_catalog()

        validated = validate_installation_source(
            raw,
            expected_descriptor_sha256=hashlib.sha256(raw).hexdigest(),
            expected_environment="production",
            edition=self.edition,
            catalog_admission=catalog,
        )

        self.assertIsInstance(validated, ValidatedInstallationSource)
        self.assertEqual(raw, validated.canonical_descriptor_bytes)
        self.assertEqual(24576, validated.descriptor.aggregate_package_bytes)
        receipt = validated.receipt
        self.assertEqual(hashlib.sha256(raw).hexdigest(), receipt.descriptor_sha256)
        self.assertEqual(edition_binding_sha256(self.edition), receipt.edition_sha256)
        self.assertEqual(catalog.catalog_sha256, receipt.catalog_sha256)
        self.assertEqual(catalog.admission_plan_sha256, receipt.catalog_admission_sha256)
        self.assertEqual(catalog.trust_bundle_sha256, receipt.trust_bundle_sha256)
        self.assertEqual(
            catalog.verification_receipt_sha256,
            receipt.catalog_verification_receipt_sha256,
        )
        self.assertEqual(catalog.anchor_checkpoint.namespace, receipt.catalog_anchor_namespace)
        self.assertEqual(catalog.anchor_checkpoint.generation, receipt.catalog_anchor_generation)
        self.assertEqual(64, len(validated.receipt_sha256))
        boundary = receipt.canonical_payload()
        self.assertEqual("none-data-only-digest-validation", boundary["authority_scope"])
        self.assertIs(boundary["authority"], False)
        self.assertIs(boundary["installer_authorization"], False)
        self.assertIs(boundary["governed_pin_evidence"], False)
        self.assertIs(boundary["edition_governance_evidence"], False)
        self.assertIs(boundary["artifact_bytes_verified"], False)
        self.assertIs(boundary["signed_release_evidence"], False)
        self.assertIs(boundary["physical_evidence"], False)
        self.assertIs(boundary["certification_closing"], False)

    def test_parser_rejects_noncanonical_duplicate_non_ascii_and_unknown_input(self) -> None:
        value = self.descriptor()
        canonical = canonical_bytes(value)
        duplicate = canonical.replace(
            b'"environment":"production"',
            b'"environment":"production","environment":"production"',
        )
        unknown = deepcopy(value)
        unknown["url"] = "https://example.invalid/source"
        cases = (
            json.dumps(value, indent=2, sort_keys=True).encode("ascii"),
            canonical + b"\n",
            duplicate,
            canonical.replace(b'"base-files"', '"bas\N{COPYRIGHT SIGN}e-files"'.encode("utf-8")),
            canonical_bytes(unknown),
        )
        for raw in cases:
            with self.subTest(raw=raw[:80]):
                with self.assertRaises(InstallationSourceError):
                    parse_offline_installation_source(raw)

    def test_parser_rejects_oversized_or_non_bytes_descriptors(self) -> None:
        with self.assertRaises(InstallationSourceError):
            parse_offline_installation_source(b" " * (MAX_DESCRIPTOR_BYTES + 1))
        with self.assertRaises(InstallationSourceError):
            parse_offline_installation_source(  # type: ignore[arg-type]
                bytearray(canonical_bytes(self.descriptor()))
            )

    def test_package_count_order_and_identity_are_bounded(self) -> None:
        duplicate = self.descriptor()
        duplicate["packages"] = [
            deepcopy(duplicate["packages"][0]),  # type: ignore[index]
            deepcopy(duplicate["packages"][0]),  # type: ignore[index]
        ]
        unsorted = self.descriptor()
        unsorted["packages"] = list(reversed(unsorted["packages"]))  # type: ignore[arg-type]
        too_many = self.descriptor()
        too_many["packages"] = [
            {
                "name": f"pkg{index:04d}",
                "version": "1",
                "architecture": "amd64",
                "size_bytes": 1,
                "sha256": f"{index:064x}",
            }
            for index in range(MAX_PACKAGE_COUNT + 1)
        ]
        for value in (duplicate, unsorted, too_many):
            with self.subTest(package_count=len(value["packages"])):  # type: ignore[arg-type]
                with self.assertRaises(InstallationSourceError):
                    parse_offline_installation_source(canonical_bytes(value))

    def test_package_values_are_path_free_and_integer_bounded(self) -> None:
        cases: list[dict[str, object]] = []
        for field, invalid in (
            ("name", "etc/passwd"),
            ("version", "1/install.sh"),
            ("architecture", "../amd64"),
            ("size_bytes", True),
            ("size_bytes", 0),
            ("size_bytes", U64_MAX + 1),
        ):
            value = self.descriptor()
            value["packages"][0][field] = invalid  # type: ignore[index]
            cases.append(value)
        wrong_architecture = self.descriptor(target_architecture="arm64")
        cases.append(wrong_architecture)
        aggregate_overflow = self.descriptor()
        aggregate_overflow["packages"][0]["size_bytes"] = U64_MAX  # type: ignore[index]
        aggregate_overflow["packages"][1]["size_bytes"] = 1  # type: ignore[index]
        cases.append(aggregate_overflow)
        for value in cases:
            with self.subTest(packages=value["packages"]):
                with self.assertRaises(InstallationSourceError):
                    parse_offline_installation_source(canonical_bytes(value))

    def test_closed_shapes_reject_url_path_and_script_fields(self) -> None:
        for field in ("url", "path", "script"):
            top = self.descriptor()
            top[field] = "forbidden"
            package = self.descriptor()
            package["packages"][0][field] = "forbidden"  # type: ignore[index]
            for value in (top, package):
                with self.subTest(field=field, top=value is top):
                    with self.assertRaises(InstallationSourceError):
                        parse_offline_installation_source(canonical_bytes(value))

    def test_external_descriptor_pin_is_mandatory_and_exact(self) -> None:
        catalog, _ = self.committed_catalog()
        raw = canonical_bytes(self.descriptor())
        with self.assertRaises(InstallationSourceValidationDenied):
            validate_installation_source(
                raw,
                expected_descriptor_sha256="f" * 64,
                expected_environment="production",
                edition=self.edition,
                catalog_admission=catalog,
            )
        with self.assertRaises(InstallationSourceError):
            validate_installation_source(
                raw,
                expected_descriptor_sha256="F" * 64,
                expected_environment="production",
                edition=self.edition,
                catalog_admission=catalog,
            )

    def test_release_environment_architecture_and_edition_mismatches_fail_closed(self) -> None:
        catalog, _ = self.committed_catalog()
        cases = (
            self.descriptor(environment="lab"),
            self.descriptor(release_id="0.2.0"),
            self.descriptor(target_architecture="arm64", packages=[
                {
                    "name": "base-files",
                    "version": "13ubuntu10.2",
                    "architecture": "arm64",
                    "size_bytes": 8192,
                    "sha256": "1" * 64,
                }
            ]),
            self.descriptor(os_payload_sha256="9" * 64),
            self.descriptor(release_metadata_sha256="8" * 64),
        )
        for value in cases:
            raw = canonical_bytes(value)
            with self.subTest(value=value):
                with self.assertRaises(InstallationSourceValidationDenied):
                    validate_installation_source(
                        raw,
                        expected_descriptor_sha256=hashlib.sha256(raw).hexdigest(),
                        expected_environment="production",
                        edition=self.edition,
                        catalog_admission=catalog,
                    )

    def test_lab_and_production_validation_contexts_are_not_interchangeable(self) -> None:
        production, _ = self.committed_catalog(environment="production")
        lab, _ = self.committed_catalog(environment="lab")
        lab_value = self.descriptor(environment="lab")
        lab_raw = canonical_bytes(lab_value)

        validated_lab = validate_installation_source(
            lab_raw,
            expected_descriptor_sha256=hashlib.sha256(lab_raw).hexdigest(),
            expected_environment="lab",
            edition=self.edition,
            catalog_admission=lab,
        )
        self.assertEqual("lab", validated_lab.receipt.environment)

        with self.assertRaises(InstallationSourceValidationDenied):
            validate_installation_source(
                lab_raw,
                expected_descriptor_sha256=hashlib.sha256(lab_raw).hexdigest(),
                expected_environment="lab",
                edition=self.edition,
                catalog_admission=production,
            )
        with self.assertRaises(InstallationSourceValidationDenied):
            validate_installation_source(
                lab_raw,
                expected_descriptor_sha256=hashlib.sha256(lab_raw).hexdigest(),
                expected_environment="production",
                edition=self.edition,
                catalog_admission=lab,
            )

    def test_catalog_n_validation_must_be_repeated_after_n_plus_one(self) -> None:
        first_catalog, anchor = self.committed_catalog(sequence=1)
        raw = canonical_bytes(self.descriptor())
        expected_digest = hashlib.sha256(raw).hexdigest()
        validated = self.validate(catalog=first_catalog)
        self.assertEqual("0.1.0", validated.descriptor.release_id)

        second_plan, _, _ = self.catalog_fixture.prepare(
            anchor=anchor,
            sequence=2,
        )
        second_catalog = commit_catalog_admission(second_plan, anchor=anchor)
        self.assertEqual(2, second_catalog.catalog_sequence)

        # Historical data stays readable and therefore cannot be authority.
        self.assertEqual("0.1.0", validated.descriptor.release_id)
        self.assertFalse(hasattr(validated, "ensure_current"))
        with self.assertRaises(InstallationSourceContextStale):
            validate_installation_source(
                raw,
                expected_descriptor_sha256=expected_digest,
                expected_environment="production",
                edition=self.edition,
                catalog_admission=first_catalog,
            )
        refreshed = validate_installation_source(
            raw,
            expected_descriptor_sha256=expected_digest,
            expected_environment="production",
            edition=self.edition,
            catalog_admission=second_catalog,
        )
        self.assertEqual(2, refreshed.receipt.catalog_sequence)
        with self.assertRaises(CatalogAdmissionConflict):
            first_catalog.ensure_current()

    def test_validation_must_be_repeated_after_catalog_trust_advances(self) -> None:
        trust_context = self.catalog_fixture.anchored_trust(with_context=True)
        first_trust = trust_context[0]
        plan, anchor, _ = self.catalog_fixture.prepare(
            trust_bundle=first_trust,
        )
        catalog = commit_catalog_admission(plan, anchor=anchor)
        raw = canonical_bytes(self.descriptor())
        expected_digest = hashlib.sha256(raw).hexdigest()
        validated = self.validate(catalog=catalog)
        self.assertEqual("0.1.0", validated.descriptor.release_id)

        second_trust = self.catalog_fixture.advance_trust(trust_context)

        self.assertEqual("0.1.0", validated.descriptor.release_id)
        with self.assertRaises(InstallationSourceContextStale):
            validate_installation_source(
                raw,
                expected_descriptor_sha256=expected_digest,
                expected_environment="production",
                edition=self.edition,
                catalog_admission=catalog,
            )

        replacement_plan, _, _ = self.catalog_fixture.prepare(
            anchor=anchor,
            sequence=1,
            trust_bundle=second_trust,
        )
        replacement_catalog = commit_catalog_admission(
            replacement_plan,
            anchor=anchor,
        )
        refreshed = validate_installation_source(
            raw,
            expected_descriptor_sha256=expected_digest,
            expected_environment="production",
            edition=self.edition,
            catalog_admission=replacement_catalog,
        )
        self.assertEqual(second_trust.bundle_sha256, refreshed.receipt.trust_bundle_sha256)

    def test_coordinated_data_forgery_cannot_bypass_raw_pin_revalidation(self) -> None:
        catalog, _ = self.committed_catalog()
        original_raw = canonical_bytes(self.descriptor())
        original_pin = hashlib.sha256(original_raw).hexdigest()
        validated = self.validate(catalog=catalog)
        malicious_raw = canonical_bytes(
            self.descriptor(base_image_sha256="f" * 64)
        )
        malicious = parse_offline_installation_source(malicious_raw)
        forged_receipt = replace(
            validated.receipt,
            descriptor_sha256=malicious.digest,
            base_image_sha256=malicious.base_image_sha256,
        )

        # Public construction is allowed because this is explicitly inert data.
        forged = ValidatedInstallationSource(malicious, forged_receipt)
        self.assertEqual(malicious.digest, forged.receipt.descriptor_sha256)
        self.assertIs(forged.receipt.canonical_payload()["authority"], False)
        self.assertFalse(hasattr(forged, "ensure_current"))

        # An effect boundary that repeats validation against the independently
        # supplied original pin rejects the coordinated descriptor/receipt swap.
        with self.assertRaises(InstallationSourceValidationDenied):
            validate_installation_source(
                malicious_raw,
                expected_descriptor_sha256=original_pin,
                expected_environment="production",
                edition=self.edition,
                catalog_admission=catalog,
            )

        # Even an attacker-selected matching pin yields data, never authority.
        attacker_selected = validate_installation_source(
            malicious_raw,
            expected_descriptor_sha256=malicious.digest,
            expected_environment="production",
            edition=self.edition,
            catalog_admission=catalog,
        )
        self.assertIs(
            attacker_selected.receipt.canonical_payload()["governed_pin_evidence"],
            False,
        )
        self.assertIs(
            attacker_selected.receipt.canonical_payload()["installer_authorization"],
            False,
        )

    def test_anchor_read_failure_denies_a_fresh_validation(self) -> None:
        catalog, _ = self.committed_catalog()
        validated = self.validate(catalog=catalog)

        def fail_read(namespace: str):
            del namespace
            raise OSError("anchor unavailable")

        catalog._anchor.read = fail_read  # type: ignore[attr-defined,method-assign]
        self.assertEqual("0.1.0", validated.descriptor.release_id)
        with self.assertRaises(InstallationSourceContextStale):
            self.validate(catalog=catalog)

    def test_schema_is_closed_and_matches_contract_bounds(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "schemas"
            / "offline-installation-source.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(
            "https://luma-os.invalid/schemas/offline-installation-source.schema.json",
            schema["$id"],
        )
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(MAX_PACKAGE_COUNT, schema["properties"]["packages"]["maxItems"])
        self.assertEqual(
            U64_MAX,
            schema["$defs"]["package"]["properties"]["size_bytes"]["maximum"],
        )
        self.assertNotIn("url", schema["properties"])
        self.assertNotIn("path", schema["properties"])
        self.assertNotIn("script", schema["properties"])

    def test_edition_digest_payload_covers_every_edition_field(self) -> None:
        self.assertEqual(
            {field.name for field in fields(EditionSpec)},
            set(self.edition.canonical_payload()),
        )

    def test_source_to_system_architecture_mapping_is_closed_and_immutable(self) -> None:
        self.assertEqual("x86_64", system_architecture_for_target("amd64"))
        self.assertEqual("aarch64", system_architecture_for_target("arm64"))
        with self.assertRaises(InstallationSourceError):
            system_architecture_for_target("x86-64")
        with self.assertRaises(TypeError):
            TARGET_TO_SYSTEM_ARCHITECTURE["amd64"] = "other"  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
