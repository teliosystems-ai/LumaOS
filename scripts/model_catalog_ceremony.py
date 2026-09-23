#!/usr/bin/env python3
"""Prepare and assemble detached catalog-signing artifacts.

This command never accepts a private key and never performs signing.  Its
output statement is intended for an external offline/HSM Ed25519 signer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.model_catalog_signing import (  # noqa: E402
    MAX_APPROVAL_SET_BYTES,
    MAX_CATALOG_BYTES,
    MAX_RAW_SIGNATURE_READ_BYTES,
    MAX_STATEMENT_BYTES,
    CatalogReleaseRequest,
    CatalogSignatureEnvelope,
    CatalogSignatureStatement,
    ModelCatalogSigningError,
    canonical_approval_set_bytes,
    parse_canonical_approval_set,
    parse_canonical_catalog,
    parse_canonical_release_request,
    parse_canonical_statement,
)


def _read(path: str, label: str, maximum_bytes: int) -> bytes:
    try:
        with Path(path).open("rb") as stream:
            if stream.seek(0, 2) > maximum_bytes:
                raise ModelCatalogSigningError(
                    f"{label} exceeds the {maximum_bytes}-byte input limit"
                )
            stream.seek(0)
            content = stream.read(maximum_bytes + 1)
    except OSError as exc:
        raise ModelCatalogSigningError(f"cannot read {label}: {path}") from exc
    if len(content) > maximum_bytes:
        raise ModelCatalogSigningError(
            f"{label} exceeds the {maximum_bytes}-byte input limit"
        )
    return content


def _write_new(path: str, content: bytes, label: str) -> None:
    try:
        with Path(path).open("xb") as stream:
            stream.write(content)
    except FileExistsError as exc:
        raise ModelCatalogSigningError(f"refusing to overwrite {label}: {path}") from exc
    except OSError as exc:
        raise ModelCatalogSigningError(f"cannot write {label}: {path}") from exc


def _request(args: argparse.Namespace) -> dict[str, object]:
    raw_catalog = _read(args.catalog, "catalog", MAX_CATALOG_BYTES)
    catalog = parse_canonical_catalog(raw_catalog)
    request = CatalogReleaseRequest.from_mapping(
        {
            "artifact_type": "model-profile-catalog-release-request",
            "catalog_id": catalog.catalog_id,
            "catalog_sequence": args.catalog_sequence,
            "catalog_sha256": hashlib.sha256(raw_catalog).hexdigest(),
            "environment": args.environment,
            "not_after": args.not_after,
            "not_before": args.not_before,
            "policy_version": args.policy_version,
            "purpose": f"model-profile-catalog-{args.environment}",
            "release_id": args.release_id,
            "schema_version": 1,
            "signature_algorithm": "Ed25519",
            "signer_key_id": args.signer_key_id,
            "signing_activity": f"model-catalog.sign.{args.environment}",
            "signing_assignment_id": args.signing_assignment_id,
            "signing_assignment_receipt_sha256": args.signing_assignment_receipt_sha256,
            "signing_principal_id": args.signing_principal_id,
        }
    )
    _write_new(args.request_out, request.canonical_bytes, "release request")
    return {
        "catalog_sha256": request.catalog_sha256,
        "environment": request.environment,
        "purpose": request.purpose.value,
        "release_request_path": str(Path(args.request_out)),
        "release_request_sha256": request.digest,
    }


def _prepare(args: argparse.Namespace) -> dict[str, object]:
    raw_catalog = _read(args.catalog, "catalog", MAX_CATALOG_BYTES)
    catalog = parse_canonical_catalog(raw_catalog)
    request = parse_canonical_release_request(
        _read(args.request, "release request", MAX_STATEMENT_BYTES)
    )
    approvals = parse_canonical_approval_set(
        _read(args.approvals, "approval set", MAX_APPROVAL_SET_BYTES)
    )
    if request.catalog_id != catalog.catalog_id:
        raise ModelCatalogSigningError("release-request catalog_id does not match catalog")
    if request.catalog_sha256 != hashlib.sha256(raw_catalog).hexdigest():
        raise ModelCatalogSigningError("release-request digest does not match catalog")
    statement_payload = request.canonical_payload()
    statement_payload.update(
        {
            "approval_set_sha256": hashlib.sha256(
                canonical_approval_set_bytes(approvals)
            ).hexdigest(),
            "artifact_type": "model-profile-catalog",
            "release_request_sha256": request.digest,
            "signed_at": args.signed_at,
        }
    )
    statement = CatalogSignatureStatement.from_mapping(
        statement_payload
    )
    # A placeholder signature validates quorum, environment, catalog scope, and
    # custodian separation without invoking or representing private-key code.
    CatalogSignatureEnvelope(statement, approvals, b"\x00" * 64)
    _write_new(args.statement_out, statement.canonical_bytes, "statement")
    return {
        "approval_set_sha256": statement.approval_set_sha256,
        "catalog_sha256": request.catalog_sha256,
        "environment": statement.environment,
        "purpose": statement.purpose.value,
        "statement_path": str(Path(args.statement_out)),
        "statement_sha256": statement.digest,
    }


def _assemble(args: argparse.Namespace) -> dict[str, object]:
    raw_catalog = _read(args.catalog, "catalog", MAX_CATALOG_BYTES)
    catalog = parse_canonical_catalog(raw_catalog)
    approvals = parse_canonical_approval_set(
        _read(args.approvals, "approval set", MAX_APPROVAL_SET_BYTES)
    )
    statement = parse_canonical_statement(
        _read(args.statement, "statement", MAX_STATEMENT_BYTES)
    )
    signature = _read(
        args.signature,
        "raw signature",
        MAX_RAW_SIGNATURE_READ_BYTES,
    )
    if statement.catalog_id != catalog.catalog_id:
        raise ModelCatalogSigningError("statement catalog_id does not match catalog")
    if statement.catalog_sha256 != hashlib.sha256(raw_catalog).hexdigest():
        raise ModelCatalogSigningError("statement catalog digest does not match catalog")
    envelope = CatalogSignatureEnvelope(statement, approvals, signature)
    _write_new(args.envelope_out, envelope.canonical_bytes, "signature envelope")
    return {
        "catalog_sha256": statement.catalog_sha256,
        "envelope_path": str(Path(args.envelope_out)),
        "envelope_sha256": hashlib.sha256(envelope.canonical_bytes).hexdigest(),
        "statement_sha256": statement.digest,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare or assemble a Luma OS model-catalog signature; never loads private keys."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    request = subparsers.add_parser(
        "request", help="freeze canonical release scope before human approvals"
    )
    request.add_argument("--catalog", required=True)
    request.add_argument("--request-out", required=True)
    request.add_argument("--environment", required=True, choices=("lab", "production"))
    request.add_argument("--release-id", required=True)
    request.add_argument("--catalog-sequence", required=True, type=int)
    request.add_argument("--policy-version", required=True)
    request.add_argument("--signer-key-id", required=True)
    request.add_argument("--signing-principal-id", required=True)
    request.add_argument("--signing-assignment-id", required=True)
    request.add_argument("--signing-assignment-receipt-sha256", required=True)
    request.add_argument("--not-before", required=True, help="UTC: YYYY-MM-DDTHH:MM:SSZ")
    request.add_argument("--not-after", required=True, help="UTC: YYYY-MM-DDTHH:MM:SSZ")
    request.set_defaults(handler=_request)

    prepare = subparsers.add_parser("prepare", help="create canonical HSM signing input")
    prepare.add_argument("--catalog", required=True)
    prepare.add_argument("--request", required=True)
    prepare.add_argument("--approvals", required=True)
    prepare.add_argument("--statement-out", required=True)
    prepare.add_argument("--signed-at", required=True, help="UTC: YYYY-MM-DDTHH:MM:SSZ")
    prepare.set_defaults(handler=_prepare)

    assemble = subparsers.add_parser(
        "assemble", help="combine catalog, statement, approvals, and raw Ed25519 signature"
    )
    assemble.add_argument("--catalog", required=True)
    assemble.add_argument("--approvals", required=True)
    assemble.add_argument("--statement", required=True)
    assemble.add_argument("--signature", required=True)
    assemble.add_argument("--envelope-out", required=True)
    assemble.set_defaults(handler=_assemble)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        result = args.handler(args)
    except ModelCatalogSigningError as exc:
        print(f"catalog ceremony denied: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
