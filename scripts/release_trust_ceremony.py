#!/usr/bin/env python3
"""Public-only native release trust ceremony preparation and verification.

Outputs are inert Admin catalog proposals, not approvals or time authorities.
No private key is accepted, generated, exported or used by this utility.
Actual catalog review/commit verifies current protected UTC, root policy,
installation identity and the hardware-selected journal independently.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from contextlib import ExitStack

SPKI = bytes.fromhex("302a300506032b6570032100")
TRUST_FIELDS = {"schema_version", "environment", "version", "root_sha256", "not_before_ms", "expires_ms", "keys"}
KEY_FIELDS = {"id", "public_key_hex", "purpose", "not_before_ms", "expires_ms", "revoked"}
MANIFEST_FIELDS = {"schema_version", "release", "sequence", "environment", "architecture", "ubuntu", "edition", "root_hash", "root_bytes", "hash_bytes", "artifacts"}
ARTIFACTS = {"root.ext4", "root.verity", "slot-a.efi", "slot-b.efi", "bootloader.efi", "secureboot.cer"}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def closed(value: object, fields: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("closed record fields differ")
    return value


def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def parse(data: bytes) -> dict:
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON")))


def read(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        import stat
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise ValueError("input must be a bounded nonempty regular file")
        data = bytearray()
        while len(data) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        after = os.fstat(fd)
        if len(data) != before.st_size or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("input changed during observation")
        return bytes(data)
    finally:
        os.close(fd)


def number(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid bounded integer")
    return value


def hex_value(value: object, length: int) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{length * 2}}}", value):
        raise ValueError("invalid lowercase hexadecimal value")
    return bytes.fromhex(value)


def identifier(value: object) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", value):
        raise ValueError("invalid exact identifier")


def validity(start: object, end: object) -> None:
    number(start, 1, 4_102_444_800_000)
    number(end, 1, 4_102_444_800_000)
    if not 0 < end - start <= 366 * 86_400_000:
        raise ValueError("validity must be finite and at most 366 days")


def validate_trust(value: object) -> dict:
    t = closed(value, TRUST_FIELDS)
    if t["schema_version"] != 1 or type(t["schema_version"]) is not int or t["environment"] not in ("lab", "production"):
        raise ValueError("unsupported trust schema/environment")
    number(t["version"], 1, 2**63 - 1)
    hex_value(t["root_sha256"], 32)
    validity(t["not_before_ms"], t["expires_ms"])
    if not isinstance(t["keys"], list) or not 1 <= len(t["keys"]) <= 64:
        raise ValueError("trust requires one to 64 exact keys")
    ids, public = set(), set()
    for k in t["keys"]:
        closed(k, KEY_FIELDS)
        identifier(k["id"])
        key = hex_value(k["public_key_hex"], 32)
        if k["id"] in ids or key in public or key == bytes(32) or k["purpose"] != "os-release" or type(k["revoked"]) is not bool:
            raise ValueError("duplicate, invalid or wrong-purpose release key")
        ids.add(k["id"]); public.add(key)
        if t["environment"] == "production" and hashlib.sha256(SPKI + key).hexdigest() == t["root_sha256"]:
            raise ValueError("production root cannot also be the delegated OS release signer")
        validity(k["not_before_ms"], k["expires_ms"])
        if k["not_before_ms"] < t["not_before_ms"] or k["expires_ms"] > t["expires_ms"]:
            raise ValueError("key validity escapes trust validity")
    if len(canonical(t)) > 16384:
        raise ValueError("oversized trust")
    return t


def validate_manifest(value: object) -> dict:
    m = closed(value, MANIFEST_FIELDS)
    if type(m["schema_version"]) is not int or m["schema_version"] != 1 or m["environment"] not in ("lab", "production") or m["architecture"] != "amd64" or m["ubuntu"] != "24.04" or m["edition"] not in ("desktop", "headless"):
        raise ValueError("unsupported native release identity")
    number(m["sequence"], 1, 2**63 - 1)
    if not isinstance(m["release"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", m["release"]):
        raise ValueError("invalid release ID")
    hex_value(m["root_hash"], 32)
    number(m["root_bytes"], 512 * 1024**2, 32 * 1024**3)
    number(m["hash_bytes"], 4096, 512 * 1024**2)
    if m["root_bytes"] % 4096 or m["hash_bytes"] % 4096 or not isinstance(m["artifacts"], list) or len(m["artifacts"]) != 6:
        raise ValueError("invalid root geometry/inventory")
    names = set()
    for a in m["artifacts"]:
        closed(a, {"name", "bytes", "sha256"})
        if a["name"] not in ARTIFACTS or a["name"] in names:
            raise ValueError("invalid closed artifact inventory")
        names.add(a["name"])
        number(a["bytes"], 1, 32 * 1024**3)
        hex_value(a["sha256"], 32)
        if (a["name"] == "root.ext4" and a["bytes"] != m["root_bytes"]) or (a["name"] == "root.verity" and a["bytes"] != m["hash_bytes"]):
            raise ValueError("inventory root geometry differs")
    return m


def openssl(arguments: list[str], inputs: list[bytes]) -> bytes:
    if not hasattr(os, "memfd_create"):
        raise RuntimeError("public verification requires Linux sealed memfd support")
    with ExitStack() as stack:
        paths, descriptors = [], []
        for value in inputs:
            fd = os.memfd_create("luma-public-ceremony", os.MFD_ALLOW_SEALING)
            stack.callback(os.close, fd)
            position = 0
            while position < len(value):
                position += os.write(fd, value[position:])
            os.lseek(fd, 0, os.SEEK_SET)
            import fcntl
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            paths.append(f"/proc/self/fd/{fd}"); descriptors.append(fd)
        command = ["/usr/bin/openssl", *[a.format(*paths) for a in arguments]]
        result = subprocess.run(command, pass_fds=descriptors, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env={"PATH": "/usr/bin"}, timeout=15, check=False)
        if result.returncode:
            raise ValueError("public cryptographic verification refused")
        return result.stdout


def public_der(pem: bytes) -> bytes:
    der = openssl(["pkey", "-pubin", "-in", "{0}", "-outform", "DER"], [pem])
    if len(der) != 44 or not der.startswith(SPKI):
        raise ValueError("public root must be an exact Ed25519 key")
    return der


def verify(key: bytes, message: bytes, signature: bytes) -> None:
    if len(key) != 44 or not key.startswith(SPKI) or len(signature) != 64 or not message:
        raise ValueError("invalid public Ed25519 input")
    openssl(["pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", "{0}", "-rawin", "-in", "{1}", "-sigfile", "{2}"], [key, message, signature])


def admitted_public_trust(command: object, root_pem: bytes) -> dict:
    c = closed(command, {"action", "expected_version", "bundle"})
    if c["action"] != "publish_release_trust":
        raise ValueError("not a release trust publication proposal")
    b = closed(c["bundle"], {"trust", "signature_hex"})
    t = validate_trust(b["trust"])
    if number(c["expected_version"], 0, 2**63 - 2) + 1 != t["version"]:
        raise ValueError("trust proposal version differs")
    der = public_der(root_pem)
    if hashlib.sha256(der).hexdigest() != t["root_sha256"]:
        raise ValueError("provided public root differs from signed root fingerprint")
    verify(der, canonical(t), hex_value(b["signature_hex"], 64))
    return b


def signed_release(data: bytes, signature: bytes, signer: str, trust: dict) -> dict:
    if len(data) > 65536:
        raise ValueError("oversized release metadata")
    m = validate_manifest(parse(data))
    identifier(signer)
    if m["environment"] != trust["trust"]["environment"]:
        raise ValueError("release and trust environments differ")
    keys = [k for k in trust["trust"]["keys"] if k["id"] == signer and not k["revoked"]]
    if len(keys) != 1:
        raise ValueError("unknown or revoked release signer")
    verify(SPKI + hex_value(keys[0]["public_key_hex"], 32), data, signature)
    return {"manifest": m, "manifest_json": data.decode("utf-8"), "signature_hex": signature.hex(), "signer": signer}


def exclusive_write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        position = 0
        while position < len(data):
            position += os.write(fd, data[position:])
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name == "posix":
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    prepare = commands.add_parser("prepare-trust")
    prepare.add_argument("--trust", type=Path, required=True)
    prepare.add_argument("--statement-out", type=Path, required=True)
    prepare.add_argument("--root-public", type=Path, required=True)
    assemble = commands.add_parser("assemble-trust")
    assemble.add_argument("--statement", type=Path, required=True)
    assemble.add_argument("--signature", type=Path, required=True)
    assemble.add_argument("--root-public", type=Path, required=True)
    assemble.add_argument("--command-out", type=Path, required=True)
    for name in ("prepare-initialize", "prepare-update"):
        command = commands.add_parser(name)
        command.add_argument("--trust-command", type=Path, required=True)
        command.add_argument("--root-public", type=Path, required=True)
        command.add_argument("--release", type=Path, required=True)
        command.add_argument("--signature", type=Path, required=True)
        command.add_argument("--signer", required=True)
        command.add_argument("--command-out", type=Path, required=True)
        if name == "prepare-update":
            command.add_argument("--prior", type=Path, required=True)
            command.add_argument("--expected-floor", type=int, required=True)
    args = parser.parse_args(argv)
    if args.operation == "prepare-trust":
        trust = validate_trust(parse(read(args.trust, 16384)))
        root = public_der(read(args.root_public, 4096))
        if hashlib.sha256(root).hexdigest() != trust["root_sha256"]:
            raise ValueError("root fingerprint differs")
        exclusive_write(args.statement_out, canonical(trust))
    elif args.operation == "assemble-trust":
        statement = read(args.statement, 16384)
        trust = validate_trust(parse(statement))
        if canonical(trust) != statement:
            raise ValueError("trust statement must be exact canonical bytes")
        command = {"action": "publish_release_trust", "expected_version": trust["version"] - 1,
                   "bundle": {"trust": trust, "signature_hex": read(args.signature, 64).hex()}}
        admitted_public_trust(command, read(args.root_public, 4096))
        exclusive_write(args.command_out, canonical(command))
    else:
        trust = admitted_public_trust(parse(read(args.trust_command, 32768)), read(args.root_public, 4096))
        release = signed_release(read(args.release, 65536), read(args.signature, 64), args.signer, trust)
        if args.operation == "prepare-initialize":
            command = {"action": "initialize_release", "release": release}
        else:
            prior = validate_manifest(parse(read(args.prior, 65536)))
            number(args.expected_floor, 0, 2**63 - 1)
            if release["manifest"]["sequence"] <= max(args.expected_floor, prior["sequence"]):
                raise ValueError("candidate does not exceed the exact admission floor and prior sequence")
            if any(prior[field] != release["manifest"][field] for field in ("environment", "edition", "root_bytes", "hash_bytes")):
                raise ValueError("candidate changes environment/edition/geometry")
            command = {"action": "prepare_release", "expected_floor": args.expected_floor,
                       "admission": {"prior": prior, "candidate": release, "trust_version": trust["trust"]["version"],
                                     "trust_sha256": hashlib.sha256(canonical(trust)).hexdigest()}}
        exclusive_write(args.command_out, canonical(command))


if __name__ == "__main__":
    main()
