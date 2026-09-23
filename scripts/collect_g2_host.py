#!/usr/bin/env python3
"""Collect a bounded, non-destructive G2 Linux host inventory.

The JSON can be collected on native Ubuntu or Ubuntu WSL.  WSL output is useful
development evidence but is explicitly marked ineligible for physical gate
closure.  This tool never selects a disk or runs a mutating command.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from luma_os.g2_host_inventory import build_inventory, collect_observations  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--environment-id",
        required=True,
        help="declared evidence environment, for example E1, E2, or DEV-WSL-01",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="also create this JSON file; parent must exist and an existing file is refused",
    )
    parser.add_argument(
        "--include-sensitive-identifiers",
        action="store_true",
        help="include raw disk serial/WWN values; keep this output outside Git",
    )
    parser.add_argument(
        "--require-native-ubuntu-24.04",
        dest="require_native_ubuntu_24_04",
        action="store_true",
        help="return status 3 unless this is a native Ubuntu 24.04 amd64 candidate",
    )
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    return parser


def main() -> int:
    args = _parser().parse_args()
    inventory = build_inventory(
        collect_observations(),
        environment_id=args.environment_id,
        include_sensitive_identifiers=args.include_sensitive_identifiers,
    )
    payload = json.dumps(
        inventory,
        indent=None if args.compact else 2,
        separators=(",", ":") if args.compact else None,
        sort_keys=True,
    ) + "\n"
    if args.output is not None:
        if not args.output.parent.is_dir():
            raise SystemExit("--output parent directory does not exist")
        try:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
        except FileExistsError as exc:
            raise SystemExit("--output already exists; refusing to overwrite evidence") from exc
    sys.stdout.write(payload)
    if (
        args.require_native_ubuntu_24_04
        and not inventory["system"]["native_ubuntu_24_04_amd64_candidate"]
    ):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
