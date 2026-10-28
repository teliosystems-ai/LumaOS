#!/usr/bin/env python3
"""Read-only measurement of the sequence-19 live staging allocation.

Mirrors rust/luma-platform/src/bundle.rs process_member: each 1 MiB read
chunk that is not entirely zero is charged rounded up to 4096 bytes; all-zero
chunks are left sparse. Each member's length and SHA-256 are checked against
the signed release.json before its allocation is counted. Staging admission
needs that total plus the 64 MiB RESERVE in RAM-backed /var, which defaults to
half of RAM (staging.rs check_capacity).
"""
import hashlib
import json
import sys
from pathlib import Path

CHUNK = 1024 * 1024
RESERVE = 64 * 1024 * 1024
MIB = 1024 * 1024
ZERO = bytes(CHUNK)


def measure(path, artifact):
    if path.stat().st_size != artifact['bytes']:
        raise SystemExit(f'size mismatch: {path}')
    digest = hashlib.sha256()
    allocation = 0
    with path.open('rb') as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            digest.update(block)
            if block != ZERO[:len(block)]:
                allocation += (len(block) + 4095) // 4096 * 4096
    if digest.hexdigest() != artifact['sha256']:
        raise SystemExit(f'digest mismatch: {path}')
    return allocation


def main():
    directory = Path(sys.argv[1])
    release = json.loads((directory / 'release.json').read_text())
    members = {}
    for artifact in release['artifacts']:
        members[artifact['name']] = measure(directory / artifact['name'], artifact)
    total = sum(members.values())
    needed = total + RESERVE
    print(json.dumps({
        'release': release['release'],
        'members': members,
        'payload_bytes': total,
        'reserve_bytes': RESERVE,
        'tmpfs_bytes_needed': needed,
        'ram_mib_needed_more_than': (needed * 2 + MIB - 1) // MIB,
    }, indent=1, sort_keys=True))


if __name__ == '__main__':
    main()
