#!/usr/bin/env python3
"""Bounded, verified transfer from the build volume to an empty artifact folder."""
import hashlib
import os
from pathlib import Path

source=Path('/work/artifacts')
destination=Path('/out')
names=[p.name for p in source.glob('*.img.zst')]
names+=['SHA256SUMS','build.json','packages.lock','release.json','release.sig','secureboot.cer',
        'source-lock.json','toolchain-packages.lock','native-source.tar.zst']
if any(not (source/name).is_file() for name in names):
    raise SystemExit('incomplete artifact inventory; nothing has been exported')
for name in names:
    target=destination/name
    temporary=destination/(name+'.partial')
    if target.exists() or temporary.exists():
        raise SystemExit(f'refusing to overwrite artifact: {name}')
    expected=hashlib.sha256()
    with (source/name).open('rb') as src,temporary.open('xb') as dst:
        while block:=src.read(1024*1024):
            expected.update(block);dst.write(block)
        dst.flush();os.fsync(dst.fileno())
    with temporary.open('rb') as check:
        if hashlib.file_digest(check,'sha256').digest()!=expected.digest():
            raise SystemExit(f'artifact transfer digest mismatch: {name}')
    temporary.rename(target)
    print(f'Exported {name}',flush=True)
