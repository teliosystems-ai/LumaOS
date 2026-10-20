#!/usr/bin/env python3
"""Bounded, verified transfer from the build volume to an empty artifact folder."""
import hashlib
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from assembly_storage import export_headroom

source=Path('/work/artifacts')
destination=Path('/out')
names=[p.name for p in source.glob('*.img.zst')]
names+=['SHA256SUMS','build.json','packages.lock','release.json','release.sig','secureboot.cer',
        'source-lock.json','toolchain-packages.lock','native-source.tar.zst','boot-policy.json']
import json
record = json.loads((source/'build.json').read_text())
if 'optical' in record:
    optical=record['optical']
    if (not isinstance(optical,dict) or optical.get('image') != record['release']+'.iso'
            or optical.get('boot_qualified') is not False or optical.get('gate_closing') is not False):
        raise SystemExit('optical build identity or unqualified transport scope differs')
    names += [optical['image'],'optical-media.json']
if record.get('production_signed') is True:
    names.append('release-trust.json')
if len(list(source.glob('*.img.zst'))) != 1:
    raise SystemExit('export requires exactly one sealed compressed image')
if any(not (source/name).is_file() for name in names):
    raise SystemExit('incomplete artifact inventory; nothing has been exported')
export_headroom(source, destination, names)
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
