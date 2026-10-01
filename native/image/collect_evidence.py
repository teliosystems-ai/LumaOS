#!/usr/bin/env python3
"""Export successful VM evidence, excluding disks, NVRAM and credentials."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--run',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
run=args.run.resolve(strict=True)
out=args.output.resolve()
if run.parent!=Path('/work') or not run.name.startswith('vm-'):
    raise SystemExit('evidence must come from a generated /work/vm-* run')
if not out.is_relative_to('/out') or out==Path('/out') or out.exists():
    raise SystemExit('choose a new directory beneath /out')
record=json.loads((run/'result.json').read_text())
if record.get('result')!='passed':raise SystemExit('no passing result to export')
files=[run/'result.json',*sorted(run.glob('*/serial.log')),*sorted(run.glob('*/qemu.log'))]
# Only fixed-name public greeter captures from the disposable desktop fixture;
# never copy arbitrary guest screenshots, user files, disks or TPM state.
files += sorted(run.glob('*/screen-greeter.png'))
files += sorted(run.glob('*/screen-independent-greeter.png'))
for source in files:
    if source.is_symlink() or not source.resolve().is_relative_to(run) or source.stat().st_size>8*1024*1024:
        raise SystemExit('unexpected evidence file or size')
out.mkdir(parents=True,mode=0o700)
inventory=[]
for source in files:
    relative=source.relative_to(run)
    target=out/relative;target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source,target)
    with target.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    inventory.append({'path':relative.as_posix(),'bytes':target.stat().st_size,'sha256':digest})
(out/'evidence-files.json').write_text(json.dumps(inventory,indent=2)+'\n')
print(json.dumps({'result':record,'files':inventory},indent=2))
