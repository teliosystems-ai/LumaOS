#!/usr/bin/env python3
"""Remove only regenerable image intermediates from one explicitly mounted build.

Retains the verified compressed image, metadata, source, keys (never mounted),
and every VM log/disk. Refuses to remove an image used as a qcow2 backing file.
Default is a dry run; never use against a build or test still running.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--execute',action='store_true')
args=parser.parse_args()
artifacts=Path('/work/artifacts')
if artifacts.is_symlink() or artifacts.resolve()!=artifacts:
    raise SystemExit('expected a real generated artifact directory')
record=json.loads((artifacts/'build.json').read_text())
name=record['image']
if not re.fullmatch(r'luma-native-lab-\d{8}-(headless|desktop)-[1-9]\d*\.img',name):
    raise SystemExit('unexpected generated image name')
image=artifacts/name;compressed=artifacts/(name+'.zst')
checksums={line.split('  ',1)[1]:line.split('  ',1)[0]
           for line in (artifacts/'SHA256SUMS').read_text().splitlines()}
if compressed.is_symlink() or not compressed.is_file():
    raise SystemExit('missing retained compressed image')
with compressed.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
if checksums.get(compressed.name)!=digest:
    raise SystemExit('retained compressed image checksum mismatch')
for disk in Path('/work').glob('vm-*/*.qcow2'):
    info=json.loads(subprocess.run(['qemu-img','info','--output=json',str(disk)],
                    check=True,capture_output=True,text=True).stdout)
    backing=info.get('full-backing-filename')
    if backing and Path(backing).resolve()==image:
        raise SystemExit('a retained VM overlay still depends on this image')
targets=[artifacts/n for n in (name,'root.ext4','root.verity','payload.ext4','esp.fat')]
for target in targets:
    if target.is_symlink() or target.resolve().parent!=artifacts or not target.is_file():
        raise SystemExit('unexpected or missing intermediate: '+str(target))
print('Verified retained archive: '+str(compressed),flush=True)
for target in targets:
    print(('Removing ' if args.execute else 'Would remove ')+str(target),flush=True)
    if args.execute:target.unlink()
print('All removed image bytes can be recovered from the retained compressed image; build source and VM evidence are unchanged.',flush=True)
