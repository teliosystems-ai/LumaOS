#!/usr/bin/env python3
"""Require real dm-verity to reject corrupted root metadata in an image overlay."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from vm_test import VM, TEST_SOURCES

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--image',type=Path,required=True)
parser.add_argument('--work',type=Path,required=True)
args=parser.parse_args()
image=args.image.resolve(strict=True);work=args.work.resolve()
if not image.is_file() or not image.is_relative_to('/work/artifacts'):
    raise SystemExit('only generated regular-file images are accepted')
if work.parent!=Path('/work') or not work.name.startswith('vm-') or work.exists():
    raise SystemExit('use a new /work/vm-* directory')
geometry=subprocess.run(['sgdisk','--info=2',str(image)],check=True,capture_output=True,text=True).stdout
sector=re.search(r'^First sector: (\d+) ',geometry,re.M)
if sector is None or "Partition name: 'luma-live-root'" not in geometry:
    raise SystemExit('unexpected installer root partition geometry')
offset=int(sector.group(1))*512
if not 1024*1024<=offset<image.stat().st_size-4096:
    raise SystemExit('root metadata offset outside image')
work.mkdir();corrupt=work/'corrupt.qcow2';target=work/'target.qcow2'
subprocess.run(['qemu-img','create','-f','qcow2','-F','raw','-b',str(image),str(corrupt)],check=True)
subprocess.run(['qemu-io','-f','qcow2','-c',f'write -P 85 {offset} 4096',str(corrupt)],check=True)
subprocess.run(['qemu-img','create','-f','qcow2',str(target),'32G'],check=True)
vm=VM(corrupt,work/'corrupt-root',target,True,600,media_format='qcow2')
try:
    vm.expect(rb'device-mapper: verity:[^\r\n]*data block 0 is corrupted',300)
    vm.expect(rb'Kernel panic',30)
    if vm.wait_exit(timeout=60)!=0:raise RuntimeError('corruption did not trigger bounded reboot')
finally:vm.close()
with image.open('rb') as stream:image_hash=hashlib.file_digest(stream,'sha256').hexdigest()
record={'result':'passed','stages':['dm-verity-corrupted-root-refusal-and-reboot'],'image_sha256':image_hash,
        'corrupted_image_offset':offset,'corrupted_bytes':4096,'acceleration':vm.acceleration,
        'secure_boot_tested':False,'physical_hardware_tested':False,'gate_closing':False,
        'original_image_modified':False,'installation_tested':False,'test_sources':TEST_SOURCES}
(work/'result.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record),flush=True)
