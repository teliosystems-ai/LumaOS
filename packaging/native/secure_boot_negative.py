#!/usr/bin/env python3
"""Require virtual UEFI to reject an unsigned copy of this build's bootloader."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
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
work.mkdir()
fat=work/'unsigned.fat'
# Derive the EFI filesystem from the distributed image itself. This also works
# on a separate Ubuntu machine without the builder's loose intermediates.
geometry=subprocess.run(['sgdisk','--info=1',str(image)],check=True,capture_output=True,text=True).stdout
first=re.search(r'^First sector: (\d+) ',geometry,re.M)
last=re.search(r'^Last sector: (\d+) ',geometry,re.M)
if first is None or last is None or "Partition name: 'LUMA-LIVE-ESP'" not in geometry:
    raise SystemExit('unexpected media EFI geometry')
offset=int(first.group(1))*512;size=(int(last.group(1))-int(first.group(1))+1)*512
if not 0<size<=2*1024**3 or offset<1024**2 or offset+size>image.stat().st_size:
    raise SystemExit('EFI partition outside accepted image bounds')
with image.open('rb') as src,fat.open('xb') as dst:
    src.seek(offset);remaining=size
    while remaining:
        block=src.read(min(remaining,1024**2))
        if not block:raise SystemExit('truncated EFI filesystem')
        if block.count(0)==len(block):dst.seek(len(block),1)
        else:dst.write(block)
        remaining-=len(block)
    dst.truncate(size)
unsigned=work/'unsigned.efi'
subprocess.run(['mcopy','-i',str(fat),'::/EFI/BOOT/BOOTX64.EFI',str(unsigned)],check=True)
shutil.copyfile(image.parent/'secureboot.cer',work/'secureboot.cer')
subprocess.run(['sbattach','--remove',str(unsigned)],check=True)
subprocess.run(['mcopy','-o','-i',str(fat),str(unsigned),'::/EFI/BOOT/BOOTX64.EFI'],check=True)
target=work/'target.qcow2'
subprocess.run(['qemu-img','create','-f','qcow2',str(target),'32G'],check=True)
vm=VM(fat,work/'unsigned-boot',target,True,300,True,'tcg')
try:
    vm.expect(rb'BdsDxe: failed to (?:load|start)[^\r\n]*(?:Access Denied|Security Violation)',240)
finally:vm.close()
with image.open('rb') as stream:image_hash=hashlib.file_digest(stream,'sha256').hexdigest()
record={'result':'passed','stages':['unsigned-efi-refusal'],'image_sha256':image_hash,
        'unsigned_bootloader_sha256':hashlib.sha256(unsigned.read_bytes()).hexdigest(),
        'secure_boot_tested':True,'acceleration':'tcg','physical_hardware_tested':False,
        'gate_closing':False,'installation_tested':False,'test_sources':TEST_SOURCES}
(work/'result.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record),flush=True)
