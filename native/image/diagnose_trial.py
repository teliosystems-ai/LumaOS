#!/usr/bin/env python3
"""Diagnostic only: boot an overlay of a retained failed VM fixture.

Never emits a passing qualification result; preserves the original target.
"""
import argparse
from pathlib import Path
import shutil
import subprocess
from vm_test import VM, DATA_PASSWORD

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--image',type=Path,required=True)
parser.add_argument('--base-run',type=Path,required=True)
parser.add_argument('--work',type=Path,required=True)
args=parser.parse_args()
image=args.image.resolve(strict=True);base=args.base_run.resolve(strict=True);work=args.work.resolve()
if not image.is_file() or not image.is_relative_to('/work/artifacts'):
    raise SystemExit('expected a generated image')
if base.parent!=Path('/work') or not base.name.startswith('vm-'):
    raise SystemExit('expected a retained VM fixture')
if work.parent!=Path('/work') or not work.name.startswith('vm-') or work.exists():
    raise SystemExit('expected a new VM diagnostic directory')
backing=(base/'target.qcow2').resolve(strict=True)
if not backing.is_file() or not backing.is_relative_to(base):
    raise SystemExit('expected a regular fixture disk')
work.mkdir();target=work/'target.qcow2'
shutil.copyfile(base/'firmware.fd',work/'firmware.fd')
subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(backing),str(target)],check=True)
vm=VM(image,work/'trial',target,False,600)
try:
    vm.expect(b'LUMA_DATA_UNLOCK: enter data or independent recovery passphrase:');vm.send(DATA_PASSWORD)
    vm.expect(rb'luma-platform: Is a directory')
    print('health failure observed; waiting for actual reboot',flush=True)
    print('guest exit code: '+str(vm.wait_exit()),flush=True)
finally:vm.close()
