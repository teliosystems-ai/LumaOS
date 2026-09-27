#!/usr/bin/env python3
"""Validate the corrected loader pattern on an overlay of a failed fixture.

Diagnostic only: no gate or release acceptance record is emitted.
"""
import argparse
from pathlib import Path
import shlex
import shutil
import subprocess
from vm_test import VM, live_ready, failed_trial, fallback_ready

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
if not backing.is_file() or not backing.is_relative_to(base):raise SystemExit('invalid backing disk')
work.mkdir();target=work/'target.qcow2'
shutil.copyfile(base/'firmware.fd',work/'firmware.fd')
subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(backing),str(target)],check=True)
for name in ['setup','trial-1','trial-2','trial-3','fallback']:
    print('Diagnostic: '+name,flush=True)
    vm=VM(image,work/name,target,name=='setup',600)
    try:
        if name=='setup':
            live_ready(vm)
            vm.run('mkdir /tmp/esp && mount /dev/disk/by-id/virtio-LUMA-VM-TARGET-part1 /tmp/esp')
            code="from pathlib import Path; p=list(Path('/tmp/esp/EFI/Linux').glob('luma-a-*.efi')); assert len(p)==1; stem=p[0].stem.split('+')[0]; p[0].rename(p[0].with_name(stem+'+3.efi')); Path('/tmp/esp/loader/loader.conf').write_text('default '+stem+'+[1-3]*.efi\\ntimeout 3\\neditor no\\nauto-entries no\\n')"
            vm.run('python3 -c '+shlex.quote(code));vm.run('umount /tmp/esp && sync')
        elif name.startswith('trial-'):failed_trial(vm)
        else:fallback_ready(vm)
    finally:vm.close()
print('Corrected default pattern passed three trial reboots and good-slot fallback on this diagnostic overlay.',flush=True)
