#!/usr/bin/env python3
"""Exercise an actual signed update on an overlay of a passed VM fixture.

The original installed fixture and both distribution images stay unchanged.
Only generated image files in the explicitly mounted build volumes are accepted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
from vm_test import VM, TEST_SOURCES, installed_login


def image_hash(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--base-run',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    args=parser.parse_args()
    image=args.image.resolve(strict=True);candidate=args.candidate.resolve(strict=True)
    base=args.base_run.resolve(strict=True);work=args.work.resolve()
    if not image.is_file() or not image.is_relative_to('/work/artifacts'):
        raise SystemExit('base image must be a generated regular artifact')
    if not candidate.is_file() or not candidate.is_relative_to('/candidate/artifacts'):
        raise SystemExit('candidate must be a generated regular artifact in /candidate/artifacts')
    if base.parent!=Path('/work') or not base.name.startswith('vm-'):
        raise SystemExit('base must be a retained generated VM run')
    result=json.loads((base/'result.json').read_text())
    if result.get('result')!='passed' or result.get('stages',[])[-1:]!=['repaired-a']:
        raise SystemExit('base must have passed the full installer/recovery sequence')
    original_hash=image_hash(image)
    if result.get('image_sha256')!=original_hash:
        raise SystemExit('base fixture evidence does not match this image')
    if work.parent!=Path('/work') or not work.name.startswith('vm-') or work.exists():
        raise SystemExit('use a new /work/vm-* directory')
    original=json.loads((image.parent/'release.json').read_text())
    updated=json.loads((candidate.parent/'release.json').read_text())
    if updated['sequence']<=original['sequence']:
        raise SystemExit('candidate sequence must increase')
    backing=(base/'target.qcow2').resolve(strict=True)
    if not backing.is_file() or not backing.is_relative_to(base):
        raise SystemExit('base target must be a retained regular VM disk')
    work.mkdir();target=work/'target.qcow2'
    subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(backing),str(target)],check=True)
    stages=[]
    for name,media in [('stage-update',candidate),('updated',image)]:
        print('VM stage: '+name,flush=True)
        vm=VM(media,work/name,target,False,1800,attach_media=True)
        try:
            installed_login(vm)
            vm.run('luma-platform boot-health')
            vm.run('grep -Fx persistent-fixture /home/lumauser/recovery-test.txt')
            if name=='stage-update':
                vm.run('grep -qw luma.slot=a /proc/cmdline')
                vm.send('luma-platform update /media/luma')
                vm.action(b'Type exactly: UPDATE LUMA-VM-TARGET',900)
                vm.send('UPDATE LUMA-VM-TARGET')
                vm.action(b'Inactive slot staged for at most three trial boots.',900)
                vm.expect(rb'root@[^\r\n]*[#]')
                vm.run('test -f /var/lib/luma-os/pending.json')
            else:
                vm.run('grep -qw luma.slot=b /proc/cmdline')
                vm.run('grep -Fx '+shlex.quote(updated['release'])+' /usr/share/luma-os/release-id')
                check="import json; from pathlib import Path; m=json.loads(Path('/var/lib/luma-os/installed.json').read_text()); assert m['sequence']=="+str(updated['sequence'])
                vm.run('python3 -c '+shlex.quote(check))
                vm.run('test ! -e /var/lib/luma-os/pending.json')
                vm.run('test -f /var/lib/luma-os/model-disabled')
                vm.run('systemctl is-active luma-reference.service')
                vm.run('test "$(systemctl is-active luma-model.service)" = inactive')
                refusal=vm.run('luma-platform update /media/luma',expected=1,timeout=900)
                if b'update sequence must increase' not in refusal:
                    raise RuntimeError('older bundle was not rejected by sequence admission')
                vm.run('test ! -e /var/lib/luma-os/pending.json')
            vm.run('sync');stages.append(name)
        finally:vm.close()
    record={'result':'passed','stages':stages,'image_sha256':original_hash,
            'candidate_image_sha256':image_hash(candidate),'candidate_release':updated['release'],
            'acceleration':vm.acceleration,'secure_boot_tested':False,
            'physical_hardware_tested':False,'gate_closing':False,'test_sources':TEST_SOURCES,
            'observations':['inactive-slot update','encrypted data preserved','model-disable preserved',
                            'healthy trial acknowledged','pending transaction cleared','older sequence refused']}
    (work/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record),flush=True)


if __name__=='__main__':main()
