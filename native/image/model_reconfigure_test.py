#!/usr/bin/env python3
"""Install the smaller catalog profile after offline recovery, on an overlay.

Uses a passed full-suite fixture; neither repeats nor claims fresh OS installation.
Only the first stage has outbound NAT, and there are no guest port forwards.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from vm_test import VM, TEST_SOURCES, installed_login
from model_vm_test import healthy, infer

MODEL='qwen3-1-7b-q4-k-m'


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--base-run',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    a=parser.parse_args();image=a.image.resolve(strict=True);base=a.base_run.resolve(strict=True);work=a.work.resolve()
    if not image.is_file() or not image.is_relative_to('/work/artifacts'):
        raise SystemExit('expected generated image')
    if base.parent!=Path('/work') or not base.name.startswith('vm-'):
        raise SystemExit('expected generated base run')
    prior=json.loads((base/'result.json').read_text());image_hash=digest(image)
    if prior.get('result')!='passed' or prior.get('image_sha256')!=image_hash or prior.get('stages',[])[-1:]!=['repaired-a']:
        raise SystemExit('base must match a passing complete platform run')
    if work.parent!=Path('/work') or not work.name.startswith('vm-') or work.exists():
        raise SystemExit('use a fresh generated VM directory')
    backing=(base/'target.qcow2').resolve(strict=True)
    if not backing.is_file() or not backing.is_relative_to(base):raise SystemExit('invalid base disk')
    work.mkdir();target=work/'target.qcow2'
    subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(backing),str(target)],check=True)
    stages=[];inference=None;inferences=[]
    for stage in ('install-small-profile','offline-small-profile'):
        print('Model reconfiguration stage: '+stage,flush=True)
        vm=VM(image,work/stage,target,False,5400,network=stage=='install-small-profile')
        try:
            installed_login(vm);vm.run('luma-platform boot-health')
            vm.run('grep -Fx persistent-fixture /home/lumauser/recovery-test.txt')
            if stage=='install-small-profile':
                vm.run('test -f /var/lib/luma-os/model-disabled')
                vm.run('nmcli networking on && nm-online --timeout=60',timeout=90)
                vm.run('luma-platform model-install '+MODEL,timeout=3900)
                vm.run('test -f /var/lib/luma-os/model-disabled')
                vm.run('test "$(systemctl is-active luma-model.service)" = inactive')
                # Explicit operator re-enablement, never an automatic override.
                vm.run('rm /var/lib/luma-os/model-disabled && systemctl start luma-model.service')
            healthy(vm)
            vm.run('test "$(cat /sys/fs/cgroup/system.slice/luma-model.service/memory.max)" = 2684354560')
            inference=infer(vm,MODEL)
            inferences.append({'stage':stage,'response':inference})
            vm.run('luma-platform model-install not-a-catalog-model',expected=1)
            vm.run('systemctl is-active luma-model.service luma-reference.service')
            vm.run('sync');stages.append(stage)
        finally:vm.close()
    record={'result':'passed','stages':stages,'image_sha256':image_hash,
        'base_result_sha256':digest(base/'result.json'),'base_run':base.name,
        'model':MODEL,'guest_memory_mib':4096,'inference':inference,'inferences':inferences,
        'acquisition':'publisher-https-download-by-installed-native-model-command',
        'preseeded_weights':False,'recovery_disable_preserved_until_operator_enable':True,
        'original_fixture_modified':False,'secure_boot_tested':False,
        'physical_hardware_tested':False,'gate_closing':False,'test_sources':TEST_SOURCES}
    (work/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True)


if __name__=='__main__':main()
