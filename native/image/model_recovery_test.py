#!/usr/bin/env python3
"""Additional offline recovery/integrity checks on a passed model VM overlay.

Preserves the original downloaded weights, installed disk and acquisition logs.
Does not relabel cached acquisition as a new installer/download evaluation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from vm_test import VM, TEST_SOURCES, installed_login
from model_vm_test import healthy, disable_from_recovery, reject_same_size_corruption, stage_timeout
from vm_shutdown import finish_stage


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def arguments(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',type=Path,required=True)
    p.add_argument('--base-run',type=Path,required=True)
    p.add_argument('--work',type=Path,required=True)
    p.add_argument('--secure-boot', action='store_true')
    p.add_argument('--accel', choices=('auto','kvm','tcg'), default='auto')
    p.add_argument('--require-clean-shutdown', action='store_true')
    p.add_argument('--timeout', type=stage_timeout, default=1200)
    return p.parse_args(argv)


def main():
    a=arguments();image=a.image.resolve(strict=True);base=a.base_run.resolve(strict=True);work=a.work.resolve()
    if not image.is_file() or not image.is_relative_to('/work/artifacts'):
        raise SystemExit('expected a generated image artifact')
    if base.parent!=Path('/work') or not base.name.startswith('vm-'):
        raise SystemExit('expected a retained generated model VM run')
    prior=json.loads((base/'result.json').read_text());image_hash=digest(image)
    if (prior.get('result')!='passed' or prior.get('image_sha256')!=image_hash
            or 'offline-reboot' not in prior.get('stages',[])
            or prior.get('model')!='qwen3-4b-q4-k-m'):
        raise SystemExit('base must have passed actual model acquisition/inference/offline boot')
    if work.parent!=Path('/work') or not work.name.startswith('vm-') or work.exists():
        raise SystemExit('use a fresh generated VM directory')
    backing=(base/'target.qcow2').resolve(strict=True)
    if not backing.is_file() or not backing.is_relative_to(base):raise SystemExit('invalid base disk')
    work.mkdir();target=work/'target.qcow2'
    subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(backing),str(target)],check=True)
    stages=[]
    for stage in ('independent-recovery-disable','manual-disabled-boot','same-size-corruption'):
        print('Model recovery stage: '+stage,flush=True)
        vm=VM(image,work/stage,target,stage=='independent-recovery-disable',a.timeout,
              secure_boot=a.secure_boot,acceleration=a.accel,memory_mib=6144)
        try:
            if stage=='independent-recovery-disable':disable_from_recovery(vm)
            else:
                installed_login(vm)
                vm.run('test -f /var/lib/luma-os/model-disabled')
                vm.run('test "$(systemctl is-active luma-model.service)" = inactive')
                vm.run('systemctl is-active luma-reference.service && luma-platform boot-health')
                if stage=='same-size-corruption':
                    vm.run('rm /var/lib/luma-os/model-disabled')
                    reject_same_size_corruption(vm)
                    vm.run('systemctl reset-failed luma-model.service && systemctl start luma-model.service')
                    healthy(vm)
            finish_stage(vm, require_clean=a.require_clean_shutdown, secure_boot=a.secure_boot)
            stages.append(stage)
        finally:vm.close()
    record={'result':'passed','stages':stages,'image_sha256':image_hash,
        'base_result_sha256':digest(base/'result.json'),'base_run':base.name,
        'original_fixture_modified':False,'network_enabled':False,
        'secure_boot_tested':a.secure_boot,'physical_hardware_tested':False,'gate_closing':False,
        'clean_shutdown_tested':a.require_clean_shutdown,'poweroff_stages':stages,
        'acceleration':vm.acceleration,'stage_timeout_seconds':a.timeout,
        'test_sources':TEST_SOURCES}
    (work/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True)


if __name__=='__main__':main()
