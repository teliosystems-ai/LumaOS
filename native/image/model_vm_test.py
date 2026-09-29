#!/usr/bin/env python3
"""Model download/install/inference on a fresh disposable VM disk.

Explicitly enables outbound guest networking for publisher HTTPS acquisition;
no guest port forwarding and no physical disk access. No weight is pre-seeded.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
from vm_test import VM, TEST_SOURCES, TARGET, RECOVERY_PASSWORD, install, installed_login, live_ready
from vm_shutdown import poweroff

MODEL='qwen3-4b-q4-k-m'
WEIGHT='/var/lib/luma-os/models/'+MODEL+'.gguf'


def inference_result(output, model):
    # Require this invocation's exact response; never reuse an earlier stage's
    # object when a resumed/offline request produced no result.
    records = [json.loads(line) for line in output.decode(errors='strict').splitlines()
               if line.startswith('{"model":')]
    if len(records) != 1:
        raise RuntimeError('expected exactly one fresh inference result')
    result = records[0]
    usage = result.get('usage')
    tokens = usage.get('completion_tokens') if isinstance(usage, dict) else None
    if (result.get('model') != model or type(tokens) is not int or tokens <= 0
            or not isinstance(result.get('text'), str) or not result['text'].strip()
            or result.get('effects_executed') is not False
            or result.get('certification_closing') is not False):
        raise RuntimeError('invalid model identity, completion or authority claim')
    return result


def infer(vm, model=MODEL):
    output = vm.run("printf 'Reply with a short greeting.' | luma-platform model-chat", timeout=240)
    return inference_result(output, model)


def healthy(vm):
    poll="import time,urllib.request,json; end=time.monotonic()+300\nwhile time.monotonic()<end:\n try:\n  r=json.load(urllib.request.urlopen('http://127.0.0.1:8081/health',timeout=3))\n  if r.get('status')=='ok': break\n except Exception: pass\n time.sleep(2)\nelse: raise RuntimeError('model health timeout')"
    vm.run('python3 -c '+shlex.quote(poll),timeout=330)
    vm.run('systemctl is-active luma-model.service luma-reference.service')
    vm.run('luma-platform boot-health')


def disable_from_recovery(vm):
    live_ready(vm)
    vm.send('luma-platform recover repair-data '+TARGET)
    vm.action(b'Type exactly: REPAIR-DATA LUMA-VM-TARGET');vm.send('REPAIR-DATA LUMA-VM-TARGET')
    vm.expect(b'Enter data or independent recovery passphrase:');vm.send(RECOVERY_PASSWORD)
    vm.action(b'Encrypted data filesystem checked/repaired without formatting.')
    vm.expect(rb'root@[^\r\n]*[#]')
    vm.send('luma-platform recover disable-model '+TARGET)
    vm.action(b'Type exactly: RECOVER LUMA-VM-TARGET');vm.send('RECOVER LUMA-VM-TARGET')
    vm.expect(b'Enter data or independent recovery passphrase:');vm.send(RECOVERY_PASSWORD)
    vm.action(b'Model disabled.');vm.expect(rb'root@[^\r\n]*[#]')


def reject_same_size_corruption(vm):
    vm.run('systemctl stop luma-model.service')
    mutate="from pathlib import Path; p=Path('"+WEIGHT+"'); f=p.open('r+b'); assert f.read(1)==b'G'; f.seek(0); f.write(b'X'); f.close()"
    vm.run('python3 -c '+shlex.quote(mutate))
    vm.run('systemctl reset-failed luma-model.service && systemctl start luma-model.service')
    refusal="import time,subprocess; end=time.monotonic()+120\nwhile time.monotonic()<end:\n r=subprocess.run(['journalctl','-u','luma-model.service','--no-pager'],capture_output=True)\n if b'model SHA-256 mismatch' in r.stdout: break\n time.sleep(2)\nelse: raise RuntimeError('same-size corrupt model was not refused')"
    vm.run('python3 -c '+shlex.quote(refusal),timeout=150)
    vm.run('systemctl stop luma-model.service')
    restore="from pathlib import Path; f=Path('"+WEIGHT+"').open('r+b'); f.write(b'G'); f.close()"
    vm.run('python3 -c '+shlex.quote(restore))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--secure-boot', action='store_true')
    parser.add_argument('--accel', choices=('auto', 'kvm', 'tcg'), default='auto')
    parser.add_argument('--require-clean-shutdown', action='store_true')
    args=parser.parse_args();image=args.image.resolve(strict=True);work=args.work.resolve()
    if not image.is_file() or not image.is_relative_to('/work/artifacts'):
        raise SystemExit('image must be a generated artifact')
    if work.parent!=Path('/work') or not work.name.startswith('vm-') or work.exists():
        raise SystemExit('use a new /work/vm-* directory')
    work.mkdir();target=work/'target.qcow2'
    subprocess.run(['qemu-img','create','-f','qcow2',str(target),'32G'],check=True)
    stages=[];inference=None;offline_inference=None
    for stage in ('model-install','model-inference','offline-reboot','recovery-disable','disabled-boot'):
        print('Model VM stage: '+stage,flush=True)
        vm=VM(image,work/stage,target,stage in ('model-install','recovery-disable'),5400,
              secure_boot=args.secure_boot,acceleration=args.accel,
              memory_mib=6144,network=stage=='model-install')
        try:
            if stage=='model-install':
                live_ready(vm)
                vm.run('ip -br link && nmcli device status && NetworkManager --print-config')
                vm.run('nmcli networking on && nm-online --timeout=60',timeout=90)
                install(vm,MODEL)
            elif stage=='recovery-disable':
                disable_from_recovery(vm)
            elif stage=='disabled-boot':
                installed_login(vm)
                vm.run('test -f /var/lib/luma-os/model-disabled')
                vm.run('test "$(systemctl is-active luma-model.service)" = inactive')
                vm.run('systemctl is-active luma-reference.service && luma-platform boot-health')
            else:
                installed_login(vm);healthy(vm)
                if stage=='model-inference':
                    vm.run('test "$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8081/v1/models)" = 401')
                    inference=infer(vm)
                    vm.run('test "$(cat /sys/fs/cgroup/system.slice/luma-model.service/memory.max)" = 4831838208')
                    vm.run('test "$(cat /sys/fs/cgroup/system.slice/luma-model.service/memory.swap.max)" = 0')
                    vm.run('test "$(cat /sys/fs/cgroup/system.slice/luma-model.service/pids.max)" = 64')
                    status=vm.run('pid=$(systemctl show --value -p MainPID luma-model.service); grep -E "^(NoNewPrivs:|Seccomp:|CapEff:)" /proc/$pid/status; cat /proc/$pid/attr/current')
                    for field,value in [(b'NoNewPrivs',b'1'),(b'Seccomp',b'2'),(b'CapEff',b'0000000000000000')]:
                        if not re.search(field+rb':\s*'+value+rb'\s',status):raise RuntimeError('missing model kernel restriction')
                    if b'luma-model (enforce)' not in status:raise RuntimeError('model AppArmor not enforced')
                    vm.run('runuser -u lumauser -- cat /var/lib/luma-os/model-auth/api-key',expected=1)
                    vm.run('systemctl stop luma-model.service && mv '+WEIGHT+' '+WEIGHT+'.test-retained && printf corrupt > '+WEIGHT)
                    vm.run('systemctl start luma-model.service')
                    refusal="import time,subprocess; end=time.monotonic()+25\nwhile time.monotonic()<end:\n if subprocess.run(['systemctl','is-active','--quiet','luma-model.service']).returncode: break\n time.sleep(1)\nelse: raise RuntimeError('corrupt model was not refused')"
                    vm.run('python3 -c '+shlex.quote(refusal))
                    vm.run('journalctl -u luma-model.service --no-pager | grep -F "model byte count mismatch"')
                    vm.run('systemctl stop luma-model.service && mv '+WEIGHT+'.test-retained '+WEIGHT)
                    reject_same_size_corruption(vm)
                    vm.run('touch /var/lib/luma-os/model-disabled && systemctl reset-failed luma-model.service && systemctl start luma-model.service')
                    vm.run('test "$(systemctl is-active luma-model.service)" = inactive')
                    vm.run('systemctl is-active luma-reference.service && luma-platform boot-health')
                    vm.run('rm /var/lib/luma-os/model-disabled && sync')
                else:
                    # A healthy listener alone is not offline inference.
                    offline_inference=infer(vm)
            if args.secure_boot:
                vm.run('test "$(od -An -tu1 -j4 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c | tr -d \' \\n\')" = 1')
            poweroff(vm, args.require_clean_shutdown)
            stages.append(stage)
        finally:vm.close()
    with image.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    record={'result':'passed','stages':stages,'image_sha256':digest,'model':MODEL,
        'acquisition':'publisher-https-download-by-native-installer','preseeded_weights':False,
        'inference':inference,'offline_inference':offline_inference,
        'guest_memory_mib':6144,'acceleration':vm.acceleration,
        'secure_boot_tested':args.secure_boot,'clean_shutdown_tested':args.require_clean_shutdown,
        'physical_hardware_tested':False,'gate_closing':False,'test_sources':TEST_SOURCES}
    (work/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True)


if __name__=='__main__':main()
