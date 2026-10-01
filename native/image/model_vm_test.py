#!/usr/bin/env python3
"""Model download/install/inference on a fresh disposable VM disk.

Explicitly enables outbound guest networking for publisher HTTPS acquisition;
no guest port forwarding and no physical disk access. No weight is pre-seeded.
"""
import argparse
import hashlib
import inspect
import json
import math
from pathlib import Path
import re
import shlex
import subprocess
import time
from vm_test import VM, TEST_SOURCES, TARGET, RECOVERY_PASSWORD, install, installed_login, live_ready
from vm_shutdown import poweroff

MODEL='qwen3-4b-q4-k-m'
MODEL_FIXTURES = {
    MODEL: (6144, 4831838208),
    'qwen3-1-7b-q4-k-m': (4096, 2684354560),
}


def model_fixture(model):
    # Deliberately closed test profiles; never turn an arbitrary CLI string
    # into a guest shell path or silently select a different/larger model.
    if not isinstance(model, str) or model not in MODEL_FIXTURES:
        raise ValueError('unsupported model evaluation profile')
    guest_mib, memory_max = MODEL_FIXTURES[model]
    return {'model': model, 'guest_memory_mib': guest_mib,
            'memory_max_bytes': memory_max,
            'weight': '/var/lib/luma-os/models/' + model + '.gguf'}


def verify_selected(vm, model):
    model_fixture(model)
    catalog = hashlib.sha256(Path(__file__).with_name('model-catalog.json').read_bytes()).hexdigest()
    vm.run("printf '%s\\n' '" + catalog + "  /usr/share/luma-os/model-catalog.json' | sha256sum -c -")
    probe = ("import json; selection=json.load(open('/var/lib/luma-os/model-selection.json')); "
             "assert selection == {'schema_version':1,'id':" + repr(model) + "}")
    vm.run('python3 -c ' + shlex.quote(probe))


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


def inference_budget(acceleration):
    # Emulation is functional evidence, not native performance qualification.
    # Keep both the generated token count and the real operation bounded.
    return (1800, 16) if acceleration == 'tcg' else (180, 128)


def infer(vm, model=MODEL, *, bounded=False):
    seconds, tokens = inference_budget(vm.acceleration) if bounded else (180, 128)
    command = "printf 'Reply with a short greeting.' | luma-platform model-chat"
    if bounded:
        command += f" --timeout-seconds {seconds} --max-tokens {tokens}"
    output = vm.run(command, timeout=seconds + 60)
    result = inference_result(output, model)
    if bounded:
        elapsed = result.get('elapsed_seconds')
        if (type(result.get('timeout_seconds')) is not int or result['timeout_seconds'] != seconds
                or type(result.get('max_tokens')) is not int or result['max_tokens'] != tokens
                or type(elapsed) not in (int, float) or not math.isfinite(elapsed)
                or not 0 <= elapsed <= seconds
                or result['usage']['completion_tokens'] > tokens):
            raise RuntimeError('inference result does not attest the selected bounded request')
    return result


def healthy(vm):
    poll="import time,urllib.request,json; end=time.monotonic()+300\nwhile time.monotonic()<end:\n try:\n  r=json.load(urllib.request.urlopen('http://127.0.0.1:8081/health',timeout=3))\n  if r.get('status')=='ok': break\n except Exception: pass\n time.sleep(2)\nelse: raise RuntimeError('model health timeout')"
    vm.run('python3 -c '+shlex.quote(poll),timeout=330)
    vm.run('systemctl is-active luma-model.service luma-reference.service')
    vm.run('luma-platform boot-health')


def failure_diagnostics(vm):
    # The fixture prompts and account passwords are already public. Never
    # print service Environment, model-selection credentials or the API key.
    # Capture runtime pressure/timing so a timeout is diagnosable, not merely
    # rerun with a larger deadline. Failure here cannot turn a test into a pass.
    try:
        vm.run('systemctl show luma-model.service -p ActiveState -p SubState '
               '-p Result -p MainPID -p MemoryCurrent -p CPUUsageNSec; '
               'journalctl -u luma-model.service --no-pager -n 120; '
               'for metric in memory.events memory.current memory.peak cpu.stat; do '
               'test ! -f /sys/fs/cgroup/system.slice/luma-model.service/$metric || '
               'cat /sys/fs/cgroup/system.slice/luma-model.service/$metric; done', timeout=30)
        return True
    except Exception:
        return False


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


def guest_refusal(message):
    # Executed inside the disposable guest. Old journal lines must never pass
    # a new corruption test, especially on overlays of earlier passing runs.
    if message not in ('model byte count mismatch', 'model SHA-256 mismatch'):
        raise ValueError('unknown refusal observation')
    deadline = time.monotonic() + 150

    def run(arguments):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('fresh model refusal deadline')
        return subprocess.run(arguments, check=True, capture_output=True, text=True,
                              timeout=min(remaining, 10)).stdout

    run(['journalctl', '--sync'])
    output = run(['journalctl', '-b', '-n', '1', '--show-cursor', '--no-pager', '-o', 'json'])
    cursors = [line[len('-- cursor: '):] for line in output.splitlines() if line.startswith('-- cursor: ')]
    if len(cursors) != 1 or not cursors[0] or len(cursors[0]) > 4096:
        raise RuntimeError('fresh journal cursor unavailable')
    cursor = cursors[0]
    run(['systemctl', 'reset-failed', 'luma-model.service'])
    run(['systemctl', 'start', 'luma-model.service'])
    while time.monotonic() < deadline:
        output = run(['journalctl', '-b', '-u', 'luma-model.service', '--after-cursor', cursor,
                      '--no-pager', '-n', '100', '-o', 'json'])
        if len(output) > 1024 * 1024:
            raise RuntimeError('model refusal journal exceeds bound')
        for line in output.splitlines():
            if not line.startswith('{'):
                continue
            entry = json.loads(line)
            if (entry.get('_SYSTEMD_UNIT') == 'luma-model.service'
                    and entry.get('MESSAGE') == 'luma-platform: ' + message
                    and isinstance(entry.get('__CURSOR'), str)
                    and entry['__CURSOR'] and entry['__CURSOR'] != cursor):
                return {'fresh_model_refusal': message, 'after_cursor': cursor,
                        'observed_cursor': entry['__CURSOR'], 'gate_closing': False}
        time.sleep(2)
    raise TimeoutError('no fresh model integrity refusal observed')


def start_expect_refusal(vm, message):
    if message not in ('model byte count mismatch', 'model SHA-256 mismatch'):
        raise ValueError('unknown refusal observation')
    probe = ('import json, subprocess, time\n' + inspect.getsource(guest_refusal) +
             '\nprint(json.dumps(guest_refusal(' + repr(message) + ')), flush=True)')
    output = vm.run('python3 -c ' + shlex.quote(probe), timeout=180)
    records = [json.loads(line) for line in output.decode().splitlines()
               if line.startswith('{"fresh_model_refusal":')]
    if (len(records) != 1 or records[0].get('fresh_model_refusal') != message
            or records[0].get('gate_closing') is not False
            or not isinstance(records[0].get('after_cursor'), str) or not records[0]['after_cursor']
            or not isinstance(records[0].get('observed_cursor'), str) or not records[0]['observed_cursor']
            or records[0]['observed_cursor'] == records[0]['after_cursor']):
        raise RuntimeError('invalid fresh model refusal observation')
    return records[0]


def reject_same_size_corruption(vm, model=MODEL):
    weight = model_fixture(model)['weight']
    vm.run('systemctl stop luma-model.service')
    mutate="from pathlib import Path; p=Path('"+weight+"'); f=p.open('r+b'); assert f.read(1)==b'G'; f.seek(0); f.write(b'X'); f.close()"
    vm.run('python3 -c '+shlex.quote(mutate))
    refusal = start_expect_refusal(vm, 'model SHA-256 mismatch')
    vm.run('systemctl stop luma-model.service')
    restore="from pathlib import Path; f=Path('"+weight+"').open('r+b'); f.write(b'G'); f.close()"
    vm.run('python3 -c '+shlex.quote(restore))
    return refusal


def stage_timeout(value):
    try:
        seconds = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError('timeout must be an integer number of seconds') from error
    if not 60 <= seconds <= 21600:
        raise argparse.ArgumentTypeError('timeout must be between 60 and 21600 seconds')
    return seconds


def arguments(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--model', choices=tuple(MODEL_FIXTURES), default=MODEL,
                        help='exact existing image-catalog profile; default remains Qwen3 4B')
    parser.add_argument('--secure-boot', action='store_true')
    parser.add_argument('--accel', choices=('auto', 'kvm', 'tcg'), default='auto')
    parser.add_argument('--require-clean-shutdown', action='store_true')
    parser.add_argument('--bounded-model-chat', action='store_true',
                        help='require new image CLI with whole-request/token budgets; not supported by sequence 10 or earlier')
    parser.add_argument('--timeout', type=stage_timeout, default=5400,
                        help='whole-stage deadline in seconds (60..21600; default: 5400)')
    return parser.parse_args(argv)


def main():
    args=arguments();image=args.image.resolve(strict=True);work=args.work.resolve()
    fixture = model_fixture(args.model)
    weight = fixture['weight']
    if not image.is_file() or not image.is_relative_to('/work/artifacts'):
        raise SystemExit('image must be a generated artifact')
    if work.parent!=Path('/work') or not work.name.startswith('vm-') or work.exists():
        raise SystemExit('use a new /work/vm-* directory')
    work.mkdir();target=work/'target.qcow2'
    subprocess.run(['qemu-img','create','-f','qcow2',str(target),'32G'],check=True)
    stages=[];inference=None;offline_inference=None;refusals=[]
    for stage in ('model-install','model-inference','offline-reboot','recovery-disable','disabled-boot'):
        print('Model VM stage: '+stage,flush=True)
        vm=VM(image,work/stage,target,stage in ('model-install','recovery-disable'),args.timeout,
              secure_boot=args.secure_boot,acceleration=args.accel,
              memory_mib=fixture['guest_memory_mib'],network=stage=='model-install')
        try:
            if stage=='model-install':
                live_ready(vm)
                vm.run('ip -br link && nmcli device status && NetworkManager --print-config')
                vm.run('nmcli networking on && nm-online --timeout=60',timeout=90)
                install(vm,args.model)
            elif stage=='recovery-disable':
                disable_from_recovery(vm)
            elif stage=='disabled-boot':
                installed_login(vm)
                verify_selected(vm, args.model)
                vm.run('test -f /var/lib/luma-os/model-disabled')
                vm.run('test "$(systemctl is-active luma-model.service)" = inactive')
                vm.run('systemctl is-active luma-reference.service && luma-platform boot-health')
            else:
                installed_login(vm);verify_selected(vm, args.model);healthy(vm)
                if stage=='model-inference':
                    vm.run('test "$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8081/v1/models)" = 401')
                    inference=infer(vm, args.model, bounded=args.bounded_model_chat)
                    vm.run('test "$(cat /sys/fs/cgroup/system.slice/luma-model.service/memory.max)" = '+str(fixture['memory_max_bytes']))
                    vm.run('test "$(cat /sys/fs/cgroup/system.slice/luma-model.service/memory.swap.max)" = 0')
                    vm.run('test "$(cat /sys/fs/cgroup/system.slice/luma-model.service/pids.max)" = 64')
                    status=vm.run('pid=$(systemctl show --value -p MainPID luma-model.service); grep -E "^(NoNewPrivs:|Seccomp:|CapEff:)" /proc/$pid/status; cat /proc/$pid/attr/current')
                    for field,value in [(b'NoNewPrivs',b'1'),(b'Seccomp',b'2'),(b'CapEff',b'0000000000000000')]:
                        if not re.search(field+rb':\s*'+value+rb'\s',status):raise RuntimeError('missing model kernel restriction')
                    if b'luma-model (enforce)' not in status:raise RuntimeError('model AppArmor not enforced')
                    vm.run('runuser -u lumauser -- cat /var/lib/luma-os/model-auth/api-key',expected=1)
                    vm.run('systemctl stop luma-model.service && mv '+weight+' '+weight+'.test-retained && printf corrupt > '+weight)
                    refusals.append(start_expect_refusal(vm, 'model byte count mismatch'))
                    vm.run('systemctl stop luma-model.service && mv '+weight+'.test-retained '+weight)
                    refusals.append(reject_same_size_corruption(vm, args.model))
                    vm.run('touch /var/lib/luma-os/model-disabled && systemctl reset-failed luma-model.service && systemctl start luma-model.service')
                    vm.run('test "$(systemctl is-active luma-model.service)" = inactive')
                    vm.run('systemctl is-active luma-reference.service && luma-platform boot-health')
                    vm.run('rm /var/lib/luma-os/model-disabled && sync')
                else:
                    # A healthy listener alone is not offline inference.
                    offline_inference=infer(vm, args.model, bounded=args.bounded_model_chat)
            if args.secure_boot:
                vm.run('test "$(od -An -tu1 -j4 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c | tr -d \' \\n\')" = 1')
            poweroff(vm, args.require_clean_shutdown)
            stages.append(stage)
        except Exception as error:
            captured = failure_diagnostics(vm) if stage in ('model-inference', 'offline-reboot') else False
            # A failed run intentionally has no result.json. Keep the exact
            # failed stage and selected bounds separate from passed evidence.
            failure = {'result':'failed', 'stage':stage, 'completed_stages':stages,
                'error_type':type(error).__name__, 'runtime_diagnostics_captured':captured,
                'bounded_model_chat':args.bounded_model_chat, 'acceleration':vm.acceleration,
                'model':args.model, 'fixture':fixture,
                'gate_closing':False, 'test_sources':TEST_SOURCES}
            (work/'failure.json').write_text(json.dumps(failure,indent=2)+'\n')
            raise
        finally:vm.close()
    with image.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    record={'result':'passed','stages':stages,'image_sha256':digest,'model':args.model,
        'acquisition':'publisher-https-download-by-native-installer','preseeded_weights':False,
        'inference':inference,'offline_inference':offline_inference,
        'guest_memory_mib':fixture['guest_memory_mib'],'acceleration':vm.acceleration,
        'fixture':fixture,
        'fresh_integrity_refusals':refusals,
        'catalog_sha256':hashlib.sha256(Path(__file__).with_name('model-catalog.json').read_bytes()).hexdigest(),
        'stage_timeout_seconds':args.timeout,
        'bounded_model_chat':args.bounded_model_chat,
        'inference_budget':dict(zip(('timeout_seconds','max_tokens'),
            inference_budget(vm.acceleration) if args.bounded_model_chat else (180, 128))),
        'secure_boot_tested':args.secure_boot,'clean_shutdown_tested':args.require_clean_shutdown,
        'physical_hardware_tested':False,'gate_closing':False,'test_sources':TEST_SOURCES}
    (work/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True)


if __name__=='__main__':main()
