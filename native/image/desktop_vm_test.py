#!/usr/bin/env python3
"""Installed GNOME/Wayland greeter on fresh disposable virtual media.

Not password login, screen locking, graphical application workflow or physical
GPU qualification. All installer credentials are the public VM test fixtures.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

from model_vm_test import stage_timeout
from vm_display import screenshot
from vm_shutdown import finish_stage
from vm_test import VM, TEST_SOURCES, install, installed_login, live_ready


def verified_image(image):
    build = json.loads((image.parent / 'build.json').read_text())
    if build.get('edition') != 'desktop' or build.get('image') != image.name:
        raise ValueError('desktop fixture requires the exact declared desktop image')
    with image.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != build.get('image_sha256'):
        raise ValueError('desktop image does not match build digest')
    return digest


def greeter_result(output):
    records = [json.loads(line) for line in output.decode().splitlines()
               if line.startswith('{"desktop_greeter":')]
    if len(records) != 1:
        raise RuntimeError('expected one fresh greeter observation')
    record = records[0]
    expected = {'Name': 'gdm', 'Class': 'greeter', 'Type': 'wayland',
                'Remote': 'no', 'Active': 'yes', 'Seat': 'seat0',
                'Service': 'gdm-launch-environment'}
    if (record.get('desktop_greeter') != expected
            or record.get('user_login_tested') is not False
            or record.get('gate_closing') is not False):
        raise RuntimeError('wrong greeter/session identity or unsupported acceptance claim')
    return record


def observe_greeter(vm):
    # Query the real system logind, not a synthetic compositor/session. Every
    # subprocess and the overall polling loop is bounded. No session is created
    # by the probe, and no GDM configuration or authentication is bypassed.
    probe = '''import json, subprocess, time
required = {'Name':'gdm', 'Class':'greeter', 'Type':'wayland', 'Remote':'no',
            'Active':'yes', 'Seat':'seat0', 'Service':'gdm-launch-environment'}
deadline = time.monotonic()+600
while time.monotonic() < deadline:
    listing = subprocess.run(['loginctl','list-sessions','--no-legend','--no-pager'],
                             capture_output=True, text=True, check=True, timeout=10)
    matches = []
    for line in listing.stdout.splitlines()[:32]:
        if not line.strip(): continue
        identity = line.split()[0]
        if not identity.isalnum(): raise RuntimeError('unexpected session identity')
        result = subprocess.run(['loginctl','show-session',identity,'--no-pager'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode: continue
        properties = dict(row.split('=',1) for row in result.stdout.splitlines() if '=' in row)
        if all(properties.get(key) == value for key,value in required.items()):
            matches.append({key:properties[key] for key in required})
    if len(matches) == 1:
        print(json.dumps({'desktop_greeter':matches[0], 'user_login_tested':False,
                          'gate_closing':False}), flush=True)
        break
    if len(matches) > 1: raise RuntimeError('ambiguous active greeter')
    time.sleep(2)
else: raise RuntimeError('no active local Wayland GDM greeter')
'''
    return greeter_result(vm.run('python3 -c ' + shlex.quote(probe), timeout=650))


def desktop_checks(vm):
    installed_login(vm)
    vm.run('test "$(cat /usr/share/luma-os/desktop-profile)" = gnome-wayland-v1 && '
           'grep -qw systemd.unit=graphical.target /proc/cmdline && '
           'grep -qw luma.mode=installed /proc/cmdline')
    vm.run('luma-platform boot-health && systemctl is-active graphical.target gdm.service')
    vm.run('test "$(systemctl is-active luma-model.service)" = inactive')
    normal = observe_greeter(vm)
    screens = [screenshot(vm, 'greeter')]
    # Only the fresh VM's services are stopped. This checks the existing
    # greeter, not whether an interactive user can successfully authenticate.
    vm.run('systemctl stop luma-model.service luma-broker.service luma-reference.service')
    vm.run('test "$(systemctl is-active luma-model.service)" = inactive && '
           'test "$(systemctl is-active luma-broker.service)" = inactive && '
           'test "$(systemctl is-active luma-reference.service)" = inactive && '
           'systemctl is-active gdm.service')
    independent = observe_greeter(vm)
    screens.append(screenshot(vm, 'independent-greeter'))
    vm.run('systemctl start luma-broker.service luma-reference.service && luma-platform boot-health')
    return {'normal': normal, 'services_stopped': independent, 'screenshots': screens}


def diagnostics(vm):
    try:
        vm.run('systemctl show gdm.service -p ActiveState -p SubState -p Result; '
               'loginctl list-sessions --no-pager; '
               'journalctl -u gdm.service --no-pager -n 100; '
               'journalctl _COMM=gnome-shell --no-pager -n 100', timeout=30)
        return True
    except Exception:
        return False


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--timeout', type=stage_timeout, default=5400)
    parser.add_argument('--accel', choices=('auto', 'kvm', 'tcg'), default='auto')
    parser.add_argument('--secure-boot', action='store_true')
    parser.add_argument('--require-clean-shutdown', action='store_true')
    return parser.parse_args(argv)


def main():
    args = arguments()
    image = args.image.resolve(strict=True)
    work = args.work.resolve()
    if not image.is_file() or not image.is_relative_to('/work/artifacts'):
        raise SystemExit('only generated regular-file media under /work/artifacts is accepted')
    if work.parent != Path('/work') or not work.name.startswith('vm-') or work.exists():
        raise SystemExit('use a new /work/vm-* directory')
    image_hash = verified_image(image)
    work.mkdir()
    target = work / 'target.qcow2'
    subprocess.run(['qemu-img', 'create', '-f', 'qcow2', str(target), '32G'], check=True)
    stages = []
    observations = {}
    for stage in ('install', 'installed-greeter', 'cold-greeter'):
        print('Desktop VM stage: ' + stage, flush=True)
        vm = VM(image, work / stage, target, stage == 'install', args.timeout,
                secure_boot=args.secure_boot, acceleration=args.accel, graphical=True)
        try:
            if stage == 'install':
                live_ready(vm)
                vm.run('test "$(systemctl is-active gdm.service)" = inactive')
                install(vm)
            else:
                observations[stage] = desktop_checks(vm)
            finish_stage(vm, require_clean=args.require_clean_shutdown, secure_boot=args.secure_boot)
            stages.append(stage)
        except Exception as error:
            captured = diagnostics(vm) if stage != 'install' else False
            try:
                screenshot(vm, 'failure')
            except Exception:
                pass
            (work / 'failure.json').write_text(json.dumps({
                'result': 'failed', 'stage': stage, 'completed_stages': stages,
                'error_type': type(error).__name__, 'diagnostics_captured': captured,
                'test_sources': TEST_SOURCES, 'gate_closing': False,
            }, indent=2) + '\n')
            raise
        finally:
            vm.close()
    if verified_image(image) != image_hash:
        raise RuntimeError('image identity changed during evaluation')
    record = {'result': 'passed', 'stages': stages, 'observations': observations,
              'image_sha256': image_hash, 'acceleration': vm.acceleration,
              'display': 'virtio-vga-software', 'guest_memory_mib': 4096,
              'secure_boot_tested': args.secure_boot,
              'clean_shutdown_tested': args.require_clean_shutdown,
              'installed_wayland_greeter_tested': True, 'user_login_tested': False,
              'graphical_workflow_tested': False, 'screen_lock_tested': False,
              'physical_hardware_tested': False, 'gate_closing': False,
              'test_sources': TEST_SOURCES}
    (work / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record), flush=True)


if __name__ == '__main__':
    main()
