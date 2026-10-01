#!/usr/bin/env python3
"""Real QMP/PNG transport check, not an OS boot or desktop acceptance test."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'image'))
from vm_display import display_arguments, screenshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not Path('/.dockerenv').is_file() or output.parent != Path('/evidence') or output.exists():
        raise SystemExit('use a new directory directly beneath /evidence in a disposable container')
    output.mkdir()
    with tempfile.TemporaryDirectory(prefix='luma-display-') as sockets, \
            (output / 'qemu.log').open('wb') as log:
        socket_dir = Path(sockets)
        command = ['qemu-system-x86_64', '-no-user-config', '-nodefaults',
                   '-machine', 'q35,accel=tcg', '-m', '128', '-S', '-nic', 'none',
                   '-display', 'none', '-serial', 'none', '-monitor', 'none',
                   '-qmp', f'unix:{socket_dir}/qmp.sock,server=on,wait=off',
                   *display_arguments(True)]
        process = subprocess.Popen(command, stdout=log, stderr=log)
        vm = SimpleNamespace(work=output, socket_dir=socket_dir, deadline=time.monotonic()+30)
        try:
            while not (socket_dir / 'qmp.sock').exists():
                if process.poll() is not None or time.monotonic() >= vm.deadline:
                    raise RuntimeError('QEMU display fixture did not start')
                time.sleep(.05)
            screen = screenshot(vm, 'greeter')
            image = output / 'screen-greeter.png'
            record = {'result': 'passed', 'screenshot': screen,
                      'screenshot_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
                      'os_boot_tested': False, 'desktop_tested': False,
                      'physical_hardware_tested': False, 'gate_closing': False}
            (output / 'result.json').write_text(json.dumps(record, indent=2)+'\n')
            print(json.dumps(record), flush=True)
        finally:
            # This fixture deliberately never boots an OS; there is no guest
            # filesystem or shutdown claim. Only terminate our QEMU child.
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == '__main__':
    main()
