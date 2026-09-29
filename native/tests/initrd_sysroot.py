#!/usr/bin/env python3
"""Kernel-less initrd regression against a retained, read-only image root.

Run in a disposable tools container with its retained build volume at /work
(read-only), checkout at /repo (read-only), and a fresh evidence file under /out.
For a source repair, bind the candidate dracut module over the corresponding
/work/root module read-only. No host TPM, private key volume or privilege grant
is needed. This is not an OS boot test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
import boot_policy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path('/work/root')
    output = args.output.resolve()
    if (not Path('/.dockerenv').is_file() or not root.is_dir()
            or not os.statvfs(root).f_flag & os.ST_RDONLY):
        raise SystemExit('requires a disposable container and read-only /work/root')
    if not output.is_relative_to('/out') or output == Path('/out') or output.exists():
        raise SystemExit('choose a fresh evidence file beneath /out')
    if Path('/etc/udev/rules.d/99-luma-tpm.rules').exists():
        raise SystemExit('build-host rule would mask the sysroot-only regression')
    paths = ('etc/udev/rules.d/99-luma-tpm.rules',
             'usr/lib/dracut/modules.d/92luma-pcrphase/module-setup.sh')
    sources = {p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths}
    with tempfile.TemporaryDirectory(prefix='luma-sysroot-initrd-') as folder:
        initrd = Path(folder)/'initrd'
        subprocess.run(['dracut', '--sysroot', str(root), '--force', '--no-kernel',
                        '--tmpdir', '/tmp', '--no-hostonly', '--no-hostonly-cmdline',
                        '--no-compress', '--modules',
                        'systemd systemd-initrd luma-pcrphase', str(initrd)], check=True)
        policy = boot_policy.verify_initrd(initrd)
    record = {'result':'passed', 'kind':'kernel-less-sysroot-initrd',
              'policy':policy, 'sources':sources, 'os_boot_tested':False,
              'gate_closing':False,
              'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'verifier_sha256':hashlib.sha256(Path(boot_policy.__file__).read_bytes()).hexdigest()}
    with output.open('x') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n')
    print(json.dumps(record), flush=True)


if __name__ == '__main__':
    main()
