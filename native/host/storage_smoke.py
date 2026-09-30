#!/usr/bin/env python3
"""Actual Linux filesystem/persistence smoke in a dedicated disposable volume."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT = Path('/probe/luma-storage-smoke')
PAYLOAD = b'Luma D-backed storage fixture\n'*32768


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--create', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path('/.dockerenv').exists():
        raise RuntimeError('run inside the isolated disposable test container')
    if args.create:
        ROOT.mkdir(mode=0o700)
        with (ROOT/'payload').open('xb') as stream:
            stream.write(PAYLOAD)
            stream.flush()
            os.fsync(stream.fileno())
        (ROOT/'payload').chmod(0o600)
        os.setxattr(ROOT/'payload', 'user.luma-probe', b'ext4')
        os.link(ROOT/'payload', ROOT/'hardlink')
        (ROOT/'symlink').symlink_to('payload')
        os.mknod(ROOT/'null', stat.S_IFCHR | 0o600, os.makedev(1, 3))
        descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    expected = hashlib.sha256(PAYLOAD).hexdigest()
    assert hashlib.sha256((ROOT/'payload').read_bytes()).hexdigest() == expected
    assert (ROOT/'hardlink').stat().st_ino == (ROOT/'payload').stat().st_ino
    assert (ROOT/'symlink').readlink() == Path('payload')
    assert (ROOT/'payload').stat().st_mode & 0o777 == 0o600
    assert ROOT.stat().st_mode & 0o777 == 0o700
    assert os.getxattr(ROOT/'payload', 'user.luma-probe') == b'ext4'
    assert stat.S_ISCHR((ROOT/'null').stat().st_mode)
    with (ROOT/'null').open('wb') as stream:
        stream.write(b'local null-device probe')
    print(json.dumps({'result':'passed', 'created':args.create, 'payload_sha256':expected,
                      'hardlinks':True, 'symlinks':True, 'permissions':True,
                      'xattrs':True, 'device_nodes':True, 'file_directory_fsync':True}))


if __name__ == '__main__':
    main()
