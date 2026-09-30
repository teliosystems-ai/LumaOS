#!/usr/bin/env python3
"""Admission for the dedicated D:-backed WSL build daemon; no fallback to C:."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tomllib

STORE = Path('/mnt/luma-build')
BACKING = Path('/mnt/d/LumaOS-builds/docker/luma-build-v1.ext4')
SIZE = 96*1024**3
ENDPOINT = 'unix:///run/luma-build-docker.sock'
CONFIG = Path('/etc/luma-build/storage.json')


def command(*args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


def mount_info(path):
    record = json.loads(command('findmnt', '--json', '--target', str(path),
                                '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS'))
    entries = record.get('filesystems', [])
    if len(entries) != 1:
        raise ValueError('ambiguous build storage mount')
    return entries[0]


def validate_mount(record, backing):
    if (record.get('target') != str(STORE) or record.get('fstype') != 'ext4'
            or not re.fullmatch(r'/dev/loop[0-9]+', record.get('source', ''))
            or 'rw' not in record.get('options', '').split(',')
            or backing != str(BACKING)):
        raise ValueError('build store is not the expected writable D:-backed ext4 mount')


def profile():
    metadata = CONFIG.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o022 or metadata.st_size > 4096):
        raise ValueError('unsafe build storage profile')
    record = json.loads(CONFIG.read_text())
    if (set(record) != {'schema_version', 'uuid'} or record['schema_version'] != 1
            or not re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', record['uuid'])):
        raise ValueError('invalid build storage profile')
    return record


def verify_backing():
    outer = mount_info(BACKING)
    if outer['target'] != '/mnt/d' or outer['source'] != 'D:'+chr(92) or outer['fstype'] != '9p':
        raise ValueError('D: is not mounted at the expected WSL path')
    metadata = BACKING.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != SIZE:
        raise ValueError('build backing file was replaced or resized')


def verify_store():
    expected = profile()
    verify_backing()
    record = mount_info(STORE)
    device = record.get('source', '')
    if not re.fullmatch(r'/dev/loop[0-9]+', device):
        raise ValueError('build store is not mounted; refusing C: fallback')
    backing = (Path('/sys/class/block')/Path(device).name/'loop/backing_file').read_text().strip()
    validate_mount(record, backing)
    marker = STORE/'.luma-build-store.json'
    metadata = marker.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o022 or metadata.st_size > 4096
            or json.loads(marker.read_text()) != expected):
        raise ValueError('build-store identity marker mismatch')
    return expected


def mount_store():
    if os.geteuid() != 0:
        raise ValueError('mount requires WSL root')
    expected = profile()
    verify_backing()
    if STORE.is_symlink():
        raise ValueError('refusing linked store mountpoint')
    if STORE.is_mount():
        verify_store()
        return
    if STORE.exists() and any(STORE.iterdir()):
        raise ValueError('refusing to hide existing mountpoint contents')
    uuid = command('blkid', '-p', '-s', 'UUID', '-o', 'value', str(BACKING))
    if uuid != expected['uuid']:
        raise ValueError('backing filesystem UUID mismatch')
    STORE.mkdir(mode=0o755, exist_ok=True)
    subprocess.run(['mount', '-t', 'ext4', '-o', 'loop,noatime', str(BACKING), str(STORE)],
                   check=True, timeout=60)
    marker = STORE/'.luma-build-store.json'
    if not marker.exists() and not marker.is_symlink():
        if {p.name for p in STORE.iterdir()} - {'lost+found'}:
            raise ValueError('uninitialized store contains unexpected files')
        with marker.open('x') as stream:
            json.dump(expected, stream)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        marker.chmod(0o444)
    verify_store()


def validate_daemon(info):
    if info.get('DockerRootDir') != str(STORE/'docker') or info.get('Driver') != 'overlay2':
        raise ValueError('wrong Docker daemon/storage backend; refusing C: fallback')
    runtime = info.get('Containerd', {})
    if (runtime.get('Address') != '/run/luma-build-containerd/containerd.sock'
            or runtime.get('Namespaces', {}).get('Containers') != 'luma-build'):
        raise ValueError('shared/default containerd is not admitted for D-only builds')


def validate_runtime(record):
    # Ubuntu's containerd merges its default import glob even when imports=[]
    # is requested. Validate the effective configuration, not just our TOML.
    if (record.get('root') != str(STORE/'containerd')
            or record.get('state') != '/run/luma-build-containerd'
            or record.get('temp') != str(STORE/'tmp/containerd')
            or record.get('grpc', {}).get('address') != '/run/luma-build-containerd/containerd.sock'
            or not {'io.containerd.cri.v1.images', 'io.containerd.cri.v1.runtime'}.issubset(record.get('disabled_plugins', []))):
        raise ValueError('effective containerd configuration is not the dedicated D: profile')


def check_space(path, minimum_gib):
    free = shutil.disk_usage(path).free
    print(f'Build preflight: {path}: {free} free bytes; minimum {minimum_gib} GiB', flush=True)
    if free < minimum_gib*1024**3:
        raise ValueError('insufficient build headroom: '+str(path))


def preflight(repository, external, edition):
    if edition not in ('headless', 'desktop'):
        raise ValueError('unknown edition')
    desktop = edition == 'desktop'
    if os.environ.get('DOCKER_HOST') == ENDPOINT:
        verify_store()
        if os.environ.get('DOCKER_CONTEXT'):
            raise ValueError('DOCKER_CONTEXT overrides the dedicated daemon')
        validate_daemon(json.loads(command('docker', 'info', '--format', '{{json .}}')))
        validate_runtime(tomllib.loads(command('containerd', '--config', '/etc/luma-build/containerd.toml', 'config', 'dump')))
        for name in ('TMPDIR', 'DOCKER_CONFIG'):
            path = Path(os.environ.get(name, '/')).resolve(strict=True)
            if not path.is_relative_to(STORE) or not path.is_dir():
                raise ValueError(name+' must use the dedicated build store')
        if not external or Path(external).resolve() != Path('/mnt/d/LumaOS-builds'):
            raise ValueError('dedicated builds require D:/LumaOS-builds artifacts')
        check_space(STORE, 32 if desktop else 24)
        check_space(external, 60 if desktop else 40)
        print('Verified D:-backed Docker and temporary storage; no C: build-space reservation.', flush=True)
    else:
        check_space(repository, 8 if external else (24 if desktop else 16))
        if external:
            check_space(external, 60 if desktop else 40)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('mount', 'verify', 'preflight'))
    parser.add_argument('--repository', type=Path)
    parser.add_argument('--external', default='')
    parser.add_argument('--edition', choices=('headless', 'desktop'), default='headless')
    args = parser.parse_args()
    if args.action == 'mount':
        mount_store()
    elif args.action == 'verify':
        verify_store()
        print('Verified dedicated D:-backed ext4 store.')
    else:
        if not args.repository:
            parser.error('--repository is required for preflight')
        preflight(args.repository, args.external, args.edition)


if __name__ == '__main__':
    main()
