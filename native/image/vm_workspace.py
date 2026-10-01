#!/usr/bin/env python3
"""Stage exact candidate media in a new Linux VM workspace; never repair disks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

MAX_IMAGE = 64 * 1024**3
HEADROOM = 36 * 1024**3  # One 32 GiB virtual target plus working reserve.


def regular(path, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        raise ValueError('expected bounded regular input: ' + path.name)
    return info


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate metadata field')
        result[key] = value
    return result


def bounded_bytes(path, limit):
    regular(path, limit)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError('metadata changed before open')
        data = stream.read(limit+1)
    if len(data) != info.st_size:
        raise ValueError('metadata changed size')
    return data


def copy_verified(source, target, expected, limit):
    """Retain failed partials, preserve zero regions, verify destination bytes."""
    before = regular(source, limit)
    partial = target.with_name(target.name + '.partial')
    if target.exists() or target.is_symlink() or partial.exists() or partial.is_symlink():
        raise ValueError('refusing to overwrite staged artifact')
    digest = hashlib.sha256()
    total = 0
    # Parent trees are operator-owned mounts, not an adversarial shared namespace.
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as src:
        opened = os.fstat(src.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValueError('source changed before open')
        descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as dst:
            while block := src.read(1024*1024):
                total += len(block)
                if total > before.st_size:
                    raise ValueError('source grew during copy')
                digest.update(block)
                if block.count(0) == len(block):
                    dst.seek(len(block), os.SEEK_CUR)
                else:
                    dst.write(block)
            after = os.fstat(src.fileno())
            if (total != before.st_size or digest.hexdigest() != expected
                    or (opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError('source identity/digest changed')
            dst.truncate(total)
            dst.flush()
            os.fsync(dst.fileno())
    with partial.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
            raise ValueError('staged artifact read-back digest mismatch')
    os.link(partial, target)  # Atomic no-replace publication on the Linux store.
    partial.unlink()
    return {'name': target.name, 'bytes': total, 'sha256': expected}


def prepare(source, work, expected_image, *, headroom=HEADROOM):
    if not re.fullmatch('[0-9a-f]{64}', expected_image):
        raise ValueError('pin the expected image SHA-256')
    if source.is_symlink() or work.is_symlink() or not source.is_dir() or not work.is_dir() or any(work.iterdir()):
        raise ValueError('use real input and empty workspace directories')
    metadata = bounded_bytes(source / 'build.json', 65536)
    build = json.loads(metadata, object_pairs_hook=object_pairs)
    if not isinstance(build, dict):
        raise ValueError('build record must be an object')
    name = build.get('image', '')
    if (not isinstance(name, str) or not re.fullmatch(r'luma-native-lab-[0-9]{8}-(headless|desktop)-[1-9][0-9]*\.img', name)
            or build.get('image_sha256') != expected_image):
        raise ValueError('build record does not match pinned candidate')
    hashes = {}
    for line in bounded_bytes(source / 'SHA256SUMS', 65536).decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})', line)
        if not match or match[2] in hashes:
            raise ValueError('invalid checksum inventory')
        hashes[match[2]] = match[1]
    if hashes.get(name) != expected_image or 'secureboot.cer' not in hashes:
        raise ValueError('candidate/certificate absent from checksum inventory')
    image = regular(source / name, MAX_IMAGE)
    regular(source / 'secureboot.cer', 65536)
    if shutil.disk_usage(work).free < image.st_size + headroom:
        raise ValueError('insufficient workspace capacity for media and fresh target')
    target = work / 'artifacts'
    target.mkdir(mode=0o700)
    records = []
    for filename, digest, limit in (
            ('build.json', hashlib.sha256(metadata).hexdigest(), 65536),
            ('secureboot.cer', hashes['secureboot.cer'], 65536),
            (name, expected_image, MAX_IMAGE)):
        records.append(copy_verified(source / filename, target / filename, digest, limit))
        print('Verified staged artifact: ' + filename, flush=True)
    # Revalidate metadata after copying too: it may not switch the expected image.
    staged = json.loads(bounded_bytes(target / 'build.json', 65536), object_pairs_hook=object_pairs)
    if staged != build:
        raise ValueError('build metadata changed while staging')
    record = {'result': 'prepared', 'image_sha256': expected_image, 'files': records,
              'image_tested': False, 'gate_closing': False}
    with (work / 'workspace.json').open('x') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    for directory in (target, work):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-image-sha256', required=True)
    args = parser.parse_args()
    if subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '-T', '/work'], text=True, timeout=10).strip() != 'ext4':
        raise SystemExit('VM workspace must be an explicit ext4 mount')
    print(json.dumps(prepare(Path('/input'), Path('/work'), args.expected_image_sha256)), flush=True)


if __name__ == '__main__':
    main()
