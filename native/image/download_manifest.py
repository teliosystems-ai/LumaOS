#!/usr/bin/env python3
"""Lay out one native download set and describe it; never signs, uploads or publishes.

Profile N (this module) and profile V (packaging/windows/Luma.HyperV.psm1,
ConvertFrom-LumaSha256Sums) share one download-verification shape. SHA256SUMS
holds one "<64 lowercase hex><two spaces><plain name>\\n" line per file. It
uses LF endings, is 68 bytes to 64 KiB long, and no name appears twice, even
ignoring case. The SHA-256 of that SHA256SUMS file is the single independent
pin. It must reach the tester through the repository record, never through
the download location: SHA256SUMS proves the files are intact, not where they
came from (origin_authenticated stays false).

Input is one completed export folder written by export.py, optionally with the
Hyper-V VHDX and its two records written by `hyperv_image.py export`. The
output is a NEW folder holding SHA256SUMS, download-manifest.json and
VERIFY.txt. With --copy, the payload is also copied there and read back, so the
folder is the whole download set. Without --copy, download-manifest.json names
the source path of every payload file.

The raw <release>.img row is listed although the raw image is not shipped by
default. It is what <release>.img.zst decompresses to, and it is the row the
export's own SHA256SUMS and build.json already carry. --verify-decompressed
proves that row by decompressing; --include-raw also ships the raw image.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

SCHEMA = 'luma-native-download-set-v1'
SUMS = 'SHA256SUMS'
MANIFEST = 'download-manifest.json'
VERIFY = 'VERIFY.txt'
SUMS_MIN, SUMS_MAX = 68, 65536
NAME = r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}'
# The same expression as Luma.HyperV.psm1 and vm_workspace.py. Python \Z is .NET \z.
SUMS_FILE = re.compile(rb'\A(?:[0-9a-f]{64}  ' + NAME.encode() + rb'\n)+\Z')
SUMS_LINE = re.compile(r'([0-9a-f]{64})  (' + NAME + r')')
IMAGE = re.compile(r'luma-native-lab-[0-9]{8}-(?:headless|desktop)-([1-9][0-9]*)\.img')
VHDX = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.vhdx')
COMMIT = re.compile(r'[0-9a-f]{40}')
HEX = re.compile(r'[0-9a-f]{64}')
MIB = 1024**2
MAX_MEDIA = 64 * 1024**3
MAX_RECORD = 16 * MIB
MAX_LOG = 1024**3
BLOCK = 4 * MIB
EXPORT_FIXED = ('SHA256SUMS', 'build.json', 'packages.lock', 'release.json', 'release.sig',
                'secureboot.cer', 'source-lock.json', 'toolchain-packages.lock',
                'native-source.tar.zst', 'boot-policy.json')
ROLES = {
    'build.json': 'build-record',
    'packages.lock': 'package-lock',
    'release.json': 'signed-release-record',
    'release.sig': 'release-record-signature',
    'secureboot.cer': 'secure-boot-db-certificate',
    'source-lock.json': 'source-lock',
    'toolchain-packages.lock': 'toolchain-package-lock',
    'native-source.tar.zst': 'corresponding-source-archive',
    'boot-policy.json': 'boot-policy',
    'optical-media.json': 'optical-build-record',
    'release-trust.json': 'production-trust-record',
    MANIFEST: 'download-manifest',
    VERIFY: 'verification-instructions',
}
OWNER_DECISIONS = (
    'publication-location: the owner chooses the HTTPS download location and uploads the set; agents never upload',
    'signing: SHA256SUMS is not signed; until the owner signs it with a key of their choice, the pin in the '
    'repository record is the only origin check',
    'secure-boot-trust: the lab secureboot.cer must be enrolled in the firmware db; Hyper-V templates refuse '
    'lab-signed media (shim, own shim or another hypervisor are owner options)',
    'raw-image: whether to also host the uncompressed .img for hosts without zstd',
)


class DownloadError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise DownloadError(message)


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def open_regular(path, limit):
    """Open a bounded regular file without following a final symlink."""
    path = Path(path)
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode), 'expected a regular file: ' + path.name)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
    stream = os.fdopen(descriptor, 'rb')
    try:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), 'file changed before open: ' + path.name)
        require(0 < opened.st_size <= limit, 'file empty or over its bound: ' + path.name)
        return stream, opened
    except BaseException:
        stream.close()
        raise


def hash_file(path, limit, copy_to=None):
    """Stream-hash one file; optionally copy it to a new file and verify the copy."""
    stream, before = open_regular(path, limit)
    digest = hashlib.sha256()
    total = 0
    with stream:
        target = None
        if copy_to is not None:
            target = _new_partial(copy_to)
        try:
            while block := stream.read(BLOCK):
                total += len(block)
                require(total <= before.st_size, 'file grew while reading: ' + Path(path).name)
                digest.update(block)
                if target is not None:
                    target.write(block)
            after = os.fstat(stream.fileno())
            require(total == before.st_size and (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns),
                    'file changed while reading: ' + Path(path).name)
            if target is not None:
                target.flush()
                os.fsync(target.fileno())
        finally:
            if target is not None:
                target.close()
    result = digest.hexdigest()
    if copy_to is not None:
        _publish_partial(copy_to, result, total)
    return total, result


def _partial(target):
    return Path(target).with_name(Path(target).name + '.partial')


def _new_partial(target):
    target = Path(target)
    require(not os.path.lexists(target) and not os.path.lexists(_partial(target)),
            'refusing to overwrite: ' + target.name)
    return _partial(target).open('xb')


def _publish_partial(target, expected, size):
    partial = _partial(target)
    verified_size, verified = hash_file(partial, max(size, 1))
    require((verified_size, verified) == (size, expected), 'copy read-back differs: ' + Path(target).name)
    require(not os.path.lexists(target), 'refusing to overwrite: ' + Path(target).name)
    os.rename(partial, target)


def bounded_json(path, limit=MAX_RECORD):
    stream, info = open_regular(path, limit)
    with stream:
        data = stream.read(limit + 1)
    require(len(data) == info.st_size, 'record changed size: ' + Path(path).name)
    try:
        value = json.loads(data, object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DownloadError('invalid JSON: ' + Path(path).name) from error
    require(isinstance(value, dict), 'record must be a JSON object: ' + Path(path).name)
    return value, data


def parse_sums(data):
    """Parse SHA256SUMS exactly as ConvertFrom-LumaSha256Sums does."""
    require(isinstance(data, bytes) and SUMS_MIN <= len(data) <= SUMS_MAX,
            'SHA256SUMS must hold at least one entry and at most 64 KiB')
    require(SUMS_FILE.fullmatch(data) is not None,
            'SHA256SUMS lines must be <64 lowercase hex><two spaces><plain file name> with LF endings')
    entries, folded = {}, set()
    for line in data.decode('ascii').splitlines():
        digest, name = SUMS_LINE.fullmatch(line).groups()
        require(name.lower() not in folded, 'SHA256SUMS lists a file name twice')
        folded.add(name.lower())
        entries[name] = digest
    return entries


def render_sums(entries):
    data = ''.join(f'{entries[name]}  {name}\n' for name in sorted(entries)).encode('ascii')
    require(parse_sums(data) == entries, 'SHA256SUMS rendering differs from its entries')
    return data


def export_names(build):
    """The exact inventory export.py writes for this build record."""
    image = build.get('image')
    require(isinstance(image, str) and IMAGE.fullmatch(image), 'build record image name differs')
    names = [image + '.zst', *EXPORT_FIXED]
    if 'optical' in build:
        optical = build['optical']
        require(isinstance(optical, dict) and optical.get('image') == build.get('release', '') + '.iso',
                'optical build identity differs')
        names += [optical['image'], 'optical-media.json']
    if build.get('production_signed') is True:
        names.append('release-trust.json')
    return names


def role(name, release):
    if name == release + '.img':
        return 'raw-disk-image-for-usb-and-vm-disk'
    if name == release + '.img.zst':
        return 'compressed-raw-disk-image'
    if name == release + '.iso':
        return 'vm-dvd-file-image'
    if name.endswith('.vhdx'):
        return 'hyperv-generation2-disk'
    if name.endswith('.vhdx.conversion.json'):
        return 'hyperv-conversion-record'
    if name.endswith('.vhdx.export.json'):
        return 'hyperv-export-receipt'
    return ROLES[name]


def read_export(export, sequence):
    """Check one completed export folder against its own records; return its rows."""
    export = Path(export)
    require(not export.is_symlink() and export.is_dir(), 'export must be a real directory')
    build, _ = bounded_json(export/'build.json', 65536)
    names = export_names(build)
    image = build['image']
    release = image[:-len('.img')]
    require(build.get('release') == release, 'build record release differs from its image name')
    require(IMAGE.fullmatch(image).group(1) == str(sequence), 'image sequence differs from --sequence')
    with os.scandir(export) as entries:
        present = sorted(entry.name for entry in entries)
    require(present == sorted(names), 'export inventory differs from export.py: '
            + ', '.join(sorted(set(present) ^ set(names))))
    stream, _ = open_regular(export/SUMS, SUMS_MAX)
    with stream:
        sums_bytes = stream.read(SUMS_MAX + 1)
    rows = parse_sums(sums_bytes)
    listed = (set(names) - {SUMS, 'build.json'}) | {image}
    require(set(rows) == listed, 'export SHA256SUMS lists a different file set')
    require(build.get('image_sha256') == rows[image], 'build record image hash differs from SHA256SUMS')
    if 'optical' in build:
        require(build['optical'].get('iso_sha256') == rows[release + '.iso'],
                'build record ISO hash differs from SHA256SUMS')
    release_record, _ = bounded_json(export/'release.json', 65536)
    require(release_record.get('release') == release and release_record.get('sequence') == sequence,
            'release record differs from --sequence or the build record')
    files = {}
    for name in names:
        if name == SUMS:
            continue
        limit = MAX_MEDIA if name.endswith(('.zst', '.iso')) else MAX_RECORD
        size, digest = hash_file(export/name, limit)
        if name != 'build.json':
            require(rows[name] == digest, 'export file differs from its SHA256SUMS row: ' + name)
        if name == release + '.iso' and 'iso_bytes' in build['optical']:
            require(build['optical']['iso_bytes'] == size, 'build record ISO size differs')
        files[name] = dict(bytes=size, sha256=digest, source=str(export/name))
    return dict(build=build, release=release, release_record=release_record, rows=rows, files=files,
                sums_sha256=hashlib.sha256(sums_bytes).hexdigest(), image=image)


def read_vhdx(vhdx, raw_sha256):
    """Check a Hyper-V export written by `hyperv_image.py export` against the raw image."""
    vhdx = Path(vhdx)
    require(VHDX.fullmatch(vhdx.name) is not None, 'VHDX name differs from hyperv_image.py export names')
    names = [vhdx.name + suffix for suffix in ('', '.conversion.json', '.export.json')]
    require(not os.path.lexists(vhdx.with_name(vhdx.name + '.failure.json')),
            'the Hyper-V export left a failure record')
    files = {}
    for name in names:
        size, digest = hash_file(vhdx.with_name(name), MAX_MEDIA if name == names[0] else 65536)
        files[name] = dict(bytes=size, sha256=digest, source=str(vhdx.with_name(name)))
    receipt, _ = bounded_json(vhdx.with_name(names[2]), 65536)
    conversion, _ = bounded_json(vhdx.with_name(names[1]), 65536)
    require(receipt.get('purpose') == 'luma-hyperv-public-export-v1' and receipt.get('output_name') == names[0]
            and receipt.get('output_sha256') == files[names[0]]['sha256']
            and receipt.get('output_bytes') == files[names[0]]['bytes']
            and receipt.get('conversion_name') == names[1]
            and receipt.get('conversion_sha256') == files[names[1]]['sha256']
            and receipt.get('source_raw_sha256') == raw_sha256, 'Hyper-V export receipt differs from its files')
    require(conversion.get('purpose') == 'luma-hyperv-live-installer-v1'
            and conversion.get('source_raw_sha256') == raw_sha256
            and conversion.get('output_sha256') == files[names[0]]['sha256'],
            'Hyper-V conversion record differs from the VHDX or the raw image')
    return files


def decompress(compressed, expected_bytes_limit, target=None, zstd='zstd'):
    """Hash what the .img.zst decompresses to; optionally write it to a new file."""
    executable = shutil.which(zstd)
    require(executable is not None, 'zstd is required to check the decompressed image')
    stream, _ = open_regular(compressed, MAX_MEDIA)
    digest, total = hashlib.sha256(), 0
    with stream:
        output = _new_partial(target) if target is not None else None
        try:
            with subprocess.Popen([executable, '-d', '-c', '-q'], stdin=stream, stdout=subprocess.PIPE) as process:
                while block := process.stdout.read(BLOCK):
                    total += len(block)
                    require(total <= expected_bytes_limit, 'decompressed image exceeds its bound')
                    digest.update(block)
                    if output is not None:
                        output.write(block)
                status = process.wait()
            require(status == 0, 'zstd failed to decompress the image')
            if output is not None:
                output.flush()
                os.fsync(output.fileno())
        finally:
            if output is not None:
                output.close()
    if target is not None:
        _publish_partial(target, digest.hexdigest(), total)
    return total, digest.hexdigest()


def verify_text(release, sequence, commit, names):
    """Plain instructions shipped in the set. The pin itself is never in the set."""
    image, compressed = release + '.img', release + '.img.zst'
    lines = [
        f'LumaOS native download set {release}',
        f'Sequence {sequence}, profile N, source commit {commit}.',
        '',
        'Nothing here is production-signed. SHA256SUMS proves that the files are intact,',
        'not where they came from. First compare the SHA-256 of SHA256SUMS with the pin',
        'in the LumaOS repository record for this release. Never take the pin from this',
        'folder or from the download location.',
        '',
        'Windows PowerShell, in this folder:',
        "  $pin = '<64-hex pin from the repository record>'",
        '  (Get-FileHash -Algorithm SHA256 -LiteralPath .\\SHA256SUMS).Hash.ToLowerInvariant() -ceq $pin',
        '  Get-Content -LiteralPath .\\SHA256SUMS | ForEach-Object {',
        "    $hash, $name = $_ -split '  ', 2",
        '    if (Test-Path -LiteralPath $name) {',
        '      $ok = (Get-FileHash -Algorithm SHA256 -LiteralPath $name).Hash.ToLowerInvariant() -ceq $hash',
        "      '{0} {1}' -f $(if ($ok) { 'OK    ' } else { 'FAILED' }), $name",
        "    } else { 'absent ' + $name }",
        '  }',
        'Every file you downloaded must print OK. The first command must print True.',
        '',
        'Linux, in this folder:',
        "  printf '%s  SHA256SUMS\\n' '<64-hex pin from the repository record>' | sha256sum --check -",
        '  sha256sum --check --ignore-missing SHA256SUMS',
        f'  zstd -d --keep {compressed}',
        '  sha256sum --check --ignore-missing SHA256SUMS',
        '',
        f'{image} is listed although it may not be shipped: it is what {compressed}',
        'decompresses to. The last check covers it once it exists. Write that raw',
        'image to a whole USB stick of 32 GB or more, or attach it to a VM as a raw disk.',
    ]
    if any(name.endswith('.iso') for name in names):
        lines += [f'{release}.iso is not hybrid: attach it to a VM as a DVD file only; it cannot be',
                  'written to a USB stick.']
    vhdx = [name for name in names if name.endswith('.vhdx')]
    if vhdx:
        lines += ['', 'Hyper-V (profile V) checks the same SHA256SUMS and pin itself:',
                  '  powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\\packaging\\windows\\plan-hyperv.ps1 `',
                  f'    -Sha256SumsPath .\\SHA256SUMS -Sha256SumsSha256 $pin -ImagePath .\\{vhdx[0]} -StorageDrive E']
    lines += ['', 'Secure Boot stays on. Enroll secureboot.cer in the firmware db. The full procedure',
              'is in the repository: native/evidence/NATIVE_DOWNLOAD_ACCEPTANCE_19_20_2026-11-03.md', '']
    return '\n'.join(lines).encode('ascii')


def write_new(path, data):
    with Path(path).open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def build_set(export, output, sequence, commit, cut, logs=(), vhdx=None, copy=False,
              verify_decompressed=False, include_raw=False, zstd='zstd'):
    require(isinstance(sequence, int) and sequence > 0, 'sequence must be a positive integer')
    require(COMMIT.fullmatch(commit or '') is not None, 'source commit must be 40 lowercase hex characters')
    require(re.fullmatch(NAME, cut or '') is not None, 'source cut must be a plain name')
    require(not include_raw or copy, '--include-raw needs --copy')
    output = Path(output)
    require(output.parent.is_dir() and not output.parent.is_symlink(), 'output parent must be an existing directory')
    require(not os.path.lexists(output), 'refusing an existing output folder')
    found = read_export(export, sequence)
    release, image = found['release'], found['image']
    raw_sha256 = found['rows'][image]
    build_logs = []
    for log in logs:
        size, digest = hash_file(log, MAX_LOG)
        build_logs.append(dict(path=str(log), bytes=size, sha256=digest))
    files = dict(found['files'])
    if vhdx is not None:
        added = read_vhdx(vhdx, raw_sha256)
        require(not set(added) & set(files), 'VHDX names collide with the export')
        files.update(added)
    output.mkdir()
    raw = dict(name=image, sha256=raw_sha256, shipped=include_raw, bytes=None,
               check='export-sha256sums-and-build-record-agree')
    if include_raw or verify_decompressed:
        limit = MAX_MEDIA
        size, digest = decompress(files[image + '.zst']['source'], limit,
                                  output/image if include_raw else None, zstd)
        require(digest == raw_sha256, 'decompressed image differs from its SHA256SUMS row')
        raw.update(bytes=size, check='decompressed-and-hashed')
    if copy:
        for name, entry in files.items():
            size, digest = hash_file(entry['source'], entry['bytes'], copy_to=output/name)
            require((size, digest) == (entry['bytes'], entry['sha256']), 'source changed while copying: ' + name)
    rows = {name: entry['sha256'] for name, entry in files.items()}
    rows[image] = raw_sha256
    verify = verify_text(release, sequence, commit, sorted(rows))
    write_new(output/VERIFY, verify)
    rows[VERIFY] = hashlib.sha256(verify).hexdigest()
    entries = [dict(name=name, role=role(name, release), bytes=entry['bytes'], sha256=entry['sha256'],
                    source=entry['source'], in_package=copy) for name, entry in sorted(files.items())]
    entries.append(dict(name=image, role=role(image, release), bytes=raw['bytes'], sha256=raw_sha256,
                        source=None, in_package=include_raw))
    entries.append(dict(name=VERIFY, role=role(VERIFY, release), bytes=len(verify), sha256=rows[VERIFY],
                        source=None, in_package=True))
    build = found['build']
    manifest = dict(
        schema_version=1, purpose=SCHEMA, profile='N', release=release, sequence=sequence,
        edition=found['release_record'].get('edition'), kernel=build.get('kernel'), root_hash=build.get('root_hash'),
        build_status=build.get('status'), production_signed=build.get('production_signed') is True,
        source=dict(commit=commit, cut=cut, source_lock_sha256=build.get('source_lock_sha256')),
        export=dict(directory=str(Path(export)), sha256sums_sha256=found['sums_sha256']),
        raw_image=raw, files=sorted(entries, key=lambda entry: entry['name']), build_logs=build_logs,
        sha256sums=dict(name=SUMS, format='luma-sha256sums-v1', listed=sorted([*rows, MANIFEST]),
                        independent_pin_required=True),
        payload_in_package=copy, signed=False, uploaded=False, published=False, origin_authenticated=False,
        boot_qualified=False, gate_closing=False, owner_decisions=list(OWNER_DECISIONS))
    data = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode('ascii')
    write_new(output/MANIFEST, data)
    rows[MANIFEST] = hashlib.sha256(data).hexdigest()
    sums = render_sums(rows)
    write_new(output/SUMS, sums)  # Last: a set without SHA256SUMS is visibly incomplete.
    return dict(release=release, sequence=sequence, output=str(output), sha256sums_sha256=hashlib.sha256(sums).hexdigest(),
                sha256sums_bytes=len(sums), files=len(rows), payload_in_package=copy, raw_image_check=raw['check'],
                signed=False, uploaded=False, origin_authenticated=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--export', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sequence', type=int, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--source-cut', required=True)
    parser.add_argument('--build-log', type=Path, action='append', default=[])
    parser.add_argument('--vhdx', type=Path)
    parser.add_argument('--copy', action='store_true')
    parser.add_argument('--verify-decompressed', action='store_true')
    parser.add_argument('--include-raw', action='store_true')
    args = parser.parse_args(argv)
    result = build_set(args.export, args.output, args.sequence, args.source_commit, args.source_cut,
                       args.build_log, args.vhdx, args.copy, args.verify_decompressed, args.include_raw)
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
