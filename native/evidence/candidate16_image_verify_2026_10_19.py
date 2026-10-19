#!/usr/bin/env python3
"""Offline, source-bound candidate-16 laboratory image verification.

This is not installation, boot execution, production custody, installed
confinement, real-PAM workflow execution, or native hardware qualification.
All filesystem images stay read-only. No raw decompressed image is created.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

sys.dont_write_bytecode = True
MIB = 1024 ** 2
REPO, WORK, OUT, EVIDENCE = map(Path, ('/repo', '/work', '/out', '/evidence'))
RELEASE = 'luma-native-lab-20260927-desktop-16'
RAW, COMPRESSED = RELEASE + '.img', RELEASE + '.img.zst'
META = ('release.json', 'release.sig', 'secureboot.cer', 'packages.lock',
        'source-lock.json', 'toolchain-packages.lock', 'native-source.tar.zst', 'boot-policy.json')
EXPORTS = (COMPRESSED, 'SHA256SUMS', 'build.json', *META)
PAYLOAD_NAMES = {'root.ext4', 'root.verity', 'slot-a.efi', 'slot-b.efi',
                 'bootloader.efi', 'secureboot.cer', 'release.json', 'release.sig', 'packages.lock'}
REPORT = {'schema_version': 1, 'status': 'verification-in-progress',
          'release': RELEASE,
          'checks': [], 'qualification': {
              'image_boot_executed': False, 'installation_executed': False,
              'installed_enforcement_qualified': False, 'pam_or_product_grants_exercised': False,
              'restore_or_retirement_executed': False, 'physical_tpm_accessed': False,
              'production_custody_qualified': False, 'native_qualified': False,
              'g2_closed': False, 'gate_closing': False}}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON field')
        value[key] = item
    return value


def document(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_selected_mounts(build_id):
    """Check the selected names under the externally verified D-only daemon.

    No Docker socket/root/key volume is mounted. These kernel observations do
    not independently attest the host daemon or signing/physical custody.
    """
    with open('/proc/self/mountinfo', 'r', encoding='ascii') as stream:
        data = stream.read(MIB + 1)
    if len(data) > MIB:
        raise ValueError('kernel mount inventory exceeds the verifier bound')
    selected = {}
    for line in data.splitlines():
        left, separator, right = line.partition(' - ')
        fields, filesystem = left.split(), right.split()
        if not separator or len(fields) < 6 or len(filesystem) < 3:
            raise ValueError('kernel mount inventory is malformed')
        if fields[4] in ('/work', '/out', '/repo', '/evidence'):
            if fields[4] in selected:
                raise ValueError('selected verification mount is ambiguous')
            selected[fields[4]] = dict(mount_id=int(fields[0]), device=fields[2],
                root=fields[3], target=fields[4], options=fields[5].split(','),
                filesystem=filesystem[0], source=filesystem[1])
    if set(selected) != {'/work', '/out', '/repo', '/evidence'}:
        raise ValueError('all four exact verification mounts are required')
    work = selected['/work']
    volume = 'luma-native-build-' + build_id
    if (work['root'] != '/docker/volumes/' + volume + '/_data'
            or work['filesystem'] != 'ext4' or 'ro' not in work['options']):
        raise ValueError('work is not the exact selected read-only D-backed assembly volume')
    for name in ('/repo', '/evidence'):
        record = selected[name]
        if (record['filesystem'] != 'ext4' or record['source'] != work['source']
                or record['device'] != work['device']
                or ('ro' if name == '/repo' else 'rw') not in record['options']):
            raise ValueError('source/evidence differs from the selected actual ext4 build store')
    exported = selected['/out']
    if (exported['root'] != '/LumaOS-builds/native/' + build_id
            or 'ro' not in exported['options']):
        raise ValueError('exports are not the exact selected read-only public build directory')
    return dict(kernel_observations=selected, external_dedicated_daemon_preflight_required=True,
                host_daemon_self_attested=False, physical_storage_qualification=False)


def witness(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


class Held:
    def __init__(self):
        self.files = {}
        self.links = {}
        self.absent = {}

    @staticmethod
    def parents(path):
        result = []
        for parent in path.parents:
            value = parent.lstat()
            if not stat.S_ISDIR(value.st_mode):
                raise ValueError('verification refuses linked input ancestors')
            result.append((parent, witness(value)[:5]))
        return result

    def capture_link(self, path, target):
        path = Path(path)
        parents = self.parents(path)
        before = path.lstat()
        if (not stat.S_ISLNK(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or before.st_nlink != 1 or before.st_size != len(target.encode('ascii'))
                or os.readlink(path) != target):
            raise ValueError('a fixed image mask is not its exact owned symlink')
        fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if witness(os.fstat(fd)) != witness(before) or witness(path.lstat()) != witness(before):
                raise ValueError('a fixed image mask changed during capture')
            self.links[path] = (fd, witness(before), parents, target)
        except BaseException:
            os.close(fd)
            raise

    def require_absent(self, path):
        path = Path(path)
        parents = self.parents(path)
        try:
            path.lstat()
        except FileNotFoundError:
            self.absent[path] = parents
            return
        raise ValueError('an explicitly forbidden image member is present')

    def capture(self, path, maximum, aliases=None):
        path = Path(path)
        if aliases is None:
            aliases = (WORK / 'payload' / path.name,) if path.parent == WORK / 'artifacts' and path.name in PAYLOAD_NAMES else ()
        if path in self.files:
            if self.files[path][1][6] > maximum:
                raise ValueError('existing held file exceeds the requested bound')
            if self.files[path][3] != tuple(map(Path, aliases)):
                raise ValueError('an existing held member has a different alias plan')
            self.check_one(path)
            return path
        parents = []
        for parent in path.parents:
            value = parent.lstat()
            if not stat.S_ISDIR(value.st_mode):
                raise ValueError('verification refuses linked input ancestors')
            parents.append((parent, witness(value)[:5]))
        value = path.lstat()
        if not stat.S_ISREG(value.st_mode) or not 0 <= value.st_size <= maximum:
            raise ValueError('verification input is special or outside its file bound')
        if value.st_nlink != len(aliases) + 1:
            raise ValueError('verification input has undeclared hardlink aliases')
        for alias in aliases:
            if witness(Path(alias).lstat()) != witness(value):
                raise ValueError('reviewed artifact hardlink alias differs')
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        if witness(os.fstat(fd)) != witness(value):
            os.close(fd)
            raise ValueError('verification input changed during capture')
        self.files[path] = (fd, witness(value), parents, tuple(map(Path, aliases)))
        return path

    def bytes(self, path, maximum):
        self.capture(path, maximum)
        fd, expected, _, _ = self.files[Path(path)]
        data, offset = bytearray(), 0
        while offset <= maximum:
            block = os.pread(fd, min(65536, maximum + 1 - offset), offset)
            if not block:
                break
            data.extend(block)
            offset += len(block)
        if offset != expected[6] or offset > maximum:
            raise ValueError('bounded held input changed size')
        self.check_one(Path(path))
        return bytes(data)

    def hash(self, path):
        fd, expected, _, _ = self.files[Path(path)]
        value, offset = hashlib.sha256(), 0
        while offset < expected[6]:
            block = os.pread(fd, min(MIB, expected[6] - offset), offset)
            if not block:
                raise ValueError('held input was truncated')
            value.update(block)
            offset += len(block)
        if os.pread(fd, 1, offset):
            raise ValueError('held input grew')
        self.check_one(Path(path))
        return value.hexdigest()

    def check_one(self, path):
        fd, expected, parents, aliases = self.files[path]
        if witness(path.lstat()) != expected or witness(os.fstat(fd)) != expected:
            raise ValueError('a held verification input changed')
        for alias in aliases:
            if witness(alias.lstat()) != expected:
                raise ValueError('an exact artifact hardlink alias changed')
        for parent, before in parents:
            if witness(parent.lstat())[:5] != before:
                raise ValueError('a held input namespace changed')

    def check(self):
        for path in self.files:
            self.check_one(path)
        for path, (fd, before, parents, target) in self.links.items():
            if (witness(path.lstat()) != before or witness(os.fstat(fd)) != before
                    or os.readlink(path) != target):
                raise ValueError('a held fixed image mask changed')
            for parent, expected in parents:
                if witness(parent.lstat())[:5] != expected:
                    raise ValueError('a held fixed mask namespace changed')
        for path, parents in self.absent.items():
            for parent, expected in parents:
                if witness(parent.lstat())[:5] != expected:
                    raise ValueError('a held negative image namespace changed')
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            raise ValueError('an explicitly forbidden image member appeared')

    def close(self):
        for fd, _, _, _ in self.files.values():
            os.close(fd)
        for fd, _, _, _ in self.links.values():
            os.close(fd)


class Commands:
    def __init__(self, temporary):
        self.number = 0
        self.log_bytes = 0
        self.env = {'PATH': '/usr/bin:/usr/sbin:/bin', 'LANG': 'C.UTF-8',
                    'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
                    'SYSTEMD_LOG_LEVEL': 'err', 'TMPDIR': str(temporary)}

    def run(self, *arguments, timeout=300, fixture=False):
        self.number += 1
        if self.number > 512:
            raise ValueError('verification subprocess count exceeded its closed bound')
        env = dict(self.env)
        if fixture:
            # The 30-case fixture deliberately drops to nobody and makes its
            # own 0755 scratch directory. /tmp is the disposable D-backed
            # container layer, not host /tmp or the private evidence namespace.
            env['TMPDIR'] = '/tmp'
        child = subprocess.Popen(list(map(str, arguments)), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        output = {'stdout': bytearray(), 'stderr': bytearray()}
        deadline = time.monotonic() + timeout
        state, status = 'failed', None
        with selectors.DefaultSelector() as selector:
            for stream, label in ((child.stdout, 'stdout'), (child.stderr, 'stderr')):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError('verification subprocess exceeded its observation deadline')
                    for key, _ in selector.select(min(remaining, 1)):
                        block = os.read(key.fileobj.fileno(), 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        output[key.data].extend(block)
                        if len(output[key.data]) > 4 * MIB:
                            raise ValueError('verification subprocess exceeded its output bound')
                status = child.wait(timeout=max(.01, deadline - time.monotonic()))
                if status != 0:
                    raise ValueError('verification subprocess failed: ' + str(arguments[0]))
                state = 'passed'
                return bytes(output['stdout']), bytes(output['stderr'])
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait()
                child.stdout.close()
                child.stderr.close()
                log = dict(argv=list(map(str, arguments)), state=state,
                           exit_code=child.returncode, stdout=output['stdout'].decode('utf-8', 'replace'),
                           stderr=output['stderr'].decode('utf-8', 'replace'))
                self.log_bytes += len(output['stdout']) + len(output['stderr'])
                if self.log_bytes > 64 * MIB:
                    raise ValueError('cumulative verification diagnostic output exceeded its bound')
                write_json(EVIDENCE / ('command-%04d.json' % self.number), log, 9 * MIB)

    def text(self, *arguments, timeout=300):
        return self.run(*arguments, timeout=timeout)[0].decode('utf-8', 'strict')


def write_json(path, value, maximum=MIB):
    data = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')
    if len(data) > maximum:
        raise ValueError('bounded verification report exceeded its limit')
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def checked(label, details=None):
    REPORT['checks'].append(dict(name=label, passed=True, details=details))
    print('Verified: ' + label, flush=True)


def descriptors(raw, maximum_count):
    value = document(raw)
    if (type(value) is not dict or set(value) != {'schema_version', 'files'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or type(value['files']) is not list or not 1 <= len(value['files']) <= maximum_count):
        raise ValueError('source manifest is not its bounded closed schema')
    result, total = {}, 0
    for record in value['files']:
        if (type(record) is not dict or set(record) != {'path', 'bytes', 'sha256'}
                or not isinstance(record['path'], str) or len(record['path']) > 512
                or not re.fullmatch(r'[A-Za-z0-9_./+@\-]+', record['path'])
                or record['path'].startswith('/') or any(part in ('', '.', '..') for part in record['path'].split('/'))
                or type(record['bytes']) is not int or not 0 <= record['bytes'] <= 16 * MIB
                or not isinstance(record['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', record['sha256'])
                or record['path'] in result):
            raise ValueError('source descriptor is unsafe, duplicated or outside its bound')
        result[record['path']] = record
        total += record['bytes']
    if list(result) != sorted(result) or total > 64 * MIB:
        raise ValueError('source inventory order/total differs')
    return result


def module(name):
    spec = importlib.util.spec_from_file_location('candidate16_' + name, REPO / 'native/image' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def install_instance_template_extraction(resume):
    """Verifier-only compatibility for two already-signed unit drop-ins.

    The frozen resume module's general path grammar predates these instances.
    Delegate every ordinary path unchanged and extend only the exact two fixed
    image members; never modify the source, signed filesystem or generic API.
    """
    allowed = (
        '/etc/systemd/system/getty@tty1.service.d/luma-mode.conf',
        '/etc/systemd/system/serial-getty@ttyS0.service.d/luma-mode.conf',
    )
    original = resume.ext4_member_size

    def instance_member_size(image, source, maximum):
        if not isinstance(source, str):
            raise ValueError('unsafe fixed instance-template extraction path')
        if '@' not in source:
            return original(image, source, maximum)
        if source not in allowed or type(maximum) is not int or not 0 <= maximum <= 16 * MIB:
            raise ValueError('instance-template extraction is not its exact bounded allowlist')
        output = resume.run('debugfs', '-R', 'stat ' + source, image)
        if not isinstance(output, str):
            raise ValueError('instance-template ext4 observation is not text')
        size = re.search(r'\bSize:\s*([0-9]+)(?=\s|$)', output)
        if (not re.search(r'\bType:\s+regular(?=\s|$)', output) or not size
                or int(size[1]) > maximum or not re.search(r'\bLinks:\s*1(?=\s|$)', output)):
            raise ValueError('instance-template member is not a bounded, single-link regular file')
        return int(size[1])

    resume.ext4_member_size = instance_member_size
    return dict(profile='candidate16-fixed-instance-template-extraction-v1',
                exact_allowed_paths=list(allowed), ordinary_paths_delegated_unchanged=True,
                verifier_compatibility_only=True, signed_source_or_image_modified=False)


def stream_compressed(path, expected_size, expected_hash):
    child = subprocess.Popen(['zstd', '-dc', str(path)], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    value, total, errors = hashlib.sha256(), 0, bytearray()
    deadline = time.monotonic() + 3600
    with selectors.DefaultSelector() as selector:
        for stream, label in ((child.stdout, 'image'), (child.stderr, 'diagnostic')):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('decompression exceeded its observation deadline')
                for key, _ in selector.select(min(remaining, 1)):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == 'image':
                        total += len(block)
                        if total > expected_size:
                            raise ValueError('compressed image expanded beyond exact GPT geometry')
                        value.update(block)
                    else:
                        errors.extend(block)
                        if len(errors) > 65536:
                            raise ValueError('decompression diagnostics exceeded their bound')
            if child.wait(timeout=120) != 0 or total != expected_size or value.hexdigest() != expected_hash:
                raise ValueError('streamed decompression differs from exact raw size/hash')
            return dict(bytes=total, sha256=value.hexdigest(), raw_copy_written=False)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
            child.stdout.close()
            child.stderr.close()
            with (EVIDENCE / 'image-decompression.stderr').open('xb') as stream:
                stream.write(errors[:65536])
                stream.flush()
                os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-public-sha256', required=True)
    parser.add_argument('--pcr-public-sha256', required=True)
    parser.add_argument('--secureboot-cert-sha256', required=True)
    parser.add_argument('--frozen-source-sha256', required=True)
    parser.add_argument('--frozen-source-files', required=True, type=int)
    parser.add_argument('--build-id', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[a-f0-9]{64}', args.frozen_source_sha256) or not 1 <= args.frozen_source_files <= 4096:
        raise ValueError('explicit source SHA256 and bounded exact record count are required')
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-desktop', args.build_id):
        raise ValueError('select one exact timestamped desktop build identity')
    datetime.datetime.strptime(args.build_id, '%Y%m%dT%H%M%SZ-desktop')
    REPORT['source_pins'] = dict(sha256=args.frozen_source_sha256, files=args.frozen_source_files)
    REPORT['build_identity'] = dict(build_id=args.build_id, volume='luma-native-build-' + args.build_id,
        export_directory='D:/LumaOS-builds/native/' + args.build_id)
    if (os.name != 'posix' or os.geteuid() != 0 or os.uname().machine != 'x86_64'
            or not Path('/.dockerenv').is_file()
            or any(Path(name).exists() for name in ('/dev/tpm0', '/dev/tpmrm0', '/run/docker.sock', '/var/run/docker.sock', '/keys'))):
        raise ValueError('use only the isolated offline tools container without host devices/sockets/keys')
    for pin in (args.release_public_sha256, args.pcr_public_sha256, args.secureboot_cert_sha256):
        if not re.fullmatch('[a-f0-9]{64}', pin):
            raise ValueError('explicit current public-key/certificate SHA256 pins are required')
    evidence = EVIDENCE.lstat()
    if (not stat.S_ISDIR(evidence.st_mode) or evidence.st_uid != 0
            or evidence.st_mode & 0o077 or any(EVIDENCE.iterdir())):
        raise ValueError('use a new empty private root-owned evidence directory')
    held = Held()
    try:
        frozen_bytes = held.bytes(REPO / 'build-inputs.json', MIB)
        if digest(frozen_bytes) != args.frozen_source_sha256:
            raise ValueError('selected frozen candidate manifest differs from the explicitly selected tested cut')
        frozen = descriptors(frozen_bytes, 4096)
        if len(frozen) != args.frozen_source_files:
            raise ValueError('selected source inventory differs from its exact external record count')
        for name, record in frozen.items():
            path = held.capture(REPO / name, record['bytes'])
            if path.stat().st_size != record['bytes'] or held.hash(path) != record['sha256']:
                raise ValueError('a tested frozen source record differs')
        sys.path.insert(0, str(REPO / 'native/image'))
        resume = module('resume')
        for path in (REPO, WORK, OUT):
            resume.require_readonly(path)
        checked('exact-selected-build-volume-export-and-source-evidence-mount-identities',
                verify_selected_mounts(args.build_id))
        storage = module('assembly_storage')
        storage.require_ext4(EVIDENCE)
        if not resume.exact_mount(EVIDENCE):
            raise ValueError('evidence requires its exact private ext4 mount')
        temporary = EVIDENCE / 'temporary'
        temporary.mkdir(mode=0o700)
        os.environ['TMPDIR'] = str(temporary)
        tempfile.tempdir = str(temporary)
        commands = Commands(temporary)
        resume.ENV = dict(commands.env)
        resume.run = commands.text
        checked('verifier-only-two-fixed-instance-template-extraction-compatibility',
                install_instance_template_extraction(resume))
        checked('all-explicitly-selected-frozen-source-records-match')

        artifacts, root = WORK / 'artifacts', WORK / 'root'
        if set(path.name for path in OUT.iterdir()) != set(EXPORTS):
            raise ValueError('public export directory must contain exactly all eleven members')
        manifest = resume.parse_manifest(held.bytes(artifacts / 'release.json', MIB))
        if manifest['release'] != RELEASE or manifest['sequence'] != 16 or manifest['edition'] != 'desktop':
            raise ValueError('only the fresh desktop sequence16 laboratory candidate is accepted')
        build = document(held.bytes(artifacts / 'build.json', MIB))
        build_fields = {'status', 'release', 'kernel', 'edition', 'root_hash', 'image',
                        'image_sha256', 'source_lock_sha256', 'desktop', 'production_signed',
                        'gate_closing', 'custody_qualified', 'native_qualification_claimed'}
        if (set(build) != build_fields or build['status'] != 'built-not-yet-boot-tested'
                or build['release'] != RELEASE or build['edition'] != 'desktop' or build['image'] != RAW
                or build['root_hash'] != manifest['root_hash']
                or any(build[name] is not False for name in ('production_signed', 'gate_closing', 'custody_qualified', 'native_qualification_claimed'))
                or not re.fullmatch('[a-f0-9]{64}', build['image_sha256'])):
            raise ValueError('build record is not the closed honest fresh laboratory profile')
        sums_raw = held.bytes(artifacts / 'SHA256SUMS', 16384)
        sums = {}
        for line in sums_raw.decode('ascii').splitlines():
            match = re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9._-]+)', line)
            if not match or match[2] in sums:
                raise ValueError('checksum inventory is malformed or duplicated')
            sums[match[2]] = match[1]
        if set(sums) != {RAW, COMPRESSED, *META} or sums[RAW] != build['image_sha256']:
            raise ValueError('checksum inventory differs from the exact ten sealed members')
        _, raw_size = resume.layout('desktop')
        exports = []
        for name in EXPORTS:
            maximum = raw_size if name == COMPRESSED else 256 * MIB if name == 'native-source.tar.zst' else 16 * MIB
            original = held.capture(artifacts / name, maximum)
            exported = held.capture(OUT / name, maximum)
            sha = held.hash(original)
            if original.stat().st_size != exported.stat().st_size or held.hash(exported) != sha or (name in sums and sums[name] != sha):
                raise ValueError('an exported member differs from its sealed original/checksum')
            exports.append(dict(name=name, bytes=original.stat().st_size, sha256=sha))
        REPORT['exports'] = exports
        checked('eleven-public-exports-and-ten-checksum-rows')

        entries = descriptors(held.bytes(artifacts / 'source-lock.json', 16 * MIB), 4096)
        expected = {name: item for name, item in frozen.items() if not name.startswith('native/tests/')}
        if entries != expected or digest(held.bytes(artifacts / 'source-lock.json', 16 * MIB)) != build['source_lock_sha256']:
            raise ValueError('image product lock is not the exact tested product subset')
        retained_names = set()
        for directory, folders, files in os.walk(WORK / 'source', followlinks=False):
            for name in folders:
                if not stat.S_ISDIR((Path(directory) / name).lstat().st_mode):
                    raise ValueError('retained source includes a linked directory')
            for name in files:
                relative = (Path(directory) / name).relative_to(WORK / 'source').as_posix()
                if relative not in entries:
                    raise ValueError('retained source includes an undeclared member')
                retained_names.add(relative)
        if retained_names != set(entries):
            raise ValueError('retained source is incomplete')
        for name, record in entries.items():
            source = held.capture(WORK / 'source' / name, record['bytes'])
            if source.stat().st_size != record['bytes'] or held.hash(source) != record['sha256']:
                raise ValueError('assembly retained product source differs from tested source')
        resume.verify_compressed_source(artifacts / 'native-source.tar.zst', entries)
        checked('exact-tested-product-subset-and-complete-compressed-source-archive', {'product_records': len(entries)})

        signed_names = set(resume.SIGNED)
        for item in manifest['artifacts']:
            aliases = (WORK / 'payload' / item['name'],)
            path = held.capture(artifacts / item['name'], item['bytes'], aliases)
            if path.stat().st_size != item['bytes'] or held.hash(path) != item['sha256']:
                raise ValueError('signed release member differs from exact size/hash')
        if signed_names != {item['name'] for item in manifest['artifacts']}:
            raise ValueError('signed member inventory changed')
        raw_path = held.capture(artifacts / RAW, raw_size)
        if raw_path.stat().st_size != raw_size or held.hash(raw_path) != sums[RAW]:
            raise ValueError('raw disk size/hash differs from build record and closed geometry')
        checked('compressed-image-stream-equals-exact-raw-disk',
                stream_compressed(OUT / COMPRESSED, raw_size, sums[RAW]))
        partitions = resume.verify_gpt(raw_path, 'desktop')
        for name, size in (('esp.fat', partitions[0]['bytes']), ('payload.ext4', partitions[3]['bytes']),
                           ('slot-live.efi', 256 * MIB), ('loader.conf', 4096)):
            path = held.capture(artifacts / name, size)
            if name in ('esp.fat', 'payload.ext4') and path.stat().st_size != size:
                raise ValueError('partition filesystem size differs from closed layout')
        resume.verify_ranges(raw_path, [artifacts / name for name in ('esp.fat', 'root.ext4', 'root.verity', 'payload.ext4')], partitions)
        checked('primary-backup-GPT-partition-content-and-zero-slack')

        extracted = EVIDENCE / 'extracted'
        extracted.mkdir(mode=0o700)
        serial = 0
        def member(relative, maximum):
            nonlocal serial
            original = held.capture(root / relative, maximum)
            serial += 1
            target = extracted / ('member-%04d' % serial)
            resume.extract_ext4(artifacts / 'root.ext4', '/' + relative, target, maximum)
            held.capture(target, maximum)
            if target.stat().st_size != original.stat().st_size or held.hash(target) != held.hash(original):
                raise ValueError('actual signed-root member differs from retained root')
            return target

        public = member('usr/share/luma-os/release.pub', 16384)
        pcr = member('usr/share/luma-os/admin-pcr-public.pem', 16384)
        for path, wanted in ((public, args.release_public_sha256), (pcr, args.pcr_public_sha256),
                             (artifacts / 'secureboot.cer', args.secureboot_cert_sha256)):
            if held.hash(path) != wanted:
                raise ValueError('explicit independently supplied public pin differs')
        REPORT['public_pins'] = dict(release_public_sha256=args.release_public_sha256,
            pcr_public_sha256=args.pcr_public_sha256, secureboot_cert_sha256=args.secureboot_cert_sha256)
        commands.text('openssl', 'pkeyutl', '-verify', '-pubin', '-rawin', '-inkey', public,
                      '-in', artifacts / 'release.json', '-sigfile', artifacts / 'release.sig')
        commands.text('veritysetup', 'verify', artifacts / 'root.ext4', artifacts / 'root.verity', manifest['root_hash'], timeout=1800)
        identity = member('usr/share/luma-os/release-identity.json', 16384)
        release_id = member('usr/share/luma-os/release-id', 16384)
        resume.check_release_identity(held.bytes(identity, 16384), held.bytes(release_id, 16384), manifest)
        embedded_lock = member('usr/share/luma-os/source-lock.json', 16 * MIB)
        if held.bytes(embedded_lock, 16 * MIB) != held.bytes(artifacts / 'source-lock.json', 16 * MIB):
            raise ValueError('signed-root embedded source lock differs')
        certificate = extracted / 'secureboot.pem'
        commands.text('openssl', 'x509', '-inform', 'DER', '-in', artifacts / 'secureboot.cer', '-out', certificate)
        held.capture(certificate, 16384)
        if commands.text('openssl', 'x509', '-in', certificate, '-noout', '-subject', '-nameopt', 'RFC2253').strip() != 'subject=CN=Luma Native Laboratory Only':
            raise ValueError('Secure Boot certificate is not the laboratory profile')
        boot, shutdown, desktop = module('boot_policy'), module('shutdown_policy'), module('desktop_policy')
        def public_command(*arguments, **kwargs):
            if kwargs:
                raise ValueError('unexpected public verification subprocess options')
            return commands.run(*arguments, timeout=180)[0]
        boot.command = public_command
        shutdown.subprocess = SimpleNamespace(check_output=lambda argv, text=False:
            commands.text(*argv) if text else commands.run(*argv)[0])
        version = build['kernel']
        if not isinstance(version, str) or not re.fullmatch('[0-9][A-Za-z0-9.+_-]{0,95}', version):
            raise ValueError('build kernel identity exceeds its closed bound')
        kernel = member('boot/vmlinuz-' + version, 128 * MIB)
        initrd = member('boot/luma-initrd', 256 * MIB)
        initrd_policy = boot.verify_initrd(initrd)
        initrd_policy['shutdown'] = shutdown.verify_initrd(initrd)
        uki_records = []
        for slot in ('a', 'b', 'live'):
            image = artifacts / ('slot-' + slot + '.efi')
            uki_records.append(boot.verify_uki(image, slot, held.bytes(pcr, 16384), certificate))
            sections = boot.read_sections(image)
            mode = 'live' if slot == 'live' else 'installed'
            desktop.verify_boot_target(sections['.cmdline'], 'desktop', mode)
            data = 'luma-live-root' if slot == 'live' else 'luma-root-' + slot
            hashes = 'luma-live-hash' if slot == 'live' else 'luma-hash-' + slot
            wanted = (f"root=/dev/mapper/root ro roothash={manifest['root_hash']} "
                      'systemd.verity_root_options=panic-on-corruption '
                      f'systemd.verity_root_data=/dev/disk/by-partlabel/{data} '
                      f'systemd.verity_root_hash=/dev/disk/by-partlabel/{hashes} '
                      f'luma.mode={mode} luma.slot={slot} systemd.unit={desktop.target("desktop", mode)} '
                      'console=tty0 console=ttyS0,115200n8 apparmor=1 security=apparmor '
                      'systemd.show_status=yes rd.shell=0 panic=10').encode('ascii')
            osrel = f'ID=luma\nNAME="Luma Native Laboratory"\nVERSION_ID=16\nPRETTY_NAME="{RELEASE}"\n'.encode('ascii')
            if (sections['.cmdline'].rstrip(b'\0') != wanted
                    or digest(sections['.linux']) != held.hash(kernel)
                    or digest(sections['.initrd']) != held.hash(initrd)
                    or sections['.uname'].rstrip(b'\0') != version.encode('ascii')
                    or sections['.osrel'].rstrip(b'\0') != osrel):
                raise ValueError('measured UKI members differ from exact signed root/release')
        expected_boot = dict(schema_version=1, environment='lab', slots=uki_records,
                             initrd=initrd_policy, enrollment_active=False, gate_closing=False)
        if document(held.bytes(artifacts / 'boot-policy.json', MIB)) != expected_boot:
            raise ValueError('boot-policy metadata differs from actual public verification')
        commands.text('sbverify', '--cert', certificate, artifacts / 'bootloader.efi')
        checked('lab-release-signature-verity-and-three-measured-signed-UKIs')
        resume.verify_payload(artifacts, extracted)
        resume.verify_esp(artifacts, extracted)
        checked('exact-offline-payload-and-ESP-member-inventories-and-bytes')

        copied = {}
        prefix = 'native/image/overlay/'
        for name, record in entries.items():
            if name.startswith(prefix):
                copied[name[len(prefix):]] = record
        for name in ('workspace_host.py', 'workspace_auth.py', 'workspace_app.py', 'browser_adapter.py'):
            copied['usr/libexec/luma-os/' + name] = entries['native/desktop/' + name]
        for name in ('native-workspace.html', 'native-workspace.js', 'native-workspace.css'):
            copied['usr/share/luma-os/workspace/' + name] = entries['web/' + name]
        copied['usr/libexec/luma-os/utc-windows-front.py'] = entries['native/utc/windows_front.py']
        for relative, record in copied.items():
            actual = member(relative, record['bytes'])
            if actual.stat().st_size != record['bytes'] or held.hash(actual) != record['sha256']:
                raise ValueError('packaged native UI/policy differs from tested source')
        policy = member('usr/share/luma-os/content-custody-policy.json', 4096)
        if document(held.bytes(policy, 4096)) != {'schema_version': 1, 'authority': 'tpm-checkpoint-v1'}:
            raise ValueError('candidate policy does not require genuine content checkpoint authority')
        for relative in ('usr/share/applications/luma-workspace.desktop',
                         'usr/share/applications/luma-reference-workspace.desktop',
                         'usr/share/luma-os/adapters/office-pdf-v1.json',
                         'usr/share/luma-os/adapters/browser-presentation-v1.json',
                         'usr/share/luma-os/utc/windows-transport.json'):
            member(relative, MIB)
        browser_path = member('usr/share/luma-os/adapters/browser-presentation-v1.json', 65536)
        browser_bytes = held.bytes(browser_path, 65536)
        browser_policy = module('browser_policy')
        if browser_bytes != browser_policy.canonical_manifest(root):
            raise ValueError('browser manifest differs from the actual image-owned package/ELF/profile tuple')
        browser_spec = importlib.util.spec_from_file_location('candidate16_browser_runtime',
            REPO / 'native/desktop/browser_adapter.py')
        browser_runtime = importlib.util.module_from_spec(browser_spec)
        browser_spec.loader.exec_module(browser_runtime)
        browser_data = document(browser_bytes)
        browser = browser_runtime.runtime_manifest(browser_bytes, tuple(browser_data['runtime_version']))
        # Reuse the exact pure runtime parser/hash checks without pretending to
        # observe a loaded AppArmor DFA, WebKit process, or Wayland session.
        def protected_browser_bytes(path, maximum):
            actual = member(path.lstrip('/'), maximum)
            return held.bytes(actual, maximum)
        browser_runtime.verify_runtime_files(browser, protected_browser_bytes)
        profile = held.bytes(root / 'etc/apparmor.d/luma-workspace', 65536)
        active_lines = [line.strip() for line in profile.decode('utf-8').splitlines()
                        if line.strip() and not line.lstrip().startswith('#')]
        if active_lines != ['abi <abi/4.0>,', 'include <tunables/global>',
                'profile luma-workspace /usr/libexec/luma-os/luma-workspace-launch flags=(unconfined) {',
                'userns,', '}']:
            raise ValueError('workspace profile is not the exact fixed-ELF named userns compatibility policy')
        launcher_metadata = (root / 'usr/libexec/luma-os/luma-workspace-launch').lstat()
        if (not stat.S_ISREG(launcher_metadata.st_mode) or launcher_metadata.st_uid != 0
                or launcher_metadata.st_gid != 0 or launcher_metadata.st_nlink != 1
                or stat.S_IMODE(launcher_metadata.st_mode) != 0o755):
            raise ValueError('actual image launcher metadata differs from the fixed ordinary-user entry')
        for relative, mode in (('usr/libexec/luma-os/luma-workspace-launch', 0o755),
                               ('usr/libexec/luma-os/workspace_app.py', 0o644),
                               ('etc/apparmor.d/luma-workspace', 0o644)):
            inode = commands.text('debugfs', '-R', 'stat /' + relative, artifacts / 'root.ext4')
            image_mode = re.search(r'\bMode:\s*([0-7]{4})\b', inode)
            owners = re.search(r'\bUser:\s*([0-9]+)\s+Group:\s*([0-9]+)\b', inode)
            if ('Type: regular' not in inode or not image_mode or not owners
                    or int(image_mode[1], 8) != mode or owners.groups() != ('0', '0')
                    or not re.search(r'\bLinks:\s*1\b', inode)):
                raise ValueError('signed ext4 launcher/script/profile ownership/mode differs')
        checked('browser-v2-actual-image-library-fixed-ELF-launcher-and-profile-pins',
                dict(launcher=browser['launcher'], apparmor_profile=browser['apparmor_profile'],
                     expected_kernel_label=browser['apparmor_label'], loaded_profile_observed=False,
                     wayland_session_observed=False, webkit_userns_exercised=False,
                     profile_is_full_application_confinement=False, native_qualified=False))
        launcher = (root / 'usr/share/applications/luma-workspace.desktop').read_bytes()
        reference_launcher = (root / 'usr/share/applications/luma-reference-workspace.desktop').read_bytes()
        if (b'Exec=/usr/libexec/luma-os/luma-workspace-launch\n' not in launcher
                or b'TryExec=/usr/libexec/luma-os/luma-workspace-launch\n' not in launcher
                or b'http://' in launcher or b'NoDisplay=true\n' not in reference_launcher):
            raise ValueError('native launcher/reference separation differs')
        if resume.desktop_report(root, 'desktop', desktop) != build['desktop']:
            raise ValueError('desktop record differs from actual packaged profile')
        checked('packaged-native-UI-overlay-policies-and-native-primary-launcher', {'exact_source_members': len(copied)})

        # The package's qemu-kvm boot helper otherwise defaults to global KSM
        # preparation on bare metal. Verify only image-owned prevention data;
        # never execute the helper or inspect/change a host/guest sysfs knob.
        qemu_policy = module('qemu_policy')
        qemu_report = qemu_policy.validate(root)
        if type(qemu_report) is not dict:
            raise ValueError('required image QEMU policy did not return its validation report')
        expected_qemu_config = (b'# Luma: no ungoverned global memory sharing or QEMU boot preparation.\n'
                                b'KSM_ENABLED=0\nSLEEP_MILLISECS=200\n')
        qemu_config = member('etc/default/qemu-kvm', 4096)
        if qemu_policy.CONFIG != expected_qemu_config or held.bytes(qemu_config, 4096) != qemu_policy.CONFIG:
            raise ValueError('signed-root QEMU defaults do not contain the exact global-KSM refusal policy')
        held.capture_link(root / 'etc/systemd/system/qemu-kvm.service', '/dev/null')
        held.require_absent(root / 'etc/systemd/system/multi-user.target.wants/qemu-kvm.service')
        mask = commands.text('debugfs', '-R', 'stat /etc/systemd/system/qemu-kvm.service', artifacts / 'root.ext4')
        mask_owners = re.search(r'\bUser:\s*([0-9]+)\s+Group:\s*([0-9]+)\b', mask)
        if (not re.search(r'\bType:\s+symlink\b', mask)
                or not re.search(r'\bMode:\s*0777\b', mask)
                or not re.search(r'\bSize:\s*9\b', mask)
                or not re.search(r'\bLinks:\s*1\b', mask)
                or not mask_owners or mask_owners.groups() != ('0', '0')
                or not re.search(r'^Fast link dest: "/dev/null"$', mask, re.MULTILINE)):
            raise ValueError('actual signed ext4 QEMU helper mask is not the exact owned fast symlink to /dev/null')
        wanted_entries = resume.ext4_entries(artifacts / 'root.ext4', '/etc/systemd/system/multi-user.target.wants')
        if 'qemu-kvm.service' in wanted_entries:
            raise ValueError('actual signed ext4 still enables the global QEMU boot helper')
        member('usr/lib/systemd/system/qemu-kvm.service', 65536)
        qemu_binary = member('usr/bin/qemu-system-x86_64', 512 * MIB)
        qemu_header = os.pread(held.files[qemu_binary][0], 64, 0)
        if (len(qemu_header) != 64 or qemu_header[:7] != b'\x7fELF\x02\x01\x01'
                or int.from_bytes(qemu_header[16:18], 'little') not in (2, 3)
                or int.from_bytes(qemu_header[18:20], 'little') != 62
                or int.from_bytes(qemu_header[20:24], 'little') != 1):
            raise ValueError('retained signed-root QEMU is not the actual compiled x86-64 executable')
        checked('signed-root-QEMU-global-KSM-default-disabled-boot-helper-masked-and-not-enabled',
                dict(image_policy=qemu_report, qemu_executable_retained=True,
                     mask_target='/dev/null', multi_user_wanted_link_absent=True,
                     helper_executed=False, sysfs_written=False,
                     loaded_unit_or_kernel_KSM_state_observed=False,
                     native_boot_or_QEMU_qualified=False))

        packaged_binary = member('usr/libexec/luma-os/luma-platform', 64 * MIB)
        runtime = EVIDENCE / 'runtime'
        runtime.mkdir(mode=0o700)
        executable = runtime / 'luma-platform'
        with packaged_binary.open('rb') as source, executable.open('xb') as target:
            while block := source.read(MIB):
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
        executable.chmod(0o555)
        held.capture(executable, 64 * MIB)
        if held.hash(executable) != held.hash(packaged_binary):
            raise ValueError('controlled fixture executable differs from signed-root binary')
        REPORT['packaged_release_binary_sha256'] = held.hash(executable)
        _, stderr = commands.run('python3', '-I', '-B', REPO / 'native/tests/content_contract_cli.py',
                                  '--binary', executable, timeout=600, fixture=True)
        if not re.search(rb'\bRan 30 tests in ', stderr) or not re.search(rb'\nOK\s*$', stderr):
            raise ValueError('actual packaged CLI suite did not pass exactly30 with zero skips')
        stdout, _ = commands.run('python3', '-I', '-B', REPO / 'native/tests/test_workspace_workflow.py',
                                  '--native-cli', executable, timeout=300)
        workflow = document(stdout)
        if workflow.get('actual_native_engine_reopen_recalculation_cases') != 4:
            raise ValueError('actual packaged four-engine workflow fixture count differs')
        stdout, _ = commands.run('python3', '-I', '-B', REPO / 'native/tests/test_workspace_recovery.py',
                                  '--native-cli', executable, timeout=300)
        recovery = document(stdout)
        if recovery.get('actual_native_data_canonicalizers_checked') != 4:
            raise ValueError('actual packaged four recovery DATA canonicalizers count differs')
        REPORT['packaged_cli'] = dict(contract_tests_passed=30, workflow_data_cases=workflow,
                                      recovery_data_cases=recovery, zero_skips=True,
                                      installed_product_authority_exercised=False)
        checked('actual-packaged-release-binary-30CLI-4workflow-4recovery-DATA-fixtures')
        held.check()
        REPORT['status'] = 'candidate16-offline-image-and-export-verification-passed'
        REPORT['limitations'] = [
            'Public signature pins establish only this identified laboratory builder check, not production custody.',
            'No model weights are embedded or inference/QA executed by this verification.',
            'DATA fixtures do not exercise original PAM, grants, live C authority or installed AppArmor/cgroups.',
            'The exact named unconfined userns compatibility policy is packaged data, not proof of its loaded label or full application confinement.',
            'QEMU defaults/unit-mask checks are image data, not observations of loaded units or kernel KSM state.',
            'No boot, installation, real security/recovery, firmware, physical TPM or native certification was executed.',
            'Filesystem/kernel I/O and child reaping have no hard wall-clock completion guarantee.',
        ]
        write_json(EVIDENCE / 'verification.json', REPORT)
        print(json.dumps(REPORT, sort_keys=True), flush=True)
    except BaseException as error:
        REPORT['status'] = 'candidate16-offline-verification-failed'
        REPORT['error_type'] = type(error).__name__
        REPORT['error'] = str(error)[:4096]
        if not (EVIDENCE / 'verification.json').exists():
            write_json(EVIDENCE / 'verification.json', REPORT)
        raise
    finally:
        held.close()


if __name__ == '__main__':
    main()
