"""Unprivileged terminal bridge to the existing native PAM/grant ceremony.

No password, private result, grant issuance or content authority enters WebKit.
Launching a terminal is not a successful authentication/publication receipt.
The terminal child owns a tiny inert staging file until its native command exits;
no GNOME Console early-return/DBus handoff is mistaken for command completion.
"""
from __future__ import annotations

import json
import hashlib
import importlib.util
import itertools
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import uuid

MAX_REQUEST = 16 * 1024 * 1024 + 32768
MAX_STAGE = MAX_REQUEST * 6 + 16384
HELPER = '/usr/libexec/luma-os/workspace_auth.py'
NATIVE = '/usr/libexec/luma-os/luma-platform'


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def strict_json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError('duplicate bridge field')
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite bridge JSON')))


def proposal(value):
    fields = {'schema_version', 'operation', 'login', 'read_grant', 'effect_grant', 'approval', 'request'}
    if isinstance(value, dict) and value.get('operation') == 'office-export':
        fields.add('output_path')
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('closed terminal bridge fields required')
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('invalid terminal bridge version')
    if not isinstance(value['login'], str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', value['login']):
        raise ValueError('invalid native human login')
    for field in ('read_grant', 'effect_grant'):
        if not isinstance(value[field], str) or (value[field] and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value[field])):
            raise ValueError('invalid finite grant identifier')
    operation = value['operation']
    if operation in ('inspection', 'office-proposal'):
        if any(value[field] for field in ('read_grant', 'effect_grant', 'approval')):
            raise ValueError('inspection cannot select effect authority')
    elif operation == 'review':
        if not value['read_grant'] or value['effect_grant'] or value['approval']:
            raise ValueError('review requires only its exact finite Read grant')
    elif operation == 'office-export':
        if not value['read_grant'] or not value['effect_grant'] or value['read_grant'] == value['effect_grant'] or value['approval']:
            raise ValueError('Office requires only exact independent Read and Export grants')
        path = value['output_path']
        if not isinstance(path, str) or not Path(path).is_absolute() or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,123}\.pdf', Path(path).name):
            raise ValueError('Office export requires an explicit new bounded PDF filename')
    elif operation == 'apply':
        if not value['read_grant'] or not value['effect_grant'] or not isinstance(value['approval'], str) or not re.fullmatch(r'(?:write|retain|recover):[0-9a-f]{64}', value['approval']):
            raise ValueError('apply requires exact Read/effect grants and reviewed approval')
    else:
        raise ValueError('unsupported authenticated terminal operation')
    request = value['request']
    if not isinstance(request, str) or not 0 < len(request.encode('utf-8')) <= MAX_REQUEST:
        raise ValueError('native request exceeds bound')
    source = strict_json(request)
    if not isinstance(source, dict) or source.get('login') != value['login']:
        raise ValueError('request and original human login differ')
    return value


def runtime():
    uid = os.getuid()
    if uid < 1000 or uid >= 65534 or os.geteuid() != uid:
        raise ValueError('ordinary installed interactive account required')
    base = Path('/run/user') / str(uid)
    if os.environ.get('XDG_RUNTIME_DIR') != str(base) or base.resolve(strict=True) != base:
        raise ValueError('fixed installed private runtime required')
    metadata = base.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError('unsafe interactive runtime metadata')
    path = base / 'luma-terminal-proposals'
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != 0o700 or path.resolve(strict=True) != path:
        raise ValueError('unsafe terminal proposal directory')
    return path


def protected(path, maximum, *, sudo=False):
    path = Path(path)
    if path.resolve(strict=True) != path:
        raise ValueError('bridge dependency alias refused')
    for ancestor in path.parents:
        value = ancestor.stat()
        if value.st_uid != 0 or not stat.S_ISDIR(value.st_mode) or value.st_mode & 0o022:
            raise ValueError('unprotected bridge dependency ancestor')
    value = path.stat()
    forbidden = 0o3022 if sudo and str(path) == '/usr/bin/sudo' else 0o7022
    if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_nlink != 1 or value.st_mode & forbidden or not 0 < value.st_size <= maximum:
        raise ValueError('unprotected or oversized bridge dependency')


def terminal_arguments(value, path):
    value = proposal(value)
    prefix = ['/usr/bin/sudo', '--', NATIVE, 'granted-run']
    if value['operation'] == 'office-proposal':
        return prefix + ['content-office-export-proposal', value['login'], str(path)]
    if value['operation'] == 'office-export':
        return prefix + ['content-office-export', value['login'], value['read_grant'], value['effect_grant'], str(path)]
    if value['operation'] == 'inspection':
        return prefix + ['content-owned-inspection-review', value['login'], str(path)]
    if value['operation'] == 'review':
        return prefix + ['content-owned-review', value['login'], value['read_grant'], str(path)]
    return prefix + ['content-owned-apply', value['login'], value['read_grant'], value['effect_grant'], value['approval'], str(path)]


def launch(value):
    value = proposal(value)
    directory = runtime()
    for path, maximum in [(HELPER, 128 * 1024), (NATIVE, 128 * 1024 * 1024), ('/usr/bin/kgx', 16 * 1024 * 1024), ('/usr/bin/sudo', 16 * 1024 * 1024)]:
        protected(path, maximum, sudo=(path == '/usr/bin/sudo'))
    # A hard closed bound prevents an idle GUI from accumulating unbounded
    # unconsumed proposals; stale files require explicit user disposition.
    if len(list(itertools.islice(directory.iterdir(), 16))) >= 16:
        raise ValueError('terminal proposal capacity reached')
    path = directory / (uuid.uuid4().hex + '.json')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        data = encoded(value)
        if len(data) > MAX_STAGE:
            raise ValueError('terminal proposal transport bound exceeded')
        with os.fdopen(descriptor, 'wb') as output:
            descriptor = -1
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        # No shell, caller-selected executable, captured password or privileged
        # WebKit callback. Native command output remains in the real terminal.
        subprocess.Popen(['/usr/bin/kgx', '--', '/usr/bin/python3', '-I', HELPER, '--terminal', str(path)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True, start_new_session=True)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return {'state': 'terminal-launched', 'authenticated': False, 'committed': False, 'completion_observed': False}


def held_read(path, directory):
    if path.parent != directory or not re.fullmatch(r'[0-9a-f]{32}\.json', path.name):
        raise ValueError('invalid exact terminal staging path')
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= MAX_STAGE:
            raise ValueError('unsafe bounded terminal staging file')
        data = bytearray()
        while len(data) <= MAX_STAGE:
            block = os.read(descriptor, min(65536, MAX_STAGE + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        identity = lambda m: (m.st_dev,m.st_ino,m.st_mode,m.st_uid,m.st_gid,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
        if len(data) != before.st_size or identity(before) != identity(os.fstat(descriptor)) or identity(before) != identity(path.lstat()):
            raise ValueError('terminal staging changed during capture')
        return proposal(strict_json(data)), identity(before)
    finally:
        os.close(descriptor)


def canonical_response(value, output):
    if not isinstance(output, bytes) or not 0 < len(output) <= MAX_STAGE:
        raise ValueError('native canonical response exceeds bound')
    response = strict_json(output)
    flags = ('owner_authenticated', 'authority_returned', 'committed', 'certified', 'gate_closing')
    if not isinstance(response, dict) or set(response) != {'schema_version', 'result', *flags} or type(response['schema_version']) is not int or response['schema_version'] != 1 or any(response.get(flag) is not False for flag in flags):
        raise ValueError('canonical request response claims authority or unknown fields')
    result = response['result']
    expected = 'office-request' if value['operation'].startswith('office-') else 'native-request'
    if not isinstance(result, dict) or set(result) != {'operation', 'request_sha256', 'canonical_request', 'private_content_read'} or result['operation'] != expected or result['private_content_read'] is not False:
        raise ValueError('native canonical request response schema differs')
    canonical = result['canonical_request']
    if not isinstance(canonical, str) or not 0 < len(canonical.encode('utf-8')) <= MAX_REQUEST:
        raise ValueError('native canonicalizer response refused')
    # Sorted serialized trees distinguish true from 1, unlike Python ==, and
    # permit only field ordering/insignificant input whitespace to change.
    tree = lambda text: json.dumps(strict_json(text), sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    if result['request_sha256'] != hashlib.sha256(canonical.encode('utf-8')).hexdigest() or tree(canonical) != tree(value['request']):
        raise ValueError('canonical native request substituted source or identity')
    return canonical


def export_pdf(value, arguments):
    """No-overwrite ordinary-user sink; errors retain an explicit partial file.

    Only the native original PAM/Read/Export channel authorizes/delivers bytes.
    A Python file/hash is not custody, publication or production qualification.
    """
    target = Path(value['output_path'])
    parent = target.parent
    if parent.resolve(strict=True) != parent:
        raise ValueError('PDF target parent must be canonical')
    uid = os.getuid()
    for ancestor in parent.parents:
        item = ancestor.stat()
        if not stat.S_ISDIR(item.st_mode) or item.st_uid not in (0, uid) or item.st_mode & 0o022:
            raise ValueError('PDF target ancestor is not protected')
    item = parent.stat()
    if not stat.S_ISDIR(item.st_mode) or item.st_uid != uid or item.st_mode & 0o022:
        raise ValueError('PDF target must be a protected directory owned by this human')
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary = '.' + target.name + '.luma-export-' + uuid.uuid4().hex + '.partial'
    try:
        try:
            os.stat(target.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError('PDF target already exists; no export started')
        descriptor = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, 'w+b') as output:
            result = subprocess.call(arguments, stdout=output, close_fds=True)
            if result != 0:
                print('Native Office export did not complete. Its ordinary-user .partial file is retained; inspect the actual native outcome before retry.', file=sys.stderr)
                return result
            output.flush()
            os.fsync(output.fileno())
            metadata = os.fstat(output.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 16 <= metadata.st_size <= 16*1024*1024:
                raise ValueError('actual exported PDF inode or size refused; partial retained')
            output.seek(0)
            if output.read(5) != b'%PDF-':
                raise ValueError('native export did not deliver PDF; partial retained')
            output.seek(max(0, metadata.st_size-1024))
            if b'%%EOF' not in output.read(1024):
                raise ValueError('native PDF framing incomplete; partial retained')
            current = parent.stat()
            if (current.st_dev,current.st_ino) != (os.fstat(directory).st_dev,os.fstat(directory).st_ino):
                raise ValueError('PDF target directory changed; partial retained')
            named = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
            if (named.st_dev,named.st_ino,named.st_size,named.st_mode,named.st_uid,named.st_nlink) != (metadata.st_dev,metadata.st_ino,metadata.st_size,metadata.st_mode,metadata.st_uid,metadata.st_nlink):
                raise ValueError('PDF partial was substituted before delivery')
            os.link(temporary,target.name,src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
            os.fsync(directory)
            os.unlink(temporary,dir_fd=directory)
            os.fsync(directory)
        print('Native PDF export delivered to the explicitly selected new file and synchronized. No production qualification is inferred.', flush=True)
        return 0
    finally:
        os.close(directory)


def terminal(path):
    directory = runtime()
    value, identity = held_read(path, directory)
    # The native canonicalizer is unprivileged and authorizes nothing. It
    # selects the same exact typed Input encoding the root launcher captures.
    protected(NATIVE, 128 * 1024 * 1024)
    request_path = directory / (uuid.uuid4().hex + '.request')
    try:
        host_path = Path('/usr/libexec/luma-os/workspace_host.py')
        protected(host_path, 128 * 1024)
        spec = importlib.util.spec_from_file_location('luma_terminal_native_host', host_path)
        host = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(host)
        binary = host.PinnedExecutable(Path(NATIVE))
        try:
            command = 'content-office-request' if value['operation'].startswith('office-') else 'content-contract-native-request'
            state, output = host.run_process(binary, command, value['request'].encode('utf-8'),
                                             threading.Event(), lambda _: None, maximum=MAX_STAGE)
        finally:
            binary.close()
        if state != 'completed' or not output:
            raise ValueError('native canonical request did not complete')
        # Canonicalizer prints its closed contract response, not a bare Input.
        canonical = canonical_response(value, output)
        value = dict(value, request=canonical)
        proposal(value)
        descriptor = os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(canonical.encode('utf-8'))
            output.flush()
            os.fsync(output.fileno())
        print('Luma native owner operation. Enter passwords only in this terminal.\nSudo transports the fixed executor; original PAM and finite grants authorize the operation.\nIf interrupted, inspect the exact native checkpoint before any retry.', flush=True)
        arguments = terminal_arguments(value, request_path)
        return export_pdf(value, arguments) if value['operation'] == 'office-export' else subprocess.call(arguments, close_fds=True)
    finally:
        request_path.unlink(missing_ok=True)
        try:
            current = path.lstat()
            observed = (current.st_dev,current.st_ino,current.st_mode,current.st_uid,current.st_gid,current.st_nlink,current.st_size,current.st_mtime_ns,current.st_ctime_ns)
            if observed == identity:
                path.unlink()
        except FileNotFoundError:
            pass


if __name__ == '__main__':
    try:
        if not sys.flags.isolated or len(sys.argv) != 3 or sys.argv[1] != '--terminal':
            raise ValueError('fixed isolated terminal entry required')
        raise SystemExit(terminal(Path(sys.argv[2])))
    except Exception:
        print('Native owner ceremony refused; no completion or custody state is inferred.', file=sys.stderr)
        raise SystemExit(1)
