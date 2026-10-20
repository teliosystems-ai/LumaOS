#!/usr/bin/env python3
"""Build the existing unsigned profile-W USTAR format from real Linux inputs.

No input executable is run. This is a build tool, not a distribution importer,
installer, dependency downloader, signature authority or runtime qualification.
The caller must supply an immutable, reviewed Ubuntu 24.04 source tree. Explicit
exclusions and permission normalization are inputs, never implicit repairs.
"""
import argparse
from contextlib import contextmanager
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import tarfile

MAX_ARCHIVE = 16 * 1024**3
MAX_FILE = 512 * 1024**2
MAX_MEMBERS = 200000
MAX_ELF = 64 * 1024**2
MAX_DEPTH = 64
WSL = b'[boot]\nsystemd=true\n[automount]\nenabled=false\n[interop]\nenabled=false\nappendWindowsPath=false\n'
LIB_DIRS = ('lib/x86_64-linux-gnu', 'usr/lib/x86_64-linux-gnu',
            'lib64', 'usr/lib64', 'lib', 'usr/lib')
SEARCH_DIRS = frozenset((*LIB_DIRS, 'usr/lib/x86_64-linux-gnu/systemd',
                         'lib/x86_64-linux-gnu/systemd'))
NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9._+@=-]*\Z')
RESERVED = re.compile(r'(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|\Z)', re.I)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def relative(path):
    if (not isinstance(path, str) or not path or len(path) > 4096 or
            path.startswith('/') or '\x00' in path or '\\' in path or
            any(p in ('', '.', '..') for p in path.split('/'))):
        raise ValueError('noncanonical source-relative path')
    return path


def archive_path(path):
    relative(path)
    if len(path) > 255 or any(not NAME.fullmatch(p) or p.endswith('.') or RESERVED.match(p)
                              for p in path.split('/')):
        raise ValueError('path cannot be represented by the unchanged Windows validator: ' + path)
    # USTAR splits only at a slash; a 101-byte basename is not representable.
    if len(path.encode('ascii')) > 100 and not any(
            len(path[:i]) <= 155 and len(path[i + 1:]) <= 100
            for i, char in enumerate(path) if char == '/'):
        raise ValueError('path exceeds normalized USTAR fields: ' + path)
    return path


class Tree:
    """Resolve every source component through pinned no-follow directory FDs.

    Absolute symlinks mean this root, never the build host's root. Sources may
    contain aliases, but links escaping the supplied root or cycling are refused.
    """
    def __init__(self, root):
        if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
            raise ValueError('rootfs capture requires Linux no-follow descriptor support')
        root = Path(os.path.abspath(root))
        descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in root.parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_fd
            self.fd = descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def close(self):
        os.close(self.fd)

    @contextmanager
    def opened(self, path, directory=False):
        parts = relative(path).split('/')
        resolved = []
        hops = 0
        descriptor = os.dup(self.fd)
        try:
            while parts:
                part = parts.pop(0)
                if part == '.':
                    continue
                if part == '..':
                    if not resolved:
                        raise ValueError('source link escapes supplied root')
                    resolved.pop()
                    os.close(descriptor)
                    descriptor = os.dup(self.fd)
                    for component in resolved:
                        new = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=descriptor)
                        os.close(descriptor)
                        descriptor = new
                    continue
                before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISLNK(before.st_mode):
                    hops += 1
                    if hops > 40:
                        raise ValueError('source symlink chain exceeds bound')
                    target = os.readlink(part, dir_fd=descriptor)
                    if identity(before) != identity(os.stat(part, dir_fd=descriptor, follow_symlinks=False)):
                        raise ValueError('source symlink changed during resolution')
                    if '\x00' in target or not target or len(target) > 4096:
                        raise ValueError('invalid source symlink target')
                    if target.startswith('/'):
                        resolved = []
                        os.close(descriptor)
                        descriptor = os.dup(self.fd)
                    parts = [p for p in target.split('/') if p] + parts
                    if len(parts) + len(resolved) > MAX_DEPTH:
                        raise ValueError('source link depth exceeds bound')
                    continue
                final = not parts
                if not stat.S_ISDIR(before.st_mode) and not (final and stat.S_ISREG(before.st_mode)):
                    raise ValueError('source contains a special or nondirectory intermediate member: ' + path)
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                if not final or directory:
                    flags |= os.O_DIRECTORY
                new = os.open(part, flags, dir_fd=descriptor)
                if identity(before) != identity(os.fstat(new)):
                    os.close(new)
                    raise ValueError('source changed during no-follow capture')
                os.close(descriptor)
                descriptor = new
                resolved.append(part)
            metadata = os.fstat(descriptor)
            if directory and not stat.S_ISDIR(metadata.st_mode):
                raise ValueError('expected source directory')
            yield descriptor, metadata
            if identity(os.fstat(descriptor)) != identity(metadata):
                raise ValueError('source changed during capture: ' + path)
        finally:
            os.close(descriptor)

    def read(self, path, maximum):
        with self.opened(path) as (descriptor, metadata):
            if not stat.S_ISREG(metadata.st_mode) or not 0 <= metadata.st_size <= maximum:
                raise ValueError('source file exceeds bound: ' + path)
            value = bytearray()
            while len(value) <= maximum:
                block = os.read(descriptor, min(65536, maximum + 1 - len(value)))
                if not block:
                    break
                value.extend(block)
            if len(value) != metadata.st_size:
                raise ValueError('source size changed or exceeds bound')
            return bytes(value)


def plan_input(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate build plan field')
            result[key] = value
        return result
    path = Path(os.path.abspath(path))
    tree = Tree(path.parent)
    try:
        data = tree.read(path.name, 65536)
    finally:
        tree.close()
    if not 0 < len(data) <= 65536:
        raise ValueError('build plan exceeds bound')
    value = json.loads(data, object_pairs_hook=unique)
    if (not isinstance(value, dict) or set(value) !=
            {'schema_version', 'exclude_paths', 'normalize_privileged_modes'} or
            type(value['schema_version']) is not int or value['schema_version'] != 1 or
            type(value['normalize_privileged_modes']) is not bool or
            not isinstance(value['exclude_paths'], list) or len(value['exclude_paths']) > 256):
        raise ValueError('unsupported closed build plan')
    paths = [relative(p) for p in value['exclude_paths']]
    if len(set(paths)) != len(paths) or any(
            b.startswith(a + '/') for a in paths for b in paths if a != b):
        raise ValueError('duplicate or overlapping exclusions')
    return value


def runtime_search_paths(text, object_path, private_dirs=()):
    """Closed Ubuntu search paths, with lexical root-bound ORIGIN expansion.

    This never consults host paths, LD_LIBRARY_PATH or the working directory.
    ORIGIN expansions may normalize parent components only while remaining
    beneath the package root and ending at an explicitly supported directory.
    """
    relative(object_path)
    if private_dirs not in ((), ('usr/libexec/luma-os/hosted-llama',)):
        raise ValueError('only the versioned hosted inference private runtime directory is supported')
    admitted = SEARCH_DIRS | set(private_dirs)
    if not text or len(text) > 4096:
        raise ValueError('ELF search path is empty or exceeds bound')
    result = []
    for item in text.split(':'):
        if not item:
            raise ValueError('ELF search path contains the working directory')
        if item.startswith('/'):
            path = relative(item[1:])
        else:
            token = next((value for value in ('$ORIGIN', '${ORIGIN}')
                          if item == value or item.startswith(value + '/')), None)
            if token is None:
                raise ValueError('ELF search path uses unsupported relative or dynamic tokens')
            pieces = object_path.split('/')[:-1]
            suffix = item[len(token):]
            if suffix.endswith('/') or '//' in suffix:
                raise ValueError('ELF ORIGIN search path is noncanonical')
            forward = False
            for component in suffix.split('/'):
                if not component:
                    continue
                if component == '.':
                    raise ValueError('ELF ORIGIN search path contains a redundant component')
                if component == '..':
                    if forward:
                        raise ValueError('ELF ORIGIN search path cancels a potentially missing directory')
                    if not pieces:
                        raise ValueError('ELF ORIGIN search path escapes package root')
                    pieces.pop()
                else:
                    if not NAME.fullmatch(component):
                        raise ValueError('ELF ORIGIN search path contains unsupported components')
                    pieces.append(component)
                    forward = True
            path = '/'.join(pieces)
        if path not in admitted:
            raise ValueError('ELF search path is outside the closed Ubuntu directory policy')
        if path in result or len(result) >= len(admitted):
            raise ValueError('ELF search path is duplicated or exceeds bound')
        result.append(path)
    return tuple(result)


def elf(data, require_entry=False, object_path=None, details=False, private_dirs=()):
    """Inspect bounded real ELF segments and direct loader dependencies, no execution."""
    if len(data) < 64 or len(data) > MAX_ELF or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('required runtime is not an amd64 executable ELF')
    fields = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    kind, machine, version, entry, phoff = fields[:5]
    ehsize, phsize, count = fields[7:10]
    if (kind not in (2, 3) or machine != 62 or version != 1 or ehsize != 64 or
            phsize != 56 or not 1 <= count <= 128 or phoff < 64 or phoff + count * 56 > len(data)):
        raise ValueError('invalid real ELF program table')
    loads, dynamic, interpreter = [], None, None
    for index in range(count):
        ptype, flags, offset, virtual, _, size, memory, alignment = struct.unpack_from(
            '<IIQQQQQQ', data, phoff + index * 56)
        if offset + size > len(data) or size > memory or (alignment and alignment & (alignment - 1)):
            raise ValueError('invalid ELF segment range')
        if ptype == 1:
            loads.append((offset, virtual, size, memory, flags))
        elif ptype == 2:
            if dynamic is not None or size % 16:
                raise ValueError('invalid ELF dynamic table')
            dynamic = data[offset:offset + size]
        elif ptype == 3:
            if interpreter is not None or not 2 <= size <= 256:
                raise ValueError('invalid ELF interpreter')
            raw = data[offset:offset + size]
            if raw[-1] or b'\0' in raw[:-1]:
                raise ValueError('invalid ELF interpreter termination')
            interpreter = raw[:-1].decode('ascii')
            if not interpreter.startswith('/'):
                raise ValueError('ELF interpreter must be root-absolute')
            relative(interpreter[1:])
    if (not loads or (require_entry and not entry) or
            (entry and not any(v <= entry < v + m and f & 1 for _, v, _, m, f in loads))):
        raise ValueError('ELF has no loadable executable entry')
    needed = []
    search = {'rpath': (), 'runpath': None, 'soname': None}
    if dynamic is not None:
        tags = {}
        terminated = False
        for offset in range(0, len(dynamic), 16):
            tag, value = struct.unpack_from('<qQ', dynamic, offset)
            if tag == 0:
                terminated = True
                break
            tags.setdefault(tag, []).append(value)
        if not terminated:
            raise ValueError('unterminated ELF dynamic table')
        if 15 in tags and 29 in tags:
            raise ValueError('mixed ELF RPATH and RUNPATH is outside the closed build profile')
        if any(tag in tags for tag in (1, 14, 15, 29)):
            if len(tags.get(5, [])) != 1 or len(tags.get(10, [])) != 1:
                raise ValueError('ELF lacks unique dynamic string table')
            address, size = tags[5][0], tags[10][0]
            ranges = [(o + address - v, size) for o, v, s, _, _ in loads
                      if v <= address and address + size <= v + s]
            if len(ranges) != 1 or not 0 < size <= 1024 * 1024:
                raise ValueError('ELF dynamic strings are out of range')
            offset, _ = ranges[0]
            strings = data[offset:offset + size]
            if len(tags.get(1, [])) > 128:
                raise ValueError('ELF dependencies exceed bound')
            def string(start):
                end = strings.find(b'\0', start)
                if not 0 <= start < len(strings) or end < 0 or end - start > 4096:
                    raise ValueError('ELF dynamic string is invalid')
                return strings[start:end].decode('ascii')
            for start in tags.get(1, []):
                name = string(start)
                if len(name) > 255 or not NAME.fullmatch(name):
                    raise ValueError('ELF dependency must use a plain supported soname')
                needed.append(name)
            if 14 in tags:
                if len(tags[14]) != 1:
                    raise ValueError('ELF has multiple SONAME identities')
                soname = string(tags[14][0])
                if len(soname) > 255 or not NAME.fullmatch(soname):
                    raise ValueError('ELF SONAME must use a plain supported name')
                search['soname'] = soname
            for tag, label in ((15, 'rpath'), (29, 'runpath')):
                if tag in tags:
                    if len(tags[tag]) != 1 or object_path is None:
                        raise ValueError('ELF search path requires a unique tag and package object location')
                    search[label] = runtime_search_paths(string(tags[tag][0]), object_path, private_dirs)
    return (interpreter, needed, search) if details else (interpreter, needed)


def build(root, platform, plan_path, output, release, hosted_compute=False, hosted_inference=False, hosted_workspace=False):
    if hosted_compute and (hosted_inference or hosted_workspace):
        raise ValueError('select one distinct hosted runtime profile')
    if hosted_workspace:
        spec=importlib.util.spec_from_file_location('luma_windows_workspace_build',Path(__file__).with_name('windows_workspace.py'))
        workspace=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(workspace)
    else:
        workspace=None
    if hosted_inference:
        spec = importlib.util.spec_from_file_location('luma_windows_inference_build', Path(__file__).with_name('windows_inference.py'))
        inference = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inference)
    else:
        inference = None
    private_dirs = inference.PRIVATE_DIRS if inference else ()
    if not re.fullmatch(r'luma-wsl-dev-[A-Za-z0-9][A-Za-z0-9.-]{0,63}', release):
        raise ValueError('release ID is outside the existing development schema')
    plan = plan_input(plan_path)
    output = Path(os.path.abspath(output))
    root = Path(os.path.abspath(root))
    if output == root or root in output.parents:
        raise ValueError('output must be outside the source root')
    tree = Tree(root)
    binary_tree = Tree(Path(platform).absolute().parent)
    output_parent = None
    output_fd = None
    try:
        binary = binary_tree.read(Path(platform).name, MAX_ELF)
        elf(binary, require_entry=True, object_path='usr/bin/luma-platform')
        os_release = tree.read('etc/os-release', 16384)
        keys = {}
        for line in os_release.decode('utf-8').splitlines():
            if line.startswith(('ID=', 'VERSION_ID=')):
                match = re.fullmatch(r'(ID|VERSION_ID)=(?:"([A-Za-z0-9.]+)"|([A-Za-z0-9.]+))', line)
                if not match or match[1] in keys:
                    raise ValueError('ambiguous Ubuntu identity')
                keys[match[1]] = match[2] or match[3]
        if keys != {'ID': 'ubuntu', 'VERSION_ID': '24.04'}:
            raise ValueError('source must identify actual Ubuntu 24.04 userland')
        embedded_identity = {'schema_version': 1, 'release_id': release, 'architecture': 'amd64', 'profile': 'W'}
        wsl = WSL
        hosted = None
        if hosted_compute or hosted_inference or workspace:
            spec = importlib.util.spec_from_file_location('luma_windows_hosted_package', Path(__file__).with_name('windows_hosted.py'))
            hosted = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(hosted)
            embedded_identity.update(schema_version=3 if workspace else 2, runtime_profile=workspace.PROFILE if workspace else inference.PROFILE if inference else hosted.PROFILE)
            wsl += b'[user]\ndefault=nobody\n'
        replacements = {
            'usr/bin/luma-platform': (binary, 0o755),
            'etc/wsl.conf': (wsl, 0o644),
            'usr/lib/luma/platform.json': (canonical(embedded_identity), 0o644)}
        entries, folded, excluded, normalizations, directories = {}, {}, set(), [], {}
        def add(path, directory, mode, size, source):
            archive_path(path)
            if path.lower() in folded:
                raise ValueError('case-aliased or duplicate output member: ' + path)
            if len(entries) >= MAX_MEMBERS:
                raise ValueError('rootfs member count exceeds bound')
            folded[path.lower()] = path
            entries[path] = (directory, mode, size, source)

        def visit(path, ancestry):
            if path in plan['exclude_paths']:
                excluded.add(path)
                return
            if path in replacements:
                return
            with tree.opened(path) as (descriptor, metadata):
                directory = stat.S_ISDIR(metadata.st_mode)
                mode = stat.S_IMODE(metadata.st_mode)
                if mode & 0o6000:
                    if not plan['normalize_privileged_modes']:
                        raise ValueError('privileged mode requires explicit normalization: ' + path)
                    normalizations.append(path)
                    mode &= ~0o6000
                if (mode & 0o022 and not (directory and mode == 0o1777)) or (not directory and mode & 0o1000):
                    raise ValueError('unsafe writable or sticky member mode: ' + path)
                if directory:
                    inode = (metadata.st_dev, metadata.st_ino)
                    if inode in ancestry or len(ancestry) >= MAX_DEPTH:
                        raise ValueError('directory alias cycle or excessive depth: ' + path)
                    children = sorted(os.listdir(descriptor))
                    directories[path] = identity(metadata)
                    add(path, True, mode, 0, None)
                    for child in children:
                        visit(path + '/' + child, ancestry + (inode,))
                else:
                    maximum = inference.MODEL_BYTES if inference and path == inference.MODEL else MAX_FILE
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                        raise ValueError('source member exceeds regular-file bounds: ' + path)
                    add(path, False, mode, metadata.st_size, identity(metadata))
        root_identity = identity(os.fstat(tree.fd))
        for child in sorted(os.listdir(tree.fd)):
            visit(child, ((root_identity[0], root_identity[1]),))
        if identity(os.fstat(tree.fd)) != root_identity:
            raise ValueError('source root changed during inventory')
        if excluded != set(plan['exclude_paths']):
            raise ValueError('exclusion did not name an observed source path')
        for path, (data, mode) in replacements.items():
            parent = path.rsplit('/', 1)[0]
            parents = []
            while parent:
                parents.append(parent)
                parent = parent.rsplit('/', 1)[0] if '/' in parent else ''
            for parent in reversed(parents):
                if parent not in entries:
                    add(parent, True, 0o755, 0, None)
                elif not entries[parent][0]:
                    raise ValueError('replacement parent is not a directory')
            add(path, False, mode, len(data), None)
        def data_at(path):
            if path in replacements:
                return replacements[path][0]
            record = entries.get(path)
            if not record or record[0] or record[2] > MAX_ELF:
                raise ValueError('missing bounded runtime file: ' + path)
            with tree.opened(path) as (_, metadata):
                if identity(metadata) != record[3]:
                    raise ValueError('source changed after inventory')
            return tree.read(path, MAX_ELF)
        required = {'etc/os-release', 'etc/wsl.conf', 'usr/lib/luma/platform.json',
                    'usr/bin/luma-platform', 'bin/sh', 'usr/lib/systemd/systemd'}
        roots = ('usr/bin/luma-platform', 'bin/sh', 'usr/lib/systemd/systemd')
        if hosted_compute or hosted_inference or workspace:
            required.update((*hosted.GENERATED, hosted.PLATFORM, hosted.POLICY, *hosted.BINARIES,
                             'usr/bin/systemctl'))
            if not required.issubset(entries):
                raise ValueError('hosted compute composition lacks mandatory fixed runtime files')
            hosted.validate(data_at, entries, binary)
            roots += (*hosted.BINARIES, hosted.PLATFORM, 'usr/bin/systemctl')
        if inference:
            required.update(inference.validate(data_at, entries, tree))
            roots += (inference.PRIVATE+'/llama-completion', inference.PRIVATE+'/libggml-cpu-x64.so')
        if workspace:
            required.update(workspace.validate(data_at,entries,tree))
            roots+=(workspace.AUTH_HELPER,workspace.SHELL,workspace.PAM_MODULE)
        if not required.issubset(entries):
            raise ValueError('explicit exclusions removed mandatory runtime content')
        todo = [(path, (), path) for path in roots]
        loaded = {path: {} for path in roots}
        checked = set()
        while todo:
            path, inherited, scope = todo.pop()
            key = (path, inherited, scope)
            if key in checked:
                continue
            checked.add(key)
            if len(checked) > (512 if inference or workspace else 256) or len({item[0] for item in checked}) > (128 if inference or workspace else 60):
                raise ValueError('runtime dependency closure exceeds manifest bounds')
            executable_root = path in roots and not (inference and path.endswith('/libggml-cpu-x64.so')) and not (workspace and path==workspace.PAM_MODULE)
            interp, needed, search = elf(data_at(path), require_entry=executable_root, object_path=path,
                                        details=True, private_dirs=private_dirs)
            if executable_root and not entries[path][1] & 0o111:
                raise ValueError('required ELF is not executable: ' + path)
            dependencies = []
            inherited_next = tuple(dict.fromkeys((*search['rpath'], *inherited)))
            # RUNPATH applies to this object's direct dependencies only. Old
            # RPATH is inherited down the bounded dependency graph. Comparing
            # all admitted candidates below makes supported lookup precedence
            # immaterial: differing soname bytes always refuse.
            private = search['runpath'] if search['runpath'] is not None else inherited_next
            folders = tuple(dict.fromkeys((*private, *LIB_DIRS)))
            if interp:
                dependencies.append(interp[1:])
            for name in needed:
                candidates = [folder + '/' + name for folder in folders
                              if folder + '/' + name in entries and not entries[folder + '/' + name][0]]
                existing = loaded[scope].get(name)
                if existing is not None and existing not in candidates:
                    candidates.append(existing)
                if not candidates:
                    raise ValueError('missing ELF dependency: ' + name)
                # Loader aliases may have multiple names, but not different bytes.
                hashes = {hashlib.sha256(data_at(p)).hexdigest() for p in candidates}
                if len(hashes) != 1:
                    raise ValueError('ambiguous ELF dependency resolution: ' + name)
                selected = existing if existing is not None else candidates[0]
                _, _, selected_metadata = elf(data_at(selected), object_path=selected, details=True, private_dirs=private_dirs)
                if selected_metadata['soname'] not in (None, name):
                    # Do not approximate the loader's multiple-name aliases.
                    # The closed Ubuntu profile supports matching SONAMEs or
                    # a library without SONAME, never a different claimed one.
                    raise ValueError('ELF dependency SONAME differs from requested name: ' + name)
                loaded[scope][name] = selected
                dependencies.append(selected)
            required.update(dependencies)
            # Seed every direct NEEDED binding before visiting any child. Real
            # Ubuntu systemd directly loads core+shared using RUNPATH; core has
            # no RUNPATH of its own and reuses the already loaded shared soname.
            # This namespace is private to each independent executable root.
            todo.extend((p, inherited_next, scope) for p in dependencies
                        if (p, inherited_next, scope) not in checked)
        if len(required) > (128 if inference or workspace else 64):
            raise ValueError('required runtime files exceed existing manifest bound')
        content_bytes = sum(item[2] for item in entries.values())
        archive_bytes = 1024 + sum(512 + ((item[2] + 511) // 512) * 512 for item in entries.values())
        if content_bytes > MAX_ARCHIVE or archive_bytes > MAX_ARCHIVE:
            raise ValueError('rootfs archive exceeds unchanged validator bounds')
        # Never replace prior output. Failure leaves its private diagnostic directory.
        output_parent = Tree(output.parent)
        os.mkdir(output.name, mode=0o700, dir_fd=output_parent.fd)
        output_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=output_parent.fd)
        records = []
        with os.fdopen(os.open('rootfs.tar', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                               0o600, dir_fd=output_fd), 'wb') as target:
            for path, (directory, mode, size, expected) in sorted(entries.items()):
                header = tarfile.TarInfo(path)
                header.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
                header.mode, header.uid, header.gid, header.mtime = mode, 0, 0, 0
                header.size = size
                target.write(header.tobuf(format=tarfile.USTAR_FORMAT, encoding='ascii', errors='strict'))
                digest = hashlib.sha256()
                if not directory:
                    if path in replacements:
                        stream = io.BytesIO(replacements[path][0])
                        context = None
                    else:
                        context = tree.opened(path)
                        descriptor, metadata = context.__enter__()
                        if identity(metadata) != expected:
                            context.__exit__(None, None, None)
                            raise ValueError('source changed before archive read')
                        stream = os.fdopen(os.dup(descriptor), 'rb')
                    try:
                        read = 0
                        while block := stream.read(65536):
                            read += len(block)
                            if read > size:
                                raise ValueError('source grew while archiving')
                            target.write(block)
                            digest.update(block)
                        if read != size:
                            raise ValueError('source truncated while archiving')
                    finally:
                        stream.close()
                        if context:
                            context.__exit__(None, None, None)
                    target.write(b'\0' * ((-size) % 512))
                if path in required:
                    records.append({'path': path, 'bytes': size, 'sha256': digest.hexdigest(),
                                    'executable': bool(mode & 0o111)})
            target.write(b'\0' * 1024)
            target.flush()
            os.fsync(target.fileno())
        # The caller must still supply an immutable source, but also reject
        # observable nested mutations after a subtree's first traversal/read.
        if identity(os.fstat(tree.fd)) != root_identity:
            raise ValueError('source root changed after archive capture')
        for path, expected in directories.items():
            with tree.opened(path, directory=True) as (_, metadata):
                if identity(metadata) != expected:
                    raise ValueError('source directory changed after capture: ' + path)
        for path, (directory, _, _, expected) in entries.items():
            if not directory and expected is not None:
                with tree.opened(path) as (_, metadata):
                    if identity(metadata) != expected:
                        raise ValueError('source file changed after capture: ' + path)
        archive_hash = hashlib.sha256()
        with os.fdopen(os.open('rootfs.tar', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=output_fd), 'rb') as stream:
            while block := stream.read(1024 * 1024):
                archive_hash.update(block)
        manifest = {'schema_version': 1, 'package_type': 'luma-wsl-rootfs-ustar-v1',
                    'release_id': release, 'architecture': 'amd64', 'profile': 'W',
                    'rootfs': {'path': 'rootfs.tar', 'bytes': archive_bytes, 'sha256': archive_hash.hexdigest(),
                               'member_count': len(entries), 'content_bytes': content_bytes},
                    'required_files': records}
        manifest_bytes = canonical(manifest)
        if len(manifest_bytes) > 65536 or os.stat('rootfs.tar', dir_fd=output_fd, follow_symlinks=False).st_size != archive_bytes:
            raise ValueError('constructed package exceeds manifest or exact archive size bound')
        with os.fdopen(os.open('manifest.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                               0o600, dir_fd=output_fd), 'wb') as target:
            target.write(manifest_bytes)
            target.flush()
            os.fsync(target.fileno())
        return {'schema_version': 1, 'status': 'unsigned-populated-development-package-built',
                'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
                'rootfs_sha256': archive_hash.hexdigest(), 'rootfs_bytes': archive_bytes,
                'member_count': len(entries), 'required_file_count': len(records),
                'plan_sha256': hashlib.sha256(canonical(plan)).hexdigest(),
                'excluded_paths': sorted(excluded), 'privileged_modes_removed': sorted(normalizations),
                'real_runtime_elf_segments_checked': True, 'elf_needed_closure_checked': True,
                'dlopen_dependencies_qualified': False, 'source_authentication_established': False,
                'package_authenticated': False, 'runtime_qualified': False,
                'product_installation_admitted': False, 'distribution_imported': False,
                'host_settings_changed': False, 'production_qualified': False, 'gate_closing': False}
    finally:
        tree.close()
        binary_tree.close()
        if output_fd is not None:
            os.close(output_fd)
        if output_parent is not None:
            output_parent.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--platform', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--release-id', required=True)
    parser.add_argument('--hosted-compute', action='store_true')
    parser.add_argument('--hosted-inference', action='store_true')
    parser.add_argument('--hosted-workspace', action='store_true')
    args = parser.parse_args()
    print(canonical(build(args.root, args.platform, args.plan, args.output, args.release_id,
                         hosted_compute=args.hosted_compute, hosted_inference=args.hosted_inference,hosted_workspace=args.hosted_workspace)).decode(), end='')
