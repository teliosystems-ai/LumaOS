"""Pinned, streamed profile-W compact inference composition, not activation.

Only the approved CPU runtime and Qwen3-4B input are accepted. Building never
executes supplied programs, imports a distribution, creates custody, or grants
the guest publication authority. The publisher must sign the resulting exact
package and every required profile/runtime/model member independently.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('luma_inference_package', HERE/'windows_package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)
PROFILE = 'luma-windows-hosted-inference-v1'
PRIVATE = 'usr/libexec/luma-os/hosted-llama'
PRIVATE_DIRS = (PRIVATE,)
MODEL = 'usr/share/luma-os/models/qwen3-4b-q4-k-m.gguf'
MODEL_BYTES = 2497280256
MODEL_SHA = '7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5'
ARCHIVE_SHA = 'a836c913236ab4533ef9aaf49f0e1ad2955c8159869d7eec1a9072a92e13d61b'
PROFILE_PATH = 'usr/share/luma-os/hosted-inference.json'
MANIFEST_PATH = 'usr/share/luma-os/hosted-inference-runtime.json'
POLICY = 'etc/apparmor.d/luma-hosted-inference'
SERVICE = 'etc/systemd/system/luma-hosted-inference-confinement.service'
ENABLED = 'etc/systemd/system/multi-user.target.wants/luma-hosted-inference-confinement.service'
RUNTIME_NAMES = ('llama-completion', 'libllama-completion-impl.so',
                 'libggml-cpu-x64.so', *tuple(name for stem, version in (
                     ('libllama', '0.4.1'), ('libllama-common', '0.4.1'),
                     ('libmtmd', '0.4.1'), ('libggml', '0.24.0'), ('libggml-base', '0.24.0'))
                     for name in (stem+'.so', stem+'.so.0', stem+'.so.'+version)))


def closed(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate inference manifest field')
            result[key] = value
        return result
    def nonfinite(_value):
        raise ValueError('nonfinite inference manifest number')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def profile(manifest_sha):
    if not isinstance(manifest_sha, str) or not package.re.fullmatch('[0-9a-f]{64}', manifest_sha) or manifest_sha == '0'*64:
        raise ValueError('exact runtime manifest digest required')
    return dict(schema_version=1, profile=PROFILE, environment='lab', runtime='llama.cpp-b11100-cpu-amd64-completion',
                model_path=MODEL, model_bytes=MODEL_BYTES, model_sha256=MODEL_SHA,
                runtime_manifest_sha256=manifest_sha, context_tokens=2048, maximum_output_tokens=512,
                memory_max_bytes=4831838208, memory_swap_max_bytes=0, tasks_max=16,
                cpu_quota_usec=200000, cpu_period_usec=100000, runtime_cpu_seconds=300, threads=2)


def runtime_archive(raw):
    if not isinstance(raw, bytes) or len(raw) > 32*1024**2 or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA:
        raise ValueError('runtime archive differs from the independently pinned b11100 input')
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as source:
        members = source.getmembers()
        if len(members) > 128 or len({m.name for m in members}) != len(members):
            raise ValueError('ambiguous runtime archive inventory')
        index = {m.name: m for m in members}
        for name in RUNTIME_NAMES:
            member = index['llama-b11100/'+name]
            seen = set()
            while member.issym():
                if member.name in seen or member.linkname not in RUNTIME_NAMES:
                    raise ValueError('runtime alias escapes its closed allowlist')
                seen.add(member.name)
                member = index['llama-b11100/'+member.linkname]
            if not member.isfile() or not 64 <= member.size <= package.MAX_ELF:
                raise ValueError('runtime member is not a bounded actual ELF')
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError('runtime member cannot be read')
            with stream:
                data = stream.read(package.MAX_ELF+1)
            package.elf(data, require_entry=name == 'llama-completion', object_path=PRIVATE+'/'+name,
                        private_dirs=PRIVATE_DIRS)
            result[PRIVATE+'/'+name] = (data, 0o755 if name == 'llama-completion' else 0o644)
    return result


def write_new(tree, name, data, mode):
    """Exclusive publication beneath a held, no-follow staging root."""
    package.archive_path(name)
    descriptor = os.dup(tree.fd)
    try:
        for part in name.split('/')[:-1]:
            created = False
            try:
                os.mkdir(part, 0o755, dir_fd=descriptor)
                created = True
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            info = os.fstat(child)
            if info.st_uid != 0 or info.st_mode & 0o022:
                os.close(child)
                raise ValueError('inference staging ancestor is not protected')
            if created:
                os.fchmod(child, 0o755)
            elif info.st_mode & 0o055 != 0o055:
                os.close(child)
                raise ValueError('existing inference staging ancestor is not traversable by the fixed worker')
            os.close(descriptor)
            descriptor = child
        fd = os.open(name.split('/')[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     mode, dir_fd=descriptor)
        with os.fdopen(fd, 'wb') as output:
            if isinstance(data, bytes):
                output.write(data)
            else:
                data(output)
            output.flush()
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def source_elf(tree, name):
    """Capture actual dependency bytes and safe modes through the same held FD."""
    with tree.opened(name) as (fd, info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o7022 or not 64 <= info.st_size <= package.MAX_ELF):
            raise ValueError('inference dependency is not a protected bounded ELF input')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            value = stream.read(package.MAX_ELF+1)
        if len(value) != info.st_size:
            raise ValueError('inference dependency changed during held capture')
        return value, stat.S_IMODE(info.st_mode)


def compose(root, source_root, model_path, runtime_path):
    """Add inference only to one fresh, root-owned compute staging tree."""
    if os.geteuid() != 0:
        raise ValueError('isolated root-owned Linux build required')
    root = Path(os.path.abspath(root))
    if root == Path('/') or root == Path('/mnt/c') or str(root).startswith('/mnt/c/'):
        raise ValueError('inference composition requires a narrow external Linux staging root, not host root or C')
    target = source = model_tree = archive_tree = None
    try:
        target = package.Tree(root)
        source = package.Tree(source_root)
        model_tree = package.Tree(Path(model_path).absolute().parent)
        archive_tree = package.Tree(Path(runtime_path).absolute().parent)
        root_info = os.fstat(target.fd)
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or root_info.st_mode & 0o022:
            raise ValueError('inference staging root must be root-owned and protected')
        for name in (PROFILE_PATH, MANIFEST_PATH, MODEL, POLICY, SERVICE, ENABLED, PRIVATE):
            try:
                with target.opened(name):
                    raise ValueError('inference staging destination already exists: '+name)
            except FileNotFoundError:
                pass
        data = runtime_archive(archive_tree.read(Path(runtime_path).name, 32*1024**2))
        # Resolve every direct ELF dependency, including the one explicitly
        # allowed dynamically loaded CPU plugin. No RPC, GPU or server program.
        queue = list(data)
        checked = set()
        while queue:
            name = queue.pop()
            if name in checked:
                continue
            checked.add(name)
            if len(checked) > 64:
                raise ValueError('inference ELF closure exceeds its fixed bound')
            interpreter, needed, search = package.elf(data[name][0], object_path=name, details=True,
                require_entry=name == PRIVATE+'/llama-completion', private_dirs=PRIVATE_DIRS)
            folders = tuple(dict.fromkeys((*(search['runpath'] or search['rpath']), *PRIVATE_DIRS, *package.LIB_DIRS)))
            dependencies = [interpreter[1:]] if interpreter else []
            for soname in needed:
                candidates = []
                for folder in folders:
                    candidate = folder+'/'+soname
                    if candidate in data:
                        candidates.append((candidate, data[candidate][0]))
                    elif folder not in PRIVATE_DIRS:
                        try:
                            value, source_mode = source_elf(source, candidate)
                        except FileNotFoundError:
                            continue
                        candidates.append((candidate, value))
                if not candidates or len({hashlib.sha256(value).digest() for _, value in candidates}) != 1:
                    raise ValueError('missing or ambiguous inference dependency: '+soname)
                selected, value = candidates[0]
                metadata = package.elf(value, object_path=selected, details=True, private_dirs=PRIVATE_DIRS)[2]
                if metadata['soname'] not in (None, soname):
                    raise ValueError('inference SONAME differs from requested dependency')
                if selected not in data:
                    captured, source_mode = source_elf(source, selected)
                    if captured != value:
                        raise ValueError('inference dependency changed between resolution and capture')
                    data[selected] = (captured, source_mode)
                dependencies.append(selected)
            for dependency in dependencies:
                if dependency not in data:
                    data[dependency] = source_elf(source, dependency)
                queue.append(dependency)
        # The worker itself is also bound into the exact runtime descriptor.
        worker = 'usr/libexec/luma-os/luma-platform'
        data[worker] = (target.read(worker, package.MAX_ELF), 0o755)
        records = []
        for name, (value, mode) in sorted(data.items()):
            try:
                current = target.read(name, package.MAX_ELF)
            except FileNotFoundError:
                write_new(target, name, value, mode)
            else:
                if current != value:
                    raise ValueError('inference dependency conflicts with staged compute userland')
            with target.opened(name) as (_, metadata):
                executable = bool(metadata.st_mode & 0o111)
            records.append(dict(path=name, bytes=len(value), sha256=hashlib.sha256(value).hexdigest(), executable=executable))
        if not 1 <= len(records) <= 64:
            raise ValueError('final inference runtime inventory exceeds its fixed member bound')
        manifest = package.canonical(dict(schema_version=1, profile=PROFILE, files=records))
        if len(manifest) > 16384:
            raise ValueError('final inference runtime descriptor exceeds its 16-KiB transport bound')
        write_new(target, MANIFEST_PATH, manifest, 0o644)
        description = package.canonical(profile(hashlib.sha256(manifest).hexdigest()))
        if len(description) > 8192:
            raise ValueError('final inference profile exceeds its 8-KiB transport bound')
        write_new(target, PROFILE_PATH, description, 0o644)
        with model_tree.opened(Path(model_path).name) as (fd, info):
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != MODEL_BYTES:
                raise ValueError('model is not the exact bounded single-link GGUF input')
            def copy_model(output):
                digest, length = hashlib.sha256(), 0
                with os.fdopen(os.dup(fd), 'rb') as stream:
                    while block := stream.read(1024**2):
                        length += len(block)
                        if length > MODEL_BYTES:
                            raise ValueError('model grew during bounded staging')
                        digest.update(block)
                        output.write(block)
                if length != MODEL_BYTES or digest.hexdigest() != MODEL_SHA or package.identity(os.fstat(fd)) != package.identity(info):
                    raise ValueError('full model bytes or held identity differs; partial output retained')
            write_new(target, MODEL, copy_model, 0o644)
        # Reuse the pinned policy preprocessor without changing compute policy.
        spec = importlib.util.spec_from_file_location('luma_inference_hosted', HERE/'windows_hosted.py')
        hosted = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hosted)
        policy = hosted.preprocess_policy(POLICY)
        unit = hosted.UNIT.replace(b'hosted inert compute', b'hosted compact inference').replace(b'luma-hosted-compute', b'luma-hosted-inference')
        for name, value in ((POLICY, policy), (SERVICE, unit), (ENABLED, unit)):
            write_new(target, name, value, 0o644)
        return dict(schema_version=1, profile=PROFILE, model_sha256=MODEL_SHA, model_bytes=MODEL_BYTES,
            profile_sha256=hashlib.sha256(description).hexdigest(), runtime_manifest_sha256=hashlib.sha256(manifest).hexdigest(),
            runtime_files=len(records), model_runtime_installed=True, package_authenticated=False,
            guest_confinement_qualified=False, inference_executed=False, production_qualified=False, gate_closing=False)
    finally:
        for tree in (archive_tree, model_tree, source, target):
            if tree is not None:
                tree.close()


def validate(data_at, entries, tree):
    raw = data_at(PROFILE_PATH)
    description = closed(raw)
    manifest_raw = data_at(MANIFEST_PATH)
    if not 1 <= len(raw) <= 8192 or not 1 <= len(manifest_raw) <= 16384:
        raise ValueError('inference profile/runtime descriptor exceeds its fixed transport bound')
    if raw != package.canonical(profile(hashlib.sha256(manifest_raw).hexdigest())):
        raise ValueError('inference profile is not the exact approved closed CPU profile')
    manifest = closed(manifest_raw)
    if (not isinstance(manifest, dict) or set(manifest) != {'schema_version', 'profile', 'files'} or type(manifest['schema_version']) is not int
            or manifest['schema_version'] != 1 or manifest['profile'] != PROFILE
            or not isinstance(manifest['files'], list) or not 1 <= len(manifest['files']) <= 64
            or manifest_raw != package.canonical(manifest)):
        raise ValueError('inference runtime manifest is not closed and canonical')
    previous, required = None, set()
    for member in manifest['files']:
        if (not isinstance(member, dict) or set(member) != {'path', 'bytes', 'sha256', 'executable'}
                or type(member['bytes']) is not int or type(member['executable']) is not bool):
            raise ValueError('inference runtime member schema differs')
        name = package.archive_path(member['path'])
        if (previous is not None and name <= previous) or name not in entries or entries[name][0]:
            raise ValueError('inference runtime inventory order, uniqueness or membership differs')
        if (not name.startswith(PRIVATE+'/') and name != 'usr/libexec/luma-os/luma-platform'
                and not name.startswith(('lib/', 'lib64/', 'usr/lib/', 'usr/lib64/'))):
            raise ValueError('inference runtime member is outside the closed library namespaces')
        value = data_at(name)
        if len(value) != member['bytes'] or hashlib.sha256(value).hexdigest() != member['sha256']:
            raise ValueError('inference runtime member differs from full pinned bytes')
        if bool(entries[name][1] & 0o111) != member['executable']:
            raise ValueError('inference runtime executable mode differs')
        package.elf(value, object_path=name,
                    require_entry=name in ('usr/libexec/luma-os/luma-platform', PRIVATE+'/llama-completion'),
                    private_dirs=PRIVATE_DIRS)
        required.add(name)
        previous = name
    private = {name for name in entries if name.startswith(PRIVATE+'/') and not entries[name][0]}
    if private != {PRIVATE+'/'+name for name in RUNTIME_NAMES} or not private <= required:
        raise ValueError('inference private runtime contains missing or unapproved programs/plugins')
    if 'usr/libexec/luma-os/luma-platform' not in required:
        raise ValueError('inference runtime manifest omits its exact worker')
    if entries.get(MODEL, (True, 0, 0))[0] or entries[MODEL][2] != MODEL_BYTES or entries[MODEL][1] != 0o644:
        raise ValueError('inference model geometry or permissions differ')
    with tree.opened(MODEL) as (fd, _), os.fdopen(os.dup(fd), 'rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != MODEL_SHA:
            raise ValueError('inference model full SHA256 differs')
    policy = data_at(POLICY)
    if b'profile luma-hosted-inference ' not in policy or b'deny network,' not in policy:
        raise ValueError('inference policy is not the closed preprocessed enforcing profile')
    spec = importlib.util.spec_from_file_location('luma_inference_validate_hosted', HERE/'windows_hosted.py')
    hosted = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hosted)
    unit = hosted.UNIT.replace(b'hosted inert compute', b'hosted compact inference').replace(b'luma-hosted-compute', b'luma-hosted-inference')
    if data_at(SERVICE) != unit or data_at(ENABLED) != unit or hosted.unresolved_includes(policy):
        raise ValueError('inference confinement deployment differs')
    return required | {MODEL, PROFILE_PATH, MANIFEST_PATH, POLICY, SERVICE, ENABLED}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'platform', 'work-root', 'runtime', 'model'):
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--output-name', required=True)
    arguments = parser.parse_args()
    spec = importlib.util.spec_from_file_location('luma_inference_stage', HERE/'windows_stage.py')
    stage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage)
    stage.stage(arguments.root, arguments.platform, arguments.work_root, arguments.output_name, hosted_compute=True)
    result = compose(arguments.work_root/arguments.output_name/'rootfs', arguments.root, arguments.model, arguments.runtime)
    with (arguments.work_root/arguments.output_name/'inference-stage.json').open('xb') as output:
        output.write(package.canonical(result))
    print(package.canonical(result).decode(), end='')
