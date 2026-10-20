#!/usr/bin/env python3
"""Build fixed speech workers inside a fresh image root before image signing.

No network, model inference or audio device is used here. Third-party source
archives and the exact auxiliary model must already be acquired by the pinned
image recipe. GPL renderer corresponding source/notices and our fixed recipe
remain in the candidate; a model's existence never supplies runtime authority.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile

ASSETS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('luma_speech_pack_layout', ASSETS/'model_layout.py')
layout = importlib.util.module_from_spec(spec); spec.loader.exec_module(layout)
INPUTS = {
    'whisper-source.tar.gz': (9631456, layout.SOURCE_SHA256),
    'model-LICENSE': (1063, 'b5d65a59060e68c4ff940e1eddfa6f94b2d68fdf58ed7f4dd57721c997e35e9d'),
    'espeak-ng_1.51+dfsg-12build1.dsc': (2731, '7d7e4f7606f1ddf3eb497a4848649eb72fc0acf70caccd9a61987f4d4444d688'),
    'espeak-ng_1.51+dfsg.orig.tar.gz': (12985129, '72242d7c06a4d80f5056335977c5be1ff79ff27bb502d4d054be1803ff787fa9'),
    'espeak-ng_1.51+dfsg-12build1.debian.tar.xz': (51348, 'ccd4411d9efe0604030c604bd7369ec19598bc4d2b6435a0782398e174c0ee54'),
}
SOURCES = ('CMakeLists.txt', 'asr_engine.cpp', 'asr_engine.h', 'asr_worker.cpp',
           'tts_engine.c', 'tts_engine.h', 'tts_worker.c')


def build_commands():
    return [
        ['/usr/bin/cmake', '-S', '/usr/src/luma-speech/controller', '-B', '/usr/src/luma-speech/build',
         '-DCMAKE_BUILD_TYPE=Release', '-DWHISPER_SOURCE=/usr/src/luma-speech/whisper/whisper.cpp-'+layout.SOURCE_COMMIT],
        ['/usr/bin/cmake', '--build', '/usr/src/luma-speech/build', '--target', 'luma-asr-worker', '--parallel', '2'],
        ['/usr/bin/cc', '-O2', '-Wall', '-Wextra', '-Werror', '-fstack-protector-strong',
         '-Wl,-z,relro,-z,now,-z,noexecstack', '/usr/src/luma-speech/controller/tts_engine.c',
         '/usr/src/luma-speech/controller/tts_worker.c', '-lespeak-ng', '-o', '/usr/src/luma-speech/build/luma-tts-render'],
    ]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, maximum):
    path = Path(path)
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError('redirected speech build input ancestor')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise ValueError('speech build input is nonregular, linked or exceeds its bound')
        data = source.read(maximum+1)
        key = lambda m: (m.st_dev, m.st_ino, m.st_mode, m.st_uid, m.st_gid, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
        if len(data) != before.st_size or key(before) != key(os.fstat(source.fileno())) or key(before) != key(path.lstat()):
            raise ValueError('speech build input changed')
        return data


def publish(path, content, mode=0o444):
    path = Path(path)
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError('redirected speech artifact ancestor')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w+b') as output:
        output.write(content); output.flush(); os.fsync(output.fileno())
        output.seek(0)
        if output.read(len(content)+1) != content:
            raise ValueError('speech artifact publication readback failed')


def package(root, work):
    root, work = Path(root), Path(work)
    if root.is_symlink() or work.is_symlink() or not root.is_dir() or not work.is_dir():
        raise ValueError('speech packaging requires actual fresh image/work roots')
    base = root/'usr/src/luma-speech'
    inputs = base/'inputs'
    for name, (size, digest) in INPUTS.items():
        data = read(inputs/name, size)
        if len(data) != size or sha(data) != digest:
            raise ValueError('pinned speech source/license mismatch: '+name)
    model_path = root/'usr/share/luma-os/speech/ggml-tiny.bin'
    descriptor = layout.inspect(model_path)
    source_dir = base/'controller'
    source_hashes = {}
    for name in SOURCES:
        data = read(ASSETS/name, 128*1024)
        publish(source_dir/name, data)
        source_hashes[name] = sha(data)
    # Preserve the exact builder, parser and unsigned metadata proposal recipe
    # as source, without placing development signing custody in the image.
    for name in ('package_runtime.py', 'model_layout.py', 'catalog.py'):
        publish(source_dir/name, read(ASSETS/name, 128*1024))
    upstream = base/'whisper'
    upstream.mkdir(mode=0o755)
    with tarfile.open(inputs/'whisper-source.tar.gz') as archive:
        members = archive.getmembers()
        if len(members) > 10000 or sum(member.size for member in members) > 100*1024*1024:
            raise ValueError('pinned Whisper source archive exceeds extraction budget')
        top = set()
        for member in members:
            parts = Path(member.name).parts
            if not parts or '..' in parts or member.name.startswith('/') or not (member.isfile() or member.isdir()):
                raise ValueError('unexpected Whisper source archive member')
            top.add(parts[0])
        if top != {'whisper.cpp-'+layout.SOURCE_COMMIT}:
            raise ValueError('Whisper source root is not the pinned commit')
        archive.extractall(upstream, filter='data')
    binary_dir = root/'usr/libexec/luma-os/speech'
    binary_dir.mkdir(parents=True, mode=0o755)
    transcript = work/'speech-runtime-build.log'
    commands = build_commands()
    with transcript.open('xb') as log:
        for command in commands:
            result = subprocess.run(['/usr/sbin/chroot', str(root), *command], stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, timeout=900, close_fds=True,
                env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'})
            if result.returncode:
                raise ValueError('fixed speech build failed; preserve its actual build transcript')
    for name in ('luma-asr-worker', 'luma-tts-render'):
        data = read(base/'build'/name, 16*1024*1024)
        if data[:7] != b'\x7fELF\x02\x01\x01':
            raise ValueError('fixed speech worker did not produce actual amd64 ELF')
        publish(binary_dir/name, data, 0o555)
    runtime = {'schema_version': 1, 'profile': 'whisper-tiny-multilingual-f16-cpu-v1',
        'runtime_source_commit': layout.SOURCE_COMMIT,
        'worker_sha256': sha(read(binary_dir/'luma-asr-worker', 16*1024*1024)),
        'engine_source_sha256': source_hashes['asr_engine.cpp'],
        'worker_source_sha256': source_hashes['asr_worker.cpp'],
        'policy_sha256': sha(layout.canonical(layout.policy())), 'memory_max_bytes': 512*1024*1024,
        'maximum_virtual_address_bytes': 1024*1024*1024,
        'tasks_max': 16, 'maximum_audio_bytes': 960000, 'maximum_decoder_tokens': 128, 'maximum_decode_seconds': 18}
    publish(root/'usr/share/luma-os/speech/runtime.json', layout.canonical(runtime))
    publish(root/'usr/share/luma-os/speech/model-layout.json', layout.canonical(descriptor))
    publish(root/'usr/share/luma-os/speech/model-LICENSE', read(inputs/'model-LICENSE', 1063))
    report = {'schema_version': 1, 'source_sha256': source_hashes,
        'input_sha256': {name: digest for name, (_size, digest) in INPUTS.items()},
        'asr_worker_sha256': runtime['worker_sha256'],
        'tts_worker_sha256': sha(read(binary_dir/'luma-tts-render', 16*1024*1024)),
        'compiler_arguments': commands, 'asr_runtime_sha256': sha(layout.canonical(runtime)),
        'tts_backend': 'espeak-ng-1.51+dfsg-12build1-synchronous-retrieval-only',
        'whisper_backend': 'v1.9.5-luma-asr-v1-amd64-sse2-cpu-only',
        'asr_model_available_by_bytes': True, 'model_authority_provisioned': False,
        'actual_asr_job_executed': False, 'audio_device_opened': False,
        'host_apparmor_qualified': False, 'production_qualified': False, 'gate_closing': False}
    publish(root/'usr/share/luma-os/speech/build-receipt.json', layout.canonical(report))
    # Compiler objects are retained under the image's corresponding-source kit:
    # users can inspect/rebuild the GPL-linked renderer against the supplied
    # exact source and ordinary Ubuntu eSpeak development package. They are not
    # model-produced code and never receive a native execution grant.
    return report


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(package(args.root, args.work), sort_keys=True))
