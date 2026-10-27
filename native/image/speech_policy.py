"""Closed image prerequisites and exact source-bound speech runtime inventory."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

ASSETS = Path(__file__).parent
spec = importlib.util.spec_from_file_location('luma_image_speech_layout', ASSETS/'speech/model_layout.py')
layout = importlib.util.module_from_spec(spec); spec.loader.exec_module(layout)
spec = importlib.util.spec_from_file_location('luma_image_speech_builder', ASSETS/'speech/package_runtime.py')
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
PROFILE = 'whisper-tiny-multilingual-f16-cpu-v1'
PACKAGES = ('libespeak-ng1=1.51+dfsg-12build1', 'espeak-ng-data=1.51+dfsg-12build1',
            'libespeak-ng-dev=1.51+dfsg-12build1', 'g++', 'cmake', 'make')
REQUIRED = ('usr/libexec/luma-os/workspace_speech.py', 'usr/libexec/luma-os/speech/luma-tts-render',
    'usr/libexec/luma-os/speech/luma-asr-worker', 'usr/share/luma-os/speech/runtime.json',
    'usr/share/luma-os/speech/model-layout.json', 'usr/share/luma-os/speech/build-receipt.json',
    'usr/share/luma-os/speech/model-LICENSE', 'usr/share/luma-os/speech/ggml-tiny.bin',
    'usr/lib/x86_64-linux-gnu/espeak-ng-data/en_dict',
    'etc/apparmor.d/luma-workspace-speech', 'etc/apparmor.d/luma-speech-asr',
    'usr/bin/aa-exec', 'usr/bin/python3.12',
    'usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstapp.so',
    'usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstpulseaudio.so')


def read(path, maximum=128*1024*1024):
    path = Path(path)
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError('redirected packaged speech ancestor')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise ValueError('nonregular, linked, empty or oversized packaged speech input')
        data = source.read(maximum+1)
        key = lambda m: (m.st_dev, m.st_ino, m.st_mode, m.st_uid, m.st_gid, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
        if len(data) != before.st_size or key(before) != key(os.fstat(source.fileno())) or key(before) != key(path.lstat()):
            raise ValueError('packaged speech input changed during verification')
        return data


def digest(path):
    return hashlib.sha256(read(path)).hexdigest()


def protected(root, path):
    root, path = Path(root).absolute(), Path(path).absolute()
    if not path.is_relative_to(root) or root.is_symlink():
        raise ValueError('speech image input escapes its actual root')
    for at in (path, *path.parents):
        info = at.lstat()
        expected = stat.S_ISREG(info.st_mode) if at == path else stat.S_ISDIR(info.st_mode)
        if not expected or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o7022:
            raise ValueError('speech image input or ancestor is not root-protected')
        if at == root:
            break


def validate_report(report):
    report_keys = {'schema_version', 'source_sha256', 'input_sha256', 'asr_worker_sha256',
        'tts_worker_sha256', 'compiler_arguments', 'asr_runtime_sha256', 'tts_backend',
        'whisper_backend', 'asr_model_available_by_bytes', 'model_authority_provisioned',
        'actual_asr_job_executed', 'audio_device_opened', 'host_apparmor_qualified',
        'production_qualified', 'gate_closing'}
    if not isinstance(report, dict) or set(report) != report_keys or type(report['schema_version']) is not int or report['schema_version'] != 1:
        raise ValueError('speech build receipt is not the exact closed schema')
    if not isinstance(report['source_sha256'], dict) or set(report['source_sha256']) != set(builder.SOURCES) or not isinstance(report['input_sha256'], dict) or set(report['input_sha256']) != set(builder.INPUTS):
        raise ValueError('speech build receipt omitted or added corresponding-source/input pins')
    if report['asr_model_available_by_bytes'] is not True or any(report[key] is not False for key in ('model_authority_provisioned', 'actual_asr_job_executed', 'audio_device_opened', 'host_apparmor_qualified', 'production_qualified', 'gate_closing')):
        raise ValueError('speech build receipt invents runtime or production qualification')
    if report['tts_backend'] != 'espeak-ng-1.51+dfsg-12build1-synchronous-retrieval-only' or report['whisper_backend'] != 'v1.9.5-luma-asr-v1-amd64-sse2-cpu-only':
        raise ValueError('speech build receipt backend differs from fixed recipe')
    if report['compiler_arguments'] != builder.build_commands():
        raise ValueError('speech build receipt commands differ from fixed image recipe')
    if report['input_sha256'] != {name: expected_hash for name, (_size, expected_hash) in builder.INPUTS.items()}:
        raise ValueError('speech build receipt does not pin exact acquired source inputs')
    if report['source_sha256'] != {name: digest(ASSETS/'speech'/name) for name in builder.SOURCES}:
        raise ValueError('speech build receipt does not pin exact reviewed controller sources')


def verify(root):
    root = Path(root)
    for name in REQUIRED:
        protected(root, root/name)
        read(root/name)
    for name in ('luma-workspace-speech', 'luma-speech-asr'):
        if read(root/'etc/apparmor.d'/name) != read(ASSETS/'overlay/etc/apparmor.d'/name):
            raise ValueError('speech confinement differs from reviewed source: '+name)
    if read(root/REQUIRED[0]) != read(ASSETS.parent/'desktop/workspace_speech.py'):
        raise ValueError('speech controller differs from reviewed source')
    profile = json.loads(read(root/'usr/share/luma-os/speech/runtime.json'))
    report = json.loads(read(root/'usr/share/luma-os/speech/build-receipt.json'))
    validate_report(report)
    expected = {'schema_version': 1, 'profile': PROFILE, 'runtime_source_commit': layout.SOURCE_COMMIT,
        'worker_sha256': digest(root/'usr/libexec/luma-os/speech/luma-asr-worker'),
        'engine_source_sha256': digest(ASSETS/'speech/asr_engine.cpp'),
        'worker_source_sha256': digest(ASSETS/'speech/asr_worker.cpp'),
        'policy_sha256': hashlib.sha256(layout.canonical(layout.policy())).hexdigest(),
        'memory_max_bytes': 512*1024*1024, 'tasks_max': 16, 'maximum_audio_bytes': 960000,
        'maximum_virtual_address_bytes': 1024*1024*1024,
        'maximum_decoder_tokens': 128, 'maximum_decode_seconds': 18}
    if profile != expected or report['asr_worker_sha256'] != expected['worker_sha256'] or report['asr_runtime_sha256'] != digest(root/'usr/share/luma-os/speech/runtime.json') or report['tts_worker_sha256'] != digest(root/'usr/libexec/luma-os/speech/luma-tts-render'):
        raise ValueError('speech worker/runtime source and artifact pins differ')
    for name, value in report['source_sha256'].items():
        protected(root, root/'usr/src/luma-speech/controller'/name)
        if name not in ('CMakeLists.txt', 'asr_engine.cpp', 'asr_engine.h', 'asr_worker.cpp', 'tts_engine.c', 'tts_engine.h', 'tts_worker.c') or value != digest(ASSETS/'speech'/name) or value != digest(root/'usr/src/luma-speech/controller'/name):
            raise ValueError('speech installed corresponding source differs from actual build')
    descriptor = layout.inspect(root/'usr/share/luma-os/speech/ggml-tiny.bin')
    if json.loads(read(root/'usr/share/luma-os/speech/model-layout.json')) != descriptor:
        raise ValueError('ASR layout receipt differs from actual embedded tokenizer/tensor closure')
    inputs = root/'usr/src/luma-speech/inputs'
    for name, value in report['input_sha256'].items():
        protected(root, inputs/name)
        size, expected_digest = builder.INPUTS[name]
        if value != expected_digest or len(read(inputs/name, size)) != size or digest(inputs/name) != value:
            raise ValueError('speech redistributed corresponding source/input changed')
    return {'profile': PROFILE, 'tts_rule_based_render_available': True, 'asr_runtime_and_weight_present': True,
        'native_finite_infer_required': True, 'selected_text_model_dependency': False,
        'initial_decoder_language': 'en', 'language_accuracy_qualified': False,
        'capture_model_submission_automatic': False, 'audio_device_permission_qualified': False,
        'host_apparmor_qualified': False, 'model_authority_provisioned': False,
        'production_qualified': False, 'gate_closing': False}
