#!/usr/bin/env python3
"""Acquire exact public speech build inputs without executing any download."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import ssl
import stat
import time
import urllib.request

ASSETS = Path(__file__).resolve().parent/'speech'
SPEC = importlib.util.spec_from_file_location('luma_speech_input_recipe', ASSETS/'package_runtime.py')
recipe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recipe)
SNAPSHOT = 'https://snapshot.ubuntu.com/ubuntu/20260927T000000Z/pool/universe/e/espeak-ng/'
URLS = {name: SNAPSHOT+name for name in recipe.INPUTS if name.startswith('espeak-ng_')}
URLS['whisper-source.tar.gz'] = 'https://codeload.github.com/ggml-org/whisper.cpp/tar.gz/'+recipe.layout.SOURCE_COMMIT
URLS['ggml-tiny.bin'] = recipe.layout.MODEL_URL


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith('https://'):
            raise ValueError('speech input redirects must remain HTTPS')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid,
        metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def local(path):
    path = Path(path)
    if path.resolve(strict=True) != path:
        raise ValueError('cached speech input must have an exact nonredirected absolute path')
    fd = os.open(path, os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        os.close(fd)
        raise ValueError('cached speech input must be regular and single-linked')
    return os.fdopen(fd, 'rb'), metadata


def deliver(source, target, size, expected):
    """Preserve partial failures for inspection; never overwrite or execute."""
    digest, total, deadline = hashlib.sha256(), 0, time.monotonic()+300
    with target.open('xb') as destination:
        while True:
            data = source.read(min(1024*1024, size+1-total))
            if not data:
                break
            total += len(data)
            if total > size or time.monotonic() >= deadline:
                raise ValueError('speech input size/time budget exceeded')
            digest.update(data)
            destination.write(data)
        destination.flush()
        os.fsync(destination.fileno())
    if total != size or digest.hexdigest() != expected:
        raise ValueError('speech input bytes/digest differ; failed input retained, no executable was run')


def prepare(output, cached=None):
    output = Path(output)
    if output.resolve(strict=True) != output or not output.is_dir():
        raise ValueError('speech acquisition needs the existing exact runtime context')
    if cached is not None:
        cached = Path(cached)
        if cached.resolve(strict=True) != cached or not cached.is_dir():
            raise ValueError('speech cache must be an exact nonredirected directory')
    root = output/'speech'
    root.mkdir(mode=0o755)
    (root/'inputs').mkdir(mode=0o755)
    inputs = dict(recipe.INPUTS)
    inputs['ggml-tiny.bin'] = (recipe.layout.MODEL_BYTES, recipe.layout.MODEL_SHA256)
    opener = urllib.request.build_opener(HTTPSRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    for name, (size, digest) in inputs.items():
        target = root/name if name == 'ggml-tiny.bin' else root/'inputs'/name
        path = cached/name if cached is not None else ASSETS/'WHISPER-MODEL-LICENSE' if name == 'model-LICENSE' else None
        if path is not None:
            source, before = local(path)
            with source:
                if before.st_size != size:
                    raise ValueError('cached speech input has the wrong exact size')
                deliver(source, target, size, digest)
                if identity(before) != identity(os.fstat(source.fileno())) or identity(before) != identity(path.lstat()):
                    raise ValueError('cached speech input changed during acquisition')
        else:
            with opener.open(URLS[name], timeout=30) as source:
                if not source.geturl().startswith('https://'):
                    raise ValueError('speech input source is not HTTPS')
                deliver(source, target, size, digest)
    return {'schema_version': 1, 'status': 'exact-public-inputs-acquired',
        'sha256': {name: digest for name, (_size, digest) in inputs.items()},
        'code_executed': False, 'model_authority_provisioned': False, 'installed_qualified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cached-directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output, args.cached_directory), sort_keys=True), flush=True)
