#!/usr/bin/env python3
"""Derive lossless native sidecars from an exact compiled, digest-pinned GGUF.

This reads data only. It neither executes models nor signs/certifies a pack.
The destination must not exist; source weights are never changed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

MAX_METADATA = 64 * 1024 * 1024
MAX_RAW = 7 * 1024 * 1024
SCALARS = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 10: 8, 11: 8, 12: 8}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


class Metadata:
    def __init__(self, stream, bound):
        self.stream = stream
        self.bound = bound
        self.position = 0

    def read(self, count):
        if count < 0 or self.position + count > self.bound:
            raise ValueError('GGUF metadata exceeds bounded file prefix')
        result = self.stream.read(count)
        if len(result) != count:
            raise ValueError('truncated GGUF metadata')
        self.position += count
        return result

    def integer(self, size):
        return int.from_bytes(self.read(size), 'little')

    def text(self, maximum=65536):
        length = self.integer(8)
        if length > maximum:
            raise ValueError('GGUF metadata string exceeds bound')
        return self.read(length).decode('utf-8', errors='strict')

    def value(self, kind):
        if kind == 8:
            return self.text()
        if kind == 7:
            if self.integer(1) > 1:
                raise ValueError('invalid GGUF boolean')
            return None
        if kind == 9:
            element = self.integer(4)
            count = self.integer(8)
            if count > 1_048_576 or element == 9 or element not in SCALARS and element not in (7, 8):
                raise ValueError('unsupported or oversized GGUF metadata array')
            if element in (7, 8):
                for _ in range(count):
                    self.value(element)
            else:
                self.read(count * SCALARS[element])
            return None
        if kind not in SCALARS:
            raise ValueError('unknown GGUF metadata scalar type')
        raw = self.read(SCALARS[kind])
        return int.from_bytes(raw, 'little') if kind == 4 else None


def extract(stream, size, profile):
    stream.seek(0)
    meta = Metadata(stream, min(size, MAX_METADATA))
    if meta.read(4) != b'GGUF' or meta.integer(4) != 3:
        raise ValueError('native sidecars require GGUF v3')
    tensors, count = meta.integer(8), meta.integer(8)
    if not 1 <= tensors <= 8192 or not 1 <= count <= 4096:
        raise ValueError('GGUF tensor/metadata counts exceed bound')
    seen, entries, shape = set(), [], {}
    template = None
    raw_total = 0
    for _ in range(count):
        key = meta.text(512)
        if not key or '\0' in key or key in seen:
            raise ValueError('empty, duplicate or unsafe GGUF key')
        seen.add(key)
        kind = meta.integer(4)
        start = meta.position
        value = meta.value(kind)
        end = meta.position
        if key == 'general.architecture' or key.startswith('qwen3.'):
            shape[key] = (kind, value)
        if key.startswith('split.') or 'sliding_window' in key or key.endswith('_swa') \
                or 'recurrent' in key or 'expert' in key:
            raise ValueError('unsupported GGUF runtime shape')
        if key == 'tokenizer.chat_template':
            if kind != 8 or not value:
                raise ValueError('GGUF chat template must be nonempty UTF8 text')
            template = value.encode('utf-8')
        elif key.startswith('tokenizer.'):
            if key == 'tokenizer.ggml.model' and (kind != 8 or value != 'gpt2'):
                raise ValueError('native embedded tokenizer model must be gpt2')
            raw_total += end - start
            if raw_total > MAX_RAW:
                raise ValueError('native tokenizer raw bytes exceed bound')
            stream.seek(start)
            raw = stream.read(end - start)
            if len(raw) != end - start:
                raise ValueError('GGUF changed while capturing tokenizer value')
            stream.seek(end)
            if key == 'tokenizer.ggml.tokens' and (kind != 9 or len(raw) < 12
                    or int.from_bytes(raw[:4], 'little') != 8 or int.from_bytes(raw[4:12], 'little') == 0):
                raise ValueError('native tokenizer tokens must be nonempty GGUF string array')
            entries.append({'key': key, 'type': kind, 'value_hex': raw.hex()})
    if shape.get('general.architecture') != (8, 'qwen3'):
        raise ValueError('GGUF architecture differs from compiled native model')
    layout = profile['layout']
    for key, value in (('block_count', layout['layers']), ('embedding_length', layout['embedding']),
                       ('attention.head_count', layout['attention_heads']),
                       ('attention.head_count_kv', layout['kv_heads']),
                       ('context_length', layout['training_context'])):
        if shape.get('qwen3.' + key) != (4, value):
            raise ValueError('GGUF runtime layout differs from compiled native model')
    for key, value in (('attention.key_length', layout['key_width']), ('attention.value_length', layout['value_width'])):
        actual = shape.get('qwen3.' + key, (4, layout['embedding'] // layout['attention_heads']))
        if actual != (4, value):
            raise ValueError('GGUF cache width differs from compiled native model')
    if not {'tokenizer.ggml.model', 'tokenizer.ggml.tokens'} <= {v['key'] for v in entries} or template is None:
        raise ValueError('GGUF lacks required embedded tokenizer/template metadata')
    tokenizer = canonical({'format': 'gguf-tokenizer-metadata-v1', 'schema_version': 1,
                           'entries': sorted(entries, key=lambda v: v['key'])})
    if len(tokenizer) > 16 * 1024 * 1024:
        raise ValueError('native tokenizer JSON exceeds bound')
    return tokenizer, template


def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns,
            meta.st_mode, meta.st_uid, meta.st_nlink)


def derive(weights, profile_id, destination):
    profiles = json.loads(Path(__file__).with_name('model-catalog.json').read_bytes())['models']
    profile = next((p for p in profiles if p['id'] == profile_id), None)
    if profile is None:
        raise ValueError('only exact compiled native profiles can produce sidecars')
    path = Path(weights)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != profile['bytes']:
            raise ValueError('weights are not exact single-link regular compiled model bytes')
        if hashlib.file_digest(stream, 'sha256').hexdigest() != profile['sha256']:
            raise ValueError('weights digest differs from pinned compiled native profile')
        tokenizer, template = extract(stream, before.st_size, profile)
        if identity(os.fstat(stream.fileno())) != identity(before) or identity(path.lstat()) != identity(before):
            raise ValueError('weights changed during sidecar extraction')
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    results = {}
    for role, value in (('tokenizer', tokenizer), ('template', template)):
        digest = hashlib.sha256(value).hexdigest()
        target = destination / 'blobs/sha256' / digest
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open('xb') as output:
            output.write(value); output.flush(); os.fsync(output.fileno())
        results[role] = {'role': role, 'path': 'blobs/sha256/' + digest,
                         'sha256': digest, 'size_bytes': len(value)}
    return {'schema_version': 1, 'profile': profile_id, 'weights_sha256': profile['sha256'],
            'sidecars': results, 'signed': False, 'certified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--weights', type=Path, required=True)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(derive(args.weights, args.profile, args.destination), sort_keys=True))
