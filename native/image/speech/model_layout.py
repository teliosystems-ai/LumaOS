"""Exact initial ASR adapter: pinned multilingual Whisper tiny GGML/F16.

This is not GGUF, a chat model, or an execution qualification. It validates the
embedded mel filters, tokenizer bytes and complete supported tensor namespace
before creating metadata consumed by the signed auxiliary-model pack builder.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

MODEL_BYTES = 77691713
MODEL_SHA256 = 'be07e048e1e599ad46341c8d2a135645097a538221678b7acdd1b1919c6e1b21'
SOURCE_COMMIT = 'd1be6fde11ac6e0407606b4e42fe72d34add8037'
SOURCE_SHA256 = '645445da884df6dbd52b30f82d7be7c01d1767c938714e477e786b88d529e9f4'
MODEL_REVISION = '5359861c739e955e79d9a303bcbc70fb988958b1'
MODEL_URL = ('https://huggingface.co/ggerganov/whisper.cpp/resolve/'
             + MODEL_REVISION + '/ggml-tiny.bin')
VOCAB_SHA256 = '358bdf83c2253dea0c8a1749f5288d96d2b6f5f4119faee9e5e26611a8c8f17b'
PARAMETERS = 37760640


def tokenizer():
    return {'kind': 'embedded-whisper-multilingual-vocabulary-v1',
            'model_sha256': MODEL_SHA256, 'offset': 64376, 'size_bytes': 508089,
            'sha256': VOCAB_SHA256, 'stored_tokens': 50257,
            'runtime_vocabulary_size': 51865,
            'generated_special_tokens_runtime_commit': SOURCE_COMMIT}


def policy():
    return {'schema_version': 1, 'profile': 'whisper-tiny-multilingual-f16-cpu-v1',
            'runtime_source_commit': SOURCE_COMMIT, 'input_encoding': 'S16LE',
            'channels': 1, 'sample_rate': 16000, 'maximum_seconds': 30,
            'maximum_pcm_bytes': 960000, 'translation': False, 'language': 'en',
            'maximum_decoder_tokens': 128, 'maximum_text_bytes': 8192,
            'cpu_threads': 2, 'maximum_decode_seconds': 18,
            'physical_memory_max_bytes': 512*1024*1024,
            'maximum_virtual_address_bytes': 1024*1024*1024,
            'review_before_model_handoff': True, 'automatic_model_handoff': False}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def tensors():
    result = {
        'decoder.positional_embedding': (0, (384, 448)),
        'encoder.positional_embedding': (0, (384, 1500)),
        'decoder.token_embedding.weight': (1, (384, 51865)),
        'encoder.conv1.weight': (1, (3, 80, 384)),
        'encoder.conv1.bias': (0, (1, 384)),
        'encoder.conv2.weight': (1, (3, 384, 384)),
        'encoder.conv2.bias': (0, (1, 384)),
    }
    for name in ('decoder.ln', 'encoder.ln_post'):
        for suffix in ('weight', 'bias'):
            result[name+'.'+suffix] = (0, (384,))
    for system in ('encoder', 'decoder'):
        for layer in range(4):
            prefix = system+'.blocks.'+str(layer)+'.'
            for norm in ('mlp_ln', 'attn_ln') + (('cross_attn_ln',) if system == 'decoder' else ()):
                for suffix in ('weight', 'bias'):
                    result[prefix+norm+'.'+suffix] = (0, (384,))
            for key, value in {'mlp.0.weight': (1, (384, 1536)),
                               'mlp.0.bias': (0, (1536,)),
                               'mlp.2.weight': (1, (1536, 384)),
                               'mlp.2.bias': (0, (384,))}.items():
                result[prefix+key] = value
            for attention in ('attn',) + (('cross_attn',) if system == 'decoder' else ()):
                for projection in ('query', 'key', 'value', 'out'):
                    result[prefix+attention+'.'+projection+'.weight'] = (1, (384, 384))
                    if projection != 'key':
                        result[prefix+attention+'.'+projection+'.bias'] = (0, (384,))
    if len(result) != 167:
        raise ValueError('internal ASR tensor namespace is inconsistent')
    return result


def inspect(path):
    path = Path(path)
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError('redirected ASR model ancestor')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    source = os.fdopen(fd, 'rb')
    before = os.fstat(source.fileno())
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != MODEL_BYTES:
        source.close()
        raise ValueError('ASR weights require the exact supported multilingual tiny blob')
    expected, observed, parameters = tensors(), {}, 0
    with source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
        if digest != MODEL_SHA256:
            raise ValueError('ASR model blob is not the pinned exact digest')
        source.seek(0)
        def read(size):
            value = source.read(size)
            if len(value) != size:
                raise ValueError('truncated ASR model')
            return value
        if struct.unpack('<12i', read(48)) != (0x67676d6c, 51865, 1500, 384, 6, 4, 448, 384, 6, 4, 80, 1):
            raise ValueError('unsupported ASR model header')
        if struct.unpack('<ii', read(8)) != (80, 201):
            raise ValueError('unsupported ASR mel-filter shape')
        mel = read(80*201*4)
        if any(not -1000 < value < 1000 for value in struct.unpack('<16080f', mel)):
            raise ValueError('nonfinite or unbounded ASR mel-filter coefficients')
        vocabulary = bytearray(read(4))
        if struct.unpack('<i', vocabulary)[0] != 50257:
            raise ValueError('unsupported embedded ASR vocabulary count')
        for _ in range(50257):
            length = read(4)
            size, = struct.unpack('<I', length)
            if size > 33:
                raise ValueError('unsupported embedded ASR token bound')
            vocabulary.extend(length)
            vocabulary.extend(read(size))
        if source.tell() != 572465 or hashlib.sha256(vocabulary).hexdigest() != VOCAB_SHA256:
            raise ValueError('embedded ASR vocabulary differs from exact supported tokenizer')
        while source.tell() < MODEL_BYTES:
            dimensions, length, kind = struct.unpack('<iii', read(12))
            if not 1 <= dimensions <= 3 or not 1 <= length <= 96 or kind not in (0, 1):
                raise ValueError('unsupported ASR tensor metadata')
            shape = struct.unpack('<'+'i'*dimensions, read(dimensions*4))
            name = read(length).decode('ascii', 'strict')
            if name not in expected or name in observed or expected[name] != (kind, shape):
                raise ValueError('ASR tensor duplicate, namespace, dtype or shape mismatch')
            elements = 1
            for dimension in shape:
                elements *= dimension
            size = elements*(4 if kind == 0 else 2)
            if source.tell()+size > MODEL_BYTES:
                raise ValueError('ASR tensor extent exceeds exact model size')
            source.seek(size, 1)
            parameters += elements
            observed[name] = {'dtype': 'F32' if kind == 0 else 'F16', 'shape': list(shape)}
        if observed.keys() != expected.keys() or parameters != PARAMETERS or source.tell() != MODEL_BYTES:
            raise ValueError('incomplete ASR tensor closure')
        key = lambda m: (m.st_dev, m.st_ino, m.st_mode, m.st_uid, m.st_gid, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
        if key(before) != key(os.fstat(source.fileno())) or key(before) != key(path.lstat()) or any(parent.is_symlink() for parent in path.parents):
            raise ValueError('ASR model bytes or namespace changed during exact validation')
    return {'schema_version': 1, 'architecture': 'whisper-tiny-multilingual',
            'container': 'whisper-ggml-v1', 'quantization': 'mixed-F16-F32',
            'model_sha256': digest, 'model_size_bytes': MODEL_BYTES,
            'tensor_count': len(observed), 'stored_scalar_parameters': parameters,
            'tensor_layout_sha256': hashlib.sha256(canonical(observed)).hexdigest(),
            'tokenizer': tokenizer(),
            'runtime_source_commit': SOURCE_COMMIT,
            'input': {'encoding': 'S16LE', 'channels': 1, 'sample_rate': 16000,
                      'maximum_seconds': 30, 'maximum_pcm_bytes': 960000},
            'decoding': {'translation': False, 'language': 'en', 'maximum_decoder_tokens': 128,
                         'maximum_text_bytes': 8192, 'cpu_threads': 2},
            'languages': {'initial_product_profile': ['en'],
                          'other_multilingual_decoders_enabled': False,
                          'accuracy_qualification_asserted': False}}
