#!/usr/bin/env python3
"""Check production command parsing in the exact pinned CPU runtime, without loading a model."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile


def options(source):
    serve = source.split('pub fn serve()')[1].split('#[cfg(test)]')[0]
    match = re.search(r'command\s*\.args\(\[\s*(.*?)\s*\]\)', serve, re.S)
    if match is None:
        raise ValueError('production runtime argument list unavailable')
    fixed = {'&descriptor': '/nonexistent-luma-runtime-contract.gguf',
             '&p.id': 'qwen3-4b-q4-k-m',
             '&p.context_tokens.to_string()': '2048'}
    arguments = []
    for line in match[1].splitlines():
        expression = line.strip().removesuffix(',')
        if expression in fixed:
            arguments.append(fixed[expression])
        elif expression.startswith('"'):
            value = json.loads(expression)
            if not isinstance(value, str):
                raise ValueError('non-string runtime argument')
            arguments.append(value)
        else:
            raise ValueError('unreviewed runtime argument expression')
    if not arguments or len(arguments) > 128:
        raise ValueError('runtime argument bound exceeded')
    return arguments


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    lock = json.loads((args.repository/'native/image/runtime-lock.json').read_text())
    if args.archive.is_symlink() or not args.archive.is_file() or args.archive.stat().st_size != lock['bytes']:
        raise ValueError('runtime archive is not the exact bounded regular input')
    with args.archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if args.archive.stat().st_size != lock['bytes'] or digest != lock['sha256']:
        raise ValueError('runtime archive differs from captured lock')
    args.output.mkdir(mode=0o700)
    members = []
    total = 0
    names = set()
    with tarfile.open(args.archive, 'r:gz') as archive:
        for index, member in enumerate(archive):
            if index >= 256:
                raise ValueError('runtime archive entry bound exceeded')
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not path.parts:
                raise ValueError('unsafe runtime archive path')
            if len(path.parts) == 1 and member.isdir():
                continue
            if len(path.parts) != 2:
                raise ValueError('unsupported runtime archive layout')
            name = path.parts[1]
            # Match image packaging: never install either RPC executable/backend.
            if name in ('libggml-rpc.so', 'ggml-rpc-server'):
                continue
            if name != 'llama-server' and not re.fullmatch(r'lib[\w.+-]+\.so(?:\.[0-9]+)*', name):
                continue
            if name in names or not (member.isfile() or member.issym()):
                raise ValueError('duplicate or unsafe runtime member')
            if member.issym() and (PurePosixPath(member.linkname).name != member.linkname
                                   or not re.fullmatch(r'lib[\w.+-]+\.so(?:\.[0-9]+)*', member.linkname)
                                   or member.linkname == 'libggml-rpc.so'):
                raise ValueError('runtime library link escapes reviewed files')
            total += member.size
            if total > 128 * 1024 * 1024:
                raise ValueError('runtime extraction bound exceeded')
            names.add(name)
            member.name = name
            members.append(member)
        if 'llama-server' not in names:
            raise ValueError('pinned runtime executable missing')
        archive.extractall(args.output, members=members, filter='data')
    command = options((args.repository/'rust/luma-platform/src/model.rs').read_text())
    key_index = command.index('--api-key-file') + 1
    if command[key_index] != '/var/lib/luma-os/model-auth/api-key':
        raise ValueError('unexpected production credential argument')
    # The actual parser reads this file even with --help. Supply a private,
    # disposable, non-production fixture; no model or listener is started.
    key = args.output/'parser-test-api-key'
    with key.open('x') as stream:
        stream.write('a' * 64)
    key.chmod(0o600)
    command[key_index] = str(key)
    environment = {'PATH': '/usr/bin', 'LC_ALL': 'C', 'LD_LIBRARY_PATH': str(args.output)}
    executable = args.output/'llama-server'
    negative = subprocess.run([str(executable), '--luma-unknown-contract-option', *command, '--help'],
                              env=environment, capture_output=True, timeout=15)
    positive = subprocess.run([str(executable), *command, '--help'],
                              env=environment, capture_output=True, timeout=15)
    for result in (negative, positive):
        if len(result.stdout) + len(result.stderr) > 256 * 1024:
            raise ValueError('runtime parser output exceeds bound')
    if negative.returncode == 0 or b'invalid argument' not in negative.stderr.lower():
        raise ValueError('negative parser control did not reject the unknown option')
    if positive.returncode != 0:
        raise ValueError('pinned runtime rejected production options: '+positive.stderr.decode('utf-8', 'replace')[:4096])
    print(json.dumps({'runtime_sha256': digest, 'release': lock['release'],
                      'production_argument_count': len(command), 'positive_exit': positive.returncode,
                      'negative_control_exit': negative.returncode,
                      'model_loaded': False, 'installed_enforcement_qualified': False}), flush=True)


if __name__ == '__main__':
    main()
