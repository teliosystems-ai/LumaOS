#!/usr/bin/env python3
"""Compiled CLI and real framed Unix IPC against a synthetic root authority.

Disposable network-isolated container only. A test-only preload shim supplies
the installed-slot fixture to each CLI; this is not installed-image qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading


def main():
    if os.geteuid() != 0 or not Path('/.dockerenv').is_file():
        raise SystemExit('requires a disposable root test container')
    assert 'luma.slot=a' not in Path('/proc/cmdline').read_text().split()
    preloader = Path(os.environ['TMPDIR']) / 'resource-history-cmdline-fixture.so'
    assert preloader.is_file()
    environment = dict(os.environ, LD_PRELOAD=str(preloader))
    binary = '/usr/libexec/luma-os/luma-platform'
    root = Path('/run/luma-broker')
    root.mkdir(mode=0o700)
    path = root / 'control.sock'
    # ASCII canonical archive fixture spans multiple IPC frames. No production
    # ledger or model is created or claimed by this transport-only test.
    archive = json.dumps({'schema_version': 1, 'fixture': 'x'*5000},
                         separators=(',', ':')).encode()
    digest = hashlib.sha256(archive).hexdigest()
    fault = [None]
    errors = []
    seen = []
    stop = threading.Event()

    def exact(peer, length):
        result = b''
        while len(result) < length:
            block = peer.recv(length-len(result))
            if not block:
                raise ValueError('truncated request fixture')
            result += block
        return result

    def broker(listener):
        while not stop.is_set():
            try:
                peer, _ = listener.accept()
            except socket.timeout:
                continue
            try:
                with peer:
                    peer.settimeout(3)
                    pid, uid, _ = struct.unpack('3i', peer.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    assert uid == 0 and pid > 0
                    size = struct.unpack('!I', exact(peer, 4))[0]
                    assert 0 < size <= 16384
                    request = json.loads(exact(peer, size))
                    assert request['caller'] == uid
                    assert isinstance(request['deadline'], str)
                    action = request['action']
                    seen.append((action, pid))
                    status = {'preserved': True}
                    if action == 'resource-request-export':
                        assert set(request) == {'schema_version', 'request_id', 'caller',
                            'deadline', 'action', 'batch', 'sha256', 'offset'}
                        assert request['batch'] == '1' and request['sha256'] == digest
                        offset = int(request['offset'])
                        assert str(offset) == request['offset'] and offset % 2048 == 0
                        end = min(offset+2048, len(archive))
                        status = {'batch': '1', 'sha256': digest, 'offset': str(offset),
                            'next_offset': str(end), 'total_bytes': str(len(archive)),
                            'data': archive[offset:end].decode('ascii'),
                            'worker_resources_released': False}
                        if fault[0] == 'digest':
                            status['data'] = status['data'].replace('x', 'y')
                        elif fault[0] == 'offset':
                            status['offset'] = str(offset+1)
                        elif fault[0] == 'total' and offset > 0:
                            status['total_bytes'] = str(len(archive)+1)
                        elif fault[0] == 'unknown':
                            status['unsafe'] = True
                        elif fault[0] == 'lost-page' and offset > 0:
                            continue
                    else:
                        assert action in {'resource-request-status', 'resource-request-archive',
                                          'resource-request-recovery-status', 'resource-request-recover'}
                        assert set(request) == {'schema_version', 'request_id', 'caller',
                            'deadline', 'action', 'idempotency_key', 'profile', 'lease',
                            'review', 'storage_device'}
                        assert request['review'] == ('a'*64 if action in {
                            'resource-request-archive', 'resource-request-recover'} else None)
                    response = {'schema_version': 1, 'request_id': request['request_id'],
                        'caller': uid, 'result': 'ok', 'lease': None, 'status': status}
                    if fault[0] == 'correlation':
                        response['request_id'] = 'other'
                    elif fault[0] == 'shape':
                        response['status'] = None
                    encoded = json.dumps(response).encode()
                    assert len(encoded) <= 16384
                    peer.sendall(struct.pack('!I', len(encoded))+encoded)
            except Exception as error:
                errors.append(error)
                stop.set()

    cases = 0
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen(8)
        listener.settimeout(.2)
        thread = threading.Thread(target=broker, args=(listener,))
        thread.start()
        try:
            for action in ('resource-request-status', 'resource-request-archive',
                           'resource-request-recovery-status', 'resource-request-recover'):
                args = [binary, action]
                if action in {'resource-request-archive', 'resource-request-recover'}:
                    args.append('a'*64)
                for defect in (None, 'correlation', 'shape'):
                    fault[0] = defect
                    result = subprocess.run(args, env=environment, capture_output=True, timeout=6)
                    assert not errors, errors
                    if defect is None:
                        assert result.returncode == 0, result.stderr
                        assert json.loads(result.stdout)['status'] == {'preserved': True}
                    else:
                        assert result.returncode != 0 and result.stdout == b''
                    cases += 1
            for defect in (None, 'digest', 'offset', 'total', 'unknown', 'lost-page', 'correlation'):
                fault[0] = defect
                result = subprocess.run([binary, 'resource-request-export', '1', digest],
                                        env=environment, capture_output=True, timeout=8)
                assert not errors, errors
                if defect is None:
                    assert result.returncode == 0 and result.stdout == archive, result.stderr
                else:
                    assert result.returncode != 0 and result.stdout == b'', (defect, result)
                cases += 1
            fault[0] = None
            before = len(seen)
            for batch in ('01', '0', '65'):
                result = subprocess.run([binary, 'resource-request-export', batch, digest],
                                        env=environment, capture_output=True, timeout=6)
                assert result.returncode != 0 and result.stdout == b''
                cases += 1
            result = subprocess.run([binary, 'resource-request-status'], user=989, group=989,
                                    extra_groups=[], env=environment, capture_output=True, timeout=6)
            assert result.returncode != 0 and result.stdout == b''
            assert len(seen) == before
            cases += 1
            result = subprocess.run([binary, 'resource-request-status'],
                                    capture_output=True, timeout=6)
            assert result.returncode != 0 and result.stdout == b''
            assert b'not an installed A/B system' in result.stderr
            assert len(seen) == before
            cases += 1
        finally:
            stop.set()
            thread.join(5)
            assert not thread.is_alive()
    assert not errors, errors
    path.unlink()
    root.rmdir()
    print(f'RESOURCE_HISTORY_NATIVE_CLI_UNIX_PASSED cases={cases} '
          'synthetic_authority=true test_only_cmdline_preload=true installed_image_tested=false', flush=True)


if __name__ == '__main__':
    main()
