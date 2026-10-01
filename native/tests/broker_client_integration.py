#!/usr/bin/env python3
"""Real CLI exit/output checks against a private fixture broker, not authorization.

Use only in a new disposable container, with no host socket or device mounts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess


def receive(connection, size):
    data = b''
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise RuntimeError('client truncated its request')
        data += chunk
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not Path('/.dockerenv').is_file() or os.geteuid() != 0:
        raise SystemExit('use a disposable root container')
    output = args.output.resolve()
    if output.parent != Path('/evidence') or output.exists():
        raise SystemExit('use a new evidence directory')
    binary = args.binary.resolve(strict=True)
    directory = Path('/run/luma-broker')
    directory.mkdir(mode=0o700)  # Refuse an existing service namespace.
    output.mkdir()
    observations = []
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(directory / 'control.sock'))
        listener.listen(1)
        listener.settimeout(5)
        for case in ('success', 'denied', 'malformed', 'request-id', 'uid', 'version',
                     'authority', 'generated-code', 'extra', 'trailing', 'duplicate',
                     'truncated', 'oversized', 'empty'):
            process = subprocess.Popen([str(binary), 'status'], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env={'PATH':'/usr/bin:/bin'})
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(5)
                    size = struct.unpack('!I', receive(connection, 4))[0]
                    if not 1 <= size <= 16384:
                        raise RuntimeError('invalid outgoing CLI frame')
                    request = json.loads(receive(connection, size))
                    if request['caller'] != 0 or request['action'] != 'status':
                        raise RuntimeError('unexpected CLI request')
                    reply = {'schema_version':1, 'request_id':request['request_id'],
                             'authenticated_uid':request['caller'], 'result':'ok',
                             'implementation':'rust-native-lab', 'generated_native_code':'denied',
                             'certification_closing':False}
                    if case == 'denied':
                        reply = {'schema_version':1, 'result':'denied'}
                    elif case == 'request-id':
                        reply['request_id'] = 'different-request'
                    elif case == 'uid':
                        reply['authenticated_uid'] = 990
                    elif case == 'version':
                        reply['schema_version'] = 2
                    elif case == 'authority':
                        reply['certification_closing'] = True
                    elif case == 'generated-code':
                        reply['generated_native_code'] = 'allowed'
                    elif case == 'extra':
                        reply['extra'] = 'private-fixture-peer-payload'
                    payload = json.dumps(reply).encode()
                    if case == 'malformed':
                        payload = b'private-fixture-peer-payload'
                    elif case == 'trailing':
                        payload += b'\n{}'
                    elif case == 'duplicate':
                        payload = b'{"result":"ok",' + payload[1:]
                    elif case == 'empty':
                        payload = b''
                    frame = struct.pack('!I', len(payload)) + payload
                    if case == 'truncated':
                        frame = frame[:-1]
                    elif case == 'oversized':
                        frame = struct.pack('!I', 16385)
                    connection.sendall(frame)
                stdout, stderr = process.communicate(timeout=10)
                if case == 'success':
                    if process.returncode != 0 or json.loads(stdout) != reply or stderr:
                        raise RuntimeError('valid broker reply did not yield exact CLI success')
                elif process.returncode != 1 or stdout or not stderr.startswith(b'luma-platform: '):
                    raise RuntimeError('denied/malformed broker reply appeared successful: ' + case)
                if b'private-fixture-peer-payload' in stdout + stderr:
                    raise RuntimeError('unvalidated peer payload leaked to CLI output')
                observations.append({'case':case, 'exit_code':process.returncode,
                                     'success_output':bool(stdout)})
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=10)
    record = {'result':'passed', 'cases':observations,
              'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
              'real_broker_authorization_tested':False, 'image_tested':False,
              'physical_hardware_tested':False, 'gate_closing':False}
    (output / 'result.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(record), flush=True)


if __name__ == '__main__':
    main()
