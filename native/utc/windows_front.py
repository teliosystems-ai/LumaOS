"""Unprivileged fixed HTTPS transport for independently signed protected UTC.

This process has no time authority, signing key, TPM, Admin journal or grants.
It never reads local UTC. Deadlines below are observed monotonic I/O budgets,
not a hard realtime guarantee for synchronous TLS/filesystem/kernel calls.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import struct
import sys
import time

UID = 985
CONFIG = Path('/etc/luma-os/utc-windows/transport.json')
CERT = CONFIG.parent / 'certificate.pem'
KEY = CONFIG.parent / 'private-key.pem'
MANIFEST = Path('/usr/share/luma-os/utc/windows-transport.json')
SOCKET = '/run/luma-utc-windows/control.sock'
ROUTE = '/luma/utc/v1'
PORT = 8443
CHALLENGE = b'luma-windows-hosted-utc-challenge-v1'
DELIVERY = b'luma-windows-hosted-utc-delivery-v1'
PROOF = b'luma-windows-hosted-utc-v1'
MAX_HEADER = 4096
MAX_RESPONSE = 12288


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate transport configuration field')
        result[key] = value
    return result


def canonical(data):
    value = json.loads(data.decode('utf-8', errors='strict'), object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    if json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode() != data:
        raise ValueError('noncanonical transport configuration')
    return value


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def protected(path, maximum, private=False):
    """Read a fixed bounded pinned file; no alias, writable ancestor or secret log."""
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('transport input must have exact nonaliased path')
    for parent in path.parents:
        info = parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('transport ancestor protection differs')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & 0o7022 or not 0 < before.st_size <= maximum
                or private and (before.st_gid != UID or stat.S_IMODE(before.st_mode) != 0o640)):
            raise ValueError('transport fixed file protections/bounds differ')
        result = bytearray()
        while len(result) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(result)))
            if not block:
                break
            result.extend(block)
        if (len(result) != before.st_size or len(result) > maximum
                or identity(before) != identity(os.fstat(descriptor))
                or identity(before) != identity(path.stat(follow_symlinks=False))):
            raise ValueError('transport fixed file changed during read')
        return bytes(result), identity(before)
    finally:
        os.close(descriptor)


def challenge(value):
    prefix = struct.pack('>I', len(CHALLENGE)) + CHALLENGE
    if (not isinstance(value, bytes) or len(value) != len(prefix) + 96
            or not value.startswith(prefix)
            or any(not any(value[start:start + 32]) for start in range(len(prefix), len(value), 32))):
        raise ValueError('fixed nonzero Windows UTC challenge required')
    return value


def delivery(value, original):
    """Transport shape/binding only; Windows independently verifies P256 proof."""
    challenge(original)
    prefix = struct.pack('>I', len(DELIVERY)) + DELIVERY
    proof_prefix = struct.pack('>I', len(PROOF)) + PROOF
    size = len(proof_prefix) + 112
    if (not isinstance(value, bytes) or len(value) != len(prefix) + 4 + size + 64
            or not value.startswith(prefix) or value[len(prefix):len(prefix) + 4] != struct.pack('>I', size)):
        raise ValueError('fixed bounded UTC delivery required')
    proof = value[len(prefix) + 4:-64]
    if (not proof.startswith(proof_prefix)
            or proof[len(proof_prefix):len(proof_prefix) + 96] != original[-96:]):
        raise ValueError('UTC delivery challenge substitution refused')
    lower, upper = struct.unpack('>QQ', proof[-16:])
    if not 0 < lower <= upper <= 4102444800000 or upper - lower > 10000:
        raise ValueError('UTC delivery interval shape refused')
    return value


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError('UTC transport original deadline exhausted')
    return min(value, 0.25)


def receive(stream, size, deadline):
    result = bytearray()
    while len(result) < size:
        stream.settimeout(remaining(deadline))
        try:
            block = stream.recv(size - len(result))
        except (TimeoutError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
            continue
        if not block:
            raise ValueError('UTC transport truncated frame')
        result.extend(block)
    return bytes(result)


def send(stream, value, deadline):
    while value:
        stream.settimeout(remaining(deadline))
        try:
            count = stream.send(value)
        except (TimeoutError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
            continue
        if count <= 0:
            raise ValueError('UTC transport closed output')
        value = value[count:]


def request(stream, hostname, deadline):
    header = bytearray()
    while not header.endswith(b'\r\n\r\n'):
        if len(header) >= MAX_HEADER:
            raise ValueError('UTC HTTP header exceeds bound')
        header.extend(receive(stream, 1, deadline))
    lines = bytes(header[:-4]).split(b'\r\n')
    if lines.pop(0) != b'POST /luma/utc/v1 HTTP/1.1' or len(lines) > 16:
        raise ValueError('fixed UTC HTTPS request route required')
    fields = {}
    for line in lines:
        key, separator, value = line.partition(b': ')
        if (not separator or not re.fullmatch(b'[A-Za-z-]{1,32}', key)
                or key.lower() in fields or any(byte < 32 or byte > 126 for byte in value)):
            raise ValueError('ambiguous UTC HTTP header')
        fields[key.lower()] = value
    if (fields.get(b'host') != f'{hostname}:{PORT}'.encode('ascii')
            or fields.get(b'content-type') != b'application/octet-stream'
            or b'transfer-encoding' in fields or b'expect' in fields
            or fields.get(b'connection', b'close').lower() not in (b'close', b'keep-alive')
            or not re.fullmatch(b'[1-9][0-9]{0,3}', fields.get(b'content-length', b''))):
        raise ValueError('fixed UTC HTTP framing/host required')
    size = int(fields[b'content-length'])
    if size > 1024:
        raise ValueError('UTC HTTP body exceeds bound')
    return challenge(receive(stream, size, deadline))


def relay(original, deadline):
    before = Path(SOCKET).stat(follow_symlinks=False)
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != 0 or before.st_gid != UID or stat.S_IMODE(before.st_mode) != 0o660:
        raise ValueError('fixed publisher socket protection differs')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as local:
        local.settimeout(remaining(deadline))
        local.connect(SOCKET)
        pid, uid, gid = struct.unpack('3i', local.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid <= 0 or uid != 0 or gid != 0:
            raise ValueError('fixed publisher kernel peer differs')
        label = local.getsockopt(socket.SOL_SOCKET, socket.SO_PEERSEC, 256).rstrip(b'\0')
        if label != b'luma-utc-windows (enforce)' or identity(before) != identity(Path(SOCKET).stat(follow_symlinks=False)):
            raise ValueError('fixed publisher confinement/socket changed')
        send(local, struct.pack('>I', len(original)) + original, deadline)
        local.shutdown(socket.SHUT_WR)
        size = struct.unpack('>I', receive(local, 4, deadline))[0]
        if not 0 < size <= MAX_RESPONSE:
            raise ValueError('publisher response size refused')
        value = receive(local, size, deadline)
        local.settimeout(remaining(deadline))
        if local.recv(1):
            raise ValueError('publisher response has trailing bytes')
        return delivery(value, original)


def runtime(manifest):
    value = canonical(manifest)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'profile', 'python_version', 'openssl_version', 'files', 'native_qualified'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['profile'] != 'windows-protected-utc-https-transport-v1'
            or not isinstance(value['python_version'], list) or any(type(item) is not int for item in value['python_version'])
            or value['python_version'] != list(sys.version_info[:3])
            or value['openssl_version'] != ssl.OPENSSL_VERSION or value['native_qualified'] is not False
            or not isinstance(value['files'], list) or len(value['files']) != 6):
        raise ValueError('actual image transport runtime tuple differs')
    import _ssl
    expected = [str(Path(sys.executable).resolve()), str(Path(ssl.__file__).resolve()),
                str(Path(_ssl.__file__).resolve()), '/usr/lib/x86_64-linux-gnu/libssl.so.3',
                '/usr/lib/x86_64-linux-gnu/libcrypto.so.3', '/usr/libexec/luma-os/utc-windows-front.py']
    for pin, path in zip(value['files'], expected):
        if (not isinstance(pin, dict) or set(pin) != {'path', 'bytes', 'sha256'} or pin['path'] != path
                or type(pin['bytes']) is not int or not 0 < pin['bytes'] <= 64 * 1024**2
                or not isinstance(pin['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', pin['sha256'])):
            raise ValueError('fixed transport runtime pin differs')
        data, _ = protected(Path(path), 64 * 1024**2)
        if len(data) != pin['bytes'] or hashlib.sha256(data).hexdigest() != pin['sha256']:
            raise ValueError('actual transport runtime bytes changed')


def serve():
    if (len(sys.argv) != 1 or os.getuid() != UID or os.geteuid() != UID or os.getgid() != UID
            or os.getgroups() not in ([], [UID]) or not sys.flags.isolated or not sys.flags.no_site
            or not sys.flags.dont_write_bytecode or os.environ.get('LISTEN_PID') != str(os.getpid())
            or os.environ.get('LISTEN_FDS') != '1'):
        raise ValueError('fixed isolated socket-activated transport required')
    runtime(protected(MANIFEST, 16384)[0])
    config_bytes, _ = protected(CONFIG, 4096, private=True)
    config = canonical(config_bytes)
    if (set(config) != {'schema_version', 'hostname', 'certificate_sha256', 'private_key_sha256'}
            or type(config['schema_version']) is not int or config['schema_version'] != 1
            or not isinstance(config['hostname'], str) or len(config['hostname']) > 253
            or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', config['hostname'])
            or any(not isinstance(config[name], str) or not re.fullmatch('[0-9a-f]{64}', config[name])
                   for name in ('certificate_sha256', 'private_key_sha256'))):
        raise ValueError('explicit commissioned TLS transport configuration required')
    certificate, cert_identity = protected(CERT, 65536, private=True)
    private_key, key_identity = protected(KEY, 16384, private=True)
    if (hashlib.sha256(certificate).hexdigest() != config['certificate_sha256']
            or hashlib.sha256(private_key).hexdigest() != config['private_key_sha256']):
        raise ValueError('explicit commissioned TLS input pin differs')
    del private_key
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')
    context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET
    context.load_cert_chain(str(CERT), str(KEY))
    if cert_identity != identity(CERT.stat(follow_symlinks=False)) or key_identity != identity(KEY.stat(follow_symlinks=False)):
        raise ValueError('TLS inputs changed during fixed context load')
    with socket.socket(fileno=3) as listener:
        if (listener.family not in (socket.AF_INET, socket.AF_INET6) or listener.type != socket.SOCK_STREAM
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1 or listener.getsockname()[1] != PORT):
            raise ValueError('fixed listening socket activation differs')
        while True:
            connection, _ = listener.accept()
            deadline = time.monotonic() + 15
            with connection:
                try:
                    if (config_bytes != protected(CONFIG, 4096, private=True)[0]
                            or cert_identity != identity(CERT.stat(follow_symlinks=False))
                            or key_identity != identity(KEY.stat(follow_symlinks=False))):
                        raise ValueError('commissioned TLS configuration changed; restart explicitly')
                    connection.settimeout(remaining(deadline))
                    with context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False) as stream:
                        while True:
                            stream.settimeout(remaining(deadline))
                            try:
                                stream.do_handshake()
                                break
                            except (TimeoutError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                                continue
                        original = request(stream, config['hostname'], deadline)
                        value = relay(original, deadline)
                        headers = (f'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n'
                                   f'Content-Length: {len(value)}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n').encode('ascii')
                        send(stream, headers + value, deadline)
                except (OSError, ValueError):
                    # No interval, request bytes, TLS key or private exception is
                    # logged. Closing refuses; never invent successful time.
                    continue


if __name__ == '__main__':
    serve()
