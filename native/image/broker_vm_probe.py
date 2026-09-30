"""Guest-side slow-frame probe. Run as the unprivileged control identity."""
import json
import os
import socket
import struct
import threading
import time


SOCKET = '/run/luma-broker/control.sock'


def receive(sock):
    def exact(size):
        result = b''
        while len(result) < size:
            part = sock.recv(size-len(result))
            if not part:
                raise RuntimeError('broker closed without a framed response')
            result += part
        return result
    size = struct.unpack('!I', exact(4))[0]
    if not 0 < size <= 16384:
        raise RuntimeError('invalid broker response bound')
    return json.loads(exact(size))


def request(identifier):
    body = json.dumps({'schema_version': 1, 'request_id': identifier,
                       'caller': os.geteuid(), 'deadline': int(time.time())+20,
                       'action': 'status'}).encode()
    return struct.pack('!I', len(body))+body


def status():
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5)
        sock.connect(SOCKET)
        sock.sendall(request('after-slow-frame'))
        response = receive(sock)
    if (response.get('result') != 'ok' or
            response.get('authenticated_uid') != os.geteuid() or
            response.get('request_id') != 'after-slow-frame'):
        raise RuntimeError('broker did not resume authenticated status service')


def slow_frame(phase):
    if phase not in ('header', 'body'):
        raise ValueError('unknown fixture phase')
    stop = threading.Event()
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5)
        sock.connect(SOCKET)
        frame = request('slow-'+phase)
        if phase == 'body':
            sock.sendall(frame[:4])
            frame = frame[4:]

        def send():
            try:
                for byte in frame:
                    sock.sendall(bytes([byte]))
                    if stop.wait(.35):
                        break
            except OSError:
                pass  # The broker may close the expired connection.

        started = time.monotonic()
        sender = threading.Thread(target=send)
        sender.start()
        try:
            response = receive(sock)
            elapsed = time.monotonic()-started
            if response != {'schema_version': 1, 'result': 'denied'} or elapsed > 4.5:
                raise RuntimeError('slow frame was not denied within its absolute budget')
        finally:
            stop.set()
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sender.join(timeout=6)
            if sender.is_alive():
                raise RuntimeError('fixture sender did not terminate')
    status()
    return {'phase': phase, 'denial_seconds': elapsed, 'subsequent_status': 'ok'}


def main():
    if os.geteuid() != 990:
        raise RuntimeError('run as the image control identity, not root')
    status()
    print(json.dumps({'bounded_ipc': [slow_frame('header'), slow_frame('body')],
                      'certification_closing': False}))


if __name__ == '__main__':
    main()
