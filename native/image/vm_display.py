"""Software-only guest display and bounded QMP screenshot evidence.

No host display, GPU, clipboard, input device or listening network port.
"""
import json
import socket
import struct
import time


def display_arguments(graphical):
    if type(graphical) is not bool:
        raise ValueError('graphical fixture must be an explicit boolean')
    return ['-vga', 'none', '-device', 'virtio-vga'] if graphical else []


def screenshot(vm, name):
    # Restrict the file QEMU may create to a new, fixed-name stage artifact.
    if name not in ('greeter', 'independent-greeter', 'failure'):
        raise ValueError('unknown screenshot observation')
    target = vm.work / ('screen-' + name + '.png')
    if target.exists() or target.is_symlink():
        raise ValueError('screenshot must not overwrite an existing artifact')
    end = min(vm.deadline, time.monotonic() + 30)
    pending = b''
    total = 0
    with socket.socket(socket.AF_UNIX) as connection:
        def remaining():
            seconds = end - time.monotonic()
            if seconds <= 0:
                raise TimeoutError('QMP screenshot deadline')
            connection.settimeout(seconds)

        def message():
            nonlocal pending, total
            while b'\n' not in pending:
                remaining()
                chunk = connection.recv(4096)
                if not chunk:
                    raise RuntimeError('QMP closed before screenshot response')
                total += len(chunk)
                if total > 65536:
                    raise RuntimeError('QMP response exceeds bound')
                pending += chunk
            line, pending = pending.split(b'\n', 1)
            result = json.loads(line)
            if not isinstance(result, dict):
                raise RuntimeError('QMP response must be an object')
            return result

        def command(identity, execute, arguments=None):
            request = {'execute': execute, 'id': identity}
            if arguments is not None:
                request['arguments'] = arguments
            remaining()
            connection.sendall(json.dumps(request).encode() + b'\n')
            for _ in range(128):
                response = message()
                if 'event' in response and 'id' not in response:
                    continue
                if response.get('id') != identity or 'error' in response or 'return' not in response:
                    raise RuntimeError('unexpected or failed QMP screenshot response')
                return
            raise RuntimeError('QMP event count exceeds bound')

        remaining()
        connection.connect(str(vm.socket_dir / 'qmp.sock'))
        if not isinstance(message().get('QMP'), dict):
            raise RuntimeError('missing QMP greeting')
        command('capabilities', 'qmp_capabilities')
        command('screenshot', 'screendump', {'filename': str(target), 'format': 'png'})
    if target.is_symlink() or not target.is_file() or not 24 <= target.stat().st_size <= 8 * 1024 * 1024:
        raise RuntimeError('missing or oversized screenshot')
    with target.open('rb') as stream:
        header = stream.read(24)
    if header[:8] != b'\x89PNG\r\n\x1a\n' or header[12:16] != b'IHDR':
        raise RuntimeError('screenshot is not PNG')
    width, height = struct.unpack('!II', header[16:24])
    if not (320 <= width <= 4096 and 200 <= height <= 4096):
        raise RuntimeError('unexpected screenshot geometry')
    return {'path': target.relative_to(vm.work.parent).as_posix(), 'width': width, 'height': height}
