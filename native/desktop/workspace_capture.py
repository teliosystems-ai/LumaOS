"""Consent-bound ordinary-user capture, independent of content/model authority.

The trusted GTK controls own each short-lived operation. Screen selection uses
the desktop portal; no X11 grab, restore token, hidden capture, URL source or
device path is accepted. Application samples remain in memory until an explicit
save to a new private file. Existing imports and portal screenshot source files
remain under their source's lifetime policy. Saving is not publication,
transcription or a native grant.

Portal contracts: https://flatpak.github.io/xdg-desktop-portal/docs/
doc-org.freedesktop.portal.ScreenCast.html and
doc-org.freedesktop.portal.Screenshot.html .
"""
import dataclasses
import hashlib
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit
import uuid
import zlib

MAX_BYTES = 32 * 1024 * 1024
MAX_IMAGE = 8 * 1024 * 1024
MAX_SECONDS = 30
MAX_FRAMES = 30
WIDTH, HEIGHT = 1280, 720
AUDIO_RATE = 16000
PNG_MAGIC = b'\x89PNG\r\n\x1a\n'


def capture_clock():
    """Finite consent includes time spent suspended; no wall-clock dependency."""
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def capture_clock_ns():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def bind_capture_parent(parent_pid):
    """Kill input capture when its exact UI owner dies, including setup races."""
    if type(parent_pid) is not int or not 1 < parent_pid < 2**31 or os.getppid() != parent_pid:
        raise ValueError('capture worker lost its original UI owner')
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, int(signal.SIGKILL), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'capture parent-death binding failed')
    if os.getppid() != parent_pid:
        raise ValueError('capture UI owner exited during parent-death binding')


def close_capture_backend(state):
    """Attempt every revocation even when another resource cannot be drained.

    Retain uncertain handles for another cleanup attempt; an error must never
    strand the portal permission merely because the worker failed to reap.
    The caller must close admission after any failure, not claim completion.
    """
    errors = []
    pipeline = state['pipeline']
    if pipeline is not None:
        try:
            if pipeline.poll() is None:
                try:
                    os.killpg(pipeline.pid, signal.SIGKILL)
                except ProcessLookupError:
                    # An exit between poll and kill still requires actual reap.
                    pass
            pipeline.wait(timeout=2)
            try:
                os.killpg(pipeline.pid, 0)
            except ProcessLookupError:
                state['pipeline'] = None
            else:
                # Do not signal a group after reaping its leader: its numeric
                # identity may already have been reused by an unrelated task.
                raise ValueError('capture worker group did not prove complete drain')
        except Exception as error:
            errors.append(error)
        try:
            pipeline.stdout.close()
        except Exception as error:
            errors.append(error)
    portal = state['portal']
    if portal is not None:
        try:
            portal.close()
            state['portal'] = None
        except Exception as error:
            errors.append(error)
    descriptor = state['fd']
    if descriptor is not None:
        # Detach before close: Linux may release a descriptor despite a close
        # error, so retrying that integer could close a different resource.
        state['fd'] = None
        try:
            os.close(descriptor)
        except OSError as error:
            errors.append(error)
    state['received'].clear()
    state['stopping'] = None
    state['pending'] = False
    if errors:
        raise ValueError('capture revocation could not prove complete cleanup') from errors[0]


def validate_png(data):
    """Bounded complete PNG structure/inflate check; no decoder or URI loader.

    Accept ordinary non-interlaced 8-bit RGB/RGBA only. Ancillary chunks are
    opaque bounded bytes, never interpreted as profiles, code or references.
    The exact PNG, not an invented description/OCR result, is returned.
    """
    if not isinstance(data, bytes) or not 45 <= len(data) <= MAX_IMAGE or data[:8] != PNG_MAGIC:
        raise ValueError('select one bounded PNG image')
    offset, width, height, channels, compressed = 8, 0, 0, 0, bytearray()
    seen_header = seen_data = closed_data = ended = False
    chunks = 0
    while offset < len(data):
        chunks += 1
        if chunks > 4096:
            raise ValueError('PNG chunk count exceeds its parsing budget')
        if len(data)-offset < 12:
            raise ValueError('truncated PNG chunk')
        size, = struct.unpack_from('>I', data, offset)
        kind = data[offset+4:offset+8]
        if size > MAX_IMAGE or offset+12+size > len(data) or not re.fullmatch(b'[A-Za-z]{4}', kind) or kind[2] & 32:
            raise ValueError('invalid PNG chunk bounds')
        body = data[offset+8:offset+8+size]
        crc, = struct.unpack_from('>I', data, offset+8+size)
        if zlib.crc32(kind+body) & 0xffffffff != crc:
            raise ValueError('PNG checksum mismatch')
        offset += size+12
        if not seen_header and kind != b'IHDR':
            raise ValueError('PNG header must be first')
        if kind == b'IHDR':
            if seen_header or size != 13:
                raise ValueError('duplicate or malformed PNG header')
            width, height, depth, color, compression, filtering, interlace = struct.unpack('>IIBBBBB', body)
            if not 1 <= width <= 4096 or not 1 <= height <= 4096 or width*height > 8*1024*1024 or depth != 8 or color not in (2, 6) or (compression, filtering, interlace) != (0, 0, 0):
                raise ValueError('PNG requires bounded non-interlaced 8-bit RGB or RGBA')
            channels = 3 if color == 2 else 4
            seen_header = True
        elif kind == b'IDAT':
            if closed_data:
                raise ValueError('PNG data chunks must be contiguous')
            compressed.extend(body)
            seen_data = True
        elif kind == b'IEND':
            if size or not seen_data or offset != len(data):
                raise ValueError('invalid PNG end or trailing bytes')
            ended = True
            break
        elif kind in (b'PLTE', b'acTL', b'fcTL', b'fdAT') or not kind[0] & 32:
            raise ValueError('unsupported critical or animated PNG chunk')
        elif seen_data:
            closed_data = True
    if not ended:
        raise ValueError('PNG end is missing')
    row = width*channels+1
    expected = height*row
    inflater = zlib.decompressobj()
    raw = inflater.decompress(bytes(compressed), expected+1)
    if len(raw) != expected or not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
        raise ValueError('PNG decompressed geometry differs or stream has trailing data')
    if any(raw[start] > 4 for start in range(0, expected, row)):
        raise ValueError('invalid PNG scanline filter')
    return width, height


def rgb_png(data, width, height, stride):
    if not isinstance(data, bytes) or not 1 <= width <= WIDTH or not 1 <= height <= HEIGHT or not width*3 <= stride <= width*3+64 or len(data) != stride*height:
        raise ValueError('captured RGB frame geometry exceeds the fixed bound')
    def chunk(kind, body):
        return struct.pack('>I', len(body))+kind+body+struct.pack('>I', zlib.crc32(kind+body) & 0xffffffff)
    rows = b''.join(b'\0'+data[y*stride:y*stride+width*3] for y in range(height))
    result = PNG_MAGIC+chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))+chunk(b'IDAT', zlib.compress(rows, 3))+chunk(b'IEND', b'')
    validate_png(result)
    return result


def open_directory(path):
    """Hold every canonical directory component without following links."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or str(path) != os.path.normpath(path):
        raise ValueError('canonical absolute directory required')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def private_file(path, maximum=MAX_IMAGE):
    """Read explicit local user selection with exact before/after inode binding."""
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('select a canonical local regular file, not a link')
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    parent = open_directory(path.parent)
    descriptor = None
    try:
        descriptor = os.open(path.name, flags, dir_fd=parent)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.getuid() or not 0 < before.st_size <= maximum:
            raise ValueError('selected input is not one bounded user-owned regular file')
        data = bytearray()
        while len(data) <= maximum:
            part = os.read(descriptor, min(65536, maximum+1-len(data)))
            if not part:
                break
            data.extend(part)
        after = os.fstat(descriptor)
        identity = lambda m: (m.st_dev, m.st_ino, m.st_mode, m.st_uid, m.st_gid, m.st_nlink, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if len(data) != before.st_size or identity(before) != identity(after) or identity(named) != identity(after):
            raise ValueError('selected input changed during capture')
        return bytes(data)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def screenshot_path(uri):
    if not isinstance(uri, str) or len(uri) > 8192 or '\0' in uri or re.search(r'%(?![0-9a-fA-F]{2})', uri):
        raise ValueError('invalid portal screenshot URI')
    parsed = urlsplit(uri)
    if parsed.scheme != 'file' or parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError('portal screenshot must be an explicit local file')
    path = unquote(parsed.path, errors='strict')
    if '\0' in path or not path.startswith('/'):
        raise ValueError('invalid portal screenshot path')
    return Path(path)


@dataclasses.dataclass(frozen=True)
class Capture:
    kind: str
    frames: tuple[bytes, ...]
    elapsed_ms: int
    sample_rate: int = 0
    capture_id: str = dataclasses.field(default_factory=lambda: uuid.uuid4().hex)

    def __post_init__(self):
        if self.kind not in ('image', 'screen', 'video', 'speech') or not isinstance(self.capture_id, str) or not re.fullmatch(r'[0-9a-f]{32}', self.capture_id) or type(self.elapsed_ms) is not int or not 0 <= self.elapsed_ms <= MAX_SECONDS*1000+1000 or not isinstance(self.frames, tuple) or not self.frames or any(not isinstance(frame, bytes) or not frame for frame in self.frames) or sum(map(len, self.frames)) > MAX_BYTES:
            raise ValueError('closed bounded capture result required')
        if self.kind == 'speech':
            if self.sample_rate != AUDIO_RATE or len(self.frames) != 1 or len(self.frames[0]) % 2 or len(self.frames[0]) > AUDIO_RATE*2*MAX_SECONDS:
                raise ValueError('speech capture requires at most thirty seconds of mono S16LE PCM')
        else:
            if self.sample_rate or len(self.frames) > (MAX_FRAMES if self.kind == 'video' else 1):
                raise ValueError('image/video sample count exceeds explicit scope')
            for frame in self.frames:
                validate_png(frame)

    def metadata(self):
        return {'schema_version': 1, 'capture_id': self.capture_id, 'kind': self.kind, 'elapsed_ms': self.elapsed_ms,
                'sample_rate': self.sample_rate, 'channels': 1 if self.kind == 'speech' else 0,
                'format': 's16le-pcm' if self.kind == 'speech' else 'png',
                'bytes': sum(map(len, self.frames)),
                'frames': [{'index': index, 'bytes': len(frame), 'sha256': hashlib.sha256(frame).hexdigest()} for index, frame in enumerate(self.frames)],
                'transcribed': False, 'published': False, 'model_submitted': False}


def grounded_sample(captures, selector):
    """Select exact local evidence or demand clarification; never guess latest.

    A local capture reference is DATA, not a product content VersionReference
    or permission to transmit it. It remains bound to this window's retained
    immutable bytes, even when several inputs have identical content hashes.
    """
    if not isinstance(captures, tuple) or len(captures) > 64 or any(not isinstance(capture, Capture) for capture in captures):
        raise ValueError('bounded explicit local capture set required')
    if not isinstance(selector, dict) or set(selector) != {'capture_id', 'index', 'sha256'} or not isinstance(selector['capture_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', selector['capture_id']) or type(selector['index']) is not int or not 0 <= selector['index'] < MAX_FRAMES or not isinstance(selector['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', selector['sha256']):
        raise ValueError('clarify the exact capture, sample number and digest before use')
    matches = [capture for capture in captures if capture.capture_id == selector['capture_id']]
    if len(matches) != 1 or selector['index'] >= len(matches[0].frames):
        raise ValueError('capture reference is missing or ambiguous; ask for clarification')
    sample = matches[0].frames[selector['index']]
    if hashlib.sha256(sample).hexdigest() != selector['sha256']:
        raise ValueError('capture digest changed; ask for a fresh explicit selection')
    return sample


class CaptureBuffer:
    """One finite local permission generation, revoked on any uncertainty."""
    def __init__(self, kind, seconds, *, clock=capture_clock):
        if kind not in ('speech', 'video') or type(seconds) is not int or not 1 <= seconds <= MAX_SECONDS:
            raise ValueError('capture requires one explicit kind and one to thirty seconds')
        self.kind, self.seconds, self.clock = kind, seconds, clock
        self.started = clock()
        self.state = 'active'
        self.frames = []
        self.bytes = 0
        self.last_second = -1

    def active(self):
        return self.state == 'active' and 0 <= self.clock()-self.started < self.seconds

    def append(self, data, *, drain=False):
        elapsed = self.clock()-self.started
        available = (self.state == 'active' and 0 <= elapsed <= self.seconds+1) if drain else self.active()
        if not available or not isinstance(data, bytes) or not data:
            self.revoke()
            raise ValueError('capture is inactive, expired or empty')
        bound = AUDIO_RATE*2*self.seconds if self.kind == 'speech' else MAX_BYTES
        if self.bytes+len(data) > bound or self.kind == 'speech' and len(data) % 2:
            self.revoke()
            raise ValueError('capture exceeded its exact byte budget')
        if self.kind == 'video':
            try:
                validate_png(data)
            except Exception:
                self.revoke()
                raise
            second = int(self.clock()-self.started)
            if second == self.last_second:
                return False
            if len(self.frames) >= min(MAX_FRAMES, self.seconds):
                self.revoke()
                raise ValueError('video sample budget exhausted')
            self.last_second = second
        self.frames.append(data)
        self.bytes += len(data)
        return True

    def revoke(self):
        self.state = 'revoked'
        self.frames.clear()
        self.bytes = 0

    def finish(self):
        if self.state != 'active' or not self.frames:
            self.revoke()
            raise ValueError('no completed consent-bound capture is available')
        elapsed = self.clock()-self.started
        if elapsed < 0 or elapsed > self.seconds+1:
            self.revoke()
            raise ValueError('capture controller missed its finite stop deadline')
        frames = tuple(self.frames) if self.kind == 'video' else (b''.join(self.frames),)
        result = Capture(self.kind, frames, int(elapsed*1000), AUDIO_RATE if self.kind == 'speech' else 0)
        self.state = 'completed'
        self.frames.clear()
        self.bytes = 0
        return result


def save_new(capture, path):
    """Create one explicit private ZIP envelope; no overwrite or publication.

    The envelope uses only generated inert entry names, fixed format metadata,
    ZIP_STORED and exact frame bytes. No archive input/extraction is accepted.
    """
    import json
    import zipfile
    if not isinstance(capture, Capture):
        raise ValueError('one completed capture required')
    path = Path(path)
    if not path.is_absolute() or path.name in ('.', '..') or not path.name.endswith('.luma-capture.zip') or path.parent.resolve(strict=True) != path.parent:
        raise ValueError('select a new canonical .luma-capture.zip output')
    parent = open_directory(path.parent)
    descriptor = None
    try:
        before = os.fstat(parent)
        if before.st_uid != os.getuid() or before.st_mode & 0o022:
            raise ValueError('capture output requires a private user-owned directory')
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, 'wb', closefd=False) as output:
            with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
                archive.writestr('capture.json', json.dumps(capture.metadata(), sort_keys=True, separators=(',', ':')).encode())
                extension = 'pcm' if capture.kind == 'speech' else 'png'
                for index, frame in enumerate(capture.frames):
                    archive.writestr(f'{index:02d}.{extension}', frame)
            output.flush()
            os.fsync(output.fileno())
        after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        held = os.fstat(descriptor)
        current_parent = path.parent.stat()
        if not stat.S_ISREG(after.st_mode) or stat.S_IMODE(after.st_mode) != 0o600 or (after.st_dev, after.st_ino, after.st_nlink, after.st_uid) != (held.st_dev, held.st_ino, 1, os.getuid()) or (current_parent.st_dev, current_parent.st_ino, current_parent.st_mode, current_parent.st_uid, current_parent.st_gid) != (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid):
            raise ValueError('capture output changed during save; retain evidence and inspect it')
        os.fsync(parent)
        return capture.metadata()
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


class Portal:
    """Nonpersistent desktop requests on the original ordinary-user bus."""
    NAME = 'org.freedesktop.portal.Desktop'
    PATH = '/org/freedesktop/portal/desktop'

    def __init__(self, Gio, GLib):
        self.Gio, self.GLib = Gio, GLib
        address = Gio.dbus_address_get_for_bus_sync(Gio.BusType.SESSION, None)
        self.bus = Gio.DBusConnection.new_for_address_sync(address,
            Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
        self.bus.set_exit_on_close(False)
        self.pending = {}
        self.session = None
        self.closed = False
        self.subscriptions = []
        self.on_revoked = lambda: None
        self.bus.connect('closed', lambda *_: self.revoke())

    def request(self, interface, method, signature, arguments, options, completed):
        if self.closed or self.pending:
            raise ValueError('portal request already pending or revoked')
        token = 'luma_'+uuid.uuid4().hex
        sender = self.bus.get_unique_name()[1:].replace('.', '_')
        expected = f'/org/freedesktop/portal/desktop/request/{sender}/{token}'
        options = dict(options, handle_token=self.GLib.Variant('s', token))
        def response(_connection, _sender, path, _interface, _member, parameters, _data):
            pending = self.pending.pop(expected, None)
            if pending is None or self.closed:
                return
            self.bus.signal_unsubscribe(pending[0])
            self.GLib.source_remove(pending[1])
            code, results = parameters.unpack()
            if path != expected or code != 0:
                self.close()
                completed(None, 'Desktop permission was denied or cancelled.')
            else:
                completed(results, None)
        subscription = self.bus.signal_subscribe(self.NAME, 'org.freedesktop.portal.Request', 'Response', expected, None, self.Gio.DBusSignalFlags.NONE, response, None)
        def expired():
            self.close()
            completed(None, 'Desktop permission request timed out.')
            return False
        timer = self.GLib.timeout_add_seconds(60, expired)
        self.pending[expected] = (subscription, timer)
        def accepted(connection, result, _data):
            try:
                handle, = connection.call_finish(result).unpack()
                if handle != expected:
                    raise ValueError('portal returned a substituted request handle')
            except Exception:
                if expected in self.pending:
                    self.close()
                    completed(None, 'Desktop permission request failed.')
        self.bus.call(self.NAME, self.PATH, interface, method,
            self.GLib.Variant(signature, (*arguments, options)), self.GLib.VariantType.new('(o)'),
            self.Gio.DBusCallFlags.NONE, 10000, None, accepted, None)

    def screenshot(self, completed):
        self.request('org.freedesktop.portal.Screenshot', 'Screenshot', '(sa{sv})', ('',),
            {'interactive': self.GLib.Variant('b', True), 'modal': self.GLib.Variant('b', True)}, completed)

    def screen(self, completed):
        interface = 'org.freedesktop.portal.ScreenCast'
        def created(results, error):
            if error:
                completed(None, error); return
            session = results.get('session_handle')
            sender = self.bus.get_unique_name()[1:].replace('.', '_')
            if not isinstance(session, str) or not session.startswith('/org/freedesktop/portal/desktop/session/'+sender+'/') or not re.fullmatch(r'/[A-Za-z0-9_/]+', session):
                self.close(); completed(None, 'Desktop session identity was refused.'); return
            self.session = session
            self.subscriptions.append(self.bus.signal_subscribe(self.NAME, 'org.freedesktop.portal.Session', 'Closed', session, None, self.Gio.DBusSignalFlags.NONE, lambda *_: self.revoke(), None))
            self.request(interface, 'SelectSources', '(oa{sv})', (session,),
                {'types': self.GLib.Variant('u', 3), 'multiple': self.GLib.Variant('b', False), 'persist_mode': self.GLib.Variant('u', 0)}, selected)
        def selected(_results, error):
            if error:
                completed(None, error); return
            self.request(interface, 'Start', '(osa{sv})', (self.session, ''), {}, started)
        def started(results, error):
            if error:
                completed(None, error); return
            streams = results.get('streams')
            if not isinstance(streams, list) or len(streams) != 1 or not isinstance(streams[0], (list, tuple)) or len(streams[0]) != 2 or type(streams[0][0]) is not int or not 0 < streams[0][0] < 2**32:
                self.close(); completed(None, 'Desktop did not return one selected stream.'); return
            # The restricted remote exposes only this session's nodes. Close on
            # session destruction, and never reconnect to the ambient remote.
            node, properties = streams[0]
            serial = properties.get('pipewire-serial') if isinstance(properties, dict) else None
            if serial is not None and (type(serial) is not int or not 1 <= serial < 2**64):
                self.close(); completed(None, 'Invalid desktop stream serial.'); return
            def opened(connection, result, _data):
                descriptor = None
                try:
                    answer, descriptors = connection.call_with_unix_fd_list_finish(result)
                    index, = answer.unpack()
                    if self.closed or descriptors is None or descriptors.get_length() != 1 or index != 0:
                        raise ValueError('restricted PipeWire remote descriptor refused')
                    descriptor = descriptors.get(index)
                    completed((descriptor, str(serial if serial is not None else node)), None)
                    descriptor = None
                except Exception:
                    if descriptor is not None:
                        os.close(descriptor)
                    self.close(); completed(None, 'Desktop PipeWire connection failed.')
            self.bus.call_with_unix_fd_list(self.NAME, self.PATH, interface, 'OpenPipeWireRemote',
                self.GLib.Variant('(oa{sv})', (self.session, {})), self.GLib.VariantType.new('(h)'),
                self.Gio.DBusCallFlags.NONE, 10000, None, None, opened, None)
        self.request(interface, 'CreateSession', '(a{sv})', (),
            {'session_handle_token': self.GLib.Variant('s', 'luma_'+uuid.uuid4().hex)}, created)

    def revoke(self):
        if not self.closed:
            self.close()
            self.on_revoked()

    def close(self):
        if self.closed:
            if not self.bus.is_closed():
                self.bus.close_sync(None)
            return
        self.closed = True
        try:
            for path, (subscription, timer) in list(self.pending.items()):
                self.bus.signal_unsubscribe(subscription)
                self.GLib.source_remove(timer)
                self.bus.call(self.NAME, path, 'org.freedesktop.portal.Request', 'Close', None, None, self.Gio.DBusCallFlags.NONE, 1000, None, None, None)
            self.pending.clear()
            for subscription in self.subscriptions:
                self.bus.signal_unsubscribe(subscription)
            self.subscriptions.clear()
            session, self.session = self.session, None
            if session:
                self.bus.call(self.NAME, session, 'org.freedesktop.portal.Session', 'Close', None, None, self.Gio.DBusCallFlags.NONE, 1000, None, None, None)
        finally:
            # Disconnect even if a request-close/unsubscribe operation failed.
            # It also cancels an unknown CreateSession response racing Stop.
            if not self.bus.is_closed():
                self.bus.close_sync(None)


def capture_worker(kind, seconds, deadline_ns, descriptor=None, target=None, *, source_factory=None, parent_pid=None):
    """Dedicated killable bounded GStreamer process; no file/URI pipeline input.

    A test can supply an actual audiotestsrc/videotestsrc factory by importing
    this function. The installed CLI never accepts that hook or test sources.
    The only production source factories are pulsesrc and the portal-owned FD.
    """
    if kind not in ('speech', 'video') or type(seconds) is not int or not 1 <= seconds <= MAX_SECONDS:
        raise ValueError('invalid finite worker scope')
    if type(deadline_ns) is not int or not capture_clock_ns() < deadline_ns <= capture_clock_ns()+seconds*1000000000:
        raise ValueError('capture worker requires an unexpired absolute suspend-inclusive deadline')
    if kind == 'video' and (type(descriptor) is not int or descriptor < 3 or not isinstance(target, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', target)):
        raise ValueError('video worker requires the exact restricted portal descriptor and stream')
    if kind == 'speech' and (descriptor is not None or target is not None):
        raise ValueError('speech worker cannot accept a video descriptor')
    if source_factory is None:
        bind_capture_parent(parent_pid)
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU, (MAX_SECONDS+5, MAX_SECONDS+5))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Pulse/PipeWire legitimately resize finite anonymous/shared-memory FDs.
    # A zero FSIZE would silently disable the real transport, not secure it.
    # The AppArmor domain permits no ordinary output path or personal files.
    resource.setrlimit(resource.RLIMIT_FSIZE, (64*1024*1024, 64*1024*1024))
    if source_factory is None:
        label = Path('/proc/self/attr/current').read_text(encoding='ascii').strip()
        profile = 'luma-workspace-capture-audio' if kind == 'speech' else 'luma-workspace-capture-video'
        if label != profile+' (enforce)':
            raise ValueError('capture worker requires its exact enforcing AppArmor domain')
    os.environ['GST_REGISTRY_FORK'] = 'no'
    os.environ['GST_PLUGIN_PATH'] = ''
    os.environ['GST_PLUGIN_PATH_1_0'] = ''
    os.environ['GST_PLUGIN_SYSTEM_PATH_1_0'] = '/usr/lib/x86_64-linux-gnu/gstreamer-1.0'
    os.environ['GST_REGISTRY'] = '/dev/null'
    import gi
    gi.require_version('Gst', '1.0')
    from gi.repository import Gst
    Gst.init(None)
    source = source_factory(Gst) if source_factory else Gst.ElementFactory.make('pulsesrc' if kind == 'speech' else 'pipewiresrc')
    if source is None:
        raise ValueError('required packaged capture source is unavailable')
    if kind == 'video' and source_factory is None:
        source.set_property('fd', descriptor)
        source.set_property('path', target)
        source.set_property('do-timestamp', True)
    elif kind == 'speech' and source_factory is None:
        source.set_property('server', f'unix:/run/user/{os.getuid()}/pulse/native')
        source.set_property('client-name', 'Luma explicit push-to-talk input')
    names = (('audioconvert', 'audioresample', 'capsfilter', 'appsink') if kind == 'speech'
             else ('videoconvert', 'videoscale', 'videorate', 'capsfilter', 'appsink'))
    pipeline = Gst.Pipeline.new('luma-finite-capture')
    elements = [source]+[Gst.ElementFactory.make(name) for name in names]
    if any(element is None for element in elements):
        raise ValueError('required packaged capture element is unavailable')
    for element in elements:
        pipeline.add(element)
    for left, right in zip(elements, elements[1:]):
        if not left.link(right):
            raise ValueError('capture worker could not link its fixed pipeline')
    caps = ('audio/x-raw,format=S16LE,rate=16000,channels=1,layout=interleaved' if kind == 'speech'
            else f'video/x-raw,format=RGB,width={WIDTH},height={HEIGHT},framerate=1/1,pixel-aspect-ratio=1/1')
    if kind == 'video':
        elements[2].set_property('add-borders', True)
    elements[-2].set_property('caps', Gst.Caps.from_string(caps))
    sink = elements[-1]
    sink.set_property('max-buffers', 1)
    sink.set_property('drop', True)
    sink.set_property('sync', False)
    running = [True]
    signal.signal(signal.SIGINT, lambda *_: running.__setitem__(0, False))
    emitted, frames = 0, 0
    output = sys.stdout.buffer
    try:
        if capture_clock_ns() >= deadline_ns:
            raise ValueError('capture permission expired during engine initialization')
        if pipeline.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
            raise ValueError('capture worker could not start its exact source')
        while running[0] and capture_clock_ns() < deadline_ns:
            message = pipeline.get_bus().pop_filtered(Gst.MessageType.ERROR | Gst.MessageType.EOS)
            if message and message.type == Gst.MessageType.ERROR:
                raise ValueError('capture device or stream failed')
            sample = sink.emit('try-pull-sample', 50*Gst.MSECOND)
            if sample is None:
                if message or sink.get_property('eos'):
                    break
                continue
            if not running[0] or capture_clock_ns() >= deadline_ns:
                break
            raw = sample.get_buffer()
            maximum = AUDIO_RATE*2*MAX_SECONDS if kind == 'speech' else (WIDTH*3+64)*HEIGHT
            if raw.get_size() > maximum:
                raise ValueError('capture sample exceeded its fixed geometry')
            data = raw.extract_dup(0, raw.get_size())
            if kind == 'video':
                shape = sample.get_caps().get_structure(0)
                if shape.get_value('format') != 'RGB' or shape.get_value('width') != WIDTH or shape.get_value('height') != HEIGHT or len(data) != WIDTH*HEIGHT*3:
                    raise ValueError('capture frame format substitution refused')
                data = rgb_png(data, WIDTH, HEIGHT, WIDTH*3)
                frames += 1
                if frames > min(seconds, MAX_FRAMES):
                    break
            budget = seconds*AUDIO_RATE*2 if kind == 'speech' else MAX_BYTES
            if not data or emitted+len(data) > budget or kind == 'speech' and len(data) % 2:
                raise ValueError('capture exceeded its finite byte budget')
            output.write(struct.pack('>I', len(data)))
            output.write(data)
            output.flush()
            emitted += len(data)
        if emitted == 0:
            raise ValueError('capture produced no actual samples')
    finally:
        pipeline.set_state(Gst.State.NULL)
        result, current, _pending = pipeline.get_state(2*Gst.SECOND)
        if result == Gst.StateChangeReturn.FAILURE or current != Gst.State.NULL:
            raise ValueError('capture device closure could not be confirmed')


def launch_capture(parent, on_complete=None):
    """Open independent trusted GTK controls; never callable through WebKit.

    Returns the window for lifetime ownership. Optional on_complete receives
    only inert metadata, not private samples, native grants or model input.
    """
    if os.getuid() == 0 or os.geteuid() != os.getuid() or os.environ.get('XDG_SESSION_TYPE') != 'wayland':
        raise ValueError('capture requires the original ordinary-user Wayland session')
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, Gio, GLib
    window = Gtk.Window(title='Luma explicit input capture')
    window.set_transient_for(parent)
    window.set_default_size(640, 320)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin=16)
    window.add(box)
    notice = Gtk.Label(label='Capture never starts automatically. Application samples stay in memory; selected imports and portal screenshot source files retain their source lifetime. No transcription, model submission or publication occurs.', wrap=True, xalign=0)
    box.pack_start(notice, False, False, 0)
    indicator = Gtk.Label(label='INACTIVE — no input device or desktop stream open', wrap=True, xalign=0)
    indicator.set_selectable(True)
    box.pack_start(indicator, False, False, 0)
    duration = Gtk.SpinButton.new_with_range(1, MAX_SECONDS, 1)
    duration.set_value(10)
    duration.set_tooltip_text('Maximum capture duration in seconds; no automatic renewal')
    label = Gtk.Label(label='Maximum capture duration (seconds)', xalign=0)
    label.set_mnemonic_widget(duration)
    box.pack_start(label, False, False, 0); box.pack_start(duration, False, False, 0)
    actions = Gtk.Box(spacing=6)
    box.pack_start(actions, False, False, 0)
    speech = Gtk.Button.new_with_mnemonic('_Hold to talk')
    screenshot = Gtk.Button.new_with_mnemonic('Select _screen image…')
    video = Gtk.Button.new_with_mnemonic('Sample _video…')
    image = Gtk.Button.new_with_mnemonic('Select _PNG…')
    for button in (speech, screenshot, video, image):
        actions.pack_start(button, True, True, 0)
    stop = Gtk.Button.new_with_mnemonic('_Stop and discard / revoke permission')
    save = Gtk.Button.new_with_mnemonic('Save completed input _locally…')
    box.pack_start(stop, False, False, 0); box.pack_start(save, False, False, 0)
    state = {'pipeline': None, 'buffer': None, 'portal': None, 'fd': None, 'timer': None, 'result': None, 'generation': 0, 'pending': False, 'closed': False, 'speech_arm': None, 'received': bytearray(), 'stopping': None}
    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    subscriptions = []

    def enabled():
        active = state['pipeline'] is not None or state['pending']
        for button in (speech, screenshot, video, image, duration):
            button.set_sensitive(not state['closed'] and (not active or button == speech and state['buffer'] is not None and state['buffer'].kind == 'speech'))
        save.set_sensitive(state['result'] is not None and not active)
        stop.set_sensitive(active or state['result'] is not None)

    def clear_backend():
        state['generation'] += 1
        state['speech_arm'] = None
        if state['timer'] is not None:
            GLib.source_remove(state['timer']); state['timer'] = None
        close_capture_backend(state)

    def revoke(message='INACTIVE — stopped, discarded and permission revoked'):
        buffer, state['buffer'] = state['buffer'], None
        if buffer:
            buffer.revoke()
        state['result'] = None
        try:
            clear_backend()
        except Exception:
            message = 'ERROR — capture could not prove device closure; close this application before continuing.'
            state['closed'] = True
        indicator.set_text(message)
        enabled()

    def complete(result):
        clear_backend()
        state['buffer'] = None
        state['result'] = result
        indicator.set_text(f'INACTIVE — completed {result.kind}; {sum(map(len, result.frames))} bytes, {len(result.frames)} sample(s). Permission closed. Nothing sent to a model or published.')
        enabled()
        if on_complete:
            on_complete(result.metadata())

    def consent(kind):
        if state['closed'] or state['pipeline'] or state['pending'] or not window.get_visible():
            return False
        state['speech_arm'] = None
        dialog = Gtk.MessageDialog(transient_for=window, modal=True, message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.OK_CANCEL, text=f'Allow one explicit {kind} input?')
        dialog.format_secondary_text('Audio is at most 30 seconds, only while holding the talk control. Video samples at most one frame/second for the selected duration. Stop, window hiding, screen lock or portal revocation discards active input. No background permission is retained.')
        allowed = dialog.run() == Gtk.ResponseType.OK
        dialog.destroy()
        if allowed:
            state['result'] = None
        return allowed

    def start_pipeline(kind, seconds, descriptor=None, target=None):
        if state['closed'] or not window.get_visible():
            raise ValueError('visible capture controls required')
        script = str(Path(__file__).resolve(strict=True))
        buffer = CaptureBuffer(kind, seconds)
        deadline_ns = int((buffer.started+seconds)*1000000000)
        profile = 'luma-workspace-capture-audio' if kind == 'speech' else 'luma-workspace-capture-video'
        arguments = ['/usr/bin/aa-exec', '-p', profile, '--', '/usr/bin/python3', '-I', script, '--capture-worker', kind, str(seconds), str(deadline_ns), str(os.getpid())]
        if kind == 'video':
            arguments.extend((str(descriptor), target))
        environment = {key: value for key, value in os.environ.items() if key in ('PATH', 'USER', 'LOGNAME', 'XDG_RUNTIME_DIR')}
        environment['PATH'] = '/usr/bin:/bin'
        pipeline = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True, pass_fds=(() if descriptor is None else (descriptor,)),
            start_new_session=True, env=environment)
        os.set_blocking(pipeline.stdout.fileno(), False)
        state['pipeline'] = pipeline
        state['buffer'] = buffer
        state['pending'] = False
        generation = state['generation']
        indicator.set_text(f'ACTIVE — {kind.upper()} input. Maximum {seconds} seconds. Stop/revoke is available below.')
        enabled()
        def poll():
            if generation != state['generation']:
                return False
            try:
                if not window.get_visible() or state['closed']:
                    revoke(); return False
                buffer = state['buffer']
                now = capture_clock()
                if now-buffer.started > seconds+1 or state['stopping'] is not None and now-state['stopping'] > 1:
                    revoke('INACTIVE — capture deadline exceeded; worker stopped and partial input discarded.'); return False
                for _ in range(64):
                    try:
                        data = os.read(pipeline.stdout.fileno(), 65536)
                    except BlockingIOError:
                        break
                    if not data:
                        break
                    state['received'].extend(data)
                    if len(state['received']) > MAX_IMAGE+4:
                        raise ValueError('capture worker frame exceeded the fixed wire bound')
                    while len(state['received']) >= 4:
                        size, = struct.unpack_from('>I', state['received'])
                        if not 0 < size <= (AUDIO_RATE*2*seconds if kind == 'speech' else MAX_IMAGE):
                            raise ValueError('capture worker frame length refused')
                        if len(state['received']) < size+4:
                            break
                        data = bytes(state['received'][4:4+size])
                        del state['received'][:4+size]
                        buffer.append(data, drain=True)
                exited = pipeline.poll()
                if exited is not None:
                    if exited != 0 or state['received']:
                        raise ValueError('capture worker failed or returned a partial frame')
                    result = buffer.finish()
                    state['timer'] = None
                    complete(result); return False
            except Exception:
                revoke('INACTIVE — capture scope/budget refused; partial input discarded.'); return False
            return True
        state['timer'] = GLib.timeout_add(20, poll)

    def microphone(_button):
        armed = state['speech_arm']
        if armed is not None and capture_clock() < armed and state['pipeline'] is None and not state['pending']:
            state['speech_arm'] = None
            try:
                start_pipeline('speech', duration.get_value_as_int())
            except Exception:
                revoke('INACTIVE — microphone could not start under its bound.')
        elif consent('push-to-talk default audio input'):
            # Consent is not held while a modal dialog is open. Require a fresh
            # press after approval and end on its release/focus loss.
            indicator.set_text('ARMED — press and hold talk again now; release stops. Permission expires in ten seconds.')
            token = state['generation']
            state['speech_arm'] = capture_clock()+10
            def expires():
                if state['generation'] == token and state['pipeline'] is None:
                    state['generation'] += 1
                    indicator.set_text('INACTIVE — unused push-to-talk consent expired.')
                return False
            GLib.timeout_add_seconds(10, expires)

    def released(_button):
        if state['buffer'] and state['buffer'].kind == 'speech':
            pipeline = state['pipeline']
            if pipeline and pipeline.poll() is None and state['stopping'] is None:
                state['stopping'] = capture_clock()
                pipeline.send_signal(signal.SIGINT)

    def portal_capture(kind):
        if not consent(kind):
            return
        state['pending'] = True
        portal = Portal(Gio, GLib)
        state['portal'] = portal
        portal.on_revoked = lambda: revoke('INACTIVE — desktop permission revoked; input discarded.')
        token = state['generation']
        indicator.set_text('PERMISSION PENDING — select one source in the desktop dialog; cancel/stop discards.')
        enabled()
        def completed(value, error):
            if token != state['generation'] or state['closed']:
                if kind == 'video' and value is not None:
                    os.close(value[0])
                return
            if error:
                revoke('INACTIVE — desktop permission denied, cancelled or unavailable.'); return
            try:
                if kind == 'screen':
                    data = private_file(screenshot_path(value.get('uri')))
                    validate_png(data)
                    complete(Capture('screen', (data,), 0))
                else:
                    descriptor, target = value
                    state['fd'] = descriptor
                    start_pipeline('video', duration.get_value_as_int(), descriptor, target)
            except Exception:
                revoke('INACTIVE — selected desktop input failed its exact bounds.')
        try:
            portal.screenshot(completed) if kind == 'screen' else portal.screen(completed)
        except Exception:
            revoke('INACTIVE — desktop portal unavailable; no fallback capture attempted.')

    def selected_image(_button):
        if not consent('selected PNG image'):
            return
        chooser = Gtk.FileChooserDialog(title='Explicitly select one PNG image', transient_for=window,
            action=Gtk.FileChooserAction.OPEN)
        chooser.add_buttons('_Cancel', Gtk.ResponseType.CANCEL, '_Select image', Gtk.ResponseType.OK)
        chooser.set_local_only(True); chooser.set_select_multiple(False)
        try:
            if chooser.run() == Gtk.ResponseType.OK:
                data = private_file(chooser.get_filename())
                validate_png(data)
                complete(Capture('image', (data,), 0))
        except Exception:
            revoke('INACTIVE — selected image refused; requires one bounded local RGB/RGBA PNG.')
        finally:
            chooser.destroy()

    def save_input(_button):
        result = state['result']
        if result is None:
            return
        chooser = Gtk.FileChooserDialog(title='Save input locally, not publication', transient_for=window,
            action=Gtk.FileChooserAction.SAVE)
        chooser.add_buttons('_Cancel', Gtk.ResponseType.CANCEL, '_Save new private file', Gtk.ResponseType.OK)
        chooser.set_local_only(True); chooser.set_do_overwrite_confirmation(True)
        chooser.set_current_name('explicit-input.luma-capture.zip')
        try:
            if chooser.run() == Gtk.ResponseType.OK:
                save_new(result, chooser.get_filename())
                indicator.set_text('INACTIVE — saved exact input to one new private local envelope. Not published, transcribed or sent to a model.')
        except Exception:
            indicator.set_text('INACTIVE — local save refused; no existing output is overwritten. Inspect any interrupted output before retrying.')
        finally:
            chooser.destroy()

    def locked(_connection, _sender, _path, _interface, _member, parameters, _data):
        values = parameters.unpack()
        if len(values) != 1 or type(values[0]) is not bool or values[0]:
            revoke('INACTIVE — session locked; permission revoked and samples discarded.')
    for name in ('org.gnome.ScreenSaver', 'org.freedesktop.ScreenSaver'):
        subscriptions.append(bus.signal_subscribe(name, name, 'ActiveChanged', None, None, Gio.DBusSignalFlags.NONE, locked, None))
    def portal_owner_changed(_connection, _sender, _path, _interface, _member, parameters, _data):
        _name, old, new = parameters.unpack()
        if old and old != new:
            revoke('INACTIVE — desktop permission service changed; input discarded.')
    subscriptions.append(bus.signal_subscribe('org.freedesktop.DBus', 'org.freedesktop.DBus', 'NameOwnerChanged',
        '/org/freedesktop/DBus', Portal.NAME, Gio.DBusSignalFlags.NONE, portal_owner_changed, None))
    def destroyed(*_):
        state['closed'] = True
        revoke()
        bus.disconnect(lock_bus_closed)
        for subscription in subscriptions:
            bus.signal_unsubscribe(subscription)
        subscriptions.clear()
    lock_bus_closed = bus.connect('closed', lambda *_: revoke('INACTIVE — session permission/lock bus was lost; samples discarded.'))
    window.connect('destroy', destroyed)
    window.connect('unmap', lambda *_: revoke())
    window.connect('focus-out-event', lambda *_: released(None) or False)
    speech.connect('pressed', microphone); speech.connect('released', released)
    screenshot.connect('clicked', lambda *_: portal_capture('screen'))
    video.connect('clicked', lambda *_: portal_capture('video'))
    image.connect('clicked', selected_image)
    stop.connect('clicked', lambda *_: revoke())
    save.connect('clicked', save_input)
    parent.connect('destroy', lambda *_: window.destroy())
    window.show_all(); enabled()
    return window


if __name__ == '__main__':
    try:
        if not sys.flags.isolated or os.getuid() == 0 or os.geteuid() != os.getuid() or len(sys.argv) not in (6, 8) or sys.argv[1] != '--capture-worker' or not re.fullmatch(r'[1-9][0-9]?', sys.argv[3]) or not re.fullmatch(r'[1-9][0-9]{0,19}', sys.argv[4]) or not re.fullmatch(r'[1-9][0-9]{0,9}', sys.argv[5]):
            raise ValueError('capture worker requires an isolated ordinary-user finite invocation')
        capture_worker(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), *(tuple((int(sys.argv[6]), sys.argv[7])) if len(sys.argv) == 8 else ()), parent_pid=int(sys.argv[5]))
    except Exception:
        sys.exit(1)
