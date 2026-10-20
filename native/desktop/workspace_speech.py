"""Explicit local speech output; no model, microphone or publication authority.

The user reviews literal text, renders a complete bounded WAV in a separate
confined one-shot worker, then separately consents to audible playback. Hiding,
locking or closing the window revokes both stages. A rendered WAV is data, never
an inference result, an OS effect, or permission to execute model suggestions.
"""
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import time
import zipfile

RATE = 22050
MAX_SECONDS = 30
MAX_TEXT = 4096
MAX_WAV = 44 + RATE * MAX_SECONDS * 2
RENDER = '/usr/libexec/luma-os/speech/luma-tts-render'
SCRIPT = '/usr/libexec/luma-os/workspace_speech.py'
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
ASR_PROFILE = 'whisper-tiny-multilingual-f16-cpu-v1'
MAX_PCM = 960000
UNCERTAIN = []
_CAPTURE = None


def capture_module():
    global _CAPTURE
    if _CAPTURE is not None:
        return _CAPTURE
    import importlib.util
    helper = Path('/usr/libexec/luma-os/workspace_capture.py')
    if helper.resolve(strict=True) != helper:
        raise ValueError('speech capture dependency is redirected')
    for ancestor in helper.parents:
        info = ancestor.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('speech capture dependency ancestor is unprotected')
    info = helper.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o7022 or not 0 < info.st_size <= 128*1024:
        raise ValueError('speech capture dependency is not protected')
    spec = importlib.util.spec_from_file_location('luma_speech_capture_controls', helper)
    loaded = importlib.util.module_from_spec(spec); sys.modules[spec.name] = loaded
    spec.loader.exec_module(loaded)
    _CAPTURE = loaded
    return loaded


def strict_json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError('duplicate speech field')
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite speech JSON')))


def transcription_request(value):
    if not isinstance(value, dict) or set(value) != {'schema_version', 'login', 'capture_path'} or type(value['schema_version']) is not int or value['schema_version'] != 1 or not isinstance(value['login'], str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', value['login']):
        raise ValueError('speech journey requires exact original human login and selected local capture')
    path = value['capture_path']
    if not isinstance(path, str) or len(path.encode()) > 8192 or '\0' in path or not Path(path).is_absolute() or not path.endswith('.luma-capture.zip'):
        raise ValueError('explicit local .luma-capture.zip audio envelope required')
    return value


def capture_pcm(envelope):
    """Import exactly one explicit saved bounded speech capture, never a URI.

    ZIP metadata is inert and cannot confer capture permission, authorship or
    model authority. The caller separately holds one ordinary-user private-file
    read; sample bounds and actual digest are reconstructed here.
    """
    if not isinstance(envelope, bytes) or not 0 < len(envelope) <= MAX_PCM+16384:
        raise ValueError('saved audio envelope exceeds its closed input bound')
    with zipfile.ZipFile(io.BytesIO(envelope), 'r') as archive:
        entries = archive.infolist()
        if len(entries) != 2 or archive.comment or min(entry.header_offset for entry in entries) != 0 or {entry.filename for entry in entries} != {'capture.json', '00.pcm'} or any(entry.compress_type != zipfile.ZIP_STORED or entry.compress_size != entry.file_size or entry.flag_bits or entry.extra or entry.is_dir() for entry in entries):
            raise ValueError('speech import requires two exact uncompressed capture members')
        sizes = {entry.filename: entry.file_size for entry in entries}
        if not 0 < sizes['capture.json'] <= 8192 or not 3200 <= sizes['00.pcm'] <= MAX_PCM or sizes['00.pcm'] % 2:
            raise ValueError('saved speech sample duration or metadata exceeds bounds')
        metadata = strict_json(archive.read('capture.json'))
        pcm = archive.read('00.pcm')
    fields = {'schema_version', 'capture_id', 'kind', 'elapsed_ms', 'sample_rate', 'channels',
              'format', 'bytes', 'frames', 'transcribed', 'published', 'model_submitted'}
    frame = {'index': 0, 'bytes': len(pcm), 'sha256': hashlib.sha256(pcm).hexdigest()}
    if not isinstance(metadata, dict) or set(metadata) != fields or type(metadata['schema_version']) is not int or metadata['schema_version'] != 1 or metadata['kind'] != 'speech' or not isinstance(metadata['capture_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', metadata['capture_id']) or type(metadata['elapsed_ms']) is not int or not 0 <= metadata['elapsed_ms'] <= 31000 or type(metadata['sample_rate']) is not int or metadata['sample_rate'] != 16000 or type(metadata['channels']) is not int or metadata['channels'] != 1 or metadata['format'] != 's16le-pcm' or type(metadata['bytes']) is not int or metadata['bytes'] != len(pcm) or metadata['frames'] != [frame] or any(metadata[key] is not False for key in ('transcribed', 'published', 'model_submitted')) or not any(pcm):
        raise ValueError('saved input is not exact non-silent mono16kHz PCM capture data')
    if len(metadata['frames']) != 1 or any(type(metadata['frames'][0][key]) is not int for key in ('index', 'bytes')):
        raise ValueError('saved audio frame counters must be exact integers')
    return pcm


def asr_input(pcm):
    if not isinstance(pcm, bytes) or not 3200 <= len(pcm) <= MAX_PCM or len(pcm) % 2 or not any(pcm):
        raise ValueError('ASR needs one bounded non-silent mono16kHz S16LE utterance')
    return json.dumps({'schema_version': 1, 'profile_id': ASR_PROFILE, 'pcm_hex': pcm.hex()}, separators=(',', ':')).encode('ascii')


def transcription_scope(encoded):
    value = strict_json(encoded)
    if not isinstance(value, dict) or set(value) != {'action', 'selector', 'input_bytes', 'output_bytes', 'units'} or value['action'] != 'inference.execute' or any(type(value[key]) is not int or value[key] != expected for key, expected in (('input_bytes', MAX_PCM), ('output_bytes', 65536), ('units', 128))):
        raise ValueError('ASR native review is not its exact finite audio/decoder allowance')
    selector = value['selector']
    if not isinstance(selector, dict) or set(selector) != {'kind', 'id', 'generation', 'digest'} or selector['kind'] != 'model' or selector['id'] != ASR_PROFILE or type(selector['generation']) is not int or selector['generation'] != 1 or not isinstance(selector['digest'], str) or not re.fullmatch(r'[0-9a-f]{64}', selector['digest']) or selector['digest'] == '0'*64:
        raise ValueError('ASR review substituted its exact auxiliary resource selector')
    return value


def transcription_result(encoded, request, pcm, scope):
    if not isinstance(encoded, bytes) or not 0 < len(encoded) < 65536:
        raise ValueError('ASR output exceeds complete-result bound')
    value = strict_json(encoded)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'request_sha256', 'binding', 'lease', 'transcript'} or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['request_sha256'] != hashlib.sha256(request).hexdigest() or value['binding'] != scope['selector']['digest']:
        raise ValueError('ASR result differs from exact reviewed input/resource request')
    token = value['lease']
    if not isinstance(token, dict) or set(token) != {'lease_id', 'generation', 'manager_epoch'} or any(not isinstance(token[key], str) or not re.fullmatch(r'[0-9a-f]{32}', token[key]) for key in ('lease_id', 'manager_epoch')) or not isinstance(token['generation'], str) or not re.fullmatch(r'[1-9][0-9]{0,19}', token['generation']) or int(token['generation']) > 2**64-1:
        raise ValueError('ASR result has no exact physical resource generation')
    result = value['transcript']
    fields = {'schema_version', 'profile_id', 'model_binding', 'runtime_sha256', 'audio_sha256',
              'audio_samples', 'decoder_tokens', 'language', 'text', 'human_review_required', 'automatic_model_handoff'}
    if not isinstance(result, dict) or set(result) != fields or type(result['schema_version']) is not int or result['schema_version'] != 1 or result['profile_id'] != ASR_PROFILE or result['audio_sha256'] != hashlib.sha256(pcm).hexdigest() or type(result['audio_samples']) is not int or result['audio_samples'] != len(pcm)//2 or type(result['decoder_tokens']) is not int or not 0 <= result['decoder_tokens'] < 128 or result['language'] != 'en' or result['human_review_required'] is not True or result['automatic_model_handoff'] is not False or any(not isinstance(result[key], str) or not re.fullmatch(r'[0-9a-f]{64}', result[key]) for key in ('model_binding', 'runtime_sha256')) or not isinstance(result['text'], str) or len(result['text'].encode('utf-8')) > 8192 or any(ord(c) < 32 and c not in '\t\n' or 127 <= ord(c) <= 159 for c in result['text']):
        raise ValueError('ASR transcript changed the decoder/audio/runtime bounds or claims automatic authority')
    return result


def transcription_journey(auth, value, directory):
    """Original native finite Infer, then optional edited human conversation.

    Reuse the fixed bridge's PAM tty, private request lifetime, bounded capture
    and existing real-model conversation. Audio itself is never forwarded to
    the text model, content store or a workflow; a transcript needs new review.
    """
    auth.proposal(value)
    source = transcription_request(auth.strict_json(value['request']))
    capture_path = Path('/usr/libexec/luma-os/workspace_capture.py')
    auth.protected(capture_path, 128*1024)
    import importlib.util
    spec = importlib.util.spec_from_file_location('luma_speech_capture_import', capture_path)
    capture = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = capture
    spec.loader.exec_module(capture)
    pcm = capture_pcm(capture.private_file(Path(source['capture_path']), MAX_PCM+16384))
    request = asr_input(pcm)
    submitted = observed = False
    try:
        print('Explicit auxiliary ASR, not manual mode and not the selected text LLM. Requires current signed/qualified auxiliary model and a fresh finite Infer grant. Initial decoder: English. Tiny ASR can mistranscribe and hallucinate; always review. No microphone, speaker, model handoff or workflow starts automatically.', flush=True)
        with auth.request_stage(directory, request.decode('ascii')) as path:
            prefix = ['/usr/bin/sudo', '--', auth.NATIVE, 'granted-run']
            scope = transcription_scope(auth._capture_native(prefix+['speech-review', str(path)], 65536))
            print('Exact audio SHA256: '+hashlib.sha256(pcm).hexdigest()+'; samples: '+str(len(pcm)//2)+'; profile: '+ASR_PROFILE, flush=True)
            print('Native finite Infer scope (DATA, not an issued grant):\n'+json.dumps(scope, ensure_ascii=True, indent=2), flush=True)
            grant = auth.grant_selection('Fresh finite Infer grant for exactly this auxiliary scope, or q: ')
            if grant is None or auth.terminal_line('Type transcribe:'+scope['selector']['digest']+' to submit this exact utterance, or q: ', 128) != 'transcribe:'+scope['selector']['digest']:
                print('CANCELLED before ASR submission.', flush=True)
                return 0
            submitted = True
            result = transcription_result(auth._capture_native(prefix+['speech-transcribe', source['login'], grant, str(path)], 65536), request, pcm, scope)
            observed = True
        print('OBSERVED actual bounded ASR completion. Transcript is escaped untrusted DATA, not a grounded reference or OS instruction:\n'+json.dumps(result['text'], ensure_ascii=True), flush=True)
        choice = auth.terminal_line('q finish; c REVIEW/EDIT a separate human text-model prompt; s separately reviewed local speech output: ', 8)
        if choice == 'q':
            return 0
        if choice == 's':
            return readback(auth, result['text'], directory)
        if choice != 'c':
            raise ValueError('explicit reviewed handoff selection required')
        prompt = auth.terminal_line('Enter the reviewed/corrected human prompt (one line, at most4096UTF-8bytes; q cancels). Resolve ambiguous references before consequential use: ', 4096)
        if prompt == 'q':
            return 0
        auth.conversation_messages([{'role': 'user', 'content': prompt}])
        request = {'schema_version': 1, 'login': source['login'], 'messages': [{'role': 'user', 'content': prompt}], 'max_tokens': 128}
        handoff = dict(value, operation='conversation-journey', request=auth.encoded(request).decode('utf-8'))
        return auth.conversation_journey(handoff, directory)
    except (KeyboardInterrupt, EOFError):
        print('ASR already completed and was validated; interruption does not undo it.' if observed else 'UNCERTAIN: ASR was submitted; native retains revocation/drain obligations. Do not assume cancellation, release or retry.' if submitted else 'Stopped before ASR submission.', file=sys.stderr, flush=True)
        return 130
    except Exception:
        print('ASR was already validated; subsequent handoff failed without an inferred model/workflow completion.' if observed else 'UNCERTAIN: submitted ASR has no complete validated delivery; inspect native resource/effect evidence before retry.' if submitted else 'ASR unavailable or refused before submission. Use manual controls; no ungoverned fallback.', file=sys.stderr, flush=True)
        return 1


def readback(auth, text, directory):
    if not isinstance(text, str) or len(text.encode('utf-8')) > 8192:
        raise ValueError('speech review needs one bounded observed text reply')
    auth.protected(Path(SCRIPT), 128*1024)
    with auth.request_stage(directory, text) as path:
        # Completion of this GUI subprocess is not audible success. Its trusted
        # controls still require separate Render then Play clicks after editing.
        return subprocess.call(['/usr/bin/python3', '-I', SCRIPT, '--review-output', str(path)],
            close_fds=True, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8',
                **{key: os.environ[key] for key in ('DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'XDG_SESSION_TYPE') if key in os.environ}})


def review_output(path):
    if os.getuid() < 1000 or os.getuid() >= 65534 or os.getuid() != os.geteuid() or not sys.flags.isolated:
        raise ValueError('speech review requires an ordinary installed human session')
    if any(os.environ.get(key) for key in ('GTK_MODULES', 'GI_TYPELIB_PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH')):
        raise ValueError('speech review refuses runtime module injection')
    # Reuse the same fixed protected import/canonical private-file reader as
    # capture. No caller-selected Python module is loaded.
    import importlib.util
    helper = Path('/usr/libexec/luma-os/workspace_capture.py')
    if helper.resolve(strict=True) != helper:
        raise ValueError('speech capture dependency is redirected')
    for ancestor in helper.parents:
        info = ancestor.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('speech review dependency ancestor is unprotected')
    info = helper.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o7022 or not 0 < info.st_size <= 128*1024:
        raise ValueError('speech review capture dependency is not protected')
    spec = importlib.util.spec_from_file_location('luma_speech_review_capture', helper)
    capture = importlib.util.module_from_spec(spec); sys.modules[spec.name] = capture
    spec.loader.exec_module(capture)
    text = capture.private_file(Path(path), 8192).decode('utf-8', 'strict')
    if any(ord(c) < 32 and c not in '\t\n' or 127 <= ord(c) <= 159 for c in text):
        raise ValueError('speech review text contains control sequences')
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk
    Gtk.init([])
    parent = Gtk.Window(title='Reviewed speech output owner')
    dialog = launch_speech(parent, text)
    dialog.connect('destroy', lambda *_: Gtk.main_quit())
    try:
        Gtk.main()
    finally:
        parent.destroy()


def clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def literal_text(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('review nonempty literal text first')
    encoded = value.encode('utf-8', 'strict')
    if len(encoded) > MAX_TEXT or any(ord(c) < 32 and c not in '\t\n' or 127 <= ord(c) <= 159 for c in value):
        raise ValueError('speech text exceeds its literal UTF-8 bound')
    return encoded


def wav_samples(value):
    if not isinstance(value, bytes) or not 46 <= len(value) <= MAX_WAV:
        raise ValueError('speech requires a complete bounded PCM WAV')
    expected = (b'RIFF', len(value)-8, b'WAVE', b'fmt ', 16, 1, 1,
                RATE, RATE*2, 2, 16, b'data', len(value)-44)
    if struct.unpack('<4sI4s4sIHHIIHH4sI', value[:44]) != expected or (len(value)-44) % 2:
        raise ValueError('speech WAV is not the exact fixed mono S16LE format')
    return value[44:]


def sealed(name, content):
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise ValueError('incomplete speech input snapshot')
            offset += written
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, SEALS)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class OwnedSpeech:
    """One PIDFD-owned worker, bounded output and revocation that proves reap.

    No numeric process group is signalled. Workers prohibit descendant process
    creation; the PIDFD keeps cancellation bound to the original worker even
    after exit. An uncertain cleanup retains its handle and refuses renewal.
    """
    def __init__(self):
        self.child = None
        self.pidfd = None
        self.deadline = None
        self.received = bytearray()
        self.failed = False
        self.kind = None

    def start(self, kind, content):
        if self.failed or self.child is not None or kind not in ('render', 'play'):
            raise ValueError('speech worker admission is closed or already occupied')
        if kind == 'render':
            if literal_text(content.decode('utf-8', 'strict')) != content:
                raise ValueError('speech text changed')
            command = ['/usr/bin/aa-exec', '-p', 'luma-workspace-speech-render', '--', RENDER]
            name, duration = 'luma-speech-text', 5
        else:
            wav_samples(content)
            command = ['/usr/bin/aa-exec', '-p', 'luma-workspace-speech-play', '--',
                       '/usr/bin/python3', '-I', SCRIPT, '--play-worker', str(os.getpid())]
            name, duration = 'luma-speech-wave', MAX_SECONDS+2
        descriptor = sealed(name, content)
        child = None
        try:
            self.deadline = clock()+duration
            child = subprocess.Popen(command, stdin=descriptor, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True,
                env={'LANG': 'C.UTF-8', 'LUMA_SPEECH_PARENT': str(os.getpid())})
            self.child = child
            self.pidfd = os.pidfd_open(child.pid, 0)
            os.set_blocking(child.stdout.fileno(), False)
            self.kind = kind
            self.received.clear()
        except BaseException:
            self.failed = True
            if child is not None:
                self.child = child
                self.cancel()
            raise
        finally:
            os.close(descriptor)

    def poll(self):
        if self.failed or self.child is None:
            raise ValueError('no active speech worker')
        try:
            if clock() >= self.deadline:
                raise ValueError('speech operation exceeded its consent lifetime')
            while True:
                try:
                    block = os.read(self.child.stdout.fileno(), min(65536, MAX_WAV+1-len(self.received)))
                except BlockingIOError:
                    return None
                if not block:
                    result = self.child.wait(timeout=0.1)
                    if result != 0:
                        raise ValueError('speech worker refused or did not complete')
                    output = bytes(self.received)
                    if self.kind == 'render':
                        wav_samples(output)
                    elif output != b'played\n':
                        raise ValueError('playback did not produce its exact completion marker')
                    self._retire()
                    return output
                self.received.extend(block)
                maximum = MAX_WAV if self.kind == 'render' else len(b'played\n')
                if len(self.received) > maximum:
                    raise ValueError('speech worker output exceeded its complete-result bound')
        except BaseException:
            self.cancel()
            raise

    def _retire(self):
        # Call only after wait proved the exact worker exited. Clearing the
        # handle earlier would lose revocation ownership on cleanup failure.
        self.child.stdout.close()
        if self.pidfd is not None:
            descriptor, self.pidfd = self.pidfd, None
            os.close(descriptor)
        self.child = None
        self.deadline = self.kind = None
        self.received.clear()

    def cancel(self):
        errors = []
        self.received.clear()
        if self.child is not None:
            try:
                if self.pidfd is not None:
                    try:
                        signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                elif self.child.poll() is None:
                    # The unreaped child still owns this PID if PIDFD setup
                    # failed; never signal this PID after poll has reaped it.
                    self.child.kill()
                self.child.wait(timeout=2)
            except BaseException as error:
                errors.append(error)
            if not errors:
                try:
                    self._retire()
                except BaseException as error:
                    errors.append(error)
        if errors:
            self.failed = True
            raise ValueError('speech cleanup could not prove exact worker drain') from errors[0]


def _worker_guard(parent):
    import ctypes
    import resource
    if type(parent) is not int or not 1 < parent < 2**31 or os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid() or os.getppid() != parent:
        raise ValueError('playback requires its original ordinary-user UI owner')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, int(signal.SIGKILL), 0, 0, 0) or os.getppid() != parent:
        raise ValueError('playback parent-death binding failed')
    if Path('/proc/self/attr/current').read_bytes() != b'luma-workspace-speech-play (enforce)\n':
        raise ValueError('playback confinement is not enforcing')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if any(int(status.get(key, '-1').strip(), 16) != 0 for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')):
        raise ValueError('playback must hold no capability')
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(39, 0, 0, 0, 0) != 1:
        raise ValueError('playback cannot acquire privilege')
    for kind, maximum in ((resource.RLIMIT_AS, 256*1024*1024), (resource.RLIMIT_CPU, 3),
                          (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CORE, 0),
                          (resource.RLIMIT_FSIZE, 0), (resource.RLIMIT_MEMLOCK, 0)):
        resource.setrlimit(kind, (maximum, maximum))
    os.environ.clear()
    os.umask(0o077)
    forbid_descendants()


def forbid_descendants():
    """amd64 thread-only seccomp: no child process can escape PIDFD drain."""
    import ctypes
    import platform
    if platform.machine() != 'x86_64':
        raise ValueError('speech worker requires the pinned amd64 runtime')
    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]
    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
    # Load arch/nr; kill other ABIs. Return ENOSYS for clone3 so glibc can use
    # clone; permit clone only with CLONE_THREAD. Exec/fork/vfork are denied.
    instructions = ((0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000),
        (0x20,0,0,0),(0x35,0,1,0x40000000),(0x06,0,0,0x80000000),
        (0x15,0,1,435),(0x06,0,0,0x50000|38),
        (0x15,4,0,57),(0x15,3,0,58),(0x15,2,0,59),(0x15,1,0,322),
        (0x15,1,4,56),(0x06,0,0,0x50000|1),(0x20,0,0,16),
        (0x45,1,0,0x10000),(0x06,0,0,0x50000|1),(0x06,0,0,0x7fff0000))
    rules = (Filter*len(instructions))(*(Filter(*item) for item in instructions))
    program = Program(len(rules), rules)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError(ctypes.get_errno(), 'speech descendant exclusion failed')


def play_worker(parent):
    _worker_guard(parent)
    info = os.fstat(0)
    if not stat.S_ISFIFO(os.fstat(1).st_mode) or not stat.S_ISREG(info.st_mode) or not 46 <= info.st_size <= MAX_WAV or fcntl.fcntl(0, fcntl.F_GET_SEALS) != SEALS or os.readlink('/proc/self/fd/0') != '/memfd:luma-speech-wave (deleted)':
        raise ValueError('playback input is not its exact sealed snapshot')
    content = os.pread(0, MAX_WAV+1, 0)
    os.close(0)
    samples = wav_samples(content)
    import gi
    gi.require_version('Gst', '1.0')
    from gi.repository import Gst
    Gst.init(None)
    pipeline = Gst.Pipeline.new('luma-explicit-speech-output')
    source = Gst.ElementFactory.make('appsrc', 'speech')
    convert = Gst.ElementFactory.make('audioconvert', None)
    resample = Gst.ElementFactory.make('audioresample', None)
    sink = Gst.ElementFactory.make('pulsesink', None)
    if any(item is None for item in (pipeline, source, convert, resample, sink)):
        raise ValueError('fixed speech playback runtime is unavailable')
    # Never accept inherited PULSE_SERVER, a device, a URI or arbitrary caps.
    sink.set_property('server', 'unix:/run/user/'+str(os.getuid())+'/pulse/native')
    source.set_property('caps', Gst.Caps.from_string('audio/x-raw,format=S16LE,rate=22050,channels=1,layout=interleaved'))
    source.set_property('format', Gst.Format.TIME)
    source.set_property('block', True)
    source.set_property('max-bytes', MAX_WAV)
    for item in (source, convert, resample, sink):
        pipeline.add(item)
    if not source.link(convert) or not convert.link(resample) or not resample.link(sink):
        raise ValueError('fixed speech playback pipeline could not link')
    deadline = clock()+len(samples)/(RATE*2)+2
    try:
        if pipeline.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
            raise ValueError('audio output is unavailable or permission was denied')
        buffer = Gst.Buffer.new_allocate(None, len(samples), None)
        buffer.fill(0, samples)
        buffer.pts = 0
        buffer.duration = len(samples)*Gst.SECOND//(RATE*2)
        if source.emit('push-buffer', buffer) != Gst.FlowReturn.OK or source.emit('end-of-stream') != Gst.FlowReturn.OK:
            raise ValueError('speech playback refused its complete bounded buffer')
        bus = pipeline.get_bus()
        while clock() < deadline:
            message = bus.timed_pop_filtered(50*Gst.MSECOND, Gst.MessageType.EOS | Gst.MessageType.ERROR)
            if message is None:
                continue
            if message.type != Gst.MessageType.EOS:
                raise ValueError('audio device was lost or playback failed')
            if os.write(1, b'played\n') != 7:
                raise ValueError('playback completion pipe closed')
            return
        raise ValueError('playback exceeded its bounded duration')
    finally:
        pipeline.set_state(Gst.State.NULL)


def launch_speech(parent, text=''):
    if UNCERTAIN:
        raise ValueError('prior speech worker drainage is uncertain; this controller refuses renewal')
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, GLib, Gio
    window = Gtk.Window(title='Explicit local speech output')
    window.set_transient_for(parent)
    window.set_destroy_with_parent(True)
    window.set_default_size(640, 420)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    box.set_border_width(14)
    window.add(box)
    explanation = Gtk.Label(label='Review literal text first. Render opens no audio device; Play requires a separate click. English rule-based voice; no neural model, microphone, publication or OS action. Stop, hiding or session lock discards audio.')
    explanation.set_line_wrap(True)
    box.pack_start(explanation, False, False, 0)
    view = Gtk.TextView(); view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
    view.get_buffer().set_text(text)
    scroll = Gtk.ScrolledWindow(); scroll.add(view)
    box.pack_start(scroll, True, True, 0)
    indicator = Gtk.Label(label='INACTIVE — no audio output permission held.')
    indicator.set_line_wrap(True)
    box.pack_start(indicator, False, False, 0)
    buttons = Gtk.Box(spacing=10)
    render, play, stop = (Gtk.Button(label=label) for label in ('Render reviewed text', 'Play audio', 'Stop / discard'))
    for button in (render, play, stop):
        buttons.pack_start(button, False, False, 0)
    box.pack_start(buttons, False, False, 0)
    worker = OwnedSpeech()
    state = {'wave': None, 'generation': 0, 'closed': False}
    subscriptions = []
    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    capture = capture_module()
    permission = capture.SessionPermission(lambda: capture.unlocked_session(bus, Gio, GLib))

    def enabled():
        idle = worker.child is None and not worker.failed and not state['closed']
        render.set_sensitive(idle)
        play.set_sensitive(idle and state['wave'] is not None)
        view.set_editable(idle)

    def revoke(message='INACTIVE — permission revoked; audio discarded.'):
        permission.revoke()
        state['generation'] += 1
        state['wave'] = None
        try:
            worker.cancel()
        except Exception:
            message = 'REFUSED — worker cleanup is uncertain; close this window. No new admission is permitted.'
        indicator.set_text(message)
        enabled()

    def begin(kind):
        try:
            if state['closed'] or not window.get_visible():
                raise ValueError('speech review controls are unavailable')
            permission_token = permission.fresh()
            if kind == 'render':
                buffer = view.get_buffer()
                content = literal_text(buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True))
                state['wave'] = None
            else:
                content = state['wave']
                wav_samples(content)
            worker.start(kind, content)
            token = state['generation']
            indicator.set_text('RENDERING — no audio device opened.' if kind == 'render' else 'PLAYING — explicit default-output consent; Stop cancels now.')
            enabled()
            def tick():
                if token != state['generation'] or state['closed']:
                    return False
                try:
                    permission.current(permission_token)
                    result = worker.poll()
                    if result is None:
                        return True
                    permission.check(permission_token)
                    if kind == 'render':
                        state['wave'] = result
                        indicator.set_text('READY — complete audio rendered privately. Click Play separately, or Stop to discard.')
                    else:
                        state['wave'] = None
                        indicator.set_text('INACTIVE — output stream completed; audibility is not asserted. Audio discarded.')
                    enabled()
                except Exception:
                    revoke('INACTIVE — speech failed, exceeded its bounds, or lost its audio device; audio discarded.')
                return False
            GLib.timeout_add(25, tick)
        except Exception:
            revoke('INACTIVE — speech refused; review nonempty UTF-8 text of at most 4096 bytes and try a shorter utterance.')

    def changed(*_):
        if worker.child is None:
            state['wave'] = None
            enabled()

    def locked(_connection, _sender, _path, _interface, _member, parameters, _data):
        values = parameters.unpack()
        if len(values) != 1 or type(values[0]) is not bool or values[0]:
            revoke('INACTIVE — session locked; output permission revoked.')
    for name in ('org.gnome.ScreenSaver', 'org.freedesktop.ScreenSaver'):
        subscriptions.append(bus.signal_subscribe(name, name, 'ActiveChanged', None, None,
            Gio.DBusSignalFlags.NONE, locked, None))
        def owner_changed(_connection, _sender, _path, _interface, _member, parameters, _data):
            _name, old, new = parameters.unpack()
            if old != new:
                revoke('INACTIVE — session lock service changed; output permission revoked.')
        subscriptions.append(bus.signal_subscribe('org.freedesktop.DBus', 'org.freedesktop.DBus',
            'NameOwnerChanged', '/org/freedesktop/DBus', name, Gio.DBusSignalFlags.NONE,
            owner_changed, None))
    def lost_bus(*_):
        permission.close()
        revoke('INACTIVE — session lock bus was lost; output permission revoked.')
    bus_closed = bus.connect('closed', lost_bus)
    def destroyed(*_):
        state['closed'] = True
        revoke()
        if worker.child is not None and worker not in UNCERTAIN:
            # Keep the actual PIDFD and child until this UI process exits, whose
            # death also triggers the worker's kernel parent-death SIGKILL.
            UNCERTAIN.append(worker)
        bus.disconnect(bus_closed)
        for subscription in subscriptions:
            bus.signal_unsubscribe(subscription)
        subscriptions.clear()
    window.connect('destroy', destroyed)
    window.connect('unmap', lambda *_: revoke())
    parent.connect('destroy', lambda *_: window.destroy())
    render.connect('clicked', lambda *_: begin('render'))
    play.connect('clicked', lambda *_: begin('play'))
    stop.connect('clicked', lambda *_: revoke())
    view.get_buffer().connect('changed', changed)
    window.show_all(); enabled()
    return window


if __name__ == '__main__':
    try:
        if sys.flags.isolated and len(sys.argv) == 3 and sys.argv[1] == '--review-output':
            review_output(sys.argv[2])
        elif sys.flags.isolated and len(sys.argv) == 3 and sys.argv[1] == '--play-worker' and re.fullmatch(r'[1-9][0-9]{0,9}', sys.argv[2]):
            play_worker(int(sys.argv[2]))
        else:
            raise ValueError('speech output worker requires one isolated finite invocation')
    except Exception:
        sys.exit(1)
