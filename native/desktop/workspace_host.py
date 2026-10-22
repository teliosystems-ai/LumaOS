"""Unprivileged native-engine preview host; no product/storage authority.

Only a fixed installed CLI and closed content-contract commands execute. There
is no HTTP server, account lookup, grant issuance, private repository access,
model call, persistence, export, or workflow-completion receipt here.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import threading
import time

MAX_SOURCE = 1024 * 1024
MAX_ENVELOPE = MAX_SOURCE * 6 + 8192
MAX_MESSAGE = MAX_ENVELOPE * 2 + 16384
MAX_OUTPUT = MAX_ENVELOPE * 2 + 16384
TIMEOUT = 15.0
ENGINES = frozenset(('text', 'csv', 'json', 'spreadsheet', 'document', 'diagram', 'animation', 'collection'))
FLAGS = dict(owner_authenticated=False, authority_returned=False, committed=False,
             workflow_executed=False, source_retained=False, gate_closing=False)
PREVIEW_BINDING = dict(installation=hashlib.sha256(b'luma-untrusted-preview-installation-v1').hexdigest(),
                       owner=hashlib.sha256(b'luma-untrusted-preview-owner-v1').hexdigest(), owner_generation=1)


def digest(value):
    return hashlib.sha256(value.encode('utf-8') if isinstance(value, str) else value).hexdigest()


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def strict_json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def request(value):
    if isinstance(value, str):
        if len(value.encode('utf-8')) > MAX_MESSAGE:
            raise ValueError('preview transport bound exceeded')
        value = strict_json(value)
    if not isinstance(value, dict) or type(value.get('schema_version')) is not int or value['schema_version'] != 1:
        raise ValueError('invalid preview schema')
    if not isinstance(value.get('id'), str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}', value['id']):
        raise ValueError('invalid preview request ID')
    operation = value.get('operation')
    if operation == 'cancel':
        if set(value) != {'schema_version', 'id', 'operation'}:
            raise ValueError('unknown cancellation field')
        return value
    fields = {'schema_version', 'id', 'operation', 'source'}
    if operation == 'preview':
        fields.add('engine')
        if value.get('engine') not in ENGINES:
            raise ValueError('unsupported preview engine')
        maximum = MAX_SOURCE
    elif operation == 'reopen':
        fields.add('expected_envelope_sha256')
        if not isinstance(value.get('expected_envelope_sha256'), str) or not re.fullmatch(r'[0-9a-f]{64}', value['expected_envelope_sha256']):
            raise ValueError('reopen requires the independently selected whole-envelope SHA256')
        maximum = MAX_ENVELOPE
    else:
        raise ValueError('unsupported preview operation')
    if set(value) != fields or not isinstance(value.get('source'), str) or len(value['source'].encode('utf-8')) > maximum:
        raise ValueError('invalid preview source or closed fields')
    if operation == 'reopen' and digest(value['source']) != value['expected_envelope_sha256']:
        raise ValueError('whole-envelope hash mismatch')
    return value


def invocation(value):
    """Prepare inert CLI input, never a private read selector or a grant."""
    if value['operation'] == 'reopen':
        envelope = strict_json(value['source'])
        binding = envelope['receipt']['binding']
        return 'content-contract-reopen', encode(dict(schema_version=1, binding=binding, envelope=value['source']))
    engine, source = value['engine'], value['source']
    if engine in ('text', 'csv', 'json'):
        payload = dict(schema_version=1, binding=PREVIEW_BINDING, artifact_id='manual-preview',
                       format='utf8-text' if engine == 'text' else engine, content=source,
                       provenance=dict(request_id=value['id'], workflow_sha256=digest('unexecuted-manual-preview-v1'),
                                       source_sha256=digest(source), origin='managed'))
        return 'content-contract-capture', encode(payload)
    return 'content-contract-' + engine, source.encode('utf-8')


def closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError('native result has unknown or missing fields')
    return value


def integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('native result integer is invalid or exceeds its bound')
    return value


def same_json(left, right):
    # Python considers True == 1, including inside dictionaries. A typed native
    # source must not be replaced by a structurally different JSON scalar.
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(same_json(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(same_json(a, b) for a, b in zip(left, right))
    return left == right


def checked_text(value, key, sha, maximum=MAX_SOURCE):
    text = value.get(key)
    if not isinstance(text, str) or len(text.encode('utf-8')) > maximum or value.get(sha) != digest(text):
        raise ValueError('native result digest mismatch: ' + key)
    return text


def spreadsheet_values(rendered, source):
    """Join displayed cell bytes to verified CSV; never recalculate formulas."""
    values = rendered['values']
    rows = source.get('rows') if isinstance(source, dict) else None
    if not isinstance(values, list) or not 1 <= len(values) <= 64 or not isinstance(rows, list) or len(rows) != len(values):
        raise ValueError('native table height differs from exact source')
    width = len(values[0]) if isinstance(values[0], list) else 0
    if not 1 <= width <= 32:
        raise ValueError('native table width exceeds bound')
    lines = []
    for row, source_row in zip(values, rows):
        if not isinstance(row, list) or len(row) != width or not isinstance(source_row, list) or len(source_row) != width:
            raise ValueError('native table is ragged or differs from exact source')
        fields = []
        for cell, original in zip(row, source_row):
            if not isinstance(cell, dict) or not isinstance(original, dict):
                raise ValueError('native table cell has wrong type')
            kind = cell.get('kind')
            expected = {'blank': 'blank', 'text': 'text', 'number': 'number', 'formula': 'number'}.get(original.get('kind'))
            if kind != expected or kind not in ('blank', 'text', 'number'):
                raise ValueError('native table result type differs from exact source')
            closed(cell, ('kind',) if kind == 'blank' else ('kind', 'value'))
            text = '' if kind == 'blank' else cell['value']
            if not isinstance(text, str) or len(text.encode('utf-8')) > 4096:
                raise ValueError('native table cell exceeds byte bound')
            if kind == 'number' and (not re.fullmatch(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]{0,5}[1-9])?', text)
                                     or text == '-0' or len(text) > 40):
                raise ValueError('native table number is not canonical exact decimal')
            if kind == 'text' and (not isinstance(original.get('value'), str) or text != original['value'].replace('\r\n', '\n')):
                raise ValueError('native table literal text differs from exact source')
            fields.append('"' + text.replace('"', '""') + '"' if any(character in text for character in ',"\n') else text)
        lines.append(','.join(fields) + '\n')
    if ''.join(lines) != rendered['canonical_csv']:
        raise ValueError('native displayed table differs from its verified CSV')


def csv_values(source):
    source = source.replace('\r\n', '\n')
    if '\r' in source:
        raise ValueError('native capture CSV comparison has unsupported line endings')
    values = []
    for row in csv.reader(io.StringIO(source, newline=''), strict=True):
        if len(values) >= 10001 or not 1 <= len(row) <= 32 or any(len(field.encode('utf-8')) > 4096 for field in row):
            raise ValueError('native capture CSV comparison exceeds its bound')
        if values and len(row) != len(values[0]):
            raise ValueError('native capture CSV comparison is ragged')
        values.append(row)
    if not values:
        raise ValueError('native capture CSV comparison cannot be empty')
    return values


def validate_result(value, output):
    if not isinstance(output, (bytes, str)) or len(output.encode('utf-8') if isinstance(output, str) else output) > MAX_OUTPUT:
        raise ValueError('native result exceeds transport bound')
    result = strict_json(output)
    closed(result, ('schema_version', 'result', 'owner_authenticated', 'authority_returned', 'committed', 'certified', 'gate_closing'))
    integer(result['schema_version'], 1, 1)
    for field in ('owner_authenticated', 'authority_returned', 'committed', 'certified', 'gate_closing'):
        if result.get(field) is not False:
            raise ValueError('native preview response claims authority')
    data = result['result']
    if not isinstance(data, dict):
        raise ValueError('native result payload must be a closed object')
    operation = value['operation']
    engine = value.get('engine')
    expected = 'reopen' if operation == 'reopen' else 'capture' if engine in ('text', 'csv', 'json') else 'collection-source' if engine == 'collection' else engine
    if data.get('operation') != expected:
        raise ValueError('native response operation substitution')
    if expected in ('capture', 'reopen'):
        closed(data, ('operation', 'validated' if expected == 'reopen' else 'proposed'))
        artifact = data['validated' if expected == 'reopen' else 'proposed']
        closed(artifact, ('receipt', 'reference', 'canonical_envelope'))
        envelope_text = artifact['canonical_envelope']
        if not isinstance(envelope_text, str) or len(envelope_text.encode('utf-8')) > MAX_ENVELOPE:
            raise ValueError('native envelope bound exceeded')
        envelope = strict_json(envelope_text)
        closed(envelope, ('receipt', 'receipt_sha256', 'content'))
        receipt, content = envelope['receipt'], envelope['content']
        closed(receipt, ('schema_version', 'binding', 'artifact_id', 'version', 'previous', 'format', 'media_type',
                         'content_sha256', 'content_bytes', 'original_bytes', 'provenance'))
        integer(receipt['schema_version'], 1, 1)
        integer(receipt['version'], 1, 2**64 - 1)
        integer(receipt['content_bytes'], 0, MAX_SOURCE)
        integer(receipt['original_bytes'], 0, MAX_SOURCE)
        closed(receipt['binding'], ('installation', 'owner', 'owner_generation'))
        integer(receipt['binding']['owner_generation'], 1, 2**64 - 1)
        closed(receipt['provenance'], ('request_id', 'workflow_sha256', 'source_sha256', 'origin'))
        closed(artifact['reference'], ('artifact_id', 'version', 'content_sha256', 'receipt_sha256'))
        integer(artifact['reference']['version'], 1, 2**64 - 1)
        media = {'utf8-text': 'text/plain; charset=utf-8', 'csv': 'text/csv; charset=utf-8', 'json': 'application/json'}
        if receipt['format'] not in media or receipt['media_type'] != media[receipt['format']]:
            raise ValueError('native content media type differs from exact format')
        if receipt['format'] != 'utf8-text' and (receipt['content_bytes'] == 0 or receipt['original_bytes'] == 0):
            raise ValueError('native non-text receipt cannot describe empty content')
        if (not isinstance(content, str) or digest(content) != receipt['content_sha256']
                or len(content.encode('utf-8')) != receipt['content_bytes']
                or digest(encode(receipt)) != envelope['receipt_sha256']
                or not same_json(artifact['receipt'], receipt)
                or not same_json(artifact['reference'], dict(artifact_id=receipt['artifact_id'], version=receipt['version'],
                                                 content_sha256=receipt['content_sha256'], receipt_sha256=envelope['receipt_sha256']))):
            raise ValueError('native content/reference/receipt digest mismatch')
        if operation == 'reopen' and envelope_text != value['source']:
            raise ValueError('native reopen substituted the exact selected envelope')
        if operation != 'reopen':
            wanted_format = 'utf8-text' if engine == 'text' else engine
            wanted_provenance = dict(request_id=value['id'], workflow_sha256=digest('unexecuted-manual-preview-v1'),
                                     source_sha256=digest(value['source']), origin='managed')
            if (not same_json(receipt['binding'], PREVIEW_BINDING) or receipt['format'] != wanted_format
                    or not same_json(receipt['provenance'], wanted_provenance) or receipt['artifact_id'] != 'manual-preview'
                    or receipt['version'] != 1 or receipt['previous'] is not None
                    or receipt['original_bytes'] != len(value['source'].encode('utf-8'))):
                raise ValueError('native capture substituted the exact preview intent')
            if ((engine == 'text' and content != value['source'].replace('\r\n', '\n'))
                    or (engine == 'json' and not same_json(strict_json(content), strict_json(value['source'])))
                    or (engine == 'csv' and csv_values(content) != csv_values(value['source']))):
                raise ValueError('native capture content differs from exact selected source')
        data['envelope_sha256'] = digest(envelope_text)
        data['preview_content'] = content
        data['preview_format'] = receipt['format']
    elif engine == 'collection':
        closed(data, ('operation', 'artifact_id', 'canonical_source', 'source_sha256', 'membership_validated_against_private_history',
                      'membership_is_authority', 'semantic_classification', 'source_retained'))
        canonical = checked_text(data, 'canonical_source', 'source_sha256')
        source = strict_json(canonical)
        if not same_json(source, strict_json(value['source'])):
            raise ValueError('native collection source substitution')
        if (any(data[field] is not False for field in ('membership_validated_against_private_history', 'membership_is_authority',
                                                       'semantic_classification', 'source_retained'))
                or data['artifact_id'] != 'collection.' + source['collection_id']):
            raise ValueError('collection preview cannot validate membership authority')
    else:
        if engine == 'spreadsheet':
            closed(data, ('operation', 'calculation', 'typed_expressions_evaluated', 'csv_formula_text_executed', 'source_retained'))
            if data['typed_expressions_evaluated'] is not True or data['csv_formula_text_executed'] is not False or data['source_retained'] is not False:
                raise ValueError('native spreadsheet claims unsupported execution or retention')
        else:
            fields = ('operation', 'rendering', 'scripts_executed', 'external_resources_loaded', 'source_retained')
            closed(data, (*fields, 'playback_started') if engine == 'animation' else fields)
            if any(data[field] is not False for field in fields[2:]) or (engine == 'animation' and data['playback_started'] is not False):
                raise ValueError('native rendering claims scripts, external resources, retention or autoplay')
        rendered = data['calculation' if engine == 'spreadsheet' else 'rendering']
        fields = ('schema_version', 'engine', 'canonical_source', 'source_sha256')
        extra = {'spreadsheet': ('values', 'canonical_csv', 'csv_sha256', 'evaluation_steps'),
                 'document': ('canonical_html', 'html_sha256', 'work_units'),
                 'diagram': ('canonical_svg', 'svg_sha256', 'work_units'),
                 'animation': ('frames_per_second', 'frames', 'frames_sha256', 'work_units')}
        closed(rendered, (*fields, *extra[engine]))
        canonical = checked_text(rendered, 'canonical_source', 'source_sha256')
        source = strict_json(canonical)
        if not same_json(source, strict_json(value['source'])):
            raise ValueError('native editable source substitution')
        implementation = {'spreadsheet': 'luma-exact-spreadsheet-v1', 'document': 'luma-static-document-v1',
                          'diagram': 'luma-static-diagram-v1', 'animation': 'luma-sampled-animation-v1'}
        if rendered.get('engine') != implementation[engine]:
            raise ValueError('native engine implementation substitution')
        integer(rendered['schema_version'], 1, 1)
        integer(rendered['evaluation_steps'] if engine == 'spreadsheet' else rendered['work_units'], 0,
                {'spreadsheet': 65536, 'document': 2 * MAX_SOURCE, 'diagram': 65536, 'animation': 120 * (1 + 32 * 64)}[engine])
        if engine == 'spreadsheet':
            checked_text(rendered, 'canonical_csv', 'csv_sha256')
            spreadsheet_values(rendered, source)
        elif engine == 'document':
            checked_text(rendered, 'canonical_html', 'html_sha256')
        elif engine == 'diagram':
            checked_text(rendered, 'canonical_svg', 'svg_sha256')
        elif engine == 'animation':
            integer(rendered['frames_per_second'], 1, 60)
            if (rendered['frames_per_second'] != source.get('frames_per_second')
                    or type(source.get('frames_per_second')) is not int):
                raise ValueError('native animation timing differs from exact source')
            frames = rendered['frames']
            if not isinstance(frames, list) or not 1 <= len(frames) <= 120 or len(frames) != source.get('frame_count') or type(source.get('frame_count')) is not int:
                raise ValueError('native frame count exceeds bound')
            ordered = []
            total = 0
            for index, frame in enumerate(frames):
                closed(frame, ('index', 'canonical_svg', 'svg_sha256'))
                if type(frame['index']) is not int or frame['index'] != index:
                    raise ValueError('native frame identity mismatch')
                total += len(checked_text(frame, 'canonical_svg', 'svg_sha256').encode('utf-8'))
                if total > MAX_SOURCE:
                    raise ValueError('native animation total rendering exceeds bound')
                ordered.append(dict(index=index, canonical_svg=frame['canonical_svg'], svg_sha256=frame['svg_sha256']))
            if digest(encode(ordered)) != rendered['frames_sha256']:
                raise ValueError('native ordered frame digest mismatch')
    return data


class PinnedExecutable:
    """Pin exact installed bytes; this does not attest release/dependency custody."""
    def __init__(self, path):
        path = Path(path)
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('native executable must be canonical and absolute')
        for parent in path.parents:
            metadata = parent.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError('native executable path is not root protected')
        self.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(self.fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1
                    or metadata.st_mode & 0o7022 or not metadata.st_mode & 0o111 or metadata.st_size > 128 * 1024 * 1024):
                raise ValueError('unsafe native executable metadata')
            self.identity = self.metadata(metadata)
            self.sha256 = self.hash()
            self.check()
        except BaseException:
            os.close(self.fd)
            raise

    @staticmethod
    def metadata(value):
        return value.st_dev, value.st_ino, value.st_size, value.st_mode, value.st_uid, value.st_gid, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns

    def hash(self):
        result, offset = hashlib.sha256(), 0
        while True:
            block = os.pread(self.fd, 65536, offset)
            if not block:
                break
            result.update(block)
            offset += len(block)
            if offset > 128 * 1024 * 1024:
                raise ValueError('native executable byte bound exceeded')
        return result.hexdigest()

    def check(self):
        if self.metadata(os.fstat(self.fd)) != self.identity or self.hash() != self.sha256:
            raise ValueError('pinned native executable changed')

    def close(self):
        os.close(self.fd)


def run_process(binary, command, payload, cancelled, started, *, timeout=TIMEOUT, maximum=MAX_OUTPUT):
    """Bound both streams while reading; cancellation completes only after reap."""
    if command not in ('content-office-request', 'content-restore-request', 'content-restore-retire-request', 'editor-request', 'editor-checkpoint-request', 'index-request', 'index-scope-proposal') and command not in {'content-contract-' + name for name in ('capture', 'reopen', 'spreadsheet', 'document', 'diagram', 'animation', 'collection', 'native-request')}:
        raise ValueError('preview command is not allowlisted')
    binary.check()
    with tempfile.TemporaryDirectory(prefix='luma-native-preview-') as directory:
        process = subprocess.Popen(['/proc/self/fd/' + str(binary.fd), command],
            executable='/proc/self/fd/' + str(binary.fd), pass_fds=(binary.fd,),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=directory, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'},
            start_new_session=True, close_fds=True)
        selector = selectors.DefaultSelector()
        result, errors, offset = bytearray(), bytearray(), 0
        reason = None
        deadline = time.monotonic() + timeout
        try:
            for stream in (process.stdin, process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, 'input')
            selector.register(process.stdout, selectors.EVENT_READ, result)
            selector.register(process.stderr, selectors.EVENT_READ, errors)
            started(process.pid)
            while selector.get_map():
                if cancelled.is_set():
                    reason = 'cancelled'
                    break
                if time.monotonic() >= deadline:
                    reason = 'timeout'
                    break
                for key, _ in selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                    if key.data == 'input':
                        try:
                            count = os.write(key.fd, payload[offset:offset + 65536]) if offset < len(payload) else 0
                            offset += count
                        except BrokenPipeError:
                            count = 0
                        except (BlockingIOError, InterruptedError):
                            continue
                        if count == 0 or offset == len(payload):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        try:
                            block = os.read(key.fd, min(65536, maximum + 1 - len(result) - len(errors)))
                        except (BlockingIOError, InterruptedError):
                            continue
                        if not block:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        else:
                            key.data.extend(block)
                            if len(result) + len(errors) > maximum:
                                reason = 'output-bound'
                                break
                if reason:
                    break
            if reason is None:
                # Observe without reaping. Keeping our leader (including its
                # zombie) until group cleanup prevents numeric PID/PGID reuse
                # from redirecting killpg to an unrelated later process.
                while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    if cancelled.wait(min(0.05, max(0, deadline - time.monotonic()))):
                        reason = 'cancelled'
                        break
                    if time.monotonic() >= deadline:
                        reason = 'timeout'
                        break
        finally:
            # This is our fresh process group, not another application/session.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            selector.close()
            for stream in (process.stdin, process.stdout, process.stderr):
                if not stream.closed:
                    stream.close()
        if reason:
            return reason, None
        binary.check()
        if process.returncode != 0:
            # Native stderr can contain user text. Return a fixed safe error;
            # neither source nor diagnostics are logged/persisted by this host.
            raise ValueError('native engine refused the input')
        return 'completed', bytes(result)


class Host:
    def __init__(self, binary, emit):
        self.binary, self.emit = binary, emit
        self.lock = threading.RLock()
        self.active = None
        self.seen = set()
        self.closed = False

    def event(self, request_id, state, **values):
        self.emit(dict(schema_version=1, id=request_id, state=state, **FLAGS, **values))

    def submit(self, raw):
        value = request(raw)
        with self.lock:
            if self.closed:
                raise ValueError('preview host is closed')
            if value['operation'] == 'cancel':
                if self.active is None or self.active[0] != value['id']:
                    raise ValueError('no matching active preview to cancel')
                self.active[1].set()
                self.event(value['id'], 'cancel-requested')
                return
            if self.active is not None or value['id'] in self.seen or len(self.seen) >= 1024:
                raise ValueError('preview busy, reused ID, or session capacity reached')
            command, payload = invocation(value)
            cancel = threading.Event()
            self.seen.add(value['id'])
            thread = threading.Thread(target=self.work, args=(value, command, payload, cancel), daemon=True)
            self.active = value['id'], cancel, thread
            thread.start()

    def work(self, value, command, payload, cancel):
        try:
            status, output = run_process(self.binary, command, payload, cancel,
                lambda _: self.event(value['id'], 'started', engine=value.get('engine', 'reopen')))
            if status == 'completed':
                self.event(value['id'], 'validating', engine=value.get('engine', 'reopen'))
                data = validate_result(value, output)
                with self.lock:
                    # Cancellation racing with successful exit is not a claim
                    # that the work never ran. Exact observed completion wins.
                    self.active = None
                    self.event(value['id'], 'completed', result=data, native_executable_sha256=self.binary.sha256)
            else:
                with self.lock:
                    self.active = None
                    self.event(value['id'], status if status == 'cancelled' else 'failed', reason=status)
        except Exception:
            with self.lock:
                self.active = None
                self.event(value['id'], 'failed', reason='native-input-or-result-refused')

    def close(self):
        with self.lock:
            self.closed = True
            active = self.active
            if active:
                active[1].set()
        if active:
            active[2].join()
        self.binary.close()
