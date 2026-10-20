"""Explicit original-terminal leased editing and separately authorized checkpoints.

Python never edits an active document or renews a lease. Native owns the real
terminal, PAM, 30-second edit period, output fences and physical drainage.
Frozen data is not Saved, a portable lease, or permission to resume.
"""
import hashlib
import json
from pathlib import Path
import re
import threading
import uuid

MAX_START = 32768
MAX_DOCUMENT = 16384
MAX_COMMANDS = 64


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value):
        raise ValueError('explicit stable identifier required; no path or guessed latest')
    return value


def document(auth, value):
    """Reconstruct the closed native struct order, without changing text bytes."""
    def fields(item, names):
        if not isinstance(item, dict) or set(item) != set(names):
            raise ValueError('closed typed document required')
        return {key: item[key] for key in names}

    def text(item, maximum=4096):
        if not isinstance(item, str) or len(item.encode('utf-8')) > maximum:
            raise ValueError('bounded complete document text required; no clipping')
        if any((ord(char) < 32 and char not in '\n\t') or 127 <= ord(char) <= 159
                or char == '\ufeff' for char in item):
            raise ValueError('unsupported document control')
        return item

    def runs(items):
        if not isinstance(items, list) or not 1 <= len(items) <= 64:
            raise ValueError('bounded nonempty document runs required')
        result = []
        for item in items:
            kind = item.get('kind') if isinstance(item, dict) else None
            if kind == 'line-break':
                result.append(fields(item, ('kind',)))
            elif kind in ('text', 'strong', 'emphasis', 'code'):
                result.append(fields(item, ('kind', 'text')))
                text(item['text'])
            else:
                raise ValueError('unsupported typed document run')
        return result

    result = fields(value, ('schema_version', 'title', 'blocks'))
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('document schema required')
    text(value['title'], 256)
    if not isinstance(value['blocks'], list) or len(value['blocks']) > 256:
        raise ValueError('bounded document blocks required')
    blocks = []
    for item in value['blocks']:
        kind = item.get('kind') if isinstance(item, dict) else None
        if kind == 'heading':
            block = fields(item, ('kind', 'level', 'text'))
            if type(item['level']) is not int or not 1 <= item['level'] <= 6:
                raise ValueError('heading level required')
            text(item['text'])
        elif kind == 'paragraph':
            block = fields(item, ('kind', 'runs')); block['runs'] = runs(item['runs'])
        elif kind == 'list':
            block = fields(item, ('kind', 'ordered', 'items'))
            if type(item['ordered']) is not bool or not isinstance(item['items'], list) or not 1 <= len(item['items']) <= 128:
                raise ValueError('bounded typed list required')
            block['items'] = [runs(row) for row in item['items']]
        elif kind == 'table':
            block = fields(item, ('kind', 'header', 'rows'))
            if (not isinstance(item['header'], list) or not 1 <= len(item['header']) <= 2048
                    or not isinstance(item['rows'], list) or len(item['rows']) > 2048
                    or (len(item['rows'])+1)*len(item['header']) > 2048):
                raise ValueError('bounded document table required')
            for row in [item['header']]+item['rows']:
                if not isinstance(row, list) or len(row) != len(item['header']):
                    raise ValueError('rectangular typed table required')
                for cell in row:
                    text(cell)
        elif kind == 'code':
            block = fields(item, ('kind', 'text')); text(item['text'])
        elif kind == 'rule':
            block = fields(item, ('kind',))
        else:
            raise ValueError('unsupported closed document block')
        blocks.append(block)
    result['blocks'] = blocks
    if len(auth.encoded(result)) > MAX_DOCUMENT:
        raise ValueError('complete document exceeds native 16-KiB period bound')
    return result


def request(auth, value):
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'login', 'start'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1):
        raise ValueError('closed editor journey required')
    start = value['start']
    if (not isinstance(start, dict) or set(start) != {'schema_version', 'binding', 'session_id',
            'checkpoint_artifact_id', 'document', 'resume'} or type(start['schema_version']) is not int
            or start['schema_version'] != 1 or not isinstance(start['session_id'], str)
            or not re.fullmatch(r'[0-9a-f]{32}', start['session_id']) or start['session_id'] == '0'*32):
        raise ValueError('exact native editor period required')
    auth.owner_request(dict(schema_version=1, login=value['login'], binding=start['binding'], operation={}))
    identifier(start['checkpoint_artifact_id'])
    document(auth, start['document'])
    if start['resume'] is not None:
        auth.reference_data(start['resume'])
        if start['resume']['artifact_id'] != start['checkpoint_artifact_id']:
            raise ValueError('resume must select the exact checkpoint artifact')
    if len(auth.encoded(start)) > MAX_START:
        raise ValueError('editor initial request exceeds its closed bound')
    return value


def canonical(auth, host, command, payload):
    if command not in ('editor-request', 'editor-checkpoint-request'):
        raise ValueError('only pure editor data canonicalizers are available')
    binary = host.PinnedExecutable(Path(auth.NATIVE))
    try:
        state, output = host.run_process(binary, command, auth.encoded(payload),
            threading.Event(), lambda _pid: None, maximum=256*1024)
    finally:
        binary.close()
    result = auth.strict_json(output)
    if (state != 'completed' or not isinstance(result, dict) or set(result) != {'schema_version',
            'canonical_request', 'request_sha256', 'authority_returned', 'session_lease_held', 'saved'}
            or type(result['schema_version']) is not int or result['schema_version'] != 1
            or any(result[key] is not False for key in ('authority_returned', 'session_lease_held', 'saved'))
            or not isinstance(result['canonical_request'], str) or not 0 < len(result['canonical_request'].encode()) <= 128*1024
            or result['request_sha256'] != hashlib.sha256(result['canonical_request'].encode()).hexdigest()):
        raise ValueError('actual pure native canonicalizer did not return exact bounded data')
    if command == 'editor-request' and not auth.same_data(auth.strict_json(result['canonical_request']), payload):
        raise ValueError('native canonicalizer substituted initial editor source')
    return result['canonical_request']


def capture(auth, source, command, path, start_grant=None, read_grant=None):
    request(auth, source)
    prefix = ['/usr/bin/sudo', '--', auth.NATIVE, 'granted-run', command, source['login']]
    if command == 'editor-review' and start_grant is None and read_grant is None:
        arguments = prefix+[str(path)]
    elif command == 'editor-run':
        identifier(start_grant)
        if source['start']['resume'] is None:
            if read_grant != 'none':
                raise ValueError('new editor cannot borrow checkpoint Read authority')
        else:
            identifier(read_grant)
            if read_grant == start_grant:
                raise ValueError('resume Read and Start grants must be independent')
        arguments = prefix+[start_grant, read_grant, str(path)]
    else:
        raise ValueError('closed editor review/run only')
    auth.protected(auth.NATIVE, 128*1024*1024)
    return auth._capture_native(arguments, auth.MAX_QUERY_OUTPUT)


def review(auth, source, output):
    value = auth.strict_json(output)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'start_usage',
            'checkpoint_read_usage', 'request', 'authority_returned', 'saved'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['authority_returned'] is not False or value['saved'] is not False
            or not auth.same_data(value['request'], source['start'])):
        raise ValueError('native editor review changes source or claims saved/authority')
    usage = value['start_usage']
    if (not isinstance(usage, dict) or set(usage) != {'action', 'selector', 'input_bytes', 'output_bytes', 'units'}
            or usage['action'] != 'worker.start' or type(usage['input_bytes']) is not int
            or usage['input_bytes'] != (MAX_START+4)*(MAX_COMMANDS+1)
            or type(usage['output_bytes']) is not int or usage['output_bytes'] != (65536+4)*(MAX_COMMANDS+1)
            or type(usage['units']) is not int or usage['units'] != MAX_COMMANDS):
        raise ValueError('native editor Start finite limits differ')
    selector = usage['selector']
    if (not isinstance(selector, dict) or set(selector) != {'kind', 'id', 'generation', 'digest'}
            or selector['kind'] != 'worker' or selector['id'] != 'native-editor-session-v1'
            or type(selector['generation']) is not int or selector['generation'] != 1
            or not auth.exact_sha(selector['digest'])):
        raise ValueError('fixed editor worker/generation required')
    if source['start']['resume'] is None:
        if value['checkpoint_read_usage'] is not None:
            raise ValueError('new editor cannot select a resume Read')
    else:
        auth.finite_scope(value['checkpoint_read_usage'], dict(binding=source['start']['binding']),
            'file.read', 'file', 'native-content-envelope-v1')
    return value


def frozen(auth, source, canonical_start, reviewed, output):
    value = auth.strict_json(output)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'request_sha256', 'binding',
            'lease', 'checkpoint', 'saved'} or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['saved'] is not False
            or value['request_sha256'] != hashlib.sha256(canonical_start.encode()).hexdigest()
            or value['binding'] != reviewed['start_usage']['selector']['digest']):
        raise ValueError('no exact completed/drained Frozen result observed')
    auth.conversation_worker(value['lease'])
    checkpoint = value['checkpoint']
    if (not isinstance(checkpoint, dict) or set(checkpoint) != {'schema_version', 'profile', 'binding',
            'document', 'source_sha256', 'previous_checkpoint'} or type(checkpoint['schema_version']) is not int
            or checkpoint['schema_version'] != 1 or checkpoint['profile'] != 'luma-editor-document-v1'
            or not auth.same_data(checkpoint['binding'], source['start']['binding'])
            or not auth.same_data(checkpoint['previous_checkpoint'], source['start']['resume'])
            or checkpoint['source_sha256'] != hashlib.sha256(auth.encoded(document(auth, checkpoint['document']))).hexdigest()):
        raise ValueError('Frozen source/owner/base differs; never infer a checkpoint or resume permission')
    return value


def checkpoint_input(auth, source, result, request_id, native):
    identifier(request_id)
    checkpoint_source(auth, native)
    start = source['start']
    operation = native['operation']
    resumed = start['resume'] is not None
    fields = {'kind', 'artifact_id', 'content', 'provenance', 'expected' if resumed else 'format'}
    if (native['login'] != source['login'] or not auth.same_data(native['binding'], start['binding'])
            or not isinstance(operation, dict) or set(operation) != fields
            or operation['kind'] != ('external' if resumed else 'capture')
            or operation['artifact_id'] != start['checkpoint_artifact_id']
            or (resumed and not auth.same_data(operation['expected'], start['resume']))
            or (not resumed and operation['format'] != 'json')
            or not isinstance(operation['content'], str)
            or not auth.same_data(auth.strict_json(operation['content']), result['checkpoint'])):
        raise ValueError('pure checkpoint request changes exact Frozen source, owner or base')
    canonical_content = json.dumps(result['checkpoint'], sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    if operation['content'] != canonical_content:
        raise ValueError('checkpoint must retain the exact native canonical content')
    provenance = operation['provenance']
    if (not isinstance(provenance, dict) or set(provenance) != {'request_id', 'workflow_sha256', 'source_sha256', 'origin'}
            or provenance['request_id'] != request_id or provenance['origin'] != 'external'
            or provenance['source_sha256'] != hashlib.sha256(operation['content'].encode()).hexdigest()
            or not auth.exact_sha(provenance['workflow_sha256'])):
        raise ValueError('checkpoint descriptive provenance differs; no authority is inferred')
    return native


def checkpoint_source(auth, native):
    auth.owner_request(native)
    operation = native['operation']
    if not isinstance(operation, dict) or operation.get('kind') not in ('capture', 'external'):
        raise ValueError('closed editor checkpoint operation required')
    resumed = operation['kind'] == 'external'
    if set(operation) != {'kind', 'artifact_id', 'content', 'provenance', 'expected' if resumed else 'format'}:
        raise ValueError('complete exact checkpoint operation required')
    identifier(operation['artifact_id'])
    if resumed:
        auth.reference_data(operation['expected'])
        if operation['expected']['artifact_id'] != operation['artifact_id']:
            raise ValueError('checkpoint base substitutes artifact')
    elif operation['format'] != 'json':
        raise ValueError('editor checkpoint must retain typed JSON')
    if not isinstance(operation['content'], str) or not 0 < len(operation['content'].encode()) <= 32768:
        raise ValueError('bounded complete checkpoint content required')
    checkpoint = auth.strict_json(operation['content'])
    if (not isinstance(checkpoint, dict) or set(checkpoint) != {'schema_version', 'profile', 'binding',
            'document', 'source_sha256', 'previous_checkpoint'} or type(checkpoint['schema_version']) is not int
            or checkpoint['schema_version'] != 1 or checkpoint['profile'] != 'luma-editor-document-v1'
            or not auth.same_data(checkpoint['binding'], native['binding'])
            or not auth.same_data(checkpoint['previous_checkpoint'], operation.get('expected'))
            or checkpoint['source_sha256'] != hashlib.sha256(auth.encoded(document(auth, checkpoint['document']))).hexdigest()
            or operation['content'] != json.dumps(checkpoint, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)):
        raise ValueError('exact canonical editor checkpoint source required')
    provenance = operation['provenance']
    if (not isinstance(provenance, dict) or set(provenance) != {'request_id', 'workflow_sha256', 'source_sha256', 'origin'}
            or provenance['origin'] != 'external' or not auth.exact_sha(provenance['workflow_sha256'])
            or provenance['source_sha256'] != hashlib.sha256(operation['content'].encode()).hexdigest()):
        raise ValueError('exact checkpoint descriptive provenance required')
    identifier(provenance['request_id'])
    return native


def save_review(auth, source, output):
    checkpoint_source(auth, source)
    value = auth.strict_json(output)
    fields = {'schema_version', 'approval', 'review_sha256', 'decision', 'resulting', 'derivation',
        'source_bytes', 'storage_bytes', 'inspection_usage', 'effect_usage', 'committed',
        'authority_returned', 'provenance_authority', 'workflow_executed'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['derivation'] is not None
            or any(value[key] is not False for key in ('committed', 'authority_returned', 'provenance_authority', 'workflow_executed'))
            or value['decision'] not in ('published', 'conflict-retained', 'no-change-retained')
            or not auth.exact_sha(value['review_sha256'])
            or value['approval'] != ('write:' if value['decision'] == 'published' else 'retain:')+value['review_sha256']):
        raise ValueError('exact original native checkpoint review required')
    operation = source['operation']; expected = operation.get('expected')
    reference = auth.reference_data(value['resulting'])
    if (reference['artifact_id'] != operation['artifact_id']
            or value['decision'] == 'published' and reference['version'] != (1 if expected is None else expected['version']+1)
            or value['decision'] == 'no-change-retained' and not auth.same_data(reference, expected)
            or value['decision'] == 'conflict-retained' and (expected is None or auth.same_data(reference, expected))
            or type(value['source_bytes']) is not int or value['source_bytes'] != len(operation['content'].encode())
            or type(value['storage_bytes']) is not int or not 8192 <= value['storage_bytes'] <= 24*1024*1024):
        raise ValueError('checkpoint review substitutes exact content/version/conflict or capacity')
    auth.finite_scope(value['inspection_usage'], source, 'file.read', 'file', 'native-content-inspect-v1')
    auth.finite_scope(value['effect_usage'], source, 'artifact.write' if value['decision'] == 'published' else 'resource.retention',
        'artifact', 'native-content-store-v1')
    if value['inspection_usage']['selector']['digest'] != value['effect_usage']['selector']['digest']:
        raise ValueError('checkpoint Read/effect bind different acquisitions')
    return value


def save_completed(auth, source, reviewed, output):
    value = auth.strict_json(output)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'outcome', 'derivation', 'committed',
            'authority_returned', 'provenance_authority', 'workflow_executed'} or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['committed'] is not True or value['derivation'] is not None
            or any(value[key] is not False for key in ('authority_returned', 'provenance_authority', 'workflow_executed'))):
        raise ValueError('no exact C checkpoint completion observed')
    outcome = value['outcome']; operation = source['operation']
    if (not isinstance(outcome, dict) or set(outcome) != {'sequence', 'request_id', 'review_sha256', 'decision',
            'resulting', 'source_sha256', 'source_kind', 'replayed'} or type(outcome['sequence']) is not int
            or not 1 <= outcome['sequence'] <= 256 or type(outcome['replayed']) is not bool
            or outcome['request_id'] != operation['provenance']['request_id']
            or outcome['review_sha256'] != reviewed['review_sha256'] or outcome['decision'] != reviewed['decision']
            or not auth.same_data(outcome['resulting'], reviewed['resulting']) or outcome['source_kind'] != 'content'
            or outcome['source_sha256'] != hashlib.sha256(operation['content'].encode()).hexdigest()):
        raise ValueError('checkpoint completion differs from exact reviewed transaction')
    return value


def capture_save(auth, value, path):
    value = auth.proposal(value)
    checkpoint_source(auth, auth.strict_json(value['request']))
    if (value['operation'] != 'apply' or value['read_grant'] == value['effect_grant']
            or not re.fullmatch(r'(?:write|retain):[0-9a-f]{64}', value['approval'])):
        raise ValueError('checkpoint effect requires closed source and independent grants')
    auth.protected(auth.NATIVE, 128*1024*1024)
    return auth._capture_native(auth.terminal_arguments(value, path), auth.MAX_QUERY_OUTPUT)


def save(auth, source, result, host, directory):
    print('Frozen, NOT Saved. A new native C review, independent grants, exact approval, commit and separate fresh exact Read are required. No automatic save or resume.', flush=True)
    choice = auth.terminal_line('s explicitly checkpoint this Frozen source; q discard memory copy: ', 8)
    if choice == 'q':
        return 0
    if choice != 's':
        raise ValueError('explicit save selection required')
    request_id = auth.terminal_line('New stable checkpoint request ID (q cancels): ', 128)
    if request_id == 'q':
        return 130
    identifier(request_id)
    payload = dict(schema_version=1, login=source['login'], request_id=request_id, start=source['start'], frozen=result)
    exact = canonical(auth, host, 'editor-checkpoint-request', payload)
    native = checkpoint_input(auth, source, result, request_id, auth.strict_json(exact))
    inspect = dict(schema_version=1, operation='inspection', login=source['login'], read_grant='', effect_grant='', approval='', request=exact)
    submitted, observed = False, False
    try:
        with auth.request_stage(directory, exact) as path:
            scope = auth.owner_inspection(auth.capture_query(auth.terminal_arguments(inspect, path)), native)
            print('Exact checkpoint review Read scope DATA:\n'+json.dumps(scope, ensure_ascii=True), flush=True)
            first = auth.grant_selection('Fresh checkpoint review Read grant (q cancels): ')
            if first is None:
                return 130
            reviewed = save_review(auth, native, auth.capture_query(auth.terminal_arguments(dict(inspect, operation='review', read_grant=first), path)))
            print('Actual native checkpoint review, including exact conflict and independent scopes:\n'+json.dumps(reviewed, ensure_ascii=True), flush=True)
            read = auth.grant_selection('NEW checkpoint apply Read grant (q cancels): ')
            if read is None:
                return 130
            effect = auth.grant_selection('Independent checkpoint Write/Retain grant (q cancels): ')
            if effect is None:
                return 130
            if read == first or read == effect:
                raise ValueError('apply Read must be fresh and independent of review/effect')
            if auth.terminal_line('Type exact '+reviewed['approval']+' (q cancels): ', 128) != reviewed['approval']:
                return 130
            applying = dict(inspect, operation='apply', read_grant=read, effect_grant=effect, approval=reviewed['approval'])
            auth.proposal(applying)
            print('Submitting exact checkpoint. Interruption may be uncertain, never rollback or permission to retry:\n'+json.dumps(dict(request=native, review_sha256=reviewed['review_sha256']), ensure_ascii=True), flush=True)
            submitted = True
            completed = save_completed(auth, native, reviewed, capture_save(auth, applying, path))
            observed = True
        print('Observed C checkpoint '+completed['outcome']['decision']+'. Not yet labeled Saved: separate exact reopen remains.\n'+json.dumps(completed, ensure_ascii=True), flush=True)
        if completed['outcome']['decision'] == 'conflict-retained':
            print('Conflicting Frozen candidate was retained, NOT Saved as the selected document. No automatic merge, undo or retry.', flush=True)
            return 0
        if auth.terminal_line('r obtain a separately granted fresh exact checkpoint Read/reopen; q finish without reopen: ', 8) != 'r':
            return 0
        read_source = dict(schema_version=1, login=source['login'], binding=native['binding'], operation=dict(kind='envelope', expected=completed['outcome']['resulting']))
        actual = auth.envelope_read(dict(inspect, operation='envelope-read', request=auth.encoded(read_source).decode()), directory)
        if actual is None:
            return 0
        selected, reopened, _actual_host = actual
        if (not auth.same_data(selected, read_source) or reopened.get('preview_format') != 'json'
                or reopened.get('preview_content') != native['operation']['content']):
            raise ValueError('fresh exact reopened checkpoint differs from Frozen source; no Saved label')
        print('Saved checkpoint and separately granted exact reopen observed. This is historical completion, NOT an active edit lease or permission to resume. Resume needs a new original-PAM period and fresh C checkpoint Read.', flush=True)
        return 0
    except (Exception, KeyboardInterrupt):
        print('C checkpoint completion was observed; subsequent read/presentation failed. No second publication or automatic retry.' if observed else
            'UNCERTAIN checkpoint outcome after submission; inspect exact retained native request/C state before retry. No Saved, rollback or release inferred.' if submitted else
            'Checkpoint refused before publication submission. Frozen memory data is NOT Saved.', flush=True)
        return 1


def journey(auth, value, directory):
    try:
        source = request(auth, auth.strict_json(value['request']))
        host = auth.workspace_controller('draft').host_module(auth)
        exact = canonical(auth, host, 'editor-request', source['start'])
        source = dict(source, start=auth.strict_json(exact))
        with auth.request_stage(directory, exact) as path:
            reviewed = review(auth, source, capture(auth, source, 'editor-review', path))
            print('Native bounded editor review DATA. The actual 30-second original-PAM period has NOT started. All live edits occur only in the native terminal; Freeze drains, never Saves.\n'+json.dumps(reviewed, ensure_ascii=True), flush=True)
            read = 'none'
            if source['start']['resume'] is not None:
                read = auth.grant_selection('Independent fresh exact checkpoint Read grant for resume (q cancels): ')
                if read is None:
                    return 130
            start = auth.grant_selection('Fresh finite Start grant for this exact 30-second editor period (q cancels): ')
            if start is None:
                return 130
            result = frozen(auth, source, exact, reviewed, capture(auth, source, 'editor-run', path, start, read))
        print('Actual native Frozen completion observed after edit-period drain; memory DATA only, NOT Saved. No lease renewal or automatic checkpoint.\n'+json.dumps(result, ensure_ascii=True), flush=True)
        return save(auth, source, result, host, directory)
    except (Exception, KeyboardInterrupt):
        print('Editor stopped/refused without an observed Saved checkpoint. Timeout/revocation is not Freeze, automatic save, lease renewal, rollback or permission to resume.', flush=True)
        return 1


def dialog_request(auth, login, binding, artifact, document_text, resume_text):
    start = dict(schema_version=1, binding=auth.strict_json(binding), session_id=uuid.uuid4().hex,
        checkpoint_artifact_id=artifact, document=document(auth, auth.strict_json(document_text)), resume=auth.strict_json(resume_text))
    value = request(auth, dict(schema_version=1, login=login, start=start))
    return auth.proposal(dict(schema_version=1, operation='editor-journey', login=login,
        read_grant='', effect_grant='', approval='', request=auth.encoded(value).decode()))


def launch_dialog(parent, auth):
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk
    dialog = Gtk.Dialog(title='Original-session bounded editor', transient_for=parent, modal=True)
    dialog.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Open original native terminal', Gtk.ResponseType.OK)
    dialog.set_default_size(780, 640)
    area = dialog.get_content_area()
    note = Gtk.Label(label='This form selects initial DATA, not an active editor. Live editing occurs only after fresh native PAM, finite Start and actual resource admission in the original terminal: 30 seconds, 64 operations, no renewal. Explicit Freeze drains; Frozen is NOT Saved. Checkpoint publication and exact reopen require separate fresh native Read/effect review. Resume must supply the exact stored document and immutable checkpoint reference; native freshly reads C and rejects stale or copied substitutes. No password, grant or private response enters WebKit.')
    note.set_line_wrap(True); area.pack_start(note, False, False, 8)
    entries = {}
    for key, label, maximum in (('login', '_Human login', 32), ('binding', 'Exact _owner binding JSON', 1024),
            ('artifact', 'Stable checkpoint _artifact ID', 128), ('resume', 'Exact _resume reference JSON; null for NEW', 2048)):
        caption = Gtk.Label.new_with_mnemonic(label); entry = Gtk.Entry(); entry.set_max_length(maximum)
        caption.set_mnemonic_widget(entry); area.pack_start(caption, False, False, 3); area.pack_start(entry, False, False, 3)
        entries[key] = entry
    entries['resume'].set_text('null')
    caption = Gtk.Label.new_with_mnemonic('Complete initial typed _document JSON (16 KiB; DATA only)')
    source = Gtk.TextView(); source.set_accepts_tab(False); source.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
    caption.set_mnemonic_widget(source); area.pack_start(caption, False, False, 3)
    scroll = Gtk.ScrolledWindow(); scroll.set_min_content_height(180); scroll.add(source); area.pack_start(scroll, True, True, 3)
    error = Gtk.Label(); error.set_line_wrap(True); area.pack_start(error, False, False, 4)
    dialog.show_all()
    try:
        while dialog.run() == Gtk.ResponseType.OK:
            try:
                buffer = source.get_buffer()
                value = dialog_request(auth, entries['login'].get_text(), entries['binding'].get_text(), entries['artifact'].get_text(),
                    buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False), entries['resume'].get_text())
                auth.launch(value)
                return True
            except Exception:
                error.set_text('Not launched. Provide complete exact owner/document/checkpoint DATA. No active lease, saved state, latest version or permission was inferred.')
        return False
    finally:
        dialog.destroy()
