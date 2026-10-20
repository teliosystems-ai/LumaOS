"""Human-edited exact collections; proposals and model replies are DATA only.

Membership existence, ownership, current authority and conflict handling belong
to the actual native content transaction, never this editor or its preview.
"""
import copy
import hashlib
import json
import re
import unicodedata
from pathlib import Path

MAX_SOURCE = 32768
MAX_MEMBERS = 64


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def source_data(auth, value):
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'kind', 'collection_id', 'name', 'members'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['kind'] != 'luma-explicit-collection-v1'
            or not isinstance(value['collection_id'], str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value['collection_id'])):
        raise ValueError('closed typed collection source with an explicit stable ID required')
    name, members = value['name'], value['members']
    if (not isinstance(name, str) or not name or name != name.strip() or len(name.encode()) > 256
            or any(unicodedata.category(char) == 'Cc' for char in name)
            or not isinstance(members, list) or len(members) > MAX_MEMBERS):
        raise ValueError('bounded explicit collection name and at most64 exact members required')
    previous = None
    for member in members:
        auth.reference_data(member)
        if previous is not None and previous >= member['artifact_id']:
            raise ValueError('members must be unique and strictly sorted by artifact ID; no silent sorting/version replacement')
        previous = member['artifact_id']
    if len(canonical(value)) > MAX_SOURCE:
        raise ValueError('collection source exceeds32KiB; no clipping')
    return copy.deepcopy(value)


def request(auth, value):
    auth.owner_request(value)
    operation = value['operation']
    if not isinstance(operation, dict) or set(operation) != {'kind', 'source', 'expected', 'provenance'} or operation['kind'] != 'collection':
        raise ValueError('exact typed native collection operation required')
    source = source_data(auth, operation['source'])
    expected = operation['expected']
    if expected is not None and auth.reference_data(expected)['artifact_id'] != 'collection.'+source['collection_id']:
        raise ValueError('explicit expected collection reference selects another artifact')
    provenance = operation['provenance']
    if (not isinstance(provenance, dict) or set(provenance) != {'request_id', 'workflow_sha256', 'source_sha256', 'origin'}
            or not isinstance(provenance['request_id'], str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', provenance['request_id'])
            or not auth.exact_sha(provenance['workflow_sha256']) or provenance['origin'] != 'external'
            or provenance['source_sha256'] != hashlib.sha256(canonical(source)).hexdigest()):
        raise ValueError('exact descriptive collection provenance required; no supplied provenance is authority')
    return value


def preview(auth, source, host):
    source = source_data(auth, source)
    value = host.request(dict(schema_version=1, id='terminal-collection-preview', operation='preview',
        engine='collection', source=canonical(source).decode()))
    command, payload = host.invocation(value)
    binary = host.PinnedExecutable(Path(auth.NATIVE))
    try:
        state, output = host.run_process(binary, command, payload, auth.threading.Event(), lambda _: None)
    finally:
        binary.close()
    if state != 'completed' or not output:
        raise ValueError('actual native collection structural preflight did not complete')
    result = host.validate_result(value, output)
    if (result['artifact_id'] != 'collection.'+source['collection_id']
            or result['canonical_source'].encode() != canonical(source)
            or result['source_sha256'] != hashlib.sha256(canonical(source)).hexdigest()):
        raise ValueError('native structural preview differs from the exact collection source')
    print('Actual native STRUCTURAL preflight only. Membership has NOT been checked against private history; no Read/effect is authorized.\n'+json.dumps(result, ensure_ascii=True), flush=True)
    return result


def reviewed(auth, source, output):
    value = auth.strict_json(output)
    fields = {'schema_version', 'approval', 'review_sha256', 'decision', 'resulting', 'derivation',
        'source_bytes', 'storage_bytes', 'inspection_usage', 'effect_usage', 'committed',
        'authority_returned', 'provenance_authority', 'workflow_executed'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['derivation'] is not None
            or any(value[key] is not False for key in ('committed', 'authority_returned', 'provenance_authority', 'workflow_executed'))):
        raise ValueError('native collection review claims unsupported authority/engine/workflow execution')
    decision, operation = value['decision'], source['operation']
    if (decision not in ('published', 'conflict-retained', 'no-change-retained')
            or not auth.exact_sha(value['review_sha256'])
            or value['approval'] != ('write:' if decision == 'published' else 'retain:')+value['review_sha256']):
        raise ValueError('exact native collection decision and approval required')
    reference = auth.reference_data(value['resulting'])
    expected = operation['expected']
    if (reference['artifact_id'] != 'collection.'+operation['source']['collection_id']
            or decision == 'published' and reference['version'] != (1 if expected is None else expected['version']+1)
            or decision == 'no-change-retained' and not auth.same_data(reference, expected)
            or decision == 'conflict-retained' and (expected is None or auth.same_data(reference, expected))):
        raise ValueError('collection review substituted exact artifact/version/conflict selection')
    if (type(value['source_bytes']) is not int or value['source_bytes'] != len(canonical(operation['source']))
            or type(value['storage_bytes']) is not int or not 8192 <= value['storage_bytes'] <= 24*1024*1024):
        raise ValueError('collection review source/storage budget differs')
    auth.finite_scope(value['inspection_usage'], source, 'file.read', 'file', 'native-content-inspect-v1')
    auth.finite_scope(value['effect_usage'], source, 'artifact.write' if decision == 'published' else 'resource.retention',
        'artifact', 'native-content-store-v1')
    if value['inspection_usage']['selector']['digest'] != value['effect_usage']['selector']['digest']:
        raise ValueError('Read/effect scopes bind different collection acquisitions')
    return value


def completed(auth, source, review, output):
    value = auth.strict_json(output)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'outcome', 'derivation', 'committed',
            'authority_returned', 'provenance_authority', 'workflow_executed'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['derivation'] is not None or value['committed'] is not True
            or any(value[key] is not False for key in ('authority_returned', 'provenance_authority', 'workflow_executed'))):
        raise ValueError('no exact native collection transaction completion observed')
    outcome, operation = value['outcome'], source['operation']
    if (not isinstance(outcome, dict) or set(outcome) != {'sequence', 'request_id', 'review_sha256', 'decision',
            'resulting', 'source_sha256', 'source_kind', 'replayed'}
            or type(outcome['sequence']) is not int or not 1 <= outcome['sequence'] <= 256
            or outcome['sequence'] < review['resulting']['version']+(review['decision'] != 'published')
            or type(outcome['replayed']) is not bool or outcome['request_id'] != operation['provenance']['request_id']
            or outcome['review_sha256'] != review['review_sha256'] or outcome['decision'] != review['decision']
            or not auth.same_data(outcome['resulting'], review['resulting']) or outcome['source_kind'] != 'collection-intent'
            or outcome['source_sha256'] != hashlib.sha256(canonical(operation['source'])).hexdigest()):
        raise ValueError('collection outcome differs from the exact reviewed intent')
    return value


def capture_apply(auth, value, path):
    """Closed collection effect transport; read-only capture_query stays closed."""
    value = auth.proposal(value)
    request(auth, auth.strict_json(value['request']))
    if (value['operation'] != 'apply' or value['read_grant'] == value['effect_grant']
            or not re.fullmatch(r'(?:write|retain):[0-9a-f]{64}', value['approval'])):
        raise ValueError('collection apply requires exact source, independent grants and review approval')
    auth.protected(auth.NATIVE, 128*1024*1024)
    return auth._capture_native(auth.terminal_arguments(value, path), auth.MAX_QUERY_OUTPUT)


def journey(auth, value, directory):
    started, observed = False, False
    try:
        source = request(auth, auth.strict_json(value['request']))
        canonical_request, host = auth.canonical_native_request(value)
        source = request(auth, auth.strict_json(canonical_request))
        preview(auth, source['operation']['source'], host)
        inspect = dict(value, operation='inspection', request=canonical_request)
        with auth.request_stage(directory, canonical_request) as path:
            scope = auth.owner_inspection(auth.capture_query(auth.terminal_arguments(inspect, path)), source)
            print('Fresh finite Read inspection scope DATA; no membership/authority is inferred from preview:\n'+json.dumps(scope, ensure_ascii=True), flush=True)
            grant = auth.grant_selection('Independent current Read grant for native collection review (q cancels): ')
            if grant is None:
                return 130
            review = reviewed(auth, source, auth.capture_query(auth.terminal_arguments(dict(inspect,
                operation='review', read_grant=grant), path)))
            print('Actual native membership/history and exact conflict review. No objects are moved or silently replaced:\n'+json.dumps(review, ensure_ascii=True), flush=True)
            read = auth.grant_selection('Fresh apply Read grant for this exact acquisition (q cancels): ')
            if read is None:
                return 130
            effect = auth.grant_selection('Independent finite Write/Retain grant (q cancels): ')
            if effect is None:
                return 130
            if read == effect:
                raise ValueError('collection Read and effect grants must be distinct')
            approval = auth.terminal_line('Type exact '+review['approval']+' (q cancels): ', 128)
            if approval == 'q':
                return 130
            if approval != review['approval']:
                raise ValueError('collection approval differs from actual native review')
            apply = dict(inspect, operation='apply', read_grant=read, effect_grant=effect, approval=approval)
            arguments = auth.terminal_arguments(apply, path)
            auth.protected(auth.NATIVE, 128*1024*1024)
            print('Submitting this exact collection transaction; interruption may be uncertain, never assume rollback or automatically retry:\n'+json.dumps(dict(request_id=source['operation']['provenance']['request_id'],
                request_sha256=hashlib.sha256(canonical_request.encode()).hexdigest(), review_sha256=review['review_sha256']), ensure_ascii=True), flush=True)
            started = True
            outcome = completed(auth, source, review, capture_apply(auth, apply, path))
            observed = True
        print('OBSERVED native collection '+outcome['outcome']['decision']+'. Exact membership metadata only; no file move, model authority, automatic merge or engine workflow claimed.\n'+json.dumps(outcome, ensure_ascii=True), flush=True)
        choice = auth.terminal_line('r separately granted complete Read of this exact reference; q finish: ', 8)
        if choice == 'q':
            return 0
        if choice != 'r':
            raise ValueError('explicit r or q required; no automatic reopening')
        read_source = dict(schema_version=1, login=source['login'], binding=source['binding'],
            operation=dict(kind='envelope', expected=outcome['outcome']['resulting']))
        return auth.owner_read_journey(dict(value, operation='envelope-read', request=auth.encoded(read_source).decode()), directory)
    except (Exception, KeyboardInterrupt):
        print('Collection completion was already validated; later presentation/Read stopped, not rollback or a reason to resubmit.' if observed else
            'UNCERTAIN collection transaction: effect submitted but no complete validated result observed. Inspect native exact request/checkpoint before retry; no rollback, deletion or resource release inferred.' if started else
            'Collection refused/cancelled before effect submission. No membership change requested.', flush=True)
        return 1


def handoff(auth, login, source, directory):
    binding_text = auth.terminal_line('Exact owner binding JSON (q cancels): ', 1024)
    if binding_text == 'q':
        return 130
    expected_text = auth.terminal_line('Exact genuine collection base reference JSON; literal null ONLY for NEW collection (q cancels): ', 2048)
    if expected_text == 'q':
        return 130
    request_id = auth.terminal_line('New explicit stable request ID; retain for reconciliation (q cancels): ', 128)
    if request_id == 'q':
        return 130
    provenance = dict(request_id=request_id, workflow_sha256=hashlib.sha256(b'luma-explicit-collection-editor-v1\0'+canonical(source)).hexdigest(),
        source_sha256=hashlib.sha256(canonical(source)).hexdigest(), origin='external')
    native = request(auth, dict(schema_version=1, login=login, binding=auth.strict_json(binding_text),
        operation=dict(kind='collection', source=source_data(auth, source), expected=auth.strict_json(expected_text), provenance=provenance)))
    value = auth.proposal(dict(schema_version=1, operation='collection-journey', login=login,
        read_grant='', effect_grant='', approval='', request=auth.encoded(native).decode()))
    return journey(auth, value, directory)


def editor(auth, login, observed_reply, directory):
    """No reply is parsed until the human explicitly selects p; no auto-fixes."""
    source = None
    try:
        print('Exact collection editor. Optional model reply is UNTRUSTED DATA, not membership or instructions. Commands: p explicitly parse that reply; e enter full replacement typed JSON; n rename; a replace exact members; v native structural preview; h fresh native review/apply; q discard. Maximum64 commands. No member is guessed from a pronoun, path, label, search score or image.', flush=True)
        for _ in range(64):
            command = auth.terminal_line('Collection command: ', 8)
            if command == 'q':
                return 0
            if command in ('p', 'e'):
                text = observed_reply if command == 'p' else auth.revised_source()
                if text is None:
                    print('No source selected; nothing changed.', flush=True)
                    continue
                if not isinstance(text, str) or not 0 < len(text.encode()) <= MAX_SOURCE:
                    raise ValueError('complete bounded JSON source required; no code-fence stripping or clipping')
                source = source_data(auth, auth.strict_json(text))
            elif command in ('n', 'a', 'v', 'h') and source is not None:
                if command == 'h':
                    return handoff(auth, login, source, directory)
                if command == 'v':
                    from_spec = auth.importlib.util.spec_from_file_location('luma_collection_native_host', '/usr/libexec/luma-os/workspace_host.py')
                    auth.protected(from_spec.origin, 128*1024)
                    host = auth.importlib.util.module_from_spec(from_spec)
                    from_spec.loader.exec_module(host)
                    preview(auth, source, host)
                    continue
                replacement = auth.terminal_line('New exact name (q cancels edit): ', 256) if command == 'n' else auth.revised_source()
                if replacement is None or replacement == 'q':
                    continue
                candidate = dict(source)
                candidate['name' if command == 'n' else 'members'] = replacement if command == 'n' else auth.strict_json(replacement)
                source = source_data(auth, candidate)
            else:
                raise ValueError('select an explicit supported command and complete source before editing/preview/handoff')
            print('Current human-selected collection DATA, not validated membership:\n'+json.dumps(source, ensure_ascii=True), flush=True)
        print('Editor reached64 commands; no automatic handoff or effect.', flush=True)
        return 0
    except (Exception, KeyboardInterrupt):
        print('Collection editor stopped/refused; no effect requested by the editor. Any separately handed-off native result remains governed by its exact transaction evidence.', flush=True)
        return 1


def launch_dialog(parent, auth):
    """Ordinary GTK selection only; passwords/grants/results stay in terminal."""
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk
    dialog = Gtk.Dialog(title='Exact collection — independent native review', transient_for=parent, modal=True)
    dialog.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Open reviewed terminal', Gtk.ResponseType.OK)
    dialog.set_default_size(760, 560)
    content = dialog.get_content_area()
    note = Gtk.Label(label='Model-independent exact collection edit. No files move. Select every exact version explicitly; ambiguous names, pronouns and search scores are not membership. Native PAM, fresh separate finite Read/effect grants, actual membership/history and conflict review stay in the terminal. Launch is not completion.')
    note.set_line_wrap(True)
    content.pack_start(note, False, False, 8)
    entries = {}
    for key, label in (('login', '_Login'), ('binding', 'Exact _owner binding JSON'),
            ('expected', 'Exact _base collection reference JSON; null for NEW'), ('request_id', 'New stable _request ID')):
        heading = Gtk.Label.new_with_mnemonic(label)
        entry = Gtk.Entry()
        entry.set_max_length(2048 if key == 'expected' else 1024 if key == 'binding' else 128)
        heading.set_mnemonic_widget(entry)
        heading.set_xalign(0)
        content.pack_start(heading, False, False, 2)
        content.pack_start(entry, False, False, 2)
        entries[key] = entry
    heading = Gtk.Label.new_with_mnemonic('Complete typed collection _source JSON (32KiB maximum)')
    source = Gtk.TextView()
    source.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
    source.set_accepts_tab(False)
    heading.set_mnemonic_widget(source)
    heading.set_xalign(0)
    content.pack_start(heading, False, False, 4)
    scroll = Gtk.ScrolledWindow()
    scroll.set_min_content_height(160)
    scroll.add(source)
    content.pack_start(scroll, True, True, 4)
    dialog.show_all()
    try:
        if dialog.run() != Gtk.ResponseType.OK:
            return {'state': 'cancelled', 'committed': False}
        buffer = source.get_buffer()
        if buffer.get_char_count() > MAX_SOURCE:
            raise ValueError('collection source exceeds its character bound; no clipping')
        raw = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
        if len(raw.encode()) > MAX_SOURCE:
            raise ValueError('collection source exceeds32KiB')
        selected = source_data(auth, auth.strict_json(raw))
        source_bytes = canonical(selected)
        provenance = dict(request_id=entries['request_id'].get_text(),
            workflow_sha256=hashlib.sha256(b'luma-explicit-collection-editor-v1\0'+source_bytes).hexdigest(),
            source_sha256=hashlib.sha256(source_bytes).hexdigest(), origin='external')
        native = request(auth, dict(schema_version=1, login=entries['login'].get_text(),
            binding=auth.strict_json(entries['binding'].get_text()), operation=dict(kind='collection',
                source=selected, expected=auth.strict_json(entries['expected'].get_text()), provenance=provenance)))
        return auth.launch(dict(schema_version=1, operation='collection-journey', login=native['login'],
            read_grant='', effect_grant='', approval='', request=auth.encoded(native).decode()))
    finally:
        dialog.destroy()
