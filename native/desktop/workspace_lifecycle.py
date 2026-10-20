"""Explicit owner-local logical trash/restore; all authority stays native.

Status and historical receipts are data, not a continuing permission or undo.
No model, capture, WebKit, physical deletion, expiry or automatic retry is used.
"""
import hashlib
import json
import re

RETENTION = 'until-explicit-restore-no-purge'


def lifecycle_reference(auth, value):
    if (not isinstance(value, dict) or set(value) != {'version', 'revision', 'state_sha256', 'status'}
            or type(value['revision']) is not int or not 1 <= value['revision'] <= 256
            or not auth.exact_sha(value['state_sha256']) or value['status'] not in ('live', 'trashed')):
        raise ValueError('full exact lifecycle reference required; no latest/version inference')
    auth.reference_data(value['version'])
    return value


def request(auth, source):
    auth.owner_request(source)
    operation = source['operation']
    if not isinstance(operation, dict):
        raise ValueError('closed native lifecycle operation required')
    if operation.get('kind') == 'lifecycle-status':
        if (set(operation) != {'kind', 'artifact_id'} or not isinstance(operation['artifact_id'], str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', operation['artifact_id'])):
            raise ValueError('explicit stable artifact ID required')
        return source
    if set(operation) != {'kind', 'request'} or operation['kind'] != 'lifecycle':
        raise ValueError('only status or exact logical lifecycle request supported')
    intent = operation['request']
    if (not isinstance(intent, dict) or set(intent) != {'schema_version', 'binding', 'request_id',
            'workflow_sha256', 'expected', 'operation', 'retention'}
            or type(intent['schema_version']) is not int or intent['schema_version'] != 1
            or not auth.same_data(intent['binding'], source['binding'])
            or not isinstance(intent['request_id'], str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', intent['request_id'])
            or not auth.exact_sha(intent['workflow_sha256']) or intent['operation'] not in ('trash', 'restore')
            or intent['retention'] != RETENTION or len(auth.encoded(intent)) > 8192):
        raise ValueError('complete exact human lifecycle intent required; no purge or automatic restore')
    lifecycle_reference(auth, intent['expected'])
    return source


def action(source):
    intent = source['operation']['request']
    return (('artifact.delete', 'native-content-trash-v1', 'trash:') if intent['operation'] == 'trash'
            else ('artifact.write', 'native-content-restore-deleted-v1', 'untrash:'))


def inspection(auth, source, output):
    value = auth.strict_json(output)
    query = source['operation']['kind'] == 'lifecycle-status'
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'inspection_usage', 'query_only',
            'private_content_read', 'grant_issued', 'committed'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['query_only'] is not query
            or any(value[key] is not False for key in ('private_content_read', 'grant_issued', 'committed'))):
        raise ValueError('native lifecycle inspection claims private read/authority or another operation')
    auth.finite_scope(value['inspection_usage'], source, 'file.read', 'file',
        'native-content-trash-read-v1' if query else 'native-content-inspect-v1')
    return value['inspection_usage']


def status(auth, source, output):
    value = auth.strict_json(output)
    fields = {'schema_version', 'lifecycle', 'content_delivered', 'committed', 'authority_returned',
        'physical_purge_available', 'retention', 'restore_authorized', 'production_qualified'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['retention'] != RETENTION
            or any(value[key] is not False for key in fields - {'schema_version', 'lifecycle', 'retention'})):
        raise ValueError('exact native status-only response required; no content/purge/restore authority')
    current = lifecycle_reference(auth, value['lifecycle'])
    if current['version']['artifact_id'] != source['operation']['artifact_id']:
        raise ValueError('native lifecycle status substitutes the selected artifact')
    return value


def reviewed(auth, source, output):
    value = auth.strict_json(output)
    fields = {'schema_version', 'approval', 'review_sha256', 'decision', 'resulting', 'derivation',
        'source_bytes', 'storage_bytes', 'inspection_usage', 'effect_usage', 'committed', 'authority_returned',
        'provenance_authority', 'workflow_executed', 'lifecycle_request', 'logical_only', 'physical_bytes_erased'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['derivation'] is not None or value['logical_only'] is not True
            or any(value[key] is not False for key in ('committed', 'authority_returned', 'provenance_authority',
                'workflow_executed', 'physical_bytes_erased'))):
        raise ValueError('native logical lifecycle review schema/authority claims differ')
    intent = source['operation']['request']
    effect_action, effect_id, prefix = action(source)
    desired_decision = 'trashed' if intent['operation'] == 'trash' else 'restored'
    if (not auth.same_data(value['lifecycle_request'], intent) or not auth.exact_sha(value['review_sha256'])
            or value['approval'] != prefix+value['review_sha256']
            or value['decision'] not in (desired_decision, 'conflict-retained', 'no-change-retained')):
        raise ValueError('native review substitutes requested operation, exact intent, decision or approval')
    reference = auth.reference_data(value['resulting'])
    if (reference['artifact_id'] != intent['expected']['version']['artifact_id']
            or value['decision'] != 'conflict-retained' and not auth.same_data(reference, intent['expected']['version'])):
        raise ValueError('native review substitutes selected immutable version')
    if (type(value['source_bytes']) is not int or value['source_bytes'] != len(auth.encoded(intent))
            or type(value['storage_bytes']) is not int or not 8192 <= value['storage_bytes'] <= 24*1024*1024):
        raise ValueError('native lifecycle review source/storage bound differs')
    auth.finite_scope(value['inspection_usage'], source, 'file.read', 'file', 'native-content-inspect-v1')
    auth.finite_scope(value['effect_usage'], source, effect_action, 'artifact', effect_id)
    if value['inspection_usage']['selector']['digest'] != value['effect_usage']['selector']['digest']:
        raise ValueError('native lifecycle Read/effect scopes bind different acquisitions')
    return value


def completed(auth, source, review, output):
    value = auth.strict_json(output)
    fields = {'schema_version', 'outcome', 'derivation', 'committed', 'authority_returned', 'provenance_authority',
        'workflow_executed', 'lifecycle', 'requested_lifecycle', 'logical_only', 'physical_bytes_erased',
        'historical_replay_is_not_a_new_state_change'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['derivation'] is not None or value['committed'] is not True
            or value['logical_only'] is not True or value['historical_replay_is_not_a_new_state_change'] is not True
            or any(value[key] is not False for key in ('authority_returned', 'provenance_authority',
                'workflow_executed', 'physical_bytes_erased'))):
        raise ValueError('no exact native logical lifecycle completion observed')
    intent, outcome = source['operation']['request'], value['outcome']
    if (not isinstance(outcome, dict) or set(outcome) != {'sequence', 'request_id', 'review_sha256', 'decision',
            'resulting', 'source_sha256', 'source_kind', 'replayed'}
            or type(outcome['sequence']) is not int or not 1 <= outcome['sequence'] <= 256
            or type(outcome['replayed']) is not bool or outcome['request_id'] != intent['request_id']
            or outcome['review_sha256'] != review['review_sha256'] or outcome['decision'] != review['decision']
            or not auth.same_data(outcome['resulting'], review['resulting'])
            or outcome['source_kind'] != 'lifecycle-intent'
            or outcome['source_sha256'] != hashlib.sha256(auth.encoded(intent)).hexdigest()
            or not auth.same_data(value['requested_lifecycle'], intent)):
        raise ValueError('native lifecycle outcome differs from the exact reviewed original request')
    current = lifecycle_reference(auth, value['lifecycle'])
    if current['version']['artifact_id'] != intent['expected']['version']['artifact_id']:
        raise ValueError('actual lifecycle result selects another artifact')
    if not outcome['replayed']:
        if current['revision'] > outcome['sequence']:
            raise ValueError('nonreplayed lifecycle result precedes its actual state')
        if outcome['decision'] in ('trashed', 'restored') and (current['revision'] != outcome['sequence']
                or current['status'] != ('trashed' if outcome['decision'] == 'trashed' else 'live')
                or not auth.same_data(current['version'], outcome['resulting'])):
            raise ValueError('new logical transition differs from the actual current lifecycle')
    return value


def apply_arguments(auth, value, path):
    value = auth.proposal(value)
    source = request(auth, auth.strict_json(value['request']))
    if (value['operation'] != 'apply' or source['operation']['kind'] != 'lifecycle'
            or value['read_grant'] == value['effect_grant']
            or not value['approval'].startswith(action(source)[2])):
        raise ValueError('only exact lifecycle apply with independent grants and operation-specific approval supported')
    return auth.terminal_arguments(value, path)


def capture_apply(auth, value, path):
    """Dedicated bounded effect transport; never widens capture_query."""
    arguments = apply_arguments(auth, value, path)
    auth.protected(auth.NATIVE, 128*1024*1024)
    return auth._capture_native(arguments, auth.MAX_QUERY_OUTPUT)


def journey(auth, value, directory):
    submitted = observed = False
    try:
        auth.proposal(value)
        source = request(auth, auth.strict_json(value['request']))
        canonical, _host = auth.canonical_native_request(value)
        source = request(auth, auth.strict_json(canonical))
        query = source['operation']['kind'] == 'lifecycle-status'
        inspect = dict(value, operation='inspection', request=canonical)
        with auth.request_stage(directory, canonical) as path:
            usage = inspection(auth, source, auth.capture_query(auth.terminal_arguments(inspect, path)))
            print('Fresh exact finite Read scope DATA, not a grant:\n'+json.dumps(usage, ensure_ascii=True), flush=True)
            read = auth.grant_selection('Independent Read grant for current status / exact native review (q cancels): ')
            if read is None:
                return 130
            data = auth.capture_query(auth.terminal_arguments(dict(inspect, operation='review', read_grant=read), path))
            if query:
                current = status(auth, source, data)
                print('OBSERVED current logical lifecycle after independently granted native Read. This is DATA, not permission to trash, restore or read bytes. Start an explicit new exact-reference journey for any change; no purge is available.\n'+json.dumps(current, ensure_ascii=True), flush=True)
                return 0
            review = reviewed(auth, source, data)
            print('OBSERVED native logical lifecycle review. Retention has no expiry or physical purge; conflict/no-change still requires this operation-specific effect grant.\n'+json.dumps(review, ensure_ascii=True), flush=True)
            apply_read = auth.grant_selection('Fresh apply Read grant for this exact reviewed acquisition (q cancels): ')
            if apply_read is None:
                return 130
            if apply_read == read:
                raise ValueError('apply requires a newly selected exact Read grant, not the consumed review Read')
            effect = auth.grant_selection('Independent finite Delete grant for trash / Write grant for restore (q cancels): ')
            if effect is None:
                return 130
            if apply_read == effect:
                raise ValueError('Read and lifecycle effect grant must be independent')
            approval = auth.terminal_line('Type exact '+review['approval']+' (q cancels): ', 128)
            if approval == 'q':
                return 130
            if approval != review['approval']:
                raise ValueError('lifecycle approval differs from actual native review')
            applying = dict(inspect, operation='apply', read_grant=apply_read, effect_grant=effect, approval=approval)
            apply_arguments(auth, applying, path)
            auth.protected(auth.NATIVE, 128*1024*1024)
            print('Submitting exact lifecycle request; retain this data for reconciliation. Interruption is not rollback or permission to retry:\n'+json.dumps(dict(request=source,
                request_sha256=hashlib.sha256(canonical.encode()).hexdigest(), review_sha256=review['review_sha256']), ensure_ascii=True), flush=True)
            submitted = True
            result = completed(auth, source, review, capture_apply(auth, applying, path))
            observed = True
        print('OBSERVED retained native lifecycle outcome: '+result['outcome']['decision']+'. Historical replay is NOT a new state change; ACTUAL CURRENT lifecycle is reported separately below. No bytes were physically erased; no automatic undo/retry or inferred permission.\n'+json.dumps(result, ensure_ascii=True), flush=True)
        return 0
    except (Exception, KeyboardInterrupt):
        print('Validated native lifecycle completion remains observed; later presentation stopped, not rollback.' if observed else
            'UNCERTAIN lifecycle outcome: apply was submitted but no complete validated result observed. Inspect the exact native request/C checkpoint before any retry; no rollback, undo or release inferred.' if submitted else
            'Lifecycle refused/cancelled before effect submission. Any observed status/review is data only; no logical change requested.', flush=True)
        return 1


def dialog_request(auth, login, binding, selection, artifact, expected, request_id):
    source = dict(schema_version=1, login=login, binding=auth.strict_json(binding))
    if selection == 'status':
        source['operation'] = dict(kind='lifecycle-status', artifact_id=artifact)
    elif selection in ('trash', 'restore'):
        reference = lifecycle_reference(auth, auth.strict_json(expected))
        if artifact != reference['version']['artifact_id']:
            raise ValueError('explicit artifact ID and supplied lifecycle reference differ')
        intent = dict(schema_version=1, binding=source['binding'], request_id=request_id,
            workflow_sha256=hashlib.sha256(b'luma-human-reviewed-logical-lifecycle-v1').hexdigest(),
            expected=reference, operation=selection, retention=RETENTION)
        source['operation'] = dict(kind='lifecycle', request=intent)
    else:
        raise ValueError('explicit supported lifecycle selection required')
    source = request(auth, source)
    return auth.proposal(dict(schema_version=1, operation='lifecycle-journey', login=login,
        read_grant='', effect_grant='', approval='', request=auth.encoded(source).decode()))


def launch_dialog(parent, auth):
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk
    dialog = Gtk.Dialog(title='Versioned trash — exact native review', transient_for=parent, modal=True)
    dialog.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Open original native terminal', Gtk.ResponseType.OK)
    dialog.set_default_size(780, 600)
    area = dialog.get_content_area()
    note = Gtk.Label(label='Status requires a fresh finite Read. Trash/restore requires a complete explicitly selected lifecycle reference, original native PAM, review, separate fresh Read and Delete/Write grants and exact approval. No guessed latest target, physical purge, expiry, automatic undo or retry. Passwords, private results and grants remain ONLY in the separate terminal. Historical replay never means the current artifact is in that old state.')
    note.set_line_wrap(True)
    area.pack_start(note, False, False, 8)
    selection_label = Gtk.Label.new_with_mnemonic('_Action')
    selection = Gtk.ComboBoxText()
    for name, label in (('status', 'Read current lifecycle status only'), ('trash', 'Logical trash — independent Delete'), ('restore', 'Restore from trash — independent Write')):
        selection.append(name, label)
    selection.set_active_id('status')
    selection_label.set_mnemonic_widget(selection)
    area.pack_start(selection_label, False, False, 3)
    area.pack_start(selection, False, False, 3)
    entries = {}
    for key, label, maximum in (('login', '_Human login', 32), ('binding', '_Owner binding JSON', 1024),
            ('artifact', '_Stable artifact ID', 128), ('expected', 'Exact _lifecycle reference JSON (trash/restore)', 4096),
            ('request_id', '_New stable request ID (trash/restore; retain for reconciliation)', 128)):
        caption = Gtk.Label.new_with_mnemonic(label)
        entry = Gtk.Entry(); entry.set_max_length(maximum); caption.set_mnemonic_widget(entry)
        area.pack_start(caption, False, False, 3); area.pack_start(entry, False, False, 3)
        entries[key] = entry
    error = Gtk.Label(); error.set_line_wrap(True); area.pack_start(error, False, False, 6)
    dialog.show_all()
    try:
        while dialog.run() == Gtk.ResponseType.OK:
            try:
                value = dialog_request(auth, entries['login'].get_text(), entries['binding'].get_text(),
                    selection.get_active_id(), entries['artifact'].get_text(), entries['expected'].get_text(), entries['request_id'].get_text())
                auth.launch(value)
                return True
            except Exception:
                error.set_text('Not launched. Select exact owner/artifact and full lifecycle reference for changes. No identity, latest version, grant, change or completion was assumed.')
        return False
    finally:
        dialog.destroy()
