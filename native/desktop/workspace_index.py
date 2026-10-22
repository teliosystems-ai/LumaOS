"""Trusted terminal index reads and proposed-build reviews, never build effects.

Canonicalization and scope calculation are public DATA operations. Only the
separate original-PAM index-review command may read current private C state.
No model, copied review, cursor, output or UI selection is authority.
"""
import hashlib
import json
from pathlib import Path
import re
import threading
import uuid

MAX_REQUEST = 65536
MAX_OUTPUT = 65536
DATA_FLAGS = ('authority_returned', 'private_content_read', 'session_lease_held',
              'effect_executed', 'actor_authenticated')


def fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError('closed exact index DATA required')
    return value


def integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('bounded exact integer required')
    return value


def digest(auth, value):
    if not auth.exact_sha(value):
        raise ValueError('exact nonzero lowercase digest required')
    return value


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{32}', value) or value == '0'*32:
        raise ValueError('exact nonzero native transaction ID required')
    return value


def limits(value, query=False):
    fields(value, ('read_bytes', 'write_bytes', 'source_bytes', 'postings', 'floating_operations'))
    integer(value['read_bytes'], 1, (128*1024*1024 if query else 128*1024**3))
    integer(value['write_bytes'], 0, 0 if query else 64*1024**3)
    integer(value['source_bytes'], 0, 8*1024**3)
    integer(value['postings'], 0, 32_000_000)
    integer(value['floating_operations'], 1, 64_000_000_000)
    return value


def request(auth, value):
    fields(value, ('schema_version', 'login', 'binding', 'request_id', 'operation'))
    auth.owner_request({key: value[key] for key in ('schema_version', 'login', 'binding', 'operation')})
    identifier(value['request_id'])
    operation = value['operation']
    kind = operation.get('kind') if isinstance(operation, dict) else None
    if kind == 'status':
        fields(operation, ('kind',))
    elif kind == 'query':
        fields(operation, ('kind', 'generation_sha256', 'query_kind', 'query', 'limit', 'limits'))
        digest(auth, operation['generation_sha256'])
        if operation['query_kind'] not in ('lexical-and', 'feature-lsa'):
            raise ValueError('fixed lexical/feature query required')
        if (not isinstance(operation['query'], str) or not operation['query']
                or len(operation['query'].encode()) > 4096):
            raise ValueError('bounded complete query required; Rust determines canonical grammar')
        integer(operation['limit'], 1, 64)
        limits(operation['limits'], query=True)
    elif kind == 'start':
        fields(operation, ('kind', 'expected_owner_sha256', 'expected_selection_sha256', 'job_id', 'dimensions', 'limits'))
        digest(auth, operation['expected_owner_sha256']); digest(auth, operation['expected_selection_sha256'])
        identifier(operation['job_id']); integer(operation['dimensions'], 1, 8)
        limits(operation['limits'])
        integer(operation['limits']['write_bytes'], 1, 64*1024**3)
    elif kind in ('step', 'advance', 'publish'):
        fields(operation, ('kind', 'job_id', 'expected_job_sha256', *(['window'] if kind == 'step' else [])))
        identifier(operation['job_id']); digest(auth, operation['expected_job_sha256'])
        if kind == 'step':
            window = fields(operation['window'], ('maximum', 'read_bytes', 'write_bytes'))
            integer(window['maximum'], 1, 8192); integer(window['read_bytes'], 1, 64*1024*1024)
            integer(window['write_bytes'], 0, 64*1024*1024)
    else:
        raise ValueError('status/query/proposed start/step/advance/publish only; no effects or recovery')
    if len(auth.encoded(value)) > MAX_REQUEST:
        raise ValueError('complete native index request exceeds64KiB')
    return value


def build_request(auth, login, binding, operation):
    return request(auth, dict(schema_version=1, login=login, binding=binding,
        request_id=uuid.uuid4().hex, operation=operation))


def status_request(auth, login, binding):
    return build_request(auth, login, binding, dict(kind='status'))


def query_request(auth, login, binding, generation, query, kind, limit, resource_limits):
    return build_request(auth, login, binding, dict(kind='query', generation_sha256=generation,
        query_kind=kind, query=query, limit=limit, limits=resource_limits))


def review_request(auth, login, binding, operation):
    if not isinstance(operation, dict) or operation.get('kind') not in ('start', 'step', 'advance', 'publish'):
        raise ValueError('explicit proposed phase operation required, not caller phase/cursor')
    return build_request(auth, login, binding, operation)


def mode(source):
    kind = source['operation']['kind']
    return kind if kind in ('status', 'query') else 'review'


def canonical_reply(auth, source, output, scope=False):
    value = auth.strict_json(output)
    fields(value, ('schema_version', 'canonical_request', 'request_sha256', *DATA_FLAGS,
                   *(['profile', 'storage_device', 'usage', 'installation_verified'] if scope else [])))
    integer(value['schema_version'], 1, 1)
    if any(value[key] is not False for key in DATA_FLAGS):
        raise ValueError('pure canonicalization/scope DATA cannot authenticate/read/lease/effect')
    canonical = value['canonical_request']
    if (not isinstance(canonical, str) or not 0 < len(canonical.encode()) <= MAX_REQUEST
            or value['request_sha256'] != hashlib.sha256(canonical.encode()).hexdigest()):
        raise ValueError('actual Rust canonical DATA substituted source or digest')
    normalized = request(auth, auth.strict_json(canonical))
    compared = dict(normalized)
    if source['operation']['kind'] == 'query':
        # Only actual pinned Rust may normalize query case/whitespace/term
        # aliases. Show its resulting exact source BEFORE selecting a grant.
        compared['operation'] = dict(normalized['operation'], query=source['operation']['query'])
    if not auth.same_data(compared, source):
        raise ValueError('actual Rust canonicalizer changed fields other than query normalization')
    if scope:
        if value['installation_verified'] is not False:
            raise ValueError('claimed installation DATA is not installed identity authority')
        expected = 'index-v2-{}-{}-{}-{}'.format(mode(normalized), normalized['binding']['owner_generation'],
            value['request_sha256'], value['request_sha256'])
        if value['profile'] != expected or not isinstance(value['storage_device'], str):
            raise ValueError('scope DATA changed actual closed readonly profile')
        device = re.fullmatch(r'([1-9][0-9]*):(0|[1-9][0-9]*)', value['storage_device'])
        if device is None or any(int(part) > 2**32-1 for part in device.groups()):
            raise ValueError('exact installed block tuple DATA required')
        usage = fields(value['usage'], ('action', 'selector', 'input_bytes', 'output_bytes', 'units'))
        selector = fields(usage['selector'], ('kind', 'id', 'generation', 'digest'))
        selected = mode(source)
        if (usage['action'] != 'file.read' or selector['kind'] != 'file'
                or selector['id'] != 'native-content-index-'+{'status':'inspect', 'query':'query', 'review':'source'}[selected]+'-v2'
                or selector['generation'] != source['binding']['owner_generation']):
            raise ValueError('scope DATA changed finite Read selector/owner')
        integer(selector['generation'], 1, 2**64-1); digest(auth, selector['digest'])
        integer(usage['input_bytes'], 4*1024*1024 if selected == 'status' else 128*1024*1024,
                4*1024*1024 if selected == 'status' else 128*1024*1024)
        integer(usage['output_bytes'], MAX_OUTPUT, MAX_OUTPUT); integer(usage['units'], 1, 1)
    return value


def canonical(auth, host, source, scope=False):
    request(auth, source)
    binary = host.PinnedExecutable(Path(auth.NATIVE))
    try:
        state, output = host.run_process(binary, 'index-scope-proposal' if scope else 'index-request',
            auth.encoded(source), threading.Event(), lambda _pid: None, maximum=128*1024)
    finally:
        binary.close()
    if state != 'completed':
        raise ValueError('actual pure native index canonicalizer unavailable/refused')
    return canonical_reply(auth, source, output, scope)


def capture(auth, source, grant, path):
    request(auth, source)
    if not isinstance(grant, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', grant):
        raise ValueError('explicit fresh finite Read grant ID required')
    auth.protected(auth.NATIVE, 128*1024*1024)
    return auth._capture_native(['/usr/bin/sudo', '--', auth.NATIVE, 'granted-run',
        'index-review', source['login'], grant, str(path)], MAX_OUTPUT)


def completed(auth, source, canonical_source, output):
    value = auth.strict_json(output)
    selected = mode(source)
    common = ('schema_version', 'kind', 'selection_sha256', 'effect_executed', 'authority_returned', 'production_qualified')
    specific = {'status': ('owner_sha256', 'corpus_sha256', 'documents', 'current_generation', 'job', 'preparation_pending'),
                'query': ('result',), 'review': ('review', 'effect_profile', 'quota_preview')}[selected]
    fields(value, (*common, *specific)); integer(value['schema_version'], 2, 2)
    if value['kind'] != selected or any(value[key] is not False for key in common[-3:]):
        raise ValueError('read reply cannot become authority, build completion or qualification')
    digest(auth, value['selection_sha256'])
    if selected == 'status':
        digest(auth, value['owner_sha256']); digest(auth, value['corpus_sha256'])
        integer(value['documents'], 0, 100000)
        if type(value['preparation_pending']) is not bool:
            raise ValueError('exact pending observation required')
        if value['current_generation'] is not None:
            digest(auth, value['current_generation'])
        if value['job'] is not None:
            job = fields(value['job'], ('job_id', 'job_sha256', 'revision', 'phase', 'phase_complete', 'totals',
                'source_corpus_sha256', 'stale_corpus', 'stale_builder'))
            identifier(job['job_id']); digest(auth, job['job_sha256']); digest(auth, job['source_corpus_sha256'])
            integer(job['revision'], 1, 2**64-1)
            if (job['phase'] not in ('ingest', 'statistics', 'covariance', 'projection', 'vectors', 'audit', 'publish', 'published', 'retained')
                    or any(type(job[key]) is not bool for key in ('phase_complete', 'stale_corpus', 'stale_builder'))):
                raise ValueError('closed observed job phase required')
            if job['totals'] is not None:
                totals = fields(job['totals'], ('read_bytes', 'write_bytes', 'source_bytes', 'postings', 'work'))
                for key, maximum in (('read_bytes', 128*1024**3), ('write_bytes', 64*1024**3),
                        ('source_bytes', 8*1024**3), ('postings', 32_000_000), ('work', 64_000_000_000)):
                    integer(totals[key], 0, maximum)
    elif selected == 'query':
        query = fields(value['result'], ('schema_version', 'profile', 'kind', 'canonical_query', 'corpus_sha256',
            'index_sha256', 'matches', 'total_matches', 'truncated'))
        operation = source['operation']; integer(query['schema_version'], 1, 1)
        if (query['profile'] != 'luma-selected-corpus-generation-v2' or query['kind'] != operation['query_kind']
                or query['canonical_query'] != operation['query'] or query['index_sha256'] != operation['generation_sha256']
                or not isinstance(query['matches'], list) or len(query['matches']) > operation['limit']):
            raise ValueError('query response changed exact selected generation/query/limit')
        digest(auth, query['corpus_sha256']); integer(query['total_matches'], 0, 100000)
        if (type(query['truncated']) is not bool or query['truncated'] != (query['total_matches'] > operation['limit'])
                or len(query['matches']) != min(query['total_matches'], operation['limit'])):
            raise ValueError('query totals/truncation differ; no clipping')
        seen = set()
        for match in query['matches']:
            fields(match, ('reference', 'format', 'score')); auth.reference_data(match['reference'])
            integer(match['score'], 1, 2**63-1)
            artifact = match['reference']['artifact_id']
            if match['format'] not in ('utf8-text', 'csv', 'json') or artifact in seen:
                raise ValueError('exact distinct current candidate references required')
            seen.add(artifact)
    else:
        review = value['review']
        transition = source['operation']['kind'] in ('start', 'advance')
        fields(review, ('schema_version', 'input_sha256', 'review_sha256', 'core_review_sha256', 'builder',
            'policy_sha256', 'metadata_maximum', *(
                ('base_owner_sha256', 'base_job_sha256', 'selection_sha256', 'operation', 'next_job', 'objects') if transition else
                ('base_sha256', 'phase', 'planned_objects_sha256', 'source_bytes', 'maximum_read_bytes', 'maximum_write_bytes'))))
        integer(review.get('schema_version'), 2, 2)
        digest(auth, review.get('policy_sha256'))
        builder = fields(review['builder'], ('source_sha256', 'runtime_sha256'))
        for item in builder.values():
            digest(auth, item)
        maximum = fields(review['metadata_maximum'], ('object_writes', 'read_bytes', 'write_bytes', 'new_files'))
        if not auth.same_data(maximum, dict(object_writes=256, read_bytes=8*1024*1024, write_bytes=32*1024*1024, new_files=768)):
            raise ValueError('native review changed explicit finite metadata ceiling')
        quota = fields(value['quota_preview'], ('summary', 'sha256', 'quota_data_only', 'free_space_proven',
            'reservation_created', 'effect_admitted'))
        digest(auth, quota['sha256'])
        if (quota['quota_data_only'] is not True or any(quota[key] is not False for key in
                ('free_space_proven', 'reservation_created', 'effect_admitted')) or not isinstance(quota['summary'], dict)
                or quota['summary'].get('policy_sha256') != review['policy_sha256']):
            raise ValueError('quota arithmetic DATA is not capacity admission or a reservation')
        summary = fields(quota['summary'], ('schema_version', 'policy_sha256', 'actual', 'retained_records',
            'retained', 'requested', 'total'))
        integer(summary['schema_version'], 1, 1); integer(summary['retained_records'], 0, 1048576)
        for key in ('actual', 'retained', 'requested', 'total'):
            liability = fields(summary[key], ('allocated_bytes', 'regular_files', 'directories', 'segments'))
            for part, cap in (('allocated_bytes', 64*1024**3), ('regular_files', 1048576),
                    ('directories', 65536), ('segments', 4096)):
                integer(liability[part], 0, cap)
        if transition:
            digest(auth, review['base_owner_sha256']); digest(auth, review['selection_sha256'])
            if review['selection_sha256'] != value['selection_sha256'] or review['operation'] != source['operation']['kind']:
                raise ValueError('transition review changed actual operation/selection')
            if review['base_job_sha256'] is not None:
                digest(auth, review['base_job_sha256'])
            if source['operation']['kind'] == 'start' and (
                    review['base_owner_sha256'] != source['operation']['expected_owner_sha256']
                    or review['selection_sha256'] != source['operation']['expected_selection_sha256']):
                raise ValueError('start review changed expected owner/selection')
            blob = fields(review['next_job'], ('schema_version', 'domain', 'binding', 'sha256', 'bytes', 'chunk_count', 'index_sha256'))
            integer(blob['schema_version'], 1, 1); integer(blob['bytes'], 1, 1024*1024)
            integer(blob['chunk_count'], (blob['bytes']+16383)//16384, (blob['bytes']+16383)//16384)
            if blob['domain'] != 'luma-editable-content-store-v2' or not auth.same_data(blob['binding'], source['binding']):
                raise ValueError('review substituted immutable next-job owner')
            digest(auth, blob['sha256']); digest(auth, blob['index_sha256'])
            if not isinstance(review['objects'], list) or not 1 <= len(review['objects']) <= 256:
                raise ValueError('bounded complete transition inventory required')
            seen = set()
            for obj in review['objects']:
                fields(obj, ('sha256', 'bytes')); digest(auth, obj['sha256']); integer(obj['bytes'], 1, 16384)
                if obj['sha256'] in seen:
                    raise ValueError('transition inventory repeats immutable object')
                seen.add(obj['sha256'])
        else:
            digest(auth, review['base_sha256']); digest(auth, review['planned_objects_sha256'])
            if review['phase'] not in ('ingest', 'statistics', 'covariance', 'projection', 'vectors', 'audit', 'publish'):
                raise ValueError('closed current native phase required')
            if source['operation']['kind'] == 'publish' and review['phase'] != 'publish':
                raise ValueError('publish review selected a different phase')
            integer(review['source_bytes'], 0, 64*1024*1024)
            integer(review['maximum_read_bytes'], 1, 128*1024*1024)
            integer(review['maximum_write_bytes'], 0, 128*1024*1024)
        source_sha = hashlib.sha256(canonical_source.encode()).hexdigest()
        if review.get('input_sha256') != source_sha:
            raise ValueError('review changed exact canonical source')
        digest(auth, review.get('review_sha256')); digest(auth, review.get('core_review_sha256'))
        expected = 'index-v2-{}-{}-{}-{}'.format(source['operation']['kind'], source['binding']['owner_generation'],
            source_sha, review['review_sha256'])
        if value['effect_profile'] != expected:
            raise ValueError('review substituted source/native envelope/owner; no effect submitted')
        base_key = 'base_sha256' if source['operation']['kind'] in ('step', 'publish') else 'base_job_sha256'
        if source['operation']['kind'] in ('advance', 'step', 'publish') and review.get(base_key) != source['operation']['expected_job_sha256']:
            raise ValueError('review changed expected current job')
    return value


def journey(auth, value, directory):
    try:
        source = request(auth, auth.strict_json(value['request']))
        host = auth.workspace_controller('draft').host_module(auth)
        proposed = canonical(auth, host, source, scope=True)
        source = request(auth, auth.strict_json(proposed['canonical_request']))
        print('Pure scope proposal DATA only: no authentication, private read, grant, lease or effects.\n'+
            json.dumps(proposed, ensure_ascii=True), flush=True)
        grant = auth.grant_selection('Fresh exact finite index Read grant (q cancels): ')
        if grant is None:
            return 130
        with auth.request_stage(directory, proposed['canonical_request']) as path:
            result = completed(auth, source, proposed['canonical_request'], capture(auth, source, grant, path))
        print('Observed native private index Read/review DATA, not build execution, saved content, permission or production qualification. '
              'No next phase, retry or effect is automatic. Query references need separately granted exact artifact Reads.\n'+
              json.dumps(result, ensure_ascii=True), flush=True)
        return 0
    except (Exception, KeyboardInterrupt):
        print('Index read/review stopped or refused. No current result, permission, build completion, automatic retry or effect was inferred.', flush=True)
        return 1


def dialog_request(auth, login, binding, operation):
    source = build_request(auth, login, auth.strict_json(binding), auth.strict_json(operation))
    return auth.proposal(dict(schema_version=1, operation='index-journey', login=login,
        read_grant='', effect_grant='', approval='', request=auth.encoded(source).decode()))


def launch_dialog(parent, auth):
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk
    dialog = Gtk.Dialog(title='Native index status, query and review', transient_for=parent, modal=True)
    dialog.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Open original native terminal', Gtk.ResponseType.OK)
    dialog.set_default_size(780, 570)
    area = dialog.get_content_area()
    note = Gtk.Label(label='Status, lexical/feature query and proposed build review only. Supply exact owner DATA and a closed operation. '
        'The terminal first shows a public scope proposal, then requires fresh original PAM, finite Read and actual resource/C checks. '
        'Build effects, recovery, automatic phase advancement and hidden retries are unavailable. A review is not completion; no grants or private results enter WebKit.')
    note.set_line_wrap(True); area.pack_start(note, False, False, 8)
    entries = {}
    for key, caption, maximum in (('login', '_Human login', 32), ('binding', 'Exact _owner binding JSON', 1024)):
        label = Gtk.Label.new_with_mnemonic(caption); entry = Gtk.Entry(); entry.set_max_length(maximum)
        label.set_mnemonic_widget(entry); area.pack_start(label, False, False, 3); area.pack_start(entry, False, False, 3)
        entries[key] = entry
    label = Gtk.Label.new_with_mnemonic('Complete typed _operation JSON (status, query, proposed start/step/advance/publish)')
    text = Gtk.TextView(); text.set_accepts_tab(False); text.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
    text.get_buffer().set_text('{"kind":"status"}')
    label.set_mnemonic_widget(text); area.pack_start(label, False, False, 3)
    scroll = Gtk.ScrolledWindow(); scroll.set_min_content_height(190); scroll.add(text); area.pack_start(scroll, True, True, 3)
    error = Gtk.Label(); error.set_line_wrap(True); area.pack_start(error, False, False, 4)
    dialog.show_all()
    try:
        while dialog.run() == Gtk.ResponseType.OK:
            try:
                buffer = text.get_buffer()
                value = dialog_request(auth, entries['login'].get_text(), entries['binding'].get_text(),
                    buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False))
                auth.launch(value)
                return True
            except Exception:
                error.set_text('Not launched. Supply complete closed owner/operation DATA; no current selection, authority or completion was inferred.')
        return False
    finally:
        dialog.destroy()
