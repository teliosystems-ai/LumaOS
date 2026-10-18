"""GI-free protocol/process tests; these do not qualify GTK or product authority."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('luma_workspace_host_tests', ROOT / 'native/desktop/workspace_host.py')
host = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host)


def preview(engine='document', source='{}'):
    return dict(schema_version=1, id='request-1', operation='preview', engine=engine, source=source)


def response(data):
    return host.encode(dict(schema_version=1, result=data, owner_authenticated=False, authority_returned=False,
                            committed=False, certified=False, gate_closing=False))


def document():
    return dict(operation='document', rendering=dict(schema_version=1, engine='luma-static-document-v1',
                canonical_source='{}', source_sha256=host.digest('{}'), canonical_html='<p>Safe</p>',
                html_sha256=host.digest('<p>Safe</p>'), work_units=0), scripts_executed=False,
                external_resources_loaded=False, source_retained=False)


def capture_fixture(text='Manual text\n'):
    receipt = dict(schema_version=1, binding=host.PREVIEW_BINDING, artifact_id='manual-preview', version=1,
                   previous=None, format='utf8-text', media_type='text/plain; charset=utf-8',
                   content_sha256=host.digest(text), content_bytes=len(text.encode()), original_bytes=len(text.encode()),
                   provenance=dict(request_id='request-1', workflow_sha256=host.digest('unexecuted-manual-preview-v1'),
                                   source_sha256=host.digest(text), origin='managed'))
    return capture_receipt(receipt, text)


def capture_receipt(receipt, text):
    receipt_hash = host.digest(host.encode(receipt))
    reference = dict(artifact_id=receipt['artifact_id'], version=receipt['version'],
                     content_sha256=receipt['content_sha256'], receipt_sha256=receipt_hash)
    envelope = host.encode(dict(receipt=receipt, receipt_sha256=receipt_hash, content=text)).decode()
    return dict(operation='capture', proposed=dict(receipt=receipt, reference=reference, canonical_envelope=envelope))


def spreadsheet_fixture():
    rows = [[dict(kind='text', value='Quoted, field'), dict(kind='blank'), dict(kind='number', value='2'),
             dict(kind='formula', expression=dict(op='number', value='6'))]]
    source = host.encode(dict(schema_version=1, rows=rows)).decode()
    csv = '"Quoted, field",,2,6\n'
    values = [[dict(kind='text', value='Quoted, field'), dict(kind='blank'), dict(kind='number', value='2'), dict(kind='number', value='6')]]
    return source, dict(operation='spreadsheet', typed_expressions_evaluated=True, csv_formula_text_executed=False,
                        source_retained=False, calculation=dict(schema_version=1, engine='luma-exact-spreadsheet-v1',
                        canonical_source=source, source_sha256=host.digest(source), values=values,
                        canonical_csv=csv, csv_sha256=host.digest(csv), evaluation_steps=2))


class Pin:
    def __init__(self):
        self.fd = os.open(sys.executable, os.O_RDONLY)
        self.sha256 = 'a' * 64
        self.checks = 0
        self.closed = False

    def check(self):
        self.checks += 1

    def close(self):
        os.close(self.fd)
        self.closed = True


class WorkspaceHostTests(unittest.TestCase):
    def test_closed_protocol_has_no_command_path_env_grant_or_owner_override(self):
        good = preview()
        self.assertEqual(host.request(json.dumps(good)), good)
        for field in ('path', 'command', 'executable', 'environment', 'grant', 'owner', 'model', 'timeout'):
            with self.assertRaises(ValueError):
                host.request(dict(good, **{field: 'anything'}))
        for field, value in [('schema_version', True), ('id', '../path'), ('operation', 'publish'), ('engine', 'browser')]:
            with self.assertRaises(ValueError):
                host.request(dict(good, **{field: value}))
        with self.assertRaises(ValueError):
            host.request('{"schema_version":1,"schema_version":1}')

    def test_exact_utf8_source_and_transport_bounds_precede_invocation(self):
        host.request(preview('text', 'a' * host.MAX_SOURCE))
        for value in [preview('text', 'a' * (host.MAX_SOURCE + 1)), preview('text', 'é' * host.MAX_SOURCE)]:
            with self.assertRaises(ValueError):
                host.request(value)
        with self.assertRaises(ValueError):
            host.request(' ' * (host.MAX_MESSAGE + 1))

    def test_fixed_capture_binding_is_explicitly_untrusted_not_an_actual_account(self):
        value = preview('csv', 'a,b\n1,2\n')
        command, payload = host.invocation(value)
        self.assertEqual(command, 'content-contract-capture')
        parsed = json.loads(payload)
        self.assertEqual(parsed['binding'], host.PREVIEW_BINDING)
        self.assertEqual(parsed['format'], 'csv')
        self.assertEqual(parsed['provenance']['source_sha256'], host.digest(value['source']))
        self.assertFalse(host.FLAGS['owner_authenticated'])
        self.assertFalse(host.FLAGS['committed'])

    def test_reopen_requires_exact_complete_selected_envelope_hash(self):
        envelope = '{"receipt":{"binding":{}},"content":"data"}'
        good = dict(schema_version=1, id='reopen-1', operation='reopen', source=envelope,
                    expected_envelope_sha256=host.digest(envelope))
        self.assertEqual(host.request(good), good)
        command, payload = host.invocation(good)
        self.assertEqual(command, 'content-contract-reopen')
        self.assertEqual(json.loads(payload)['envelope'], envelope)
        for replacement in ('0' * 64, 'A' * 64, ''):
            with self.assertRaises(ValueError):
                host.request(dict(good, expected_envelope_sha256=replacement))
        with self.assertRaises(ValueError):
            host.request(dict(good, source=envelope + ' '))

    def test_document_source_output_and_engine_digests_are_joined(self):
        good = document()
        self.assertEqual(host.validate_result(preview(), response(good)), good)
        for field, value in [('source_sha256', 'f' * 64), ('html_sha256', 'f' * 64),
                             ('canonical_html', '<script>1</script>'), ('engine', 'another-engine')]:
            bad = copy.deepcopy(good)
            bad['rendering'][field] = value
            with self.assertRaises(ValueError):
                host.validate_result(preview(), response(bad))
        bad = copy.deepcopy(good)
        bad['rendering']['canonical_source'] = '{"other":1}'
        bad['rendering']['source_sha256'] = host.digest(bad['rendering']['canonical_source'])
        with self.assertRaises(ValueError):
            host.validate_result(preview(), response(bad))

    def test_capture_reopen_full_envelope_content_and_receipt_digests_are_joined(self):
        text = 'Unicode café\n'
        receipt = dict(schema_version=1, binding=host.PREVIEW_BINDING, artifact_id='manual-preview',
            version=1, previous=None, format='utf8-text', media_type='text/plain; charset=utf-8',
            content_sha256=host.digest(text), content_bytes=len(text.encode()), original_bytes=len(text.encode()),
            provenance=dict(request_id='request-1', workflow_sha256=host.digest('unexecuted-manual-preview-v1'),
                            source_sha256=host.digest(text), origin='managed'))
        receipt_hash = host.digest(host.encode(receipt))
        reference = dict(artifact_id='manual-preview', version=1, content_sha256=host.digest(text), receipt_sha256=receipt_hash)
        envelope = host.encode(dict(receipt=receipt, receipt_sha256=receipt_hash, content=text)).decode()
        artifact = dict(receipt=receipt, reference=reference, canonical_envelope=envelope)
        capture = dict(operation='capture', proposed=artifact)
        checked = host.validate_result(preview('text', text), response(capture))
        self.assertEqual(checked['envelope_sha256'], host.digest(envelope))
        self.assertEqual(checked['preview_content'], text)
        reopened = dict(schema_version=1, id='reopen-1', operation='reopen', source=envelope,
                        expected_envelope_sha256=host.digest(envelope))
        host.validate_result(reopened, response(dict(operation='reopen', validated=artifact)))
        for change in ('content', 'receipt', 'reference', 'selected-envelope'):
            bad = copy.deepcopy(capture)
            if change == 'reference':
                bad['proposed']['reference']['version'] = 2
            elif change == 'selected-envelope':
                with self.assertRaises(ValueError):
                    host.validate_result(dict(reopened, source=envelope + ' '), response(dict(operation='reopen', validated=artifact)))
                continue
            else:
                parsed = json.loads(bad['proposed']['canonical_envelope'])
                if change == 'content':
                    parsed['content'] = 'substitution'
                else:
                    parsed['receipt']['content_bytes'] += 1
                bad['proposed']['canonical_envelope'] = host.encode(parsed).decode()
            with self.assertRaises(ValueError):
                host.validate_result(preview('text', text), response(bad))

    def test_authority_flags_and_operation_substitution_are_refused(self):
        good = json.loads(response(document()))
        for field in ('owner_authenticated', 'authority_returned', 'committed', 'certified', 'gate_closing'):
            bad = dict(good, **{field: True})
            with self.assertRaises(ValueError):
                host.validate_result(preview(), host.encode(bad))
        with self.assertRaises(ValueError):
            host.validate_result(preview('diagram'), response(document()))

    def test_animation_validates_each_frame_and_exact_ordered_frame_commitment(self):
        frame = dict(index=0, canonical_svg='<svg/>', svg_sha256=host.digest('<svg/>'))
        source = '{"frames_per_second":1,"frame_count":1}'
        rendering = dict(schema_version=1, engine='luma-sampled-animation-v1', canonical_source=source,
                         source_sha256=host.digest(source), frames=[frame], frames_per_second=1,
                         frames_sha256=host.digest(host.encode([frame])), work_units=0)
        data = dict(operation='animation', rendering=rendering, scripts_executed=False,
                    external_resources_loaded=False, source_retained=False, playback_started=False)
        host.validate_result(preview('animation', source), response(data))
        for field, value in [('frames_sha256', 'f' * 64), ('frames', []), ('frames', [dict(frame, index=1)]),
                             ('frames', [dict(frame, svg_sha256='f' * 64)])]:
            bad = copy.deepcopy(data)
            bad['rendering'][field] = value
            with self.assertRaises(ValueError):
                host.validate_result(preview('animation', source), response(bad))

    def test_closed_native_result_schema_refuses_additional_flags_and_boolean_integers(self):
        good = json.loads(response(document()))
        for path in [('schema_version',), ('result', 'rendering', 'schema_version'), ('result', 'rendering', 'work_units')]:
            bad = copy.deepcopy(good)
            parent = bad
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = True
            with self.assertRaises(ValueError):
                host.validate_result(preview(), host.encode(bad))
        for path in [(), ('result',), ('result', 'rendering')]:
            bad = copy.deepcopy(good)
            parent = bad
            for key in path:
                parent = parent[key]
            parent['grant_issued'] = False
            with self.assertRaises(ValueError):
                host.validate_result(preview(), host.encode(bad))
        with self.assertRaises(ValueError):
            host.validate_result(preview(), b' ' * (host.MAX_OUTPUT + 1))

    def test_capture_rejects_consistently_rehashed_wrong_intent_not_only_bad_hashes(self):
        text = 'Manual text\n'
        good = capture_fixture(text)
        host.validate_result(preview('text', text), response(copy.deepcopy(good)))
        receipt = good['proposed']['receipt']
        for field, replacement in [('artifact_id', 'other-source'), ('version', True), ('original_bytes', len(text.encode()) + 1),
                                   ('format', 'csv'), ('previous', {'artifact_id': 'forged'})]:
            changed = copy.deepcopy(receipt)
            changed[field] = replacement
            if field == 'format':
                changed['media_type'] = 'text/csv; charset=utf-8'
            with self.assertRaises(ValueError):
                host.validate_result(preview('text', text), response(capture_receipt(changed, text)))
        changed = copy.deepcopy(receipt)
        changed['content_sha256'] = host.digest('Substituted\n')
        changed['content_bytes'] = len('Substituted\n'.encode())
        with self.assertRaises(ValueError):
            host.validate_result(preview('text', text), response(capture_receipt(changed, 'Substituted\n')))
        for field in ('request_id', 'workflow_sha256', 'source_sha256', 'origin'):
            changed = copy.deepcopy(receipt)
            changed['provenance'][field] = 'external' if field == 'origin' else 'other' if field == 'request_id' else 'ab' * 32
            with self.assertRaises(ValueError):
                host.validate_result(preview('text', text), response(capture_receipt(changed, text)))

    def test_capture_comparison_preserves_native_crlf_and_quoted_csv_semantics(self):
        self.assertEqual(host.csv_values('Name,Value\r\n"Quoted, field\r\nline",2\r\n'),
                         [['Name', 'Value'], ['Quoted, field\nline', '2']])
        source, data = spreadsheet_fixture()
        parsed = json.loads(source)
        parsed['rows'][0][0]['value'] = 'First\r\nSecond'
        source = host.encode(parsed).decode()
        data['calculation']['canonical_source'] = source
        data['calculation']['source_sha256'] = host.digest(source)
        data['calculation']['values'][0][0]['value'] = 'First\nSecond'
        data['calculation']['canonical_csv'] = '"First\nSecond",,2,6\n'
        data['calculation']['csv_sha256'] = host.digest(data['calculation']['canonical_csv'])
        host.validate_result(preview('spreadsheet', source), response(data))

    def test_rendering_refuses_scripts_resources_retention_and_autoplay_even_with_matching_digests(self):
        for field in ('scripts_executed', 'external_resources_loaded', 'source_retained'):
            changed = document()
            changed[field] = True
            with self.assertRaises(ValueError):
                host.validate_result(preview(), response(changed))
        source = '{"frames_per_second":1,"frame_count":1}'
        frame = dict(index=0, canonical_svg='<svg/>', svg_sha256=host.digest('<svg/>'))
        data = dict(operation='animation', scripts_executed=False, external_resources_loaded=False,
                    source_retained=False, playback_started=False, rendering=dict(schema_version=1,
                    engine='luma-sampled-animation-v1', canonical_source=source, source_sha256=host.digest(source),
                    frames_per_second=1, frames=[frame], frames_sha256=host.digest(host.encode([frame])), work_units=0))
        for field, replacement in [('playback_started', True), ('frames_per_second', 2), ('frames_per_second', True)]:
            changed = copy.deepcopy(data)
            if field == 'playback_started':
                changed[field] = replacement
            else:
                changed['rendering'][field] = replacement
            with self.assertRaises(ValueError):
                host.validate_result(preview('animation', source), response(changed))

    def test_spreadsheet_display_is_bound_to_exact_digest_verified_csv_and_source_shape(self):
        source, good = spreadsheet_fixture()
        host.validate_result(preview('spreadsheet', source), response(copy.deepcopy(good)))
        for change in ('value', 'type', 'unknown', 'ragged', 'extra-row', 'formula-execution', 'evaluation-bool'):
            changed = copy.deepcopy(good)
            calculation = changed['calculation']
            if change == 'value':
                calculation['values'][0][3]['value'] = '9'
            elif change == 'type':
                calculation['values'][0][3]['kind'] = 'text'
            elif change == 'unknown':
                calculation['values'][0][1]['ignored_value'] = 'forged'
            elif change == 'ragged':
                calculation['values'][0].pop()
            elif change == 'extra-row':
                calculation['values'].append(copy.deepcopy(calculation['values'][0]))
            elif change == 'formula-execution':
                changed['csv_formula_text_executed'] = True
            else:
                calculation['evaluation_steps'] = True
            with self.assertRaises(ValueError):
                host.validate_result(preview('spreadsheet', source), response(changed))

    def test_json_source_comparison_distinguishes_nested_booleans_from_integers(self):
        self.assertFalse(host.same_json({'schema_version': True}, {'schema_version': 1}))
        self.assertFalse(host.same_json([{'count': 1}], [{'count': 1.0}]))
        self.assertTrue(host.same_json({'one': [1, False]}, {'one': [1, False]}))

    def test_pinned_executable_refuses_mutable_noncanonical_and_relative_paths(self):
        for path in ('relative', '/tmp/../tmp/not-a-platform'):
            with self.assertRaises((ValueError, OSError)):
                host.PinnedExecutable(path)

    def child(self, script, *, cancel=None, timeout=1.0, maximum=4096):
        """Actual disposable subprocess; substitution is confined to this test."""
        binary, pids = Pin(), []
        real_spawn = subprocess.Popen
        def spawn(_arguments, **kwargs):
            kwargs.pop('executable')
            return real_spawn([sys.executable, '-I', '-c', script], **kwargs)
        try:
            with patch.object(host.subprocess, 'Popen', spawn):
                status, output = host.run_process(binary, 'content-contract-document', b'{}',
                    cancel or threading.Event(), lambda pid: pids.append(pid), timeout=timeout, maximum=maximum)
            self.assertEqual(len(pids), 1)
            with self.assertRaises(ProcessLookupError):
                os.kill(pids[0], 0)
            return status, output
        finally:
            binary.close()

    def test_incremental_stdout_and_stderr_bounds_kill_and_reap_before_result(self):
        for descriptor in (1, 2):
            status, output = self.child(f'import os\nwhile True: os.write({descriptor}, b"x" * 4096)', maximum=1024)
            self.assertEqual(status, 'output-bound')
            self.assertIsNone(output)

    def test_actual_timeout_and_cancel_are_reaped_not_invented_success(self):
        status, output = self.child('import time; time.sleep(10)', timeout=0.1)
        self.assertEqual(status, 'timeout')
        self.assertIsNone(output)
        cancel = threading.Event()
        cancel.set()
        status, output = self.child('import time; time.sleep(10)', cancel=cancel)
        self.assertEqual(status, 'cancelled')
        self.assertIsNone(output)

    def test_closed_stream_wait_stays_cancellable(self):
        cancel = threading.Event()
        timer = threading.Timer(0.1, cancel.set)
        timer.start()
        try:
            status, _ = self.child('import os,time; os.close(0); os.close(1); os.close(2); time.sleep(10)', cancel=cancel)
            self.assertEqual(status, 'cancelled')
        finally:
            timer.cancel()

    def test_actual_success_exit_is_only_process_observation_not_authority(self):
        status, output = self.child('import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b"{}")')
        self.assertEqual((status, output), ('completed', b'{}'))
        with self.assertRaises(ValueError):
            host.validate_result(preview(), output)

    def test_nonzero_exit_and_unknown_command_never_yield_completion(self):
        with self.assertRaises(ValueError):
            self.child('raise SystemExit(3)')
        binary = Pin()
        try:
            with self.assertRaises(ValueError):
                host.run_process(binary, 'model-activate', b'{}', threading.Event(), lambda _: None)
        finally:
            binary.close()

    def test_host_busy_reused_ids_and_observed_cancel_state(self):
        binary, events = Pin(), []
        started, finish = threading.Event(), threading.Event()
        def run(_binary, _command, _payload, cancel, observe):
            observe(1)
            started.set()
            self.assertTrue(finish.wait(2))
            self.assertTrue(cancel.is_set())
            return 'cancelled', None
        service = host.Host(binary, events.append)
        with patch.object(host, 'run_process', run):
            service.submit(preview())
            self.assertTrue(started.wait(2))
            with self.assertRaises(ValueError):
                service.submit(preview())
            service.submit(dict(schema_version=1, id='request-1', operation='cancel'))
            self.assertEqual([event['state'] for event in events], ['started', 'cancel-requested'])
            thread = service.active[2]
            finish.set()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(events[-1]['state'], 'cancelled')
            self.assertTrue(all(event['authority_returned'] is False for event in events))
            with self.assertRaises(ValueError):
                service.submit(preview())
            service.close()
            self.assertTrue(binary.closed)

    def test_ui_is_separate_ephemeral_scriptless_manual_surface(self):
        app = (ROOT / 'native/desktop/workspace_app.py').read_text()
        js = (ROOT / 'web/native-workspace.js').read_text()
        html = (ROOT / 'web/native-workspace.html').read_text()
        self.assertIn('WebContext.new_ephemeral()', app)
        self.assertIn('context.set_sandbox_enabled(True)', app)
        self.assertIn('permission.deny()', app)
        self.assertIn("frame.setAttribute('sandbox', '')", js)
        self.assertNotIn('innerHTML', js)
        self.assertNotIn('fetch(', js)
        self.assertNotIn('setInterval(', js)
        self.assertIn('no autoplay', html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn("connect-src 'none'", html)
        self.assertIn('No account, grant, repository, publication', html)


def real_cli_fixture(path):
    """Explicit extra lane: real cached CLI, no executable/result substitution.

    LUMA_WORKSPACE_TEST_CLI exists only in this test entry point. The installed
    desktop product never reads it and keeps its fixed installed binary path.
    """
    sources = {
        'text': 'Exact café source\r\nSecond line\n',
        'csv': 'Name,Value\n"Quoted, field",2\n',
        'json': '{"schema_version":1,"value":"Exact editable JSON"}',
        'spreadsheet': host.encode(dict(schema_version=1, rows=[[
            dict(kind='text', value='Quoted, field\r\nline'), dict(kind='blank'),
            dict(kind='number', value='2'),
            dict(kind='formula', expression=dict(op='binary', operator='multiply',
                left=dict(op='cell', row=0, column=2), right=dict(op='number', value='3')))
        ]])).decode(),
        'document': host.encode(dict(schema_version=1, title='Actual native document', blocks=[
            dict(kind='heading', level=1, text='Native preview'),
            dict(kind='paragraph', runs=[dict(kind='text', text='Inert <script> text')])
        ])).decode(),
        'diagram': host.encode(dict(schema_version=1, title='Actual native diagram', width=400, height=200,
                                    nodes=[], edges=[])).decode(),
        'animation': host.encode(dict(schema_version=1, width=320, height=180, background='#ffffff',
                                      frames_per_second=1, frame_count=2, sprites=[])).decode(),
        'collection': host.encode(dict(schema_version=1, kind='luma-explicit-collection-v1',
                                       collection_id='actual-native', name='Actual native source', members=[])).decode(),
    }
    binary = host.PinnedExecutable(Path(path))
    observations = []
    reopened = []
    refused = []
    try:
        def execute(value):
            value = host.request(value)
            command, payload = host.invocation(value)
            pids = []
            status, output = host.run_process(binary, command, payload, threading.Event(), pids.append)
            if status != 'completed' or len(pids) != 1:
                raise AssertionError('actual native CLI did not complete and reap')
            return host.validate_result(value, output)
        for engine, source in sources.items():
            result = execute(dict(schema_version=1, id='actual-' + engine, operation='preview', engine=engine, source=source))
            observations.append(engine)
            if engine in ('text', 'csv', 'json'):
                envelope = result['proposed']['canonical_envelope']
                verified = execute(dict(schema_version=1, id='reopen-' + engine, operation='reopen', source=envelope,
                                        expected_envelope_sha256=result['envelope_sha256']))
                if verified['validated']['canonical_envelope'] != envelope:
                    raise AssertionError('actual native reopen substituted selected bytes')
                reopened.append(engine)
            if engine == 'spreadsheet' and result['calculation']['canonical_csv'] != '"Quoted, field\nline",,2,6\n':
                raise AssertionError('actual native exact calculation differs')
            if engine == 'document' and '<script>' in result['rendering']['canonical_html']:
                raise AssertionError('actual native document failed to escape text')
        for engine in ('document', 'spreadsheet'):
            try:
                execute(dict(schema_version=1, id='invalid-' + engine, operation='preview', engine=engine,
                             source='{"schema_version":1,"unexpected_authority":true}'))
            except ValueError:
                refused.append(engine)
            else:
                raise AssertionError('actual native engine accepted malformed source')
        return dict(schema_version=1, status='manual-native-cli-fixture-passed',
                    actual_native_preview_engines=observations, actual_exact_reopen_formats=reopened,
                    actual_native_malformed_sources_refused=refused, native_executable_sha256=binary.sha256,
                    gtk_or_webkit_exercised=False, product_authority_qualified=False, **host.FLAGS)
    finally:
        binary.close()


if __name__ == '__main__':
    if sys.argv[1:] == ['--real-cli']:
        selected = os.environ.get('LUMA_WORKSPACE_TEST_CLI')
        if not selected:
            raise SystemExit('Explicit LUMA_WORKSPACE_TEST_CLI is required for --real-cli')
        print(json.dumps(real_cli_fixture(selected), sort_keys=True))
    else:
        unittest.main()
