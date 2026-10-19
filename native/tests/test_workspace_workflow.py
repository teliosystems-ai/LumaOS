"""Real terminal-controller behavior over explicitly inert native fixtures.

These tests cannot authorize PAM, custody or effects. Installed native original
sessions, loaded confinement, physical recovery and GTK remain qualification.
"""
import copy
import hashlib
import importlib.util
import io
import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('luma_workspace_workflow_auth', ROOT / 'native/desktop/workspace_auth.py')
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)
HOST_SPEC = importlib.util.spec_from_file_location('luma_workspace_workflow_host', ROOT / 'native/desktop/workspace_host.py')
host = importlib.util.module_from_spec(HOST_SPEC)
HOST_SPEC.loader.exec_module(host)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def scope(source, action='file.read', kind='file', identifier='native-content-inspect-v1', output=auth.MAX_QUERY_OUTPUT):
    return dict(action=action, selector=dict(kind=kind, id=identifier, generation=source['binding']['owner_generation'], digest='a'*64),
                input_bytes=auth.MAX_REQUEST, output_bytes=output, units=1)


def inspect(source, envelope=False):
    usage = scope(source, identifier='native-content-envelope-v1' if envelope else 'native-content-inspect-v1',
                  output=auth.MAX_ENVELOPE_OUTPUT if envelope else auth.MAX_QUERY_OUTPUT)
    return auth.encoded(dict(schema_version=1, inspection_usage=usage, query_only=envelope,
                             private_content_read=False, grant_issued=False, committed=False))


def fixture(decision='published'):
    source = dict(schema_version=1, login='alice', binding=dict(installation='1'*64, owner='2'*64, owner_generation=7),
        operation=dict(kind='workflow', request=dict(schema_version=1, request_id='workflow-one', artifact_id='document-one',
            expected=None, engine='document', source='{"schema_version":1,"title":"Exact source","blocks":[]}')))
    request = source['operation']['request']
    wrapper = json.dumps(dict(schema_version=1, engine='document', source=auth.strict_json(request['source'])), sort_keys=True, separators=(',', ':'))
    receipt = dict(schema_version=1, binding=source['binding'], artifact_id=request['artifact_id'], version=1,
        previous=None, format='json', media_type='application/json', content_sha256=digest(wrapper.encode()),
        content_bytes=len(wrapper.encode()), original_bytes=len(wrapper.encode()),
        provenance=dict(request_id='workflow-one', workflow_sha256='5'*64, source_sha256='6'*64, origin='managed'))
    reference = dict(artifact_id=receipt['artifact_id'], version=1, content_sha256=receipt['content_sha256'],
                     receipt_sha256=digest(auth.encoded(receipt)))
    if decision != 'published':
        request['expected'] = copy.deepcopy(reference)
        if decision == 'conflict-retained':
            request['expected']['receipt_sha256'] = '9'*64
    calculation = dict(engine='document', implementation='luma-static-document-v1', canonical_source_sha256=digest(request['source'].encode()),
                       output_sha256='b'*64, output_bytes=64, media_type='text/html; charset=utf-8')
    review = dict(schema_version=1, approval=('write:' if decision == 'published' else 'retain:')+'4'*64,
        review_sha256='4'*64, decision=decision, resulting=reference, derivation=calculation, source_bytes=1024,
        storage_bytes=16384, inspection_usage=scope(source), effect_usage=scope(source,
            action='artifact.write' if decision == 'published' else 'resource.retention', kind='artifact', identifier='native-content-store-v1'),
        committed=False, authority_returned=False, provenance_authority=False, workflow_executed=False)
    intent = dict(binding=source['binding'], artifact_id=request['artifact_id'], expected=request['expected'],
        metadata=dict(request_id=request['request_id'], workflow_sha256='5'*64), engine=request['engine'], source=request['source'])
    intent_sha = digest(auth.encoded(intent))
    sequence = 1 if decision == 'published' else 2
    outcome = dict(sequence=sequence, request_id=request['request_id'], review_sha256=review['review_sha256'], decision=decision,
        resulting=reference, source_sha256=intent_sha, source_kind='managed-render-intent', replayed=False)
    checkpoint = dict(schema_version=1, profile='native-content-engine-v1', workflow_sha256='5'*64, binding=source['binding'],
        request_id=request['request_id'], review_sha256=review['review_sha256'], original_intent_sha256=intent_sha,
        derivation=calculation, record_sha256='6'*64, protected_outcome=dict(binding=source['binding'], outcome_count=sequence,
            head_sha256='7'*64, quarantine_sha256='8'*64), outcome=outcome)
    completed = dict(schema_version=1, outcome=outcome, derivation=calculation, workflow_checkpoint=checkpoint,
        committed=True, authority_returned=False, provenance_authority=False, workflow_executed=True)
    value = dict(schema_version=1, operation='workflow-journey', login='alice', read_grant='', effect_grant='',
                 approval='', request=auth.encoded(source).decode())
    envelope = auth.encoded(dict(receipt=receipt, receipt_sha256=reference['receipt_sha256'], content=wrapper))
    return value, source, calculation, review, completed, envelope


def envelope_response(source, envelope):
    data = auth.strict_json(envelope)
    return auth.encoded(dict(schema_version=1, reference=source['operation']['expected'], format=data['receipt']['format'],
        envelope_bytes=len(envelope), envelope_sha256=digest(envelope), canonical_envelope=envelope.decode(), content_delivered=True,
        committed=False, authority_returned=False, provenance_authority=False, workflow_executed=False, production_qualified=False))


class WorkspaceWorkflowTests(unittest.TestCase):
    def test_closed_workflow_has_no_graph_receipt_grant_command_or_identity_defaults(self):
        value, source, *_ = fixture()
        self.assertEqual(auth.proposal(value), value)
        for field in ('workflow_sha256', 'completion', 'checkpoint', 'command', 'grant'):
            wrong = copy.deepcopy(source)
            wrong['operation']['request'][field] = 'untrusted'
            with self.assertRaises(ValueError):
                auth.workflow_request(wrong)
        for field, invalid in [('read_grant', 'prior-read'), ('effect_grant', 'prior-effect'), ('approval', 'write:'+'a'*64)]:
            with self.assertRaises(ValueError):
                auth.proposal(dict(value, **{field: invalid}))
        for field, invalid in [('schema_version', True), ('source', '[]'), ('source', 'a'*(1024*1024+1)),
                                ('expected', {}), ('engine', 'shell'), ('request_id', '')]:
            wrong = copy.deepcopy(source)
            wrong['operation']['request'][field] = invalid
            with self.assertRaises(ValueError):
                auth.workflow_request(wrong)
        with self.assertRaises(ValueError):
            auth.terminal_arguments(value, Path('/inert/request'))

    def test_review_requires_actual_engine_commitment_independent_finite_scopes_and_exact_decision(self):
        for decision in ('published', 'conflict-retained', 'no-change-retained'):
            _, source, calculation, review, *_ = fixture(decision)
            self.assertEqual(auth.reviewed_workflow(source, calculation, auth.encoded(review)), review)
        _, source, calculation, review, *_ = fixture()
        for field, invalid in [('approval', 'retain:'+'4'*64), ('decision', 'unknown'), ('committed', True),
                                ('workflow_executed', True), ('source_bytes', True), ('storage_bytes', 0), ('unknown', False)]:
            with self.assertRaises(ValueError):
                auth.reviewed_workflow(source, calculation, auth.encoded(dict(review, **{field: invalid})))
        for field in ('derivation', 'inspection_usage', 'effect_usage', 'resulting'):
            wrong = copy.deepcopy(review)
            if field == 'derivation':
                wrong[field]['output_sha256'] = 'f'*64
            elif field == 'resulting':
                wrong[field]['artifact_id'] = 'another-artifact'
            else:
                wrong[field]['selector']['generation'] += 1
            with self.assertRaises(ValueError):
                auth.reviewed_workflow(source, calculation, auth.encoded(wrong))

    def test_compact_completion_is_bound_to_source_owner_decision_review_and_exact_outcome(self):
        for decision in ('published', 'conflict-retained', 'no-change-retained'):
            _, source, _, review, completed, _ = fixture(decision)
            self.assertEqual(auth.completed_workflow(source, review, auth.encoded(completed)), completed)
        _, source, _, review, completed, _ = fixture()
        changes = [lambda v: v.update(workflow_executed=False), lambda v: v.update(committed=False),
            lambda v: v.update(authority_returned=True), lambda v: v.update(extra=False),
            lambda v: v['outcome'].update(request_id='different'), lambda v: v['outcome'].update(sequence=True),
            lambda v: v['outcome'].update(source_kind='content'), lambda v: v['outcome'].update(replayed=1),
            lambda v: v['workflow_checkpoint'].update(original_intent_sha256='f'*64),
            lambda v: v['workflow_checkpoint']['binding'].update(owner_generation=8),
            lambda v: v['workflow_checkpoint']['protected_outcome'].update(outcome_count=0),
            lambda v: v['workflow_checkpoint'].update(record_sha256='0'*64),
            lambda v: v['workflow_checkpoint'].update(profile='caller-workflow')]
        for mutate in changes:
            wrong = copy.deepcopy(completed)
            mutate(wrong)
            with self.assertRaises(ValueError):
                auth.completed_workflow(source, review, auth.encoded(wrong))
        duplicate = auth.encoded(completed).replace(b'"committed":true', b'"committed":true,"committed":true')
        with self.assertRaises(ValueError):
            auth.completed_workflow(source, review, duplicate)

    def test_whole_envelope_checks_all_bytes_reference_owner_and_no_authority_claim(self):
        _, source, _, _, completed, envelope = fixture()
        read = dict(source, operation=dict(kind='envelope', expected=completed['outcome']['resulting']))
        auth.envelope_request(read)
        output = envelope_response(read, envelope)
        self.assertEqual(auth.whole_envelope_response(read, output), envelope)
        self.assertEqual(auth.owner_inspection(inspect(read, True), read, envelope=True)['output_bytes'], 12615680)
        for field, invalid in [('envelope_bytes', True), ('envelope_bytes', auth.MAX_ENVELOPE+1),
                                ('envelope_sha256', 'f'*64), ('canonical_envelope', envelope.decode()+' '),
                                ('committed', True), ('workflow_executed', True), ('content_delivered', False), ('extra', 0)]:
            with self.assertRaises(ValueError):
                auth.whole_envelope_response(read, auth.encoded(dict(auth.strict_json(output), **{field: invalid})))
        with self.assertRaises(ValueError):
            auth.owner_inspection(inspect(read, True), read)

    def test_human_inputs_are_bounded_no_missing_selection_or_unbounded_source(self):
        with patch('sys.stdin', io.StringIO('q\n')), patch('sys.stdout', io.StringIO()):
            self.assertIsNone(auth.grant_selection('explicit grant: '))
        for text in ('x'*129+'\n', '', 'x'*40+'\n'):
            with patch('sys.stdin', io.StringIO(text)), patch('sys.stdout', io.StringIO()):
                with self.assertRaises((ValueError, EOFError)):
                    auth.terminal_line('bounded: ', maximum=32)
        with patch('sys.stdin', io.StringIO('{"schema_version":1}\nEND\n')), patch('sys.stdout', io.StringIO()):
            self.assertEqual(auth.revised_source(), '{"schema_version":1}\n')
        with patch('sys.stdin', io.StringIO('q\n')), patch('sys.stdout', io.StringIO()):
            self.assertIsNone(auth.revised_source())
        with patch('sys.stdin', io.StringIO('x'*(1024*1024+1))), patch('sys.stdout', io.StringIO()):
            with self.assertRaises(ValueError):
                auth.revised_source()

    def test_capture_routes_are_closed_and_separate_full_read_from_exact_workflow_effect(self):
        value, source, _, review, completed, _ = fixture()
        apply = dict(value, operation='apply', read_grant='apply-read', effect_grant='write-effect', approval=review['approval'])
        with patch.object(auth, '_capture_native', return_value=b'fixture data only') as transport:
            self.assertEqual(auth.capture_workflow(apply, Path('/exact/request')), b'fixture data only')
            self.assertEqual(transport.call_args.args[0][4], 'content-owned-apply')
            self.assertEqual(transport.call_args.args[1], auth.MAX_QUERY_OUTPUT)
        wrong = dict(apply, effect_grant=apply['read_grant'])
        with patch.object(auth, '_capture_native') as transport:
            with self.assertRaises(ValueError):
                auth.capture_workflow(wrong, Path('/exact/request'))
            transport.assert_not_called()
        read_source = dict(source, operation=dict(kind='envelope', expected=completed['outcome']['resulting']))
        read = dict(value, operation='review', read_grant='envelope-read', request=auth.encoded(read_source).decode())
        with patch.object(auth, '_capture_native', return_value=b'fixture data only') as transport:
            auth.capture_envelope(read, Path('/exact/request'))
            self.assertEqual(transport.call_args.args[0][4], 'content-owned-review')
            self.assertEqual(transport.call_args.args[1], 12615680)
        with patch.object(auth, '_capture_native') as transport:
            with self.assertRaises(ValueError):
                auth.capture_envelope(apply, Path('/exact/request'))
            transport.assert_not_called()

    def journey(self, choices, decision='published', apply_error=None, review_error=None, reopen=False, read_error=None, apply_result=None):
        value, source, calculation, review, completed, envelope = fixture(decision)
        queries = [inspect(source), auth.encoded(review) if review_error is None else review_error]
        captured = []
        def apply(value, path):
            captured.append((copy.deepcopy(value), Path(path).read_bytes()))
            if apply_error is not None:
                raise apply_error
            return auth.encoded(completed if apply_result is None else apply_result)
        with tempfile.TemporaryDirectory(prefix='luma-workflow-control-') as temporary:
            with patch.object(auth, 'canonical_native_request', side_effect=lambda value: (value['request'], host)), \
                 patch.object(auth, 'native_calculation', return_value=({}, calculation)), patch.object(auth, 'protected'), \
                 patch.object(auth, 'capture_query', side_effect=queries) as query, \
                 patch.object(auth, 'capture_workflow', side_effect=apply), \
                 patch.object(auth, 'terminal_line', side_effect=choices), \
                 patch.object(auth, 'envelope_read', side_effect=read_error, return_value=(dict(source, operation=dict(kind='envelope', expected=completed['outcome']['resulting'])),
                        dict(preview_content=auth.strict_json(envelope)['content'], preview_format='json'), host)) as read, \
                 patch.object(auth, 'recalculate_owner', return_value=(auth.strict_json(auth.strict_json(envelope)['content']), calculation)) as calculate, \
                 patch('sys.stdout', new_callable=io.StringIO) as output, patch('sys.stderr', new_callable=io.StringIO) as errors:
                status = auth.workflow_journey(value, Path(temporary))
            self.assertEqual(list(Path(temporary).iterdir()), [])
        self.assertEqual(read.call_count, 1 if reopen else 0)
        self.assertEqual(calculate.call_count, 1 if reopen and read_error is None else 0)
        return status, output.getvalue(), errors.getvalue(), captured, query.call_count

    def test_reachable_journey_reviews_approves_applies_and_reports_each_native_decision(self):
        for decision, label in [('published', 'Published:'), ('conflict-retained', 'Conflict retained:'), ('no-change-retained', 'No version change:')]:
            approval = ('write:' if decision == 'published' else 'retain:')+'4'*64
            status, output, errors, captured, calls = self.journey(['review-read', 'apply-read', 'effect', approval, 'q'], decision)
            self.assertEqual(status, 0)
            self.assertEqual(errors, '')
            self.assertEqual(calls, 2)
            self.assertEqual(len(captured), 1)
            self.assertEqual(captured[0][0]['approval'], approval)
            self.assertEqual(captured[0][0]['read_grant'], 'apply-read')
            self.assertEqual(captured[0][0]['effect_grant'], 'effect')
            self.assertIn(label, output)
            self.assertIn('workflow_checkpoint', output)

    def test_cancel_or_refused_approval_before_apply_never_calls_effect_or_reopen(self):
        for choices in [['q'], ['review-read', 'q'], ['review-read', 'apply-read', 'q'],
                        ['review-read', 'apply-read', 'effect', 'q']]:
            status, output, errors, captured, _ = self.journey(choices)
            self.assertEqual(status, 130)
            self.assertFalse(captured)
            self.assertIn('No effect requested', output)
            self.assertEqual(errors, '')
        status, _, errors, captured, _ = self.journey(['review-read', 'apply-read', 'effect', 'write:'+'f'*64])
        self.assertEqual(status, 1)
        self.assertFalse(captured)
        self.assertIn('before apply', errors)

    def test_revoked_review_or_uncertain_native_apply_is_not_fake_success_or_rollback(self):
        status, output, errors, captured, _ = self.journey(['review-read'], review_error=ValueError('revoked review'))
        self.assertEqual(status, 1)
        self.assertFalse(captured)
        self.assertNotIn('Published:', output)
        self.assertIn('before apply', errors)
        for failure, expected in [(ValueError('output incomplete after commit'), 1), (KeyboardInterrupt(), 130)]:
            status, output, errors, captured, _ = self.journey(['review-read', 'apply-read', 'effect', 'write:'+'4'*64], apply_error=failure)
            self.assertEqual(status, expected)
            self.assertEqual(len(captured), 1)
            self.assertNotIn('Published:', output)
            self.assertIn('UNCERTAIN', errors)
            self.assertNotIn('No effect requested', errors)

    def test_fresh_read_and_actual_recalculation_are_separate_from_observed_native_completion(self):
        status, output, errors, captured, _ = self.journey(['review-read', 'apply-read', 'effect', 'write:'+'4'*64, 'r', 'q'], reopen=True)
        self.assertEqual(status, 0)
        self.assertEqual(errors, '')
        self.assertEqual(len(captured), 1)
        self.assertIn('Published:', output)

    def test_later_read_refusal_does_not_erase_known_completion_or_trigger_another_effect(self):
        status, output, errors, captured, _ = self.journey(['review-read', 'apply-read', 'effect', 'write:'+'4'*64, 'r'],
            reopen=True, read_error=ValueError('current owner or Read revoked'))
        self.assertEqual(status, 1)
        self.assertEqual(len(captured), 1)
        self.assertIn('Published:', output)
        self.assertIn('completion was already observed', errors)
        self.assertNotIn('UNCERTAIN', errors)

    def test_malformed_apply_result_is_uncertain_but_cancellation_after_valid_completion_is_not(self):
        status, output, errors, captured, _ = self.journey(['review-read', 'apply-read', 'effect', 'write:'+'4'*64], apply_result={})
        self.assertEqual(status, 1)
        self.assertEqual(len(captured), 1)
        self.assertNotIn('Published:', output)
        self.assertIn('UNCERTAIN', errors)
        status, output, errors, captured, _ = self.journey(['review-read', 'apply-read', 'effect', 'write:'+'4'*64, KeyboardInterrupt()])
        self.assertEqual(status, 130)
        self.assertEqual(len(captured), 1)
        self.assertIn('Published:', output)
        self.assertIn('completion was already observed', errors)
        self.assertNotIn('UNCERTAIN', errors)

    def test_next_edit_requires_new_request_and_fresh_review_grants_without_auto_retry(self):
        value, source, calculation, review, completed, envelope = fixture()
        read_source = dict(source, operation=dict(kind='envelope', expected=completed['outcome']['resulting']))
        reopened = dict(preview_content=auth.strict_json(envelope)['content'], preview_format='json')
        canonicalized = []
        def canonical(current):
            canonicalized.append(copy.deepcopy(current))
            return current['request'], host
        with tempfile.TemporaryDirectory(prefix='luma-workflow-edit-') as temporary:
            with patch.object(auth, 'canonical_native_request', side_effect=canonical), \
                 patch.object(auth, 'native_calculation', return_value=({}, calculation)), patch.object(auth, 'protected'), \
                 patch.object(auth, 'capture_query', side_effect=[inspect(source), auth.encoded(review), inspect(source)]) as query, \
                 patch.object(auth, 'capture_workflow', return_value=auth.encoded(completed)) as apply, \
                 patch.object(auth, 'terminal_line', side_effect=['review-read', 'apply-read', 'effect', review['approval'], 'r', 'e', 'workflow-two', 'q']), \
                 patch.object(auth, 'envelope_read', return_value=(read_source, reopened, host)), \
                 patch.object(auth, 'recalculate_owner', return_value=(auth.strict_json(reopened['preview_content']), calculation)), \
                 patch.object(auth, 'revised_source', return_value='{"schema_version":1,"title":"Revised source","blocks":[]}'), \
                 patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(auth.workflow_journey(value, Path(temporary)), 130)
            self.assertEqual(apply.call_count, 1)
            self.assertEqual(query.call_count, 3)
            self.assertEqual(len(canonicalized), 2)
            next_request = auth.strict_json(canonicalized[1]['request'])['operation']['request']
            self.assertEqual(next_request['request_id'], 'workflow-two')
            self.assertEqual(next_request['expected'], completed['outcome']['resulting'])
            self.assertIn('Revised source', next_request['source'])
            self.assertEqual(canonicalized[1]['read_grant'], '')
            self.assertEqual(canonicalized[1]['effect_grant'], '')
            self.assertEqual(canonicalized[1]['approval'], '')
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_whole_read_uses_one_explicit_grant_then_genuine_reopen_not_a_supplied_receipt(self):
        value, source, _, _, completed, envelope = fixture()
        read_source = dict(source, operation=dict(kind='envelope', expected=completed['outcome']['resulting']))
        read = dict(value, operation='envelope-read', request=auth.encoded(read_source).decode())
        data = auth.strict_json(envelope)
        native = auth.encoded(dict(schema_version=1, result=dict(operation='reopen', validated=dict(receipt=data['receipt'],
            reference=completed['outcome']['resulting'], canonical_envelope=envelope.decode())), owner_authenticated=False,
            authority_returned=False, committed=False, certified=False, gate_closing=False))
        class Pin:
            def close(self):
                pass
        with tempfile.TemporaryDirectory(prefix='luma-workflow-read-') as temporary:
            with patch.object(auth, 'canonical_native_request', return_value=(read['request'], host)), \
                 patch.object(auth, 'protected'), patch.object(auth, 'capture_query', return_value=inspect(read_source, True)) as query, \
                 patch.object(auth, 'capture_envelope', return_value=envelope_response(read_source, envelope)) as captured, \
                 patch.object(auth, 'terminal_line', return_value='one-envelope-read') as selected, \
                 patch.object(host, 'PinnedExecutable', return_value=Pin()), \
                 patch.object(host, 'run_process', return_value=('completed', native)) as reopened, \
                 patch('sys.stdout', new_callable=io.StringIO):
                actual_source, actual_result, _ = auth.envelope_read(read, Path(temporary))
            self.assertEqual(actual_source, read_source)
            self.assertEqual(actual_result['preview_content'], data['content'])
            self.assertEqual(query.call_count, 1)
            self.assertEqual(selected.call_count, 1)
            self.assertEqual(captured.call_args.args[0]['read_grant'], 'one-envelope-read')
            self.assertEqual(reopened.call_args.args[1], 'content-contract-reopen')
            self.assertEqual(list(Path(temporary).iterdir()), [])


def real_cli_fixture(path):
    """Explicit extra lane: actual engines/reopen, no native owner authority.

    Only this test entry point redirects the fixed installed binary pin to the
    selected immutable build. Production never reads an executable override.
    """
    original_pin = host.PinnedExecutable
    cases = 0
    sources = {
        'spreadsheet': dict(schema_version=1, rows=[[dict(kind='number', value='2'),
            dict(kind='formula', expression=dict(op='binary', operator='multiply',
                left=dict(op='cell', row=0, column=0), right=dict(op='number', value='3')))]]),
        'document': dict(schema_version=1, title='Actual exact source', blocks=[
            dict(kind='paragraph', runs=[dict(kind='text', text='Unicode caf\u00e9 exact source')])]),
        'diagram': dict(schema_version=1, title='Actual diagram', width=320, height=180, nodes=[], edges=[]),
        'animation': dict(schema_version=1, width=320, height=180, background='#ffffff',
            frames_per_second=1, frame_count=2, sprites=[]),
    }
    with patch.object(host, 'PinnedExecutable', side_effect=lambda _installed: original_pin(path)):
        for engine, data in sources.items():
            result, derivation = auth.native_calculation(engine, host.encode(data).decode(), host)
            rendered = result['calculation' if engine == 'spreadsheet' else 'rendering']
            assert derivation['canonical_source_sha256'] == rendered['source_sha256']
            wrapper = host.encode(dict(schema_version=1, engine=engine, source=host.strict_json(rendered['canonical_source']))).decode()
            value = host.request(dict(schema_version=1, id='actual-wrapper-'+engine, operation='preview', engine='json', source=wrapper))
            command, payload = host.invocation(value)
            binary = original_pin(path)
            try:
                state, output = host.run_process(binary, command, payload, auth.threading.Event(), lambda _: None)
            finally:
                binary.close()
            assert state == 'completed' and output
            captured = host.validate_result(value, output)
            reopened = auth.native_reopen(captured['proposed']['canonical_envelope'].encode(), host)
            with patch('sys.stdout', io.StringIO()):
                actual_wrapper, recalculated = auth.recalculate_owner(reopened, host)
            assert auth.same_data(recalculated, derivation), engine
            assert actual_wrapper['engine'] == engine
            cases += 1
    print(json.dumps(dict(schema_version=1, actual_native_engine_reopen_recalculation_cases=cases,
        owner_authenticated=False, effects_executed=False, graphical_qualified=False, authority_returned=False)))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--native-cli':
        real_cli_fixture(Path(sys.argv[2]).resolve(strict=True))
    else:
        unittest.main()
