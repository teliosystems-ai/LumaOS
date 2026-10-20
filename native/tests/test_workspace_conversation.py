"""Native conversation DATA/control contracts, not synthetic PAM qualification.

The command/response fixtures test exact joins and refusal/cancellation; they
never claim installed inference, authorization, a model evaluation or a GUI run.
The subprocess test actually runs a bounded harmless private transport child.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


auth = load('luma_conversation_auth', 'native/desktop/workspace_auth.py')
app = load('luma_conversation_app', 'native/desktop/workspace_app.py')
draft = load('luma_conversation_manual_draft', 'native/desktop/workspace_draft.py')


def initial(prompt='Explain this without changing any files.', maximum=128):
    return app.conversation_proposal(auth, 'alice', prompt, maximum)


def review(messages, maximum=128):
    return dict(schema_version=1, usage=dict(action='inference.execute',
        selector=dict(kind='model', id='qwen3-4b-q4-k-m', generation=2**64-1, digest='1'*64),
        input_bytes=sum(len(item['content'].encode()) for item in messages), output_bytes=8192, units=maximum),
        worker=dict(lease_id='2'*32, generation=str(2**64-1), manager_epoch='3'*32),
        input_sha256=auth.conversation_digest(messages), authority_returned=False, gate_closing=False)


def completed(checked, grant='infer-first', text='Untrusted actual-pipe fixture text, not verified facts.'):
    output = dict(text=text, prompt_tokens='14', output_tokens='8')
    digest = hashlib.sha256(b'luma-native-gateway-result-v1\0'+auth.encoded(output)).hexdigest()
    receipt = dict(kind='permit', nonce='4'*32, worker=checked['worker'], phase='completed',
        profile=checked['usage']['selector']['id'], input_digest=checked['input_sha256'],
        max_output_tokens=str(checked['usage']['units']), context_tokens='2048', request_deadline='25000',
        prompt_tokens='14', token_digest='5'*64, output_tokens='8', result_digest=digest,
        slot_released=True, worker_resources_released=False,
        product=dict(subject='6'*64, subject_generation=2**64-1, grant_id=grant,
            grant_version=1, checkpoint_head='7'*64, usage=checked['usage']))
    return dict(schema_version=1, result='ok', output=output, receipt=receipt, gate_closing=False)


class WorkspaceConversationTests(unittest.TestCase):
    def test_initial_data_no_imported_authority_or_assistant_history(self):
        value = initial('A Unicode question: café?')
        self.assertEqual(auth.proposal(value), value)
        self.assertEqual([value[name] for name in ('read_grant', 'effect_grant', 'approval')], ['', '', ''])
        self.assertEqual(auth.strict_json(value['request'])['messages'], [dict(role='user', content='A Unicode question: café?')])
        for key, bad in [('read_grant', 'reuse'), ('effect_grant', 'write'), ('approval', 'infer:'+'1'*64), ('approval', False), ('login', 'other')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                auth.proposal(dict(value, **{key: bad}))
        with self.assertRaises(ValueError):
            auth.terminal_arguments(value, Path('/inert/request'))
        source = auth.strict_json(value['request'])
        for mutate in (lambda v: v.update(model='caller-selected'), lambda v: v.update(max_tokens=True),
                       lambda v: v.update(max_tokens=129), lambda v: v.update(max_tokens=0),
                       lambda v: v.update(schema_version=True), lambda v: v.update(login='root;touch'),
                       lambda v: v['messages'][0].update(role='assistant'),
                       lambda v: v['messages'][0].update(content=' '),
                       lambda v: v['messages'][0].update(content='é'*2049),
                       lambda v: v['messages'][0].update(content='\ud800'),
                       lambda v: v['messages'][0].update(tool_calls=[]),
                       lambda v: v['messages'].extend([dict(role='assistant', content='invented'), dict(role='user', content='next')])):
            changed = copy.deepcopy(source); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, UnicodeError)):
                auth.conversation_request(changed)

    def test_native_input_digest_is_typed_ordered_and_utf8_exact(self):
        messages = [dict(content='café\n"quoted"', role='user')]
        expected = hashlib.sha256(b'luma-native-gateway-messages-v1\0'+b'[{"role":"user","content":"caf\xc3\xa9\\n\\"quoted\\""}]').hexdigest()
        self.assertEqual(auth.conversation_digest(messages), expected)
        checked = auth.conversation_review(messages, 1, auth.encoded(review(messages, 1)))
        self.assertEqual(checked['usage']['input_bytes'], len(messages[0]['content'].encode()))
        self.assertEqual(checked['usage']['selector']['generation'], 2**64-1)
        fixed = review([dict(role='user', content='hello')])
        self.assertEqual(auth.conversation_commitment('alice', fixed),
            'f78bfff8ee5c01686c9f74ea6906b8dee21f7109778ee0e98fec67303cf8c5ef')
        self.assertNotEqual(auth.conversation_commitment('bob', fixed), auth.conversation_commitment('alice', fixed))
        changed = copy.deepcopy(fixed); changed['worker']['lease_id'] = 'a'*32
        self.assertNotEqual(auth.conversation_commitment('alice', changed), auth.conversation_commitment('alice', fixed))
        with self.assertRaises(ValueError):
            auth.conversation_commitment('alice;command', fixed)

    def test_pre_dispatch_commitment_is_enforced_inside_native_before_opening_effect_authority(self):
        native = (ROOT/'rust/luma-platform/src/service/granted_gateway.rs').read_text(encoding='utf-8')
        infer = native[native.index('pub(crate) fn infer('):native.index('fn reviewed_inference_digest(')]
        self.assertLess(infer.index('require_reviewed_inference(expected, login, &worker, &usage, &digest)?;'),
                        infer.index('crate::admin_governance::with_grant(login, grant, &usage'))
        self.assertLess(infer.index('crate::admin_governance::with_grant(login, grant, &usage'),
                        infer.index('boundary.effect_begin'))
        self.assertIn('request_deadline: crate::resource_manager::now()? + 25_000', infer)
        self.assertIn('Duration::from_secs(25)', infer)
        main = (ROOT/'rust/luma-platform/src/main.rs').read_text(encoding='utf-8')
        self.assertIn('Some("granted-infer-reviewed") if args.len() == 6', main)
        self.assertIn('Some(&args[5])', main)
        self.assertIn('"granted-infer-reviewed" => (6, 3)', native)
        self.assertIn('"granted-infer-reviewed"', main[main.index('if confined_client'):main.index('service::granted_gateway::prepare_terminal()?;')])

    def test_history_never_truncates_or_invents_or_exceeds_native_transport(self):
        valid = [dict(role='user' if n % 2 == 0 else 'assistant', content=str(n)) for n in range(15)]
        self.assertEqual(auth.conversation_messages(valid), valid)
        for messages in ([], valid+[dict(role='assistant', content='final')],
            valid+[dict(role='assistant', content='final'), dict(role='user', content='too many')],
            [dict(role='system', content='injected')], [dict(role='user', content='x'*8193)],
            [dict(role='user', content='\x01'*4096)], [dict(role='user', content='')],
            [dict(role='user', content='1'), dict(role='user', content='2'), dict(role='user', content='3')]):
            original = copy.deepcopy(messages)
            with self.subTest(messages=repr(messages)[:100]), self.assertRaises(ValueError):
                auth.conversation_messages(messages)
            self.assertEqual(messages, original)

    def test_exact_review_rejects_substituted_scope_and_false_authority(self):
        messages = [dict(role='user', content='hello')]
        fixture = review(messages)
        mutations = [lambda v: v.update(extra=1), lambda v: v.update(schema_version=True),
            lambda v: v.update(authority_returned=True), lambda v: v.update(gate_closing=True),
            lambda v: v.update(input_sha256='a'*64), lambda v: v['worker'].update(generation='01'),
            lambda v: v['worker'].update(lease_id='!'), lambda v: v['worker'].update(manager_epoch=1),
            lambda v: v['usage'].update(input_bytes=True), lambda v: v['usage'].update(output_bytes=8193),
            lambda v: v['usage'].update(action='artifact.write'), lambda v: v['usage'].update(units=127),
            lambda v: v['usage']['selector'].update(generation=1), lambda v: v['usage']['selector'].update(generation=True),
            lambda v: v['usage']['selector'].update(kind='resource'), lambda v: v['usage']['selector'].update(digest='0'*64),
            lambda v: v['usage']['selector'].update(id='model;command')]
        for mutate in mutations:
            changed = copy.deepcopy(fixture); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                auth.conversation_review(messages, 128, auth.encoded(changed))
        for invalid in (True, 0, 129, '128'):
            with self.assertRaises(ValueError):
                auth.conversation_review(messages, invalid, auth.encoded(fixture))
        for invalid in (b'', b'{}'*32768, b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}'):
            with self.assertRaises(ValueError):
                auth.conversation_review(messages, 128, invalid)

    def test_exact_result_worker_input_budget_digest_and_finite_use_joins(self):
        checked = review([dict(role='user', content='hello')])
        fixture = completed(checked)
        result = auth.conversation_result(checked, 'infer-first', auth.encoded(fixture))
        self.assertEqual(result, fixture['output'])
        self.assertNotIn('receipt', result)
        for mutate in (lambda v: v.update(extra=1), lambda v: v.update(gate_closing=True),
            lambda v: v['output'].update(text='forged'), lambda v: v['output'].update(prompt_tokens='2049'),
            lambda v: v['output'].update(output_tokens='129'), lambda v: v['output'].update(prompt_tokens=14),
            lambda v: v['receipt'].update(slot_released=False), lambda v: v['receipt'].update(worker_resources_released=True),
            lambda v: v['receipt'].update(profile='other'), lambda v: v['receipt'].update(input_digest='a'*64),
            lambda v: v['receipt']['worker'].update(generation='1'), lambda v: v['receipt'].update(max_output_tokens='127'),
            lambda v: v['receipt'].update(context_tokens='4096'), lambda v: v['receipt'].update(request_deadline='01'),
            lambda v: v['receipt'].update(result_digest='a'*64), lambda v: v['receipt'].update(token_digest='0'*64),
            lambda v: v['receipt']['product'].update(grant_id='wrong'), lambda v: v['receipt']['product'].update(subject_generation=True),
            lambda v: v['receipt']['product'].update(grant_version=2), lambda v: v['receipt']['product']['usage'].update(units=1),
            lambda v: v['receipt']['product'].update(operation_id='not-a-native-operation'),
            lambda v: v['receipt']['product'].update(checkpoint_head='0'*64)):
            changed = copy.deepcopy(fixture); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                auth.conversation_result(checked, 'infer-first', auth.encoded(changed))
        extended = copy.deepcopy(fixture)
        extended['receipt']['product']['operation_id'] = 'a'*32
        self.assertEqual(auth.conversation_result(checked, 'infer-first', auth.encoded(extended)), fixture['output'])

    def test_closed_command_builder_uses_only_original_native_client(self):
        path = Path('/inert/exact-input.json')
        with patch.object(auth, 'protected') as protected, patch.object(auth, '_capture_native', return_value=b'fixture') as capture:
            self.assertEqual(auth.conversation_capture('review', path, 128), b'fixture')
            self.assertEqual(capture.call_args.args[0], ['/usr/bin/sudo', '--', auth.NATIVE, 'granted-run', 'granted-infer-review', str(path), '128'])
            auth.conversation_capture('infer', path, 4, 'alice', 'fresh-grant', 'a'*64)
            self.assertEqual(capture.call_args.args[0], ['/usr/bin/sudo', '--', auth.NATIVE, 'granted-run', 'granted-infer-reviewed', 'alice', 'fresh-grant', str(path), '4', 'a'*64])
            self.assertEqual(protected.call_count, 2)
            for args in [('model-chat', path, 128), ('review', path, 128, 'alice', 'grant'),
                         ('infer', path, 128, 'alice', 'grant;touch', 'a'*64), ('infer', path, 128, 'alice;touch', 'grant', 'a'*64),
                         ('infer', path, True, 'alice', 'grant', 'a'*64), ('infer', path, 129, 'alice', 'grant', 'a'*64),
                         ('infer', path, 128, 'alice', 'grant'), ('infer', path, 128, 'alice', 'grant', '0'*64)]:
                with self.assertRaises(ValueError):
                    auth.conversation_capture(*args)
            self.assertEqual(capture.call_count, 2)

    def test_two_turn_journey_uses_actual_returned_text_and_new_explicit_grants(self):
        calls = []
        replies = ['First reply\x1b[2J with \"quotes\".', 'Second reply']
        def capture(command, path, maximum, login=None, grant=None, review_sha256=None):
            messages = auth.strict_json(path.read_bytes())
            calls.append((command, copy.deepcopy(messages), login, grant))
            checked = review(messages, maximum)
            if command == 'infer':
                self.assertEqual(review_sha256, auth.conversation_commitment(login, checked))
            return auth.encoded(checked if command == 'review' else completed(checked, grant, replies[len(calls)//2-1]))
        value = initial('First question')
        first_messages = auth.strict_json(value['request'])['messages']
        second_messages = first_messages+[dict(role='assistant', content=replies[0]), dict(role='user', content='Follow-up')]
        controls = ['infer:'+auth.conversation_commitment('alice', review(first_messages)), 'n', 'Follow-up',
                    'infer:'+auth.conversation_commitment('alice', review(second_messages)), 'q']
        with tempfile.TemporaryDirectory(prefix='luma-conversation-', dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as directory, \
             patch.object(auth, 'conversation_capture', side_effect=capture), \
             patch.object(auth, 'grant_selection', side_effect=['infer-one', 'infer-two']) as grants, \
             patch.object(auth, 'terminal_line', side_effect=controls), \
             patch.object(auth, 'workflow_journey') as effect, patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(auth.conversation_journey(value, Path(directory)), 0)
            self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertEqual(grants.call_count, 2)
            effect.assert_not_called()
            self.assertNotIn('\x1b', output.getvalue())
            self.assertIn('\\u001b', output.getvalue())
        self.assertEqual([item[0] for item in calls], ['review', 'infer', 'review', 'infer'])
        self.assertEqual(calls[2][1], second_messages)
        self.assertEqual([calls[1][3], calls[3][3]], ['infer-one', 'infer-two'])
        self.assertEqual([calls[1][2], calls[3][2]], ['alice', 'alice'])

    def test_cancellation_before_grant_or_approval_does_not_submit_inference(self):
        value = initial()
        checked = review(auth.strict_json(value['request'])['messages'])
        for grant, controls in [(None, []), ('fresh', ['q']), ('fresh', ['infer:'+'0'*64])]:
            with tempfile.TemporaryDirectory(prefix='luma-conversation-', dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as directory, \
                 patch.object(auth, 'conversation_capture', return_value=auth.encoded(checked)) as capture, \
                 patch.object(auth, 'grant_selection', return_value=grant), \
                 patch.object(auth, 'terminal_line', side_effect=controls), patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(auth.conversation_journey(value, Path(directory)), 0)
                self.assertEqual([call.args[0] for call in capture.call_args_list], ['review'])
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_unavailable_model_keeps_manual_controls_no_smoke_fallback(self):
        with tempfile.TemporaryDirectory(prefix='luma-conversation-', dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as directory, \
             patch.object(auth, 'conversation_capture', side_effect=ValueError('not ready')) as capture, \
             patch.object(auth, 'grant_selection') as grant, patch.object(auth, 'terminal_line', return_value='m'), \
             patch('sys.stdout', new_callable=io.StringIO) as output, patch('sys.stderr', new_callable=io.StringIO) as errors:
            self.assertEqual(auth.conversation_journey(initial(), Path(directory)), 0)
            self.assertEqual(capture.call_count, 1)
            grant.assert_not_called()
            self.assertIn('Manual controls remain available', output.getvalue())
            self.assertIn('No inference submitted', errors.getvalue())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_manual_handoff_requires_every_exact_field_and_new_native_workflow_authority(self):
        binding = dict(installation='1'*64, owner='2'*64, owner_generation=2**64-1)
        controls = [json.dumps(binding), 'document.new', 'manual.request.1', 'null', 'document']
        with patch.object(auth, 'draft_controller', return_value=draft), patch.object(auth, 'terminal_line', side_effect=controls), \
             patch.object(auth, 'revised_source', return_value='{"manual":"explicit human source, not a model reply"}'), \
             patch.object(auth, 'workflow_journey', return_value=0) as workflow, patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(auth.conversation_manual_workflow('alice', Path('/inert/private')), 0)
            value, directory = workflow.call_args.args
            self.assertEqual(directory, Path('/inert/private'))
            self.assertEqual(value['operation'], 'workflow-journey')
            self.assertEqual([value[key] for key in ('read_grant', 'effect_grant', 'approval')], ['', '', ''])
            source = auth.strict_json(value['request'])
            self.assertEqual(source['login'], 'alice')
            self.assertEqual(source['binding'], binding)
            self.assertIsNone(source['operation']['request']['expected'])
            self.assertEqual(source['operation']['request']['request_id'], 'manual.request.1')
            self.assertIn('explicit human source', source['operation']['request']['source'])
        with patch.object(auth, 'draft_controller', return_value=draft), patch.object(auth, 'terminal_line', return_value='q'), patch.object(auth, 'revised_source') as source, \
             patch.object(auth, 'workflow_journey') as workflow, patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(auth.conversation_manual_workflow('alice', Path('/inert/private')), 0)
            workflow.assert_not_called()
            source.assert_not_called()

    def test_native_capture_entry_is_independent_singleton_and_destroyed_before_shell_exit(self):
        source = (ROOT/'native/desktop/workspace_app.py').read_text(encoding='utf-8')
        capture = source[source.index('    def permission_capture('):source.index("    capture_button.connect(")]
        self.assertIn('if capture_windows:', capture)
        self.assertIn('capture_windows[0].present()', capture)
        self.assertIn('protected_file(path, 128*1024)', capture)
        self.assertIn('capture_module.launch_capture(window)', capture)
        self.assertNotIn('on_complete=', capture)
        self.assertNotIn('deliver(', capture)
        self.assertNotIn('conversation_journey(', capture)
        close = source[source.index('    def close(*_):'):]
        self.assertLess(close.index('capture_window.destroy()'), close.index('Gtk.main_quit()'))

    def test_submitted_uncertain_result_is_fenced_without_automatic_retry(self):
        value = initial()
        messages = auth.strict_json(value['request'])['messages']
        checked = review(messages)
        for error, expected in [(ValueError('lost'), 1), (KeyboardInterrupt(), 130)]:
            with tempfile.TemporaryDirectory(prefix='luma-conversation-', dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as directory, \
                 patch.object(auth, 'conversation_capture', side_effect=[auth.encoded(checked), error]) as capture, \
                 patch.object(auth, 'grant_selection', return_value='fresh'), \
                 patch.object(auth, 'terminal_line', return_value='infer:'+auth.conversation_commitment('alice', checked)) as controls, \
                 patch('sys.stdout', new_callable=io.StringIO), patch('sys.stderr', new_callable=io.StringIO) as errors:
                self.assertEqual(auth.conversation_journey(value, Path(directory)), expected)
                self.assertEqual(capture.call_count, 2)
                self.assertEqual(controls.call_count, 1)
                self.assertIn('UNCERTAIN', errors.getvalue())
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_explicit_clear_discards_history_and_final_turn_never_solicits_an_unusable_followup(self):
        submitted = []
        turns = 0
        def capture(command, path, maximum, login=None, grant=None, review_sha256=None):
            nonlocal turns
            messages = auth.strict_json(path.read_bytes())
            checked = review(messages, maximum)
            if command == 'review':
                return auth.encoded(checked)
            submitted.append(copy.deepcopy(messages))
            turns += 1
            return auth.encoded(completed(checked, grant, 'Observed reply '+str(turns)))
        controls = []
        for index in range(8):
            prompt = 'Prompt '+str(index)
            controls.append('infer:'+auth.conversation_commitment('alice', review([dict(role='user', content=prompt)])))
            if index != 7:
                controls.extend(['c', 'Prompt '+str(index+1)])
        controls.append('q')
        with tempfile.TemporaryDirectory(prefix='luma-conversation-', dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as directory, \
             patch.object(auth, 'conversation_capture', side_effect=capture), \
             patch.object(auth, 'grant_selection', side_effect=['fresh-'+str(index) for index in range(8)]) as grants, \
             patch.object(auth, 'terminal_line', side_effect=controls) as control, patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(auth.conversation_journey(initial('Prompt 0'), Path(directory)), 0)
            self.assertEqual(grants.call_count, 8)
            self.assertEqual(control.call_count, 23)
            self.assertIn('fixed eight-turn limit', output.getvalue())
            self.assertEqual(list(Path(directory).iterdir()), [])
        self.assertEqual(submitted, [[dict(role='user', content='Prompt '+str(index))] for index in range(8)])

    def test_native_transport_actually_bounds_and_reaps_harmless_child(self):
        self.assertEqual(auth._capture_native([sys.executable, '-I', '-c', 'print("bounded-fixture")'], auth.MAX_QUERY_OUTPUT, 2), b'bounded-fixture\r\n' if os.name == 'nt' else b'bounded-fixture\n')
        with self.assertRaises(ValueError):
            auth._capture_native([sys.executable, '-I', '-c', 'print("x"*65536)'], auth.MAX_QUERY_OUTPUT, 2)
        with self.assertRaises(ValueError):
            auth._capture_native([sys.executable, '-I', '-c', 'import time,signal,sys;signal.signal(signal.SIGINT,lambda *_:sys.exit(0));time.sleep(2)'], auth.MAX_QUERY_OUTPUT, .15)


if __name__ == '__main__':
    unittest.main()
