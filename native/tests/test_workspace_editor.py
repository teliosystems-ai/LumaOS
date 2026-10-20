"""Ordered software transports, not installed PAM/C/TPM/editor qualification."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


auth = load('editor_test_auth', 'native/desktop/workspace_auth.py')
editor = load('editor_test_controller', 'native/desktop/workspace_editor.py')
host = load('editor_test_host', 'native/desktop/workspace_host.py')
host_tests = load('editor_test_host_fixtures', 'native/tests/test_workspace_host.py')


def reference():
    return dict(artifact_id='checkpoint.one', version=3, content_sha256='a'*64, receipt_sha256='b'*64)


def initial(resume=False):
    binding = dict(installation='1'*64, owner='2'*64, owner_generation=2**64-1)
    return dict(schema_version=1, login='alice', start=dict(schema_version=1, binding=binding,
        session_id='3'*32, checkpoint_artifact_id='checkpoint.one',
        document=dict(schema_version=1, title='Human seed', blocks=[dict(kind='paragraph', runs=[dict(kind='text', text='Exact seed')])]),
        resume=reference() if resume else None))


def proposal(source):
    return dict(schema_version=1, operation='editor-journey', login=source['login'], read_grant='',
        effect_grant='', approval='', request=auth.encoded(source).decode())


def usage(source, *, resume=False, effect=False):
    return dict(action='artifact.write' if effect else 'file.read', selector=dict(kind='artifact' if effect else 'file',
        id='native-content-store-v1' if effect else 'native-content-envelope-v1' if resume else 'native-content-inspect-v1',
        generation=source['start']['binding']['owner_generation'], digest='4'*64),
        input_bytes=auth.MAX_REQUEST, output_bytes=auth.MAX_QUERY_OUTPUT, units=1)


def reviewed(source):
    return dict(schema_version=1, start_usage=dict(action='worker.start', selector=dict(kind='worker',
        id='native-editor-session-v1', generation=1, digest='5'*64),
        input_bytes=(32768+4)*65, output_bytes=(65536+4)*65, units=64),
        checkpoint_read_usage=usage(source, resume=True) if source['start']['resume'] is not None else None,
        request=copy.deepcopy(source['start']), authority_returned=False, saved=False)


def frozen(source):
    document = copy.deepcopy(source['start']['document']); document['title'] = 'Actually edited title'
    checkpoint = dict(schema_version=1, profile='luma-editor-document-v1', binding=source['start']['binding'],
        document=document, source_sha256=hashlib.sha256(auth.encoded(document)).hexdigest(),
        previous_checkpoint=source['start']['resume'])
    return dict(schema_version=1, request_sha256=hashlib.sha256(auth.encoded(source['start'])).hexdigest(),
        binding='5'*64, lease=dict(lease_id='6'*32, generation='18446744073709551615', manager_epoch='7'*32),
        checkpoint=checkpoint, saved=False)


def checkpoint(source, result):
    content = json.dumps(result['checkpoint'], sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    operation = dict(kind='capture', artifact_id='checkpoint.one', format='json', content=content,
        provenance=dict(request_id='checkpoint.request.1', workflow_sha256='8'*64,
            source_sha256=hashlib.sha256(content.encode()).hexdigest(), origin='external'))
    if source['start']['resume'] is not None:
        operation = dict(kind='external', artifact_id='checkpoint.one', expected=source['start']['resume'],
            content=content, provenance=operation['provenance'])
    return dict(schema_version=1, login='alice', binding=source['start']['binding'], operation=operation)


def save_outputs(source, native, decision='published'):
    resulting = dict(artifact_id='checkpoint.one', version=1 if source['start']['resume'] is None else 4,
        content_sha256=hashlib.sha256(native['operation']['content'].encode()).hexdigest(), receipt_sha256='9'*64)
    expected = source['start']['resume']
    if decision == 'no-change-retained':
        resulting = copy.deepcopy(expected)
    inspected = dict(schema_version=1, inspection_usage=usage(source), query_only=False,
        private_content_read=False, grant_issued=False, committed=False)
    effect = usage(source, effect=True)
    if decision != 'published':
        effect['action'] = 'resource.retention'
    review = dict(schema_version=1, approval=('write:' if decision == 'published' else 'retain:')+'a'*64,
        review_sha256='a'*64, decision=decision, resulting=resulting, derivation=None,
        source_bytes=len(native['operation']['content'].encode()), storage_bytes=16384,
        inspection_usage=usage(source), effect_usage=effect, committed=False, authority_returned=False,
        provenance_authority=False, workflow_executed=False)
    complete = dict(schema_version=1, outcome=dict(sequence=5, request_id='checkpoint.request.1', review_sha256='a'*64,
        decision=decision, resulting=resulting, source_sha256=hashlib.sha256(native['operation']['content'].encode()).hexdigest(),
        source_kind='content', replayed=False), derivation=None, committed=True, authority_returned=False,
        provenance_authority=False, workflow_executed=False)
    return inspected, review, complete


class EditorTests(unittest.TestCase):
    def test_closed_journey_no_carried_grants_and_no_direct_effect_route(self):
        source = initial(); original = copy.deepcopy(source)
        self.assertEqual(editor.request(auth, source), original)
        with patch.object(auth, 'workspace_controller', return_value=editor):
            self.assertEqual(auth.proposal(proposal(source)), proposal(source))
            with self.assertRaises(ValueError): auth.terminal_arguments(proposal(source), Path('/inert'))
            for field in ('read_grant', 'effect_grant', 'approval'):
                with self.subTest(field=field), self.assertRaises(ValueError):
                    auth.proposal(dict(proposal(source), **{field: 'old-grant'}))

    def test_initial_source_rejects_unknown_latest_alias_bool_bounds(self):
        for field, changed in [('schema_version', True), ('session_id', '0'*32), ('session_id', 'A'*32),
                ('checkpoint_artifact_id', '../checkpoint'), ('resume', 'latest'),
                ('resume', dict(reference(), artifact_id='other')), ('document', dict(schema_version=1, title='a', blocks='code'))]:
            source = initial(); source['start'][field] = changed
            with self.subTest(field=field, changed=changed), self.assertRaises((ValueError, TypeError)):
                editor.request(auth, source)
        source = initial(); source['start']['duration_seconds'] = 300
        with self.assertRaises(ValueError): editor.request(auth, source)

    def test_all_native_document_variants_preserve_exact_typed_order_and_unicode(self):
        value = dict(blocks=[dict(text='é e\u0301', level=2, kind='heading'),
            dict(runs=[dict(kind=kind, text='literal') for kind in ('text', 'strong', 'emphasis', 'code')]+[dict(kind='line-break')], kind='paragraph'),
            dict(items=[[dict(text='item', kind='text')]], ordered=False, kind='list'),
            dict(rows=[['value']], header=['column'], kind='table'), dict(text='no execution', kind='code'), dict(kind='rule')],
            title='Exact', schema_version=1)
        ordered = editor.document(auth, value)
        self.assertEqual(list(ordered), ['schema_version', 'title', 'blocks'])
        self.assertEqual(list(ordered['blocks'][0]), ['kind', 'level', 'text'])
        self.assertEqual(list(ordered['blocks'][1]['runs'][0]), ['kind', 'text'])
        self.assertTrue(auth.same_data(ordered, value))
        for invalid in [dict(value, title='x'*257), dict(value, blocks=[dict(kind='heading', level=True, text='x')]),
                dict(value, blocks=[dict(kind='table', header=['a'], rows=[['x', 'y']])]),
                dict(value, blocks=[dict(kind='paragraph', runs=[dict(kind='link', url='https://external')])]),
                dict(value, blocks=[dict(kind='code', text='\x1bterminal')]),
                dict(value, blocks=[dict(kind='code', text='x'*4096)]*5)]:
            with self.assertRaises(ValueError): editor.document(auth, invalid)

    def test_fixed_review_and_run_routes_no_arbitrary_command_or_borrowed_read(self):
        with patch.object(auth, '_capture_native', return_value=b'observed') as transport, patch.object(auth, 'protected'):
            self.assertEqual(editor.capture(auth, initial(), 'editor-review', Path('/inert')), b'observed')
            editor.capture(auth, initial(), 'editor-run', Path('/inert'), 'start', 'none')
            self.assertEqual(transport.call_args.args[0][4:], ['editor-run', 'alice', 'start', 'none', '/inert'])
            for args in [('content-owned-apply', None, None), ('editor-run', 'start', 'borrowed'), ('editor-review', 'start', None)]:
                with self.assertRaises(ValueError): editor.capture(auth, initial(), args[0], Path('/inert'), args[1], args[2])
            with self.assertRaises(ValueError): editor.capture(auth, initial(True), 'editor-run', Path('/inert'), 'same', 'same')

    def test_review_exact_source_finite_limits_and_resume_scope(self):
        for resumed in (False, True):
            source = initial(resumed); value = reviewed(source)
            self.assertEqual(editor.review(auth, source, auth.encoded(value)), value)
            for key, changed in [('authority_returned', True), ('saved', True), ('checkpoint_read_usage', None if resumed else usage(source)),
                    ('request', dict(source['start'], session_id='f'*32))]:
                with self.subTest(key=key), self.assertRaises(ValueError): editor.review(auth, source, auth.encoded(dict(value, **{key: changed})))
            for key in ('input_bytes', 'output_bytes', 'units'):
                bad = copy.deepcopy(value); bad['start_usage'][key] += 1
                with self.assertRaises(ValueError): editor.review(auth, source, auth.encoded(bad))

    def test_frozen_is_never_saved_and_is_bound_to_exact_start_source_base_and_lease(self):
        source = initial(True); value = frozen(source)
        self.assertEqual(editor.frozen(auth, source, auth.encoded(source['start']).decode(), reviewed(source), auth.encoded(value)), value)
        variants = [dict(value, saved=True), dict(value, request_sha256='b'*64), dict(value, binding='a'*64),
            dict(value, lease=dict(value['lease'], generation=1)), dict(value, renewed=True)]
        for field, changed in [('source_sha256', 'c'*64), ('previous_checkpoint', None), ('binding', dict(source['start']['binding'], owner='4'*64)),
                ('document', dict(value['checkpoint']['document'], title='substituted'))]:
            variants.append(dict(value, checkpoint=dict(value['checkpoint'], **{field: changed})))
        for bad in variants:
            with self.assertRaises(ValueError): editor.frozen(auth, source, auth.encoded(source['start']).decode(), reviewed(source), auth.encoded(bad))

    def test_checkpoint_canonical_data_never_substitutes_source_base_or_origin(self):
        for resumed in (False, True):
            source = initial(resumed); result = frozen(source); native = checkpoint(source, result)
            self.assertEqual(editor.checkpoint_input(auth, source, result, 'checkpoint.request.1', native), native)
            for change in (dict(kind='workflow'), dict(artifact_id='other'), dict(content='{}'),
                    dict(provenance=dict(native['operation']['provenance'], origin='managed'))):
                bad = copy.deepcopy(native); bad['operation'].update(change)
                with self.assertRaises(ValueError): editor.checkpoint_input(auth, source, result, 'checkpoint.request.1', bad)

    def test_pure_canonicalizer_has_closed_false_flags_exact_hash_and_source(self):
        source = initial()['start']; exact = auth.encoded(source).decode()
        reply = dict(schema_version=1, canonical_request=exact, request_sha256=hashlib.sha256(exact.encode()).hexdigest(),
            authority_returned=False, session_lease_held=False, saved=False)
        fake = types.SimpleNamespace(PinnedExecutable=lambda _path: types.SimpleNamespace(close=lambda: None),
            run_process=lambda *_args, **_kwargs: ('completed', auth.encoded(reply)))
        self.assertEqual(editor.canonical(auth, fake, 'editor-request', source), exact)
        for key, changed in [('saved', True), ('authority_returned', True), ('session_lease_held', True), ('request_sha256', 'b'*64)]:
            bad = dict(reply, **{key: changed}); fake.run_process = lambda *_a, **_k: ('completed', auth.encoded(bad))
            with self.assertRaises(ValueError): editor.canonical(auth, fake, 'editor-request', source)
        with self.assertRaises(ValueError): editor.canonical(auth, fake, 'editor-run', source)

    def test_save_review_completion_and_effect_transport_are_exact_and_not_readonly(self):
        source = initial(); result = frozen(source); native = checkpoint(source, result)
        _inspection, review, complete = save_outputs(source, native)
        self.assertEqual(editor.save_review(auth, native, auth.encoded(review)), review)
        self.assertEqual(editor.save_completed(auth, native, review, auth.encoded(complete)), complete)
        for changed in (dict(source_bytes=1), dict(approval='retain:'+'a'*64), dict(resulting=dict(review['resulting'], artifact_id='other'))):
            with self.assertRaises(ValueError): editor.save_review(auth, native, auth.encoded(dict(review, **changed)))
        value = dict(proposal(source), operation='apply', read_grant='read', effect_grant='write', approval=review['approval'], request=auth.encoded(native).decode())
        with patch.object(auth, '_capture_native', return_value=b'observed') as captured, patch.object(auth, 'protected'):
            with self.assertRaises(ValueError): auth.capture_query(auth.terminal_arguments(value, Path('/inert')))
            captured.assert_not_called()
            editor.capture_save(auth, value, Path('/inert'))
            self.assertEqual(captured.call_args.args[0][4], 'content-owned-apply')
            for bad in (dict(value, read_grant='write'), dict(value, approval='trash:'+'a'*64), dict(value, request=auth.encoded(dict(native, operation=dict(kind='capture'))).decode())):
                with self.assertRaises(ValueError): editor.capture_save(auth, bad, Path('/inert'))

    def run_journey(self, *, resumed=False, save=False, controls=None, grants=None, bad_frozen=None, bad_reopen=False):
        source = initial(resumed); result = frozen(source); native = checkpoint(source, result)
        inspected, review, complete = save_outputs(source, native)
        frames = [auth.encoded(reviewed(source)), bad_frozen or auth.encoded(result)]
        if save:
            frames += [auth.encoded(inspected), auth.encoded(review), auth.encoded(complete)]
        calls = []
        def transport(arguments, maximum, timeout=40):
            calls.append((arguments, maximum, timeout))
            return frames.pop(0)
        def canonical(_auth, _host, command, payload):
            return auth.encoded(source['start']).decode() if command == 'editor-request' else auth.encoded(native).decode()
        read_source = dict(schema_version=1, login='alice', binding=source['start']['binding'],
            operation=dict(kind='envelope', expected=complete['outcome']['resulting']))
        reopened = dict(preview_format='json', preview_content='substituted' if bad_reopen else native['operation']['content'])
        fake_draft = types.SimpleNamespace(host_module=lambda _auth: host)
        def controller(name):
            return editor if name == 'editor' else fake_draft
        with tempfile.TemporaryDirectory(dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as directory, \
                patch.object(auth, 'workspace_controller', side_effect=controller), patch.object(editor, 'canonical', side_effect=canonical), \
                patch.object(auth, '_capture_native', side_effect=transport), patch.object(auth, 'protected'), \
                patch.object(auth, 'grant_selection', side_effect=grants or (['resume-read', 'start'] if resumed else ['start'])+(['review-read', 'apply-read', 'effect'] if save else [])), \
                patch.object(auth, 'terminal_line', side_effect=controls or (['s', 'checkpoint.request.1', review['approval'], 'r'] if save else ['q'])), \
                patch.object(auth, 'envelope_read', return_value=(read_source, reopened, host)) as exact_read, \
                patch('sys.stdout', new_callable=io.StringIO) as output:
            result_code = editor.journey(auth, proposal(source), Path(directory))
            self.assertEqual(list(Path(directory).iterdir()), [])
            return result_code, calls, exact_read.call_args_list, output.getvalue()

    def test_ordered_actual_routing_uses_native_terminal_then_explicit_freeze_no_automatic_save(self):
        for resumed in (False, True):
            code, calls, reads, output = self.run_journey(resumed=resumed)
            self.assertEqual(code, 0); self.assertEqual(len(calls), 2); self.assertEqual(reads, [])
            self.assertEqual([call[0][4] for call in calls], ['editor-review', 'editor-run'])
            self.assertEqual(calls[1][0][-2], 'resume-read' if resumed else 'none')
            self.assertIn('NOT Saved', output); self.assertNotIn('Saved checkpoint and', output)

    def test_ordered_save_requires_new_review_apply_and_actual_exact_reopen_before_saved(self):
        for resumed in (False, True):
            code, calls, reads, output = self.run_journey(resumed=resumed, save=True)
            self.assertEqual(code, 0)
            self.assertEqual([call[0][4] for call in calls], ['editor-review', 'editor-run', 'content-owned-inspection-review', 'content-owned-review', 'content-owned-apply'])
            self.assertEqual(len(reads), 1); self.assertIn('Saved checkpoint and separately granted exact reopen observed', output)
            self.assertNotIn('review-read', calls[-1][0]); self.assertIn('apply-read', calls[-1][0]); self.assertIn('effect', calls[-1][0])

    def test_cancel_invalid_frozen_or_reused_read_never_autosaves_or_retries(self):
        code, calls, reads, _output = self.run_journey(grants=[None])
        self.assertEqual(code, 130); self.assertEqual(len(calls), 1); self.assertEqual(reads, [])
        code, calls, reads, output = self.run_journey(bad_frozen=b'{"saved":true}')
        self.assertEqual(code, 1); self.assertEqual(len(calls), 2); self.assertEqual(reads, [])
        self.assertNotIn('Saved checkpoint and', output)
        code, calls, reads, output = self.run_journey(save=True, grants=['start', 'same', 'same', 'effect'])
        self.assertEqual(code, 1); self.assertEqual(len(calls), 4); self.assertEqual(reads, [])
        self.assertNotIn('Saved checkpoint and', output)

    def test_commit_without_reopen_and_wrong_exact_reopen_never_claim_saved(self):
        code, calls, reads, output = self.run_journey(save=True, controls=['s', 'checkpoint.request.1', 'write:'+'a'*64, 'q'])
        self.assertEqual(code, 0); self.assertEqual(len(calls), 5); self.assertEqual(reads, [])
        self.assertNotIn('Saved checkpoint and', output)
        code, calls, reads, output = self.run_journey(save=True, bad_reopen=True)
        self.assertEqual(code, 1); self.assertEqual(len(calls), 5); self.assertEqual(len(reads), 1)
        self.assertNotIn('Saved checkpoint and', output)

    def test_image_loader_native_button_and_size_contract_are_bound(self):
        self.assertIn("workspace_controller('editor').launch_dialog", (ROOT/'native/desktop/workspace_app.py').read_text())
        self.assertIn('workspace_editor.py', (ROOT/'native/image/assemble.py').read_text())
        self.assertIn('usr/libexec/luma-os/workspace_editor.py', (ROOT/'native/image/desktop_policy.py').read_text())
        self.assertLessEqual((ROOT/'native/desktop/workspace_auth.py').stat().st_size, 128*1024)
        self.assertLessEqual((ROOT/'native/desktop/workspace_editor.py').stat().st_size, 128*1024)

    def test_actual_owned_child_pure_whitelist_and_reap_are_not_an_editor_lease(self):
        for command in ('editor-request', 'editor-checkpoint-request'):
            pin = host_tests.Pin(); pids = []; real_spawn = subprocess.Popen
            def spawn(_arguments, **kwargs):
                kwargs.pop('executable')
                return real_spawn([sys.executable, '-I', '-c', 'import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data)'], **kwargs)
            try:
                with patch.object(host.subprocess, 'Popen', spawn):
                    state, output = host.run_process(pin, command, b'pure fixture data', threading.Event(), pids.append, timeout=2, maximum=4096)
                self.assertEqual((state, output), ('completed', b'pure fixture data'))
                with self.assertRaises(ProcessLookupError): os.kill(pids[0], 0)
                with self.assertRaises(ValueError): host.run_process(pin, 'editor-run', b'{}', threading.Event(), lambda _pid: None)
            finally:
                pin.close()


if __name__ == '__main__':
    unittest.main()
