"""Offline DATA/transport fixtures, not installed PAM/C/LSM qualification."""
import copy
from contextlib import contextmanager, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import threading
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


auth = load('index_test_auth', 'native/desktop/workspace_auth.py')
index = load('index_test_controller', 'native/desktop/workspace_index.py')
host = load('index_test_host', 'native/desktop/workspace_host.py')
host_tests = load('index_test_host_fixtures', 'native/tests/test_workspace_host.py')


def source(kind='status'):
    operation = dict(kind=kind)
    if kind == 'query':
        operation.update(generation_sha256='8'*64, query_kind='lexical-and', query='alpha', limit=2,
            limits=dict(read_bytes=128*1024*1024, write_bytes=0, source_bytes=0, postings=100000,
                        floating_operations=1000000))
    elif kind in ('step', 'advance', 'publish'):
        operation.update(job_id='4'*32, expected_job_sha256='5'*64)
        if kind == 'step':
            operation['window'] = dict(maximum=4096, read_bytes=64*1024*1024, write_bytes=16*1024*1024)
    elif kind == 'start':
        operation.update(job_id='4'*32, expected_owner_sha256='6'*64, expected_selection_sha256='7'*64,
            dimensions=8, limits=dict(read_bytes=128*1024**3, write_bytes=64*1024**3,
                source_bytes=8*1024**3, postings=32000000, floating_operations=64000000000))
    return dict(schema_version=1, login='alice', binding=dict(installation='1'*64, owner='2'*64,
        owner_generation=2**64-1), request_id='3'*32, operation=operation)


def proposal(value):
    return dict(schema_version=1, operation='index-journey', login=value['login'], read_grant='',
        effect_grant='', approval='', request=auth.encoded(value).decode())


def canonical(value, scope=True):
    # This fixture is canonicalizer DATA, not a native/source/custody proof.
    exact = auth.encoded(value).decode()
    sha = hashlib.sha256(exact.encode()).hexdigest()
    result = dict(schema_version=1, canonical_request=exact, request_sha256=sha,
        **{key:False for key in index.DATA_FLAGS})
    if scope:
        mode = index.mode(value)
        result.update(profile='index-v2-{}-{}-{}-{}'.format(mode, value['binding']['owner_generation'], sha, sha),
            installation_verified=False,
            storage_device='253:1', usage=dict(action='file.read', selector=dict(kind='file',
                id='native-content-index-'+{'status':'inspect','query':'query','review':'source'}[mode]+'-v2',
                generation=value['binding']['owner_generation'], digest='9'*64),
                input_bytes=(4 if mode == 'status' else 128)*1024*1024, output_bytes=65536, units=1))
    return result


def status():
    return dict(schema_version=2, kind='status', selection_sha256='7'*64,
        owner_sha256='6'*64, corpus_sha256='5'*64, documents=0, current_generation=None,
        job=None, preparation_pending=False, effect_executed=False, authority_returned=False,
        production_qualified=False)


def query_reply(value):
    result = dict(schema_version=2, kind='query', selection_sha256='7'*64,
        effect_executed=False, authority_returned=False, production_qualified=False)
    result['result'] = dict(schema_version=1, profile='luma-selected-corpus-generation-v2',
        kind=value['operation']['query_kind'], canonical_query='alpha', corpus_sha256='5'*64,
        index_sha256='8'*64, matches=[dict(reference=dict(artifact_id='source.one', version=1,
            content_sha256='a'*64, receipt_sha256='b'*64), format='utf8-text', score=1)],
        total_matches=1, truncated=False)
    return result


def step_review(value):
    source_sha = hashlib.sha256(auth.encoded(value)).hexdigest()
    policy = 'c'*64
    zero = dict(allocated_bytes=0, regular_files=0, directories=0, segments=0)
    review = dict(schema_version=2, input_sha256=source_sha, base_sha256='5'*64, phase='audit',
        review_sha256='a'*64, core_review_sha256='b'*64, planned_objects_sha256='d'*64,
        builder=dict(source_sha256='e'*64, runtime_sha256='f'*64), policy_sha256=policy,
        metadata_maximum=dict(object_writes=256, read_bytes=8*1024*1024, write_bytes=32*1024*1024, new_files=768),
        source_bytes=0, maximum_read_bytes=1024*1024, maximum_write_bytes=0)
    summary = dict(schema_version=1, policy_sha256=policy, actual=zero, retained_records=0,
        retained=zero, requested=zero, total=zero)
    return dict(schema_version=2, kind='review', selection_sha256='7'*64, review=review,
        effect_profile='index-v2-step-{}-{}-{}'.format(value['binding']['owner_generation'], source_sha, 'a'*64),
        quota_preview=dict(summary=summary, sha256='6'*64, quota_data_only=True, free_space_proven=False,
            reservation_created=False, effect_admitted=False), effect_executed=False, authority_returned=False,
        production_qualified=False)


class IndexWorkspaceTests(unittest.TestCase):
    def test_all_supported_requests_are_closed_and_builders_create_unique_data(self):
        for kind in ('status', 'query', 'start', 'step', 'advance', 'publish'):
            index.request(auth, source(kind))
        original = source()
        first = index.status_request(auth, 'alice', original['binding'])
        second = index.status_request(auth, 'alice', original['binding'])
        self.assertNotEqual(first['request_id'], second['request_id'])
        with self.assertRaises(ValueError):
            index.review_request(auth, 'alice', original['binding'], dict(kind='status'))

    def test_unknown_grants_paths_phase_cursor_and_retention_are_rejected(self):
        for where, name in (('request', 'path'), ('request', 'read_grant'), ('operation', 'cursor'),
                            ('operation', 'phase'), ('operation', 'complete')):
            value = source()
            (value if where == 'request' else value['operation'])[name] = 'caller'
            with self.assertRaises(ValueError):
                index.request(auth, value)
        for kind in ('retain', 'run', 'delete', 'Start'):
            with self.assertRaises(ValueError):
                index.request(auth, source(kind))

    def test_integer_aliases_limits_and_source_bounds_refuse(self):
        for edit in (lambda v:v.update(schema_version=True), lambda v:v['binding'].update(owner_generation=True),
                     lambda v:v['operation'].update(limit=True), lambda v:v['operation'].update(limit=65),
                     lambda v:v['operation']['limits'].update(write_bytes=1),
                     lambda v:v['operation'].update(query='x'*65536)):
            value = source('query'); edit(value)
            with self.assertRaises(ValueError):
                index.request(auth, value)
        value = source('step'); value['operation']['window']['maximum'] = 8193
        with self.assertRaises(ValueError):
            index.request(auth, value)

    def test_duplicate_json_and_nonfinite_inputs_refuse(self):
        with self.assertRaises(ValueError):
            index.dialog_request(auth, 'alice', auth.encoded(source()['binding']).decode(), '{"kind":"status","kind":"status"}')
        with self.assertRaises(ValueError):
            auth.strict_json('{"limit":NaN}')

    def test_pure_native_echo_scope_and_flags_are_exact_data(self):
        for kind in ('status', 'query', 'step'):
            value = source(kind); raw = canonical(value)
            self.assertEqual(index.canonical_reply(auth, value, auth.encoded(raw), True), raw)
            for flag in index.DATA_FLAGS:
                bad = copy.deepcopy(raw); bad[flag] = True
                with self.assertRaises(ValueError):
                    index.canonical_reply(auth, value, auth.encoded(bad), True)

    def test_canonicalizer_cannot_substitute_source_hash_or_extra_scope(self):
        value = source(); original = canonical(value)
        for edit in (lambda r:r.update(request_sha256='a'*64),
                     lambda r:r.update(canonical_request=auth.encoded(source('query')).decode()),
                     lambda r:r.update(enabled=True), lambda r:r.update(profile=r['profile'].replace('status', 'start')),
                     lambda r:r.update(storage_device='0253:1'), lambda r:r['usage'].update(units=2),
                     lambda r:r['usage'].update(output_bytes=65537),
                     lambda r:r['usage']['selector'].update(generation=True)):
            bad = copy.deepcopy(original); edit(bad)
            with self.assertRaises(ValueError):
                index.canonical_reply(auth, value, auth.encoded(bad), True)

    def test_pinned_pure_helper_closes_binary_and_never_pam(self):
        value = source(); binary = types.SimpleNamespace(close=lambda: closed.append(True))
        closed = []; calls = []
        host = types.SimpleNamespace(PinnedExecutable=lambda _p:binary,
            run_process=lambda *args, **kwargs:(calls.append((args, kwargs)) or ('completed', auth.encoded(canonical(value)))))
        result = index.canonical(auth, host, value, scope=True)
        self.assertEqual(result['request_sha256'], canonical(value)['request_sha256'])
        self.assertEqual(calls[0][0][1], 'index-scope-proposal'); self.assertEqual(closed, [True])
        host.run_process = lambda *a, **k:('refused', b'{}')
        with self.assertRaises(ValueError):
            index.canonical(auth, host, value)
        self.assertEqual(len(closed), 2)

    @unittest.skipUnless(os.name == 'posix', 'actual POSIX bounded process transport')
    def test_actual_host_boundary_allows_only_two_new_pure_index_commands(self):
        # Real run_process allowlist, streams, subprocess and reap. Only the
        # executable fixture is replaced; this is not a native/custody proof.
        real_spawn = subprocess.Popen
        calls = []
        def spawn(arguments, **kwargs):
            calls.append(arguments[1]); kwargs.pop('executable')
            return real_spawn([sys.executable, '-I', '-c',
                'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'], **kwargs)
        for command in ('index-request', 'index-scope-proposal'):
            binary = host_tests.Pin(); pids = []
            try:
                with patch.object(host.subprocess, 'Popen', spawn):
                    state, output = host.run_process(binary, command, b'{"data":true}', threading.Event(),
                        pids.append, timeout=2, maximum=128*1024)
                self.assertEqual((state, output), ('completed', b'{"data":true}'))
                self.assertEqual(len(pids), 1)
                with self.assertRaises(ProcessLookupError):
                    os.kill(pids[0], 0)
            finally:
                binary.close()
        self.assertEqual(calls, ['index-request', 'index-scope-proposal'])
        binary = host_tests.Pin()
        try:
            with patch.object(host.subprocess, 'Popen') as spawned:
                for command in ('index-run', 'index-review', 'index-resource-worker', 'index-request;run'):
                    with self.assertRaises(ValueError):
                        host.run_process(binary, command, b'{}', threading.Event(), lambda _:None)
                spawned.assert_not_called()
        finally:
            binary.close()

    def test_native_query_normalization_is_shown_and_cannot_substitute_other_fields(self):
        raw = source('query'); raw['operation']['query'] = '  BETA alpha ALPHA\t'
        normalized = copy.deepcopy(raw); normalized['operation']['query'] = 'alpha beta'
        result = canonical(normalized)
        actual = index.canonical_reply(auth, raw, auth.encoded(result), True)
        self.assertEqual(auth.strict_json(actual['canonical_request'])['operation']['query'], 'alpha beta')
        altered = copy.deepcopy(normalized); altered['operation']['generation_sha256'] = 'f'*64
        with self.assertRaises(ValueError):
            index.canonical_reply(auth, raw, auth.encoded(canonical(altered)), True)

    def test_capture_dispatches_only_fixed_readonly_native_command(self):
        with patch.object(auth, 'protected'), patch.object(auth, '_capture_native', return_value=b'{}') as called:
            index.capture(auth, source(), 'Read.one', Path('/explicit.request'))
            args, maximum = called.call_args.args
            self.assertEqual(args, ['/usr/bin/sudo', '--', auth.NATIVE, 'granted-run', 'index-review',
                                    'alice', 'Read.one', str(Path('/explicit.request'))])
            self.assertEqual(maximum, 65536)
            for grant in ('', '../escape', 'read;command', 'a'*129):
                with self.assertRaises(ValueError):
                    index.capture(auth, source(), grant, Path('/explicit.request'))

    def test_status_is_an_observation_not_authority_or_completion(self):
        value = source(); result = status()
        self.assertEqual(index.completed(auth, value, auth.encoded(value).decode(), auth.encoded(result)), result)
        for key in ('effect_executed', 'authority_returned', 'production_qualified'):
            bad = dict(result); bad[key] = True
            with self.assertRaises(ValueError):
                index.completed(auth, value, auth.encoded(value).decode(), auth.encoded(bad))

    def test_query_exact_generation_reference_counts_and_score_contract(self):
        value = source('query'); original = query_reply(value)
        index.completed(auth, value, auth.encoded(value).decode(), auth.encoded(original))
        for edit in (lambda r:r['result'].update(index_sha256='f'*64), lambda r:r['result'].update(canonical_query='other'),
                     lambda r:r['result'].update(truncated=True), lambda r:r['result'].update(total_matches=2),
                     lambda r:r['result']['matches'][0].update(score=True),
                     lambda r:r['result']['matches'].append(copy.deepcopy(r['result']['matches'][0]))):
            bad = copy.deepcopy(original); edit(bad)
            with self.assertRaises(ValueError):
                index.completed(auth, value, auth.encoded(value).decode(), auth.encoded(bad))

    def test_wrong_result_kind_duplicates_or_extra_fields_refuse(self):
        for bad in (dict(status(), kind='query'), dict(status(), saved=True), dict(status(), documents=True)):
            with self.assertRaises(ValueError):
                index.completed(auth, source(), auth.encoded(source()).decode(), auth.encoded(bad))
        with self.assertRaises(ValueError):
            index.completed(auth, source(), '', b'{"schema_version":2,"schema_version":2}')

    def test_review_keeps_full_native_envelope_policy_source_and_no_go_preview(self):
        value = source('step'); original = step_review(value)
        self.assertEqual(index.completed(auth, value, auth.encoded(value).decode(), auth.encoded(original)), original)
        for edit in (lambda r:r['review'].update(input_sha256='f'*64),
                     lambda r:r['review'].update(base_sha256='f'*64),
                     lambda r:r['review'].update(review_sha256='f'*64),
                     lambda r:r['review'].update(caller_phase='audit'),
                     lambda r:r['review']['metadata_maximum'].update(write_bytes=0),
                     lambda r:r['quota_preview'].update(free_space_proven=True),
                     lambda r:r['quota_preview'].update(effect_admitted=True),
                     lambda r:r['quota_preview']['summary'].update(policy_sha256='f'*64)):
            bad = copy.deepcopy(original); edit(bad)
            with self.assertRaises(ValueError):
                index.completed(auth, value, auth.encoded(value).decode(), auth.encoded(bad))

    def test_query_journey_uses_native_normalized_source_before_fresh_grant(self):
        raw = source('query'); raw['operation']['query'] = ' BETA alpha ALPHA '
        normalized = copy.deepcopy(raw); normalized['operation']['query'] = 'alpha beta'
        result = query_reply(normalized); result['result']['canonical_query'] = 'alpha beta'
        @contextmanager
        def stage(_directory, canonical_text):
            self.assertEqual(auth.strict_json(canonical_text), normalized)
            yield Path('/fixed.request')
        with patch.object(index, 'canonical', return_value=canonical(normalized)), \
                patch.object(index, 'capture', return_value=auth.encoded(result)) as captured, \
                patch.object(auth, 'workspace_controller', return_value=types.SimpleNamespace(host_module=lambda _:None)), \
                patch.object(auth, 'grant_selection', return_value='Read.fresh'), patch.object(auth, 'request_stage', side_effect=stage), redirect_stdout(io.StringIO()):
            self.assertEqual(index.journey(auth, proposal(raw), Path('/unused')), 0)
            self.assertEqual(captured.call_args.args[1], normalized)

    def test_closed_journey_hook_and_unknown_journey_never_loads_module(self):
        with patch.object(auth, 'workspace_controller', return_value=index) as called:
            auth.proposal(proposal(source()))
            self.assertEqual(called.call_args.args, ('index',))
        with patch.object(auth, 'workspace_controller') as called:
            with self.assertRaises(ValueError):
                auth.proposal(dict(proposal(source()), operation='unknown-journey'))
            called.assert_not_called()
        for name in ('../../index', 'unknown', 'Index', 'editor-journey'):
            with self.assertRaises(ValueError):
                auth.workspace_controller(name)
        with patch.object(auth, 'workspace_controller', return_value=index):
            with self.assertRaises(ValueError):
                auth.proposal(dict(proposal(source()), read_grant='Read.old'))

    def test_journey_cancel_has_no_staging_or_native_read(self):
        value = source()
        with patch.object(index, 'canonical', return_value=canonical(value)), patch.object(index, 'capture') as captured, \
                patch.object(auth, 'workspace_controller', return_value=types.SimpleNamespace(host_module=lambda _:None)), \
                patch.object(auth, 'grant_selection', return_value=None), patch.object(auth, 'request_stage') as staged, redirect_stdout(io.StringIO()):
            self.assertEqual(index.journey(auth, proposal(value), Path('/unused')), 130)
            captured.assert_not_called(); staged.assert_not_called()

    def test_journey_one_actual_call_no_effect_retry_or_automatic_advance(self):
        value = source(); calls = []
        @contextmanager
        def stage(_directory, canonical_text):
            self.assertEqual(canonical_text, canonical(value)['canonical_request'])
            yield Path('/fixed.request')
        out = io.StringIO()
        with patch.object(index, 'canonical', return_value=canonical(value)), \
                patch.object(index, 'capture', side_effect=lambda *a:(calls.append(a) or auth.encoded(status()))), \
                patch.object(auth, 'workspace_controller', return_value=types.SimpleNamespace(host_module=lambda _:None)), \
                patch.object(auth, 'grant_selection', return_value='Read.fresh'), patch.object(auth, 'request_stage', side_effect=stage), redirect_stdout(out):
            self.assertEqual(index.journey(auth, proposal(value), Path('/unused')), 0)
        self.assertEqual(len(calls), 1)
        self.assertIn('No next phase, retry or effect is automatic', out.getvalue())
        self.assertNotIn('Saved', out.getvalue())

    def test_journey_refusal_or_interrupt_does_not_retry_or_claim_completion(self):
        for error in (ValueError('refused'), KeyboardInterrupt()):
            with patch.object(index, 'canonical', side_effect=error) as called, \
                    patch.object(auth, 'workspace_controller', return_value=types.SimpleNamespace(host_module=lambda _:None)), \
                    redirect_stdout(io.StringIO()) as out:
                self.assertEqual(index.journey(auth, proposal(source()), Path('/unused')), 1)
                self.assertEqual(called.call_count, 1)
                self.assertNotIn('Observed native private', out.getvalue())

    def test_release_wiring_and_fixed_protected_module_cap(self):
        assemble = (ROOT/'native/image/assemble.py').read_text(encoding='utf-8')
        policy = (ROOT/'native/image/desktop_policy.py').read_text(encoding='utf-8')
        app = (ROOT/'native/desktop/workspace_app.py').read_text(encoding='utf-8')
        self.assertIn("'workspace_index.py'", assemble)
        self.assertIn("'usr/libexec/luma-os/workspace_index.py'", policy)
        self.assertIn("workspace_controller('index').launch_dialog", app)
        self.assertLessEqual((ROOT/'native/desktop/workspace_auth.py').stat().st_size, 128*1024)
        self.assertLessEqual((ROOT/'native/desktop/workspace_index.py').stat().st_size, 128*1024)


if __name__ == '__main__':
    unittest.main()
