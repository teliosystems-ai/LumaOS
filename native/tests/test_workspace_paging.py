"""Terminal-only paging data and reachable journey tests, never PAM authority.

Native grant/confinement qualification remains an installed-image exercise.
"""
import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('luma_workspace_paging_auth', ROOT / 'native/desktop/workspace_auth.py')
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)
HOST_SPEC = importlib.util.spec_from_file_location('luma_workspace_paging_host', ROOT / 'native/desktop/workspace_host.py')
host = importlib.util.module_from_spec(HOST_SPEC)
HOST_SPEC.loader.exec_module(host)


def fixture(content='Exact caf\u00e9 source\n' * 1500):
    binding = dict(installation='1'*64, owner='2'*64, owner_generation=7)
    sha = lambda value: hashlib.sha256(value).hexdigest()
    receipt = dict(schema_version=1, binding=binding, artifact_id='exact-document', version=1, previous=None,
                   format='utf8-text', media_type='text/plain; charset=utf-8', content_sha256=sha(content.encode()),
                   content_bytes=len(content.encode()), original_bytes=len(content.encode()),
                   provenance=dict(request_id='source-request', workflow_sha256='3'*64,
                                   source_sha256=sha(content.encode()), origin='managed'))
    reference = dict(artifact_id='exact-document', version=1, content_sha256=receipt['content_sha256'],
                     receipt_sha256=sha(auth.encoded(receipt)))
    envelope = auth.encoded(dict(receipt=receipt, receipt_sha256=reference['receipt_sha256'], content=content))
    source = dict(schema_version=1, login='alice', binding=binding,
                  operation=dict(kind='page', expected=reference, offset=0, bytes=auth.PAGE_BYTES))
    value = dict(schema_version=1, operation='paged-read', login='alice', read_grant='', effect_grant='',
                 approval='', request=auth.encoded(source).decode())
    return value, source, envelope


def page(source, envelope, offset=0):
    end = min(offset+auth.PAGE_BYTES, len(envelope))
    value = dict(schema_version=1, reference=source['operation']['expected'], format='utf8-text',
        envelope_bytes=len(envelope), envelope_sha256=hashlib.sha256(envelope).hexdigest(),
        content_delivered=True, committed=False, authority_returned=False, provenance_authority=False,
        workflow_executed=False, production_qualified=False, encoding='hex', offset=offset, next_offset=end,
        eof=end == len(envelope), slice_hex=envelope[offset:end].hex())
    # Real serde_json::Value responses can order nested keys differently from
    # the typed request. Ordering changes neither selected data nor authority.
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def inspection(source):
    return auth.encoded(dict(schema_version=1, inspection_usage=dict(action='file.read',
        selector=dict(kind='file', id='native-content-query-v1', generation=source['binding']['owner_generation'], digest='a'*64),
        input_bytes=auth.MAX_REQUEST, output_bytes=auth.MAX_QUERY_OUTPUT, units=1), query_only=True,
        private_content_read=False, grant_issued=False, committed=False))


class WorkspacePagingTests(unittest.TestCase):
    def test_exact_multi_page_utf8_reference_and_generation_reassembly(self):
        value, source, envelope = fixture()
        auth.proposal(value)
        assembled = auth.PagedEnvelope(source)
        with self.assertRaises(ValueError):
            assembled.complete()
        count = 0
        while not assembled.eof:
            offset = len(assembled.data)
            received, total = assembled.accept(page(source, envelope, offset))
            self.assertGreater(received, offset)
            self.assertEqual(total, len(envelope))
            count += 1
        self.assertGreater(count, 1)
        self.assertEqual(assembled.complete(), envelope)
        with self.assertRaises(ValueError):
            assembled.accept(page(source, envelope))
        self.assertEqual(assembled.data, bytearray())

    def test_selector_has_no_authority_defaults_and_cannot_dispatch_an_effect(self):
        value, source, _ = fixture()
        for mutate in [lambda v: v.update(read_grant='prior-grant'), lambda v: v.update(effect_grant='effect'),
                       lambda v: v.update(approval='write:'+'a'*64), lambda v: v.update(password='never')]:
            bad = copy.deepcopy(value)
            mutate(bad)
            with self.assertRaises(ValueError):
                auth.proposal(bad)
        for key, field, invalid in [('operation', 'offset', 1), ('operation', 'offset', False),
                                    ('operation', 'bytes', 1), ('binding', 'owner_generation', True),
                                    ('binding', 'owner', '0'*64)]:
            bad = copy.deepcopy(source)
            bad[key][field] = invalid
            with self.assertRaises(ValueError):
                auth.page_request(bad)
        with self.assertRaises(ValueError):
            auth.terminal_arguments(value, Path('/inert/request'))
        duplicate = value['request'].replace('"offset":0', '"offset":0,"offset":0')
        with self.assertRaises(ValueError):
            auth.proposal(dict(value, request=duplicate))

    def test_page_substitution_unknown_fields_offsets_and_type_confusion_fence_instance(self):
        _, source, envelope = fixture()
        first = auth.strict_json(page(source, envelope))
        changes = [dict(offset=True), dict(next_offset=auth.PAGE_BYTES-1), dict(eof=True),
                   dict(content_delivered=False), dict(envelope_bytes=auth.MAX_ENVELOPE+1),
                   dict(authority_returned=True), dict(encoding='base64'), dict(unknown=False),
                   dict(slice_hex=first['slice_hex'].upper()), dict(envelope_sha256='A'*64),
                   dict(reference=dict(source['operation']['expected'], version=True))]
        for changeset in changes:
            assembled = auth.PagedEnvelope(source)
            bad = dict(first, **changeset)
            with self.assertRaises(ValueError):
                assembled.accept(auth.encoded(bad))
            with self.assertRaises(ValueError):
                assembled.accept(page(source, envelope))
            self.assertEqual(assembled.data, bytearray())
        assembled = auth.PagedEnvelope(source)
        assembled.accept(page(source, envelope))
        second = auth.strict_json(page(source, envelope, len(assembled.data)))
        second['envelope_sha256'] = 'b'*64
        with self.assertRaises(ValueError):
            assembled.accept(auth.encoded(second))
        duplicate = page(source, envelope).replace(b'"offset":0', b'"offset":0,"offset":0')
        with self.assertRaises(ValueError):
            auth.PagedEnvelope(source).accept(duplicate)

    def test_complete_hash_content_receipt_and_owner_binding_are_independently_checked(self):
        _, source, envelope = fixture('Short exact content')
        for field in ('owner', 'content', 'receipt'):
            bad = auth.strict_json(envelope)
            if field == 'owner':
                bad['receipt']['binding']['owner'] = 'f'*64
            elif field == 'content':
                bad['content'] = 'substituted'
            else:
                bad['receipt']['provenance']['request_id'] = 'substituted'
            altered = auth.encoded(bad)
            assembled = auth.PagedEnvelope(source)
            assembled.accept(page(source, altered))
            with self.assertRaises(ValueError):
                assembled.complete()
            self.assertEqual(assembled.data, bytearray())
        assembled = auth.PagedEnvelope(source)
        bad = auth.strict_json(page(source, envelope))
        bad['slice_hex'] = '00' + bad['slice_hex'][2:]
        assembled.accept(auth.encoded(bad))
        with self.assertRaises(ValueError):
            assembled.complete()

    def test_native_scope_is_read_only_exact_bounded_and_generation_bound(self):
        _, source, _ = fixture()
        self.assertEqual(auth.inspection_scope(inspection(source), source)['selector']['generation'], 7)
        for key, wrong in [('action', 'artifact.write'), ('units', True), ('input_bytes', 0), ('output_bytes', 1)]:
            value = auth.strict_json(inspection(source))
            value['inspection_usage'][key] = wrong
            with self.assertRaises(ValueError):
                auth.inspection_scope(auth.encoded(value), source)
        value = auth.strict_json(inspection(source))
        value['inspection_usage']['selector']['generation'] = 8
        with self.assertRaises(ValueError):
            auth.inspection_scope(auth.encoded(value), source)

    def test_actual_journey_stops_before_private_read_when_human_cancels(self):
        value, source, _ = fixture()
        with tempfile.TemporaryDirectory(prefix='luma-paged-stop-') as temporary:
            with patch.object(auth, 'canonical_native_request', return_value=(value['request'], None)), \
                 patch.object(auth, 'protected'), patch.object(auth, 'capture_query', return_value=inspection(source)) as query, \
                 patch('builtins.input', return_value='q'), patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(auth.paged_read(value, Path(temporary)), 130)
            self.assertEqual(query.call_count, 1)
            self.assertEqual(query.call_args.args[0][4], 'content-owned-inspection-review')
            self.assertIn('No publication or export was requested', output.getvalue())
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_capture_rejects_effect_or_arbitrary_command_before_spawn(self):
        for arguments in [['sh', '-c', 'anything'], ['/usr/bin/sudo', '--', auth.NATIVE, 'granted-run',
                          'content-owned-apply', 'alice', '/inert/request']]:
            with patch.object(auth.subprocess, 'Popen') as spawn:
                with self.assertRaises(ValueError):
                    auth.capture_query(arguments)
                spawn.assert_not_called()

    def test_actual_journey_requires_distinct_page_prompts_and_whole_native_reopen(self):
        value, source, envelope = fixture()
        pages = (len(envelope)+auth.PAGE_BYTES-1)//auth.PAGE_BYTES
        observed = []
        def query(arguments):
            current = auth.strict_json(Path(arguments[-1]).read_bytes())
            observed.append((arguments[4], current['operation']['offset'], arguments))
            if arguments[4] == 'content-owned-inspection-review':
                return inspection(source)
            return page(source, envelope, current['operation']['offset'])
        data = auth.strict_json(envelope)
        artifact = dict(receipt=data['receipt'], reference=source['operation']['expected'], canonical_envelope=envelope.decode())
        native = auth.encoded(dict(schema_version=1, result=dict(operation='reopen', validated=artifact),
            owner_authenticated=False, authority_returned=False, committed=False, certified=False, gate_closing=False))
        class Pin:
            def close(self):
                pass
        with tempfile.TemporaryDirectory(prefix='luma-paged-journey-') as temporary:
            with patch.object(auth, 'canonical_native_request', side_effect=lambda current: (current['request'], host)), \
                 patch.object(auth, 'protected'), patch.object(auth, 'capture_query', side_effect=query), \
                 patch.object(host, 'PinnedExecutable', return_value=Pin()), \
                 patch.object(host, 'run_process', return_value=('completed', native)) as reopened, \
                 patch('builtins.input', side_effect=['page-read-'+str(i) for i in range(pages)]) as prompt, \
                 patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(auth.paged_read(value, Path(temporary)), 0)
            self.assertEqual(prompt.call_count, pages)
            self.assertEqual(reopened.call_count, 1)
            self.assertEqual(reopened.call_args.args[1], 'content-contract-reopen')
            self.assertEqual(len(observed), pages*2)
            self.assertEqual([entry[1] for entry in observed[::2]], list(range(0, len(envelope), auth.PAGE_BYTES)))
            self.assertEqual([entry[2][6] for entry in observed[1::2]], ['page-read-'+str(i) for i in range(pages)])
            self.assertIn('Complete immutable envelope verified', output.getvalue())
            self.assertIn('"publication_requested": false', output.getvalue())
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_failed_later_page_discards_partial_without_reopen_or_completion(self):
        value, source, envelope = fixture()
        responses = [inspection(source), page(source, envelope), inspection(source)]
        with tempfile.TemporaryDirectory(prefix='luma-paged-refusal-') as temporary:
            with patch.object(auth, 'canonical_native_request', return_value=(value['request'], host)), \
                 patch.object(auth, 'protected'), \
                 patch.object(auth, 'capture_query', side_effect=responses+[ValueError('current grant revoked')]), \
                 patch.object(host, 'run_process') as reopened, \
                 patch('builtins.input', side_effect=['page-one', 'page-two']), \
                 patch('sys.stdout', new_callable=io.StringIO) as output:
                with self.assertRaisesRegex(ValueError, 'current grant revoked'):
                    auth.paged_read(value, Path(temporary))
            reopened.assert_not_called()
            self.assertNotIn('Complete immutable envelope verified', output.getvalue())
            self.assertNotIn('"content":', output.getvalue())
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_actual_pipe_capture_observes_exit_bound_and_timeout_without_effect_command(self):
        actual_popen = subprocess.Popen
        arguments = ['/usr/bin/sudo', '--', auth.NATIVE, 'granted-run', 'content-owned-review',
                     'alice', 'explicit-read', '/not-opened/in-this-software-fixture']
        children = []
        def run(script):
            def start(*_args, **kwargs):
                child = actual_popen([sys.executable, '-I', '-c', script], **kwargs)
                children.append(child)
                return child
            return start
        with patch.object(auth.subprocess, 'Popen', side_effect=run('import os; os.write(1,b"{}")')):
            self.assertEqual(auth.capture_query(arguments), b'{}')
        with patch.object(auth.subprocess, 'Popen', side_effect=run('import os; os.write(1,b"a"*65536)')):
            with self.assertRaises(ValueError):
                auth.capture_query(arguments)
        with patch.object(auth.subprocess, 'Popen', side_effect=run('import time; time.sleep(30)')):
            with self.assertRaises(ValueError):
                auth.capture_query(arguments, timeout=.1)
        self.assertTrue(all(child.poll() is not None for child in children))


if __name__ == '__main__':
    unittest.main()
