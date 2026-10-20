"""Native discovery controller tests; fixtures are inert DATA, not authority.

No PAM/grant issuer, private repository, graphical session or installed effect
is simulated as authenticated. Optional --native-cli exercises the real public
native canonicalizer through its exact process transport, not a private Read.
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
SPEC = importlib.util.spec_from_file_location('luma_discovery_auth', ROOT / 'native/desktop/workspace_auth.py')
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def reference(identifier='alpha', version=1):
    return dict(artifact_id=identifier, version=version, content_sha256='3'*64, receipt_sha256='4'*64)


def fixture(collection=False, empty=False):
    references = [] if empty else [reference(), reference('beta', 2)]
    operation = dict(kind='collection-search-semantic' if collection else 'search-semantic-selected',
                     query='  CAT\tDOG cat ', limit=32, dimensions=2)
    operation.update(dict(expected=reference('collection.exact')) if collection else dict(references=references))
    source = dict(schema_version=1, login='alice',
                  binding=dict(installation='1'*64, owner='2'*64, owner_generation=7), operation=operation)
    value = dict(schema_version=1, operation='search-journey', login='alice', read_grant='', effect_grant='',
                 approval='', request=auth.encoded(source).decode())
    descriptor = dict(schema_version=1, algorithm='tfidf-lsa-jacobi-v1', binding=source['binding'], references=references,
                      dimensions=2, maximum_vocabulary=4096, maximum_features=512)
    result = dict(algorithm='tfidf-lsa-jacobi-v1', canonical_query='cat dog', selection_sha256=digest(canonical(references)),
        index_descriptor_sha256=digest(canonical(descriptor)), selected_versions=len(references), vocabulary_terms=0 if empty else 5,
        indexed_features=0 if empty else 5, requested_dimensions=2, effective_dimensions=0 if empty else 2,
        matches=[] if empty else [dict(reference=references[0], format='utf8-text', cosine_millionths=900000),
                                  dict(reference=references[1], format='json', cosine_millionths=300000)],
        total_matches=len(references), truncated=False)
    output = dict(schema_version=1, content_delivered=False, committed=False, authority_returned=False,
                  selection_is_authority=False, similarity_is_authority=False, provenance_authority=False,
                  workflow_executed=False, production_qualified=False)
    output['semantic_collection_search' if collection else 'semantic_search'] = (
        dict(collection=operation['expected'], search=result) if collection else result)
    return value, source, result, output


def inspection(source):
    return auth.encoded(dict(schema_version=1, query_only=True, private_content_read=False, grant_issued=False,
        committed=False, inspection_usage=dict(action='file.read', input_bytes=auth.MAX_REQUEST,
            output_bytes=auth.MAX_QUERY_OUTPUT, units=1, selector=dict(kind='file', id='native-content-query-v1',
                generation=source['binding']['owner_generation'], digest='a'*64))))


class WorkspaceDiscoveryTests(unittest.TestCase):
    def test_closed_owner_local_selectors_and_no_preselected_authority(self):
        for collection in (False, True):
            value, source, *_ = fixture(collection)
            self.assertEqual(auth.proposal(value), value)
            self.assertEqual(auth.discovery_request(source), source)
            with self.assertRaises(ValueError):
                auth.terminal_arguments(value, Path('/inert/request'))
            for field, invalid in [('read_grant', 'cached-read'), ('effect_grant', 'effect'), ('approval', 'write:'+'a'*64), ('approval', False), ('approval', 0), ('approval', [])]:
                with self.assertRaises(ValueError):
                    auth.proposal(dict(value, **{field: invalid}))
        _, source, *_ = fixture()
        for mutate in (lambda v: v.update(extra=1), lambda v: v.update(login=''),
            lambda v: v['binding'].update(owner_generation=True), lambda v: v['binding'].update(owner='0'*64),
            lambda v: v['operation'].update(kind='search'), lambda v: v['operation'].update(command='arbitrary'),
            lambda v: v['operation'].update(limit=33), lambda v: v['operation'].update(limit=True),
            lambda v: v['operation'].update(dimensions=0), lambda v: v['operation'].update(dimensions=True),
            lambda v: v['operation'].update(references=[]), lambda v: v['operation'].update(references=[reference()]*65),
            lambda v: v['operation'].update(references=[reference(), reference()]),
            lambda v: v['operation'].update(references=[reference('beta'), reference()]),
            lambda v: v['operation']['references'][0].update(version=True),
            lambda v: v['operation']['references'][0].update(version=2**64)):
            wrong = copy.deepcopy(source)
            mutate(wrong)
            with self.assertRaises(ValueError):
                auth.discovery_request(wrong)

    def test_term_grammar_matches_native_ascii_bounds_and_aliases(self):
        self.assertEqual(auth.discovery_query(' DOG\r\ncat DOG\fCat\t'), 'cat dog')
        self.assertEqual(auth.discovery_query('Z'*64), 'z'*64)
        for query in ('', ' '*256, 'x'*257, 'a'*65, 'one '*9, 'cat_dog', 'caf\u00e9', 'cat\u00a0dog', 'cat\vdog', 'a\x00b', 'cat-dog', True, []):
            with self.subTest(query=query), self.assertRaises(ValueError):
                auth.discovery_query(query)

    def test_exact_selection_descriptor_ordering_and_64_bit_references_are_preserved(self):
        value, source, result, output = fixture()
        self.assertEqual(auth.discovery_response(source, auth.encoded(output)), result)
        source['operation']['references'][0]['version'] = 2**64-1
        self.assertEqual(auth.discovery_request(source)['operation']['references'][0]['version'], 2**64-1)
        with self.assertRaises(ValueError):
            auth.discovery_response(source, auth.encoded(output))
        self.assertEqual(auth.strict_json(value['request'])['operation']['references'][0]['version'], 1)

    def test_results_reject_substitution_unknown_fields_and_authority_claims(self):
        _, source, _, output = fixture()
        for flag in ('content_delivered', 'committed', 'authority_returned', 'selection_is_authority',
                     'similarity_is_authority', 'provenance_authority', 'workflow_executed', 'production_qualified'):
            with self.assertRaises(ValueError):
                auth.discovery_response(source, auth.encoded(dict(output, **{flag: True})))
        changes = [lambda v: v.update(extra=0), lambda v: v.update(schema_version=True),
            lambda v: v['semantic_search'].update(algorithm='fake-neural'),
            lambda v: v['semantic_search'].update(canonical_query='other'),
            lambda v: v['semantic_search'].update(selection_sha256='f'*64),
            lambda v: v['semantic_search'].update(index_descriptor_sha256='f'*64),
            lambda v: v['semantic_search'].update(selected_versions=3),
            lambda v: v['semantic_search'].update(vocabulary_terms=4097),
            lambda v: v['semantic_search'].update(indexed_features=4),
            lambda v: v['semantic_search'].update(requested_dimensions=1),
            lambda v: v['semantic_search'].update(effective_dimensions=3),
            lambda v: v['semantic_search'].update(total_matches=3),
            lambda v: v['semantic_search'].update(truncated=0),
            lambda v: v['semantic_search']['matches'][0].update(extra=True),
            lambda v: v['semantic_search']['matches'][0].update(cosine_millionths=True),
            lambda v: v['semantic_search']['matches'][0].update(cosine_millionths=1000001),
            lambda v: v['semantic_search']['matches'][0].update(cosine_millionths=0),
            lambda v: v['semantic_search']['matches'][0].update(format='html'),
            lambda v: v['semantic_search']['matches'][0]['reference'].update(version=3),
            lambda v: v['semantic_search']['matches'][0]['reference'].update(artifact_id='outside')]
        for mutate in changes:
            wrong = copy.deepcopy(output)
            mutate(wrong)
            with self.assertRaises(ValueError):
                auth.discovery_response(source, auth.encoded(wrong))
        raw = auth.encoded(output)
        for invalid in (b'', raw.decode(), b' '*auth.MAX_QUERY_OUTPUT,
                        raw.replace(b'"committed":false', b'"committed":false,"committed":false')):
            with self.assertRaises(ValueError):
                auth.discovery_response(source, invalid)

    def test_unique_score_ordered_hits_and_exact_truncation(self):
        _, source, _, output = fixture()
        for mutate in (lambda v: v['matches'].reverse(),
            lambda v: v['matches'].__setitem__(1, copy.deepcopy(v['matches'][0])),
            lambda v: v.update(matches=v['matches'][:1]),
            lambda v: v.update(total_matches=True)):
            wrong = copy.deepcopy(output)
            mutate(wrong['semantic_search'])
            with self.assertRaises(ValueError):
                auth.discovery_response(source, auth.encoded(wrong))
        truncated = copy.deepcopy(output)
        truncated['semantic_search']['matches'].pop()
        truncated['semantic_search']['truncated'] = True
        self.assertEqual(len(auth.discovery_response(source, auth.encoded(truncated))['matches']), 1)
        tied = copy.deepcopy(output)
        tied['semantic_search']['matches'][1]['cosine_millionths'] = 900000
        self.assertEqual(len(auth.discovery_response(source, auth.encoded(tied))['matches']), 2)
        tied['semantic_search']['matches'].reverse()
        with self.assertRaises(ValueError):
            auth.discovery_response(source, auth.encoded(tied))

    def test_exact_collection_join_and_empty_collection_no_fallback(self):
        for empty in (False, True):
            _, source, result, output = fixture(collection=True, empty=empty)
            self.assertEqual(auth.discovery_response(source, auth.encoded(output)), result)
            wrong = copy.deepcopy(output)
            wrong['semantic_collection_search']['collection']['version'] += 1
            with self.assertRaises(ValueError):
                auth.discovery_response(source, auth.encoded(wrong))
            wrong = copy.deepcopy(output)
            wrong['semantic_collection_search']['search']['matches'] += [dict(reference=reference(), format='json', cosine_millionths=1)]
            with self.assertRaises(ValueError):
                auth.discovery_response(source, auth.encoded(wrong))

    def journey(self, choices, collection=False, empty=False, failure=None, output_mutation=None):
        value, source, result, output = fixture(collection, empty)
        if output_mutation is not None:
            output_mutation(output)
        observed = []
        def query(arguments):
            observed.append((arguments, Path(arguments[-1]).read_bytes()))
            if len(observed) == 1:
                return inspection(source)
            if failure is not None:
                raise failure
            return auth.encoded(output)
        with tempfile.TemporaryDirectory(prefix='luma-discovery-control-', dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as temporary:
            directory = Path(temporary)
            stream = io.StringIO()
            with patch.object(auth, 'canonical_native_request', return_value=(value['request'], None)), \
                 patch.object(auth, 'protected'), patch.object(auth, 'capture_query', side_effect=query), \
                 patch.object(auth, 'envelope_read', return_value=None) as read, \
                 patch('sys.stdin', io.StringIO(choices)), patch('sys.stdout', stream):
                error = None
                try:
                    code = auth.discovery_journey(value, directory)
                except (ValueError, EOFError, KeyboardInterrupt) as caught:
                    error, code = caught, None
                reads = [copy.deepcopy(call.args[0]) for call in read.call_args_list]
            self.assertEqual(list(directory.iterdir()), [])
        return code, error, observed, reads, stream.getvalue(), source

    def test_each_exact_hit_requires_new_envelope_ceremony_never_search_grant(self):
        code, error, observed, reads, text, source = self.journey('search-read\n2\n1\nq\n')
        self.assertEqual(code, 0)
        self.assertIsNone(error)
        self.assertEqual(len(observed), 2)
        self.assertEqual(observed[0][0][4], 'content-owned-inspection-review')
        self.assertEqual(observed[1][0][4:7], ['content-owned-review', 'alice', 'search-read'])
        self.assertEqual(observed[0][1], observed[1][1])
        self.assertEqual(len(reads), 2)
        for value, expected in zip(reads, reversed(source['operation']['references'])):
            self.assertEqual(value['operation'], 'envelope-read')
            self.assertTrue(all(value[key] == '' for key in ('read_grant', 'effect_grant', 'approval')))
            read = auth.envelope_request(auth.strict_json(value['request']))
            self.assertEqual(read['binding'], source['binding'])
            self.assertEqual(read['operation']['expected'], expected)
        self.assertIn('not reused', text)

    def test_cancel_empty_failure_and_invalid_result_never_open_private_hit(self):
        cases = [('q\n', {}, 1), ('search-read\n', dict(empty=True, collection=True), 2),
                 ('search-read\n', dict(failure=ValueError('revoked')), 2),
                 ('search-read\n', dict(output_mutation=lambda v: v.update(authority_returned=True)), 2),
                 ('search-read\n0\n', {}, 2), ('search-read\n33\n', {}, 2)]
        for choices, options, count in cases:
            code, error, observed, reads, text, _ = self.journey(choices, **options)
            self.assertEqual(len(observed), count)
            self.assertEqual(reads, [])
            if options.get('failure') or options.get('output_mutation'):
                self.assertIsNotNone(error)
                self.assertNotIn('Actual native semantic results observed', text)
            elif choices == 'q\n' or options.get('empty'):
                self.assertEqual(code, 0)

    def test_bounded_selection_count_and_no_retry_after_interrupted_read(self):
        code, error, _, reads, text, _ = self.journey('search-read\n'+'1\n'*16)
        self.assertEqual(code, 0)
        self.assertIsNone(error)
        self.assertEqual(len(reads), 16)
        self.assertIn('16-selection bound', text)
        value, *_ = fixture()
        with tempfile.TemporaryDirectory(prefix='luma-discovery-interrupted-', dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as temporary, \
             patch.object(auth, 'canonical_native_request', return_value=(value['request'], None)), \
             patch.object(auth, 'protected'), patch.object(auth, 'capture_query',
                side_effect=[inspection(auth.strict_json(value['request'])), auth.encoded(fixture()[3])]), \
             patch.object(auth, 'envelope_read', side_effect=KeyboardInterrupt()) as read, \
             patch('sys.stdin', io.StringIO('search-read\n1\n1\n')), patch('sys.stdout', io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                auth.discovery_journey(value, Path(temporary))
            self.assertEqual(read.call_count, 1)
            self.assertEqual(list(Path(temporary).iterdir()), [])


def actual_native(binary):
    host_spec = importlib.util.spec_from_file_location('luma_discovery_native_host', ROOT / 'native/desktop/workspace_host.py')
    host = importlib.util.module_from_spec(host_spec)
    host_spec.loader.exec_module(host)
    import threading
    for collection in (False, True):
        value, source, *_ = fixture(collection)
        if not collection:
            source['operation']['references'][0]['version'] = 2**64-1
        value['request'] = auth.encoded(source).decode()
        pinned = host.PinnedExecutable(Path(binary))
        try:
            state, output = host.run_process(pinned, 'content-contract-native-request',
                value['request'].encode(), threading.Event(), lambda _: None)
        finally:
            pinned.close()
        assert state == 'completed'
        prepared = auth.canonical_response(value, output)
        assert auth.discovery_request(auth.strict_json(prepared)) == source
    print('PASS: 2 actual native discovery canonicalizer selections, including full u64; no private read/PAM qualification', flush=True)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--native-cli':
        actual_native(sys.argv[2])
    else:
        unittest.main()
