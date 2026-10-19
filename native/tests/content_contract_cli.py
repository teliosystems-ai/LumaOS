#!/usr/bin/env python3
"""Execute the actual content-contract CLI as an unprivileged disposable UID.

Run only in the isolated tools container. No installed product paths or host
accounts are changed; supplied bindings are test data, never caller authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from html.parser import HTMLParser


class ContentContractCli(unittest.TestCase):
    binary = None

    @staticmethod
    def binding():
        return dict(installation='a' * 64, owner='b' * 64, owner_generation=7)

    @staticmethod
    def provenance(content, origin='managed'):
        return dict(request_id='fixture-edit', workflow_sha256='c' * 64,
                    source_sha256=hashlib.sha256(content.encode()).hexdigest(), origin=origin)

    def invoke(self, operation, request, valid=True):
        result = subprocess.run([str(self.binary), 'content-contract-' + operation],
            input=json.dumps(request).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, user=65534, group=65534, extra_groups=[], umask=0o077)
        if not valid:
            self.assertEqual(result.returncode, 1, 'crashes/loader failures are not valid refusals')
            self.assertTrue(result.stderr.startswith(b'luma-platform: '))
            self.assertEqual(result.stdout, b'')
            return None
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        output = json.loads(result.stdout)
        for field in ('owner_authenticated', 'authority_returned', 'committed', 'certified', 'gate_closing'):
            self.assertIs(output[field], False)
        return output['result']

    def capture(self, content, format='utf8-text'):
        return self.invoke('capture', dict(schema_version=1, binding=self.binding(),
            artifact_id='fixture-document', format=format, content=content,
            provenance=self.provenance(content)))['proposed']

    def table_request(self, version, operations):
        return dict(schema_version=1, current_envelope=version['canonical_envelope'],
            edit=dict(binding=self.binding(), expected=version['reference'],
                metadata=dict(request_id='table-edit', workflow_sha256='c' * 64),
                operations=operations))

    def test_unprivileged_capture_reopen_and_identity_are_deterministic(self):
        version = self.capture('Example\r\n')
        self.assertEqual(version, self.capture('Example\r\n'))
        envelope = version['canonical_envelope']
        self.assertEqual(json.loads(envelope)['content'], 'Example\n')
        result = self.invoke('reopen', dict(schema_version=1, binding=self.binding(), envelope=envelope))
        self.assertEqual(result['validated'], version)
        self.assertEqual(version['receipt']['binding'], self.binding())

    def test_spreadsheet_recalculates_exact_decimals_from_reopenable_source(self):
        source = dict(schema_version=1, rows=[[
            dict(kind='number', value='0.1'), dict(kind='number', value='0.2'),
            dict(kind='formula', expression=dict(op='binary', operator='add',
                left=dict(op='cell', row=0, column=0), right=dict(op='cell', row=0, column=1))) ]])
        output = self.invoke('spreadsheet', source)
        calculation = output['calculation']
        self.assertEqual(calculation['canonical_csv'], '0.1,0.2,0.3\n')
        self.assertEqual(calculation['csv_sha256'], hashlib.sha256(b'0.1,0.2,0.3\n').hexdigest())
        self.assertEqual(output, self.invoke('spreadsheet', json.loads(calculation['canonical_source'])))
        version = self.capture(calculation['canonical_source'], 'json')
        stored_source = json.loads(version['canonical_envelope'])['content']
        self.assertEqual(calculation, self.invoke('spreadsheet', json.loads(stored_source))['calculation'])
        self.assertIs(output['source_retained'], False)
        self.assertIs(output['csv_formula_text_executed'], False)

    def test_spreadsheet_cycles_rounding_and_unknown_execution_are_refused(self):
        for expression in [dict(op='cell', row=0, column=0),
                dict(op='binary', operator='divide', left=dict(op='number', value='1'),
                    right=dict(op='number', value='3')),
                dict(op='shell', command='id')]:
            self.invoke('spreadsheet', dict(schema_version=1,
                rows=[[dict(kind='formula', expression=expression)]]), valid=False)

    def test_spreadsheet_csv_formula_looking_text_stays_inert(self):
        output = self.invoke('spreadsheet', dict(schema_version=1,
            rows=[[dict(kind='text', value='=IMPORTDATA("https://example.invalid")')]]))
        self.assertIs(output['csv_formula_text_executed'], False)
        self.assertEqual(output['calculation']['values'][0][0],
            dict(kind='text', value='=IMPORTDATA("https://example.invalid")'))
        self.assertEqual(output['calculation']['canonical_csv'],
            '"=IMPORTDATA(""https://example.invalid"")"\n')

    def test_document_html_escapes_source_and_reopens_from_stored_json(self):
        source = dict(schema_version=1, title='Editable', blocks=[dict(kind='paragraph',
            runs=[dict(kind='text', text='<script src="https://example.invalid">é</script>')])])
        output = self.invoke('document', source)
        rendered = output['rendering']
        html = rendered['canonical_html']
        self.assertNotIn('<script', html)
        self.assertIn('&lt;script', html)
        self.assertEqual(hashlib.sha256(html.encode()).hexdigest(), rendered['html_sha256'])
        parser = HTMLParser(convert_charrefs=True)
        parser.feed(html)
        parser.close()
        version = self.capture(rendered['canonical_source'], 'json')
        stored = json.loads(version['canonical_envelope'])['content']
        self.assertEqual(self.invoke('document', json.loads(stored)), output)
        self.assertIs(output['scripts_executed'], False)
        self.assertIs(output['external_resources_loaded'], False)

    def test_diagram_outputs_well_formed_svg_and_reopens_editable_geometry(self):
        source = dict(schema_version=1, title='Diagram', width=320, height=240,
            nodes=[dict(id='node-one', x=10, y=20, width=80, height=40,
                shape='rounded-rectangle', fill='blue', label='<safe>')], edges=[])
        output = self.invoke('diagram', source)
        rendered = output['rendering']
        root = ET.fromstring(rendered['canonical_svg'])
        self.assertEqual(root.tag, '{http://www.w3.org/2000/svg}svg')
        self.assertEqual(root.attrib['role'], 'img')
        self.assertEqual(hashlib.sha256(rendered['canonical_svg'].encode()).hexdigest(), rendered['svg_sha256'])
        self.assertEqual(self.invoke('diagram', json.loads(rendered['canonical_source'])), output)

    def test_diagram_refuses_xml_forbidden_unicode_instead_of_emitting_invalid_svg(self):
        for character in ('\ufffe', '\uffff'):
            self.invoke('diagram', dict(schema_version=1, title=character, width=100,
                height=100, nodes=[], edges=[]), valid=False)

    def test_animation_frames_are_real_svg_with_exact_positions_without_playback(self):
        source = dict(schema_version=1, width=100, height=100, frames_per_second=30,
            frame_count=3, background='#ffffff', sprites=[dict(id='box',
                shape=dict(kind='rectangle', width=10, height=10), fill='#000000',
                keyframes=[dict(frame=0, x=0, y=0), dict(frame=2, x=3, y=-3)])])
        output = self.invoke('animation', source)
        self.assertIs(output['playback_started'], False)
        self.assertIs(output['scripts_executed'], False)
        frames = output['rendering']['frames']
        self.assertEqual(len(frames), 3)
        for index, frame in enumerate(frames):
            self.assertEqual(frame['index'], index)
            root = ET.fromstring(frame['canonical_svg'])
            sprite = next(node for node in root if node.attrib.get('id') == 'box')
            self.assertEqual(sprite.attrib['x'], str([0, 1, 3][index]))
            self.assertEqual(sprite.attrib['y'], str([0, -2, -3][index]))
            self.assertEqual(hashlib.sha256(frame['canonical_svg'].encode()).hexdigest(), frame['svg_sha256'])
        self.assertEqual(output, self.invoke('animation', json.loads(output['rendering']['canonical_source'])))

    def test_renderers_refuse_active_unknown_or_invalid_structures_without_partial_output(self):
        self.invoke('document', dict(schema_version=1, title='x', blocks=[
            dict(kind='rule', onclick='launch')]), valid=False)
        self.invoke('diagram', dict(schema_version=1, title='x', width=100,
            height=100, nodes=[], edges=[dict(id='e', **{'from':'missing'}, from_port='east',
                to='also-missing', to_port='west', arrow='none', label='')]), valid=False)
        self.invoke('animation', dict(schema_version=1, width=100, height=100,
            frames_per_second=30, frame_count=1, background='url(https://example.invalid)', sprites=[]), valid=False)

    def test_renderers_support_blank_outputs_and_delete_all_sources(self):
        self.assertIn('<main>\n</main>', self.invoke('document', dict(schema_version=1,
            title='Blank', blocks=[]))['rendering']['canonical_html'])
        self.assertNotIn('data-node-id', self.invoke('diagram', dict(schema_version=1,
            title='Blank', width=100, height=100, nodes=[], edges=[]))['rendering']['canonical_svg'])
        output = self.invoke('animation', dict(schema_version=1, width=100, height=100,
            frames_per_second=1, frame_count=1, background='#ffffff', sprites=[]))
        self.assertEqual(len(output['rendering']['frames']), 1)

    def test_managed_render_native_request_retains_exact_source_without_claiming_publication(self):
        source = '{ "schema_version":1, "rows":[[{"kind":"number","value":"2"}]] }\n'
        request = dict(schema_version=1, login='alice', binding=self.binding(), operation=dict(kind='render',
            request=dict(binding=self.binding(), artifact_id='sheet-one', expected=None,
                metadata=dict(request_id='render-one', workflow_sha256='c'*64),
                engine='spreadsheet', source=source)))
        output = self.invoke('native-request', request)
        self.assertEqual(json.loads(output['canonical_request']), request)
        self.assertIs(output['private_content_read'], False)
        request['operation']['request']['binding']['owner_generation'] = 8
        self.invoke('native-request', request, valid=False)

    def test_explicit_collection_source_prepares_exact_bytes_without_membership_authority(self):
        source = dict(schema_version=1, kind='luma-explicit-collection-v1',
            collection_id='work-items', name='Work items', members=[])
        result = self.invoke('collection', source)
        self.assertEqual(result['artifact_id'], 'collection.work-items')
        canonical = result['canonical_source']
        self.assertEqual(json.loads(canonical), source)
        self.assertEqual(result['source_sha256'], hashlib.sha256(canonical.encode()).hexdigest())
        self.assertIs(result['membership_is_authority'], False)
        self.assertIs(result['membership_validated_against_private_history'], False)
        request = dict(schema_version=1, login='alice', binding=self.binding(), operation=dict(
            kind='collection', source=source, expected=None, provenance=self.provenance(canonical, 'external')))
        prepared = self.invoke('native-request', request)
        self.assertEqual(json.loads(prepared['canonical_request']), request)
        self.assertIs(prepared['private_content_read'], False)

    def test_collection_and_preparation_queries_are_closed_data_not_grants(self):
        reference = dict(artifact_id='collection.work-items', version=1,
            content_sha256='a'*64, receipt_sha256='b'*64)
        operations = [dict(kind='collection-current', collection_id='work-items'),
            dict(kind='collection-search', expected=reference, query='exact words', limit=32),
            dict(kind='collection-page', expected=reference, offset=0, limit=32),
            dict(kind='collections-for-member', member=reference, offset=0, limit=32),
            dict(kind='preparation', target='a'*64)]
        for operation in operations:
            request = dict(schema_version=1, login='alice', binding=self.binding(), operation=operation)
            result = self.invoke('native-request', request)
            self.assertEqual(json.loads(result['canonical_request']), request)
            self.assertIs(result['private_content_read'], False)
        for operation in [dict(kind='collection-current', collection_id='../escape'),
                dict(kind='collection-search', expected=reference, query='exact', limit=33),
                dict(kind='collection-search', expected=reference, query='https://invalid', limit=1),
                dict(kind='collection-page', expected=reference, offset=0, limit=33),
                dict(kind='collections-for-member', member=reference, offset=0, limit=0),
                dict(kind='preparation', target='not-a-hash')]:
            self.invoke('native-request', dict(schema_version=1, login='alice',
                binding=self.binding(), operation=operation), valid=False)

    def test_collection_sources_refuse_forged_shape_unknown_fields_and_unsorted_members(self):
        source = dict(schema_version=1, kind='luma-explicit-collection-v1',
            collection_id='work', name='Work', members=[])
        for modification in [dict(approved=True), dict(kind='automatic-collection'), dict(name='')]:
            self.invoke('collection', dict(source, **modification), valid=False)
        reference = dict(artifact_id='z', version=1, content_sha256='a'*64, receipt_sha256='b'*64)
        source['members'] = [reference, dict(reference, artifact_id='a')]
        self.invoke('collection', source, valid=False)

    def test_recovery_preparation_review_json_cannot_create_authority_or_skip_integrity(self):
        review = dict(schema_version=1, binding=self.binding(), outcome_count=0,
            outcome_head_sha256='c'*64, target='a'*64, pending=[], quarantined=[], review_sha256='b'*64)
        self.invoke('native-request', dict(schema_version=1, login='alice', binding=self.binding(),
            operation=dict(kind='recovery', review=review)), valid=False)

    def test_native_read_queries_are_inert_canonical_requests_not_apply_authority(self):
        reference = dict(artifact_id='document-one', version=1,
            content_sha256='a' * 64, receipt_sha256='b' * 64)
        for operation in [dict(kind='current', artifact_id='document-one'),
                dict(kind='historical', expected=reference),
                dict(kind='page', expected=reference, offset=0, bytes=16384),
                dict(kind='search', query='fox blue', limit=32)]:
            request = dict(schema_version=1, login='alice', binding=self.binding(), operation=operation)
            output = self.invoke('native-request', request)
            self.assertIs(output['private_content_read'], False)
            self.assertEqual(json.loads(output['canonical_request']), request)
            self.assertEqual(output['request_sha256'],
                hashlib.sha256(output['canonical_request'].encode()).hexdigest())
        for operation in [dict(kind='page', expected=reference, offset=0, bytes=16385),
                dict(kind='search', query='fox', limit=33),
                dict(kind='search', query='https://example.invalid', limit=1)]:
            self.invoke('native-request', dict(schema_version=1, login='alice',
                binding=self.binding(), operation=operation), valid=False)

    def test_json_keys_are_canonical_and_duplicate_keys_are_refused(self):
        version = self.capture('{"z":2,"a":1}', 'json')
        self.assertEqual(json.loads(version['canonical_envelope'])['content'], '{"a":1,"z":2}')
        content = '{"a":{"x":1,"x":2}}'
        self.invoke('capture', dict(schema_version=1, binding=self.binding(), artifact_id='document',
            format='json', content=content, provenance=self.provenance(content)), valid=False)

    def test_empty_text_and_delete_all_remain_editable_versions(self):
        blank = self.capture('')
        self.assertEqual(blank['receipt']['content_bytes'], 0)
        self.assertEqual(json.loads(blank['canonical_envelope'])['content'], '')
        original = self.capture('Original')
        request = dict(schema_version=1, binding=self.binding(), current_envelope=original['canonical_envelope'],
            expected=original['reference'], content='', provenance=self.provenance('', 'external'))
        cleared = self.invoke('compare', request)
        self.assertEqual(cleared['decision'], 'new-version')
        self.assertEqual(cleared['proposed']['receipt']['content_bytes'], 0)
        self.assertEqual(cleared['proposed']['receipt']['version'], 2)

    def test_csv_is_editable_and_ragged_rows_are_refused(self):
        version = self.capture('Name,Value\r\n"a,b",2\r\n', 'csv')
        self.assertEqual(json.loads(version['canonical_envelope'])['content'], 'Name,Value\n"a,b",2\n')
        content = 'Name,Value\nx\n'
        self.invoke('capture', dict(schema_version=1, binding=self.binding(), artifact_id='document',
            format='csv', content=content, provenance=self.provenance(content)), valid=False)

    def test_finite_decimal_json_roundtrips_without_repeated_numeric_changes(self):
        for number in ('0.246094891800000034', '0.247412855200000052', '0.223771953400000058'):
            version = self.capture(number, 'json')
            reopened = self.invoke('reopen', dict(schema_version=1, binding=self.binding(),
                envelope=version['canonical_envelope']))
            self.assertEqual(reopened['validated'], version)

    def test_owner_generation_and_content_substitution_are_refused(self):
        version = self.capture('Original\n')
        foreign = self.binding()
        foreign['owner_generation'] += 1
        self.invoke('reopen', dict(schema_version=1, binding=foreign,
            envelope=version['canonical_envelope']), valid=False)
        envelope = version['canonical_envelope'].replace('Original', 'Replaced')
        self.invoke('reopen', dict(schema_version=1, binding=self.binding(), envelope=envelope), valid=False)

    def test_external_edits_preserve_stale_candidate_without_overwrite(self):
        initial = self.capture('Original\n')
        request = dict(schema_version=1, binding=self.binding(),
            current_envelope=initial['canonical_envelope'], expected=initial['reference'],
            content='Changed\n', provenance=self.provenance('Changed\n', 'external'))
        changed = self.invoke('compare', request)
        self.assertEqual(changed['decision'], 'new-version')
        self.assertEqual(changed['proposed']['receipt']['version'], 2)
        request['current_envelope'] = changed['proposed']['canonical_envelope']
        conflict = self.invoke('compare', request)
        self.assertEqual(conflict['decision'], 'conflict')
        self.assertEqual(conflict['candidate']['content'], 'Changed\n')
        self.assertEqual(conflict['candidate']['binding'], self.binding())
        self.assertIs(conflict['automatically_merged'], False)
        request['expected'] = changed['proposed']['reference']
        self.assertEqual(self.invoke('compare', request)['decision'], 'no-change')

    def test_unsupported_schema_fields_formats_and_oversize_content_are_refused(self):
        request = dict(schema_version=1, binding=self.binding(), artifact_id='document',
            format='utf8-text', content='Example', provenance=self.provenance('Example'))
        for field, value in [('schema_version', 2), ('format', 'docx'), ('grant', 'not-authority')]:
            bad = dict(request, **{field: value})
            self.invoke('capture', bad, valid=False)
        oversized = 'x' * (1024 * 1024 + 1)
        self.invoke('capture', dict(request, content=oversized, provenance=self.provenance(oversized)), valid=False)

    def test_maximum_supported_documents_and_csv_row_count_reopen(self):
        for content, format in [('x' * (1024 * 1024), 'utf8-text'),
                                ('"' + 'x' * (1024 * 1024 - 2) + '"', 'json'),
                                ('x\n' * 10001, 'csv')]:
            version = self.capture(content, format)
            result = self.invoke('reopen', dict(schema_version=1, binding=self.binding(),
                envelope=version['canonical_envelope']))
            self.assertEqual(result['validated'], version)

    def test_table_edits_publish_one_immutable_proposal_with_exact_request_digest(self):
        initial = self.capture('Name,Value\nA,1\n', 'csv')
        operations = [dict(op='set-cell', row=1, column=1, value='2'),
            dict(op='insert-row', index=2, values=['B', '=SUM(A1)']),
            dict(op='insert-column', index=2, values=['Note', 'a,b', 'plain']),
            dict(op='delete-column', index=0), dict(op='delete-row', index=1)]
        request = self.table_request(initial, operations)
        result = self.invoke('table-edit', request)
        self.assertEqual(result, self.invoke('table-edit', request))
        outcome = result['outcome']
        self.assertEqual(outcome['decision'], 'new-version')
        proposed = outcome['proposed']
        self.assertEqual(json.loads(proposed['canonical_envelope'])['content'],
                         'Value,Note\n=SUM(A1),plain\n')
        self.assertEqual(proposed['receipt']['version'], 2)
        self.assertEqual(proposed['receipt']['previous'], initial['reference'])
        self.assertEqual(proposed['receipt']['provenance']['origin'], 'managed')
        self.assertEqual(proposed['receipt']['provenance']['source_sha256'],
                         hashlib.sha256(b'Value,Note\n=SUM(A1),plain\n').hexdigest())
        self.assertEqual(outcome['edit_sha256'],
                         hashlib.sha256(result['canonical_edit'].encode()).hexdigest())
        self.assertEqual(json.loads(result['canonical_edit']), request['edit'])
        self.assertIs(result['formulas_executed'], False)
        self.assertIs(result['request_retained'], False)
        self.assertEqual(self.invoke('reopen', dict(schema_version=1, binding=self.binding(),
                         envelope=initial['canonical_envelope']))['validated'], initial)

    def test_stale_table_edits_are_not_reinterpreted_against_changed_positions(self):
        initial = self.capture('A,B\nx,1\n', 'csv')
        request = self.table_request(initial, [dict(op='delete-row', index=1)])
        changed = self.invoke('table-edit', request)['outcome']['proposed']
        stale = self.table_request(initial, [dict(op='set-cell', row=1, column=1, value='2')])
        stale['current_envelope'] = changed['canonical_envelope']
        result = self.invoke('table-edit', stale)
        self.assertEqual(result['outcome']['decision'], 'conflict')
        self.assertEqual(result['outcome']['expected'], initial['reference'])
        self.assertEqual(result['outcome']['current'], changed['reference'])
        self.assertNotIn('proposed', result['outcome'])
        self.assertIs(result['outcome']['automatically_merged'], False)
        self.assertEqual(json.loads(result['canonical_edit']), stale['edit'])

    def test_table_noops_and_reversals_do_not_increment_versions(self):
        initial = self.capture('A,B\nx,1\n', 'csv')
        for operations in ([dict(op='set-cell', row=1, column=1, value='1')],
                           [dict(op='insert-row', index=2, values=['y', '2']),
                            dict(op='delete-row', index=2)]):
            result = self.invoke('table-edit', self.table_request(initial, operations))
            self.assertEqual(result['outcome']['decision'], 'no-change')
            self.assertEqual(result['outcome']['current'], initial['reference'])
            self.assertNotIn('proposed', result['outcome'])

    def test_table_invalid_batches_and_wrong_bindings_refuse_without_partial_output(self):
        initial = self.capture('A,B\nx,1\n', 'csv')
        for operations in ([], [dict(op='delete-row', index=-1)],
                [dict(op='insert-row', index=1, values=['ragged'])],
                [dict(op='set-cell', row=1, column=1, value='changed'),
                 dict(op='set-cell', row=99, column=0, value='invalid')],
                [dict(op='set-cell', row=1, column=1, value='x', authority=True)],
                [dict(op='set-cell', row=1, column=1, value='\x00')],
                [dict(op='set-cell', row=1, column=1, value='x' * 4097)],
                [dict(op='delete-column', index=0)] * 2,
                [dict(op='set-cell', row=1, column=1, value='x')] * 257):
            self.invoke('table-edit', self.table_request(initial, operations), valid=False)
        request = self.table_request(initial, [dict(op='set-cell', row=0, column=0, value='ok')])
        request['edit']['binding']['owner_generation'] += 1
        self.invoke('table-edit', request, valid=False)
        text = self.capture('not a table')
        self.invoke('table-edit', self.table_request(text,
                    [dict(op='set-cell', row=0, column=0, value='ok')]), valid=False)

    def test_native_content_request_preparation_is_unprivileged_exact_data_not_admission(self):
        content = 'Manual document\r\n'
        request = dict(schema_version=1, login='human', binding=self.binding(),
            operation=dict(kind='capture', artifact_id='manual-document', format='utf8-text',
                content=content, provenance=self.provenance(content)))
        prepared = self.invoke('native-request', request)
        canonical = prepared['canonical_request']
        self.assertEqual(json.loads(canonical), request)
        self.assertEqual(prepared['request_sha256'], hashlib.sha256(canonical.encode()).hexdigest())
        self.assertEqual(self.invoke('native-request', json.loads(canonical)), prepared)
        self.assertIs(prepared['private_content_read'], False)
        self.invoke('native-request', dict(request, grant='not-authority'), valid=False)
        bad = dict(request, operation=dict(request['operation'], content='Changed'))
        self.invoke('native-request', bad, valid=False)

    def test_unprivileged_callers_cannot_enter_native_content_effect_or_worker_paths(self):
        for command in ('content-owned-inspection-review', 'content-owned-review',
                        'content-owned-apply', 'content-resource-worker'):
            result = subprocess.run([str(self.binary), command], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                user=65534, group=65534, extra_groups=[], umask=0o077)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr,
                b'luma-platform: this operation requires a local administrator\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    if not Path('/.dockerenv').is_file() or os.geteuid() != 0:
        raise SystemExit('requires an isolated root tools container, not the development host')
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or binary.stat().st_size > 64 * 1024 * 1024:
        raise SystemExit('requires the actual bounded compiled platform binary')
    with tempfile.TemporaryDirectory(prefix='content-contract-cli-') as directory:
        root = Path(directory)
        root.chmod(0o755)
        copied = root / 'luma-platform'
        shutil.copyfile(binary, copied)
        copied.chmod(0o555)
        ContentContractCli.binary = copied
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(ContentContractCli))
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
