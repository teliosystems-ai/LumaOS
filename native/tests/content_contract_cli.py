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

    def test_unprivileged_capture_reopen_and_identity_are_deterministic(self):
        version = self.capture('Example\r\n')
        self.assertEqual(version, self.capture('Example\r\n'))
        envelope = version['canonical_envelope']
        self.assertEqual(json.loads(envelope)['content'], 'Example\n')
        result = self.invoke('reopen', dict(schema_version=1, binding=self.binding(), envelope=envelope))
        self.assertEqual(result['validated'], version)
        self.assertEqual(version['receipt']['binding'], self.binding())

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
