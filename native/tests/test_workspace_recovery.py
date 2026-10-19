"""Native terminal recovery controller over explicitly inert transport fixtures.

No fixture authorizes PAM, decrypts an archive, publishes content or changes TPM.
The optional --native-cli lane invokes real bounded rootless DATA canonicalizers.
Installed graphical/native security and hardware qualification remain separate.
"""
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('luma_workspace_recovery_auth', ROOT/'native/desktop/workspace_auth.py')
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture(reviewed=False):
    source = dict(schema_version=1, login='admin', admin=dict(installation='1'*64, owner='2'*64, owner_generation=3),
        target_login='alice', target=dict(installation='1'*64, owner='3'*64, owner_generation=1),
        independently_selected_origin_spki_sha256='4'*64, request_namespace='restore-one', key_role='offline-admin',
        capsule_path='/home/admin/evidence.cms', capsule_bytes=4096, capsule_sha256='5'*64, review=None)
    graph = b'luma-fresh-owner-custody-restore-graph-v1:verify-independent-origin;decrypt-inert-data;replay-all-published-chronologically;remap-prior-typed-references;original-admin-finite-batch;held-source;C-anchor-before-rename;fresh-same-state-read;retain-encrypted-origin-evidence'
    review = dict(schema_version=1, profile='luma-fresh-owner-content-restore-v1',
        origin=dict(installation='6'*64, owner='7'*64, owner_generation=1), target=source['target'],
        archive_sha256='8'*64, archive_bytes=2048, manifest_sha256='9'*64, origin_head_sha256='a'*64,
        workflow_sha256=sha(graph), request_namespace=source['request_namespace'], published_outcomes=1,
        inert_committed_outcomes=1, inert_pending_directories=1, inert_quarantined_directories=1,
        planned_storage_bytes=8192, mappings_sha256='b'*64,
        steps=[dict(request_id='restore-one.1', review_sha256='c'*64)], review_sha256='')
    review['review_sha256'] = sha(auth.encoded(review))
    if reviewed:
        source['review'] = review
    value = dict(schema_version=1, operation='restore-journey', login='admin', read_grant='', effect_grant='',
        approval='', request=auth.encoded(source).decode())
    return value, source, review


def scope(source, effect=False):
    write = source['review'] is not None
    return dict(action=('artifact.write' if write else 'resource.recover') if effect else 'file.read',
        selector=dict(kind=('artifact' if write else 'resource') if effect else 'file',
            id=('native-content-restore-write-v1' if write else 'native-content-restore-review-v1') if effect else 'native-content-restore-read-v1',
            generation=source['admin']['owner_generation'], digest='d'*64), input_bytes=source['capsule_bytes'],
        output_bytes=64*1024*1024 if effect and write else auth.MAX_RECOVERY_OUTPUT,
        units=source['review']['published_outcomes'] if effect and write else 1)


def proposal(source):
    return dict(schema_version=1, request_sha256=sha(auth.encoded(dict(source, capsule_path='/runtime-original-snapshot/content-restore.cms'))),
        read_usage=scope(source), effect_usage=scope(source, True), private_key_read=False, archive_decrypted=False,
        target_content_changed=False, grant_issued=False, authority_returned=False)


def review_output(review):
    return dict(schema_version=1, restore_review=review, origin_signature_valid=True, custody_capacity_policy=dict(inert_fixture=True),
        archive_validated=True, decrypted_data_delivered=False, target_content_changed=False, restore_permitted=False,
        authority_returned=False, credentials_restored=False, encrypted_evidence_must_be_retained=True)


def completion(source):
    return dict(schema_version=1, restore_review_sha256=source['review']['review_sha256'], published_outcomes=1,
        custody_capacity_policy=dict(inert_fixture=True), current_state=dict(binding=source['target'], outcome_count=1,
            head_sha256='e'*64, quarantine_sha256='f'*64), origin_signature_valid=True, credentials_restored=False,
        grants_restored=False, TPM_state_restored=False, original_encrypted_evidence_must_be_retained=True,
        encrypted_evidence_sha256=source['capsule_sha256'], authority_returned=False, production_qualified=False)


def canonical(value):
    source = auth.strict_json(value['request'])
    data = auth.encoded(source).decode()
    if value['operation'] == 'retire-journey':
        result = dict(schema_version=1, canonical_request=data, request_sha256=sha(data.encode()),
            phase='inspect-protected-retirement' if source['expected_review_sha256'] is None else 'recover-exact-protected-review',
            usage=auth.retirement_scope_data(source), protected_review_authenticated=False, private_authority_read=False,
            admin_authenticated=False, grant_issued=False, owner_marked_unavailable=False, authority_returned=False)
    else:
        result = dict(schema_version=1, canonical_request=data,
            semantic_request_sha256=sha(auth.encoded(dict(source, capsule_path='/runtime-original-snapshot/content-restore.cms'))),
            private_key_read=False, archive_decrypted=False, target_content_changed=False, grant_issued=False, authority_returned=False)
    return result


def retirement(source):
    reviewed = dict(schema_version=1, purpose='luma-content-restore-terminal-disposition-v1',
        installation=source['target']['installation'], binding=source['target'], batch_review_sha256=source['review']['review_sha256'],
        capsule_sha256=source['capsule_sha256'], origin_spki_sha256=source['independently_selected_origin_spki_sha256'],
        start_sha256='a'*64, checkpoint_head='b'*64,
        state=dict(binding=source['target'], outcome_count=0, head_sha256='c'*64, quarantine_sha256='d'*64),
        disposition='mark-owner-generation-unavailable-preserve-all-published-pending-quarantine-bytes')
    return dict(schema_version=1, review=reviewed, review_sha256=sha(auth.encoded(reviewed)),
        owner_marked_unavailable=False, content_bytes_changed=False, TPM_extended=False, authority_returned=False)


def retired(source, wanted):
    return dict(schema_version=1, binding=source['target'], review_sha256=wanted, owner_marked_unavailable=True,
        checkpoint_head='e'*64, content_bytes_changed=False, published_records_rolled_back=False,
        pending_evidence_removed=False, damaged_data_healed=False,
        new_restore_requires_independently_provisioned_fresh_owner_binding=True, authority_returned=False, production_qualified=False)


class WorkspaceRecoveryTests(unittest.TestCase):
    def test_closed_public_data_has_no_secret_or_authority_fields_or_identity_defaults(self):
        value, source, review = fixture()
        self.assertEqual(auth.proposal(value), value)
        for field in ('password', 'private_key', 'pkcs8', 'grant', 'command', 'restore_permitted'):
            wrong = dict(source, **{field: 'never'})
            with self.assertRaises(ValueError):
                auth.proposal(dict(value, request=auth.encoded(wrong).decode()))
        for field, invalid in [('schema_version', True), ('capsule_bytes', True), ('capsule_bytes', 0),
            ('key_role', 'default'), ('capsule_path', 'relative.cms'), ('capsule_path', '/tmp/x\0cms'),
            ('capsule_sha256', '0'*64), ('request_namespace', 'escape/../')]:
            with self.assertRaises(ValueError):
                auth.recovery_request(dict(source, **{field: invalid}))
        for name in ('read_grant', 'effect_grant', 'approval'):
            with self.assertRaises(ValueError):
                auth.proposal(dict(value, **{name: 'preselected'}))
        with self.assertRaises(ValueError):
            auth.terminal_arguments(value, Path('/inert/request'))
        with self.assertRaises(ValueError):
            auth.recovery_request(dict(input=source, expected_review_sha256=None), retirement=True)
        source['review'] = review
        request = dict(input=source, expected_review_sha256=None)
        self.assertEqual(auth.recovery_request(request, retirement=True), source)
        with self.assertRaises(ValueError):
            auth.recovery_request(dict(request, expected_review_sha256='f'*64), retirement=True)

    def test_native_canonicalizer_cannot_substitute_data_or_claim_authentication(self):
        for retired_mode in (False, True):
            value, source, _ = fixture(retired_mode)
            if retired_mode:
                value = dict(value, operation='retire-journey', request=auth.encoded(dict(input=source, expected_review_sha256=None)).decode())
            result = canonical(value)
            self.assertEqual(auth.recovery_canonical_response(value, auth.encoded(result)), value['request'])
            for flag in ('authority_returned', 'grant_issued', 'private_authority_read' if retired_mode else 'private_key_read'):
                with self.assertRaises(ValueError):
                    auth.recovery_canonical_response(value, auth.encoded(dict(result, **{flag: True})))
            for field, invalid in [('schema_version', True), ('canonical_request', '{}'), ('extra', False),
                ('phase' if retired_mode else 'semantic_request_sha256', 'wrong')]:
                with self.assertRaises(ValueError):
                    auth.recovery_canonical_response(value, auth.encoded(dict(result, **{field: invalid})))
            duplicate = auth.encoded(result).replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1)
            with self.assertRaises(ValueError):
                auth.recovery_canonical_response(value, duplicate)

    def test_review_scope_and_completion_bind_exact_owner_review_prefix_and_evidence(self):
        _, source, review = fixture()
        auth.recovery_proposal(source, auth.encoded(proposal(source)))
        auth.recovery_reviewed(source, auth.encoded(review_output(review)))
        for field, invalid in [('published_outcomes', True), ('published_outcomes', 257), ('target', source['admin']),
            ('request_namespace', 'substitute'), ('review_sha256', 'f'*64), ('planned_storage_bytes', 1), ('extra', False)]:
            with self.assertRaises(ValueError):
                auth.restore_review(dict(review, **{field: invalid}), source)
        wrong = copy.deepcopy(proposal(source)); wrong['effect_usage']['selector']['digest'] = 'f'*64
        with self.assertRaises(ValueError):
            auth.recovery_proposal(source, auth.encoded(wrong))
        for field, invalid in [('generation', True), ('id', 'native-content-store-v1')]:
            wrong = copy.deepcopy(proposal(source)); wrong['read_usage']['selector'][field] = invalid
            with self.assertRaises(ValueError):
                auth.recovery_proposal(source, auth.encoded(wrong))
        source['review'] = review
        done = completion(source)
        self.assertEqual(auth.recovery_completed(source, auth.encoded(done)), done)
        for mutate in (lambda v: v.update(restore_review_sha256='a'*64), lambda v: v.update(published_outcomes=True),
            lambda v: v.update(credentials_restored=True), lambda v: v.update(encrypted_evidence_sha256='b'*64),
            lambda v: v['current_state'].update(binding=source['admin']), lambda v: v['current_state'].update(outcome_count=0),
            lambda v: v.update(authority_returned=True), lambda v: v.update(extra=False)):
            wrong = copy.deepcopy(done); mutate(wrong)
            with self.assertRaises(ValueError):
                auth.recovery_completed(source, auth.encoded(wrong))

    def test_fixed_recovery_argv_never_selects_executable_or_sends_secret(self):
        path = Path('/inert/exact-request')
        args = auth.recovery_arguments('content-restore-apply', 'admin', path, 'read-one', 'write-one')
        self.assertEqual(args, ['/usr/bin/sudo', '--', auth.NATIVE, 'granted-run', 'content-restore-apply', 'admin', 'read-one', 'write-one', str(path)])
        for command, grants in [('shell', ()), ('content-restore-apply', ('one', 'one')), ('content-restore-review', ('-flag', 'two')),
            ('content-restore-proposal', ('unwanted',)), ('content-restore-retire', ())]:
            with self.assertRaises(ValueError):
                auth.recovery_arguments(command, 'admin', path, *grants)
        with patch.object(auth, '_capture_native', return_value=b'inert') as capture:
            auth.capture_recovery('content-restore-review', dict(login='admin'), path, 'read', 'recover')
            self.assertEqual(capture.call_args.args[1], 96*1024)
            self.assertEqual(capture.call_args.args[0][-1], str(path))
        for maximum in (0, 96*1024+1):
            with self.assertRaises(ValueError):
                auth._capture_native([], maximum)

    def test_restore_review_preserves_inert_sequence_gaps_but_refuses_reorder_duplicates_and_overflow(self):
        _, source, reviewed = fixture()
        reviewed['published_outcomes'] = 2
        reviewed['inert_committed_outcomes'] = 1
        reviewed['planned_storage_bytes'] = 16384
        reviewed['steps'] = [dict(request_id='restore-one.1', review_sha256='a'*64),
                             dict(request_id='restore-one.3', review_sha256='b'*64)]

        def signed_data(value):
            value['review_sha256'] = ''
            value['review_sha256'] = sha(auth.encoded(value))
            return value

        signed_data(reviewed)
        self.assertEqual(auth.restore_review(reviewed, source), reviewed)
        # The original native response is serde_json::Value, not struct order.
        sorted_review = auth.strict_json(json.dumps(reviewed, sort_keys=True))
        self.assertEqual(auth.restore_review(sorted_review, source)['steps'][1]['request_id'], 'restore-one.3')
        invalid_ids = [('restore-one.3', 'restore-one.1'), ('restore-one.1', 'restore-one.1'),
            ('restore-one.1', 'restore-one.4'), ('restore-one.1', 'restore-one.257'),
            ('restore-one.1', 'restore-one.18446744073709551616'), ('restore-one.0', 'restore-one.3'),
            ('restore-one.01', 'restore-one.3'), ('restore-one.-1', 'restore-one.3'),
            ('restore-one.+1', 'restore-one.3'), ('restore-one.1', 'restore-one.3.0'),
            ('restore-other.1', 'restore-one.3'), ('restore-one.1', 'restore-one.٣')]
        for first, second in invalid_ids:
            wrong = copy.deepcopy(reviewed)
            wrong['steps'][0]['request_id'] = first
            wrong['steps'][1]['request_id'] = second
            signed_data(wrong)
            with self.subTest(first=first, second=second), self.assertRaises(ValueError):
                auth.restore_review(wrong, source)

    def run_journey(self, value, answers, *, fail=None):
        calls = []
        value = copy.deepcopy(value)
        original = auth.strict_json(value['request'])
        source = original['input'] if value['operation'] == 'retire-journey' else original
        reviewed = fixture()[2]

        @contextmanager
        def stage(directory, data):
            calls.append(('stage', auth.strict_json(data)))
            yield Path('/inert/staged-request')

        def prepare(v):
            return auth.recovery_canonical_response(v, auth.encoded(canonical(v))), None

        def retained(path, data):
            calls.append(('retained', auth.strict_json(data)))
            if fail == 'retain':
                raise OSError('explicit inert retention failure')
            return Path(path)

        def capture(command, selected, path, *grants):
            calls.append((command, copy.deepcopy(selected), grants))
            if command == fail:
                raise KeyboardInterrupt()
            if command == 'content-restore-proposal':
                return auth.encoded(proposal(selected))
            if command == 'content-restore-review':
                return auth.encoded(review_output(reviewed))
            if command == 'content-restore-apply':
                return b'{}' if fail == 'malformed-completion' else auth.encoded(completion(selected))
            if command == 'content-restore-retire-inspect':
                return auth.encoded(retirement(source))
            if command == 'content-restore-retire':
                return b'{}' if fail == 'malformed-completion' else auth.encoded(retired(source, retirement(source)['review_sha256']))
            raise AssertionError('unexpected fixed command '+command)

        class Output(io.StringIO):
            interrupted = False

            def write(self, text):
                if fail == 'completion-presentation' and not self.interrupted and text.startswith(('COMPLETED: actual', 'COMPLETED: genuine')):
                    self.interrupted = True
                    raise KeyboardInterrupt()
                return super().write(text)

        output = Output()
        with patch.object(auth, 'request_stage', stage), patch.object(auth, 'canonical_native_request', prepare), \
            patch.object(auth, 'capture_recovery', capture), patch.object(auth, 'retain_recovery_request', retained), \
            patch('sys.stdin', io.StringIO('\n'.join(answers)+'\n')), patch('sys.stdout', output):
            code = (auth.retire_journey if value['operation'] == 'retire-journey' else auth.restore_journey)(value, Path('/inert/runtime'))
        return code, output.getvalue(), calls

    def test_fresh_restore_and_exact_resume_retain_request_before_independent_apply(self):
        for resumed in (False, True):
            value, _, review = fixture(resumed)
            answers = ([] if resumed else ['read-review', 'recover-review'])+['read-apply', 'write-apply', 'restore:'+review['review_sha256'], '/home/admin/resume.json']
            code, output, calls = self.run_journey(value, answers)
            self.assertEqual(code, 0, output)
            self.assertIn('COMPLETED: actual native C-backed', output)
            commands = [item[0] for item in calls]
            self.assertEqual(commands.count('content-restore-review'), 0 if resumed else 1)
            self.assertEqual(commands.count('content-restore-apply'), 1)
            self.assertLess(commands.index('retained'), commands.index('content-restore-apply'))
            saved = next(item[1] for item in calls if item[0] == 'retained')
            self.assertEqual(saved['review']['review_sha256'], review['review_sha256'])
            self.assertNotIn('grant', saved)
            self.assertNotIn('private_key', saved)
            self.assertEqual(next(item[2] for item in calls if item[0] == 'content-restore-apply'), ('read-apply', 'write-apply'))

    def test_cancellation_refusal_and_interruption_never_fake_success_or_auto_retry(self):
        value, _, review = fixture()
        for answers in (['q'], ['read-review', 'q'], ['read-review', 'recover-review', 'q'],
            ['read-review', 'recover-review', 'read-apply', 'write-apply', 'q'],
            ['read-review', 'recover-review', 'read-apply', 'write-apply', 'restore:'+review['review_sha256'], 'q']):
            code, output, calls = self.run_journey(value, answers)
            self.assertEqual(code, 0, output)
            self.assertIn('CANCELLED', output)
            self.assertNotIn('COMPLETED:', output)
            self.assertFalse(any(item[0] == 'content-restore-apply' for item in calls))
        answers = ['read-review', 'recover-review', 'read-apply', 'write-apply', 'restore:'+review['review_sha256'], '/home/admin/resume.json']
        for failure in ('retain', 'content-restore-review', 'content-restore-apply', 'malformed-completion'):
            code, output, calls = self.run_journey(value, answers, fail=failure)
            self.assertEqual(code, 1, output)
            self.assertNotIn('COMPLETED:', output)
            commands = [item[0] for item in calls]
            self.assertLessEqual(commands.count('content-restore-apply'), 1)
            if failure in ('content-restore-apply', 'malformed-completion'):
                self.assertIn('UNCERTAIN / POSSIBLY PARTIAL', output)
                self.assertIn(json.dumps(str(Path('/home/admin/resume.json')), ensure_ascii=True), output)
            else:
                self.assertIn('before restore apply', output)
                self.assertNotIn('content-restore-apply', commands)
        code, output, calls = self.run_journey(value, answers, fail='completion-presentation')
        self.assertEqual(code, 1, output)
        self.assertIn('COMPLETED native restore result was validated', output)
        self.assertNotIn('before restore apply', output)
        self.assertNotIn('UNCERTAIN / POSSIBLY PARTIAL', output)

    def test_retirement_requires_actual_protected_review_separate_grant_and_exact_generation(self):
        value, source, _ = fixture(True)
        request = dict(input=source, expected_review_sha256=None)
        value = dict(value, operation='retire-journey', request=auth.encoded(request).decode())
        checked = retirement(source)
        auth.retirement_reviewed(source, auth.encoded(checked))
        # serde_json::Value response sorts keys, but its nested typed state SHA
        # commits the original Rust struct field order, not response JSON order.
        sorted_response = json.dumps(checked, sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(auth.retirement_reviewed(source, sorted_response)['review_sha256'], checked['review_sha256'])
        wrong = copy.deepcopy(checked); wrong['review']['binding']['owner_generation'] += 1
        with self.assertRaises(ValueError):
            auth.retirement_reviewed(source, auth.encoded(wrong))
        wanted = checked['review_sha256']
        answers = ['read-retire', 'recover-retire', 'retire:'+wanted, '/home/admin/retirement.json']
        code, output, calls = self.run_journey(value, answers)
        self.assertEqual(code, 0, output)
        self.assertIn('COMPLETED: genuine protected owner-generation retirement', output)
        self.assertIn('not healed or rolled back', output)
        commands = [item[0] for item in calls]
        self.assertLess(commands.index('retained'), commands.index('content-restore-retire'))
        for answers in (['q'], ['read-retire', 'q'], ['read-retire', 'recover-retire', 'q']):
            code, output, calls = self.run_journey(value, answers)
            self.assertEqual(code, 0, output)
            self.assertFalse(any(item[0] == 'content-restore-retire' for item in calls))
            self.assertNotIn('COMPLETED:', output)
        code, output, calls = self.run_journey(value, ['read-retire', 'recover-retire', 'retire:'+wanted, '/home/admin/retirement.json'], fail='content-restore-retire')
        self.assertEqual(code, 1, output)
        self.assertIn('UNCERTAIN: protected retirement', output)
        self.assertEqual(sum(item[0] == 'content-restore-retire' for item in calls), 1)
        code, output, calls = self.run_journey(value, ['read-retire', 'recover-retire', 'retire:'+wanted, '/home/admin/retirement.json'], fail='completion-presentation')
        self.assertEqual(code, 1, output)
        self.assertIn('COMPLETED protected retirement result was validated', output)
        self.assertNotIn('UNCERTAIN: protected retirement', output)

    def test_actual_durable_inert_retention_never_overwrites_or_follows_aliases(self):
        root = os.environ['LUMA_STORAGE_TEST_ROOT']
        with tempfile.TemporaryDirectory(prefix='workspace-resume-', dir=root) as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            value, _, _ = fixture(True)
            target = directory/'resume.json'
            auth.retain_recovery_request(target, value['request'])
            self.assertEqual(target.read_bytes(), value['request'].encode())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                auth.retain_recovery_request(target, value['request'])
            alias = directory/'alias.json'
            alias.symlink_to(target)
            with self.assertRaises(FileExistsError):
                auth.retain_recovery_request(alias, value['request'])
            parent = directory/'alias-parent'
            parent.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(ValueError):
                auth.retain_recovery_request(parent/'new.json', value['request'])
            self.assertFalse((directory/'new.json').exists())


def actual_native_compatibility(binary):
    """Real pure DATA endpoints only. No root/private hardware/native effects."""
    checked = 0
    for reviewed in (False, True):
        value, source, _ = fixture(reviewed)
        commands = [('content-restore-request', value)]
        if reviewed:
            for expected in (None, 'f'*64):
                commands.append(('content-restore-retire-request', dict(value, operation='retire-journey',
                    request=auth.encoded(dict(input=source, expected_review_sha256=expected)).decode())))
        for command, selected in commands:
            process = subprocess.run([str(binary), command], input=selected['request'].encode(), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=10, check=False)
            if process.returncode != 0:
                raise AssertionError('actual rootless DATA canonicalizer refused valid fixture: '+process.stderr.decode(errors='replace'))
            auth.recovery_canonical_response(selected, process.stdout)
            checked += 1
    print(json.dumps(dict(actual_native_data_canonicalizers_checked=checked, pam_authorized=False,
        archive_decrypted=False, restore_or_retirement_executed=False, installed_graphical_qualified=False)))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--native-cli':
        actual_native_compatibility(Path(sys.argv[2]).resolve(strict=True))
    else:
        unittest.main()
