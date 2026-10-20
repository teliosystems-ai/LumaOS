"""Ordered software boundary fixtures, never installed PAM/TPM qualification."""
import copy
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


auth = load('lifecycle_auth_tests', 'native/desktop/workspace_auth.py')
controller = load('lifecycle_controller_tests', 'native/desktop/workspace_lifecycle.py')
recovery = load('lifecycle_recovery_tests', 'native/tests/test_workspace_recovery.py')


def reference(state='live', revision=2):
    return dict(version=dict(artifact_id='document.one', version=1, content_sha256='a'*64,
        receipt_sha256='b'*64), revision=revision, state_sha256='c'*64, status=state)


def source(operation='trash'):
    binding = dict(installation='1'*64, owner='2'*64, owner_generation=2**64-1)
    if operation == 'status':
        selected = dict(kind='lifecycle-status', artifact_id='document.one')
    else:
        intent = dict(schema_version=1, binding=binding, request_id='lifecycle.request.1', workflow_sha256='3'*64,
            expected=reference('live' if operation == 'trash' else 'trashed'), operation=operation,
            retention=controller.RETENTION)
        selected = dict(kind='lifecycle', request=intent)
    return dict(schema_version=1, login='alice', binding=binding, operation=selected)


def scope(native, action='file.read', kind='file', identifier='native-content-inspect-v1'):
    return dict(action=action, selector=dict(kind=kind, id=identifier,
        generation=native['binding']['owner_generation'], digest='d'*64),
        input_bytes=auth.MAX_REQUEST, output_bytes=auth.MAX_QUERY_OUTPUT, units=1)


def outputs(native, decision=None, replayed=False):
    query = native['operation']['kind'] == 'lifecycle-status'
    inspected = dict(schema_version=1, inspection_usage=scope(native, identifier=
        'native-content-trash-read-v1' if query else 'native-content-inspect-v1'), query_only=query,
        private_content_read=False, grant_issued=False, committed=False)
    if query:
        state = dict(schema_version=1, lifecycle=reference(), content_delivered=False, committed=False,
            authority_returned=False, physical_purge_available=False, retention=controller.RETENTION,
            restore_authorized=False, production_qualified=False)
        return inspected, state
    intent = native['operation']['request']
    desired = 'trashed' if intent['operation'] == 'trash' else 'restored'
    action, identifier, prefix = controller.action(native)
    decision = decision or desired
    reviewed = dict(schema_version=1, approval=prefix+'e'*64, review_sha256='e'*64, decision=decision,
        resulting=copy.deepcopy(intent['expected']['version']), derivation=None,
        source_bytes=len(auth.encoded(intent)), storage_bytes=16384,
        inspection_usage=scope(native), effect_usage=scope(native, action, 'artifact', identifier),
        committed=False, authority_returned=False, provenance_authority=False, workflow_executed=False,
        lifecycle_request=copy.deepcopy(intent), logical_only=True, physical_bytes_erased=False)
    if decision == 'conflict-retained':
        reviewed['resulting']['version'] = 2
    current = copy.deepcopy(intent['expected'])
    if decision == desired:
        current.update(status='trashed' if desired == 'trashed' else 'live', revision=3)
    current['version'] = copy.deepcopy(reviewed['resulting'])
    outcome = dict(sequence=3, request_id=intent['request_id'], review_sha256=reviewed['review_sha256'],
        decision=decision, resulting=reviewed['resulting'], source_sha256=hashlib.sha256(auth.encoded(intent)).hexdigest(),
        source_kind='lifecycle-intent', replayed=replayed)
    if replayed:
        current.update(status='live' if desired == 'trashed' else 'trashed', revision=5)
        current['version'] = dict(current['version'], version=2)
    completed = dict(schema_version=1, outcome=outcome, derivation=None, committed=True, authority_returned=False,
        provenance_authority=False, workflow_executed=False, lifecycle=current, requested_lifecycle=copy.deepcopy(intent),
        logical_only=True, physical_bytes_erased=False, historical_replay_is_not_a_new_state_change=True)
    return inspected, reviewed, completed


class LifecycleTests(unittest.TestCase):
    def proposal(self, native):
        return dict(schema_version=1, operation='lifecycle-journey', login=native['login'],
            read_grant='', effect_grant='', approval='', request=auth.encoded(native).decode())

    def test_exact_requests_retain_all_revisions_without_retargeting(self):
        for operation in ('status', 'trash', 'restore'):
            native = source(operation); original = copy.deepcopy(native)
            self.assertEqual(controller.request(auth, native), original)
            with patch.object(auth, 'workspace_controller', return_value=controller):
                self.assertEqual(auth.proposal(self.proposal(native)), self.proposal(original))
        bad = source(); bad['operation']['request']['expected']['revision'] = True
        with self.assertRaises(ValueError): controller.request(auth, bad)

    def test_no_purge_latest_binding_substitution_or_unknown_intent(self):
        for change in (dict(retention='erase-after-30days'), dict(operation='purge'), dict(expected='latest'),
                       dict(request_id='../target'), dict(workflow_sha256='0'*64), dict(binding=dict(source()['binding'], owner='4'*64)),
                       dict(secret_grant='model-supplied')):
            native = source(); native['operation']['request'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): controller.request(auth, native)

    def test_managed_route_rejects_carried_authority_and_cannot_be_directly_executed(self):
        value = self.proposal(source())
        with patch.object(auth, 'workspace_controller', return_value=controller):
            for field, extra in (('read_grant', 'old-read'), ('effect_grant', 'old-effect'), ('approval', 'trash:'+'1'*64)):
                with self.subTest(field=field), self.assertRaises(ValueError): auth.proposal(dict(value, **{field: extra}))
            with self.assertRaises(ValueError): auth.terminal_arguments(value, Path('/inert/request'))

    def test_status_scope_and_response_cannot_claim_restore_or_private_delivery(self):
        native = source('status'); inspected, state = outputs(native)
        self.assertEqual(controller.inspection(auth, native, auth.encoded(inspected))['selector']['id'], 'native-content-trash-read-v1')
        self.assertEqual(controller.status(auth, native, auth.encoded(state)), state)
        for field in ('restore_authorized', 'content_delivered', 'physical_purge_available', 'production_qualified'):
            with self.subTest(field=field), self.assertRaises(ValueError): controller.status(auth, native, auth.encoded(dict(state, **{field: True})))
        inspected['inspection_usage']['selector']['id'] = 'native-content-query-v1'
        with self.assertRaises(ValueError): controller.inspection(auth, native, auth.encoded(inspected))

    def test_operation_specific_delete_write_and_approval_survive_conflict_and_noop(self):
        for operation in ('trash', 'restore'):
            native = source(operation)
            for decision in (None, 'conflict-retained', 'no-change-retained'):
                _, reviewed, complete = outputs(native, decision)
                self.assertEqual(controller.reviewed(auth, native, auth.encoded(reviewed)), reviewed)
                self.assertEqual(controller.completed(auth, native, reviewed, auth.encoded(complete)), complete)
                wrong = copy.deepcopy(reviewed)
                wrong['effect_usage']['action'] = 'resource.retention'
                with self.assertRaises(ValueError): controller.reviewed(auth, native, auth.encoded(wrong))
                with self.assertRaises(ValueError): controller.reviewed(auth, native, auth.encoded(dict(reviewed, approval='retain:'+'e'*64)))

    def test_review_substitution_and_dangerous_logical_flags_refuse(self):
        native = source(); _, reviewed, _ = outputs(native)
        for field, replacement in (('logical_only', False), ('physical_bytes_erased', True), ('workflow_executed', True),
                ('source_bytes', reviewed['source_bytes']+1), ('lifecycle_request', source('restore')['operation']['request']),
                ('decision', 'restored'), ('resulting', dict(reference()['version'], artifact_id='another'))):
            with self.subTest(field=field), self.assertRaises(ValueError): controller.reviewed(auth, native, auth.encoded(dict(reviewed, **{field: replacement})))

    def test_actual_current_lifecycle_is_distinct_from_historical_replay(self):
        native = source(); _, reviewed, complete = outputs(native, replayed=True)
        self.assertEqual(controller.completed(auth, native, reviewed, auth.encoded(complete)), complete)
        self.assertEqual(complete['outcome']['decision'], 'trashed')
        self.assertEqual(complete['lifecycle']['status'], 'live')
        wrong = copy.deepcopy(complete); wrong['outcome']['replayed'] = False
        with self.assertRaises(ValueError): controller.completed(auth, native, reviewed, auth.encoded(wrong))

    def test_completion_rejects_mismatched_request_digest_outcome_and_actual_state(self):
        native = source(); _, reviewed, complete = outputs(native)
        for field, replacement in (('request_id', 'different'), ('review_sha256', 'f'*64), ('source_kind', 'content'),
                                   ('source_sha256', 'f'*64), ('sequence', True), ('replayed', 1)):
            value = copy.deepcopy(complete); value['outcome'][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError): controller.completed(auth, native, reviewed, auth.encoded(value))
        value = copy.deepcopy(complete); value['lifecycle']['status'] = 'live'
        with self.assertRaises(ValueError): controller.completed(auth, native, reviewed, auth.encoded(value))

    def test_production_readonly_capture_refuses_effect_and_exact_lifecycle_capture_uses_bounded_transport(self):
        native = source(); _, reviewed, complete = outputs(native)
        apply = dict(self.proposal(native), operation='apply', read_grant='fresh-read', effect_grant='delete-grant', approval=reviewed['approval'])
        path = Path('/inert/explicit/content.json')
        arguments = auth.terminal_arguments(apply, path)
        with patch.object(auth, '_capture_native', return_value=auth.encoded(complete)) as transport, patch.object(auth, 'protected'):
            with self.assertRaises(ValueError): auth.capture_query(arguments)
            transport.assert_not_called()
            self.assertEqual(controller.capture_apply(auth, apply, path), auth.encoded(complete))
            transport.assert_called_once_with(arguments, auth.MAX_QUERY_OUTPUT)
        for replacement in (dict(effect_grant='fresh-read'), dict(approval='write:'+'e'*64),
                            dict(request=auth.encoded(source('status')).decode())):
            with self.subTest(replacement=replacement), patch.object(auth, '_capture_native') as transport, patch.object(auth, 'protected'):
                with self.assertRaises(ValueError): controller.capture_apply(auth, dict(apply, **replacement), path)
                transport.assert_not_called()

    def run_journey(self, operation='trash', *, decision=None, replayed=False, grants=None, approval=None, failure=None):
        native = source(operation); responses = outputs(native, decision, replayed)
        frames = [auth.encoded(item) for item in responses]
        if failure is not None: frames[-1] = failure
        events = []
        def capture(command):
            command = list(command); events.append(command)
            value = frames.pop(0)
            if isinstance(value, BaseException): raise value
            return value
        with tempfile.TemporaryDirectory(dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as temporary, \
                patch.object(auth, 'workspace_controller', return_value=controller), \
                patch.object(auth, 'canonical_native_request', return_value=(auth.encoded(native).decode(), None)), \
                patch.object(auth, '_capture_native', side_effect=lambda command, maximum, *args: capture(command)) , patch.object(auth, 'protected'), \
                patch.object(auth, 'grant_selection', side_effect=grants or ['review-read', 'apply-read', 'effect']), \
                patch.object(auth, 'terminal_line', return_value=approval or (responses[1]['approval'] if operation != 'status' else 'q')), \
                patch('sys.stdout', new_callable=io.StringIO) as output:
            result = controller.journey(auth, self.proposal(native), Path(temporary))
            self.assertEqual(list(Path(temporary).iterdir()), [])
            return result, events, output.getvalue()

    def test_ordered_separate_inspection_review_and_effect_join_is_not_authority_proof(self):
        for operation in ('trash', 'restore'):
            for decision in (None, 'conflict-retained', 'no-change-retained'):
                result, commands, output = self.run_journey(operation, decision=decision)
                self.assertEqual(result, 0)
                self.assertEqual([c[4] for c in commands], ['content-owned-inspection-review', 'content-owned-review', 'content-owned-apply'])
                self.assertIn('apply-read', commands[-1]); self.assertIn('effect', commands[-1])
                self.assertIn('trash:' if operation == 'trash' else 'untrash:', commands[-1][-2])
                self.assertIn('ACTUAL CURRENT', output)
                self.assertIn('No bytes were physically erased', output)

    def test_status_never_prompts_for_effect_or_automatically_restores(self):
        result, commands, output = self.run_journey('status', grants=['status-read'])
        self.assertEqual(result, 0); self.assertEqual(len(commands), 2)
        self.assertIn('Start an explicit new exact-reference journey', output)

    def test_cancel_bad_approval_and_reused_grants_never_submit_effect(self):
        for grants, approval in (([None], None), (['review', None], None), (['review', 'review'], None), (['review', 'same', 'same'], None),
                                 (None, 'q'), (None, 'write:'+'e'*64)):
            with self.subTest(grants=grants, approval=approval):
                result, commands, output = self.run_journey(grants=grants, approval=approval)
                self.assertNotEqual(result, 0); self.assertLessEqual(len(commands), 2)
                self.assertNotIn('UNCERTAIN', output)

    def test_submitted_ambiguous_completion_never_retries_or_claims_rollback(self):
        for failure in (b'{"committed":true}', KeyboardInterrupt(), ValueError('transport lost')):
            result, commands, output = self.run_journey(failure=failure)
            self.assertEqual(result, 1); self.assertEqual(len(commands), 3)
            self.assertIn('UNCERTAIN', output)
            self.assertIn('before any retry', output)

    def test_explicit_replay_renders_new_current_state_separately(self):
        result, commands, output = self.run_journey(replayed=True)
        self.assertEqual(result, 0); self.assertEqual(len(commands), 3)
        self.assertIn('Historical replay is NOT a new state change', output)
        self.assertIn('"status": "live"', output)

    def test_dialog_data_cannot_select_model_grants_or_latest_reference(self):
        binding = auth.encoded(source()['binding']).decode()
        with patch.object(auth, 'workspace_controller', return_value=controller):
            value = controller.dialog_request(auth, 'alice', binding, 'trash', 'document.one', auth.encoded(reference()).decode(), 'new.request')
            self.assertEqual(value['read_grant'], ''); self.assertEqual(value['effect_grant'], '')
            actual = auth.strict_json(value['request'])
            self.assertEqual(actual['operation']['request']['expected'], reference())
            self.assertEqual(actual['operation']['request']['retention'], controller.RETENTION)
            with self.assertRaises(ValueError): controller.dialog_request(auth, 'alice', binding, 'trash', 'another', auth.encoded(reference()).decode(), 'new.request')

    def test_root_protected_module_image_asset_and_accessible_manual_button(self):
        app = (ROOT/'native/desktop/workspace_app.py').read_text()
        self.assertIn("Gtk.Button.new_with_mnemonic('_Versioned trash…')", app)
        self.assertIn("workspace_controller('lifecycle').launch_dialog(window, auth_module)", app)
        callback = app[app.index('    def lifecycle_control('):app.index("    lifecycle_button.connect(")]
        self.assertNotIn('deliver(', callback); self.assertNotIn('view.', callback)
        self.assertIn('workspace_lifecycle.py', (ROOT/'native/image/assemble.py').read_text())
        self.assertIn('usr/libexec/luma-os/workspace_lifecycle.py', (ROOT/'native/image/desktop_policy.py').read_text())
        self.assertLessEqual((ROOT/'native/desktop/workspace_auth.py').stat().st_size, 128*1024)
        self.assertLessEqual((ROOT/'native/desktop/workspace_lifecycle.py').stat().st_size, 128*1024)

    def test_v2_restore_closed_profile_pair_preserves_v1_and_includes_lifecycle_steps(self):
        _, original, review = recovery.fixture()
        self.assertEqual(auth.restore_review(review, original), review)
        graph = b'luma-fresh-owner-custody-restore-graph-v2:verify-independent-origin;decrypt-inert-data;replay-published-and-logical-lifecycle-chronologically;preserve-trash-with-remapped-exact-version-and-lifecycle-revision;leave-conflicts-and-noops-inert;original-admin-finite-batch;held-source;C-anchor-before-rename;fresh-same-state-read;retain-encrypted-origin-evidence;no-purge'
        review.update(schema_version=2, profile='luma-fresh-owner-content-restore-v2', workflow_sha256=hashlib.sha256(graph).hexdigest(),
            published_outcomes=2, planned_storage_bytes=16384, steps=[dict(request_id='restore-one.1', review_sha256='c'*64), dict(request_id='restore-one.3', review_sha256='d'*64)])
        review['review_sha256'] = ''; review['review_sha256'] = hashlib.sha256(auth.encoded(review)).hexdigest()
        self.assertEqual(auth.restore_review(review, original), review)
        for version, profile in ((1, 'luma-fresh-owner-content-restore-v2'), (2, 'luma-fresh-owner-content-restore-v1'), (True, 'luma-fresh-owner-content-restore-v1')):
            with self.subTest(version=version, profile=profile), self.assertRaises(ValueError): auth.restore_review(dict(review, schema_version=version, profile=profile), original)


if __name__ == '__main__': unittest.main()
