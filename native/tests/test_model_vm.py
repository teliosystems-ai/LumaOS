"""Inference fixture oracles; these tests do not execute a model."""
import json
import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest import mock
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
import model_vm_test as models
from model_vm_test import MODEL, arguments, failure_diagnostics, infer, inference_budget, inference_result


class ModelCommandLineTests(unittest.TestCase):
    def test_default_4b_and_explicit_small_installation_profile(self):
        base = ['--image', '/absent', '--work', '/absent']
        self.assertEqual(arguments(base).model, MODEL)
        small = 'qwen3-1-7b-q4-k-m'
        self.assertEqual(arguments(base+['--model', small]).model, small)
        self.assertEqual(models.model_fixture(small)['guest_memory_mib'], 4096)
        self.assertEqual(models.model_fixture(MODEL)['guest_memory_mib'], 6144)
        for value in ('manual-only', 'gemma-unqualified', '../weights', 'x; touch /tmp/no'):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                arguments(base+['--model', value])

    def test_closed_fixture_limits_match_existing_catalog_and_memory_admission(self):
        catalog = json.loads(Path(models.__file__).with_name('model-catalog.json').read_text())
        self.assertEqual(set(models.MODEL_FIXTURES), {entry['id'] for entry in catalog['models']})
        for entry in catalog['models']:
            fixture = models.model_fixture(entry['id'])
            self.assertEqual(fixture['memory_max_bytes'], entry['memory_max_bytes'])
            self.assertGreater(fixture['guest_memory_mib']*1024*1024, entry['minimum_ram_bytes'])
            self.assertEqual(fixture['weight'], '/var/lib/luma-os/models/'+entry['id']+'.gguf')
        for value in (None, [], '../outside', 'unknown'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                models.model_fixture(value)

    def test_selected_identity_catalog_and_corruption_path_are_profile_bound(self):
        vm = mock.Mock()
        small = 'qwen3-1-7b-q4-k-m'
        models.verify_selected(vm, small)
        commands = [call.args[0] for call in vm.run.call_args_list]
        self.assertIn('sha256sum -c -', commands[0])
        self.assertIn(small, commands[1])
        vm.reset_mock()
        with mock.patch.object(models, 'start_expect_refusal', return_value={'fixture':True}) as refusal:
            self.assertEqual(models.reject_same_size_corruption(vm, small), {'fixture':True})
        refusal.assert_called_once_with(vm, 'model SHA-256 mismatch')
        commands = '\n'.join(call.args[0] for call in vm.run.call_args_list)
        self.assertIn(small+'.gguf', commands)
        self.assertNotIn(MODEL+'.gguf', commands)
        vm.reset_mock()
        with self.assertRaises(ValueError):
            models.reject_same_size_corruption(vm, '../outside')
        vm.run.assert_not_called()

    def test_default_and_explicit_stage_deadline(self):
        base = ['--image', '/work/artifacts/example.img', '--work', '/work/vm-test']
        self.assertEqual(arguments(base).timeout, 5400)
        self.assertFalse(arguments(base).bounded_model_chat)
        self.assertTrue(arguments(base+['--bounded-model-chat']).bounded_model_chat)
        for seconds in (60, 5400, 21600):
            args = arguments(base+['--timeout', str(seconds), '--require-clean-shutdown'])
            self.assertEqual(args.timeout, seconds)
            self.assertTrue(args.require_clean_shutdown)

    def test_invalid_deadline_is_rejected_before_opening_image_or_work(self):
        for value in ('0', '-1', '59', '21601', '1.5', 'forever'):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                arguments(['--image', '/absent', '--work', '/absent', '--timeout', value])
            self.assertEqual(error.exception.code, 2)


class ModelResultTests(unittest.TestCase):
    def setUp(self):
        self.result = {'model': MODEL, 'text': 'Hello',
                       'usage': {'completion_tokens': 2},
                       'effects_executed': False, 'certification_closing': False}

    def encode(self):
        return json.dumps(self.result).encode()+b'\r\n'

    def test_fresh_result_with_real_positive_token_count(self):
        self.assertEqual(inference_result(b'console command\r\n'+self.encode(), MODEL), self.result)

    def test_emulation_has_explicit_budget_without_changing_legacy_image_cli(self):
        self.assertEqual(inference_budget('tcg'), (1800, 16))
        self.assertEqual(inference_budget('kvm'), (180, 128))
        vm = mock.Mock(acceleration='tcg')
        vm.run.return_value = self.encode()
        infer(vm)
        self.assertNotIn('--timeout-seconds', vm.run.call_args.args[0])
        self.result.update(timeout_seconds=1800, max_tokens=16, elapsed_seconds=200)
        vm.run.return_value = self.encode()
        infer(vm, bounded=True)
        self.assertIn('--timeout-seconds 1800 --max-tokens 16', vm.run.call_args.args[0])
        self.assertEqual(vm.run.call_args.kwargs['timeout'], 1860)

    def test_bounded_fixture_rejects_missing_or_inconsistent_observations(self):
        vm = mock.Mock(acceleration='tcg')
        self.result.update(timeout_seconds=1800, max_tokens=16, elapsed_seconds=200)
        for field, value in (('timeout_seconds', 180), ('max_tokens', 128),
                             ('elapsed_seconds', None), ('elapsed_seconds', float('nan')),
                             ('elapsed_seconds', True), ('elapsed_seconds', 1801),
                             ('elapsed_seconds', -1), ('usage', {'completion_tokens': 17})):
            original = self.result[field]
            self.result[field] = value
            vm.run.return_value = self.encode()
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                infer(vm, bounded=True)
            self.result[field] = original

    def test_missing_or_duplicate_current_result_never_reuses_old_success(self):
        inference_result(self.encode(), MODEL)
        for output in (b'', b'healthy\r\n', self.encode()*2):
            with self.assertRaises(RuntimeError):
                inference_result(output, MODEL)

    def test_wrong_model_empty_text_and_authority_claims_refused(self):
        for field, value in (('model', 'other-model'), ('text', ''), ('text', None),
                             ('effects_executed', True), ('effects_executed', 0),
                             ('certification_closing', True)):
            original = self.result[field]
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                self.result[field] = value
                inference_result(self.encode(), MODEL)
            self.result[field] = original

    def test_usage_requires_integer_completion_count(self):
        for value in (None, {}, {'completion_tokens': 0}, {'completion_tokens': -1},
                      {'completion_tokens': True}, {'completion_tokens': 1.5}):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                self.result['usage'] = value
                inference_result(self.encode(), MODEL)

    def test_failure_diagnostics_are_bounded_and_do_not_request_credentials(self):
        vm = mock.Mock()
        self.assertTrue(failure_diagnostics(vm))
        command = vm.run.call_args.args[0]
        self.assertIn('memory.events', command)
        self.assertIn('journalctl', command)
        self.assertNotIn('Environment', command)
        self.assertNotIn('api-key', command)
        self.assertEqual(vm.run.call_args.kwargs['timeout'], 30)
        vm.run.side_effect = TimeoutError('guest unreachable')
        self.assertFalse(failure_diagnostics(vm))


class FreshRefusalTests(unittest.TestCase):
    def entry(self, **overrides):
        return {'_SYSTEMD_UNIT':'luma-model.service', '__CURSOR':'new-cursor',
                'MESSAGE':'luma-platform: model SHA-256 mismatch', **overrides}

    def exercise(self, entry, cursor=True):
        moment = [0]
        calls = []
        def run(arguments, **kwargs):
            calls.append(arguments)
            self.assertTrue(kwargs['check'])
            self.assertTrue(kwargs['capture_output'])
            self.assertLessEqual(kwargs['timeout'], 10)
            if '--show-cursor' in arguments:
                # An old identical refusal must not satisfy the subsequent test.
                output = json.dumps(self.entry(__CURSOR='old-cursor'))+'\n'
                if cursor:
                    output += '-- cursor: old-cursor\n'
            elif '--after-cursor' in arguments:
                output = json.dumps(entry)+'\n' if entry else ''
            else:
                output = ''
            return SimpleNamespace(stdout=output)
        def sleep(seconds):
            moment[0] += 80
        with mock.patch.object(models.subprocess, 'run', side_effect=run), \
                mock.patch.object(models.time, 'monotonic', side_effect=lambda:moment[0]), \
                mock.patch.object(models.time, 'sleep', side_effect=sleep):
            result = models.guest_refusal('model SHA-256 mismatch')
        return result, calls

    def test_only_fresh_matching_unit_message_is_accepted(self):
        record, calls = self.exercise(self.entry())
        self.assertEqual(record['after_cursor'], 'old-cursor')
        self.assertEqual(record['observed_cursor'], 'new-cursor')
        self.assertFalse(record['gate_closing'])
        self.assertEqual(calls[0], ['journalctl', '--sync'])
        self.assertIn('--show-cursor', calls[1])
        self.assertEqual(calls[3], ['systemctl', 'start', 'luma-model.service'])
        self.assertIn('--after-cursor', calls[4])
        self.assertIn('old-cursor', calls[4])

    def test_old_logs_wrong_unit_wrong_message_or_same_cursor_do_not_pass(self):
        for index, entry in enumerate((None, self.entry(_SYSTEMD_UNIT='other.service'),
                                      self.entry(MESSAGE='healthy'), self.entry(__CURSOR='old-cursor'))):
            with self.subTest(case=index), self.assertRaises(TimeoutError):
                self.exercise(entry)
        with self.assertRaises(RuntimeError):
            self.exercise(self.entry(), cursor=False)

    def test_controller_requires_exact_single_fresh_non_authority_result(self):
        record = {'fresh_model_refusal':'model SHA-256 mismatch', 'after_cursor':'old',
                  'observed_cursor':'new', 'gate_closing':False}
        vm = mock.Mock()
        encoded = json.dumps(record).encode()
        vm.run.return_value = encoded
        self.assertEqual(models.start_expect_refusal(vm, record['fresh_model_refusal']), record)
        self.assertEqual(vm.run.call_args.kwargs['timeout'], 180)
        for output in (b'', encoded+b'\n'+encoded,
                       json.dumps({**record,'observed_cursor':'old'}).encode(),
                       json.dumps({**record,'gate_closing':True}).encode()):
            vm.run.return_value = output
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                models.start_expect_refusal(vm, record['fresh_model_refusal'])


if __name__ == '__main__':
    unittest.main()
