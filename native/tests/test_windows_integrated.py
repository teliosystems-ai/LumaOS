"""Constructor/order/refusal contracts, not compiled-worker or model evidence.

These mock component effects explicitly. An actual combined composition must
also use the real compiled platform/helper and full pinned runtime/model bytes.
"""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('luma_integrated_test', ROOT/'native/image/windows_integrated.py')
integrated = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(integrated)


class WindowsIntegratedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='luma-integrated-constructor-', dir=os.environ.get('LUMA_STORAGE_TEST_ROOT'))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.arguments = (Path('/'), Path('/actual-platform-input'), Path('/actual-helper-input'),
                          Path('/actual-runtime-input'), Path('/actual-model-input'), self.root,
                          'combined', 'luma-wsl-dev-integrated-constructor')

    def test_constructor_selects_workspace_before_inference_and_publishes_both_flags(self):
        calls = []
        def stage(source, platform, work, name, **flags):
            calls.append(('stage', flags))
            (work/name/'rootfs').mkdir(parents=True)
            return {'component': 'mock-stage'}
        def workspace(*args):
            calls.append(('workspace', args)); return {'component': 'mock-workspace'}
        def inference(*args):
            calls.append(('inference', args)); return {'component': 'mock-inference'}
        def build(*args, **flags):
            calls.append(('package', flags)); return {'component': 'mock-package'}
        with patch.object(integrated.stage, 'stage', side_effect=stage), \
                patch.object(integrated.workspace, 'compose', side_effect=workspace), \
                patch.object(integrated.inference, 'compose', side_effect=inference), \
                patch.object(integrated.package, 'build', side_effect=build):
            result = integrated.compose(*self.arguments)
        self.assertEqual([call[0] for call in calls], ['stage', 'workspace', 'inference', 'package'])
        self.assertEqual(calls[0][1], {'hosted_workspace': True})
        self.assertEqual(calls[3][1], {'hosted_inference': True, 'hosted_workspace': True})
        self.assertEqual(result['runtime_profile'], 'luma-windows-hosted-workspace-v1')
        self.assertEqual((result['bootstrap_session_seconds'], result['inference_session_seconds']), (30, 300))
        self.assertEqual((result['initial_default_uid'], result['initial_wsl_flags']), (65534, 0))
        self.assertEqual(json.loads((self.root/'combined-stage/integrated-stage.json').read_bytes()), result)
        for field in ('package_authenticated', 'distribution_imported', 'account_created', 'pam_authenticated',
                      'inference_executed', 'host_settings_changed', 'production_qualified', 'gate_closing'):
            self.assertIs(result[field], False)

    def test_preexisting_either_destination_refuses_before_any_component_effect(self):
        for suffix in ('stage', 'package'):
            destination = self.root/('combined-'+suffix)
            destination.mkdir()
            with patch.object(integrated.stage, 'stage') as stage:
                with self.assertRaisesRegex(ValueError, 'destination already exists'):
                    integrated.compose(*self.arguments)
                stage.assert_not_called()
            destination.rmdir()

    def test_invalid_names_releases_or_work_roots_refuse_before_staging(self):
        changes = [(6, ''), (6, '../escape'), (6, 'a'*81), (6, 'space name'),
                   (7, 'production'), (7, 'luma-wsl-dev-a/escape'),
                   (5, Path('/')), (5, Path('/mnt/c')), (5, Path('/mnt/c/build'))]
        for index, value in changes:
            arguments = list(self.arguments); arguments[index] = value
            with self.subTest(index=index, value=value), patch.object(integrated.stage, 'stage') as stage:
                with self.assertRaises(ValueError):
                    integrated.compose(*arguments)
                stage.assert_not_called()

    def test_failed_workspace_composition_never_invokes_inference_or_package(self):
        with patch.object(integrated.stage, 'stage', return_value={}), \
                patch.object(integrated.workspace, 'compose', side_effect=ValueError('retained failure')), \
                patch.object(integrated.inference, 'compose') as inference, \
                patch.object(integrated.package, 'build') as build:
            with self.assertRaisesRegex(ValueError, 'retained failure'):
                integrated.compose(*self.arguments)
            inference.assert_not_called(); build.assert_not_called()

    def test_nonroot_build_refuses_before_staging(self):
        with patch.object(integrated.os, 'geteuid', return_value=1000), patch.object(integrated.stage, 'stage') as stage:
            with self.assertRaisesRegex(ValueError, 'root-owned Linux build'):
                integrated.compose(*self.arguments)
            stage.assert_not_called()


if __name__ == '__main__':
    unittest.main()
