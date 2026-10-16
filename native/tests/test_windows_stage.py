"""Capture genuine pinned-image shell/systemd, never renamed substitute programs.

These tests require the offline Ubuntu 24.04 tools image. The platform input is
the real tools-image true ELF only as a bounded *test input*, not a claimed Luma
build. Root integration supplies the actual compiled luma-platform separately.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

IMAGE = Path(__file__).resolve().parents[1] / 'image'
SPEC = importlib.util.spec_from_file_location('luma_windows_stage_test', IMAGE / 'windows_stage.py')
stage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage)


class WindowsStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='luma-windows-stage-')
        cls.base = Path(cls.work.name)
        cls.platform = Path('/usr/bin/true')
        cls.report = stage.stage(Path('/'), cls.platform, cls.base, 'baseline')
        cls.root = cls.base / 'baseline/rootfs'

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def test_real_shell_systemd_helpers_units_and_os_identity_are_copied_exactly(self):
        for path in (*stage.BINARIES, *stage.CONFIGS):
            with self.subTest(path=path):
                self.assertEqual((self.root / path).read_bytes(), (Path('/') / path).read_bytes())
        for name in stage.UNITS:
            path = 'usr/lib/systemd/system/' + name
            self.assertEqual((self.root / path).read_bytes(), (Path('/') / path).read_bytes())
        self.assertNotEqual((self.root / 'bin/sh').read_bytes(), self.platform.read_bytes())
        self.assertNotEqual((self.root / 'usr/lib/systemd/systemd').read_bytes(), self.platform.read_bytes())
        self.assertIn(b'VERSION_ID="24.04"', (self.root / 'etc/os-release').read_bytes())

    def test_host_accounts_secrets_machine_identity_and_resolver_are_not_copied(self):
        for path, (expected, mode) in stage.GENERATED.items():
            self.assertEqual((self.root / path).read_bytes(), expected)
            self.assertEqual(stat.S_IMODE((self.root / path).stat().st_mode), mode)
        self.assertEqual((self.root / 'etc/shadow').read_bytes(), b'root:!:0:0:99999:7:::\n')
        self.assertEqual((self.root / 'etc/machine-id').stat().st_size, 0)
        for path in ('etc/resolv.conf', 'etc/ssh', 'etc/hosts', 'root/.ssh', 'root/.bash_history'):
            self.assertFalse((self.root / path).exists())
        origins = {record['path']: record['origin'] for record in self.report['files']}
        for path in ('etc/passwd', 'etc/shadow', 'etc/group', 'etc/gshadow', 'etc/machine-id'):
            self.assertEqual(origins[path]['kind'], 'fixed-locked-development-profile')
        self.assertTrue(self.report['development_root_account_locked'])
        self.assertFalse(self.report['luma_admin_provisioned'])
        self.assertFalse(self.report['accounts_copied_from_source'])

    def test_real_runtime_dependencies_and_alias_bytes_are_present_without_symlinks(self):
        for path, source in stage.ALIASES.items():
            self.assertEqual((self.root / path).read_bytes(), (self.root / source).read_bytes())
        for record in self.report['files']:
            path = self.root / record['path']
            self.assertTrue(path.is_file())
            self.assertFalse(path.is_symlink())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), record['sha256'])
            self.assertEqual(path.stat().st_size, record['bytes'])
        for path in self.root.rglob('*'):
            self.assertFalse(path.is_symlink())
        self.assertTrue(any('/systemd/libsystemd-shared-' in record['path'] for record in self.report['files']))

    def test_stage_build_roundtrip_uses_unchanged_normalized_manifest(self):
        candidate = self.base / 'package'
        report = stage.package.build(self.root, self.platform, self.base / 'baseline/plan.json',
                                     candidate, 'luma-wsl-dev-real-stage-test')
        manifest = json.loads((candidate / 'manifest.json').read_bytes())
        self.assertEqual(manifest['package_type'], 'luma-wsl-rootfs-ustar-v1')
        self.assertEqual(manifest['profile'], 'W')
        self.assertLessEqual(len(manifest['required_files']), 64)
        self.assertTrue(report['real_runtime_elf_segments_checked'])
        self.assertFalse(report['runtime_qualified'])
        self.assertFalse(report['distribution_imported'])

    def test_repeated_capture_is_deterministic_and_executes_no_input(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('stager must not execute input')):
            report = stage.stage(Path('/'), self.platform, self.base, 'repeated')
        self.assertEqual(report, self.report)
        self.assertEqual((self.base / 'baseline/stage.json').read_bytes(),
                         (self.base / 'repeated/stage.json').read_bytes())

    def test_new_output_only_and_no_follow_work_ancestors(self):
        before = (self.base / 'baseline/stage.json').read_bytes()
        with self.assertRaises(FileExistsError):
            stage.stage(Path('/'), self.platform, self.base, 'baseline')
        self.assertEqual((self.base / 'baseline/stage.json').read_bytes(), before)
        link = self.base / 'work-link'
        link.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(OSError):
            stage.stage(Path('/'), self.platform, link, 'through-link')
        self.assertFalse((self.base / 'through-link').exists())

    def test_closed_output_name_and_broad_or_c_drive_work_roots_refuse(self):
        for name in ('../outside', '/absolute', 'a/b', '', '.', 'x' * 97):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    stage.stage(Path('/'), self.platform, self.base, name)
        for path in (Path('/'), Path('/mnt/c'), Path('/mnt/c/Users/hakim')):
            with self.assertRaises(ValueError):
                stage.stage(Path('/'), self.platform, path, 'unsafe')

    def test_wrong_or_ambiguous_ubuntu_identity_refuses_before_output(self):
        source = self.base / 'invalid-source'
        (source / 'etc').mkdir(parents=True)
        for identity in (b'ID=ubuntu\nVERSION_ID=26.04\n',
                         b'ID=ubuntu\nID=ubuntu\nVERSION_ID=24.04\n'):
            (source / 'etc/os-release').write_bytes(identity)
            with self.assertRaisesRegex(ValueError, 'Ubuntu identity|Ubuntu 24.04'):
                stage.stage(source, self.platform, self.base, 'invalid-output')
        self.assertFalse((self.base / 'invalid-output').exists())

    def test_file_byte_bounds_and_observable_source_change_refuse(self):
        with patch.object(stage, 'MAX_FILES', 1):
            with self.assertRaisesRegex(ValueError, 'bound'):
                stage.stage(Path('/'), self.platform, self.base, 'file-bound')
        with patch.object(stage, 'MAX_TOTAL', 16):
            with self.assertRaisesRegex(ValueError, 'bound'):
                stage.stage(Path('/'), self.platform, self.base, 'byte-bound')
        original = stage.capture
        def changed(tree, path, maximum):
            value, mode, metadata = original(tree, path, maximum)
            if path == 'etc/inputrc':
                metadata = (*metadata[:-1], metadata[-1] + 1)
            return value, mode, metadata
        with patch.object(stage, 'capture', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'source changed'):
                stage.stage(Path('/'), self.platform, self.base, 'changed')
        self.assertFalse((self.base / 'changed').exists())

    def test_only_closed_development_claims_are_returned(self):
        for key in ('host_machine_id_copied', 'host_resolver_copied', 'host_keys_copied',
                    'source_authentication_established', 'work_mount_backing_qualified',
                    'dlopen_dependencies_qualified', 'systemd_unit_dependency_closure_qualified',
                    'boot_configuration_qualified', 'service_enablement_configured',
                    'guest_confinement_qualified', 'model_runtime_installed',
                    'package_authenticated', 'product_installation_admitted',
                    'distribution_imported', 'host_settings_changed', 'production_qualified', 'gate_closing'):
            self.assertFalse(self.report[key], key)
        self.assertTrue(self.report['actual_elf_inputs_captured'])
        self.assertTrue(self.report['elf_needed_closure_checked'])
        self.assertEqual(self.report['file_count'], len(self.report['files']))
        self.assertEqual(self.report['content_bytes'], sum(record['bytes'] for record in self.report['files']))
        self.assertEqual(json.loads((self.base / 'baseline/plan.json').read_bytes()),
                         {'schema_version': 1, 'exclude_paths': [], 'normalize_privileged_modes': False})


if __name__ == '__main__':
    unittest.main()
