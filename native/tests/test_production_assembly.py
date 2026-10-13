"""Production assembly orchestration fixtures, not custody/native qualification."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

IMAGE = Path(__file__).resolve().parents[1]/'image'
sys.path.insert(0, str(IMAGE))
import production_finalize as finish
import assembly_storage as storage
import assemble


def checkpoint():
    return {'schema_version': 1, 'identity': {'schema_version': 1, 'release': 'prod-1',
            'sequence': 1, 'environment': 'production', 'architecture': 'amd64',
            'ubuntu': '24.04', 'edition': 'headless'}, 'root_hash': 'a' * 64,
            'kernel': '6.8.0-142-generic', 'source_lock_sha256': 'b' * 64,
            'initrd_policy': {'phase_module': 'luma-pcrphase', 'required_paths': ['phase-helper'],
                             'shutdown': {'required_paths': ['shutdown'], 'boot_tested': False}},
            'desktop': {'profile': 'console', 'wayland_session_tested': False}}


class ProductionAssemblyTests(unittest.TestCase):
    def test_checkpoint_is_closed_production_identity_not_native_evidence(self):
        value = checkpoint()
        self.assertEqual(finish.parse_checkpoint(json.dumps(value)), value)
        for field, bad in [('environment', 'lab'), ('architecture', 'x86_64'),
                           ('ubuntu', '26.04'), ('edition', 'other'), ('sequence', 0),
                           ('sequence', True), ('release', '../disk')]:
            changed = copy.deepcopy(value)
            changed['identity'][field] = bad
            with self.assertRaises(ValueError):
                finish.parse_checkpoint(json.dumps(changed))
        for field, bad in [('root_hash', 'A' * 64), ('source_lock_sha256', 'wrong'),
                           ('kernel', '../kernel'), ('unknown', 'caller-authority')]:
            changed = copy.deepcopy(value)
            changed[field] = bad
            with self.assertRaises(ValueError):
                finish.parse_checkpoint(json.dumps(changed))
        changed = copy.deepcopy(value)
        changed['desktop']['wayland_session_tested'] = True
        with self.assertRaises(ValueError):
            finish.parse_checkpoint(json.dumps(changed))
        changed = copy.deepcopy(value)
        changed['initrd_policy']['shutdown']['boot_tested'] = True
        with self.assertRaises(ValueError):
            finish.parse_checkpoint(json.dumps(changed))
        with self.assertRaises(ValueError):
            finish.parse_checkpoint(json.dumps(value).replace('{', '{"schema_version":1,', 1))

    def test_frozen_source_rejects_changed_code_bytecode_extra_and_path_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'source.py').write_bytes(b'reviewed code')
            value = {'schema_version': 1, 'files': [{'path': 'source.py', 'bytes': 13,
                     'sha256': hashlib.sha256(b'reviewed code').hexdigest()}]}
            raw = json.dumps(value).encode()
            expected = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):
                finish.verify_source(root, raw, 'f' * 64)
            with mock.patch.object(finish, 'regular', side_effect=lambda p, limit: Path(p).read_bytes()):
                finish.verify_source(root, raw, expected)
                (root/'source.pyc').write_bytes(b'undeclared interpreter cache')
                with self.assertRaises(ValueError):
                    finish.verify_source(root, raw, expected)
                (root/'source.pyc').unlink()
                (root/'source.py').write_bytes(b'changed code!')
                with self.assertRaises(ValueError):
                    finish.verify_source(root, raw, expected)
            value['files'][0]['path'] = '../escape.py'
            raw = json.dumps(value).encode()
            with self.assertRaises(ValueError):
                finish.verify_source(root, raw, hashlib.sha256(raw).hexdigest())

    def test_ext4_guard_rejects_drvfs_overlay_and_readonly_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            def filesystem(kind):
                library = mock.Mock()
                def statfs(path, buffer):
                    import ctypes
                    ctypes.c_long.from_buffer(buffer).value = kind
                    return 0
                library.statfs.side_effect = statfs
                return library
            with mock.patch.object(storage.os, 'name', 'posix'), \
                    mock.patch.object(storage.ctypes, 'CDLL', return_value=filesystem(0xef53)), \
                    mock.patch.object(storage.os, 'statvfs', create=True, return_value=mock.Mock(f_flag=0)):
                storage.require_ext4(Path(temporary))
            for kind in (0x9fa0, 0x794c7630, 0x01021997):
                with mock.patch.object(storage.os, 'name', 'posix'), \
                        mock.patch.object(storage.ctypes, 'CDLL', return_value=filesystem(kind)), \
                        self.assertRaises(ValueError):
                    storage.require_ext4(Path(temporary))

    def test_export_headroom_is_actual_compressed_inventory_not_old_raw(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root/'source', root/'target'
            source.mkdir(); target.mkdir()
            (source/'image.img.zst').write_bytes(b'compressed')
            with mock.patch.object(shutil, 'disk_usage', return_value=mock.Mock(free=1024**3 + 10)):
                self.assertEqual(storage.export_headroom(source, target, ['image.img.zst']), 1024**3 + 10)
            with mock.patch.object(shutil, 'disk_usage', return_value=mock.Mock(free=10)), self.assertRaises(ValueError):
                storage.export_headroom(source, target, ['image.img.zst'])
            with self.assertRaises(ValueError):
                storage.export_headroom(source, target, ['../outside'])
            (target/'existing.img').write_bytes(b'preserve')
            with self.assertRaises(ValueError):
                storage.export_headroom(source, target, ['image.img.zst'])
            self.assertEqual((target/'existing.img').read_bytes(), b'preserve')

    def test_production_main_cannot_select_lab_keys_or_skip_external_custody(self):
        source = (IMAGE/'assemble.py').read_text()
        self.assertIn('sys.dont_write_bytecode = True', source)
        self.assertIn('production assembly must not mount or create a private-key volume', source)
        self.assertLess(source.index('production_release.validate_public_inputs('),
                        source.index('public_trust.provision('))
        self.assertIn('recheck_public_domains(ROOT, OUT)', source)
        pause = source.index('production_release.prepare_pcr(OUT, ROOT)')
        self.assertLess(pause, source.index("run('sbsign'"))
        self.assertIn("'production_signed':production", source)
        self.assertIn("'custody_qualified':False", source)
        self.assertIn('production_release.verify_complete(OUT)', source)
        self.assertIn("*(['release-trust.json'] if production else [])", source)
        driver = (IMAGE/'build.sh').read_text()
        continuation = driver.split('if [ "${1:-}" = production-continue ]; then', 1)[1].split('edition=${1:-headless}', 1)[0]
        self.assertIn('/work/source/native/image/production_finalize.py', continuation)
        self.assertIn('/work/source/native/image/$helper', continuation)
        self.assertNotIn('/repo/native/image/production_finalize.py', continuation)
        self.assertNotIn('dst=/repo', continuation)

    def test_seal_refuses_missing_actual_production_verification_before_any_media_write(self):
        custody = mock.Mock()
        custody.verify_complete.side_effect = ValueError('actual signature chain refused')
        value = {**checkpoint()['identity'], 'root_hash': 'a' * 64}
        with mock.patch.dict(sys.modules, {'production_release': custody}), \
                mock.patch.object(assemble, 'stage_payload_member') as staging:
            with self.assertRaises(ValueError):
                assemble.seal_media(value, checkpoint()['desktop'], checkpoint()['kernel'])
            staging.assert_not_called()
        custody.verify_complete.assert_called_once_with(assemble.OUT)

    @unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux shell orchestration fixture')
    def test_production_shell_never_mounts_private_keys_and_exports_exact_phase_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver = root/'repo/native/image/build.sh'
            driver.parent.mkdir(parents=True)
            shutil.copyfile(IMAGE/'build.sh', driver)
            binaries, public, skills, external = root/'bin', root/'public', root/'skills', root/'external'
            for path in (binaries, public, skills, external):
                path.mkdir()
            log = root/'calls.jsonl'
            for name in ('docker', 'python3'):
                file = binaries/name
                file.write_text('#!' + sys.executable + '\nimport json,sys\n'
                                f'with open({str(log)!r},"a") as f: f.write(json.dumps([sys.argv[0],*sys.argv[1:]])+"\\n")\n')
                file.chmod(0o755)
            environment = {**os.environ, 'PATH': str(binaries) + ':/usr/bin:/bin',
                'LUMA_BUILD_PROFILE': 'standard', 'LUMA_BUILD_ROOT': str(external),
                'LUMA_NATIVE_ENVIRONMENT': 'production', 'LUMA_BUILD_NETWORK': 'none',
                'LUMA_NATIVE_PRODUCTION_PUBLIC_INPUTS': str(public),
                'LUMA_NATIVE_PUBLIC_TRUST': str(skills), 'LUMA_NATIVE_MODEL_PUBLIC_INPUTS': str(public)}
            result = subprocess.run(['/bin/bash', str(driver), 'desktop', '13'], env=environment,
                                    capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            docker = [row[1:] for row in calls if Path(row[0]).name == 'docker']
            self.assertFalse(any('dst=/keys' in word for row in docker for word in row))
            self.assertFalse(any('luma-native-lab-keys' in word for row in docker for word in row))
            assembly = next(row for row in docker if '/repo/native/image/assemble.py' in row)
            self.assertIn('type=bind,src=' + str(public) + ',dst=/production-public,readonly', assembly)
            self.assertNotIn('--external-artifacts', assembly)
            self.assertIn('production', assembly)
            self.assertTrue(any('/repo/native/image/production_request_export.py' in row and row[-1] == 'pcr' for row in docker))
            self.assertFalse(any('/repo/native/image/export.py' in row for row in docker))
            self.assertIn(b'No production private key was generated', result.stdout)


if __name__ == '__main__':
    unittest.main()
