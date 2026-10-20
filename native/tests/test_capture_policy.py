"""Closed image prerequisites, not installed device/confinement qualification."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('capture_build_policy', ROOT/'image/capture_policy.py')
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class CapturePolicyTests(unittest.TestCase):
    def fixture(self, root):
        for name in POLICY.REQUIRED:
            target = root/name
            target.parent.mkdir(parents=True, exist_ok=True)
            if name == POLICY.PROFILE:
                target.write_bytes((ROOT/'image/overlay'/name).read_bytes())
            elif name == POLICY.REQUIRED[0]:
                target.write_bytes((ROOT/'desktop/workspace_capture.py').read_bytes())
            else:
                target.write_bytes(b'fixture prerequisite, not an executable')

    def test_all_prerequisites_and_honest_nonqualification_record(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as temporary:
            root = Path(temporary)
            self.fixture(root)
            result = POLICY.verify(root)
            self.assertTrue(result['runtime_prerequisites_present'])
            self.assertEqual(result['worker_profiles'], list(POLICY.PROFILES))
            self.assertFalse(result['device_permission_qualified'])
            self.assertFalse(result['speech_transcription_available'])
            self.assertFalse(result['native_publication_authority'])
            self.assertFalse(result['model_submission_automatic'])

    def test_every_absent_empty_or_linked_prerequisite_refuses(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as temporary:
            root = Path(temporary)
            self.fixture(root)
            for name in POLICY.REQUIRED:
                target = root/name
                before = target.read_bytes()
                target.unlink()
                with self.subTest(name=name, variant='missing'), self.assertRaises(ValueError):
                    POLICY.verify(root)
                target.write_bytes(b'')
                with self.subTest(name=name, variant='empty'), self.assertRaises(ValueError):
                    POLICY.verify(root)
                target.unlink()
                alias = root/'alias'; alias.write_bytes(before)
                target.symlink_to(alias)
                with self.subTest(name=name, variant='link'), self.assertRaises(ValueError):
                    POLICY.verify(root)
                target.unlink(); alias.unlink(); target.write_bytes(before)

    def test_module_or_policy_substitution_refuses_and_domains_stay_separate(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as temporary:
            root = Path(temporary)
            self.fixture(root)
            for name in (POLICY.PROFILE, POLICY.REQUIRED[0]):
                target = root/name
                before = target.read_bytes()
                target.write_bytes(before+b'\n# substituted bytes\n')
                with self.assertRaises(ValueError):
                    POLICY.verify(root)
                target.write_bytes(before)
        text = (ROOT/'image/overlay'/POLICY.PROFILE).read_text()
        audio, video = text.split('profile luma-workspace-capture-video', 1)
        self.assertIn('owner /run/user/[0-9]*/pulse/native rw,', audio)
        self.assertNotIn('pulse/native rw,', video)
        self.assertIn('deny unix (create,connect,bind,listen,accept)', video)
        for part in (audio, video):
            for denial in ('deny dbus,', 'deny network inet,', 'deny network inet6,',
                           'deny /var/lib/luma-os/**', 'deny /home/**', 'deny /dev/{tpm*'):
                self.assertIn(denial, part)


if __name__ == '__main__':
    unittest.main()
