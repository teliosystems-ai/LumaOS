"""Bounded fixture checks for the inert laboratory skill-registry packager."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from assemble import package_skill_registry


class SkillRegistryPackagingTests(unittest.TestCase):
    def test_distinct_key_signature_and_workflow_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base/'root'
            keys = base/'keys'
            keys.mkdir(mode=0o700)
            share = root/'usr/share/luma-os'
            workflow = share/'workflows/file-to-artifact-v1.json'
            workflow.parent.mkdir(parents=True)
            content = (Path(__file__).parent/'overlay/usr/share/luma-os/workflows/file-to-artifact-v1.json').read_bytes()
            workflow.write_bytes(content)
            subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(keys/'release.key')],check=True)
            subprocess.run(['openssl','pkey','-in',str(keys/'release.key'),'-pubout','-out',str(share/'release.pub')],check=True)
            package_skill_registry(root, keys)
            skill_dir = share/'skills'
            registry = json.loads((skill_dir/'registry.json').read_text())
            self.assertEqual(registry['workflow_sha256'], hashlib.sha256(content).hexdigest())
            self.assertNotEqual((skill_dir/'skills.pub').read_bytes(), (share/'release.pub').read_bytes())
            self.assertEqual((keys/'skills-lab.key').stat().st_mode & 0o077, 0)
            subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(skill_dir/'skills.pub'),
                            '-rawin','-in',str(skill_dir/'registry.json'),'-sigfile',str(skill_dir/'registry.sig')],
                           check=True, capture_output=True)
            self.assertFalse((root/'skills-lab.key').exists())
            (share/'release.pub').write_bytes((skill_dir/'skills.pub').read_bytes())
            with self.assertRaises(SystemExit):
                package_skill_registry(root, keys)

    def test_linked_or_exposed_private_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base/'root'
            keys = base/'keys'
            keys.mkdir()
            (keys/'skills-lab.key').symlink_to(keys/'elsewhere.key')
            with self.assertRaises(SystemExit):
                package_skill_registry(root, keys)
            (keys/'skills-lab.key').unlink()
            (keys/'skills-lab.key').write_bytes(b'not a key')
            (keys/'skills-lab.key').chmod(0o644)
            with self.assertRaises(SystemExit):
                package_skill_registry(root, keys)


if __name__ == '__main__':
    unittest.main()
