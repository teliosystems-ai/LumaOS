"""Image-only original-terminal policy; not installed PAM/TTY qualification."""
import ast
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('luma_tty_assembly', REPO/'native/image/assemble.py')
ASSEMBLY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSEMBLY)


class SudoOriginalTtyPolicyTests(unittest.TestCase):
    def test_only_the_existing_fixed_launcher_has_a_command_scoped_default(self):
        self.assertEqual(ASSEMBLY.ORIGINAL_PAM_SUDOERS.splitlines(), [
            'Cmnd_Alias LUMA_ORIGINAL_PAM = /usr/libexec/luma-os/luma-platform granted-run *',
            'Defaults!LUMA_ORIGINAL_PAM !use_pty',
        ])
        self.assertNotIn('NOPASSWD', ASSEMBLY.ORIGINAL_PAM_SUDOERS)
        self.assertNotIn('ALL=', ASSEMBLY.ORIGINAL_PAM_SUDOERS)

    def test_policy_is_only_written_to_the_supplied_image_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(ASSEMBLY, 'ROOT', root):
                ASSEMBLY.configure_original_pam_sudoers()
            policy = root/'etc/sudoers.d/luma-original-pam'
            self.assertEqual(policy.read_text(), ASSEMBLY.ORIGINAL_PAM_SUDOERS)
            self.assertEqual(stat.S_IMODE(policy.stat().st_mode), 0o440)
            self.assertEqual([p for p in root.rglob('*') if p.is_file()], [policy])

    def test_image_assembly_calls_policy_and_preserves_the_native_confined_pty(self):
        tree = ast.parse((REPO/'native/image/assemble.py').read_text())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name)
                 and node.func.id == 'configure_original_pam_sudoers']
        self.assertEqual(len(calls), 1)
        launcher = (REPO/'rust/luma-platform/src/service/granted_gateway.rs').read_text()
        self.assertIn('"--pty"', launcher)
        self.assertIn('"--property=AppArmorProfile=luma-granted-client"', launcher)


if __name__ == '__main__':
    unittest.main()
