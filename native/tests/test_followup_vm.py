"""Follow-up acceptance options; not guest execution or qualification."""
import contextlib
import io
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
import model_reconfigure_test as reconfigure
import model_recovery_test as recovery
import update_powercut_test as update


class FollowupOptionsTests(unittest.TestCase):
    def cases(self):
        model = ['--image', '/absent', '--base-run', '/absent', '--work', '/absent']
        powercut = ['--base-image', '/absent', '--candidate', '/absent',
                    '--base-run', '/absent', '--work', '/absent']
        return ((reconfigure, model, 5400), (recovery, model, 1200), (update, powercut, 2400))

    def test_defaults_do_not_upgrade_historical_secure_boot_claims(self):
        for module, args, timeout in self.cases():
            with self.subTest(module=module.__name__):
                options = module.arguments(args)
                self.assertFalse(options.secure_boot)
                self.assertFalse(options.require_clean_shutdown)
                self.assertEqual(options.timeout, timeout)
                self.assertEqual(options.accel, 'auto')

    def test_explicit_strict_fixture_options_are_supported(self):
        for module, args, _ in self.cases():
            with self.subTest(module=module.__name__):
                options = module.arguments(args+['--secure-boot', '--accel', 'tcg',
                    '--require-clean-shutdown', '--timeout', '5400'])
                self.assertTrue(options.secure_boot)
                self.assertTrue(options.require_clean_shutdown)
                self.assertEqual(options.accel, 'tcg')
                self.assertEqual(options.timeout, 5400)

    def test_invalid_limits_fail_before_any_disk_access(self):
        for module, args, _ in self.cases():
            for value in ('59', '21601', 'forever'):
                with self.subTest(module=module.__name__, value=value), \
                        contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    module.arguments(args+['--timeout', value])
                self.assertEqual(error.exception.code, 2)

    def test_new_model_client_is_explicit_not_implicitly_required_by_old_images(self):
        module, args, _ = self.cases()[0]
        self.assertFalse(module.arguments(args).bounded_model_chat)
        self.assertTrue(module.arguments(args+['--bounded-model-chat']).bounded_model_chat)


if __name__ == '__main__':
    unittest.main()
