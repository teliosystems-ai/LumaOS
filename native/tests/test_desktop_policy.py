"""Desktop assembly policy tests; these are not graphical-session acceptance."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
import desktop_policy as policy


@unittest.skipUnless(os.name == 'posix', 'Linux image paths and permissions')
class DesktopPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative in policy.REQUIRED:
            path = self.root/relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('packaged prerequisite fixture\n')

    def test_profile_requires_password_and_is_independent_of_model(self):
        report = policy.configure(self.root, 'desktop')
        self.assertFalse(report['wayland_session_tested'])
        self.assertFalse(report['model_required_for_login'])
        config = (self.root/'etc/gdm3/custom.conf').read_text()
        for setting in ('WaylandEnable=true', 'DefaultSession=luma.desktop',
                        'AutomaticLoginEnable=false', 'TimedLoginEnable=false', 'Enable=false'):
            self.assertIn(setting, config)
        unit = (self.root/'etc/systemd/system/gdm.service.d/luma.conf').read_text()
        self.assertIn('ConditionKernelCommandLine=luma.mode=installed', unit)
        self.assertNotIn('Requires=', unit)
        self.assertNotIn('luma-model.service', unit)
        self.assertEqual((self.root/'usr/libexec/luma-os/luma-wayland-session').stat().st_mode & 0o777, 0o755)

    def test_headless_does_not_add_graphical_configuration(self):
        policy.configure(self.root, 'headless')
        self.assertFalse((self.root/'etc/gdm3').exists())
        self.assertFalse((self.root/'usr/share/luma-os/desktop-profile').exists())

    def test_exact_packaged_locale_alias_is_preserved_and_substitution_refused(self):
        alias = self.root/'etc/default/locale'
        alias.parent.mkdir(parents=True)
        alias.symlink_to('../locale.conf')
        policy.configure(self.root, 'desktop')
        self.assertEqual(alias.readlink(), Path('../locale.conf'))
        self.assertEqual(alias.read_text(), 'LANG=C.UTF-8\n')
        alias.unlink()
        alias.symlink_to('/tmp/unexpected-locale')
        with self.assertRaises(ValueError):
            policy.configure(self.root, 'desktop')

    def test_missing_prerequisite_linked_config_and_wrong_manager_refused(self):
        path = self.root/policy.REQUIRED[0]
        path.unlink()
        with self.assertRaises(ValueError):
            policy.configure(self.root, 'desktop')
        path.write_text('restored fixture')
        config = self.root/'etc/gdm3/custom.conf'
        config.parent.mkdir(parents=True)
        config.symlink_to('/tmp/nonexistent-luma-config')
        with self.assertRaises(ValueError):
            policy.configure(self.root, 'desktop')
        config.unlink()
        manager = self.root/'etc/systemd/system/display-manager.service'
        manager.parent.mkdir(parents=True)
        manager.symlink_to('/usr/lib/systemd/system/unexpected.service')
        with self.assertRaises(ValueError):
            policy.configure(self.root, 'desktop')

    def test_packaged_x11_sessions_are_preserved_but_not_selectable(self):
        path = self.root/'usr/share/xsessions/gnome-xorg.desktop'
        path.parent.mkdir(parents=True)
        path.write_text('packaged x11 session')
        policy.configure(self.root, 'desktop')
        self.assertFalse(path.exists())
        self.assertEqual(path.with_suffix('.desktop.disabled').read_text(), 'packaged x11 session')
        policy.configure(self.root, 'desktop')  # Stable on repeated assembly checks.

    def test_packaged_gdm3_alias_must_resolve_to_the_verified_gdm_unit(self):
        alias = self.root/'usr/lib/systemd/system/gdm3.service'
        alias.symlink_to('gdm.service')
        manager = self.root/'etc/systemd/system/display-manager.service'
        manager.parent.mkdir(parents=True)
        manager.symlink_to('/lib/systemd/system/gdm3.service')
        policy.configure(self.root, 'desktop')
        alias.unlink()
        alias.symlink_to('unexpected.service')
        with self.assertRaises(ValueError):
            policy.configure(self.root, 'desktop')

    def test_session_rejects_x11_unset_type_and_root(self):
        script = self.root/'session.sh'
        script.write_text(policy.SESSION)
        for kind in ('x11', ''):
            result = subprocess.run(['/bin/sh', str(script)], env={**os.environ, 'XDG_SESSION_TYPE':kind},
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires a Wayland session', result.stderr)
        if os.geteuid() == 0:
            result = subprocess.run(['/bin/sh', str(script)], env={**os.environ, 'XDG_SESSION_TYPE':'wayland'},
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('interactive account', result.stderr)


class DesktopBootTests(unittest.TestCase):
    def test_only_installed_desktop_selects_graphical_target(self):
        for edition in ('headless', 'desktop'):
            for mode in ('live', 'installed'):
                target = policy.target(edition, mode)
                self.assertEqual(target == 'graphical.target', (edition, mode) == ('desktop', 'installed'))
                policy.verify_boot_target(('ro systemd.unit='+target).encode(), edition, mode)
        for edition, mode in [('other', 'live'), ('desktop', 'unknown')]:
            with self.assertRaises(ValueError):
                policy.target(edition, mode)

    def test_boot_override_duplicates_missing_wrong_mode_and_alias_are_refused(self):
        for command in (b'ro', b'systemd.unit=graphical.target',
                        b'systemd.unit=multi-user.target systemd.unit=multi-user.target',
                        b'systemd.unit=multi-user.target single',
                        b'systemd.unit=multi-user.target rd.systemd.unit=rescue.target'):
            with self.assertRaises(ValueError):
                policy.verify_boot_target(command, 'desktop', 'live')

    def test_geometry_has_larger_bounded_desktop_root_and_payload(self):
        self.assertEqual(policy.geometry('headless'), (4096, 6144))
        self.assertEqual(policy.geometry('desktop'), (6144, 8192))
        with self.assertRaises(ValueError):
            policy.geometry('other')


if __name__ == '__main__':
    unittest.main()
