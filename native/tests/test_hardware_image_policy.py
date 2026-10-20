import importlib.util
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

SPEC = importlib.util.spec_from_file_location('hardware_policy', Path(__file__).parents[1] / 'image/hardware_policy.py')
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class HardwareImagePolicyTests(unittest.TestCase):
    def test_write_match_includes_both_power_aliases(self):
        for destination in policy.POWER:
            for interface, member in ((destination, 'HoldProfile'), (destination, 'ReleaseProfile'), ('org.freedesktop.DBus.Properties', 'Set')):
                with self.subTest(destination=destination, interface=interface, member=member):
                    self.assertTrue(policy._may_write(ET.Element('allow', {'send_destination': destination, 'send_interface': interface, 'send_member': member})))
                    self.assertTrue(policy._may_write(ET.Element('allow', {'send_destination': destination, 'send_member': member})))

    def test_brightness_and_wildcard_matching(self):
        for attributes in (
            {'send_destination': policy.LOGIN},
            {'send_destination': '*'},
            {'send_type': 'method_call'},
            {'send_destination_prefix': 'org.freedesktop', 'send_member': 'SetBrightness'},
            {'send_destination': policy.LOGIN, 'send_interface': policy.LOGIN + '.Session', 'send_member': 'SetBrightness'},
        ):
            self.assertTrue(policy._may_write(ET.Element('allow', attributes)))

    def test_unrelated_rules_remain_usable(self):
        for attributes in (
            {'user': '*'}, {'receive_type': 'method_call'}, {'send_type': 'signal'},
            {'send_destination': 'org.freedesktop.NetworkManager'},
            {'send_destination': policy.LOGIN, 'send_interface': policy.LOGIN + '.Manager'},
            {'send_destination': policy.POWER[0], 'send_interface': 'org.freedesktop.DBus.Properties', 'send_member': 'Get'},
            {'send_interface': 'org.freedesktop.DBus.Properties', 'send_path': '/org/freedesktop/GeoClue2/Agent'},
        ):
            self.assertFalse(policy._may_write(ET.Element('allow', attributes)))

    def fixture(self, config, extra=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for path, text in {'usr/share/dbus-1/system.conf': config, **(extra or {})}.items():
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text)
        return root

    def test_recursive_merged_policies_and_root_exception(self):
        root = self.fixture('<busconfig><includedir>system.d</includedir></busconfig>', {
            'usr/share/dbus-1/system.d/safe.conf': '<busconfig><policy user="root"><allow send_destination="*"/></policy><policy context="default"><deny send_type="method_call"/></policy></busconfig>'})
        self.assertEqual(len(policy.audit_bus(root)), 2)

    def test_every_nonroot_policy_context_refuses_write_override(self):
        for attributes in ('context="default"', 'context="mandatory"', 'user="nobody"', 'group="video"', 'at_console="true"'):
            root = self.fixture('<busconfig><policy ' + attributes + '><allow send_destination="org.freedesktop.login1"/></policy></busconfig>')
            with self.subTest(attributes=attributes), self.assertRaises(ValueError):
                policy.audit_bus(root)

    def test_mandatory_deny_cannot_fake_root_access(self):
        root = self.fixture('<busconfig><policy context="mandatory"><deny send_destination="net.hadess.PowerProfiles"/></policy></busconfig>')
        with self.assertRaises(ValueError):
            policy.audit_bus(root)

    def test_unprivileged_service_ownership_refuses(self):
        for rule in ('own="*"', 'own="org.freedesktop.UPower.PowerProfiles"', 'own_prefix="org.freedesktop"'):
            root = self.fixture('<busconfig><policy user="nobody"><allow ' + rule + '/></policy></busconfig>')
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                policy.audit_bus(root)

    def test_include_loop_and_escape_refuse(self):
        for include in ('system.conf', '../escape.conf'):
            root = self.fixture('<busconfig><include>' + include + '</include></busconfig>')
            with self.subTest(include=include), self.assertRaises(ValueError):
                policy.audit_bus(root)

    def test_missing_optional_include_and_selinux_condition(self):
        root = self.fixture('<busconfig><include ignore_missing="yes">absent.conf</include><include if_selinux_enabled="yes" selinux_root_relative="yes">contexts/dbus_contexts</include></busconfig>')
        self.assertEqual(len(policy.audit_bus(root)), 1)

    def test_unsupported_upstream_and_entity_declarations_refuse(self):
        with self.assertRaises(ValueError):
            policy.mediate_login(b'<busconfig/>')
        with self.assertRaises(ValueError):
            policy.mediate_power(b'<busconfig/>', policy.POWER[0])
        with self.assertRaises(ValueError):
            policy._xml(b'<!DOCTYPE busconfig [<!ENTITY x "y">]><busconfig/>')

    def test_symlinked_or_writable_inputs_refuse(self):
        root = self.fixture('<busconfig/>')
        selected = root / 'usr/share/dbus-1/system.conf'
        selected.chmod(0o666)
        with self.assertRaises(ValueError):
            policy.audit_bus(root)
        selected.chmod(0o644)
        selected.rename(selected.with_suffix('.original'))
        selected.symlink_to('system.original')
        with self.assertRaises(ValueError):
            policy.audit_bus(root)

    def test_unsafe_ordinary_udev_writer_refuses(self):
        root = self.fixture('<busconfig/>', {'etc/udev/rules.d/70-display.rules': 'SUBSYSTEM=="backlight", RUN+="chmod 666 brightness"\n'})
        with self.assertRaises(ValueError):
            policy.writer_inputs(root)

    def test_headless_requires_real_power_profile_package_too(self):
        root = self.fixture('<busconfig/>')
        with self.assertRaises((ValueError, FileNotFoundError)):
            policy.configure(root, 'headless')
        with self.assertRaises(ValueError):
            policy.configure(root, 'unknown')

    def test_readonly_verifier_never_creates_missing_state(self):
        root = self.fixture('<busconfig/>')
        before = sorted(path.relative_to(root).as_posix() for path in root.rglob('*'))
        with self.assertRaises(FileNotFoundError):
            policy.verify(root)
        self.assertEqual(before, sorted(path.relative_to(root).as_posix() for path in root.rglob('*')))

    def test_duplicate_manifest_fields_refuse(self):
        root = self.fixture('<busconfig/>', {policy.MANIFEST: '{"schema_version":1,"schema_version":1}\n'})
        with self.assertRaises(ValueError):
            policy.verify(root)

    def test_readonly_parent_check_does_not_make_a_directory(self):
        root = self.fixture('<busconfig/>')
        with self.assertRaises(ValueError):
            policy._parent(root, 'absent/directory/file', create=False)
        self.assertFalse((root / 'absent').exists())


if __name__ == '__main__':
    unittest.main()
