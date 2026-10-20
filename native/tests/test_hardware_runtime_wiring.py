"""Exact installed-path inventory regressions, not an AppArmor evaluator.

These assertions join source-owned package paths, activation units and explicit
read/deny declarations. They do not simulate LSM precedence or claim that a
native service, daemon, device or permission ceremony has run successfully.
"""
import ast
import importlib.util
from pathlib import Path
import unittest

REPO = Path(__file__).resolve().parents[2]
IMAGE = REPO / 'native/image'
OVERLAY = IMAGE / 'overlay'


def text(path):
    return path.read_text(encoding='utf-8')


def declarations(path):
    return {line.strip() for line in text(path).splitlines()
            if line.strip() and not line.lstrip().startswith('#')}


def constants(path):
    return {node.value for node in ast.walk(ast.parse(text(path)))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)}


def unit(path):
    values = {}
    for raw in text(path).splitlines():
        line = raw.strip()
        if not line or line.startswith(('#', '[')):
            continue
        name, separator, value = line.partition('=')
        if not separator:
            raise AssertionError('unexpected unit continuation in exact inventory')
        values.setdefault(name, []).append(value)
    return values


class HardwareRuntimeWiring(unittest.TestCase):
    def test_exact_helper_paths_and_activation_contract_are_packaged(self):
        assembly = constants(IMAGE / 'assemble.py')
        for stem, binary, socket, capabilities, source in (
            ('luma-hardware-query', 'hardware-bpf-query', '/run/luma-hardware/query.sock',
             'CAP_NET_ADMIN CAP_SYS_PTRACE', 'native/image/hardware_query/worker.c'),
            ('luma-hardware-daemon-observer', 'hardware-daemon-observer',
             '/run/luma-hardware-daemon-observer/observe.sock', 'CAP_SYS_PTRACE',
             'native/image/hardware_query/daemon.c'),
        ):
            with self.subTest(helper=stem):
                service = unit(OVERLAY / 'etc/systemd/system' / (stem + '@.service'))
                listener = unit(OVERLAY / 'etc/systemd/system' / (stem + '.socket'))
                self.assertEqual(service['ExecStart'], ['/usr/libexec/luma-os/' + binary])
                for key, expected in {'User': 'root', 'Group': 'root', 'Slice': 'system.slice',
                        'AppArmorProfile': stem, 'StandardInput': 'socket',
                        'StandardOutput': 'socket', 'NoNewPrivileges': 'yes',
                        'CapabilityBoundingSet': capabilities, 'AmbientCapabilities': '',
                        'ProtectControlGroups': 'yes', 'PrivateDevices': 'yes',
                        'RestrictAddressFamilies': 'AF_UNIX', 'LimitNOFILE': '16',
                        'MemorySwapMax': '0', 'TasksMax': '1', 'RuntimeMaxSec': '2'}.items():
                    self.assertEqual(service[key], [expected], (stem, key))
                self.assertIn('~ptrace process_vm_readv process_vm_writev',
                              ' '.join(service['SystemCallFilter']))
                self.assertEqual(listener['ListenSequentialPacket'], [socket])
                for key, expected in {'Accept': 'yes', 'DirectoryMode': '0700',
                                      'SocketMode': '0600', 'SocketUser': 'root',
                                      'SocketGroup': 'root'}.items():
                    self.assertEqual(listener[key], [expected])
                self.assertIn(stem + '.socket', assembly)
                self.assertIn('sockets.target', assembly)
                self.assertIn(source, assembly)
                self.assertTrue((OVERLAY / 'etc/apparmor.d' / stem).is_file())

    def test_fixed_parent_defaults_and_boot_lifetime_lock_inodes_agree(self):
        paths = declarations(OVERLAY / 'etc/tmpfiles.d/luma-hardware.conf')
        self.assertIn('d /run/luma-hardware 0700 root root -', paths)
        for worker in ('model', 'acquisition'):
            self.assertIn('f /run/luma-hardware/worker-' + worker + '.lock 0600 root root -', paths)
        for name in ('lumamodel.slice', 'lumaacquisition.slice'):
            values = unit(OVERLAY / 'etc/systemd/system' / name)
            for key, expected in {'IPAddressDeny': 'any', 'IPAddressAllow': 'localhost',
                                  'CPUQuota': '200%', 'MemorySwapMax': '0',
                                  'IOReadBandwidthMax': '/var 64M',
                                  'IOWriteBandwidthMax': '/var 64M'}.items():
                self.assertEqual(values[key], [expected])
        broker = unit(OVERLAY / 'etc/systemd/system/luma-broker.service')
        self.assertNotIn('luma-hardware', ' '.join(broker.get('RuntimeDirectory', [])))
        self.assertIn('/run/luma-hardware', ' '.join(broker['ReadWritePaths']))
        profile = declarations(OVERLAY / 'etc/apparmor.d/luma-broker')
        self.assertIn('ptrace (read) peer=luma-hardware,', profile)

    def test_platform_closure_has_exact_required_read_declarations(self):
        spec = importlib.util.spec_from_file_location('luma_hardware_wiring_policy', IMAGE / 'hardware_policy.py')
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        self.assertEqual(set(policy.PLATFORM_FILES), {
            'usr/bin/dbus-daemon', 'usr/lib/systemd/systemd',
            'usr/lib/systemd/system/dbus.service', 'usr/lib/systemd/system/dbus.socket'})
        profile = declarations(OVERLAY / 'etc/apparmor.d/luma-hardware')
        # These are deliberately exact source declarations. We do not infer
        # permission using fnmatch, ignore deny precedence or emulate AppArmor.
        for required in ('/usr/bin/dbus-daemon r,', '/{usr/,}lib{,64}/** mr,',
                '/usr/libexec/power-profiles-daemon r,',
                '/usr/libexec/luma-os/hardware_writer_verify.py r,',
                '/usr/bin/python3{,.12} mrix,', '/usr/share/luma-os/** r,'):
            self.assertIn(required, profile)
        for forbidden in ('capability sys_admin,', 'capability bpf,',
                           'capability net_admin,', 'capability sys_ptrace,'):
            self.assertNotIn(forbidden, profile)

    def test_installed_public_identity_aliases_have_narrow_consumer_reads(self):
        assembly = text(IMAGE / 'assemble.py')
        self.assertIn("source.symlink_to('../var/lib/luma-os/identity/'+name)", assembly)
        self.assertIn("(ROOT/'etc/machine-id').symlink_to('../var/lib/luma-os/identity/machine-id')", assembly)
        self.assertIn("(ROOT/'var/lib/dbus/machine-id').symlink_to('../luma-os/identity/machine-id')", assembly)
        observer = declarations(OVERLAY / 'etc/apparmor.d/luma-hardware-daemon-observer')
        self.assertIn('/var/lib/luma-os/identity/passwd r,', observer)
        self.assertNotIn('deny /var/lib/luma-os/** rwklx,', observer)
        self.assertIn('deny /var/lib/luma-os/** wklx,', observer)
        daemon = text(IMAGE / 'hardware_query/daemon.c')
        self.assertIn('/var/lib/luma-os/identity/passwd', daemon)
        self.assertIn('../var/lib/luma-os/identity/passwd', daemon)
        # Audio/video and playback need only these public aliases. Renderer and
        # descriptor-only ASR receive no new account or machine-id access.
        for name in ('luma-workspace-capture', 'luma-workspace-speech'):
            source = text(OVERLAY / 'etc/apparmor.d' / name)
            self.assertIn('/var/lib/luma-os/identity/{passwd,group,machine-id} r,', source)
            self.assertIn('deny /var/lib/luma-os/** wklmx,', source)

    def test_desktop_controllers_and_operator_guides_have_actual_copy_sources(self):
        assembly = constants(IMAGE / 'assemble.py')
        for name in ('workspace_capture.py', 'workspace_draft.py', 'workspace_collections.py',
                     'workspace_grounding.py', 'workspace_speech.py'):
            self.assertIn(name, assembly)
            self.assertTrue((REPO / 'native/desktop' / name).is_file())
            self.assertLessEqual((REPO / 'native/desktop' / name).stat().st_size, 131072)
        for target, source in (
            ('usr/share/doc/luma-os/hardware-policy.md', 'native/image/HARDWARE_POLICY.md'),
            ('usr/share/doc/luma-os/speech.md', 'native/image/speech/README.md'),
        ):
            self.assertIn(target, assembly)
            self.assertTrue((REPO / source).is_file())


if __name__ == '__main__':
    unittest.main()
