"""Source deployment contracts; these tests do not claim loaded LSM enforcement."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
OVERLAY = ROOT / 'native/image/overlay'
SRC = ROOT / 'rust/luma-platform/src'


def unit_values(text):
    values = {}
    section = None
    for line in text.splitlines():
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
        elif section == 'Service' and '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            values.setdefault(key, []).append(value)
    return values


class ContentDataObserverPolicyTests(unittest.TestCase):
    def test_packaged_daemon_has_an_exact_native_dispatch_and_protected_parent(self):
        main = (SRC / 'main.rs').read_text()
        assemble = (ROOT / 'native/image/assemble.py').read_text()
        custody = (OVERLAY / 'etc/systemd/system/luma-content-custody.service').read_text()
        self.assertIn('mod content_data_observer;', main)
        self.assertIn('Some("content-data-observer") if args.len() == 1 => content_data_observer::command(),', main)
        self.assertIn("'luma-content-data-observer.service'", assemble)
        self.assertIn("(ROOT/'var/lib/luma-os/content-store').mkdir()", assemble)
        self.assertIn("(ROOT/'var/lib/luma-os/content-store').chmod(0o700)", assemble)
        self.assertIn('Wants=luma-content-data-observer.service', custody)

    def test_service_is_capability_free_readonly_and_finitely_confined(self):
        unit = unit_values((OVERLAY / 'etc/systemd/system/luma-content-data-observer.service').read_text())
        expected = {
            'ExecStart': '/usr/libexec/luma-os/luma-platform content-data-observer',
            'User': 'root', 'Group': 'root', 'UMask': '0077',
            'CapabilityBoundingSet': '', 'AmbientCapabilities': '',
            'NoNewPrivileges': 'yes', 'ProtectSystem': 'strict',
            'PrivateDevices': 'yes', 'DevicePolicy': 'closed',
            'RestrictAddressFamilies': 'AF_UNIX', 'RestrictNamespaces': 'yes',
            'MemoryMax': '256M', 'MemorySwapMax': '0', 'TasksMax': '2',
            'CPUQuota': '25%', 'CPUQuotaPeriodSec': '100ms',
            'LimitNOFILE': '256', 'LimitMEMLOCK': '0', 'LimitCORE': '0',
            'AppArmorProfile': 'luma-content-data-observer',
            'ReadOnlyPaths': '/var/lib/luma-os/content-store',
            'ReadWritePaths': '/run/luma-content-data-observer',
        }
        for key, value in expected.items():
            with self.subTest(key=key):
                self.assertEqual(unit[key], [value])
        self.assertNotIn('DeviceAllow', unit)

    def test_observer_has_no_tpm_authority_or_network_membrane_escape(self):
        profile = (OVERLAY / 'etc/apparmor.d/luma-content-data-observer').read_text()
        for fence in (
            'deny network inet,', 'deny network inet6,',
            'deny ptrace (trace,tracedby),',
            'deny /var/lib/luma-os/** wklmx,',
            'deny /var/lib/luma-broker/** rwklmx,',
            'deny /etc/{passwd,group,shadow,gshadow} rwklmx,',
            'deny /dev/{tpm*,mem,kmem,port,kvm,dxg,nvidia*,dri/**} rw,',
            'deny unix (bind,listen,accept) addr=@**,',
            'deny unix (connect,send,receive) peer=(addr=@**),',
            'unix (send,receive) type=stream peer=(label=luma-content-custody),',
        ):
            self.assertIn(fence, profile)
        allow_rules = [line.strip() for line in profile.splitlines()
                       if line.strip() and not line.lstrip().startswith(('#', 'deny '))]
        self.assertFalse(any(line.startswith('capability ') for line in allow_rules))
        self.assertFalse(any(line.startswith('unix (connect') for line in allow_rules))
        self.assertFalse(any('/dev/tpm' in line for line in allow_rules))
        self.assertFalse(any('/var/lib/luma-os/content-checkpoint/' in line for line in allow_rules))

    def test_c_uses_only_fixed_observer_socket_and_retains_direct_content_denial(self):
        profile = (OVERLAY / 'etc/apparmor.d/luma-content-custody').read_text()
        self.assertIn('/run/luma-content-data-observer/read.sock rw,', profile)
        self.assertIn('unix (connect,send,receive) type=stream peer=(label=luma-content-data-observer),', profile)
        self.assertIn('deny /var/lib/luma-os/content-store/** rwklmx,', profile)
        self.assertNotIn('capability dac_override', profile)
        self.assertNotIn('capability sys_admin', profile)

    def test_c_paged_files_stay_in_closed_classes_with_no_recursive_write_allow(self):
        profile = (OVERLAY / 'etc/apparmor.d/luma-content-custody').read_text()
        prefix = '/var/lib/luma-os/content-checkpoint/paged-v3/'
        for suffix in ('identity.json rw,', '{selected.json,pending.json} rw,',
                       'controls/{selector-0,selector-1,pending} rw,',
                       'tails/[0-9a-f]*/identity.json rw,'):
            self.assertIn(prefix + suffix, profile)
        self.assertNotIn(prefix + '**', profile)
        self.assertNotIn('/var/lib/luma-os/** rw,', profile)

    def test_live_kernel_identity_is_not_supplied_by_context_json(self):
        endpoint = (SRC / 'content_data_observer/endpoint.rs').read_text()
        client = (SRC / 'content_data_observer/client.rs').read_text()
        for fence in ('kernel_unix::KernelUnix::capture()?', 'crate::service::credentials(socket)?',
                      'crate::service::peer_pidfd(socket)?', 'pidfd_alive(&self.pin)?',
                      'start(self.pid)? != self.start', 'label(socket)? != self.label'):
            self.assertIn(fence, endpoint)
        self.assertIn("original: &'a mut dyn FnMut() -> Result<()>", client)
        self.assertIn('(self.original)()?;', client)
        self.assertIn('self.peer.check(&self.socket)', client)

    def test_actual_c_callers_can_read_only_the_required_kernel_feature_witness(self):
        for name in ('luma-acquisition', 'luma-granted-client'):
            profile = (OVERLAY / 'etc/apparmor.d' / name).read_text()
            for path in ('/sys/', '/sys/kernel/', '/sys/kernel/security/',
                         '/sys/kernel/security/apparmor/', '/sys/kernel/security/apparmor/features/',
                         '/sys/kernel/security/apparmor/features/network/',
                         '/sys/kernel/security/apparmor/features/network/af_unix'):
                with self.subTest(profile=name, path=path):
                    self.assertIn(path + ' r,', profile)
                    self.assertNotIn(path + ' rw,', profile)


if __name__ == '__main__':
    unittest.main()
