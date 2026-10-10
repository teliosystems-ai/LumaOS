"""Protected UTC deployment/source-input checks; no host clock or services."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / 'native/image/utc'


def module(name):
    spec = importlib.util.spec_from_file_location(name, ASSETS / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class UtcDeployment(unittest.TestCase):
    def test_release_input_never_overwrites_or_accepts_wrong_bytes(self):
        acquire = module('prepare_release_input')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            cached = base / 'archive'
            cached.write_bytes(b'verified fixture archive')
            context = base / 'context'
            context.mkdir()
            with patch.object(acquire, 'SHA256', hashlib.sha256(cached.read_bytes()).hexdigest()):
                acquire.prepare(context, cached)
                self.assertEqual((context / 'chrony-4.9.tar.gz').read_bytes(), cached.read_bytes())
                self.assertIn('"signature_verified": false', (context / 'chrony-4.9.provenance.json').read_text())
                with self.assertRaises(ValueError):
                    acquire.prepare(context, cached)
            invalid = base / 'invalid'
            invalid.mkdir()
            with self.assertRaises(ValueError):
                acquire.prepare(invalid, cached)
            self.assertTrue((invalid / 'chrony-4.9.tar.gz').exists())
            self.assertFalse((invalid / 'chrony-4.9.provenance.json').exists())

    def test_release_candidate_never_promotes_fixture_or_omits_confinement(self):
        prepare = module('prepare_chrony')
        self.assertEqual(prepare.RELEASE, '4.9')
        self.assertEqual(prepare.RELEASE_ARCHIVE_SHA256,
                         '4924c6f530105bcd5b9e9e33c48a2ae1bfd889222c8480bc41601110efc864d0')
        self.assertNotEqual(prepare.RELEASE_ARCHIVE_SHA256, prepare.ARCHIVE_SHA256)
        self.assertIn('tls_gnutls.c', prepare.RELEASE_PINS)
        self.assertIn('sys_linux.c', prepare.RELEASE_PINS)
        script = (ASSETS / 'build_release.sh').read_text()
        for mandatory in ('--release-candidate', 'FEAT_NTS 1', 'FEAT_PRIVDROP 1',
                          'FEAT_SCFILTER 1', '+NTS', '+SCFILTER', 'dpkg-query', 'COPYING.chrony'):
            self.assertIn(mandatory, script)
        self.assertNotIn('--without-seccomp', script)
        self.assertNotIn('--without-libcap', script)

    def test_keeper_has_read_only_producer_metadata_but_no_tpm_or_network(self):
        unit = (ASSETS / 'luma-utc-keeper.service').read_text()
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-utc-keeper').read_text()
        self.assertIn('Restart=no', unit)
        self.assertIn('Before=sleep.target', unit)
        self.assertIn('ntp.service sleep.target', unit)
        self.assertIn('RestrictAddressFamilies=AF_UNIX', unit)
        self.assertIn('InaccessiblePaths=/var/lib/luma-os', unit)
        self.assertIn('ptrace (read) peer=luma-utc-producer', profile)
        self.assertNotIn('ptrace (trace)', profile)
        self.assertNotIn('network inet', profile)
        self.assertIn('deny /dev/{tpm*', profile)
        self.assertNotIn('DeviceAllow=/dev/tpm', unit)

    def test_producer_start_requires_seed_and_fixed_measurement_socket(self):
        unit = (ASSETS / 'luma-utc-producer.service').read_text()
        path = (ASSETS / 'luma-utc-producer.path').read_text()
        self.assertIn('ConditionPathExists=/run/luma-utc/seed-ready', unit)
        self.assertIn('ConditionPathExists=/run/luma-utc/measurements.sock', unit)
        self.assertIn('User=luma-utc-producer', unit)
        self.assertIn('chronyd -n -U -f', unit)
        self.assertIn('CapabilityBoundingSet=CAP_SYS_TIME', unit)
        self.assertIn('Restart=no', unit)
        self.assertIn('PathExists=/run/luma-utc/seed-ready', path)

    def test_live_client_is_peer_pinned_and_not_caller_constructible(self):
        source = (ROOT / 'rust/luma-platform/src/utc_provider.rs').read_text()
        client = source.split('pub(crate) struct Client', 1)[1].split('impl Client', 1)[0]
        self.assertNotIn('pub ', client)
        self.assertNotIn('Serialize', client)
        for boundary in ('service::peer_pidfd', 'SO_PEERSEC', 'SO_PEERCRED',
                         'self.fenced = true', 'binding_digest(binding)',
                         'self.watch.check()?', 'reply.context.validate()?',
                         'seed_transport', 'custody.observe(', 'account.observe('):
            self.assertIn(boundary, source)
        self.assertNotIn('caller_pid', source)
        self.assertNotIn('trusted: bool', source)

    def test_explicit_restart_is_fixed_kernel_authenticated_and_never_retries(self):
        source = (ROOT / 'rust/luma-platform/src/utc_restart.c').read_text()
        provider = (ROOT / 'rust/luma-platform/src/utc_provider.rs').read_text()
        for check in ('SO_PEERPIDFD', 'SO_PEERSEC', 'luma-admin (enforce)',
                      'luma-utc-restart (enforce)', 'argc != 1',
                      '"luma-utc-keeper.service"', '"luma-utc-producer.path"',
                      '"--no-ask-password"', 'execve(command[0], command, environment)'):
            self.assertIn(check, source)
        self.assertNotIn('system(', source)
        self.assertNotIn('argv[1]', source)
        for check in ('reacquire_admin', 'reacquire_custody', 'restart_review(binding, &reply)',
                      'after.instance == instance', 'Duration::from_secs(10)',
                      'never automatically retry'):
            self.assertIn(check, provider)


if __name__ == '__main__':
    unittest.main()
