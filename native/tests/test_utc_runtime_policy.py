"""UTC deployment composition checks, not installed NTS or clock qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / 'rust/luma-platform/src'


class UtcRuntimePolicy(unittest.TestCase):
    def test_history_observations_are_sealed_and_not_wire_capabilities(self):
        stream = (RUST / 'utc_stream.rs').read_text()
        observation = stream.split('pub(crate) struct Observation {', 1)[1].split('impl Observation', 1)[0]
        self.assertIn('context: Statement', observation)
        self.assertNotIn('pub ', observation)
        self.assertNotIn('Clone', observation)
        fixture = stream.split('pub(crate) fn fixture(', 1)[0]
        self.assertTrue(fixture.rstrip().endswith('#[cfg(test)]'))
        delivery = stream.split('impl HistoryDelivery', 1)[1].split('// The receiver', 1)[0]
        for check in ('self.stream.stream.poll()?', 'runtime_digest()?.to_owned()',
                      'candidate_after_history()', 'statement.supported_by(',
                      'self.stream.invalidate()', 'producer.process_generation',
                      'producer.source_clock_generation', 'keeper.epoch().clock_generation'):
            self.assertIn(check, delivery)

    def test_history_delivery_requires_real_pam_and_same_shared_checkpoint(self):
        governance = (RUST / 'admin_governance.rs').read_text()
        live = governance.split('pub(crate) fn execute_history_live', 1)[1].split('// Arbitrary authentication', 1)[0]
        for check in ('account: &authentication::AuthenticatedAccount', 'crate::require_root()?',
                      'platform::require_installed()?', 'HistoryReader::new(store, directory).read()?',
                      'account.identity()', 'stream.history_delivery(&binding)?.support(proposed)',
                      'stream.invalidate()'):
            self.assertIn(check, live)
        self.assertNotIn('caller_pid', live)
        self.assertNotIn('Observation', live)
        prefix = governance.split('fn execute_history<', 1)[0]
        self.assertTrue(prefix.rstrip().endswith('#[cfg(test)]'))
        stream = (RUST / 'utc_stream.rs').read_text()
        self.assertIn('current != &self.history', stream)
        self.assertNotIn('Serialize', stream.split('pub(crate) struct HistoryDelivery', 1)[1].split('impl HistoryDelivery', 1)[0])

    def test_raw_receiver_construction_is_fixture_only(self):
        receiver = (RUST / 'utc_receiver.rs').read_text()
        prefix = receiver.split('pub(crate) fn attach(', 1)[0]
        self.assertTrue(prefix.rstrip().endswith('#[cfg(test)]'))
        admitted = receiver.split('pub(crate) fn admitted(', 1)[1].split('pub(crate) fn epoch(', 1)[0]
        for proof in ('admission: crate::utc_runtime::Admission', 'PinnedProcess::capture(',
                      'kernel_boot()?', 'admission.recheck(peer.pid)?', 'boundary.watch.check()?',
                      'cursor.accept(', 'admission: Some(admission)', 'initial: Some(round)'):
            self.assertIn(proof, admitted)

    def test_runtime_manifest_does_not_serialize_admission_or_accept_caller_process(self):
        runtime = (RUST / 'utc_runtime.rs').read_text()
        admission = runtime.split('pub(crate) struct Admission {', 1)[1].split('impl Admission', 1)[0]
        self.assertIn('deployment: Deployment', admission)
        self.assertIn('endpoint: SocketPin', admission)
        self.assertNotIn('Serialize', admission)
        acquire = runtime.split('pub(crate) fn acquire(', 1)[1]
        self.assertIn('utc_receiver::receive(&self.socket)?', acquire)
        self.assertIn('peer.uid != PRODUCER_ID || peer.gid != PRODUCER_ID', acquire)
        self.assertIn('self.admission.recheck(peer.pid)?', acquire)
        self.assertNotIn('caller_pid:', runtime)
        self.assertNotIn('caller_runtime:', runtime)

    def test_runtime_requires_readonly_release_and_retained_descriptors(self):
        runtime = (RUST / 'utc_runtime.rs').read_text()
        for check in ('libc::fstatvfs(', 'libc::ST_RDONLY', 'libc::O_NOFOLLOW',
                      'libc::O_CLOEXEC', 'libc::openat(', 'self.file.metadata()',
                      'fs::symlink_metadata(&self.path)', 'pin.digest()? != artifact.sha256',
                      'serde_json::to_vec(&document)? != bytes', 'parents: Vec<Parent>'):
            self.assertIn(check, runtime)
        self.assertNotIn('allow_mutable', runtime)
        self.assertNotIn('trust_manifest', runtime)

    def test_live_process_admission_checks_code_namespace_and_enforcement(self):
        runtime = (RUST / 'utc_runtime.rs').read_text()
        for check in ('luma-utc-producer (enforce)', '0::/system.slice/luma-utc-producer.service',
                      'Identity::of(&executable) != *approved', 'Identity::of(&visible) != pin.identity',
                      'mapping_inventory(', 'vdso_address(', 'command_line()', 'environment(',
                      'controls(', 'self::tasks(&task_path)? != tasks', 'info.f_type != 0x9fa0'):
            self.assertIn(check, runtime)
        self.assertNotIn('unconfined fallback', runtime)

    def test_socket_has_fixed_owner_mode_and_preserves_conflicts(self):
        runtime = (RUST / 'utc_runtime.rs').read_text()
        production = runtime.split('#[cfg(test)]\nmod tests', 1)[0]
        endpoint = runtime.split('impl Endpoint {', 1)[1].split('impl Pin {', 1)[0]
        for check in ('"/run/luma-utc"', '"measurements.sock"', 'PRODUCER_ID: u32 = 987'):
            self.assertIn(check, production)
        self.assertIn('Some((0o710, PRODUCER_ID))', endpoint)
        self.assertIn('bind_socket(parent)?', endpoint)
        binding = runtime.split('fn bind_socket(', 1)[1].split('impl Endpoint {', 1)[0]
        for check in ('libc::fchownat(', '0o660',
                      'metadata.file_type().is_socket()', 'metadata.nlink() != 1',
                      'UnixDatagram::bind(', 'utc_receiver::configure(&socket)?'):
            self.assertIn(check, binding)
        self.assertIn('Duration::from_secs(2)', endpoint)
        self.assertIn('barrier_ms', endpoint)
        self.assertNotIn('remove_file', endpoint)
        self.assertNotIn('impl Drop for Endpoint', runtime)
        self.assertNotIn('unlink(', endpoint)

    def test_acquisition_watch_precedes_listener_and_survives_keeper_attachment(self):
        runtime = (RUST / 'utc_runtime.rs').read_text().split('impl Endpoint {', 1)[1]
        self.assertLess(runtime.index('StepWatch::arm()?'), runtime.index('bind_socket(parent)?'))
        self.assertLess(runtime.index('Receiver::clock(0)?'), runtime.index('bind_socket(parent)?'))
        self.assertIn('boundary: Boundary', runtime)
        self.assertIn('self.boundary.watch.check()?', runtime)
        receiver = (RUST / 'utc_receiver.rs').read_text()
        self.assertIn('self.boundary.take()', receiver)
        self.assertIn('UTC acquisition boundary absent or already consumed', receiver)
        stream = (RUST / 'utc_stream.rs').read_text()
        self.assertIn('receiver.acquisition_boundary(suspend_generation)?', stream)

    def test_closed_configuration_matches_approved_sources_without_clock_fallback(self):
        config = (ROOT / 'native/image/utc/chrony.conf').read_text()
        active = [line for line in config.splitlines() if line and not line.startswith('#')]
        self.assertEqual([line for line in active if line.startswith('server ')], [
            'server time.cloudflare.com nts minpoll 6 maxpoll 7',
            'server nts.netnod.se nts minpoll 6 maxpoll 7',
            'server ptbtime1.ptb.de nts minpoll 6 maxpoll 7',
        ])
        for directive in ('authselectmode require', 'minsources 2', 'maxdistance 0.25',
                          'maxdrift 25', 'maxslewrate 25', 'maxclockerror 50', 'nosystemcert',
                          'ntstrustedcerts /usr/share/luma-os/utc/ca-certificates.crt',
                          'port 0', 'cmdport 0', 'bindcmdaddress /'):
            self.assertIn(directive, active)
        for directive in ('include ', 'confdir ', 'sourcedir ', 'pool ', 'refclock ', 'local ',
                          'manual', 'nocerttimecheck', 'makestep', 'rtcsync', 'smoothtime'):
            self.assertFalse(any(line.startswith(directive) for line in active), directive)
        runtime = (RUST / 'utc_runtime.rs').read_text()
        self.assertIn('pin.bytes(MAX_MANIFEST)? != CONFIGURATION_BYTES', runtime)

    def test_keeper_activation_keeps_seed_measurements_and_authority_separate(self):
        main = (RUST / 'main.rs').read_text()
        self.assertIn('mod utc_runtime;', main)
        self.assertNotIn('Some("utc-runtime")', main)
        self.assertIn('Some("utc-keeper")', main)
        self.assertIn('utc_provider::serve()', main)
        provider = (RUST / 'utc_provider.rs').read_text()
        for check in ('struct Client', 'SO_PEERSEC', 'SO_PEERCRED',
                      'service::peer_pidfd', 'binding_digest(binding)',
                      'self.watch.check()?',
                      'seed_transport', 'luma-admin (enforce)'):
            self.assertIn(check, provider)
        self.assertNotIn('Deserialize', provider.split('pub(crate) struct Client', 1)[1].split('impl Client', 1)[0])
        runtime = (RUST / 'utc_runtime.rs').read_text()
        for forbidden in ('clock_settime(', 'settimeofday(', 'adjtimex(', 'Command::new(',
                          'trusted_utc_available: true', 'pub(crate) fn grant'):
            self.assertNotIn(forbidden, runtime)
