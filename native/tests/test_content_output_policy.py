"""Read-only source policy checks; loaded confinement needs native qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / 'rust/luma-platform/src'


class ContentOutputPolicyTests(unittest.TestCase):
    def test_c_remains_capability_free_and_delegates_fresh_original_credentials_to_broker(self):
        unit = (ROOT / 'native/image/overlay/etc/systemd/system/luma-content-custody.service').read_text()
        policy = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-content-custody').read_text()
        output = (SRC / 'content_custody/output.rs').read_text()
        self.assertIn('CapabilityBoundingSet=\n', unit)
        self.assertNotIn('capability sys_ptrace', policy)
        self.assertNotIn('ptrace (read) peer=', policy)
        self.assertNotIn('credential_observer::kernel_check', output)
        for fence in ('pidfd_alive(&pin)?', 'peer_label(stream, "luma-granted-client (enforce)")?',
                      'client_start: generation', 'content_output::proof(&guard)?',
                      'store.selected(&request.descriptor.binding, &mut live)?'):
            self.assertIn(fence, output)
        for forbidden in ('require_admin', 'io::installation', 'store.commit', 'store.publish'):
            self.assertNotIn(forbidden, output)

    def test_broker_proves_current_original_generation_input_and_full_effect_pair(self):
        output = (SRC / 'service/content_output.rs').read_text()
        admission = (SRC / 'service/granted_gateway.rs').read_text()
        manager = (SRC / 'resource_manager.rs').read_text()
        for fence in ('Admission::capture_acquisition', 'original_binding(',
                      'self.admission.check()?', 'self.admission.attribution()?',
                      'verify_client_request(', 'descriptor.binding.owner_generation'):
            self.assertIn(fence, output)
        self.assertIn('credential_observer::kernel_check(&self.pin, 0, 0)?', admission)
        guard = manager[manager.index('pub(crate) fn content_output_guard('):manager.index('pub(crate) fn register_content_admin(')]
        self.assertEqual(guard.count('request.descriptor.ledger(&self.store.read()?)?'), 2)
        for fence in ('peer::live_generation(peer, &pin)?', '.guard(request)?', 'self.custody_memory.baseline()?'):
            self.assertIn(fence, guard)
        routing = admission[admission.index('fn acquisition_audit('):admission.index('pub(crate) fn acquisition_proof(')]
        self.assertIn('"native-content-store-v1"', routing)
        self.assertIn('"native-content-recovery-v1"', routing)
        self.assertIn('content_pair(usage)', routing)

    def test_read_only_c_purpose_cannot_fall_through_into_admin_channel(self):
        output = (SRC / 'content_custody/output.rs').read_text()
        protocol = (SRC / 'content_custody/protocol.rs').read_text()
        for fence in ('deny_unknown_fields', 'canonical(bytes, 8192)?',
                      'request.descriptor.binding', 'original()? != initial', 'live()?;'):
            self.assertIn(fence, output)
        dispatch = protocol[protocol.index('fn handle(stream:'):protocol.index('let mut deadline = Instant::now() + DEADLINE;')]
        self.assertIn('discriminator.get("purpose")', dispatch)
        self.assertIn('Some(output::PURPOSE)', dispatch)
        self.assertIn('return output::handle(stream, confinement, &bytes);', dispatch)
        self.assertIn('return handle_admin(stream, confinement, &bytes);', dispatch)


if __name__ == '__main__':
    unittest.main()
