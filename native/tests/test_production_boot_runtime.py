"""Source-boundary regressions, not firmware, disk or boot qualification."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class ProductionBootRuntimeBoundaries(unittest.TestCase):
    def test_live_verification_is_inert_and_installed_verification_stays_governed(self):
        source = (ROOT / 'rust/luma-platform/src/bundle.rs').read_text()
        verify = source.split('pub fn verify(source: &Path)', 1)[1].split(
            'fn inert_live_verification', 1)[0]
        self.assertIn('if crate::platform::live()? {', verify)
        self.assertIn('return verify_initial(source);', verify)
        self.assertIn('crate::release_trust::verify_installed_release(bytes, signature)', verify)
        initial = source.split('pub(crate) fn verify_initial', 1)[1].split(
            '/// UI/resource planning only.', 1)[0]
        self.assertIn('crate::platform::RecoveryImage::current()?', initial)
        self.assertIn('crate::release_trust::verify_inert_release', initial)
        self.assertEqual(initial.count('image.recheck()?;'), 2)
        self.assertLess(initial.index('RecoveryImage::current()?'), initial.index('verify_inert_release'))
        self.assertNotIn('verify_installed_release', initial)

    def test_production_live_proof_requires_firmware_and_readonly_verity(self):
        source = (ROOT / 'rust/luma-platform/src/platform.rs').read_text()
        proof = source.split('fn validate_recovery_image(', 1)[1].split(
            'fn check_recovery_image_claims(', 1)[0]
        self.assertIn('require_firmware_authentication()?;', proof)
        self.assertIn('CRYPT-VERITY-', proof)
        claims = source.split('fn check_recovery_image_claims(', 1)[1].split(
            'fn require_firmware_authentication()', 1)[0]
        self.assertIn('!has_option(&mount.options, "ro")', claims)
        self.assertIn('!has_option(&mount.super_options, "ro")', claims)

    def test_static_lab_signature_requires_immutable_lab_identity_before_key_lookup(self):
        bundle = (ROOT / 'rust/luma-platform/src/bundle.rs').read_text()
        verifier = bundle.split('fn verify_lab_signature(', 1)[1].split(
            'pub(crate) fn verify_initial', 1)[0]
        self.assertLess(verifier.index('require_laboratory_image()?'), verifier.index('Path::new(TRUST)'))
        source = (ROOT / 'rust/luma-platform/src/platform.rs').read_text()
        guard = source.split('pub(crate) fn require_laboratory_image()', 1)[1].split(
            'fn require_laboratory_environment', 1)[0]
        self.assertIn('/usr/share/luma-os/release-identity.json', guard)
        self.assertIn('validate_image_identity(&identity)?;', guard)
        self.assertIn('require_laboratory_environment(&identity.environment)', guard)
        closed = source.split('fn require_laboratory_environment', 1)[1].split(
            '/// Shared service/CLI activation fence', 1)[0]
        self.assertIn('if environment != "lab"', closed)

    def test_unenrolled_repair_cannot_cross_environment_or_recreate_authority(self):
        source = (ROOT / 'rust/luma-platform/src/platform.rs').read_text()
        validation = source.split('fn validate_laboratory_repair(', 1)[1].split(
            'pub(crate) fn require_installed()', 1)[0]
        for check in ('current.environment != "lab"', 'candidate.environment != "lab"',
                      'candidate.sequence < current.sequence', 'current.edition != candidate.edition',
                      'current.root_bytes != candidate.root_bytes', 'current.hash_bytes != candidate.hash_bytes'):
            self.assertIn(check, validation)
        repair = source.split('if matches!(action.as_str(), "repair-a" | "repair-b")', 1)[1].split(
            'if !matches!(action.as_str()', 1)[0]
        self.assertIn('return repair_governed', repair)
        self.assertIn('if retained || parent || nv', repair)
        self.assertLess(repair.index('validate_laboratory_repair'), repair.index('disk.confirm("REPAIR")'))

    def test_signed_boot_members_cannot_borrow_root_image_memory_bounds(self):
        source = (ROOT / 'rust/luma-platform/src/bundle.rs').read_text()
        validation = source.split('pub fn validate_manifest(', 1)[1].split('fn open_member(', 1)[0]
        for check in ('"slot-a.efi" | "slot-b.efi" => 256 * 1024 * 1024',
                      '"bootloader.efi" => 16 * 1024 * 1024',
                      '"secureboot.cer" => 16 * 1024', 'a.bytes > maximum'):
            self.assertIn(check, validation)


if __name__ == '__main__':
    unittest.main()
