"""Fixed sealed-delivery wiring checks; not installed service qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class AdminCredentialPolicyTests(unittest.TestCase):
    def test_product_checkpoint_has_no_plaintext_credential_fallback(self):
        tpm = (ROOT / 'rust/luma-platform/src/tpm.rs').read_text().split('mod tests {')[0]
        self.assertIn('crate::admin_credentials::load()?', tpm)
        self.assertNotIn('/run/credentials/', tpm)
        self.assertNotIn('secret_array', tpm)
        loader = (ROOT / 'rust/luma-platform/src/admin_credentials.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('/usr/share/luma-os/admin-pcr-public.pem', loader)
        self.assertIn('/run/systemd/tpm2-pcr-signature.json', loader)
        self.assertIn('crate::platform::require_installed()?', loader)
        self.assertNotIn('std::env::', loader)

    def test_tmpfiles_creates_lock_directory_not_enrollment(self):
        lines = (ROOT / 'native/image/overlay/etc/tmpfiles.d/luma-admin.conf').read_text().splitlines()
        self.assertEqual([line for line in lines if line and not line.startswith('#')],
                         ['d /run/luma-admin 0700 root root -'])


if __name__ == '__main__':
    unittest.main()
