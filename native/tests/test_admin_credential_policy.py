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
        self.assertIn('owner_credential::unseal', loader)
        self.assertNotIn('sealed_credential::unseal', loader)
        self.assertNotIn('std::env::', loader)

    def test_tmpfiles_creates_lock_directory_not_enrollment(self):
        lines = (ROOT / 'native/image/overlay/etc/tmpfiles.d/luma-admin.conf').read_text().splitlines()
        self.assertEqual([line for line in lines if line and not line.startswith('#')],
                         ['d /run/luma-admin 0700 root root -'])

    def test_bootstrap_has_fixed_paths_and_independent_pam_entry_point(self):
        source = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('const DIRECTORY: &str = "/var/lib/luma-os/admin"', source)
        entry = source.split('pub fn bootstrap(')[1]
        for required in ('crate::require_root()?', 'platform::require_installed()?',
                         'authentication::local(login)?', 'tpm::LocalAnchor::installed()?',
                         'authenticated.identity()'):
            self.assertIn(required, entry)
        self.assertNotIn('std::env::', source)
        self.assertNotIn('existing_owner()', source)
        self.assertNotIn('provision(', source)

    def test_bootstrap_is_not_automatic_installer_or_broker_authority(self):
        main = (ROOT / 'rust/luma-platform/src/main.rs').read_text()
        self.assertIn('Some("admin-bootstrap") if args.len() == 2', main)
        self.assertIn('args.len() == 4 && args[2] == "--activate"', main)
        for name in ('platform.rs', 'service.rs'):
            source = (ROOT / 'rust/luma-platform/src' / name).read_text()
            self.assertNotIn('admin_governance::bootstrap', source)

    def test_catalog_operations_have_independent_pam_and_no_assignment_interface(self):
        source = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text().split('#[cfg(test)]')[0]
        for name in ('catalog_command', 'catalog_status'):
            entry = source.split(f'pub fn {name}(')[1].split('\n}\n', 1)[0]
            for required in ('crate::require_root()?', 'platform::require_installed()?',
                             'authentication::local(login)?', 'tpm::LocalAnchor::installed()?',
                             'authenticated.identity()'):
                self.assertIn(required, entry)
        roles = (ROOT / 'rust/luma-platform/src/admin_roles.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('RegisterActivity', roles)
        self.assertIn('DefineRole', roles)
        self.assertNotIn('AssignRole', roles)


if __name__ == '__main__':
    unittest.main()
