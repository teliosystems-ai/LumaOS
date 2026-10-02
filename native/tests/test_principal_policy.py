"""Installer/authentication wiring checks, not booted-image acceptance."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PrincipalPackagingTests(unittest.TestCase):
    def test_fresh_install_creates_principals_after_account_initialization(self):
        source = (ROOT / 'rust/luma-platform/src/platform.rs').read_text()
        create = source.index('create_identity(&data.at,')
        principals = source.index('crate::principal::initialize(')
        self.assertLess(create, principals)
        self.assertLess(principals, source.index('INSTALLATION COMPLETE:'))
        self.assertIn('&[(&user, 1000), (&admin, 1001)]', source)

    def test_product_authentication_uses_fixed_registry_and_never_initializes_it(self):
        source = (ROOT / 'rust/luma-platform/src/authentication.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('Path::new(principal::REGISTRY)', source)
        self.assertIn('Path::new(principal::IDENTITY)', source)
        self.assertNotIn('principal::initialize', source)
        self.assertIn('binding.current_uid()? != uid', source)
        self.assertIn('"product_admin_active":false', source)


if __name__ == '__main__':
    unittest.main()
