"""Small packaging checks; no systemd service is started or stopped."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BrokerEffectPackagingTests(unittest.TestCase):
    def test_broker_has_private_persistent_state_without_swap(self):
        unit = (ROOT / 'native/image/overlay/etc/systemd/system/luma-broker.service').read_text()
        for line in ('StateDirectory=luma-broker', 'StateDirectoryMode=0700',
                     'MemorySwapMax=0', 'ProtectSystem=strict', 'UMask=0077'):
            self.assertIn(line, unit.splitlines())

    def test_fresh_installer_initializes_receipts_and_runtime_does_not(self):
        installer = (ROOT / 'rust/luma-platform/src/platform.rs').read_text()
        initialization = 'crate::broker_effects::initialize(&data.at.join("lib/luma-broker"))?;'
        self.assertIn(initialization, installer)
        self.assertLess(installer.index(initialization), installer.index('INSTALLATION COMPLETE:'))
        broker = (ROOT / 'rust/luma-platform/src/service.rs').read_text()
        self.assertNotIn('broker_effects::initialize', broker)
        self.assertIn('broker_effects::Store::open', broker)


if __name__ == '__main__':
    unittest.main()
