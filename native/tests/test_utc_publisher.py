"""Pinned hook/asset regressions, not live NTS or installed-clock qualification."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / 'native/image/utc'
spec = importlib.util.spec_from_file_location('prepare_chrony', ASSETS / 'prepare_chrony.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PublisherAssets(unittest.TestCase):
    def test_exact_patch_anchor_required(self):
        self.assertEqual(prepare.once('abc', 'b', 'd'), 'adc')
        for text in ('ac', 'abbc'):
            with self.assertRaises(ValueError):
                prepare.once(text, 'b', 'd')

    def test_destination_refuses_existing_and_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            source.mkdir()
            with self.assertRaisesRegex(ValueError, 'must be new'):
                prepare.prepare(source, source)
            with self.assertRaisesRegex(ValueError, 'overlap'):
                prepare.prepare(source, source / 'nested')

    def test_gpl_linked_sources_and_non_authorizing_flags(self):
        for name in ('publisher.c', 'publisher.h', 'chrony_hook.c', 'chrony_hook.h', 'test_publisher.c'):
            self.assertIn('SPDX-License-Identifier: GPL-2.0-only', (ASSETS / name).read_text())
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        self.assertRegex(governance, r'"trusted_utc_available"\s*:\s*false')
        self.assertRegex(governance, r'"gate_closing"\s*:\s*false')

    def test_no_image_activation_or_report_scraper(self):
        root = (ROOT / 'native/image/Dockerfile.root').read_text()
        self.assertIn('systemd-timesyncd', root)
        self.assertNotIn('chrony_hook', root)
        hook = (ASSETS / 'chrony_hook.c').read_text()
        self.assertIn('/run/luma-utc/measurements.sock', hook)
        self.assertNotIn('popen(', hook)
        self.assertNotIn('system(', hook)
        self.assertIn('MSG_DONTWAIT', hook)

    def test_unknown_source_duplicate_alias_and_relaxed_tls_disable(self):
        hook = (ASSETS / 'chrony_hook.c').read_text()
        self.assertIn('i == 3 || !strict_nts || owners[i]', hook)
        self.assertIn('fence(); publisher.disabled = 1;', hook)
        script = (ASSETS / 'prepare_chrony.py').read_text()
        self.assertIn('params->offset == 0.0', script)
        self.assertIn('params->cert_set == 0', script)
        self.assertIn('CNF_GetNoCertTimeCheck() == 0', script)

    @unittest.skipUnless(os.environ.get('LUMA_CHRONY_UPSTREAM'), 'needs isolated pinned source fixture')
    def test_pinned_hook_follows_actual_authentication_guard(self):
        source = Path(os.environ['LUMA_CHRONY_UPSTREAM'])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'patched'
            prepare.prepare(source, output)
            core = (output / 'ntp_core.c').read_text()
            self.assertEqual(core.count('LUH_Good('), 1)
            self.assertIn('if (valid_packet) {\n    LUH_Leap(inst->luma_operator, pkt_leap == LEAP_Normal);', core)
            self.assertIn('if (good_packet) {\n      LUH_Good(inst->luma_operator, &sample, pkt_leap == LEAP_Normal);', core)
            self.assertLess(core.index('test5 = saved || NAU_CheckResponseAuth'), core.index('LUH_Good('))
            self.assertIn('valid_packet = test1 && test2 && test3 && test5;', core)
            self.assertIn('synced_packet = valid_packet && test6 && test7;', core)
            self.assertLess(core.index('LUH_Good('), core.index('process_sample(inst, &sample)'))
            auth = (output / 'ntp_auth.c').read_text()
            self.assertIn('info->auth.mode != instance->mode', auth)
            self.assertIn('NNC_CheckResponseAuth(instance->nts, response, info)', auth)

    @unittest.skipUnless(os.environ.get('LUMA_CHRONY_UPSTREAM'), 'needs isolated pinned source fixture')
    def test_modified_upstream_pin_refuses_preparation(self):
        source = Path(os.environ['LUMA_CHRONY_UPSTREAM'])
        with tempfile.TemporaryDirectory() as directory:
            altered = Path(directory) / 'altered'
            altered.mkdir()
            (altered / 'ntp_core.c').write_bytes((source / 'ntp_core.c').read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'pin mismatch'):
                prepare.prepare(altered, Path(directory) / 'patched')
            self.assertFalse((Path(directory) / 'patched').exists())
