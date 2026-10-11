#!/usr/bin/env python3
"""Mandatory executable crypto regressions; real pinned source archive required.

Run in an isolated build container with --network none, no SYS_TIME capability
and a bounded writable D-backed work directory. No daemon is ever executed.
Missing inputs/tools are failures, never skips or signature-verification mocks.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

import prepare_release_input
import prepare_chrony
import verify_release


class ReleaseAuthentication(unittest.TestCase):
    archive = None
    work = None

    def context(self):
        return tempfile.TemporaryDirectory(prefix='chrony-auth-test-', dir=self.work)

    def test_real_fixed_upstream_signature_and_independent_key_pin(self):
        result = verify_release.verify(self.archive,
                                       verify_release.ASSETS / 'chrony-4.9.tar.gz.asc', self.work)
        self.assertTrue(result['signature_verified'])
        self.assertEqual(result['signature']['signer_fingerprint'], verify_release.FINGERPRINT)
        self.assertEqual(result['signature']['primary_fingerprint'], verify_release.FINGERPRINT)
        self.assertEqual(result['signature']['hash_algorithm'], 'SHA512')
        print('UTC_AUTHENTICATED_RELEASE=' + json.dumps(result, sort_keys=True))
        key = verify_release.bounded(verify_release.ASSETS / 'upstream-signing-key.asc', 32768)
        self.assertEqual(hashlib.sha512(key).hexdigest(),
                         '8cedd37e6a42b21e71fa5c8779300e65fdc078d41fb750abd07bd8f6f1cd41bc54814c021f6fd3d25e67190e84aa45d37735ea03325dbc5e77582506fa4b8b9b')

    def test_actual_bad_signature_refuses_even_if_archive_digest_claim_is_changed(self):
        with self.context() as directory:
            altered = Path(directory) / 'archive'
            bytes_ = bytearray(verify_release.bounded(self.archive, verify_release.ARCHIVE_LIMIT))
            bytes_[len(bytes_) // 2] ^= 1
            altered.write_bytes(bytes_)
            with patch.object(verify_release, 'ARCHIVE_SHA256', hashlib.sha256(bytes_).hexdigest()):
                with self.assertRaisesRegex(ValueError, 'verification failed'):
                    verify_release.verify(altered, verify_release.ASSETS / 'chrony-4.9.tar.gz.asc', self.work)

    def test_prepare_and_reverify_never_trust_provenance_claims_or_overwrite_inputs(self):
        with self.context() as directory:
            root = Path(directory)
            prepare_release_input.prepare(root, self.archive)
            archive = root / verify_release.ARCHIVE_NAME
            genuine = verify_release.verified_provenance(archive)
            self.assertTrue(genuine['signature_verified'])
            provenance = root / 'chrony-4.9.provenance.json'
            for false in [{'signature_verified': True}, {**genuine, 'signature_verified': False},
                          {**genuine, 'extra': 'caller-selected-trust'},
                          {**genuine, 'signature_verified': 1}]:
                provenance.write_text(json.dumps(false))
                with self.assertRaises(ValueError):
                    verify_release.verified_provenance(archive)
            provenance.write_text('{"signature_verified":true,"signature_verified":false}')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                verify_release.verified_provenance(archive)
            with self.assertRaisesRegex(ValueError, 'must be new'):
                prepare_release_input.prepare(root, self.archive)

    def test_actual_signed_source_retains_packet_authentication_and_tls_refusal_guards(self):
        verify_release.verify(self.archive, verify_release.ASSETS / 'chrony-4.9.tar.gz.asc', self.work)
        with self.context() as directory:
            root = Path(directory)
            with tarfile.open(self.archive, 'r:gz') as archive:
                members = archive.getmembers()
                self.assertLessEqual(len(members), 4096)
                self.assertLessEqual(sum(member.size for member in members), 32 * 1024 * 1024)
                for member in members:
                    path = Path(member.name)
                    self.assertFalse(path.is_absolute())
                    self.assertNotIn('..', path.parts)
                    self.assertIn(path.parts[0], ('chrony-4.9',))
                    self.assertTrue(member.isfile() or member.isdir())
                archive.extractall(root, members=members, filter='data')
            patched = root / 'patched'
            prepare_chrony.prepare(root / 'chrony-4.9', patched, release=True)
            print('UTC_PATCHED_SOURCE_INPUTS=' + (patched / 'luma-hook-inputs.json').read_text())
            core = (patched / 'ntp_core.c').read_text()
            self.assertEqual(core.count('LUH_Good('), 1)
            self.assertLess(core.index('test5 = saved || NAU_CheckResponseAuth'), core.index('LUH_Good('))
            self.assertIn('valid_packet = test1 && test2 && test3 && test5;', core)
            self.assertIn('synced_packet = valid_packet && test6 && test7;', core)
            self.assertIn('if (good_packet) {\n      LUH_Good(', core)
            self.assertLess(core.index('LUH_Good('), core.index('process_sample(inst, &sample)'))
            for guard in ('params->nts &&', 'params->offset == 0.0', 'params->cert_set == 0',
                          '!params->copy', 'CNF_GetNoCertTimeCheck() == 0'):
                self.assertIn(guard, core)
            auth = (patched / 'ntp_auth.c').read_text()
            self.assertIn('info->auth.mode != instance->mode', auth)
            self.assertIn('NNC_CheckResponseAuth(instance->nts, response, info)', auth)

    def test_symlink_archive_and_output_refuse_before_reading_or_writing(self):
        with self.context() as directory:
            root = Path(directory)
            link = root / 'archive-link'
            link.symlink_to(self.archive)
            with self.assertRaisesRegex(ValueError, 'regular'):
                verify_release.bounded(link, verify_release.ARCHIVE_LIMIT)
            linked_output = root / 'output-link'
            real_output = root / 'actual-output'
            real_output.mkdir()
            linked_output.symlink_to(real_output, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'protected build directory'):
                prepare_release_input.prepare(linked_output, self.archive)
            self.assertEqual(list(real_output.iterdir()), [])

    def test_signature_substitution_missing_and_oversized_inputs_refuse(self):
        with self.context() as directory:
            signature = Path(directory) / 'signature'
            signature.write_bytes(b'caller signature')
            with self.assertRaisesRegex(ValueError, 'fixed pin'):
                verify_release.verify(self.archive, signature, self.work)
            signature.write_bytes(b'x' * (verify_release.SIGNATURE_LIMIT + 1))
            with self.assertRaisesRegex(ValueError, 'bounded'):
                verify_release.verify(self.archive, signature, self.work)
            signature.unlink()
            with self.assertRaises(FileNotFoundError):
                verify_release.verify(self.archive, signature, self.work)

    def test_authenticated_snapshot_preserves_verified_bytes_after_caller_path_replacement(self):
        with self.context() as directory:
            root = Path(directory)
            caller = root / verify_release.ARCHIVE_NAME
            genuine = verify_release.bounded(self.archive, verify_release.ARCHIVE_LIMIT)
            caller.write_bytes(genuine)
            authenticate = verify_release._authenticate
            def replace_after_authentication(*args, **kwargs):
                captured = authenticate(*args, **kwargs)
                caller.write_bytes(b'caller replacement after successful crypto')
                return captured
            with patch.object(verify_release, '_authenticate', side_effect=replace_after_authentication):
                captured = verify_release.snapshot(caller, root / 'private-snapshot',
                                                   verify_release.ASSETS / 'chrony-4.9.tar.gz.asc', work=root)
            self.assertEqual((captured / verify_release.ARCHIVE_NAME).read_bytes(), genuine)
            self.assertNotEqual(caller.read_bytes(), genuine)
            self.assertEqual(captured.stat().st_mode & 0o777, 0o700)
            for path in captured.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o400)
            self.assertTrue(verify_release.verified_provenance(captured / verify_release.ARCHIVE_NAME,
                                                              work=root)['signature_verified'])
            with self.assertRaisesRegex(ValueError, 'must be new'):
                verify_release.snapshot(self.archive, captured,
                                        verify_release.ASSETS / 'chrony-4.9.tar.gz.asc', work=root)

    def test_wrong_signer_subkey_digest_class_duplicate_and_error_status_refuse(self):
        fingerprint = verify_release.FINGERPRINT
        valid = (f'[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG {fingerprint[-16:]} Upstream\n'
                 f'[GNUPG:] VALIDSIG {fingerprint} 2026-08-27 1787835355 0 4 0 1 10 00 {fingerprint}\n')
        self.assertEqual(verify_release.parse_status(valid.encode(), 0), 1787835355)
        faults = [valid.replace(fingerprint, 'AB' * 20), valid.replace(' 1 10 00 ', ' 1 2 00 '),
                  valid.replace(' 1 10 00 ', ' 1 10 01 '), valid + valid,
                  valid + '[GNUPG:] EXPKEYSIG 123\n', valid + '[GNUPG:] BADSIG 123\n',
                  valid.replace('VALIDSIG ' + fingerprint, 'VALIDSIG ' + 'CD' * 20),
                  valid.replace('2026-08-27', '2027-08-27')]
        for fault in faults:
            with self.assertRaises(ValueError):
                verify_release.parse_status(fault.encode(), 0)
        with self.assertRaises(ValueError):
            verify_release.parse_status(valid.encode(), 1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    ReleaseAuthentication.archive = args.archive.resolve(strict=True)
    ReleaseAuthentication.work = args.work.resolve(strict=True)
    unittest.main(argv=[__file__], verbosity=2)
