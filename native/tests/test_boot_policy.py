"""Builder policy tests; fixture PE artifacts are NOT bootable OS images."""
import importlib.util
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest

IMAGE = Path(__file__).resolve().parents[1] / 'image'
spec = importlib.util.spec_from_file_location('boot_policy', IMAGE / 'boot_policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
LINUX_TOOLS = (os.name == 'posix' and Path('/.dockerenv').is_file()
               and Path('/usr/lib/systemd/ukify').exists())


class BootPolicyContractTests(unittest.TestCase):
    def test_live_is_not_an_installed_admin_policy(self):
        self.assertEqual(policy.signing_arguments('live', Path('/key'), Path('/public')), [])
        for slot in ('a', 'b'):
            args = policy.signing_arguments(slot, Path('/key'), Path('/public'))
            self.assertIn('sha256', args)
            self.assertIn(','.join(policy.PHASES), args)
            self.assertNotIn('enter-initrd', args)
        with self.assertRaises(ValueError):
            policy.signing_arguments('unknown', Path('/key'), Path('/public'))

    def test_digest_encoding_and_json_are_closed(self):
        # Observed TPM PolicyPCR digest from the prior swtpm fixture after
        # extending SHA256 PCR11 with 32 bytes of 0x55.
        self.assertEqual(policy.policy_digest('3b7c264a0d84cc84f354cfcec0d2da9a88ee0c267f7328849a602a6224f96049'),
                         'e6ec63e9bec53dde4e87477bd5e7a70f996c71129cea3eaa968a42e2aca3d055')
        for value in ('', 'AB'*32, 'aa'*31, 'gg'*32):
            with self.assertRaises(ValueError):
                policy.policy_digest(value)
        with self.assertRaises(ValueError):
            policy.closed_json('{"sha256":[],"sha256":[]}')


@unittest.skipUnless(LINUX_TOOLS, 'requires isolated Linux UKI tools container')
class BootPolicyArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='luma-boot-policy-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.keys = self.root / 'keys'
        self.keys.mkdir(mode=0o700)
        self.key, self.public = policy.prepare_lab_key(self.keys)
        self.public_path = self.root / 'public.pem'
        self.public_path.write_bytes(self.public)
        self.certificate = self.root / 'secureboot.pem'
        self.sbkey = self.root / 'secureboot.key'
        policy.command('openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes',
                       '-sha256', '-days', '1', '-subj', '/CN=Disposable PCR Test/',
                       '-keyout', self.sbkey, '-out', self.certificate)
        # Valid PE stub used as a synthetic .linux payload; cannot boot Linux.
        self.linux = Path('/usr/lib/systemd/boot/efi/linuxx64.efi.stub')
        self.initrd = self.root / 'initrd'
        self.initrd.write_bytes(b'not-a-bootable-initrd\n')

    def build(self, slot):
        target = self.root / (slot + '.efi')
        mode = 'live' if slot == 'live' else 'installed'
        policy.command('/usr/lib/systemd/ukify', 'build', '--config', '/dev/null',
                       '--linux', self.linux, '--initrd', self.initrd, '--uname', 'fixture-1',
                       '--cmdline', f'luma.slot={slot} luma.mode={mode}',
                       '--os-release', 'ID=luma-test\n', '--no-sign-kernel',
                       '--secureboot-private-key', self.sbkey,
                       '--secureboot-certificate', self.certificate,
                       *policy.signing_arguments(slot, self.key, self.public_path), '--output', target)
        return target

    def test_ab_and_live_artifacts_have_exact_policy(self):
        records = [policy.verify_uki(self.build(slot), slot, self.public, self.certificate)
                   for slot in ('a', 'b', 'live')]
        self.assertEqual(records[0]['phases'], list(policy.PHASES))
        self.assertTrue(set(records[0]['policy_digests']).isdisjoint(records[1]['policy_digests']))
        self.assertFalse(records[2]['pcr_approval'])
        with self.assertRaises(ValueError):
            policy.verify_uki(self.root / 'a.efi', 'b', self.public, self.certificate)
        with self.assertRaises(ValueError):
            policy.verify_uki(self.root / 'a.efi', 'a', b'substituted key', self.certificate)

    def test_tamper_even_after_pe_resigning_is_refused(self):
        import pefile
        image = self.build('a')
        policy.verify_uki(image, 'a', self.public, self.certificate)
        content = bytearray(image.read_bytes())
        with pefile.PE(str(image), fast_load=True) as pe:
            section = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.initrd')
            content[section.PointerToRawData] ^= 1
        tampered = self.root / 'tampered.efi'
        tampered.write_bytes(content)
        with self.assertRaises(subprocess.CalledProcessError):
            policy.verify_uki(tampered, 'a', self.public, self.certificate)
        policy.command('sbattach', '--remove', tampered)
        resigned = self.root / 'resigned.efi'
        policy.command('sbsign', '--key', self.sbkey, '--cert', self.certificate,
                       '--output', resigned, tampered)
        # Secure Boot signature alone now passes; embedded PCR approvals must not.
        policy.command('sbverify', '--cert', self.certificate, resigned)
        with self.assertRaisesRegex(ValueError, 'measured UKI'):
            policy.verify_uki(resigned, 'a', self.public, self.certificate)

    def test_key_is_stable_and_unsafe_custody_is_refused(self):
        key, public = policy.prepare_lab_key(self.keys)
        self.assertEqual(key, self.key)
        self.assertEqual(public, self.public)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        key.chmod(0o644)
        with self.assertRaises(ValueError):
            policy.prepare_lab_key(self.keys)
        key.chmod(0o600)
        self.keys.chmod(0o755)
        with self.assertRaises(ValueError):
            policy.prepare_lab_key(self.keys)
        self.keys.chmod(0o700)
        other = self.root / 'other'
        other.mkdir(mode=0o700)
        (other / 'pcr-policy.key').symlink_to(key)
        with self.assertRaises(ValueError):
            policy.prepare_lab_key(other)
        self.assertEqual(policy.prepare_lab_key(self.keys)[1], self.public)


@unittest.skipUnless(LINUX_TOOLS, 'requires isolated Linux UKI tools container')
class BootPhaseInitrdTests(unittest.TestCase):
    def test_generated_initrd_contains_real_phase_service(self):
        source = IMAGE / 'overlay/usr/lib/dracut/modules.d/92luma-pcrphase'
        module = Path('/usr/lib/dracut/modules.d/92luma-pcrphase')
        # A new, exact container-only module directory, never a host mount.
        # copytree refuses an existing target; cleanup removes only this copy.
        shutil.copytree(source, module)
        self.addCleanup(shutil.rmtree, module)
        with tempfile.TemporaryDirectory(prefix='luma-initrd-policy-') as folder:
            output = Path(folder) / 'initrd'
            policy.command('dracut', '--force', '--no-kernel', '--no-hostonly',
                           '--no-hostonly-cmdline', '--no-compress',
                           '--modules', 'systemd systemd-initrd luma-pcrphase', output)
            result = policy.verify_initrd(output)
            self.assertEqual(result['phase_module'], 'luma-pcrphase')
            unit = policy.command('lsinitrd', '--file',
                                  'usr/lib/systemd/system/systemd-pcrphase-initrd.service', output)
            self.assertIn(b'systemd-pcrextend --graceful enter-initrd', unit)
            self.assertIn(b'systemd-pcrextend --graceful leave-initrd', unit)
            empty = Path(folder) / 'empty'
            empty.write_bytes(b'not an initrd')
            with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                policy.verify_initrd(empty)


if __name__ == '__main__':
    unittest.main()
