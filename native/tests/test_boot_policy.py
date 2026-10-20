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
        self.assertEqual(policy.signing_arguments('optical', Path('/key'), Path('/public')), [])
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
        mode = 'live' if slot in ('live','optical') else 'installed'
        actual_slot='live' if slot=='optical' else slot
        optical=' luma.media=optical' if slot=='optical' else ''
        policy.command('/usr/lib/systemd/ukify', 'build', '--config', '/dev/null',
                       '--linux', self.linux, '--initrd', self.initrd, '--uname', 'fixture-1',
                       '--cmdline', f'luma.slot={actual_slot} luma.mode={mode}{optical}',
                       '--os-release', 'ID=luma-test\n', '--no-sign-kernel',
                       '--secureboot-private-key', self.sbkey,
                       '--secureboot-certificate', self.certificate,
                       *policy.signing_arguments(slot, self.key, self.public_path), '--output', target)
        return target

    def test_ab_and_live_artifacts_have_exact_policy(self):
        records = [policy.verify_uki(self.build(slot), slot, self.public, self.certificate)
                   for slot in ('a', 'b', 'live', 'optical')]
        self.assertEqual(records[0]['phases'], list(policy.PHASES))
        self.assertTrue(set(records[0]['policy_digests']).isdisjoint(records[1]['policy_digests']))
        self.assertFalse(records[2]['pcr_approval'])
        self.assertFalse(records[3]['pcr_approval'])
        with self.assertRaises(ValueError):
            policy.verify_uki(self.root/'optical.efi','live',self.public,self.certificate)
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
        for name in ('91luma','92luma-pcrphase'):
            source = IMAGE / 'overlay/usr/lib/dracut/modules.d' / name
            module = Path('/usr/lib/dracut/modules.d') / name
            # Exact new container-only copies. No host mount or existing
            # module is adopted; copytree refuses an occupied destination.
            shutil.copytree(source, module)
            self.addCleanup(shutil.rmtree, module)
        runtime = Path('/usr/libexec/luma-os')
        runtime.mkdir()  # Refuse an existing installation, even in a container.
        self.addCleanup(runtime.rmdir)
        fixture = runtime/'luma-platform'
        # A real inert ELF only satisfies dracut's installation dependency.
        # It is never executed, booted, or represented as product development.
        with fixture.open('xb') as stream:
            stream.write(Path('/usr/bin/true').read_bytes())
        fixture.chmod(0o755)
        self.addCleanup(fixture.unlink)
        rules = Path('/etc/udev/rules.d/99-luma-tpm.rules')
        rules.parent.mkdir(parents=True, exist_ok=True)
        with rules.open('xb') as stream:
            self.addCleanup(rules.unlink)
            stream.write((IMAGE/'overlay/etc/udev/rules.d/99-luma-tpm.rules').read_bytes())
        rules.chmod(0o644)
        with tempfile.TemporaryDirectory(prefix='luma-initrd-policy-',
                                         dir=Path(os.environ['LUMA_STORAGE_TEST_ROOT'])) as folder:
            output = Path(folder) / 'initrd'
            policy.command('dracut', '--force', '--no-kernel', '--no-hostonly',
                           '--no-hostonly-cmdline', '--no-compress',
                           '--modules', 'systemd systemd-initrd luma luma-pcrphase', output)
            result = policy.verify_initrd(output)
            self.assertEqual(result['phase_module'], 'luma-pcrphase')
            unit = policy.command('lsinitrd', '--file',
                                  'usr/lib/systemd/system/systemd-pcrphase-initrd.service', output)
            self.assertIn(b'systemd-pcrextend --graceful enter-initrd', unit)
            self.assertIn(b'systemd-pcrextend --graceful leave-initrd', unit)
            unpacked = Path(folder)/'unpacked'
            unpacked.mkdir()
            policy.command('lsinitrd','--unpack',output,cwd=unpacked)
            def repack(name):
                paths = [Path('.')]
                for directory, directories, files in os.walk(unpacked,followlinks=False):
                    for member in sorted([*directories,*files]):
                        paths.append((Path(directory)/member).relative_to(unpacked))
                entries = b''.join(os.fsencode(path)+b'\0' for path in paths)
                archive = Path(folder)/name
                with archive.open('xb') as stream:
                    subprocess.run(['cpio','--null','--create','--format=newc','--quiet'],
                        input=entries,stdout=stream,stderr=subprocess.PIPE,cwd=unpacked,
                        env=policy.ENV,timeout=120,check=True)
                return archive
            for index, relative in enumerate(('usr/lib/luma-optical.sh',
                    'usr/lib/systemd/system/luma-optical.service','etc/udev/rules.d/99-luma-optical.rules')):
                member = unpacked/relative
                self.assertTrue(member.is_file() and not member.is_symlink())
                original = member.read_bytes()
                member.write_bytes(original+b'\n# Disposable optical-initrd integrity test mutation\n')
                with self.subTest(tampered=relative), self.assertRaisesRegex(ValueError,'optical discovery differs'):
                    policy.verify_initrd(repack('tampered-'+str(index)))
                member.write_bytes(original)
            (unpacked/'usr/lib/systemd/system/luma-optical.service').unlink()
            with self.assertRaisesRegex(ValueError,'initrd lacks'):
                policy.verify_initrd(repack('missing-optical-service'))
            empty = Path(folder) / 'empty'
            empty.write_bytes(b'not an initrd')
            with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                policy.verify_initrd(empty)


if __name__ == '__main__':
    unittest.main()
