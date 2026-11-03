import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'image'))

import download_manifest as dm  # noqa: E402

RELEASE = 'luma-native-lab-20260927-desktop-20'
COMMIT = '6528ea1411b2dc0057bbc1ecdbaad538df21b4f3'
PSM1 = Path(__file__).resolve().parents[2] / 'packaging' / 'windows' / 'Luma.HyperV.psm1'
ZSTD = shutil.which('zstd')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def make_export(root, sequence=20, production=False):
    """A small export with the exact inventory export.py writes."""
    export = root / 'export'
    export.mkdir()
    release = RELEASE[:-2] + str(sequence)
    raw = b'GPT raw image bytes\n' * 4096
    if ZSTD:
        compressed = subprocess.run([ZSTD, '-q', '-c'], input=raw, stdout=subprocess.PIPE, check=True).stdout
    else:
        compressed = b'zstd stand-in\n' * 64
    files = {
        release + '.img.zst': compressed,
        release + '.iso': b'ISO9660 bytes\n' * 512,
        'optical-media.json': b'{"schema_version": 1}\n',
        'release.json': json.dumps(dict(release=release, sequence=sequence, edition='desktop',
                                        root_hash='a' * 64)).encode(),
        'release.sig': bytes(range(64)),
        'secureboot.cer': b'DER certificate\n',
        'packages.lock': b'packages\n',
        'source-lock.json': b'{"sources": []}\n',
        'toolchain-packages.lock': b'toolchain\n',
        'native-source.tar.zst': b'source archive\n',
        'boot-policy.json': b'{"policy": 1}\n',
    }
    if production:
        files['release-trust.json'] = b'{"trust": 1}\n'
    order = [release + '.img', release + '.img.zst', release + '.iso', 'optical-media.json', 'release.json',
             'release.sig', 'secureboot.cer', 'packages.lock', 'source-lock.json', 'toolchain-packages.lock',
             'native-source.tar.zst', 'boot-policy.json'] + (['release-trust.json'] if production else [])
    hashes = {name: sha(data) for name, data in files.items()}
    hashes[release + '.img'] = sha(raw)
    build = dict(status='built-not-yet-boot-tested', release=release, kernel='6.8.0-lab', edition='desktop',
                 root_hash='a' * 64, image=release + '.img', image_sha256=sha(raw),
                 source_lock_sha256=hashes['source-lock.json'], desktop=True, production_signed=production,
                 gate_closing=False,
                 optical=dict(iso_sha256=hashes[release + '.iso'], iso_bytes=len(files[release + '.iso']),
                              image=release + '.iso', boot_qualified=False, gate_closing=False))
    files['build.json'] = json.dumps(build, indent=2).encode()
    files['SHA256SUMS'] = ''.join(f'{hashes[name]}  {name}\n' for name in order).encode()
    for name, data in files.items():
        (export / name).write_bytes(data)
    return export, release, raw


def tree(path):
    return {entry.name: sha(entry.read_bytes()) for entry in sorted(Path(path).iterdir())}


class Base(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.export, self.release, self.raw = make_export(self.root)
        self.output = self.root / 'download'

    def build(self, **extra):
        options = dict(export=self.export, output=self.output, sequence=20, commit=COMMIT,
                       cut='candidate20-source-20261103-a')
        options.update(extra)
        return dm.build_set(**options)

    def refused(self, message, **extra):
        with self.assertRaisesRegex(dm.DownloadError, message):
            self.build(**extra)


class SumsFormatTests(unittest.TestCase):
    LINE = b'0' * 64 + b'  release.json\n'

    def test_accepts_the_shared_format_in_any_order(self):
        data = b'1' * 64 + b'  b.img\n' + b'2' * 64 + b'  a.iso\n'
        self.assertEqual(dm.parse_sums(data), {'b.img': '1' * 64, 'a.iso': '2' * 64})

    def test_refuses_lines_outside_the_shared_format(self):
        bad = [
            b'',
            self.LINE[:-1],
            self.LINE[:-1] + b'\r\n',
            b'A' * 64 + b'  release.json\n',
            b'0' * 64 + b' *release.json\n',
            b'0' * 64 + b' release.json\n',
            b'0' * 64 + b'  .hidden\n',
            b'0' * 64 + b'  dir/file\n',
            b'0' * 64 + b'  space name\n',
            b'0' * 63 + b'  release.json\n',
            b'0' * 64 + b'  ' + b'n' * 129 + b'\n',
            self.LINE + b'\n',
        ]
        for data in bad:
            with self.subTest(data=data[:80]), self.assertRaises(dm.DownloadError):
                dm.parse_sums(data)

    def test_refuses_names_that_differ_only_in_case(self):
        with self.assertRaisesRegex(dm.DownloadError, 'twice'):
            dm.parse_sums(b'1' * 64 + b'  Release.json\n' + b'2' * 64 + b'  release.json\n')

    def test_bounds_the_file_at_64_kib(self):
        lines = [f'{"0" * 64}  f{index:05d}\n'.encode() for index in range(900)]
        self.assertGreater(len(b''.join(lines)), 65536)
        with self.assertRaisesRegex(dm.DownloadError, '64 KiB'):
            dm.parse_sums(b''.join(lines))
        self.assertEqual(len(dm.parse_sums(b''.join(lines[:897]))), 897)

    def test_render_is_sorted_lf_and_round_trips(self):
        rows = {'b': '1' * 64, 'A': '2' * 64, 'a.x': '3' * 64}
        data = dm.render_sums(rows)
        self.assertEqual(data.split(b'\n')[0], b'2' * 64 + b'  A')
        self.assertNotIn(b'\r', data)
        self.assertEqual(dm.parse_sums(data), rows)

    def test_vm_workspace_reads_the_same_lines(self):
        source = (Path(dm.__file__).parent / 'vm_workspace.py').read_text(encoding='utf-8')
        self.assertIn(r"re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})', line)", source)
        self.assertEqual(dm.SUMS_LINE.pattern, r'([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})')

    @unittest.skipUnless(PSM1.is_file(), 'packaging/windows is not part of this source cut')
    def test_profile_v_module_uses_the_same_expression(self):
        text = PSM1.read_text(encoding='utf-8')
        found = re.findall(r"-cnotmatch '(\\A\(\?:\[0-9a-f\]\{64\}  [^']*)'", text)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0], dm.SUMS_FILE.pattern.decode('ascii').replace('\\Z', '\\z'))
        self.assertIn(f'-lt {dm.SUMS_MIN} -or $Bytes.Length -gt {dm.SUMS_MAX}', text)
        self.assertIn('[StringComparer]::OrdinalIgnoreCase', text)


class DownloadSetTests(Base):
    def test_describes_the_export_without_copying(self):
        before = tree(self.export)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            dm.main(['--export', str(self.export), '--output', str(self.output), '--sequence', '20',
                     '--source-commit', COMMIT, '--source-cut', 'candidate20-source-20261103-a',
                     '--build-log', str(self.export / 'packages.lock')])
        result = json.loads(stdout.getvalue())
        self.assertEqual(tree(self.export), before)
        self.assertEqual(sorted(path.name for path in self.output.iterdir()),
                         ['SHA256SUMS', 'VERIFY.txt', 'download-manifest.json'])
        sums = (self.output / 'SHA256SUMS').read_bytes()
        self.assertEqual(result['sha256sums_sha256'], sha(sums))
        rows = dm.parse_sums(sums)
        export_rows = dm.parse_sums((self.export / 'SHA256SUMS').read_bytes())
        for name, digest in export_rows.items():
            self.assertEqual(rows[name], digest)
        self.assertEqual(rows['build.json'], sha((self.export / 'build.json').read_bytes()))
        self.assertEqual(set(rows), set(export_rows) | {'build.json', 'VERIFY.txt', 'download-manifest.json'})
        self.assertEqual(list(rows), sorted(rows))
        for name in ('VERIFY.txt', 'download-manifest.json'):
            self.assertEqual(rows[name], sha((self.output / name).read_bytes()))
        text = (self.output / 'download-manifest.json').read_text(encoding='ascii')
        self.assertNotIn(result['sha256sums_sha256'], text)
        manifest = json.loads(text)
        self.assertEqual((manifest['purpose'], manifest['profile'], manifest['sequence'], manifest['release']),
                         ('luma-native-download-set-v1', 'N', 20, self.release))
        self.assertEqual(manifest['source'], dict(commit=COMMIT, cut='candidate20-source-20261103-a',
                                                  source_lock_sha256=rows['source-lock.json']))
        self.assertEqual(manifest['export']['sha256sums_sha256'], sha((self.export / 'SHA256SUMS').read_bytes()))
        for flag in ('signed', 'uploaded', 'published', 'origin_authenticated', 'boot_qualified', 'gate_closing',
                     'payload_in_package', 'production_signed'):
            self.assertIs(manifest[flag], False, flag)
        self.assertEqual(manifest['raw_image']['check'], 'export-sha256sums-and-build-record-agree')
        self.assertEqual(manifest['build_logs'][0]['sha256'], rows['packages.lock'])
        roles = {entry['name']: entry['role'] for entry in manifest['files']}
        self.assertEqual(roles[self.release + '.img.zst'], 'compressed-raw-disk-image')
        self.assertEqual(roles[self.release + '.iso'], 'vm-dvd-file-image')
        self.assertEqual(roles['secureboot.cer'], 'secure-boot-db-certificate')
        self.assertEqual(sorted(roles), sorted(set(rows) - {'download-manifest.json'}))
        self.assertTrue(manifest['owner_decisions'])

    def test_copy_makes_a_complete_verified_folder(self):
        result = self.build(copy=True)
        rows = dm.parse_sums((self.output / 'SHA256SUMS').read_bytes())
        present = {path.name for path in self.output.iterdir()}
        self.assertEqual(present, set(rows) - {self.release + '.img'} | {'SHA256SUMS'})
        for name in present - {'SHA256SUMS'}:
            self.assertEqual(sha((self.output / name).read_bytes()), rows[name], name)
        self.assertFalse(any(name.endswith('.partial') for name in present))
        self.assertTrue(result['payload_in_package'])

    def test_verify_text_carries_both_host_procedures_and_no_pin(self):
        result = self.build()
        text = (self.output / 'VERIFY.txt').read_text(encoding='ascii')
        self.assertIn('Get-FileHash -Algorithm SHA256', text)
        self.assertIn('sha256sum --check --ignore-missing SHA256SUMS', text)
        self.assertIn('not hybrid', text)
        self.assertIn(COMMIT, text)
        self.assertNotIn(result['sha256sums_sha256'], text)
        self.assertNotIn('\r', text)

    def test_production_export_includes_its_trust_record(self):
        shutil.rmtree(self.export)
        self.export, _, _ = make_export(self.root, production=True)
        self.build()
        manifest = json.loads((self.output / 'download-manifest.json').read_text(encoding='ascii'))
        self.assertIs(manifest['production_signed'], True)
        self.assertIn('release-trust.json', manifest['sha256sums']['listed'])

    def test_refuses_an_existing_output_folder(self):
        self.output.mkdir()
        self.refused('existing output')

    def test_refuses_a_missing_output_parent(self):
        self.output = self.root / 'absent' / 'download'
        self.refused('output parent')

    def test_refuses_extra_partial_or_missing_export_files(self):
        for name in ('stray.txt', self.release + '.img.zst.partial'):
            with self.subTest(name=name):
                (self.export / name).write_bytes(b'x')
                self.refused('inventory differs')
                (self.export / name).unlink()
        (self.export / 'boot-policy.json').unlink()
        self.refused('inventory differs')
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(os.name == 'posix', 'symbolic links need a POSIX host')
    def test_refuses_a_symbolic_link_in_the_export(self):
        target = self.root / 'elsewhere'
        target.write_bytes((self.export / 'release.sig').read_bytes())
        (self.export / 'release.sig').unlink()
        os.symlink(target, self.export / 'release.sig')
        self.refused('regular file')

    def test_refuses_a_tampered_file(self):
        path = self.export / 'secureboot.cer'
        path.write_bytes(path.read_bytes() + b'!')
        self.refused('differs from its SHA256SUMS row: secureboot.cer')
        self.assertFalse(self.output.exists())

    def test_refuses_a_build_record_that_disagrees(self):
        build = json.loads((self.export / 'build.json').read_text())
        build['image_sha256'] = 'f' * 64
        (self.export / 'build.json').write_text(json.dumps(build))
        self.refused('image hash differs')

    def test_refuses_a_duplicate_json_field(self):
        data = (self.export / 'build.json').read_bytes()
        (self.export / 'build.json').write_bytes(data[:-1] + b', "status": "x"}')
        self.refused('duplicate JSON field')

    def test_refuses_another_sequence(self):
        self.refused('sequence', sequence=19)

    def test_refuses_an_export_sums_file_listing_other_files(self):
        sums = (self.export / 'SHA256SUMS').read_bytes()
        (self.export / 'SHA256SUMS').write_bytes(sums + b'0' * 64 + b'  extra.bin\n')
        self.refused('different file set')

    def test_refuses_a_bad_commit_or_cut(self):
        for commit in ('6528ea1', COMMIT.upper(), COMMIT + '0', ''):
            with self.subTest(commit=commit):
                self.refused('40 lowercase hex', commit=commit)
        self.refused('plain name', cut='../cut')

    def test_include_raw_needs_copy(self):
        self.refused('needs --copy', include_raw=True)

    @unittest.skipUnless(ZSTD, 'zstd is not installed')
    def test_verify_decompressed_proves_the_raw_row(self):
        result = self.build(verify_decompressed=True)
        self.assertEqual(result['raw_image_check'], 'decompressed-and-hashed')
        manifest = json.loads((self.output / 'download-manifest.json').read_text(encoding='ascii'))
        self.assertEqual(manifest['raw_image']['bytes'], len(self.raw))
        self.assertFalse((self.output / (self.release + '.img')).exists())

    @unittest.skipUnless(ZSTD, 'zstd is not installed')
    def test_include_raw_ships_the_verified_raw_image(self):
        self.build(copy=True, include_raw=True)
        self.assertEqual((self.output / (self.release + '.img')).read_bytes(), self.raw)
        rows = dm.parse_sums((self.output / 'SHA256SUMS').read_bytes())
        self.assertEqual(rows[self.release + '.img'], sha(self.raw))

    @unittest.skipUnless(ZSTD, 'zstd is not installed')
    def test_refuses_a_compressed_image_that_decompresses_to_other_bytes(self):
        name = self.release + '.img.zst'
        other = subprocess.run([ZSTD, '-q', '-c'], input=b'other', stdout=subprocess.PIPE, check=True).stdout
        (self.export / name).write_bytes(other)
        sums = (self.export / 'SHA256SUMS').read_text()
        old = dm.parse_sums(sums.encode())[name]
        (self.export / 'SHA256SUMS').write_text(sums.replace(old, sha(other)))
        self.refused('decompressed image differs', verify_decompressed=True)


class HyperVTests(Base):
    def setUp(self):
        super().setUp()
        self.public = self.root / 'public'
        self.public.mkdir()
        self.vhdx = self.public / (self.release + '.vhdx')
        self.vhdx.write_bytes(b'vhdxfile' * 4096)
        raw_sha256 = sha(self.raw)
        conversion = dict(schema_version=1, purpose='luma-hyperv-live-installer-v1', profile='V',
                          source_raw_sha256=raw_sha256, output_name='luma-hyperv-live-installer.vhdx',
                          output_bytes=self.vhdx.stat().st_size, output_sha256=sha(self.vhdx.read_bytes()))
        conversion_path = self.public / (self.vhdx.name + '.conversion.json')
        conversion_path.write_text(json.dumps(conversion))
        self.receipt = dict(schema_version=1, purpose='luma-hyperv-public-export-v1', output_name=self.vhdx.name,
                            output_bytes=self.vhdx.stat().st_size, output_sha256=sha(self.vhdx.read_bytes()),
                            conversion_name=conversion_path.name,
                            conversion_sha256=sha(conversion_path.read_bytes()), source_raw_sha256=raw_sha256,
                            source_conversion_preserved=True, boot_qualified=False, gate_closing=False)
        self.write_receipt()

    def write_receipt(self):
        (self.public / (self.vhdx.name + '.export.json')).write_text(json.dumps(self.receipt))

    def test_adds_the_vhdx_and_its_records_to_one_sums_file(self):
        self.build(vhdx=self.vhdx, copy=True)
        rows = dm.parse_sums((self.output / 'SHA256SUMS').read_bytes())
        for suffix in ('', '.conversion.json', '.export.json'):
            name = self.vhdx.name + suffix
            self.assertEqual(rows[name], sha((self.public / name).read_bytes()))
            self.assertEqual(rows[name], sha((self.output / name).read_bytes()))
        text = (self.output / 'VERIFY.txt').read_text(encoding='ascii')
        self.assertIn(f'-ImagePath .\\{self.vhdx.name}', text)
        self.assertIn('-Sha256SumsSha256 $pin', text)
        roles = {entry['name']: entry['role'] for entry in
                 json.loads((self.output / 'download-manifest.json').read_text())['files']}
        self.assertEqual(roles[self.vhdx.name], 'hyperv-generation2-disk')

    def test_refuses_a_failed_hyperv_export(self):
        (self.public / (self.vhdx.name + '.failure.json')).write_text('{}')
        self.refused('failure record', vhdx=self.vhdx)

    def test_refuses_a_receipt_for_another_raw_image(self):
        self.receipt['source_raw_sha256'] = 'e' * 64
        self.write_receipt()
        self.refused('receipt differs', vhdx=self.vhdx)

    def test_refuses_a_changed_vhdx(self):
        self.vhdx.write_bytes(b'changed')
        self.refused('receipt differs', vhdx=self.vhdx)

    def test_refuses_a_vhdx_name_outside_the_export_names(self):
        self.refused('VHDX name', vhdx=self.public / 'bad name.vhdx')


if __name__ == '__main__':
    unittest.main()
