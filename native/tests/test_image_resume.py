"""Small packaging regressions, not native boot or production qualification.

Tool-output fixtures are explicitly synthetic. They exercise the actual closed
parsers and range checks without constructing a multigigabyte operating system.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import unittest
from unittest import mock
import uuid
import zlib

SPEC = importlib.util.spec_from_file_location(
    'luma_image_resume', Path(__file__).resolve().parents[1]/'image/resume.py')
resume = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resume)


def manifest():
    sizes = [6144 * resume.MIB, 1024, 4096, 4096, 4096, 512]
    return {'schema_version': 1, 'release': 'luma-native-lab-20260927-desktop-13',
            'sequence': 13, 'environment': 'lab', 'architecture': 'amd64',
            'ubuntu': '24.04', 'edition': 'desktop', 'root_hash': 'a' * 64,
            'root_bytes': sizes[0], 'hash_bytes': sizes[1],
            'artifacts': [{'name': name, 'bytes': size, 'sha256': 'b' * 64}
                          for name, size in zip(resume.SIGNED, sizes)]}


def source_entries(count=314):
    return [{'path': f'src/file-{index:03}.txt', 'bytes': 4,
             'sha256': resume.sha(b'data')} for index in range(count)]


def archive_bytes(entries, extra=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, descriptor in entries.items():
            member = tarfile.TarInfo('./' + name)
            member.size = descriptor['bytes']
            archive.addfile(member, io.BytesIO(b'data'))
        if extra is not None:
            archive.addfile(extra)
    return stream.getvalue()


class ResumeTests(unittest.TestCase):
    def test_independent_source_approval_requires_explicit_mode_and_all_four_pins(self):
        expected={'source-lock':'a'*64,'release-public':'b'*64,'secureboot-cert':'c'*64,'pcr-public':'d'*64}
        resume.validate_source_approval('independent-build',expected)
        with self.assertRaisesRegex(ValueError,'legacy repair'):
            resume.validate_source_approval('legacy-repair',expected)
        legacy={**expected,'source-lock':resume.SOURCE_SHA}
        resume.validate_source_approval('legacy-repair',legacy)
        for mode in ('independent','production','',None,True):
            with self.subTest(mode=mode),self.assertRaises(ValueError):resume.validate_source_approval(mode,expected)
        for name in expected:
            for bad in ('0'*64,'A'*64,'x','',None,True):
                with self.subTest(name=name,bad=bad),self.assertRaises(ValueError):
                    resume.validate_source_approval('independent-build',{**expected,name:bad})
            missing=expected.copy();del missing[name]
            with self.assertRaises(ValueError):resume.validate_source_approval('independent-build',missing)
        with self.assertRaises(ValueError):resume.validate_source_approval('independent-build',{**expected,'extra':'e'*64})

    def test_independent_source_approval_does_not_bypass_embedded_lock_join(self):
        raw=b'{"schema_version":1,"fixture":"not-a-complete-build"}\n'
        pin=resume.sha(raw)
        resume.check_embedded_source_lock(raw,raw,pin)
        for embedded,retained,expected in ((raw+b'x',raw,pin),(raw,raw+b'x',pin),(raw,raw,'f'*64),
                                         (raw,raw,'0'*64),(b'',b'',resume.sha(b'')),('text',raw,pin)):
            with self.subTest(embedded=embedded),self.assertRaises(ValueError):
                resume.check_embedded_source_lock(embedded,retained,expected)
        source=(Path(__file__).resolve().parents[1]/'image/resume.py').read_text()
        self.assertIn("choices=('legacy-repair','independent-build'),default='legacy-repair'",source)
        for required in ('verify_compressed_source(', 'check_source_tree(', 'veritysetup', 'sbverify',
                         'root image kernel/initrd differs', 'check_embedded_source_lock(extracted.read_bytes()'):
            self.assertIn(required,source)

    def test_independent_inventory_is_bounded_and_does_not_relax_legacy314(self):
        for count in (1,444,4096):
            value={'schema_version':1,'files':sorted(source_entries(count),key=lambda entry:entry['path'])}
            raw=json.dumps(value).encode();pin=resume.sha(raw)
            self.assertEqual(len(resume.parse_source_lock(raw,pin,'independent-build')),count)
            with self.assertRaises(ValueError):resume.parse_source_lock(raw,pin)
        for count in (0,4097):
            raw=json.dumps({'schema_version':1,'files':source_entries(count)}).encode()
            with self.assertRaises(ValueError):resume.parse_source_lock(raw,resume.sha(raw),'independent-build')
        raw=json.dumps({'schema_version':1,'files':source_entries(2)}).encode()
        with self.assertRaises(ValueError):resume.parse_source_lock(raw,'f'*64,'independent-build')
        for change in ('duplicate','order','path','size'):
            fields=source_entries(2)
            if change=='duplicate':fields[1]=fields[0].copy()
            elif change=='order':fields.reverse()
            elif change=='path':fields[0]['path']='../escape'
            else:fields[0]['bytes']=256*resume.MIB+1
            raw=json.dumps({'schema_version':1,'files':fields}).encode()
            with self.subTest(change=change),self.assertRaises(ValueError):
                resume.parse_source_lock(raw,resume.sha(raw),'independent-build')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_exact_lab_manifest_and_closed_signed_six_artifact_inventory(self):
        value = manifest()
        self.assertEqual(resume.parse_manifest(json.dumps(value)), value)
        mutations = []
        for key, bad in [('environment', 'production'), ('architecture', 'x86_64'),
                         ('ubuntu', '25.04'), ('edition', 'other'), ('sequence', True),
                         ('sequence', 0), ('root_hash', 'A' * 64), ('root_bytes', 1),
                         ('hash_bytes', 65 * resume.MIB), ('purpose', 'os-release')]:
            changed = copy.deepcopy(value)
            changed[key] = bad
            mutations.append(changed)
        for kind in ('path', 'unknown', 'duplicate', 'digest', 'boolean-size', 'oversize'):
            changed = copy.deepcopy(value)
            if kind == 'path':
                changed['artifacts'][0]['name'] = '../root.ext4'
            elif kind == 'unknown':
                changed['artifacts'][0]['approval'] = True
            elif kind == 'duplicate':
                changed['artifacts'][1] = changed['artifacts'][0].copy()
            elif kind == 'digest':
                changed['artifacts'][0]['sha256'] = 'wrong'
            elif kind == 'boolean-size':
                changed['artifacts'][1]['bytes'] = True
            else:
                changed['artifacts'][2]['bytes'] = 257 * resume.MIB
            mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                resume.parse_manifest(json.dumps(changed))
        with self.assertRaises(ValueError):
            resume.parse_manifest(json.dumps(value).replace('{', '{"schema_version":1,', 1))

    def test_source_lock_exact_count_paths_bounds_hash_and_order(self):
        value = {'schema_version': 1, 'files': source_entries()}
        raw = json.dumps(value).encode()
        self.assertEqual(len(resume.parse_source_lock(raw, resume.sha(raw))), 314)
        with self.assertRaises(ValueError):
            resume.parse_source_lock(raw, 'c' * 64)
        for mutate in [lambda v: v['files'].pop(),
                       lambda v: v['files'].reverse(),
                       lambda v: v['files'][0].update(path='../escape'),
                       lambda v: v['files'][0].update(path='/absolute'),
                       lambda v: v['files'][0].update(path='src\\windows'),
                       lambda v: v['files'][0].update(bytes=33 * resume.MIB),
                       lambda v: v['files'][0].update(bytes=True),
                       lambda v: v['files'][0].update(sha256='D' * 64),
                       lambda v: v['files'][1].update(path=v['files'][0]['path'])]:
            changed = copy.deepcopy(value)
            mutate(changed)
            data = json.dumps(changed).encode()
            with self.assertRaises(ValueError):
                resume.parse_source_lock(data, resume.sha(data))

    def test_source_archive_refuses_missing_duplicate_link_special_and_hidden_tail(self):
        entries = {item['path']: item for item in source_entries(2)}
        valid = archive_bytes(entries)
        resume.check_source_archive(io.BytesIO(valid), entries)
        damaged = bytearray(valid)
        damaged[-1] = 1  # Within tarfile's internally buffered final 10 KiB.
        with self.assertRaises(ValueError):
            resume.check_source_archive(io.BytesIO(damaged), entries)
        with self.assertRaises(ValueError):
            resume.check_source_archive(io.BytesIO(valid), dict(entries, missing={'bytes': 4, 'sha256': 'a' * 64}))
        for name, kind in [('src/file-000.txt', tarfile.REGTYPE),
                           ('undeclared', tarfile.SYMTYPE),
                           ('../escape', tarfile.REGTYPE),
                           ('special', tarfile.CHRTYPE)]:
            extra = tarfile.TarInfo(name)
            extra.type = kind
            extra.linkname = 'src/file-000.txt'
            with self.assertRaises(ValueError):
                resume.check_source_archive(io.BytesIO(archive_bytes(entries, extra)), entries)

    def test_source_tree_only_permits_exact_captured_build_metadata(self):
        repo = self.root/'repo'
        repo.mkdir()
        (repo/'source').write_bytes(b'data')
        raw = b'independently pinned captured lock'
        entries = {'source': {'bytes': 4, 'sha256': resume.sha(b'data')}}
        (repo/'build-inputs.json').write_bytes(raw)
        pins = resume.Pins()
        self.addCleanup(pins.close)
        resume.check_source_tree(repo, entries, pins, raw)
        (repo/'build-inputs.json').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            resume.check_source_tree(repo, entries, pins, raw)
        (repo/'build-inputs.json').write_bytes(raw)
        (repo/'extra').write_bytes(b'extra')
        with self.assertRaises(ValueError):
            resume.check_source_tree(repo, entries, pins, raw)

    def test_regular_pins_refuse_hardlinks_and_in_place_changes(self):
        file = self.root/'input'
        file.write_bytes(b'original')
        pins = resume.Pins()
        self.addCleanup(pins.close)
        pins.capture(file, 8)
        pins.recheck()
        file.write_bytes(b'changed!')
        with self.assertRaises(ValueError):
            pins.recheck()
        with self.assertRaises(ValueError):
            pins.capture(file, 7)
        alias = self.root/'alias'
        os.link(file, alias)
        with self.assertRaises(ValueError):
            pins.capture(alias, 8)

    def test_fresh_output_never_overwrites_or_adopts_old_raw(self):
        output = self.root/'output'
        output.mkdir()
        with mock.patch.object(resume.os, 'statvfs', return_value=mock.Mock(f_flag=0)), \
                mock.patch.object(resume.shutil, 'disk_usage', return_value=mock.Mock(free=1000)):
            resume.prepare_output(output, 999)
            with self.assertRaises(ValueError):
                resume.prepare_output(output, 1)
        old = self.root/'old'
        old.mkdir()
        (old/'old.img').write_bytes(b'existing raw is never overwritten')
        with self.assertRaises(ValueError):
            resume.prepare_output(old, 1)
        self.assertEqual((old/'old.img').read_bytes(), b'existing raw is never overwritten')
        empty = self.root/'empty'
        empty.mkdir()
        with mock.patch.object(resume.os, 'statvfs', return_value=mock.Mock(f_flag=0)), \
                mock.patch.object(resume.shutil, 'disk_usage', return_value=mock.Mock(free=0)):
            with self.assertRaises(ValueError):
                resume.prepare_output(empty, 1)
        self.assertFalse(any(empty.iterdir()))

    def test_mount_inventory_accepts_same_device_bind_only_at_exact_path(self):
        raw = ('40 20 0:99 / /work rw - overlay overlay rw\n'
               '41 40 0:99 /retained/root /rootfs ro - ext4 /dev/sdb ro\n'
               '42 40 0:99 /new/artifacts /work/artifacts rw - ext4 /dev/sdb rw\n')
        self.assertTrue(resume.mountpoint_in(raw, Path('/work/artifacts')))
        self.assertTrue(resume.mountpoint_in(raw, Path('/rootfs')))
        self.assertFalse(resume.mountpoint_in(raw, Path('/work/artifacts/subdir')))
        self.assertFalse(resume.mountpoint_in(raw + raw.splitlines()[2] + '\n', Path('/work/artifacts')))

    def test_root_release_identity_never_converts_lab_to_other_release_or_purpose(self):
        value = manifest()
        identity = {key: value[key] for key in
                    ('schema_version', 'release', 'sequence', 'environment', 'architecture', 'ubuntu', 'edition')}
        release_id = (value['release'] + '\n').encode()
        resume.check_release_identity(json.dumps(identity), release_id, value)
        for key, bad in [('environment', 'production'), ('sequence', 14),
                         ('edition', 'headless'), ('purpose', 'os-release')]:
            changed = identity.copy()
            changed[key] = bad
            with self.assertRaises(ValueError):
                resume.check_release_identity(json.dumps(changed), release_id, value)
        with self.assertRaises(ValueError):
            resume.check_release_identity(json.dumps(identity), b'other\n', value)

    def test_synthetic_debugfs_inventory_and_regular_link_size_checks(self):
        listing = '/2/040755/0/0/.//\n/2/040755/0/0/..//\n/11/040700/0/0/lost+found//\n/12/100644/0/0/release.json/4/\n'
        with mock.patch.object(resume, 'run', return_value=listing):
            self.assertEqual(resume.ext4_entries(Path('fixture'), '/')['release.json'], (stat.S_IFREG | 0o644, 4))
        for output in ['Inode: 12 Type: symlink Size: 4 Links: 1',
                       'Inode: 12 Type: regular Size: 4 Links: 2',
                       'Inode: 12 Type: regular Size: 100 Links: 1']:
            with mock.patch.object(resume, 'run', return_value=output), self.assertRaises(ValueError):
                resume.ext4_member_size(Path('fixture'), '/release.json', 4)
        with mock.patch.object(resume, 'run', return_value='Inode: 12 Type: regular Size: 4 Links: 1'):
            self.assertEqual(resume.ext4_member_size(Path('fixture'), '/release.json', 4), 4)

    def test_actual_debugfs_empty_recovery_slots_are_not_members(self):
        listing = '/11/040700/0/0/.//\n/2/040755/0/0/..//\n' + '/0/000000/0/0//0/\n' * 3
        with mock.patch.object(resume, 'run', return_value=listing):
            self.assertEqual(resume.ext4_entries(Path('fixture'), '/lost+found'), {})
        for invalid in ('/0/000000/0/0/hidden/0/', '/0/100644/0/0//0/',
                        '/0/000000/1/0//0/', '/0/000000/0/0//1/'):
            with self.subTest(invalid=invalid), mock.patch.object(resume, 'run', return_value=invalid):
                with self.assertRaises(ValueError):
                    resume.ext4_entries(Path('fixture'), '/lost+found')

    def test_payload_root_prefix_plus_trailing_bytes_refuses_before_large_stream(self):
        previous = self.root/'previous'
        previous.mkdir()
        for name in set(resume.SIGNED) | {'release.json', 'release.sig', 'packages.lock'}:
            (previous/name).write_bytes(b'data')
        entries = {name: (stat.S_IFREG | 0o644, 4) for name in
                   set(resume.SIGNED) | {'release.json', 'release.sig', 'packages.lock'}}
        entries['lost+found'] = (stat.S_IFDIR | 0o700, None)
        entries['root.ext4'] = (stat.S_IFREG | 0o644, 5)
        with mock.patch.object(resume, 'ext4_entries', side_effect=[entries, {}]), \
                mock.patch.object(resume, 'ext4_member_size', return_value=4), \
                mock.patch.object(resume, 'extract_ext4', side_effect=lambda image, source, target, maximum: previous/source[1:]), \
                mock.patch.object(resume.subprocess, 'Popen') as child:
            with self.assertRaises(ValueError):
                resume.verify_payload(previous, self.root)
            child.assert_not_called()

    def test_copy_ranges_require_complete_inventory_exact_bytes_and_zero_slack(self):
        image = self.root/'tiny.img'
        image.write_bytes(b'data\0\0data\0\0data\0\0data\0\0')
        sources = []
        for index in range(4):
            source = self.root/f'source-{index}'
            source.write_bytes(b'data')
            sources.append(source)
        partitions = [{'offset': index * 6, 'bytes': 6} for index in range(4)]
        resume.verify_ranges(image, sources, partitions)
        for mutated_sources, mutated_parts in [(sources[:3], partitions),
                                               (sources, partitions[:3]),
                                               (sources, [dict(part, bytes=3) for part in partitions])]:
            with self.assertRaises(ValueError):
                resume.verify_ranges(image, mutated_sources, mutated_parts)
        image.write_bytes(b'dataX\0' + b'data\0\0' * 3)
        with self.assertRaises(ValueError):
            resume.verify_ranges(image, sources, partitions)

    def test_synthetic_primary_backup_gpt_crc_geometry_types_labels_and_closed_inventory(self):
        partitions = [{'offset': (40 + index * 4) * 512, 'bytes': 4 * 512,
                       'label': label, 'type': resume.ESP_GUID if index == 0 else resume.LINUX_GUID}
                      for index, label in enumerate(resume.LABELS)]
        total = 128 * 512
        image = self.root/'gpt.img'
        raw = bytearray(total)
        raw[450] = 0xee
        raw[454:462] = struct.pack('<II', 1, 127)
        raw[510:512] = b'\x55\xaa'
        table = bytearray(128 * 128)
        for index, part in enumerate(partitions):
            table[index * 128:(index + 1) * 128] = struct.pack(
                '<16s16sQQQ72s', part['type'].bytes_le, uuid.UUID(int=index + 1).bytes_le,
                part['offset'] // 512, (part['offset'] + part['bytes']) // 512 - 1,
                0, part['label'].encode('utf-16-le').ljust(72, b'\0'))
        for location, other, entries in [(1, 127, 2), (127, 1, 95)]:
            header = bytearray(struct.pack('<8sIIIIQQQQ16sQIII', b'EFI PART', 0x10000, 92,
                                           0, 0, location, other, 34, 94, uuid.UUID(int=100).bytes_le,
                                           entries, 128, 128, zlib.crc32(table)))
            header[16:20] = struct.pack('<I', zlib.crc32(header))
            raw[location * 512:location * 512 + 92] = header
            raw[entries * 512:entries * 512 + len(table)] = table
        image.write_bytes(raw)
        with mock.patch.object(resume, 'layout', return_value=(partitions, total)):
            self.assertEqual(resume.verify_gpt(image, 'desktop'), partitions)
            for offset in [16 + 512, 450, 2 * 512, 127 * 512 + 32]:
                changed = raw.copy()
                changed[offset] ^= 1
                image.write_bytes(changed)
                with self.assertRaises(ValueError):
                    resume.verify_gpt(image, 'desktop')
            image.write_bytes(raw)
            for key, bad in [('offset', 512), ('bytes', 512), ('label', 'foreign'),
                             ('type', resume.LINUX_GUID)]:
                altered = copy.deepcopy(partitions)
                altered[0][key] = bad
                with mock.patch.object(resume, 'layout', return_value=(altered, total)), self.assertRaises(ValueError):
                    resume.verify_gpt(image, 'desktop')


if __name__ == '__main__':
    unittest.main()
