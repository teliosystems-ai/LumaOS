"""Bounded real qemu VHDX conversions; no Hyper-V, guest boot or host changes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('hyperv_image',
    Path(__file__).resolve().parents[1] / 'image/hyperv_image.py')
image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(image)


class HyperVImageTests(unittest.TestCase):
    def setUp(self):
        # There is deliberately no /tmp/public-filesystem fallback. The ordinary
        # test runner provides this root-owned private ext4 disposable fixture.
        storage = Path(os.environ['LUMA_STORAGE_TEST_ROOT'])
        self.assertTrue(storage.is_absolute())
        for path in (storage, *storage.parents):
            info = path.lstat()
            self.assertTrue(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                            and not info.st_mode & 0o022)
        parent = os.open(storage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            image.writable_ext4(parent)
        finally:
            os.close(parent)
        self.temporary = tempfile.TemporaryDirectory(prefix='luma-hyperv-image-', dir=storage)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.raw = self.work / 'source.raw'
        prefix = b'Actual qemu conversion fixture\n'
        self.raw.write_bytes(prefix + bytes(8*image.MIB-len(prefix)))
        self.raw.chmod(0o400)

    def test_hash_pin_is_exact_lowercase(self):
        self.assertEqual(image.pin('a'*64), 'a'*64)
        for bad in ('A'*64, 'a'*63, '', None, 'f'*64+'\n'):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                image.pin(bad)

    def test_held_input_hashes_actual_bytes(self):
        held = image.Held(self.raw, 9*image.MIB)
        try:
            self.assertEqual(held.hash(), hashlib.sha256(self.raw.read_bytes()).hexdigest())
        finally:
            held.close()

    def test_refuses_symlink_file_directory_hardlink_special_and_oversize(self):
        linked = self.work / 'alias.raw'
        linked.symlink_to(self.raw)
        hard = self.work / 'hard.raw'
        os.link(self.raw, hard)
        fifo = self.work / 'fifo'
        os.mkfifo(fifo)
        for path, bound in ((linked, 9*image.MIB), (self.work, 9*image.MIB),
                            (self.raw, 9*image.MIB), (fifo, 9*image.MIB)):
            with self.subTest(path=str(path)), self.assertRaises((OSError, ValueError)):
                image.Held(path, bound)
        hard.unlink()
        with self.assertRaises(ValueError):
            image.Held(self.raw, 100)

    def test_detects_input_substitution_and_byte_mutation(self):
        held = image.Held(self.raw, 9*image.MIB)
        try:
            replacement = self.work / 'replacement'
            replacement.write_bytes(self.raw.read_bytes())
            replacement.replace(self.raw)
            with self.assertRaises(ValueError):
                held.check()
        finally:
            held.close()
        held = image.Held(self.raw, 9*image.MIB)
        try:
            with self.raw.open('r+b') as stream:
                stream.write(b'changed')
            with self.assertRaises(ValueError):
                held.check()
        finally:
            held.close()

    def test_rejects_symlink_ancestor(self):
        linked = self.work / 'linked'
        linked.symlink_to(self.work, target_is_directory=True)
        with self.assertRaises(ValueError):
            image.Held(linked / self.raw.name, 9*image.MIB)

    def test_requires_readonly_source_mount(self):
        with self.assertRaises(ValueError):
            image.Held(self.raw, 9*image.MIB, readonly_mount=True)

    def test_arbitrary_script_is_not_a_converter(self):
        script = self.work / 'converter'
        script.write_bytes(b'#!/bin/sh\nexit 0\n')
        script.chmod(0o755)
        with self.assertRaises(ValueError):
            image.Held(script, image.MIB, executable=True)

    def test_converter_info_rejects_parent_unknown_format_duplicate_geometry(self):
        good = dict(format='vhdx', **{'virtual-size': 8*image.MIB,
            'cluster-size': image.BLOCK, 'dirty-flag': False})
        self.assertEqual(image.parse_info(json.dumps(good), 8*image.MIB), good)
        for extra in ({'format': 'qcow2'}, {'virtual-size': True}, {'dirty-flag': True},
                      {'cluster-size': 1024}, {'backing-filename': 'elsewhere'}, {'parent': ''}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                image.parse_info(json.dumps(dict(good, **extra)), 8*image.MIB)
        with self.assertRaises(ValueError):
            image.parse_info('{"format":"vhdx","format":"vhdx"}', 8*image.MIB)

    def test_existing_output_is_not_overwritten(self):
        directory = image.OutputDirectory(self.work / 'existing')
        self.addCleanup(directory.close)
        output = directory.path / image.OUTPUT
        output.write_bytes(b'preserve existing output')
        source = image.Held(self.raw, 9*image.MIB)
        try:
            with self.assertRaises(FileExistsError):
                image._convert(source, directory, None)
        finally:
            source.close()
        self.assertEqual(output.read_bytes(), b'preserve existing output')

    def test_unaligned_source_is_refused_before_output_creation(self):
        bad = self.work / 'unaligned.raw'
        bad.write_bytes(bytes(image.MIB+1))
        source = image.Held(bad, 2*image.MIB)
        directory = image.OutputDirectory(self.work / 'unaligned')
        self.addCleanup(directory.close)
        output = directory.path / image.OUTPUT
        try:
            with self.assertRaises(ValueError):
                image._convert(source, directory, None)
        finally:
            source.close()
        self.assertFalse(output.exists())

    def actual_conversion(self):
        # No fake converter, invented ELF stub, mocked conversion or guest run.
        tool = image.Held(Path('/usr/bin/qemu-img'), 64*image.MIB, executable=True)
        source = image.Held(self.raw, 9*image.MIB)
        directory = image.OutputDirectory(self.work / 'actual')
        self.addCleanup(directory.close)
        output = directory.path / image.OUTPUT
        self.addCleanup(tool.close)
        self.addCleanup(source.close)
        before = source.hash()
        geometry, logs, seal = image._convert(source, directory, tool)
        self.assertEqual(source.hash(), before)
        self.assertEqual(geometry, dict(virtual_bytes=8*image.MIB, block_bytes=image.BLOCK,
            logical_sector_bytes=512, physical_sector_bytes=512, dynamic=True, parent_present=False))
        self.assertEqual(len(logs), 4)
        self.assertEqual(seal, dict(bytes=output.stat().st_size,
                                   sha256=hashlib.sha256(output.read_bytes()).hexdigest()))
        return output

    def test_actual_qemu_conversion_compares_every_guest_byte(self):
        output = self.actual_conversion()
        self.assertEqual(output.read_bytes()[:8], b'vhdxfile')
        self.assertLess(output.stat().st_size, 8*image.MIB + 128*image.MIB)

    def test_actual_metadata_rejects_sector_parent_and_duplicate_identity(self):
        output = self.actual_conversion()
        fd = os.open(output, os.O_RDWR | os.O_NOFOLLOW)
        self.addCleanup(os.close, fd)
        region = os.pread(fd, 65536, 192*1024)
        metadata = next(struct.unpack_from('<Q', region, at+16)[0] for at in (16,48)
                        if region[at:at+16] == image.uuid.UUID('8b7ca206-4790-4b9a-b8fe-575f050f886e').bytes_le)
        header = os.pread(fd, 65536, metadata)
        logical_entry = metadata + 32 + 3*32
        logical_offset = struct.unpack_from('<I', header, 32+3*32+16)[0]
        sector = os.pread(fd, 4, metadata+logical_offset)
        os.pwrite(fd, struct.pack('<I', 4096), metadata+logical_offset)
        with self.assertRaises(ValueError):
            image.vhdx_geometry(fd, 8*image.MIB)
        os.pwrite(fd, sector, metadata+logical_offset)
        parameter_offset = struct.unpack_from('<I', header, 32+16)[0]
        os.pwrite(fd, struct.pack('<II', image.BLOCK, 2), metadata+parameter_offset)
        with self.assertRaises(ValueError):
            image.vhdx_geometry(fd, 8*image.MIB)
        os.pwrite(fd, struct.pack('<II', image.BLOCK, 0), metadata+parameter_offset)
        os.pwrite(fd, header[32:48], logical_entry)
        with self.assertRaises(ValueError):
            image.vhdx_geometry(fd, 8*image.MIB)

    def test_stage_cannot_target_c_or_reuse_directory(self):
        with self.assertRaises(ValueError):
            image.convert(self.raw, 'a'*64, self.work / 'new', Path('/usr/bin/qemu-img'), 'a'*64)

    def test_json_records_are_exclusive_and_bounded(self):
        directory = image.OutputDirectory(self.work / 'json')
        self.addCleanup(directory.close)
        image.write_json(directory, 'commands.json', dict(data=True))
        with self.assertRaises(FileExistsError):
            image.write_json(directory, 'commands.json', dict(data=False))
        with self.assertRaises(ValueError):
            image.write_json(directory, 'conversion.json', dict(data='a'*65536))
        self.assertEqual(json.loads((directory.path/'commands.json').read_bytes()), dict(data=True))

    def swapped_directory(self):
        directory = image.OutputDirectory(self.work / 'selected')
        self.addCleanup(directory.close)
        outside = self.work / 'outside'
        outside.mkdir()
        moved = self.work / 'held-original'
        directory.path.rename(moved)
        directory.path.symlink_to(outside, target_is_directory=True)
        return directory, outside, moved

    def test_output_and_records_refuse_preexisting_namespace_substitution(self):
        directory, outside, moved = self.swapped_directory()
        source = image.Held(self.raw, 9*image.MIB)
        self.addCleanup(source.close)
        with self.assertRaises(ValueError):
            image._convert(source, directory, None)
        for name in ('commands.json', 'conversion.json'):
            with self.assertRaises(ValueError):
                image.write_json(directory, name, dict(data=True))
        image.write_json(directory, 'failure.json', dict(failed_outputs_retained=True), forensic=True)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(json.loads((moved/'failure.json').read_bytes()), dict(failed_outputs_retained=True))

    def race_at_create(self, basename, operation):
        directory = image.OutputDirectory(self.work / 'racing')
        self.addCleanup(directory.close)
        outside = self.work / 'outside'
        outside.mkdir()
        moved = self.work / 'held-original'
        original_open = os.open
        fired = []
        def racing_open(path, flags, mode=0o777, *, dir_fd=None):
            if path == basename and dir_fd == directory.fd and not fired:
                fired.append(True)
                directory.path.rename(moved)
                directory.path.symlink_to(outside, target_is_directory=True)
            return original_open(path, flags, mode, dir_fd=dir_fd)
        with patch.object(image.os, 'open', side_effect=racing_open):
            operation(directory)
        self.assertEqual(fired, [True])
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue((moved/basename).is_file())
        return directory, moved

    def test_swap_between_output_check_and_create_cannot_redirect_write(self):
        source = image.Held(self.raw, 9*image.MIB)
        self.addCleanup(source.close)
        def effect(directory):
            with self.assertRaises(ValueError):
                image._convert(source, directory, None)
        directory, moved = self.race_at_create(image.OUTPUT, effect)
        self.assertEqual((moved/image.OUTPUT).stat().st_size, 0)
        image.write_json(directory, 'failure.json', dict(reason='namespace-substituted'), forensic=True)
        self.assertEqual(json.loads((moved/'failure.json').read_bytes()), dict(reason='namespace-substituted'))

    def test_swap_between_commands_check_and_create_cannot_redirect_record(self):
        def effect(directory):
            with self.assertRaises(ValueError):
                image.write_json(directory, 'commands.json', dict(data=True))
        directory, moved = self.race_at_create('commands.json', effect)
        self.assertEqual((moved/'commands.json').stat().st_size, 0)
        image.write_json(directory, 'failure.json', dict(reason='namespace-substituted'), forensic=True)
        self.assertTrue((moved/'failure.json').is_file())

    def test_forensic_failure_creation_remains_fd_relative_during_swap(self):
        def effect(directory):
            image.write_json(directory, 'failure.json', dict(reason='original-failure'), forensic=True)
        _, moved = self.race_at_create('failure.json', effect)
        self.assertEqual(json.loads((moved/'failure.json').read_bytes()), dict(reason='original-failure'))

    def test_no_output_record_name_can_escape_held_directory(self):
        directory = image.OutputDirectory(self.work / 'closed')
        self.addCleanup(directory.close)
        for name in ('../escape', '/tmp/escape', 'a/b', '.', 'unknown.json'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                image.write_json(directory, name, dict(data=True))

    def test_writable_or_foreign_parent_refuses_before_any_mkdir(self):
        for mode in (0o777, 0o775):
            parent = self.work / ('writable-' + oct(mode))
            parent.mkdir(mode=mode)
            parent.chmod(mode)
            with patch.object(image.os, 'mkdir', side_effect=AssertionError('must not mutate')):
                with self.assertRaises(ValueError):
                    image.OutputDirectory(parent/'not-created')
            self.assertFalse((parent/'not-created').exists())
        foreign = self.work/'foreign-parent'
        foreign.mkdir(mode=0o755)
        os.chown(foreign, 1000, 1000)
        try:
            with patch.object(image.os, 'mkdir', side_effect=AssertionError('must not mutate')):
                with self.assertRaises(ValueError):
                    image.OutputDirectory(foreign/'not-created')
            self.assertFalse((foreign/'not-created').exists())
        finally:
            os.chown(foreign, 0, 0)

    def test_constructor_refuses_plain_directory_substitution(self):
        for number, (owner, mode, contents) in enumerate(((1000,0o755,True),
                                                        (0,0o755,False), (0,0o700,True))):
            base = self.work/('swap-'+str(number))
            base.mkdir(mode=0o700)
            selected, foreign, retained = base/'selected', base/'foreign', base/'original-created'
            foreign.mkdir(mode=mode)
            if contents:
                (foreign/'sentinel').write_bytes(b'preexisting data, never conversion output')
            if owner:
                os.chown(foreign, owner, owner)
            original_open = os.open
            fired = []
            def racing_open(path, flags, permissions=0o777, *, dir_fd=None):
                if path == 'selected' and dir_fd is not None and flags & os.O_DIRECTORY and not fired:
                    fired.append(True)
                    selected.rename(retained)
                    foreign.rename(selected)
                return original_open(path, flags, permissions, dir_fd=dir_fd)
            try:
                with patch.object(image.os, 'open', side_effect=racing_open):
                    with self.assertRaises(ValueError):
                        image.OutputDirectory(selected)
                self.assertEqual(fired, [True])
                self.assertEqual(list(retained.iterdir()), [])
                self.assertEqual(sorted(p.name for p in selected.iterdir()), ['sentinel'] if contents else [])
            finally:
                if owner and selected.exists():
                    os.chown(selected, 0, 0)

    def test_output_parent_filesystem_must_be_actual_ext4(self):
        fd = os.open('/dev/shm', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with self.assertRaises(ValueError):
                image.writable_ext4(fd)
        finally:
            os.close(fd)

    def test_public_outer_d_is_never_a_private_stage(self):
        with self.assertRaises(ValueError):
            image.convert(self.raw, 'a'*64, Path('/mnt/d/LumaOS-builds/hyperv-untrusted'),
                          Path('/usr/bin/qemu-img'), 'b'*64)

    def export_fixture(self):
        output = self.actual_conversion()
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        manifest = output.parent/'conversion.json'
        record = dict(schema_version=1, purpose='luma-hyperv-live-installer-v1', architecture='amd64',
            profile='V', media_kind='live-installer-disk', vm_generation=2,
            source_raw_bytes=8*image.MIB, source_raw_sha256='a'*64, converter_sha256='b'*64,
            output_name=image.OUTPUT, output_bytes=output.stat().st_size, output_sha256=digest,
            geometry=dict(virtual_bytes=8*image.MIB, block_bytes=image.BLOCK,
                logical_sector_bytes=512, physical_sector_bytes=512, dynamic=True, parent_present=False),
            raw_preserved=True, raw_vhdx_guest_bytes_compared=True, installed_desktop=False,
            vm_created=False, vm_started=False, boot_qualified=False, production_qualified=False,
            secure_boot_trust_established=False, vtpm_commissioned=False,
            host_settings_changed=False, physical_disk_opened=False, gate_closing=False)
        manifest.write_bytes((json.dumps(record, sort_keys=True)+'\n').encode())
        manifest.chmod(0o600)
        public = self.work/'public'
        public.mkdir(mode=0o777)
        public.chmod(0o777)
        self.enterContext(patch.object(image, 'PRIVATE_STAGE', self.work))
        self.enterContext(patch.object(image, 'PUBLIC_EXPORT', public))
        # Production stays fixed at16,190,013,440. Exercise the exact exporter
        # on actual tiny qemu data without manufacturing a desktop/boot claim.
        self.enterContext(patch.object(image, 'DESKTOP_BYTES', 8*image.MIB))
        return output, manifest, public/'new.vhdx', digest

    def export(self, fixture):
        _, manifest, target, digest = fixture
        return image.export_verified(manifest, hashlib.sha256(manifest.read_bytes()).hexdigest(),
                                     'a'*64, digest, target)

    def test_actual_public_export_full_readback_and_exact_manifest(self):
        fixture = self.export_fixture()
        source, manifest, target, digest = fixture
        receipt = self.export(fixture)
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), digest)
        self.assertEqual(Path(str(target)+'.conversion.json').read_bytes(), manifest.read_bytes())
        self.assertEqual(json.loads(Path(str(target)+'.export.json').read_bytes()), receipt)
        self.assertTrue(receipt['full_destination_readback'])
        self.assertTrue(receipt['public_staging_untrusted'])
        self.assertFalse(receipt['boot_qualified'])
        self.assertFalse(Path(str(target)+'.failure.json').exists())

    def test_export_never_overwrites_any_existing_member(self):
        fixture = self.export_fixture()
        target = fixture[2]
        for suffix in ('', '.conversion.json', '.export.json', '.failure.json'):
            selected = Path(str(target)+suffix)
            selected.write_bytes(b'preexisting preserved')
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.export(fixture)
            self.assertEqual(selected.read_bytes(), b'preexisting preserved')
            self.assertEqual(list(target.parent.iterdir()), [selected])
            selected.unlink()

    def test_export_refuses_wrong_independent_pins_before_output(self):
        fixture = self.export_fixture()
        _, manifest, target, digest = fixture
        manifest_pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
        for fields in ((manifest_pin,'c'*64,digest), ('d'*64,'a'*64,digest),
                       (manifest_pin,'a'*64,'e'*64)):
            with self.subTest(pins=fields), self.assertRaises(ValueError):
                image.export_verified(manifest, fields[0], fields[1], fields[2], target)
            self.assertEqual(list(target.parent.iterdir()), [])

    def test_export_refuses_untrusted_private_source_ancestors(self):
        fixture = self.export_fixture()
        fixture[0].parent.chmod(0o777)
        try:
            with self.assertRaises(ValueError):
                self.export(fixture)
            self.assertEqual(list(fixture[2].parent.iterdir()), [])
        finally:
            fixture[0].parent.chmod(0o700)

    def test_export_closed_json_rejects_duplicate_nonfinite_and_type_confusion(self):
        for value in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                image.closed_json(value)
        fixture = self.export_fixture()
        record = json.loads(fixture[1].read_bytes())
        for field, value in (('schema_version',True), ('vm_generation',2.0), ('output_bytes',True),
                             ('boot_qualified',0), ('unexpected',False)):
            bad = dict(record, **{field:value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                image.validate_conversion(bad, 'a'*64, fixture[3])
        record['geometry']['logical_sector_bytes'] = 512.0
        with self.assertRaises(ValueError):
            image.validate_conversion(record, 'a'*64, fixture[3])

    def test_export_refuses_path_escape_symlink_parent_and_symlink_leaf(self):
        fixture = self.export_fixture()
        _, manifest, target, digest = fixture
        manifest_pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
        for output in (target.parent/'..'/'escape.vhdx', target.parent/'UPPER.VHDX',
                       self.work/'elsewhere.vhdx', target.parent/'CON.vhdx',
                       target.parent/'LPT1.nested.vhdx', target.parent/'trailing. '/'new.vhdx'):
            with self.subTest(output=output), self.assertRaises(ValueError):
                image.export_verified(manifest, manifest_pin, 'a'*64, digest, output)
        outside = self.work/'outside'
        outside.mkdir()
        linked = target.parent/'linked'
        linked.symlink_to(outside, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            image.export_verified(manifest, manifest_pin, 'a'*64, digest, linked/'new.vhdx')
        linked.unlink()
        target.symlink_to(self.raw)
        before = self.raw.read_bytes()
        with self.assertRaises(ValueError):
            self.export(fixture)
        self.assertEqual(self.raw.read_bytes(), before)

    def test_export_parent_substitution_cannot_redirect_and_retains_failure(self):
        fixture = self.export_fixture()
        public, original_open, fired = fixture[2].parent, os.open, []
        moved = self.work/'retained-public'
        outside = self.work/'outside'
        outside.mkdir()
        sentinel = outside/'new.vhdx'
        sentinel.write_bytes(b'must never be changed')
        def racing_open(path, flags, mode=0o777, *, dir_fd=None):
            if path == 'new.vhdx' and flags & os.O_CREAT and not fired:
                fired.append(True)
                public.rename(moved)
                public.symlink_to(outside, target_is_directory=True)
            return original_open(path, flags, mode, dir_fd=dir_fd)
        with patch.object(image.os, 'open', side_effect=racing_open):
            with self.assertRaises(ValueError):
                self.export(fixture)
        self.assertEqual(fired, [True])
        self.assertEqual(sentinel.read_bytes(), b'must never be changed')
        self.assertEqual(sorted(p.name for p in outside.iterdir()), ['new.vhdx'])
        self.assertEqual((moved/'new.vhdx').stat().st_size, 0)
        self.assertEqual(json.loads((moved/'new.vhdx.failure.json').read_bytes())['status'], 'export-failed')

    def test_export_mutation_after_readback_refuses_receipt_success(self):
        fixture = self.export_fixture()
        original_copy = image.copy_export
        def corrupt_after_copy(source, directory, name, digest, deadline):
            fd = original_copy(source, directory, name, digest, deadline)
            if name.endswith('.conversion.json'):
                with fixture[2].open('r+b') as stream:
                    stream.write(b'corrupt!')
            return fd
        with patch.object(image, 'copy_export', side_effect=corrupt_after_copy):
            with self.assertRaises(ValueError):
                self.export(fixture)
        self.assertFalse(Path(str(fixture[2])+'.export.json').exists())
        self.assertEqual(json.loads(Path(str(fixture[2])+'.failure.json').read_bytes())['status'], 'export-failed')

    def test_export_short_writes_are_completed_and_no_progress_refuses(self):
        fixture = self.export_fixture()
        original_write = os.pwrite
        short_writes = 0
        def short(fd, data, offset):
            nonlocal short_writes
            short_writes += 1
            return original_write(fd, data[:32768], offset)
        # A recording Mock retains every sliced MiB argument and obscures the
        # exporter's actual bounded-memory behavior. Retain scalar evidence of
        # real short writes instead, then compare every resulting byte.
        with patch.object(image.os, 'pwrite', new=short):
            self.export(fixture)
        self.assertGreater(short_writes, fixture[0].stat().st_size // image.MIB)
        self.assertEqual(fixture[2].read_bytes(), fixture[0].read_bytes())

    def test_export_zero_progress_retains_partial_without_success(self):
        fixture = self.export_fixture()
        with patch.object(image.os, 'pwrite', return_value=0):
            with self.assertRaises(ValueError) as failure:
                self.export(fixture)
        self.assertIn('export write made no progress', str(failure.exception))
        self.assertFalse(Path(str(fixture[2])+'.export.json').exists())
        self.assertEqual(fixture[2].stat().st_size, 0)
        self.assertTrue(any('Forensic record could not be created' in value
                            for value in failure.exception.__notes__))

    def test_export_observation_deadline_refuses_before_output(self):
        fixture = self.export_fixture()
        now = image.time.monotonic()
        with patch.object(image.time, 'monotonic', side_effect=[now, now+1801]):
            with self.assertRaisesRegex(ValueError, 'observation deadline'):
                self.export(fixture)
        self.assertEqual(list(fixture[2].parent.iterdir()), [])

    def test_export_mutation_between_validated_readback_and_return_keeps_old_seal(self):
        fixture = self.export_fixture()
        original_copy = image.copy_export
        def corrupt_return(source, directory, name, digest, deadline):
            result = original_copy(source, directory, name, digest, deadline)
            if name == fixture[2].name:
                os.pwrite(result[0], b'corrupt!', 0)
            return result
        with patch.object(image, 'copy_export', side_effect=corrupt_return):
            with self.assertRaisesRegex(ValueError, 'changed after readback'):
                self.export(fixture)
        self.assertFalse(Path(str(fixture[2])+'.export.json').exists())


if __name__ == '__main__':
    unittest.main()
