"""Actual tiny ISO tool/extent tests, never an installed OS or optical boot."""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

IMAGE=Path(__file__).resolve().parents[1]/'image'
SPEC=importlib.util.spec_from_file_location('luma_optical_tests_subject',IMAGE/'optical_media.py')
optical=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(optical)
LINUX=os.name=='posix' and Path('/.dockerenv').is_file() and shutil.which('xorriso') is not None


class OpticalSourceTests(unittest.TestCase):
    def test_initrd_discovery_is_fixed_readonly_and_bounded(self):
        source=(IMAGE/'overlay/usr/lib/dracut/modules.d/91luma/luma-optical.sh').read_text()
        for token in ('luma.media=','luma.mode=','luma.slot=','"$count" -le 16','[ -z "$selected" ]',
                      '-t iso9660 -o ro,nodev,nosuid,noexec','--read-only','--getro','--sizelimit',
                      'luma-optical-root','luma-optical-hash','-ge 4096','-le 67108864'):
            self.assertIn(token,source)
        self.assertNotIn('by-label',source)
        self.assertNotIn('dmsetup remove',source)
        self.assertIn('blockdev --setro "/dev/$name"',source)
        self.assertLess(source.index('--setro'),source.index('"$node/ro")" = 1'))

    def test_initrd_discovery_does_not_need_dracut_environment(self):
        # Sequence 17: sourcing dracut-lib.sh under `set -u` aborted on NEWROOT,
        # so the optical ISO never reached its verity root.
        source=(IMAGE/'overlay/usr/lib/dracut/modules.d/91luma/luma-optical.sh').read_text()
        self.assertTrue(source.startswith('#!/bin/sh\n'))
        self.assertIn('\nset -eu\n',source)
        self.assertNotRegex(source,r'(?m)^\s*(\.|source)\s')
        self.assertNotIn('getarg',source)
        self.assertIn('cmdline=$(cat /proc/cmdline)',source)

    @unittest.skipUnless(os.name=='posix' and shutil.which('dash'),'requires dash, the initrd /bin/sh')
    def test_initrd_command_line_parser_requires_each_key_once(self):
        source=(IMAGE/'overlay/usr/lib/dracut/modules.d/91luma/luma-optical.sh').read_text()
        self.assertEqual(subprocess.run([shutil.which('dash'),'-n','-c',source]).returncode,0)
        function=re.search(r'^cmdline_value\(\) \{\n.*?^\}\n',source,re.M|re.S).group(0)
        def value(cmdline,key):
            return subprocess.run(['/usr/bin/env','-i',shutil.which('dash'),'-c',
                                   'set -eu\n'+function+'cmdline=$1\ncmdline_value "$2"','dash',cmdline,key],
                                  capture_output=True,text=True,cwd='/')
        good=('root=/dev/mapper/root ro roothash='+'a'*64+' systemd.verity_root_hash=/dev/luma-optical-hash '
              'luma.mode=live luma.slot=live luma.media=optical /* rd.shell=0')
        for key,expected in (('luma.media=','optical'),('luma.mode=','live'),('luma.slot=','live'),('roothash=','a'*64)):
            result=value(good,key)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,expected+'\n',''),key)
        for cmdline in (good+' luma.media=optical',good+' luma.media=disk',good.replace('luma.media=optical','')):
            result=value(cmdline,'luma.media=')
            self.assertEqual((result.returncode,result.stdout),(1,''),cmdline)
        self.assertEqual(value('xluma.media=optical','luma.media=').returncode,1)

    def test_initrd_unit_blocks_verity_on_failed_optical_discovery(self):
        unit=(IMAGE/'overlay/usr/lib/dracut/modules.d/91luma/luma-optical.service').read_text()
        self.assertIn('ConditionKernelCommandLine=luma.media=optical',unit)
        self.assertIn('Before=systemd-veritysetup@root.service',unit)
        self.assertIn('TimeoutStartSec=90',unit)
        setup=(IMAGE/'overlay/usr/lib/dracut/modules.d/91luma/module-setup.sh').read_text()
        self.assertIn('systemd-veritysetup@root.service.requires',setup)
        self.assertIn('/etc/udev/rules.d/99-luma-optical.rules',setup)

    def test_real_root_names_optical_loops_after_switch_root(self):
        # Sequence-17 diagnostic: the real root regenerates
        # systemd-veritysetup@root, which waits for the same links. The rule
        # must ship in the root and reach the initrd from that one source.
        rule=(IMAGE/'overlay/etc/udev/rules.d/99-luma-optical.rules').read_text()
        spec=importlib.util.spec_from_file_location('luma_optical_boot_policy',IMAGE/'boot_policy.py')
        policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
        line=policy.command_line('0'*64,'optical','desktop')
        for backing,link in (('root.ext4','luma-optical-root'),('root.verity','luma-optical-hash')):
            self.assertIn(f'ATTR{{loop/backing_file}}=="/run/initramfs/luma-optical/{backing}", SYMLINK+="{link}"',rule)
            self.assertIn(f'/dev/{link} ',line)
        self.assertFalse((IMAGE/'overlay/usr/lib/dracut/modules.d/91luma/99-luma-optical.rules').exists())
        setup=(IMAGE/'overlay/usr/lib/dracut/modules.d/91luma/module-setup.sh').read_text()
        self.assertIn('inst_multiple /etc/udev/rules.d/99-luma-optical.rules || return 1',setup)
        self.assertNotIn('$moddir/99-luma-optical.rules',setup)


@unittest.skipUnless(LINUX,'requires isolated Linux xorriso tools container')
class ActualOpticalTests(unittest.TestCase):
    def setUp(self):
        base=Path(os.environ['LUMA_STORAGE_TEST_ROOT'])
        self.temp=tempfile.TemporaryDirectory(prefix='luma-optical-tiny-',dir=base)
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.efi=self.root/'efi.img'
        # Real ISO construction/catalog with an explicitly nonbootable data
        # fixture. Separately signed/FAT UKI behavior is the boot-policy lane.
        prefix=b'not-bootable-EFI-fixture\n'
        self.efi.write_bytes(prefix+bytes(2*optical.MIB-len(prefix)))
        prefix=b'not-an-ext4-OS\n'
        self.data=self.root/'root.ext4';self.data.write_bytes(prefix+bytes(65536-len(prefix)))
        self.extra=self.root/'release-trust.json';self.extra.write_bytes(b'{"fixture":"not-trust-authority"}\n')
        self.members={'efi.img':self.efi,'root.ext4':self.data,'release-trust.json':self.extra}
        self.expected={name:optical.seal(path)[0] for name,path in self.members.items()}
        self.iso=self.root/'tiny.iso';optical.build_iso(self.iso,self.members)

    def checked(self):return optical.verify_iso(self.iso,self.expected)

    def descriptor(self,kind):
        data=self.iso.read_bytes()
        return next(index*optical.SECTOR for index in range(16,48) if data[index*optical.SECTOR]==kind)

    def root_records(self):
        data=self.iso.read_bytes();pvd=self.descriptor(1)
        begin=struct.unpack_from('<I',data,pvd+158)[0]*optical.SECTOR
        size=struct.unpack_from('<I',data,pvd+166)[0];offset=0;found={}
        while offset<size:
            width=data[begin+offset]
            if not width:offset=((offset//optical.SECTOR)+1)*optical.SECTOR;continue
            name=data[begin+offset+33:begin+offset+33+data[begin+offset+32]]
            found[name]=begin+offset;offset+=width
        return found

    def change(self,offset,value):
        with self.iso.open('r+b') as stream:stream.seek(offset);stream.write(value)

    def test_actual_xorriso_primary_namespace_efi_catalog_and_full_file_hashes(self):
        record=self.checked()
        self.assertEqual(record['member_count'],3)
        self.assertTrue(record['all_member_bytes_compared'])
        self.assertTrue(record['efi_el_torito_verified'])
        self.assertFalse(record['boot_qualified'])
        self.assertEqual(record['iso_sha256'],hashlib.sha256(self.iso.read_bytes()).hexdigest())

    def test_existing_iso_is_not_overwritten(self):
        before=self.iso.read_bytes()
        with self.assertRaises(ValueError):optical.build_iso(self.iso,self.members)
        self.assertEqual(self.iso.read_bytes(),before)

    def test_optical_precedes_actual_payload_hardlinks_without_relaxing_link_policy(self):
        os.link(self.data,self.root/'deliberate-payload-hardlink')
        with self.assertRaisesRegex(ValueError,'single-link'):optical.seal(self.data)
        source=(IMAGE/'assemble.py').read_text();begin=source.index('def seal_media(')
        self.assertLess(source.index('optical = optical_media.create_iso',begin),
                        source.index('stage_payload_member(OUT/name',begin))

    def test_source_symlink_is_not_followed(self):
        linked=self.root/'linked';linked.symlink_to(self.data)
        with self.assertRaises((ValueError,OSError)):optical.build_iso(self.root/'refused.iso',{'efi.img':self.efi,'root.ext4':linked})

    def test_actual_payload_byte_tamper_is_refused(self):
        item=self.root_records()[b'root.ext4;1'];data=self.iso.read_bytes()
        extent=struct.unpack_from('<I',data,item+2)[0]*optical.SECTOR
        self.change(extent,b'tampered')
        with self.assertRaisesRegex(ValueError,'actual optical member'):self.checked()

    def test_el_torito_entry_point_substitution_is_refused(self):
        boot=self.descriptor(0);data=self.iso.read_bytes();at=struct.unpack_from('<I',data,boot+71)[0]*optical.SECTOR
        self.change(at+40,struct.pack('<I',1))
        with self.assertRaisesRegex(ValueError,'El Torito'):self.checked()

    def test_catalog_platform_and_validation_checksum_are_mandatory(self):
        boot=self.descriptor(0);original=self.iso.read_bytes();at=struct.unpack_from('<I',original,boot+71)[0]*optical.SECTOR
        for offset,value in ((at+1,b'\0'),(at+28,b'\xff\xff'),(at+30,b'\0\0')):
            with self.subTest(offset=offset):
                self.iso.write_bytes(original);self.change(offset,value)
                with self.assertRaisesRegex(ValueError,'validation'):self.checked()

    def test_dual_endian_extent_mismatch_is_refused(self):
        at=self.root_records()[b'root.ext4;1'];self.change(at+6,struct.pack('>I',1))
        with self.assertRaisesRegex(ValueError,'endian'):self.checked()

    def test_extent_alias_and_extra_file_are_refused(self):
        records=self.root_records();data=self.iso.read_bytes();root,efi=records[b'root.ext4;1'],records[b'efi.img;1']
        self.change(root+2,data[efi+2:efi+10])
        with self.assertRaisesRegex(ValueError,'aliased'):self.checked()

    def test_symlink_and_alternate_namespace_records_are_refused(self):
        at=self.root_records()[b'root.ext4;1'];self.change(at+25,b'\x02')
        with self.assertRaises(ValueError):self.checked()

    def test_root_extended_attribute_volume_and_interleave_tampering_are_refused(self):
        at=self.descriptor(1)+156;original=self.iso.read_bytes()
        for relative,value in ((1,b'\x01'),(26,b'\x01'),(28,b'\x02\0\0\x02'),(33,b'\x01')):
            with self.subTest(field=relative):
                self.iso.write_bytes(original);self.change(at+relative,value)
                with self.assertRaises(ValueError):self.checked()

    def test_alternate_el_torito_entries_and_selection_criteria_are_refused(self):
        original=self.iso.read_bytes();boot=self.descriptor(0)
        catalog=struct.unpack_from('<I',original,boot+71)[0]*optical.SECTOR
        for offset,value in ((catalog+64,b'\x91'),(catalog+44,b'\x01')):
            with self.subTest(offset=offset):
                self.iso.write_bytes(original);self.change(offset,value)
                with self.assertRaisesRegex(ValueError,'alternate El Torito'):self.checked()

    def test_legacy_four_sector_efi_load_size_is_refused(self):
        boot=self.descriptor(0);data=self.iso.read_bytes()
        catalog=struct.unpack_from('<I',data,boot+71)[0]*optical.SECTOR
        self.change(catalog+38,struct.pack('<H',4))
        with self.assertRaisesRegex(ValueError,'El Torito'):self.checked()

    def test_actual_large_efi_count_uses_firmware_full_image_sentinel(self):
        with self.efi.open('r+b') as stream:stream.truncate(34*optical.MIB)
        self.expected['efi.img']=optical.seal(self.efi)[0]
        self.iso=self.root/'efi-count-sentinel.iso';optical.build_iso(self.iso,self.members)
        self.assertTrue(self.checked()['efi_el_torito_verified'])

    def test_whole_image_hash_is_inside_final_held_identity_check(self):
        original=optical.range_hash
        def changed(fd,extents):
            value=original(fd,extents)
            if extents==[(0,self.iso.stat().st_size)]:
                self.change(self.iso.stat().st_size-1,b'x')
            return value
        with patch.object(optical,'range_hash',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'changed across'):self.checked()

    def test_actual_tiny_multiextent_member_hashes_complete_ordered_bytes(self):
        data=self.iso.read_bytes();at=self.root_records()[b'root.ext4;1'];width=data[at]
        self.assertFalse(any(data[at+width:at+2*width]))
        first,second=bytearray(data[at:at+width]),bytearray(data[at:at+width])
        start=struct.unpack_from('<I',first,2)[0]
        first[10:18]=struct.pack('<I',32768)+struct.pack('>I',32768);first[25]=128
        second[2:10]=struct.pack('<I',start+16)+struct.pack('>I',start+16)
        second[10:18]=struct.pack('<I',32768)+struct.pack('>I',32768)
        self.change(at,first+second)
        self.assertTrue(self.checked()['all_member_bytes_compared'])
        self.change(at+10,struct.pack('<I',32769)+struct.pack('>I',32769))
        with self.assertRaisesRegex(ValueError,'complete sectors'):self.checked()

    def test_unknown_and_omitted_independent_pins_are_refused(self):
        with self.assertRaises(ValueError):optical.verify_iso(self.iso,{'efi.img':self.expected['efi.img']})
        bad={**self.expected,'other.bin':self.expected['root.ext4']}
        with self.assertRaises(ValueError):optical.verify_iso(self.iso,bad)
        for field,value in (('bytes',True),('sha256','A'*64)):
            bad={**self.expected,'root.ext4':{**self.expected['root.ext4'],field:value}}
            with self.subTest(field=field),self.assertRaises(ValueError):optical.verify_iso(self.iso,bad)

    def test_tool_diagnostics_and_time_are_bounded_before_completion(self):
        with self.assertRaisesRegex(ValueError,'diagnostics'):
            optical.run('/usr/bin/python3','-c','import os;os.write(1,b"a"*2000000)')
        with self.assertRaisesRegex(ValueError,'deadline'):
            optical.run('/usr/bin/python3','-c','import time;time.sleep(5)',timeout=0.01)


if __name__=='__main__':unittest.main()
