"""External artifact staging preserves bytes and never overwrites old output."""
import errno
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

IMAGE=Path(__file__).resolve().parents[1]/'image'
spec=importlib.util.spec_from_file_location('assembler',IMAGE/'assemble.py')
assembler=importlib.util.module_from_spec(spec);spec.loader.exec_module(assembler)


class ExternalStagingTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'native root-owned cleanup contract')
    def test_verified_payload_staging_releases_only_generated_aliases(self):
        with tempfile.TemporaryDirectory(dir=os.environ['LUMA_STORAGE_TEST_ROOT']) as folder:
            root=Path(folder);source=root/'artifacts';source.mkdir();staged=root/'payload';staged.mkdir()
            original=source/'release.json';original.write_bytes(b'preserved exact signed release bytes')
            assembler.stage_payload_member(original,staged/'release.json')
            self.assertEqual(original.stat().st_nlink,2)
            with patch.object(assembler,'WORK',root),patch.object(assembler,'OUT',source):
                assembler.release_payload_staging(staged,source,['release.json'])
            self.assertEqual(original.read_bytes(),b'preserved exact signed release bytes')
            self.assertEqual(original.stat().st_nlink,1)
            self.assertFalse(staged.exists())

    @unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'native root-owned cleanup contract')
    def test_payload_cleanup_refuses_unknown_or_changed_staging_before_unlink(self):
        with tempfile.TemporaryDirectory(dir=os.environ['LUMA_STORAGE_TEST_ROOT']) as folder:
            root=Path(folder);source=root/'artifacts';source.mkdir();staged=root/'payload';staged.mkdir()
            (source/'release.json').write_bytes(b'original');(staged/'release.json').write_bytes(b'changed!')
            with patch.object(assembler,'WORK',root),patch.object(assembler,'OUT',source):
                with self.assertRaises(ValueError):assembler.release_payload_staging(staged,source,['release.json'])
                self.assertTrue((staged/'release.json').exists())
                (staged/'release.json').write_bytes(b'original');(staged/'unknown').write_bytes(b'preserve')
                with self.assertRaises(ValueError):assembler.release_payload_staging(staged,source,['release.json'])
            self.assertEqual((staged/'unknown').read_bytes(),b'preserve')
            self.assertEqual((source/'release.json').read_bytes(),b'original')

    @unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'native root-owned cleanup contract')
    def test_verified_independent_copy_staging_preserves_original_and_refuses_substitution(self):
        with tempfile.TemporaryDirectory(dir=os.environ['LUMA_STORAGE_TEST_ROOT']) as folder:
            root=Path(folder);source=root/'artifacts';source.mkdir();staged=root/'payload';staged.mkdir()
            original=source/'release.json';original.write_bytes(b'exact original')
            (staged/'release.json').write_bytes(original.read_bytes())
            with patch.object(assembler,'WORK',root),patch.object(assembler,'OUT',source):
                assembler.release_payload_staging(staged,source,['release.json'])
            self.assertEqual(original.read_bytes(),b'exact original');self.assertEqual(original.stat().st_nlink,1)
            staged.mkdir();(staged/'release.json').write_bytes(original.read_bytes())
            actual=assembler.hashlib.file_digest;swapped=[];retained=root/'retained'
            def substitute(stream,algorithm):
                value=actual(stream,algorithm)
                if not swapped:
                    staged.rename(retained);staged.mkdir();(staged/'release.json').write_bytes(b'foreign preserve')
                    swapped.append(True)
                return value
            with patch.object(assembler,'WORK',root),patch.object(assembler,'OUT',source), \
                 patch.object(assembler.hashlib,'file_digest',side_effect=substitute):
                with self.assertRaisesRegex(ValueError,'namespace changed'):
                    assembler.release_payload_staging(staged,source,['release.json'])
            self.assertEqual((staged/'release.json').read_bytes(),b'foreign preserve')
            self.assertEqual((retained/'release.json').read_bytes(),b'exact original')
            self.assertEqual(original.read_bytes(),b'exact original')

    def test_cross_device_copy_preserves_size_zeros_and_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'source';dest=Path(folder)/'dest'
            data=b'header'+bytes(2*1024*1024)+b'tail'
            source.write_bytes(data)
            with patch.object(assembler.os,'link',side_effect=OSError(errno.EXDEV,'cross device')):
                assembler.stage_payload_member(source,dest)
            self.assertEqual(dest.read_bytes(),data)
            self.assertEqual(source.read_bytes(),data)

    def test_cross_device_fallback_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'source';dest=Path(folder)/'dest'
            source.write_bytes(b'new');dest.write_bytes(b'preserve')
            with patch.object(assembler.os,'link',side_effect=OSError(errno.EXDEV,'cross device')):
                with self.assertRaises(FileExistsError):assembler.stage_payload_member(source,dest)
            self.assertEqual(dest.read_bytes(),b'preserve')

    def test_permission_failure_is_not_bypassed(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'source';dest=Path(folder)/'dest';source.write_bytes(b'source')
            with patch.object(assembler.os,'link',side_effect=PermissionError(errno.EACCES,'denied')):
                with self.assertRaises(PermissionError):assembler.stage_payload_member(source,dest)
            self.assertFalse(dest.exists())


if __name__=='__main__':unittest.main()
