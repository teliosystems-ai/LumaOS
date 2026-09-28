"""External artifact staging preserves bytes and never overwrites old output."""
import errno
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

IMAGE=Path(__file__).resolve().parents[1]/'image'
spec=importlib.util.spec_from_file_location('assembler',IMAGE/'assemble.py')
assembler=importlib.util.module_from_spec(spec);spec.loader.exec_module(assembler)


class ExternalStagingTests(unittest.TestCase):
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
