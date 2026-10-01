"""Staging contract tests, not evidence of boot or storage qualification."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'image'))
import vm_workspace as workspace


@unittest.skipUnless(os.name == 'posix', 'Linux descriptor and directory fsync semantics')
class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.source = root / 'input'; self.source.mkdir()
        self.work = root / 'work'; self.work.mkdir()
        self.name = 'luma-native-lab-20260927-desktop-11.img'
        self.payload = b'fixture' + bytes(2*1024*1024) + b'tail'
        self.digest = hashlib.sha256(self.payload).hexdigest()
        (self.source / self.name).write_bytes(self.payload)
        (self.source / 'secureboot.cer').write_bytes(b'public certificate fixture')
        self.build = {'image': self.name, 'image_sha256': self.digest}
        (self.source / 'build.json').write_text(json.dumps(self.build))
        certificate = hashlib.sha256((self.source / 'secureboot.cer').read_bytes()).hexdigest()
        self.sums = f'{self.digest}  {self.name}\n{certificate}  secureboot.cer\n'
        (self.source / 'SHA256SUMS').write_text(self.sums)

    def run_prepare(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return workspace.prepare(self.source, self.work, self.digest, headroom=0)

    def test_exact_sparse_bytes_read_back_and_no_overwrite(self):
        record = self.run_prepare()
        self.assertEqual(record['result'], 'prepared')
        self.assertFalse(record['image_tested'])
        self.assertFalse(record['gate_closing'])
        self.assertEqual((self.work / 'artifacts' / self.name).read_bytes(), self.payload)
        with self.assertRaises(ValueError):
            self.run_prepare()

    def test_wrong_image_digest_retains_partial_without_ready_record(self):
        (self.source / self.name).write_bytes(b'changed')
        with self.assertRaises(ValueError): self.run_prepare()
        self.assertFalse((self.work / 'workspace.json').exists())
        self.assertFalse((self.work / 'artifacts' / self.name).exists())
        self.assertTrue((self.work / 'artifacts' / (self.name+'.partial')).exists())

    def test_linked_source_refused(self):
        image = self.source / self.name
        image.rename(self.source / 'real-image')
        image.symlink_to('real-image')
        with self.assertRaises(ValueError): self.run_prepare()
        self.assertEqual(list(self.work.iterdir()), [])

    def test_low_space_refuses_before_copy(self):
        with patch.object(workspace.shutil, 'disk_usage', return_value=type('Usage', (), {'free':0})()):
            with self.assertRaises(ValueError): self.run_prepare()
        self.assertEqual(list(self.work.iterdir()), [])

    def test_unsafe_duplicate_or_wrong_checksum_inventory_refused(self):
        for sums in (self.sums+self.sums, self.sums.replace(self.name, '../escape'),
                     self.sums.replace(self.digest, '0'*64), self.sums.splitlines()[0]+'\n'):
            (self.source / 'SHA256SUMS').write_text(sums)
            with self.assertRaises(ValueError): self.run_prepare()
            self.assertEqual(list(self.work.iterdir()), [])

    def test_bad_image_name_digest_and_duplicate_metadata_refused(self):
        for key, value in (('image', '../escape'), ('image', '/dev/sda'), ('image_sha256', '0'*64)):
            (self.source / 'build.json').write_text(json.dumps({**self.build, key:value}))
            with self.assertRaises(ValueError): self.run_prepare()
        (self.source / 'build.json').write_text('{"image":"duplicate",'+json.dumps(self.build)[1:])
        with self.assertRaises(ValueError): self.run_prepare()
        self.assertEqual(list(self.work.iterdir()), [])


if __name__ == '__main__': unittest.main()
