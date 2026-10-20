"""Closed build-receipt checks, not model/installed-device qualification."""
import copy
import os
from pathlib import Path
import tempfile
import unittest

import speech_policy as speech


class SpeechPolicy(unittest.TestCase):
    def report(self):
        return {'schema_version': 1,
            'source_sha256': {name: speech.digest(speech.ASSETS/'speech'/name) for name in speech.builder.SOURCES},
            'input_sha256': {name: digest for name, (_size, digest) in speech.builder.INPUTS.items()},
            'asr_worker_sha256': '1'*64, 'tts_worker_sha256': '2'*64,
            'compiler_arguments': speech.builder.build_commands(), 'asr_runtime_sha256': '3'*64,
            'tts_backend': 'espeak-ng-1.51+dfsg-12build1-synchronous-retrieval-only',
            'whisper_backend': 'v1.9.5-luma-asr-v1-amd64-sse2-cpu-only',
            'asr_model_available_by_bytes': True, 'model_authority_provisioned': False,
            'actual_asr_job_executed': False, 'audio_device_opened': False,
            'host_apparmor_qualified': False, 'production_qualified': False, 'gate_closing': False}

    def test_exact_closed_build_recipe_is_data_not_qualification(self):
        speech.validate_report(self.report())

    def test_repeated_input_projection_never_shadows_the_source_hash_function(self):
        report = self.report()
        for _ in range(2):
            speech.validate_report(report)
            self.assertTrue(callable(speech.digest))
        changed = copy.deepcopy(report)
        changed['source_sha256']['tts_worker.c'] = 'f'*64
        with self.assertRaisesRegex(ValueError, 'exact reviewed controller sources'):
            speech.validate_report(changed)

    def test_omitted_or_added_sources_inputs_fields_refused(self):
        for section in ('source_sha256', 'input_sha256'):
            report=self.report(); report[section].pop(next(iter(report[section])))
            with self.assertRaises(ValueError): speech.validate_report(report)
            report=self.report(); report[section]['extra']='4'*64
            with self.assertRaises(ValueError): speech.validate_report(report)
        report=self.report(); report.pop('gate_closing')
        with self.assertRaises(ValueError): speech.validate_report(report)
        report=self.report(); report['authority']=True
        with self.assertRaises(ValueError): speech.validate_report(report)

    def test_changed_sources_pins_commands_and_qualification_refused(self):
        mutations=[lambda r:r['source_sha256'].update({'tts_worker.c':'4'*64}),
            lambda r:r['input_sha256'].update({'whisper-source.tar.gz':'5'*64}),
            lambda r:r['compiler_arguments'][0].append('-DGGML_NATIVE=ON'),
            lambda r:r.update(whisper_backend='AVX2-only'),
            lambda r:r.update(schema_version=True),
            lambda r:r.update(asr_model_available_by_bytes=1)]
        for key in ('model_authority_provisioned', 'actual_asr_job_executed', 'audio_device_opened', 'host_apparmor_qualified', 'production_qualified', 'gate_closing'):
            mutations.append(lambda r,key=key:r.update({key:True}))
        for mutate in mutations:
            report=copy.deepcopy(self.report()); mutate(report)
            with self.assertRaises(ValueError): speech.validate_report(report)

    def test_reader_refuses_symlinks_ancestors_hardlinks_empty_and_bounds(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name); path=root/'actual'; path.write_bytes(b'exact')
            self.assertEqual(speech.read(path),b'exact')
            with self.assertRaises(ValueError): speech.read(path,4)
            alias=root/'alias'; alias.symlink_to(path)
            with self.assertRaises(OSError): speech.read(alias)
            real=root/'real';real.mkdir();(real/'file').write_bytes(b'value')
            redirect=root/'redirect';redirect.symlink_to(real,target_is_directory=True)
            with self.assertRaises(ValueError):speech.read(redirect/'file')
            linked=root/'linked';os.link(path,linked)
            with self.assertRaises(ValueError):speech.read(path)
            empty=root/'empty';empty.touch()
            with self.assertRaises(ValueError):speech.read(empty)
            fifo=root/'fifo';os.mkfifo(fifo)
            with self.assertRaises(ValueError):speech.read(fifo)

    def test_image_metadata_refuses_writable_files_directories_and_escaping_paths(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name); directory=root/'assets';directory.mkdir();path=directory/'worker';path.write_bytes(b'not an actual ELF')
            speech.protected(root,path)
            path.chmod(0o666)
            with self.assertRaises(ValueError):speech.protected(root,path)
            path.chmod(0o444);directory.chmod(0o777)
            with self.assertRaises(ValueError):speech.protected(root,path)
            directory.chmod(0o755)
            with self.assertRaises(ValueError):speech.protected(directory,root/'outside')


if __name__ == '__main__': unittest.main()
