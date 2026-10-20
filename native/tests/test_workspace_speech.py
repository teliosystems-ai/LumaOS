"""Real owned-process and strict input tests; no speaker/microphone activated."""
import fcntl
import importlib.util
import io
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time
import unittest
import zipfile
from unittest import mock

SOURCE = Path(__file__).parents[1]/'desktop/workspace_speech.py'
spec = importlib.util.spec_from_file_location('luma_workspace_speech', SOURCE)
speech = importlib.util.module_from_spec(spec)
spec.loader.exec_module(speech)


def wave(samples=2205):
    pcm = b'\0\0'*samples
    return struct.pack('<4sI4s4sIHHIIHH4sI', b'RIFF', len(pcm)+36, b'WAVE', b'fmt ',
                       16, 1, 1, 22050, 44100, 2, 16, b'data', len(pcm))+pcm


class SpeechBounds(unittest.TestCase):
    def test_literal_not_markup_or_command(self):
        for value in ('hello', '<audio src="https://invalid/">literal</audio>', '$(do-not-run) `literal`', 'é'):
            self.assertEqual(speech.literal_text(value), value.encode())

    def test_closed_text_bounds(self):
        for value in ('', ' \n', 'a\0b', 'a\rb', '\x7f', '\x85', 'a'*4097, '\ud800'):
            with self.assertRaises((ValueError, UnicodeError)):
                speech.literal_text(value)
        self.assertEqual(len(speech.literal_text('a'*4096)), 4096)

    def test_complete_fixed_wav(self):
        self.assertEqual(speech.wav_samples(wave()), b'\0\0'*2205)
        self.assertEqual(len(speech.wav_samples(wave(22050*30))), 1323000)

    def test_wav_no_decoder_or_clipping(self):
        original = wave()
        for value in (b'', original[:-1], original+b'\0', wave(22050*30+1), original[:44],
                      original[:24]+struct.pack('<I',16000)+original[28:],
                      original[:20]+struct.pack('<H',3)+original[22:]):
            with self.assertRaises(ValueError):
                speech.wav_samples(value)

    def test_memfd_is_exact_immutable_snapshot(self):
        descriptor = speech.sealed('luma-speech-text', b'literal')
        try:
            self.assertEqual(os.pread(descriptor, 20, 0), b'literal')
            self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS), speech.SEALS)
            with self.assertRaises(OSError):
                os.write(descriptor, b'changed')
        finally:
            os.close(descriptor)


class SpeechTranscriptionContract(unittest.TestCase):
    def envelope(self, change=None, extra=None):
        pcm=b'\1\0'*1600
        metadata={'schema_version':1,'capture_id':'1'*32,'kind':'speech','elapsed_ms':100,
            'sample_rate':16000,'channels':1,'format':'s16le-pcm','bytes':len(pcm),
            'frames':[{'index':0,'bytes':len(pcm),'sha256':hashlib.sha256(pcm).hexdigest()}],
            'transcribed':False,'published':False,'model_submitted':False}
        if change: change(metadata)
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_STORED) as archive:
            archive.writestr('capture.json',json.dumps(metadata))
            archive.writestr('00.pcm',pcm)
            if extra: archive.writestr(extra,b'inert')
        return stream.getvalue(),pcm

    def scope(self):
        return {'action':'inference.execute','selector':{'kind':'model','id':speech.ASR_PROFILE,'generation':1,'digest':'1'*64},
                'input_bytes':960000,'output_bytes':65536,'units':128}

    def result(self, request, pcm):
        return {'schema_version':1,'request_sha256':hashlib.sha256(request).hexdigest(),'binding':'1'*64,
            'lease':{'lease_id':'2'*32,'manager_epoch':'3'*32,'generation':'9'},
            'transcript':{'schema_version':1,'profile_id':speech.ASR_PROFILE,'model_binding':'4'*64,
                'runtime_sha256':'5'*64,'audio_sha256':hashlib.sha256(pcm).hexdigest(),'audio_samples':len(pcm)//2,
                'decoder_tokens':2,'language':'en','text':'Untrusted utterance.','human_review_required':True,'automatic_model_handoff':False}}

    def test_exact_saved_audio_and_new_request(self):
        envelope,pcm=self.envelope()
        self.assertEqual(speech.capture_pcm(envelope),pcm)
        request=speech.asr_input(pcm)
        value=json.loads(request)
        self.assertEqual(value,{'schema_version':1,'profile_id':speech.ASR_PROFILE,'pcm_hex':pcm.hex()})
        self.assertTrue(request.startswith(b'{"schema_version":1,"profile_id":'))

    def test_envelope_metadata_does_not_supply_authority(self):
        for change in (lambda m:m.update(model_submitted=True),lambda m:m.update(kind='screen'),
                       lambda m:m.update(bytes=True),lambda m:m['frames'][0].update(index=False),
                       lambda m:m['frames'][0].update(sha256='6'*64)):
            envelope,_=self.envelope(change)
            with self.assertRaises(ValueError): speech.capture_pcm(envelope)
        with self.assertRaises(ValueError): speech.capture_pcm(self.envelope(extra='../run')[0])

    def test_non_audio_digital_silence_and_overlong_input_refused(self):
        for pcm in (b'\0'*3200,b'\1'*3198,b'\1'*960002,b'\1'*3201):
            with self.assertRaises(ValueError): speech.asr_input(pcm)

    def test_finite_scope_is_separate_model_infer_not_manual_or_text_selection(self):
        scope=self.scope()
        self.assertEqual(speech.transcription_scope(json.dumps(scope)),scope)
        for key,value in (('action','file.read'),('units',129),('input_bytes',3200),('output_bytes',True)):
            changed=json.loads(json.dumps(scope));changed[key]=value
            with self.assertRaises(ValueError):speech.transcription_scope(json.dumps(changed))
        changed=json.loads(json.dumps(scope));changed['selector']['id']='manual-only'
        with self.assertRaises(ValueError):speech.transcription_scope(json.dumps(changed))

    def test_exact_actual_result_provenance_and_review_only_handoff(self):
        _,pcm=self.envelope();request=speech.asr_input(pcm);value=self.result(request,pcm)
        self.assertEqual(speech.transcription_result(json.dumps(value).encode(),request,pcm,self.scope()),value['transcript'])
        for key,item in (('human_review_required',False),('automatic_model_handoff',True),('decoder_tokens',128),
                         ('audio_sha256','6'*64),('schema_version',True),('text','unsafe\x1b[31m')):
            changed=json.loads(json.dumps(value));changed['transcript'][key]=item
            with self.assertRaises(ValueError):speech.transcription_result(json.dumps(changed).encode(),request,pcm,self.scope())
        changed=json.loads(json.dumps(value));changed['lease']['generation']='09'
        with self.assertRaises(ValueError):speech.transcription_result(json.dumps(changed).encode(),request,pcm,self.scope())

    def test_explicit_selected_local_envelope_cannot_be_a_remote_uri(self):
        valid={'schema_version':1,'login':'alice','capture_path':'/home/alice/private/speech.luma-capture.zip'}
        self.assertEqual(speech.transcription_request(valid),valid)
        for path in ('https://example.invalid/audio.luma-capture.zip','relative.luma-capture.zip','/tmp/audio.wav','/tmp/a\0.luma-capture.zip'):
            with self.assertRaises(ValueError):speech.transcription_request(dict(valid,capture_path=path))

    def test_no_implicit_audio_to_model_or_os_handoff(self):
        text=SOURCE.read_text()
        self.assertIn("choice != 'c'",text)
        self.assertIn('Enter the reviewed/corrected human prompt',text)
        self.assertIn('auth.conversation_journey(handoff, directory)',text)
        self.assertIn('automatic_model_handoff',text)
        self.assertNotIn('eval(',text)


class SpeechActualChildren(unittest.TestCase):
    def fixture(self, source):
        real = subprocess.Popen
        calls = []
        def launch(arguments, **kwargs):
            calls.append(arguments)
            return real([sys.executable, '-I', '-c', source], **kwargs)
        return mock.patch.object(speech.subprocess, 'Popen', side_effect=launch), calls

    def finish(self, owner):
        deadline = time.monotonic()+3
        while time.monotonic() < deadline:
            result = owner.poll()
            if result is not None:
                return result
            time.sleep(.01)
        self.fail('actual fixture worker did not finish')

    def test_actual_pipe_complete_render(self):
        content = wave()
        fixture, calls = self.fixture('import os; os.write(1,'+repr(content)+')')
        owner = speech.OwnedSpeech()
        with fixture:
            owner.start('render', b'hello')
        self.assertIn('luma-workspace-speech-render', calls[0])
        self.assertEqual(self.finish(owner), content)
        self.assertIsNone(owner.child)
        self.assertIsNone(owner.pidfd)

    def test_actual_pipe_oversize_is_not_clipped_success(self):
        fixture, _ = self.fixture('import os; b=b"x"*65536\nfor _ in range(24):\n os.write(1,b)')
        owner = speech.OwnedSpeech()
        with fixture:
            owner.start('render', b'hello')
        with self.assertRaises(ValueError):
            self.finish(owner)
        self.assertIsNone(owner.child)
        self.assertFalse(owner.received)

    def test_actual_failed_worker_no_audio(self):
        fixture, _ = self.fixture('import os; os.write(1,b"prefix"); raise SystemExit(2)')
        owner = speech.OwnedSpeech()
        with fixture:
            owner.start('render', b'hello')
        with self.assertRaises(ValueError):
            self.finish(owner)
        self.assertIsNone(owner.child)
        self.assertFalse(owner.received)

    def test_actual_pidfd_cancellation_and_reap(self):
        fixture, _ = self.fixture('import time; time.sleep(20)')
        owner = speech.OwnedSpeech()
        with fixture:
            owner.start('play', wave())
        child, descriptor = owner.child, owner.pidfd
        owner.cancel()
        self.assertEqual(child.returncode, -signal.SIGKILL)
        self.assertIsNone(owner.child)
        self.assertIsNone(owner.pidfd)
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_expired_consent_kills_actual_worker(self):
        fixture, _ = self.fixture('import time; time.sleep(20)')
        owner = speech.OwnedSpeech()
        with fixture:
            owner.start('play', wave())
        owner.deadline = speech.clock()-1
        with self.assertRaises(ValueError):
            owner.poll()
        self.assertIsNone(owner.child)

    def test_uncertain_reap_retains_handle_and_refuses_renewal(self):
        fixture, _ = self.fixture('import time; time.sleep(20)')
        owner = speech.OwnedSpeech()
        with fixture:
            owner.start('play', wave())
        child = owner.child
        original = child.wait
        try:
            with mock.patch.object(child, 'wait', side_effect=subprocess.TimeoutExpired('fixture',2)):
                with self.assertRaises(ValueError):
                    owner.cancel()
            self.assertIs(owner.child, child)
            self.assertTrue(owner.failed)
            with self.assertRaises(ValueError):
                owner.start('play', wave())
        finally:
            original(timeout=2)
            owner.cancel()

    def test_actual_play_marker_is_exact(self):
        fixture, calls = self.fixture('import os; os.write(1,b"played\\n")')
        owner = speech.OwnedSpeech()
        with fixture:
            owner.start('play', wave())
        self.assertEqual(self.finish(owner), b'played\n')
        self.assertIn('luma-workspace-speech-play', calls[0])

    def test_actual_thread_only_seccomp(self):
        # Install the real filter in a disposable child, never in the test
        # runner. Prove fork refusal, thread support and unrelated syscall IO.
        source = ('import importlib.util,os,threading; '
            's=importlib.util.spec_from_file_location("speech",'+repr(str(SOURCE))+'); '
            'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.forbid_descendants()\n'
            'try:\n os.fork()\nexcept PermissionError:\n pass\nelse:\n os._exit(3)\n'
            'x=[];t=threading.Thread(target=lambda:x.append(1));t.start();t.join(); '
            'assert x==[1];os.write(1,b"closed\\n")')
        actual = subprocess.run([sys.executable, '-I', '-c', source], capture_output=True, timeout=5)
        self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (0, b'closed\n', b''))


if __name__ == '__main__':
    unittest.main()
