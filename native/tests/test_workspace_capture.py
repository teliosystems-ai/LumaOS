"""Real byte/file/control tests; no microphone, display or camera is opened."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
import zipfile
import zlib

MODULE = Path(__file__).resolve().parents[1]/'desktop/workspace_capture.py'
SPEC = importlib.util.spec_from_file_location('luma_capture_tests', MODULE)
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)


def chunk(kind, data):
    return struct.pack('>I', len(data))+kind+data+struct.pack('>I', zlib.crc32(kind+data) & 0xffffffff)


def image(width=2, height=2, color=2, raw=None):
    channels = 3 if color == 2 else 4
    raw = raw if raw is not None else (b'\0'+b'\x80'*(width*channels))*height
    return CAPTURE.PNG_MAGIC+chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, color, 0, 0, 0))+chunk(b'IDAT', zlib.compress(raw))+chunk(b'IEND', b'')


class CaptureTests(unittest.TestCase):
    def test_complete_png_structure_rgb_rgba_and_generated_actual_pixels(self):
        for data in (image(), image(color=6), CAPTURE.rgb_png(b'\xff\0\0\0\xff\0', 2, 1, 6)):
            self.assertEqual(CAPTURE.validate_png(data), (2, 2) if data != CAPTURE.rgb_png(b'\xff\0\0\0\xff\0', 2, 1, 6) else (2, 1))
        self.assertEqual(CAPTURE.validate_png(CAPTURE.rgb_png(b'\xff\0\0\0\xff\0'+b'xx', 2, 1, 8)), (2, 1))

    def test_png_rejects_truncation_crc_trailing_geometry_filter_bombs_animation(self):
        valid = image()
        for data in (b'', valid[:20], valid[:-1], valid+b'trailing', valid[:30]+b'!'+valid[31:],
                     image(raw=b'\0'+b'x'*100000), image(raw=b'\5xxxxxx\0xxxxxx'),
                     image(width=4097, height=1), image(color=0),
                     valid[:-12]+chunk(b'acTL', b'12345678')+valid[-12:],
                     valid[:-12]+chunk(b'abcd', b'x')+valid[-12:]):
            with self.subTest(size=len(data)), self.assertRaises((ValueError, zlib.error)):
                CAPTURE.validate_png(data)

    def test_png_refuses_critical_duplicate_and_noncontiguous_data(self):
        valid = image()
        header, encoded = valid[:33], valid[33:-12]
        for data in (header+header[8:]+encoded+valid[-12:],
                     header+chunk(b'ABCD', b'')+encoded+valid[-12:],
                     header+encoded+chunk(b'tEXt', b'a')+encoded+valid[-12:],
                     header+chunk(b'IDAT', zlib.compress(b'\0xxxxxx\0xxxxxx')+b'extra')+valid[-12:]):
            with self.assertRaises(ValueError):
                CAPTURE.validate_png(data)

    def test_rgb_encoder_rejects_wrong_bytes_stride_format_and_geometry(self):
        for arguments in ((b'x', 1, 1, 3), (b'\0'*6, 2, 1, 5),
                          (b'\0'*300, 1, 1, 300), (b'\0'*3, 0, 1, 3),
                          (bytearray(b'\0'*3), 1, 1, 3), (b'\0'*3, 1281, 1, 3)):
            with self.assertRaises(ValueError):
                CAPTURE.rgb_png(*arguments)

    def test_capture_result_closed_bounds_and_honest_metadata(self):
        capture = CAPTURE.Capture('image', (image(),), 0)
        metadata = capture.metadata()
        self.assertEqual(metadata['frames'][0]['sha256'], hashlib.sha256(image()).hexdigest())
        self.assertEqual([metadata[key] for key in ('transcribed', 'published', 'model_submitted')], [False]*3)
        for arguments in (('audio', (b'xx',), 1), ('speech', (b'x',), 1, 16000),
                          ('speech', (b'xx',), 1, 44100), ('screen', (image(), image()), 1),
                          ('video', tuple([image()]*31), 1), ('image', (image(),), True),
                          ('image', [image()], 1), ('image', (b'not png',), 1),
                          ('image', (image(),), 31001)):
            with self.assertRaises(ValueError):
                CAPTURE.Capture(*arguments)

    def test_exact_audio_byte_budget_and_finite_deadline(self):
        clock = [10.0]
        capture = CAPTURE.CaptureBuffer('speech', 1, clock=lambda: clock[0])
        capture.append(b'\0'*16000)
        clock[0] += .5
        capture.append(b'\0'*16000)
        result = capture.finish()
        self.assertEqual(result.frames, (b'\0'*32000,))
        self.assertEqual(result.elapsed_ms, 500)
        self.assertEqual(result.sample_rate, 16000)
        self.assertEqual(capture.state, 'completed')
        self.assertEqual(capture.frames, [])
        with self.assertRaises(ValueError):
            capture.append(b'\0\0')

    def test_capture_revokes_on_overflow_odd_pcm_bad_frame_or_expired_append(self):
        for kind, data, advance in (('speech', b'x', 0), ('speech', b'\0'*32002, 0),
                                    ('video', b'not a PNG', 0), ('video', image(), 2)):
            clock = [1.0]
            capture = CAPTURE.CaptureBuffer(kind, 1, clock=lambda: clock[0])
            clock[0] += advance
            with self.assertRaises(ValueError):
                capture.append(data)
            self.assertEqual(capture.state, 'revoked')
            self.assertEqual(capture.frames, [])

    def test_video_samples_at_most_once_per_second_and_respects_scope(self):
        clock = [10.0]
        capture = CAPTURE.CaptureBuffer('video', 2, clock=lambda: clock[0])
        self.assertTrue(capture.append(image()))
        clock[0] += .1
        self.assertFalse(capture.append(image()))
        clock[0] += 1
        self.assertTrue(capture.append(image(color=6)))
        result = capture.finish()
        self.assertEqual(result.frames, (image(), image(color=6)))
        with self.assertRaises(ValueError):
            capture.finish()

    def test_drain_grace_is_not_capture_permission_and_cannot_renew(self):
        clock = [10.0]
        capture = CAPTURE.CaptureBuffer('speech', 1, clock=lambda: clock[0])
        capture.append(b'\0\0')
        clock[0] = 11.1
        self.assertFalse(capture.active())
        capture.append(b'\0\0', drain=True)
        self.assertEqual(len(capture.finish().frames[0]), 4)
        capture = CAPTURE.CaptureBuffer('speech', 1, clock=lambda: clock[0])
        capture.append(b'\0\0')
        clock[0] += 2.1
        with self.assertRaises(ValueError):
            capture.finish()
        self.assertEqual(capture.state, 'revoked')

    def test_invalid_scope_and_clock_rollback_are_refused(self):
        for arguments in (('speech', 0), ('speech', True), ('speech', 31), ('camera', 1), ('video', '1')):
            with self.assertRaises(ValueError):
                CAPTURE.CaptureBuffer(*arguments)
        clock = [10.0]
        capture = CAPTURE.CaptureBuffer('speech', 1, clock=lambda: clock[0])
        clock[0] = 9.0
        self.assertFalse(capture.active())
        with self.assertRaises(ValueError):
            capture.append(b'\0\0', drain=True)

    def test_explicit_revocation_discards_partial_bytes_and_no_result(self):
        capture = CAPTURE.CaptureBuffer('video', 10)
        capture.append(image())
        capture.revoke()
        self.assertEqual((capture.bytes, capture.frames, capture.state), (0, [], 'revoked'))
        with self.assertRaises(ValueError):
            capture.finish()

    def test_screenshot_uri_never_opens_network_or_ambiguous_paths(self):
        self.assertEqual(CAPTURE.screenshot_path('file:///tmp/input%20one.png'), Path('/tmp/input one.png'))
        for uri in ('https://example.test/image.png', 'file://host/tmp/x.png',
                    'file:///tmp/x.png?download=1', 'file:///tmp/x.png#x', 'file:///tmp/%00x',
                    'file:///tmp/%xx', 'file:relative.png', '', None):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                CAPTURE.screenshot_path(uri)

    def test_exact_capture_grounding_requires_identity_index_and_digest(self):
        first = CAPTURE.Capture('image', (image(),), 0)
        second = CAPTURE.Capture('image', (image(),), 0)
        self.assertNotEqual(first.capture_id, second.capture_id)
        selector = dict(capture_id=first.capture_id, index=0, sha256=hashlib.sha256(image()).hexdigest())
        self.assertEqual(CAPTURE.grounded_sample((first, second), selector), image())
        for value in (None, {}, dict(selector, index=True), dict(selector, index=1),
                      dict(selector, capture_id='0'*32), dict(selector, sha256='0'*64), dict(selector, permission=True)):
            with self.assertRaises(ValueError):
                CAPTURE.grounded_sample((first, second), value)
        with self.assertRaises(ValueError):
            CAPTURE.grounded_sample((first, first), selector)

    def test_private_local_input_and_exclusive_envelope_save_readback(self):
        with tempfile.TemporaryDirectory(prefix='luma-capture-', dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            source = root/'input.png'
            source.write_bytes(image())
            self.assertEqual(CAPTURE.private_file(source), image())
            result = CAPTURE.Capture('image', (image(),), 0)
            output = root/'new.luma-capture.zip'
            metadata = CAPTURE.save_new(result, output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with zipfile.ZipFile(output) as envelope:
                self.assertEqual(envelope.namelist(), ['capture.json', '00.png'])
                self.assertEqual(envelope.read('00.png'), image())
                self.assertEqual(json.loads(envelope.read('capture.json')), metadata)
                self.assertEqual(envelope.testzip(), None)
            before = output.read_bytes()
            with self.assertRaises(FileExistsError):
                CAPTURE.save_new(result, output)
            self.assertEqual(output.read_bytes(), before)

    def test_local_input_and_output_refuse_links_oversize_and_shared_directory(self):
        with tempfile.TemporaryDirectory(prefix='luma-capture-', dir=os.environ.get('LUMA_STORAGE_TEST_ROOT')) as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            source = root/'input.png'; source.write_bytes(image())
            link = root/'link.png'; link.symlink_to(source)
            hard = root/'hard.png'; os.link(source, hard)
            for path, maximum in ((link, CAPTURE.MAX_IMAGE), (source, CAPTURE.MAX_IMAGE), (hard, CAPTURE.MAX_IMAGE), (source, 1)):
                with self.assertRaises((ValueError, OSError)):
                    CAPTURE.private_file(path, maximum)
            hard.unlink()
            child = root/'child'; child.mkdir(mode=0o700)
            alias = root/'alias'; alias.symlink_to(child, target_is_directory=True)
            (child/'x').write_bytes(image())
            with self.assertRaises((ValueError, OSError)):
                CAPTURE.private_file(alias/'x')
            result = CAPTURE.Capture('image', (image(),), 0)
            for path in (root/'wrong.zip', alias/'new.luma-capture.zip'):
                with self.assertRaises((ValueError, OSError)):
                    CAPTURE.save_new(result, path)
            os.chmod(root, 0o777)
            with self.assertRaises(ValueError):
                CAPTURE.save_new(result, root/'new.luma-capture.zip')

    def test_worker_protocol_does_not_accept_uri_pipeline_or_test_source_selection(self):
        for arguments in (('camera', 1, 1), ('video', 1, 1), ('speech', True, 1),
                          ('speech', 1, 1), ('speech', 1, 2**100),
                          ('speech', 1, __import__('time').monotonic_ns()+500000000, 9, '1')):
            with self.assertRaises(ValueError):
                CAPTURE.capture_worker(*arguments)


if __name__ == '__main__':
    unittest.main()
