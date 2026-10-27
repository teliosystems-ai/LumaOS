"""Pinned public acquisition mechanics; no model execution or qualification."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('speech_input_tests', ROOT/'image/prepare_speech.py')
speech = importlib.util.module_from_spec(spec)
spec.loader.exec_module(speech)


class SpeechInputTests(unittest.TestCase):
    def test_delivery_is_exact_exclusive_and_does_not_execute_anything(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)/'input'
            content = b'exact public source; never executed\n'
            speech.deliver(io.BytesIO(content), target, len(content), hashlib.sha256(content).hexdigest())
            self.assertEqual(target.read_bytes(), content)
            with self.assertRaises(FileExistsError):
                speech.deliver(io.BytesIO(b'overwrite'), target, 9, '0'*64)
            self.assertEqual(target.read_bytes(), content)

    def test_oversize_truncated_or_wrong_hash_retains_only_failed_inert_input(self):
        for content, size, digest in [(b'oversize', 2, '0'*64), (b'', 2, '0'*64), (b'ab', 2, '0'*64)]:
            with tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary)/'failed'
                with self.assertRaises(ValueError): speech.deliver(io.BytesIO(content), target, size, digest)
                self.assertTrue(target.is_file())
                self.assertLessEqual(target.stat().st_size, size)

    def test_existing_context_subtree_and_redirected_cache_are_not_adopted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'speech').mkdir()
            marker = root/'speech'/'preserve'
            marker.write_bytes(b'original')
            with self.assertRaises(FileExistsError): speech.prepare(root)
            self.assertEqual(marker.read_bytes(), b'original')
            source = root/'source'
            source.write_bytes(b'original')
            alias = root/'alias'
            alias.symlink_to(source)
            with self.assertRaises(ValueError): speech.local(alias)
            link = root/'hardlink'
            os.link(source, link)
            with self.assertRaises(ValueError): speech.local(source)

    def test_https_downgrade_refused_and_all_recipe_hashes_pinned(self):
        request = urllib.request.Request('https://example.com/source')
        with self.assertRaises(ValueError):
            speech.HTTPSRedirect().redirect_request(request, None, 302, 'Found', {}, 'http://example.com/source')
        self.assertEqual(set(speech.recipe.INPUTS), {'whisper-source.tar.gz', 'model-LICENSE',
            'espeak-ng_1.51+dfsg-12build1.dsc', 'espeak-ng_1.51+dfsg.orig.tar.gz', 'espeak-ng_1.51+dfsg-12build1.debian.tar.xz'})
        docker = (ROOT/'image/Dockerfile.root').read_text()
        for _name, (_size, digest) in speech.recipe.INPUTS.items(): self.assertIn(digest, docker)
        self.assertIn(speech.recipe.layout.MODEL_SHA256, docker)
        self.assertTrue(all(url.startswith('https://') for url in speech.URLS.values()))
        self.assertIn('prepare_speech.py', (ROOT/'image/build.sh').read_text())
        self.assertIn('speech_package.package(ROOT, WORK)', (ROOT/'image/assemble.py').read_text())
        for name in ('usr/share/doc/luma-os/speech.md', 'usr/share/doc/luma-os/hardware-policy.md'):
            self.assertIn(name, (ROOT/'image/assemble.py').read_text())

    def test_root_speech_layer_installs_the_default_generator_build_program(self):
        # Sequence-17 assembly 20261026T150426Z failed here: cmake only
        # recommends make, and the root installs without recommends.
        recipe = (ROOT/'image/Dockerfile.root').read_text()
        runs = [line for line in recipe.replace('\\\n', ' ').splitlines() if line.startswith('RUN ')]
        layer = next(line for line in runs if 'libespeak-ng-dev=' in line).split()
        self.assertIn('--no-install-recommends', layer)
        packages = layer[layer.index('--snapshot=${SNAPSHOT}')+1:]
        policy_spec = importlib.util.spec_from_file_location('speech_policy_tests', ROOT/'image/speech_policy.py')
        policy = importlib.util.module_from_spec(policy_spec)
        policy_spec.loader.exec_module(policy)
        self.assertEqual(sorted(packages), sorted(policy.PACKAGES))
        configure, build, render = speech.recipe.build_commands()
        self.assertFalse(any(argument.startswith('-G') for argument in configure))
        self.assertEqual(build[:2], ['/usr/bin/cmake', '--build'])
        self.assertEqual(render[0], '/usr/bin/cc')
        for package in ('g++', 'cmake', 'make'):
            self.assertIn(package, packages)


if __name__ == '__main__': unittest.main()
