"""Bounded profile-W inference packaging contracts; no production qualification.

Negative manifest fixtures contain an ordinary real Linux ELF, not an approved
llama runtime or authenticated model. No fake model is accepted as the pinned
2.5-GB weight file. The optional explicit runtime-archive lane inspects the real
pinned 17-MB archive without executing supplied code or importing a distro.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('luma_windows_inference_test', ROOT/'native/image/windows_inference.py')
inference = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inference)
package = inference.package


def temporary():
    return tempfile.TemporaryDirectory(prefix='luma-inference-test-', dir=os.environ.get('LUMA_STORAGE_TEST_ROOT'))


class NoModelAccess:
    def opened(self, *_args, **_kwargs):
        raise AssertionError('invalid profile/runtime must refuse before reading any model')


def negative_manifest_fixture(include_worker=True, extra=None):
    """Actual ELF bytes only for negative pre-model parser paths, not runtime QA."""
    elf = Path('/usr/bin/true').read_bytes()
    values = {inference.PRIVATE+'/'+name: elf for name in inference.RUNTIME_NAMES}
    if include_worker:
        values['usr/libexec/luma-os/luma-platform'] = elf
    if extra is not None:
        values[extra] = elf
    files = [dict(path=name, bytes=len(value), sha256=hashlib.sha256(value).hexdigest(),
        executable=name.endswith('/llama-completion') or name.endswith('/luma-platform'))
        for name, value in sorted(values.items())]
    manifest = package.canonical(dict(schema_version=1, profile=inference.PROFILE, files=files))
    values.update({inference.MANIFEST_PATH: manifest,
        inference.PROFILE_PATH: package.canonical(inference.profile(hashlib.sha256(manifest).hexdigest()))})
    entries = {name: (False, 0o755 if name.endswith(('/llama-completion', '/luma-platform')) else 0o644, len(value))
        for name, value in values.items()}
    entries[inference.MODEL] = (False, 0o644, inference.MODEL_BYTES)
    return values, entries


class WindowsInferenceTests(unittest.TestCase):
    def test_held_dependency_capture_preserves_loader_execute_mode_and_refuses_unsafe_modes(self):
        with temporary() as directory:
            root = Path(directory)
            target = root/'loader'
            actual = Path('/usr/bin/true').read_bytes()
            target.write_bytes(actual)
            target.chmod(0o755)
            tree = package.Tree(root)
            try:
                self.assertEqual(inference.source_elf(tree, 'loader'), (actual, 0o755))
                target.chmod(0o644)
                self.assertEqual(inference.source_elf(tree, 'loader'), (actual, 0o644))
                for mode in (0o777, 0o4755, 0o1755):
                    target.chmod(mode)
                    with self.subTest(mode=mode), self.assertRaises(ValueError):
                        inference.source_elf(tree, 'loader')
                target.chmod(0o755)
                target.write_bytes(b'not a bounded ELF')
                with self.assertRaises(ValueError):
                    inference.source_elf(tree, 'loader')
            finally:
                tree.close()

    def test_exact_cpu_lab_profile_is_separate_fixed_and_lossless(self):
        value = inference.profile('a'*64)
        self.assertEqual(value, dict(schema_version=1, profile='luma-windows-hosted-inference-v1',
            environment='lab', runtime='llama.cpp-b11100-cpu-amd64-completion',
            model_path='usr/share/luma-os/models/qwen3-4b-q4-k-m.gguf', model_bytes=2497280256,
            model_sha256='7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5',
            runtime_manifest_sha256='a'*64, context_tokens=2048, maximum_output_tokens=512,
            memory_max_bytes=4831838208, memory_swap_max_bytes=0, tasks_max=16,
            cpu_quota_usec=200000, cpu_period_usec=100000, runtime_cpu_seconds=300, threads=2))
        self.assertEqual(package.MAX_FILE, 512*1024**2)
        self.assertEqual(package.MAX_ELF, 64*1024**2)
        self.assertGreater(value['model_bytes'], package.MAX_FILE)
        for bad in (None, True, '', '0'*64, 'A'*64, 'a'*63, 'a'*65, 'x'*64):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                inference.profile(bad)

    def test_manifest_json_is_closed_and_finite(self):
        self.assertEqual(inference.closed(b'{"exact":1}'), {'exact': 1})
        for bad in (b'{"schema_version":1,"schema_version":2}', b'{"x":NaN}',
                    b'{"x":Infinity}', b'{"x":-Infinity}', b'{"x":}', b'\xff'):
            with self.subTest(bad=bad), self.assertRaises((ValueError, UnicodeError)):
                inference.closed(bad)

    def test_profile_canonical_bytes_refuse_boolean_and_integral_float_aliases(self):
        manifest = package.canonical(dict(schema_version=1, profile=inference.PROFILE, files=[]))
        expected = inference.profile(hashlib.sha256(manifest).hexdigest())
        values = {inference.MANIFEST_PATH: manifest}
        for field, bad in [('schema_version', True), ('schema_version', 1.0),
            ('model_bytes', float(inference.MODEL_BYTES)), ('memory_max_bytes', 4831838208.0),
            ('memory_swap_max_bytes', False), ('context_tokens', 2048.0),
            ('runtime_cpu_seconds', 300.0), ('maximum_output_tokens', 512.0)]:
            description = dict(expected, **{field: bad})
            values[inference.PROFILE_PATH] = package.canonical(description)
            with self.subTest(field=field, bad=bad), self.assertRaisesRegex(ValueError, 'exact approved closed CPU profile'):
                inference.validate(values.__getitem__, {}, NoModelAccess())
        values[inference.PROFILE_PATH] = b' '+package.canonical(expected)
        with self.assertRaisesRegex(ValueError, 'exact approved closed CPU profile'):
            inference.validate(values.__getitem__, {}, NoModelAccess())
        values[inference.PROFILE_PATH] = package.canonical(expected)
        with self.assertRaisesRegex(ValueError, 'runtime manifest'):
            inference.validate(values.__getitem__, {}, NoModelAccess())

    def test_private_origin_is_versioned_opt_in_not_a_global_loader_relaxation(self):
        object_path = inference.PRIVATE+'/llama-completion'
        for path in ('$ORIGIN', '${ORIGIN}', '/'+inference.PRIVATE):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    package.runtime_search_paths(path, object_path)
                self.assertEqual(package.runtime_search_paths(path, object_path, inference.PRIVATE_DIRS), (inference.PRIVATE,))
        for paths in (('tmp/llama',), (inference.PRIVATE, 'tmp/llama'), [inference.PRIVATE],
                      ('usr/libexec/luma-os/hosted-llama2',)):
            with self.assertRaises(ValueError):
                package.runtime_search_paths('$ORIGIN', object_path, paths)
        for path in ('.', '', '$ORIGIN:', ':$ORIGIN', '$ORIGIN:$ORIGIN', '$HOME',
                     '$ORIGIN/../../../../../../tmp', '$ORIGIN/./', '$ORIGIN//',
                     '$ORIGIN/nonexistent/..', '/tmp',
                     '$ORIGIN/$PLATFORM', '$ORIGIN/lib64', '$ORIGIN/..'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                package.runtime_search_paths(path, object_path, inference.PRIVATE_DIRS)
        self.assertEqual(package.runtime_search_paths('/lib/x86_64-linux-gnu', 'usr/bin/program'),
                         ('lib/x86_64-linux-gnu',))

    def test_runtime_archive_refuses_unpinned_unbounded_or_nonbyte_inputs_before_unpack(self):
        for bad in (b'', b'not the pinned archive', bytearray(b'data'), 'archive', None):
            with patch.object(inference.tarfile, 'open') as unpack:
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    inference.runtime_archive(bad)
                unpack.assert_not_called()
        self.assertEqual(len(inference.RUNTIME_NAMES), 18)
        self.assertEqual(len(set(inference.RUNTIME_NAMES)), 18)
        self.assertIn('libggml-cpu-x64.so', inference.RUNTIME_NAMES)
        self.assertIn('libllama-completion-impl.so', inference.RUNTIME_NAMES)
        self.assertNotIn('libllama-server-impl.so', inference.RUNTIME_NAMES)
        self.assertNotIn('llama-cli', inference.RUNTIME_NAMES)
        self.assertNotIn('llama-server', inference.RUNTIME_NAMES)
        self.assertFalse(any('rpc' in value or 'cuda' in value or 'vulkan' in value for value in inference.RUNTIME_NAMES))

    def test_runtime_manifest_missing_worker_refuses_before_model(self):
        values, entries = negative_manifest_fixture(include_worker=False)
        with self.assertRaisesRegex(ValueError, 'worker|incomplete'):
            inference.validate(values.__getitem__, entries, NoModelAccess())

    def test_runtime_manifest_rejects_namespace_outside_native_worker_library_closure(self):
        for name in ('usr/bin/unapproved-model-tool', 'etc/unapproved.so',
                     inference.PRIVATE+'/libggml-rpc.so'):
            values, entries = negative_manifest_fixture(extra=name)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'namespace|unapproved|private runtime'):
                inference.validate(values.__getitem__, entries, NoModelAccess())

    def test_runtime_manifest_refuses_reordered_duplicate_inexact_or_wrong_mode_members(self):
        original, original_entries = negative_manifest_fixture()
        manifest = inference.closed(original[inference.MANIFEST_PATH])
        for mutate in (lambda v: v['files'].reverse(), lambda v: v['files'].append(v['files'][-1]),
            lambda v: v['files'][0].update(bytes=True), lambda v: v['files'][0].update(executable=1),
            lambda v: v['files'][0].update(sha256='0'*64), lambda v: v['files'][0].update(bytes=-1),
            lambda v: v['files'][0].update(extra='unexpected'), lambda v: v.update(schema_version=True)):
            description = copy.deepcopy(manifest); mutate(description)
            raw = package.canonical(description)
            values = dict(original, **{inference.MANIFEST_PATH: raw,
                inference.PROFILE_PATH: package.canonical(inference.profile(hashlib.sha256(raw).hexdigest()))})
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                inference.validate(values.__getitem__, original_entries, NoModelAccess())
        entries = dict(original_entries)
        entries[inference.PRIVATE+'/llama-completion'] = (False, 0o644, len(original[inference.PRIVATE+'/llama-completion']))
        with self.assertRaisesRegex(ValueError, 'executable mode'):
            inference.validate(original.__getitem__, entries, NoModelAccess())

    def test_real_private_streaming_sink_is_exclusive_bounded_and_preserves_prefix_on_failure(self):
        # 3 MiB + 17 bytes, written in fixed 64-KiB blocks; never a model fixture.
        with temporary() as temporary_root:
            tree = package.Tree(temporary_root)
            try:
                block = b'inert-stream-fixture\0'.ljust(65536, b'x')
                expected = hashlib.sha256()
                def stream(output):
                    for _ in range(48):
                        output.write(block); expected.update(block)
                    output.write(block[:17]); expected.update(block[:17])
                name = 'usr/share/luma-os/inert-stream.data'
                inference.write_new(tree, name, stream, 0o644)
                path = Path(temporary_root)/name
                self.assertEqual(path.stat().st_size, 3*1024**2+17)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
                with path.open('rb') as output:
                    self.assertEqual(hashlib.file_digest(output, 'sha256').hexdigest(), expected.hexdigest())
                with self.assertRaises(FileExistsError):
                    inference.write_new(tree, name, b'overwritten', 0o644)
                def fail(output):
                    output.write(b'private-inert-prefix')
                    raise ValueError('bounded deliberate fixture failure')
                partial = 'usr/share/luma-os/inert-partial.data'
                with self.assertRaises(ValueError):
                    inference.write_new(tree, partial, fail, 0o644)
                self.assertEqual((Path(temporary_root)/partial).read_bytes(), b'private-inert-prefix')
            finally:
                tree.close()

    def test_streaming_sink_refuses_alias_ancestors_and_unprotected_directories(self):
        with temporary() as temporary_root:
            root = Path(temporary_root)
            (root/'real').mkdir()
            (root/'alias').symlink_to('real', target_is_directory=True)
            (root/'shared').mkdir(mode=0o777); (root/'shared').chmod(0o777)
            tree = package.Tree(root)
            try:
                for name in ('alias/never.data', 'shared/never.data', '../escape', '/absolute', 'bad\\name'):
                    with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                        inference.write_new(tree, name, b'not written', 0o644)
                self.assertFalse((root/'real/never.data').exists())
                self.assertFalse((root/'shared/never.data').exists())
            finally:
                tree.close()

    def test_fresh_runtime_directories_remain_guest_traversable_under_private_build_umask(self):
        with temporary() as temporary_root:
            tree = package.Tree(temporary_root)
            previous = os.umask(0o077)
            try:
                name = 'fresh/hosted-llama/inert.runtime'
                inference.write_new(tree, name, b'inert data, not executable code', 0o644)
                for part in ('fresh', 'fresh/hosted-llama'):
                    self.assertEqual(stat.S_IMODE((Path(temporary_root)/part).stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE((Path(temporary_root)/name).stat().st_mode), 0o644)
            finally:
                os.umask(previous)
                tree.close()

    def test_compose_does_not_grant_root_via_a_nonroot_call(self):
        with patch.object(inference.os, 'geteuid', return_value=1000), patch.object(package, 'Tree') as tree:
            with self.assertRaisesRegex(ValueError, 'root-owned Linux build'):
                inference.compose('/unused/root', '/unused/source', '/unused/model', '/unused/runtime')
            tree.assert_not_called()

    def test_compose_refuses_broad_host_or_unprotected_staging_roots_without_writes(self):
        for target in ('/', '/mnt/c', '/mnt/c/Users/hakim/LumaOS'):
            with patch.object(package, 'Tree') as tree:
                with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'narrow external Linux staging root'):
                    inference.compose(target, '/unused/source', '/unused/model', '/unused/runtime')
                tree.assert_not_called()
        with temporary() as temporary_root:
            root = Path(temporary_root)
            for directory in ('stage', 'source', 'inputs'):
                (root/directory).mkdir()
            (root/'stage').chmod(0o777)
            with patch.object(inference, 'runtime_archive') as archive:
                with self.assertRaisesRegex(ValueError, 'staging root must be root-owned and protected'):
                    inference.compose(root/'stage', root/'source', root/'inputs/model', root/'inputs/runtime')
                archive.assert_not_called()
            self.assertEqual(list((root/'stage').iterdir()), [])

    def test_enforcing_profile_allows_closed_inventory_read_but_denies_host_secrets_and_network(self):
        source = (ROOT/'native/image/overlay/etc/apparmor.d/luma-hosted-inference').read_text(encoding='utf-8')
        self.assertIn('/usr/libexec/luma-os/hosted-llama/ r,', source)
        self.assertIn('/usr/libexec/luma-os/hosted-llama/llama-completion mrix,', source)
        self.assertIn('deny network,', source)
        self.assertIn('deny /mnt/** rwklmx,', source)
        self.assertIn('deny /var/lib/luma-os/** rwklmx,', source)
        self.assertNotIn('complain', source)
        self.assertNotIn('/usr/bin/** ix,', source)

    def test_existing_compute_and_plain_package_defaults_do_not_enable_inference(self):
        import inspect
        signature = inspect.signature(package.build)
        self.assertIs(signature.parameters['hosted_inference'].default, False)
        self.assertIs(signature.parameters['hosted_compute'].default, False)
        with self.assertRaisesRegex(ValueError, 'distinct hosted runtime profile'):
            package.build('/unused', '/unused', '/unused', '/unused', 'not-evaluated',
                          hosted_compute=True, hosted_inference=True)


def archive_lane(path):
    """Real pinned-archive-only diagnostics, with no runtime execution/model QA."""
    path = Path(path)
    with path.open('rb') as source:
        raw = source.read(32*1024**2+1)
    members = inference.runtime_archive(raw)
    assert set(members) == {inference.PRIVATE+'/'+name for name in inference.RUNTIME_NAMES}
    for stem, version in [('libllama', '0.4.1'), ('libllama-common', '0.4.1'), ('libmtmd', '0.4.1'),
                          ('libggml', '0.24.0'), ('libggml-base', '0.24.0')]:
        hashes = {hashlib.sha256(members[inference.PRIVATE+'/'+stem+'.so'+suffix][0]).hexdigest()
                  for suffix in ('', '.0', '.'+version)}
        assert len(hashes) == 1, stem
    descriptions = []
    for name, (data, mode) in sorted(members.items()):
        interpreter, needed, search = package.elf(data, object_path=name, details=True,
            require_entry=name.endswith('/llama-completion'), private_dirs=inference.PRIVATE_DIRS)
        descriptions.append(dict(path=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
            mode=mode, interpreter=interpreter, needed=needed, search=search))
    print(json.dumps(dict(schema_version=1, archive_sha256=hashlib.sha256(raw).hexdigest(),
        runtime_members=descriptions, supplied_code_executed=False, model_read=False,
        inference_executed=False, package_authenticated=False, production_qualified=False),
        sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--runtime-archive', type=Path)
    arguments, remaining = parser.parse_known_args()
    if arguments.runtime_archive is not None:
        archive_lane(arguments.runtime_archive)
    else:
        unittest.main(argv=[sys.argv[0], *remaining])
