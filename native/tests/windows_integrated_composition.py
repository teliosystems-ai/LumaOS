"""Actual compiled-worker/PAM/Qwen combined-package regression, no activation.

All real inputs are mandatory. This script has no substitute worker, fake
weight, skipped test path, service import or model execution. Run in the
isolated Ubuntu24.04 tools builder with a fresh D-backed output name.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('luma_integrated_composition', ROOT/'native/image/windows_integrated.py')
integrated = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(integrated)


def digest_file(path, expected):
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected) or expected == '0'*64:
        raise ValueError('independently retained nonzero source artifact digest required')
    tree = integrated.package.Tree(Path(path).absolute().parent)
    try:
        raw = tree.read(Path(path).name, integrated.package.MAX_ELF)
    finally:
        tree.close()
    integrated.package.elf(raw, require_entry=True)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('actual compiled input differs from retained artifact digest')
    return raw


def verify(arguments):
    check = unittest.TestCase()
    worker = digest_file(arguments.platform, arguments.platform_sha256)
    helper = digest_file(arguments.auth_helper, arguments.auth_helper_sha256)
    result = integrated.compose(arguments.source_root, arguments.platform, arguments.auth_helper,
        arguments.runtime, arguments.model, arguments.work_root, arguments.output_name, arguments.release_id)
    stage = arguments.work_root/result['stage_directory']
    packaged = arguments.work_root/result['package_directory']
    manifest = json.loads((packaged/'manifest.json').read_bytes())
    required = {item['path']: item for item in manifest['required_files']}
    check.assertLessEqual(len(required), 128)
    with tarfile.open(packaged/'rootfs.tar', 'r:') as archive:
        def read(name, maximum=32768):
            member = archive.getmember(name)
            check.assertTrue(member.isfile())
            check.assertLessEqual(member.size, maximum)
            with archive.extractfile(member) as stream:
                raw = stream.read(maximum+1)
            check.assertEqual(len(raw), member.size)
            return raw
        identity = json.loads(read('usr/lib/luma/platform.json'))
        check.assertEqual(identity, dict(schema_version=3, release_id=arguments.release_id,
            architecture='amd64', profile='W', runtime_profile=integrated.workspace.PROFILE))
        check.assertEqual(read('etc/wsl.conf'), integrated.package.WSL+b'[user]\ndefault=nobody\n')
        for name, (raw, mode) in integrated.workspace.BASELINES.items():
            check.assertEqual(read('etc/'+name), raw)
            check.assertEqual(archive.getmember('etc/'+name).mode, mode)
        check.assertEqual(read(integrated.workspace.AUTH_HELPER, integrated.package.MAX_ELF), helper)
        check.assertEqual(read('usr/bin/luma-platform', integrated.package.MAX_ELF), worker)
        check.assertEqual(read('usr/libexec/luma-os/luma-platform', integrated.package.MAX_ELF), worker)
        descriptors = {}
        for module in (integrated.workspace, integrated.inference):
            runtime_raw = read(module.MANIFEST_PATH)
            runtime = json.loads(runtime_raw)
            by_name = {item['path']: item for item in runtime['files']}
            check.assertEqual(by_name['usr/libexec/luma-os/luma-platform']['sha256'], arguments.platform_sha256)
            check.assertTrue(set(by_name) <= set(required))
            # Every actual worker dependency must belong to BOTH runtime
            # manifests, not only to generic package RequiredFiles.
            queue, visited = ['usr/libexec/luma-os/luma-platform'], set()
            while queue:
                name = queue.pop()
                if name in visited:
                    continue
                visited.add(name)
                value = read(name, integrated.package.MAX_ELF)
                interpreter, needed, search = integrated.package.elf(value, object_path=name, details=True,
                    private_dirs=integrated.inference.PRIVATE_DIRS)
                folders = tuple(dict.fromkeys((*(search['runpath'] or search['rpath']),
                    *integrated.inference.PRIVATE_DIRS, *integrated.package.LIB_DIRS)))
                dependencies = [interpreter[1:]] if interpreter else []
                for soname in needed:
                    candidates = [folder+'/'+soname for folder in folders if folder+'/'+soname in by_name]
                    check.assertTrue(candidates, 'runtime manifest omitted worker dependency '+soname)
                    dependencies.append(candidates[0])
                for dependency in dependencies:
                    check.assertIn(dependency, by_name)
                    queue.append(dependency)
            check.assertTrue(any(name.endswith('/libsystemd.so.0') for name in visited),
                             'actual new hardware-linked platform must include libsystemd.so.0')
            descriptors[module.PROFILE] = dict(runtime_manifest_sha256=hashlib.sha256(runtime_raw).hexdigest(),
                runtime_files=len(by_name), worker_dependency_members=len(visited))
        check.assertEqual(required[integrated.inference.MODEL]['sha256'], integrated.inference.MODEL_SHA)
        check.assertEqual(required[integrated.inference.MODEL]['bytes'], integrated.inference.MODEL_BYTES)
        check.assertIn(integrated.inference.PROFILE_PATH, required)
        check.assertIn(integrated.workspace.PROFILE_PATH, required)
        check.assertFalse(any(name.startswith('home/') for name in archive.getnames()))
    # A repeated invocation must refuse before composition; it cannot append to
    # the previous root or replace its immutable unsigned package.
    with check.assertRaisesRegex(ValueError, 'destination already exists'):
        integrated.compose(arguments.source_root, arguments.platform, arguments.auth_helper,
            arguments.runtime, arguments.model, arguments.work_root, arguments.output_name, arguments.release_id)
    report = dict(schema_version=1, status='actual-combined-workspace-inference-composition-verified',
        platform_sha256=arguments.platform_sha256, auth_helper_sha256=arguments.auth_helper_sha256,
        runtime_archive_sha256=integrated.inference.ARCHIVE_SHA, model_sha256=integrated.inference.MODEL_SHA,
        model_bytes=integrated.inference.MODEL_BYTES, descriptors=descriptors,
        package=result['package'], initial_accounts_locked=True, default_uid=65534, wsl_flags=0,
        source_elfs_executed=False, package_authenticated=False, distribution_imported=False,
        pam_authenticated=False, account_created=False, inference_executed=False,
        host_settings_changed=False, native_qualified=False, production_qualified=False, gate_closing=False)
    tree = integrated.package.Tree(stage)
    try:
        integrated.inference.write_new(tree, 'integrated-verification.json', integrated.package.canonical(report), 0o600)
    finally:
        tree.close()
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'platform', 'auth-helper', 'runtime', 'model', 'work-root'):
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ('output-name', 'release-id', 'platform-sha256', 'auth-helper-sha256'):
        parser.add_argument('--'+name, required=True)
    print(integrated.package.canonical(verify(parser.parse_args())).decode(), end='')
