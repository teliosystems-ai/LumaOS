"""Build-storage admission oracles; no mounting or Docker mutations."""
import json
import io
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
import build_storage as storage


class BuildStorageTests(unittest.TestCase):
    def memory_info(self, available, total=8*1024**3):
        self.assertEqual(available % 1024, 0)
        return f'MemTotal:       {total//1024} kB\nMemAvailable:   {available//1024} kB\nSwapTotal:     999999999 kB\nSwapFree:      999999999 kB\n'

    def test_assembly_memory_selection_is_closed_with_absent_only_default(self):
        self.assertEqual(storage.selected_assembly_memory_gib({}), 4)
        for value in ('4', '5', '8'):
            self.assertEqual(storage.selected_assembly_memory_gib({'LUMA_NATIVE_ASSEMBLY_MEMORY_GIB': value}), int(value))
        for value in ('', ' 5', '5 ', '5\n', '4.0', '4.5', '05', '6', '7', '9', '08', '8 ', '8.0', '16',
                      '0', '-1', '+5', '5g', '5GiB', '8g', True, 5, 8, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                storage.selected_assembly_memory_gib({'LUMA_NATIVE_ASSEMBLY_MEMORY_GIB': value})

    def test_assembly_memory_exact_physical_boundary_and_reserve_ignore_swap(self):
        total = 12*storage.GIB
        for selected in (4, 5, 8):
            required = (selected+1)*storage.GIB
            observed = storage.check_assembly_memory(selected, self.memory_info(required, total))
            self.assertEqual(observed, dict(assembly_memory_gib=selected,
                assembly_memory_bytes=selected*storage.GIB, host_total_bytes=total,
                host_available_bytes=required, build_host_reserve_bytes=storage.GIB,
                swap_counted_as_capacity=False, reservation=False))
            with self.assertRaisesRegex(RuntimeError, 'swap is not capacity'):
                storage.check_assembly_memory(selected, self.memory_info(required-1024, total))
            with self.assertRaises(RuntimeError):
                storage.check_assembly_memory(selected, self.memory_info(0, total))
        # An 8 GiB bound on the former ~8 GiB WSL host is refused, never admitted on swap.
        with self.assertRaisesRegex(RuntimeError, 'swap is not capacity'):
            storage.check_assembly_memory(8, self.memory_info(8*storage.GIB))
        for selected in (True, '5', '8', 4.0, 8.0, 3, 6, 7, 9, None):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                storage.check_assembly_memory(selected, self.memory_info(6*storage.GIB))

    def test_assembly_memory_observation_rejects_duplicate_malformed_or_inconsistent_fields(self):
        valid = self.memory_info(6*storage.GIB)
        bad = ['', 'MemTotal: 8388608 kB\n', 'MemAvailable: 6291456 kB\n',
            valid+'MemTotal: 8388608 kB\n', valid+'MemAvailable: 6291456 kB\n',
            valid.replace('MemAvailable:', ' MemAvailable:'), valid.replace('MemTotal:', 'MemTotal'),
            valid.replace('6291456 kB', '6291456 MB'), valid.replace('6291456 kB', '-1 kB'),
            valid.replace('6291456 kB', '6.0 kB'), valid.replace('8388608 kB', '0 kB'),
            valid.replace('6291456 kB', '999999999 kB'),
            valid.replace('6291456 kB', '18446744073709551616 kB'),
            valid.replace('6291456 kB', '9'*100+' kB'), valid+'x'*65537, valid+'\N{SNOWMAN}', None, valid.encode()]
        for text in bad:
            with self.subTest(text=repr(text)[:120]), self.assertRaises(ValueError):
                storage.check_assembly_memory(5, text)

    def test_assembly_admission_reads_only_bounded_actual_proc_source(self):
        opened = mock.mock_open(read_data=self.memory_info(6*storage.GIB))
        with mock.patch.dict(os.environ, {'LUMA_NATIVE_ASSEMBLY_MEMORY_GIB': '5'}, clear=True), \
                mock.patch.object(Path, 'open', opened):
            observed = storage.admit_assembly_memory()
            self.assertEqual(observed['assembly_memory_gib'], 5)
            opened.assert_called_once_with(encoding='ascii')
            opened.return_value.read.assert_called_once_with(65537)
        for value in ('6', '7'):
            with self.subTest(value=value), \
                    mock.patch.dict(os.environ, {'LUMA_NATIVE_ASSEMBLY_MEMORY_GIB': value}, clear=True), \
                    mock.patch.object(Path, 'open') as refused:
                with self.assertRaises(ValueError):
                    storage.admit_assembly_memory()
                refused.assert_not_called()
        observed = storage.check_assembly_memory(5, self.memory_info(6*storage.GIB))
        with mock.patch.object(sys, 'argv', ['build_storage.py', 'assembly-memory']), \
                mock.patch.object(storage, 'admit_assembly_memory', return_value=observed) as check, \
                mock.patch('sys.stdout', new_callable=io.StringIO) as output:
            storage.main()
            check.assert_called_once_with()
            printed = output.getvalue()
            self.assertTrue(printed.startswith('Assembly host memory admission: '))
            self.assertEqual(json.loads(printed.partition(': ')[2]), observed)

    def test_only_assembly_container_selects_memory_and_actual_admission_is_immediate(self):
        script = (Path(__file__).resolve().parents[1]/'image/build.sh').read_text(encoding='utf-8')
        self.assertIn('assembly_memory_gib=${LUMA_NATIVE_ASSEMBLY_MEMORY_GIB-4}', script)
        self.assertIn('case "$assembly_memory_gib" in\n    4|5|8) ;;', script)
        self.assertIn('build_limits=(--memory 4g --memory-swap 4g --cpu-period 100000 --cpu-quota 200000)', script)
        self.assertIn('run_limits=(--memory 4g --memory-swap 4g --cpus 2)', script)
        self.assertIn('assembly_limits=(--memory "${assembly_memory_gib}g" --memory-swap "${assembly_memory_gib}g" --cpus 2)', script)
        guard = 'LUMA_NATIVE_ASSEMBLY_MEMORY_GIB="$assembly_memory_gib" python3 "$source_context/native/image/build_storage.py" assembly-memory'
        self.assertEqual(script.count(guard), 1)
        before, after = script.split(guard)
        self.assertTrue(after.startswith('\ndocker run --rm "${assembly_limits[@]}" --network none \\\n'))
        self.assertEqual(script.count('"${assembly_limits[@]}"'), 1)
        assembly, exports = after.split('if [ "$environment" = production ]; then', 1)
        self.assertIn('"$tools" python3 /repo/native/image/assemble.py', assembly)
        self.assertIn('-e CARGO_BUILD_JOBS=1 -e RUSTFLAGS=-Dwarnings', assembly)
        self.assertNotIn('"${assembly_limits[@]}"', before+exports)
        self.assertNotIn('wsl --shutdown', script)

    def daemon_info(self):
        return {'DockerRootDir':str(storage.STORE/'docker'), 'Driver':'overlay2',
                'Containerd':{'Address':'/run/luma-build-containerd/containerd.sock',
                              'Namespaces':{'Containers':'luma-build', 'Plugins':'plugins.moby'}}}

    def test_exact_loop_mount_required(self):
        record = {'target':str(storage.STORE), 'source':'/dev/loop12',
                  'fstype':'ext4', 'options':'rw,noatime'}
        storage.validate_mount(record, str(storage.BACKING))
        for field, value in (('target','/'), ('source','/dev/sdf'),
                             ('fstype','9p'), ('options','ro,noatime')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                storage.validate_mount({**record, field:value}, str(storage.BACKING))
        with self.assertRaises(ValueError):
            storage.validate_mount(record, '/mnt/c/wrong.ext4')

    def test_daemon_root_and_classic_driver_both_required(self):
        record = self.daemon_info()
        storage.validate_daemon(record)
        for field, value in (('DockerRootDir','/var/lib/docker'), ('Driver','overlayfs')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                storage.validate_daemon({**record, field:value})
        for runtime in ({}, {'Address':'/run/containerd/containerd.sock'},
                        {**record['Containerd'], 'Namespaces':{'Containers':'moby'}}):
            with self.assertRaises(ValueError):
                storage.validate_daemon({**record, 'Containerd':runtime})

    def test_verified_d_profile_checks_d_not_repository_free_space(self):
        environment = {'DOCKER_HOST':storage.ENDPOINT,
                       'TMPDIR':str(storage.STORE/'client/tmp'),
                       'DOCKER_CONFIG':str(storage.STORE/'client/docker')}
        info = json.dumps(self.daemon_info())
        runtime = "root='/mnt/luma-build/containerd'\nstate='/run/luma-build-containerd'\ntemp='/mnt/luma-build/tmp/containerd'\ndisabled_plugins=['io.containerd.cri.v1.images','io.containerd.cri.v1.runtime']\n[grpc]\naddress='/run/luma-build-containerd/containerd.sock'\n"
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(storage, 'verify_store') as verified, \
                mock.patch.object(storage, 'command', side_effect=lambda *args:info if args[0]=='docker' else runtime), \
                mock.patch.object(Path, 'resolve', lambda self, **kwargs:self), \
                mock.patch.object(Path, 'is_dir', return_value=True), \
                mock.patch.object(storage, 'check_space') as check:
            storage.preflight(Path('/mnt/c/repo'), '/mnt/d/LumaOS-builds', 'desktop')
            verified.assert_called_once()
            self.assertEqual(check.call_args_list,
                             [mock.call(storage.STORE,32), mock.call('/mnt/d/LumaOS-builds',60)])
            os.environ['TMPDIR'] = '/mnt/c/temp'
            with self.assertRaises(ValueError):
                storage.preflight(Path('/mnt/c/repo'), '/mnt/d/LumaOS-builds', 'desktop')
            os.environ['TMPDIR'] = environment['TMPDIR']
            os.environ['DOCKER_CONTEXT'] = 'desktop-linux'
            with self.assertRaises(ValueError):
                storage.preflight(Path('/mnt/c/repo'), '/mnt/d/LumaOS-builds', 'desktop')

    def test_effective_containerd_configuration_cannot_redirect_to_c(self):
        record = {'root':str(storage.STORE/'containerd'), 'state':'/run/luma-build-containerd',
                  'temp':str(storage.STORE/'tmp/containerd'),
                  'disabled_plugins':['io.containerd.cri.v1.images','io.containerd.cri.v1.runtime'],
                  'grpc':{'address':'/run/luma-build-containerd/containerd.sock'}}
        storage.validate_runtime(record)
        for field, value in (('root','/var/lib/containerd'), ('temp','/var/tmp'),
                             ('state','/run/containerd'), ('disabled_plugins',[]),
                             ('grpc',{'address':'/run/containerd/containerd.sock'})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                storage.validate_runtime({**record, field:value})

    def test_missing_mount_never_falls_back_to_default_daemon(self):
        with mock.patch.dict(os.environ, {'DOCKER_HOST':storage.ENDPOINT}), \
                mock.patch.object(storage, 'verify_store', side_effect=ValueError('missing mount')), \
                mock.patch.object(storage, 'command') as command:
            with self.assertRaises(ValueError):
                storage.preflight(Path('/mnt/c/repo'), '/mnt/d/LumaOS-builds', 'headless')
            command.assert_not_called()

    def test_legacy_external_build_retains_c_space_guard(self):
        with mock.patch.dict(os.environ, {'DOCKER_HOST':'unix:///var/run/docker.sock'}), \
                mock.patch.object(storage, 'check_space') as check:
            storage.preflight(Path('/mnt/c/repo'), '/mnt/d/LumaOS-builds', 'headless')
            self.assertEqual(check.call_args_list,
                             [mock.call(Path('/mnt/c/repo'),8), mock.call('/mnt/d/LumaOS-builds',40)])


if __name__ == '__main__':
    unittest.main()
