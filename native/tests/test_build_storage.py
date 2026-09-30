"""Build-storage admission oracles; no mounting or Docker mutations."""
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
import build_storage as storage


class BuildStorageTests(unittest.TestCase):
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
