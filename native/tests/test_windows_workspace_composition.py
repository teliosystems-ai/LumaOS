"""Actual Ubuntu shell/PAM/helper ELF capture; no login/account/WSL execution.

The Luma slot deliberately uses the ordinary true ELF as a structural fixture,
not a claimed product binary. The PAM helper is compiled from actual auth_pam.c;
no renamed substitute is accepted as a tested PAM implementation or user grant.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).parents[2]
SPEC=importlib.util.spec_from_file_location('workspace_composition',ROOT/'native/image/windows_workspace.py')
workspace=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workspace)
SPEC=importlib.util.spec_from_file_location('workspace_composition_stage',ROOT/'native/image/windows_stage.py')
stage=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage)


class WindowsWorkspaceComposition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid()!=0 or not Path('/.dockerenv').is_file():
            raise RuntimeError('real workspace ELF composition requires disposable offline Ubuntu24.04 tools container')
        cls.work=tempfile.TemporaryDirectory(prefix='luma-workspace-composition-',dir=os.environ.get('LUMA_STORAGE_TEST_ROOT'))
        cls.base=Path(cls.work.name)
        cls.helper=cls.base/'luma-auth-helper'
        source=ROOT/'rust/luma-platform/src/auth_pam.c'
        cls.helper_source_sha=hashlib.sha256(source.read_bytes()).hexdigest()
        subprocess.run(['cc','-std=c99','-Wall','-Wextra','-Werror','-O2','-D_FORTIFY_SOURCE=2',str(source),'-lpam','-o',str(cls.helper)],check=True,timeout=30)
        cls.helper.chmod(0o755)
        if hashlib.sha256(source.read_bytes()).hexdigest()!=cls.helper_source_sha:
            raise RuntimeError('actual helper source changed during fixture build')
        cls.stage=stage.stage(Path('/'),Path('/usr/bin/true'),cls.base,'workspace',hosted_workspace=True)
        cls.root=cls.base/'workspace/rootfs'
        cls.composition=workspace.compose(cls.root,Path('/'),cls.helper)
        cls.package=stage.package.build(cls.root,Path('/usr/bin/true'),cls.base/'workspace/plan.json',cls.base/'package',
                                        'luma-wsl-dev-workspace-composition-test',hosted_workspace=True)
        cls.manifest=json.loads((cls.base/'package/manifest.json').read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def test_actual_helper_shell_pam_and_runtime_closure_are_pinned_without_accounts(self):
        manifest=workspace.runtime_manifest((self.root/workspace.MANIFEST_PATH).read_bytes())
        by_name={value['path']:value for value in manifest['files']}
        self.assertEqual((self.root/workspace.AUTH_HELPER).read_bytes(),self.helper.read_bytes())
        self.assertEqual((self.root/workspace.SHELL).read_bytes(),Path('/usr/bin/bash').read_bytes())
        self.assertEqual((self.root/workspace.PAM_MODULE).read_bytes(),(Path('/')/workspace.PAM_MODULE).read_bytes())
        for name,record in by_name.items():
            raw=(self.root/name).read_bytes()
            self.assertEqual(record['sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual(record['bytes'],len(raw))
            self.assertEqual(record['executable'],bool((self.root/name).stat().st_mode&0o111))
        for name,(raw,mode) in workspace.BASELINES.items():
            self.assertEqual((self.root/('etc/'+name)).read_bytes(),raw)
            self.assertEqual((self.root/('etc/'+name)).stat().st_mode&0o7777,mode)
        self.assertFalse((self.root/'home/alice').exists())
        self.assertFalse((self.root/'var/lib/luma-hosted-workspace/bootstrap').exists())
        self.assertFalse(self.composition['account_created'])
        self.assertFalse(self.composition['pam_authenticated'])

    def test_new_schema3_keeps_old_canary_and_pins_every_new_pam_configuration(self):
        with tarfile.open(self.base/'package/rootfs.tar','r:') as archive:
            identity=json.loads(archive.extractfile('usr/lib/luma/platform.json').read())
            self.assertEqual(identity['schema_version'],3)
            self.assertEqual(identity['runtime_profile'],workspace.PROFILE)
            self.assertEqual(archive.extractfile('etc/wsl.conf').read(),stage.package.WSL+b'[user]\ndefault=nobody\n')
        names={file['path'] for file in self.manifest['required_files']}
        self.assertTrue(set(workspace.required_files((self.root/workspace.MANIFEST_PATH).read_bytes()))<=names)
        self.assertLessEqual(len(names),128)
        self.assertFalse(self.package['runtime_qualified'])
        self.assertFalse(self.package['distribution_imported'])
        self.assertFalse(self.package['product_installation_admitted'])

    def test_recomposition_never_overwrites_existing_profile_or_changes_account_files(self):
        before={name:(self.root/('etc/'+name)).read_bytes() for name in workspace.BASELINES}
        with self.assertRaises(ValueError):
            workspace.compose(self.root,Path('/'),self.helper)
        self.assertEqual(before,{name:(self.root/('etc/'+name)).read_bytes() for name in workspace.BASELINES})

    def test_generic_and_old_compute_flags_cannot_silently_select_workspace(self):
        with self.assertRaises(ValueError):
            stage.package.build(self.root,Path('/usr/bin/true'),cls_plan:=self.base/'workspace/plan.json',self.base/'bad',
                                'luma-wsl-dev-invalid-combination',hosted_compute=True,hosted_workspace=True)
        self.assertTrue(cls_plan.is_file())


if __name__=='__main__':
    unittest.main()
