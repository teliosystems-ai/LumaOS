import hashlib
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('windows_workspace', Path(__file__).parents[1]/'image/windows_workspace.py')
workspace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workspace)


class WorkspaceProfile(unittest.TestCase):
    def request(self):
        return dict(schema_version=1, profile=workspace.PROFILE, nonce='11'*32,
                    installation='22'*32, release_sha256='33'*32,
                    runtime_manifest_sha256='44'*32, profile_sha256='55'*32,
                    actor_sid_sha256='66'*32, login='alice', uid=1000, gid=1000,
                    account_generation=1, protected_utc_day=20746, utc_proof_sha256='77'*32)

    def test_profile_is_separate_and_fixed_thirty_second_fallback(self):
        value = workspace.profile('11'*32)
        self.assertEqual(workspace.validate_profile(workspace.encoded(value), '11'*32), value)
        self.assertEqual(value['bootstrap_purpose_seconds'], 30)
        self.assertEqual(value['bootstrap_cpu_seconds']+value['drain_seconds'], 30)
        self.assertEqual(value['default_uid'], 65534)
        self.assertEqual(value['wsl_flags'], 0)
        for key, replacement in [('schema_version', True), ('default_uid', 1000),
                                 ('bootstrap_purpose_seconds', 300), ('password_max_age_days', 99999),
                                 ('memory_swap_max_bytes', 1), ('extra', False)]:
            bad = dict(value, **{key: replacement})
            with self.subTest(key=key), self.assertRaises(ValueError):
                workspace.validate_profile(workspace.encoded(bad), '11'*32)

    def test_request_binds_actual_actor_release_utc_and_first_account_not_credentials(self):
        value = self.request()
        raw = workspace.encoded(value)
        self.assertEqual(workspace.request(raw), value)
        self.assertNotIn(b'password', raw)
        for key, replacement in [('uid', 0), ('gid', 1001), ('account_generation', 2),
                                 ('protected_utc_day', True), ('protected_utc_day', 0),
                                 ('login', 'root'), ('login', 'nobody'), ('login', '../alice'),
                                 ('actor_sid_sha256', '0'*64), ('nonce', 'A'*64),
                                 ('schema_version', True), ('password', 'not permitted')]:
            bad = dict(value, **{key: replacement})
            with self.subTest(key=key), self.assertRaises(ValueError):
                workspace.request(workspace.encoded(bad))
        for bad in (raw.replace(b'{', b'{"uid":1000,', 1), raw+b' ', raw[:-1],
                    raw.replace(b'"uid":1000', b'"uid":1e3'), b'[]'):
            with self.assertRaises((ValueError, TypeError)):
                workspace.request(bad)

    def manifest(self):
        files = sorted((workspace.PLATFORM, workspace.AUTH_HELPER, workspace.PAM_MODULE, workspace.SHELL,
                        'usr/lib/x86_64-linux-gnu/libpam.so.0'))
        return dict(schema_version=1, profile=workspace.PROFILE,
                    files=[dict(path=path, bytes=128, sha256='11'*32,
                                executable=path in (workspace.PLATFORM, workspace.AUTH_HELPER, workspace.SHELL)) for path in files])

    def test_runtime_manifest_is_bounded_exact_and_requires_real_pam(self):
        value = self.manifest()
        raw = workspace.encoded(value)
        self.assertEqual(workspace.runtime_manifest(raw), value)
        pins = workspace.required_files(raw)
        self.assertIn(workspace.PAM_PATH, pins)
        self.assertIn(workspace.AUTH_HELPER, pins)
        self.assertIn(workspace.BASE+'/shadow', pins)
        for path in ('../../etc/shadow', '/usr/bin/sh', 'usr/bin/sh',
                     'usr/lib/x86_64-linux-gnu/security/pam_permit.so',
                     'usr/lib/x86_64-linux-gnu/../libpam.so'):
            bad = self.manifest()
            bad['files'][0]['path'] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                workspace.runtime_manifest(workspace.encoded(bad))
        for mutate in (lambda rows: rows.reverse(), lambda rows: rows.append(rows[0]),
                       lambda rows: rows.pop(), lambda rows: rows[0].update(bytes=True),
                       lambda rows: rows[0].update(executable=1)):
            bad = self.manifest()
            mutate(bad['files'])
            with self.assertRaises(ValueError):
                workspace.runtime_manifest(workspace.encoded(bad))

    def test_baselines_are_still_locked_original_canary_and_no_shared_credentials(self):
        self.assertEqual(set(workspace.BASELINES), {'passwd', 'shadow', 'group', 'gshadow'})
        self.assertEqual(workspace.BASELINES['shadow'][1], 0o600)
        self.assertNotIn(b'1000', workspace.BASELINES['passwd'][0])
        self.assertIn(b'root:!:', workspace.BASELINES['shadow'][0])
        self.assertNotIn(b'include', workspace.PAM)
        self.assertNotIn(b'pam_permit', workspace.PAM)
        value = workspace.profile('11'*32)
        for name, (raw, _mode) in workspace.BASELINES.items():
            self.assertEqual(value['account_baselines'][name], hashlib.sha256(raw).hexdigest())

    def test_generated_members_pin_exact_policy_and_readonly_empty_templates(self):
        raw=workspace.encoded(self.manifest())
        generated=workspace.generated(raw)
        descriptor=generated[workspace.PROFILE_PATH][0]
        workspace.validate_profile(descriptor,hashlib.sha256(raw).hexdigest())
        self.assertEqual(generated[workspace.SERVICE],generated[workspace.ENABLED])
        self.assertIn(b'ConditionSecurity=apparmor',generated[workspace.SERVICE][0])
        self.assertNotIn(b'ExecStart=-',generated[workspace.SERVICE][0])
        self.assertEqual(generated[workspace.PAM_PATH],(workspace.PAM,0o644))
        self.assertNotIn('etc/shadow',generated)
        self.assertIn(workspace.POLICY,workspace.required_files(raw))
        for name,(baseline,_mode) in workspace.BASELINES.items():
            self.assertEqual(generated[workspace.BASE+'/'+name],(baseline,0o644))


if __name__ == '__main__':
    unittest.main()
