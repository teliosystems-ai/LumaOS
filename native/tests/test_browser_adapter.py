"""GI-free actual callback ordering contract; not a WebKit/native pass."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('luma_browser_adapter_tests', ROOT / 'native/desktop/browser_adapter.py')
browser = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(browser)


class BrowserAdapterTests(unittest.TestCase):
    def observation(self):
        self.now = 10.0
        html = '<p>Actual inert fixture bytes</p>'
        return browser.Presentation(html,hashlib.sha256(html.encode()).hexdigest(),(2,44,0),'a'*64,clock=lambda:self.now)

    def test_real_callback_order_is_required_and_finished_after_error_never_succeeds(self):
        value = self.observation()
        value.started();value.commit();value.finish()
        self.assertEqual(value.receipt()['state'],'loaded')
        self.assertTrue(value.receipt()['load_finished_observed'])
        for failed_at in ('loading','committed'):
            value=self.observation();value.started()
            if failed_at=='committed':
                value.commit()
            value.failed('load-failed');value.finish()
            self.assertEqual(value.receipt()['state'],'failed')
        value=self.observation();value.finish()
        self.assertNotEqual(value.receipt()['state'],'loaded')
        value=self.observation();value.started();value.started();value.finish()
        self.assertEqual(value.receipt()['state'],'failed')

    def test_cancel_deadline_and_actual_termination_are_distinct_observations(self):
        for reason in ('human-cancel','deadline','window-close'):
            value=self.observation();value.started();value.commit();value.request_stop(reason)
            self.assertFalse(value.receipt()['web_process_termination_observed'])
            value.finish()
            self.assertNotEqual(value.receipt()['state'],'loaded')
            value.terminated()
            self.assertTrue(value.receipt()['web_process_termination_observed'])
            self.assertFalse(value.receipt()['namespace_drained'])
        value=self.observation();value.started();value.commit();self.now=26.0;value.finish()
        self.assertNotEqual(value.receipt()['state'],'loaded')

    def test_all_receipts_refuse_authority_layout_and_workflow_claims(self):
        value=self.observation();value.started();value.commit();value.finish()
        for field in ('pixels_verified','namespace_drained','owner_authenticated','content_committed','workflow_completed','authority_returned','native_qualified'):
            self.assertIs(value.receipt()[field],False)
        with self.assertRaises(ValueError):
            browser.Presentation('bytes','f'*64,(2,44,0),'a'*64)
        with self.assertRaises(ValueError):
            browser.Presentation('x',hashlib.sha256(b'x').hexdigest(),(True,44,0),'a'*64)

    def test_manifest_requires_actual_fixed_runtime_pin_and_closed_typed_bounds(self):
        value=dict(schema_version=2,profile='webkitgtk-native-document-presentation-v1',api_version='4.1',
                   package_version='2.44.0-0ubuntu0.24.04.1',runtime_version=[2,44,0],
                   library=dict(path='/usr/lib/x86_64-linux-gnu/libwebkit2gtk-4.1.so.0.18.1',bytes=100,sha256='a'*64),
                   launcher=dict(path='/usr/libexec/luma-os/luma-workspace-launch', bytes=100, sha256='b'*64),
                   apparmor_profile=dict(path='/etc/apparmor.d/luma-workspace', bytes=100, sha256='c'*64),
                   apparmor_label='luma-workspace (unconfined)',
                   max_html_bytes=1024*1024,timeout_seconds=15,native_qualified=False)
        self.assertEqual(browser.runtime_manifest(json.dumps(value).encode(),(2,44,0)),value)
        for change in range(7):
            wrong=copy.deepcopy(value)
            if change==0:wrong['native_qualified']=True
            elif change==1:wrong['runtime_version']=[2,44,1]
            elif change==2:wrong['schema_version']=True
            elif change==3:wrong['library']['path']='/tmp/caller.so'
            elif change==4:wrong['library']['bytes']=True
            elif change==5:wrong['timeout_seconds']=1800
            else:wrong['authority']=True
            with self.assertRaises(ValueError):
                browser.runtime_manifest(json.dumps(wrong).encode(),(2,44,0))
        for field, changed in [('launcher', dict(value['launcher'], path='/usr/bin/python3')),
            ('launcher', dict(value['launcher'], bytes=True)), ('launcher', dict(value['launcher'], bytes=1024*1024+1)),
            ('apparmor_profile', dict(value['apparmor_profile'], path='/etc/apparmor.d/usr.bin.python3')),
            ('apparmor_profile', dict(value['apparmor_profile'], sha256='caller')),
            ('apparmor_label', 'unconfined'), ('apparmor_label', 'luma-workspace (enforce)'), ('schema_version', 1)]:
            with self.subTest(field=field, changed=changed), self.assertRaises(ValueError):
                browser.runtime_manifest(json.dumps(dict(value, **{field: changed})).encode(), (2,44,0))
        legacy = {key: item for key, item in value.items() if key not in ('launcher', 'apparmor_profile', 'apparmor_label')}
        with self.assertRaises(ValueError):
            browser.runtime_manifest(json.dumps(legacy).encode(), (2,44,0))

    def test_only_exact_named_kernel_userns_label_is_accepted_not_generic_or_stacked(self):
        browser.require_workspace_label(b'luma-workspace (unconfined)\n')
        for wrong in (b'unconfined\n', b'luma-workspace (enforce)\n', b'luma-workspace (complain)\n',
            b'luma-workspace (unconfined)', b'luma-workspace (unconfined)\n\n',
            b'luma-workspace//&another (unconfined)\n', b'caller (unconfined)\n', b'',
            'luma-workspace (unconfined)\n', b'luma-workspace (unconfined)\nextra'):
            with self.subTest(label=wrong), self.assertRaises(ValueError):
                browser.require_workspace_label(wrong)
        app = (ROOT/'native/desktop/workspace_app.py').read_text(encoding='utf-8')
        self.assertLess(app.index('browser_module.require_workspace_label'), app.index('import gi'))
        self.assertLess(app.index('browser_module.verify_runtime_files'), app.index('Gtk.init([])'))
        self.assertIn("with open('/proc/self/attr/current', 'rb', buffering=0)", app)
        self.assertIn('label.read(257)', app)
        assembly = (ROOT/'native/image/assemble.py').read_text(encoding='utf-8')
        compile_at = assembly.index("workspace_launcher = binary.parent/'luma-workspace-launch'")
        self.assertLess(compile_at, assembly.index('browser_policy.canonical_manifest(ROOT)'))
        for required in ("'-Wpedantic'", "'-Werror'", "'-fPIE'", "'-pie'", "'-fstack-protector-strong'", "'-D_FORTIFY_SOURCE=3'", "'-Wl,-z,relro,-z,now,-z,noexecstack'"):
            self.assertIn(required, assembly[compile_at:assembly.index('browser_policy.canonical_manifest(ROOT)')])

    def test_runtime_pins_verify_actual_elf_and_profile_bytes_without_loaded_policy_claim(self):
        # Genuine compiled ELF fixture, not an executable stub or WebKit pass.
        actual = Path('/usr/bin/true').resolve(strict=True).read_bytes()
        profile = b'profile luma-workspace /usr/libexec/luma-os/luma-workspace-launch flags=(unconfined) { userns, }\n'
        data = {'library': actual, 'launcher': actual, 'apparmor_profile': profile}
        paths = dict(library='/usr/lib/x86_64-linux-gnu/libwebkit2gtk-4.1.so.0.18.1',
            launcher='/usr/libexec/luma-os/luma-workspace-launch', apparmor_profile='/etc/apparmor.d/luma-workspace')
        pins = {key: dict(path=paths[key], bytes=len(item), sha256=hashlib.sha256(item).hexdigest()) for key, item in data.items()}
        reverse = {path: key for key, path in paths.items()}
        calls = []

        def read(path, maximum):
            calls.append((path, maximum))
            return data[reverse[path]]

        browser.verify_runtime_files(pins, read)
        self.assertEqual(calls, [(paths['library'], 256*1024*1024), (paths['launcher'], 1024*1024), (paths['apparmor_profile'], 65536)])
        for key in data:
            original = data[key]
            data[key] = original+b'changed'
            with self.subTest(member=key), self.assertRaises(ValueError):
                browser.verify_runtime_files(pins, read)
            data[key] = original
        data['launcher'] = b'not ELF'
        pins['launcher'].update(bytes=len(data['launcher']), sha256=hashlib.sha256(data['launcher']).hexdigest())
        with self.assertRaises(ValueError):
            browser.verify_runtime_files(pins, read)


if __name__=='__main__':
    unittest.main()
