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
        value=dict(schema_version=1,profile='webkitgtk-native-document-presentation-v1',api_version='4.1',
                   package_version='2.44.0-0ubuntu0.24.04.1',runtime_version=[2,44,0],
                   library=dict(path='/usr/lib/x86_64-linux-gnu/libwebkit2gtk-4.1.so.0.18.1',bytes=100,sha256='a'*64),
                   max_html_bytes=1024*1024,timeout_seconds=15,native_qualified=False)
        self.assertEqual(browser.runtime_manifest(json.dumps(value).encode(),(2,44,0)),value['library'])
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


if __name__=='__main__':
    unittest.main()
