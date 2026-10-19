"""Source/HTML accessibility contracts; actual JS runs in workspace_ui_dom.mjs.

This suite has no optional-engine skip and makes no installed graphical claim.
"""
import ast
from html.parser import HTMLParser
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Elements(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.nodes = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.nodes.append((tag, dict(attrs)))


class WorkspaceUiTests(unittest.TestCase):
    def test_labeled_navigation_live_errors_and_keyboard_targets_exist(self):
        parsed = Elements((ROOT / 'web/native-workspace.html').read_text(encoding='utf-8'))
        ids = [attrs['id'] for _, attrs in parsed.nodes if 'id' in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        nodes = {attrs['id']: (tag, attrs) for tag, attrs in parsed.nodes if 'id' in attrs}
        for tag, attrs in parsed.nodes:
            if tag == 'label':
                self.assertIn(attrs['for'], nodes)
            if tag == 'a' and attrs.get('href', '').startswith('#'):
                self.assertIn(attrs['href'][1:], nodes)
            for name in ('aria-describedby', 'aria-labelledby'):
                for target in attrs.get(name, '').split():
                    self.assertIn(target, nodes)
        self.assertEqual(nodes['status'][1]['aria-live'], 'polite')
        self.assertEqual(nodes['error'][1]['role'], 'alert')
        self.assertEqual(nodes['result-heading'][1]['tabindex'], '-1')
        self.assertEqual(nodes['preview'][1]['aria-keyshortcuts'], 'Control+Enter')
        self.assertEqual(nodes['cancel'][1]['aria-keyshortcuts'], 'Escape')
        self.assertIn('source-grounding', nodes)

    def test_private_read_is_native_control_not_a_web_message_route(self):
        app = (ROOT / 'native/desktop/workspace_app.py').read_text(encoding='utf-8')
        auth = (ROOT / 'native/desktop/workspace_auth.py').read_text(encoding='utf-8')
        host = (ROOT / 'native/desktop/workspace_host.py').read_text(encoding='utf-8')
        js = (ROOT / 'web/native-workspace.js').read_text(encoding='utf-8')
        ast.parse(app)
        ast.parse(auth)
        ast.parse(host)
        self.assertIn("read_button.connect('clicked', grounded_read)", app)
        self.assertIn("mode.append('paged-read'", app)
        self.assertIn("mode.append('envelope-read'", app)
        self.assertIn('label.set_mnemonic_widget(entry)', app)
        self.assertIn("return paged_read(value, directory)", auth)
        self.assertIn("workflow_button.connect('clicked', managed_workflow)", app)
        self.assertIn("operation='workflow-journey'", app)
        self.assertIn('return workflow_journey(value, directory)', auth)
        self.assertNotIn('workflow-journey', js)
        self.assertNotIn('paged-read', js)
        self.assertNotIn('content-owned-review', host)
        self.assertNotIn('content-owned-apply', host)
        self.assertIn("recovery_button.connect('clicked', admin_recovery)", app)
        self.assertIn("mode.append('restore-journey'", app)
        self.assertIn("mode.append('retire-journey'", app)
        self.assertIn('return restore_journey(value, directory)', auth)
        self.assertIn('return retire_journey(value, directory)', auth)
        for private_route in ('restore-journey', 'retire-journey', 'content-restore-apply', 'content-restore-retire-inspect'):
            self.assertNotIn(private_route, js)
        self.assertNotIn('content-restore-apply', host)
        self.assertNotIn('content-restore-review', host)
        self.assertLessEqual(len(auth.encode('utf-8')), 128*1024)
        self.assertLessEqual(len(app.encode('utf-8')), 128*1024)
        self.assertNotIn('innerHTML', js)
        self.assertNotIn('fetch(', js)

    def test_reduced_motion_forced_color_and_non_fabricated_progress_contracts(self):
        css = (ROOT / 'web/native-workspace.css').read_text(encoding='utf-8')
        js = (ROOT / 'web/native-workspace.js').read_text(encoding='utf-8')
        self.assertIn('prefers-reduced-motion: reduce', css)
        self.assertIn('animation: none !important', css)
        self.assertIn('transition: none !important', css)
        self.assertIn('forced-colors: active', css)
        self.assertIn("byId('preview-output').setAttribute('aria-busy'", js)
        self.assertNotIn("byId('workspace').setAttribute('aria-busy'", js)
        self.assertIn("event.state === 'validating'", js)
        self.assertNotIn('setInterval(', js)
        harness = (ROOT / 'native/tests/workspace_ui_dom.mjs').read_text(encoding='utf-8')
        self.assertIn('vm.runInNewContext(source', harness)
        self.assertIn('graphical_webkit_qualified: false', harness)


if __name__ == '__main__':
    unittest.main()
