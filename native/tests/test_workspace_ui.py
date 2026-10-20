"""Source/HTML accessibility contracts; actual JS runs in workspace_ui_dom.mjs.

This suite has no optional-engine skip and makes no installed graphical claim.
"""
import ast
import importlib.util
import json
from html.parser import HTMLParser
from pathlib import Path
import subprocess
import sys
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
    def test_native_discovery_selector_preserves_exact_u64_without_web_authority(self):
        def load(name, relative):
            spec = importlib.util.spec_from_file_location(name, ROOT/relative)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        app = load('luma_discovery_app_data', 'native/desktop/workspace_app.py')
        auth = load('luma_discovery_auth_data', 'native/desktop/workspace_auth.py')
        maximum = 2**64-1
        binding = dict(installation='a'*64, owner='b'*64, owner_generation=maximum)
        reference = dict(artifact_id='artifact-one', version=maximum, content_sha256='c'*64, receipt_sha256='d'*64)
        for mode, selector in [('search-semantic-selected', [reference]), ('collection-search-semantic', dict(reference, artifact_id='collection.work'))]:
            prepared = app.discovery_proposal(auth, 'alice', json.dumps(binding), mode, json.dumps(selector), 'Original query', 32, 8)
            self.assertEqual(prepared['operation'], 'search-journey')
            self.assertEqual([prepared[key] for key in ('read_grant', 'effect_grant', 'approval')], ['', '', ''])
            source = auth.strict_json(prepared['request'])
            self.assertEqual(source['binding']['owner_generation'], maximum)
            selected = source['operation']['references'][0] if isinstance(selector, list) else source['operation']['expected']
            self.assertEqual(selected['version'], maximum)
            self.assertIs(type(selected['version']), int)
            self.assertEqual(source['operation']['query'], 'Original query')
        arguments = ['alice', json.dumps(binding), 'search-semantic-selected', json.dumps([reference]), 'exact query', 16, 4]
        invalid = [(2, 'search'), (3, '[]'), (3, json.dumps([reference, reference])),
                   (3, json.dumps([reference]*65)), (3, json.dumps([dict(reference, grant='forged')])),
                   (3, json.dumps([dict(reference, artifact_id='z'), reference])),
                   (3, json.dumps([dict(reference, version=maximum+1)])),
                   (3, '{"artifact_id":"one","artifact_id":"two"}'),
                   (4, 'a'*257), (4, 'a'*65), (4, ' '.join(['term']*9)), (4, 'caf\u00e9'), (4, 'one\x1ctwo'), (4, 'one\x0btwo'),
                   (5, 0), (5, 33), (5, True), (6, 0), (6, 9), (6, True),
                   (1, json.dumps(dict(binding, owner_generation=True))), (0, 'root;command')]
        for index, value in invalid:
            case = arguments.copy(); case[index] = value
            with self.subTest(index=index, value=value), self.assertRaises((ValueError, TypeError)):
                app.discovery_proposal(auth, *case)

    def test_native_refusal_is_not_a_crash_loader_failure_or_partial_result(self):
        genuine = subprocess.CompletedProcess([], 1, b'', b'luma-platform: spreadsheet contains a reference cycle\n')
        native_refusal(genuine, 'cycle', 'spreadsheet contains a reference cycle')
        for code, stdout, stderr in ((0, b'', genuine.stderr), (-11, b'', genuine.stderr),
                                     (127, b'', b'loader failed'), (1, b'partial', genuine.stderr),
                                     (1, b'', b''), (1, b'', b'luma-platform: wrong error\n')):
            with self.subTest(code=code, stdout=stdout, stderr=stderr), self.assertRaises(AssertionError):
                native_refusal(subprocess.CompletedProcess([], code, stdout, stderr), 'cycle',
                               'spreadsheet contains a reference cycle')

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
        for key in ('sheet-heading', 'sheet-rows', 'sheet-columns', 'sheet-kind', 'sheet-value',
                    'sheet-second', 'sheet-grid', 'sheet-status', 'progress-events', 'composer-heading',
                    'composer-engine', 'composer-fields', 'composer-form', 'composer-status', 'composer-use',
                    'composer-load', 'composer-apply', 'composer-discard'):
            self.assertIn(key, nodes)
        self.assertEqual(nodes['sheet-heading'][1]['tabindex'], '-1')
        self.assertEqual(nodes['sheet-status'][1]['aria-live'], 'polite')
        self.assertEqual(nodes['composer-status'][1]['aria-live'], 'polite')
        self.assertEqual(nodes['composer-heading'][1]['tabindex'], '-1')
        self.assertEqual(nodes['sheet-grid'][0], 'table')
        self.assertIn('sheet-keyboard', nodes['sheet-grid'][1]['aria-describedby'].split())
        self.assertEqual(nodes['sheet-rows'][1]['max'], '64')
        self.assertEqual(nodes['sheet-columns'][1]['max'], '32')
        self.assertEqual(nodes['error'][1]['tabindex'], '-1')

    def test_private_read_is_native_control_not_a_web_message_route(self):
        app = (ROOT / 'native/desktop/workspace_app.py').read_text(encoding='utf-8')
        auth = (ROOT / 'native/desktop/workspace_auth.py').read_text(encoding='utf-8')
        host = (ROOT / 'native/desktop/workspace_host.py').read_text(encoding='utf-8')
        js = (ROOT / 'web/native-workspace.js').read_text(encoding='utf-8')
        ast.parse(app)
        ast.parse(auth)
        ast.parse(host)
        self.assertIn("read_button.connect('clicked', grounded_read)", app)
        self.assertIn("discovery_button.connect('clicked', owner_discovery)", app)
        self.assertIn("operation='search-journey'", app)
        self.assertIn('return discovery_journey(value, directory)', auth)
        self.assertNotIn('search-journey', js)
        self.assertNotIn('content-owned-review', js)
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
        self.assertNotIn('eval(', js)
        self.assertNotIn('new Function', js)
        for name in ('native-workspace.js', 'native-workspace.css', 'native-workspace.html'):
            self.assertLessEqual((ROOT/'web'/name).stat().st_size, 256*1024)

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


def native_refusal(completed, name, expected_error):
    if (not isinstance(expected_error, str) or not expected_error or
            completed.returncode != 1 or completed.stdout != b'' or
            completed.stderr != ('luma-platform: ' + expected_error + '\n').encode()):
        raise AssertionError('actual engine did not produce the exact clean required refusal: ' + name)


def actual_spreadsheet_cases(binary, cases_path):
    """Run production-JS-generated DATA through the actual Rust CLI, not PAM."""
    binary = Path(binary).resolve(strict=True)
    with Path(cases_path).open('rb') as stream:
        raw = stream.read(1024*1024+1)
    if len(raw) > 1024*1024:
        raise ValueError('bounded DOM fixture exceeded')
    spec = importlib.util.spec_from_file_location('luma_workspace_sheet_actual_host', ROOT/'native/desktop/workspace_host.py')
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    fixture = host.strict_json(raw)
    cases = fixture['spreadsheet_cases']
    if fixture['production_javascript_executed'] is not True or fixture['authority_returned'] is not False or fixture['graphical_webkit_qualified'] is not False or not isinstance(cases, list) or not 1 <= len(cases) <= 16:
        raise ValueError('real production-JS bounded fixture required')
    passed = refused = 0
    for index, case in enumerate(cases):
        request = host.request(dict(schema_version=1, id='actual-sheet-'+str(index), operation='preview', engine='spreadsheet', source=case['source']))
        completed = subprocess.run([str(binary), 'content-contract-spreadsheet'], input=request['source'].encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
        if case.get('native_refusal_required') is True:
            native_refusal(completed, case['name'], case.get('expected_native_error'))
            refused += 1
        else:
            if completed.returncode != 0:
                raise AssertionError('actual Rust engine refused generated source: '+case['name']+' '+completed.stderr.decode(errors='replace'))
            verified = host.validate_result(request, completed.stdout)
            if verified['calculation']['values'][0] != case['expected_first_row']:
                raise AssertionError('actual Rust values differ for '+case['name'])
            passed += 1
    print(json.dumps(dict(actual_rust_spreadsheet_cases_passed=passed, actual_rust_refusals_passed=refused,
        graphical_webkit_qualified=False, owner_authenticated=False, workflow_executed=False, authority_returned=False)))


def actual_engine_cases(binary, cases_path):
    """Join production composer bytes to native source/render/digest validation."""
    binary = Path(binary).resolve(strict=True)
    with Path(cases_path).open('rb') as stream:
        raw = stream.read(1024*1024+1)
    if len(raw) > 1024*1024:
        raise ValueError('bounded production-JS engine fixture exceeded')
    spec = importlib.util.spec_from_file_location('luma_workspace_composer_actual_host', ROOT/'native/desktop/workspace_host.py')
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    fixture = host.strict_json(raw)
    cases = fixture['engine_cases']
    if (fixture['production_javascript_executed'] is not True or fixture['authority_returned'] is not False
            or fixture['graphical_webkit_qualified'] is not False or not isinstance(cases, list) or not 1 <= len(cases) <= 16):
        raise ValueError('real production-JS bounded engine fixture required')
    passed = refused = 0
    for index, case in enumerate(cases):
        engine = case['engine']
        if engine not in ('document', 'diagram', 'animation', 'collection'):
            raise ValueError('closed composer engines required')
        request = host.request(dict(schema_version=1, id='actual-composer-'+str(index), operation='preview', engine=engine, source=case['source']))
        completed = subprocess.run([str(binary), 'content-contract-' + engine], input=request['source'].encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
        if case.get('native_refusal_required') is True:
            native_refusal(completed, case['name'], case.get('expected_native_error'))
            refused += 1
            continue
        if completed.returncode != 0 or completed.stderr != b'':
            raise AssertionError('actual Rust engine refused composed source: ' + case['name'] + ' ' + completed.stderr.decode(errors='replace'))
        verified = host.validate_result(request, completed.stdout)
        canonical = verified['canonical_source'] if engine == 'collection' else verified['rendering']['canonical_source']
        if not host.same_json(host.strict_json(canonical), host.strict_json(case['source'])):
            raise AssertionError('actual native engine changed composed editable source: ' + case['name'])
        # Re-render the exact native canonical source: all output/digests must
        # match the first actual invocation, not browser-generated expected SVG.
        repeated = subprocess.run([str(binary), 'content-contract-' + engine], input=canonical.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
        if repeated.returncode != 0 or repeated.stderr != b'' or repeated.stdout != completed.stdout:
            raise AssertionError('actual native composed-source rendering is not repeatable: ' + case['name'])
        passed += 1
    print(json.dumps(dict(actual_rust_composer_cases_passed=passed, actual_rust_exact_refusals_passed=refused,
        actual_native_canonical_rerenders_passed=passed, graphical_webkit_qualified=False,
        owner_authenticated=False, workflow_executed=False, authority_returned=False)))


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--native-cli' and sys.argv[3] == '--spreadsheet-cases':
        actual_spreadsheet_cases(sys.argv[2], sys.argv[4])
    elif len(sys.argv) == 5 and sys.argv[1] == '--native-cli' and sys.argv[3] == '--engine-cases':
        actual_engine_cases(sys.argv[2], sys.argv[4])
    else:
        unittest.main()
