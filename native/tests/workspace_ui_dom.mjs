// Actual production JS in a small deterministic DOM fixture, not a graphical
// WebKit/accessibility qualification. No dependencies or browser authority.
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import vm from 'node:vm';

const source = readFileSync(fileURLToPath(new URL('../../web/native-workspace.js', import.meta.url)), 'utf8');
const html = readFileSync(fileURLToPath(new URL('../../web/native-workspace.html', import.meta.url)), 'utf8');
let assertions = 0;
const spreadsheetCases = [];
const check = (value, message) => { assertions++; assert.ok(value, message); };

function fixture(available = true) {
  const elements = new Map();
  const sent = [];
  let failTransport = false;
  let document;
  class Element {
    constructor(id = '', tag = 'div') {
      this.id = id; this.tagName = tag; this.value = ''; this.textContent = '';
      this.disabled = false; this.hidden = false; this.attributes = new Map();
      this.children = []; this.listeners = new Map();
    }
    setAttribute(name, value) { this.attributes.set(name, String(value)); }
    getAttribute(name) { return this.attributes.get(name) ?? null; }
    addEventListener(name, callback) {
      const list = this.listeners.get(name) ?? []; list.push(callback); this.listeners.set(name, list);
    }
    dispatch(name, extra = {}) {
      const event = {preventDefault() { this.prevented = true; }, ...extra};
      for (const callback of this.listeners.get(name) ?? []) callback(event);
      return event;
    }
    append(child) { this.children.push(child); }
    replaceChildren(...children) { this.children = children; }
    focus() { document.activeElement = this; }
  }
  for (const id of html.matchAll(/\bid="([^"]+)"/g)) elements.set(id[1], new Element(id[1]));
  const links = [...html.matchAll(/<a[^>]+href="(#[^"]+)"/g)].map(match => {
    const link = new Element('', 'a'); link.setAttribute('href', match[1]); return link;
  });
  document = new Element('document');
  document.getElementById = id => { assert.ok(elements.has(id), 'HTML contains actual JS target ' + id); return elements.get(id); };
  document.createElement = tag => new Element('', tag);
  document.querySelectorAll = () => links;
  document.activeElement = elements.get('editor');
  const window = available ? {webkit: {messageHandlers: {workspace: {postMessage(value) {
    if (failTransport) throw new Error('fixture transport refusal');
    sent.push(JSON.parse(value));
  }}}}} : {};
  vm.runInNewContext(source, {window, document, TextEncoder}, {timeout: 2000, filename: 'native-workspace.js'});
  const byId = id => elements.get(id);
  const receive = (id, state, extra = {}) => window.LumaWorkspace.receive({schema_version: 1, id, state,
    authority_returned: false, committed: false, owner_authenticated: false, workflow_executed: false,
    gate_closing: false, ...extra});
  function cells() {
    const collect = element => (element.tagName === 'button' ? [element] : []).concat(...element.children.map(collect));
    return collect(byId('sheet-grid'));
  }
  function edit(row, column, kind, value = '', second = '') {
    const width = byId('sheet-grid').children[1].children[0].children.length - 1;
    cells()[row * width + column].dispatch('click');
    byId('sheet-kind').value = kind; byId('sheet-kind').dispatch('change');
    byId('sheet-value').value = value; byId('sheet-value').dispatch('input');
    byId('sheet-second').value = second; byId('sheet-second').dispatch('input');
    byId('sheet-cell-apply').dispatch('click');
  }
  function copy() { byId('sheet-use').dispatch('click'); return JSON.parse(byId('editor').value); }
  return {byId, sent, document, receive, links, window, cells, edit, copy, fail(value) { failTransport = value; }};
}

{
  const f = fixture(false);
  check(f.byId('preview').disabled && f.byId('reopen').disabled, 'no browser replacement engine');
  f.document.dispatch('keydown', {key: 'Enter', ctrlKey: true});
  check(f.sent.length === 0, 'keyboard cannot bypass absent native bridge');
}
{
  const f = fixture();
  f.byId('editor').value = '<img src=x onerror=alert(1)>';
  f.document.dispatch('keydown', {key: 'Enter', ctrlKey: true});
  check(f.sent.length === 1 && f.sent[0].operation === 'preview', 'keyboard invokes actual closed preview');
  const id = f.sent[0].id;
  check(f.byId('preview').disabled && f.byId('editor').disabled, 'one active immutable input');
  check(f.byId('preview-output').getAttribute('aria-busy') === 'true', 'result busy while native observation pending');
  f.receive(id, 'started');
  check(f.byId('status').textContent.includes('observed state'), 'no fabricated percentage');
  f.receive('protocol', 'refused');
  check(f.byId('preview').disabled && !f.byId('cancel').disabled, 'protocol failure cannot release active process');
  f.window.LumaWorkspace.receive(null);
  check(f.byId('preview').disabled, 'malformed response does not claim stopped');
  f.document.dispatch('keydown', {key: 'Escape'});
  check(f.sent.length === 2 && f.sent[1].operation === 'cancel' && f.sent[1].id === id, 'Escape requests exact active cancellation');
  f.document.dispatch('keydown', {key: 'Escape'});
  check(f.sent.length === 2 && f.byId('preview').disabled, 'duplicate cancellation not sent; acknowledgement not exit');
  f.receive(id, 'cancel-requested');
  check(f.byId('status').textContent.includes('waiting for the process to exit'), 'cancel ack not completion');
  f.receive(id, 'cancelled');
  check(!f.byId('preview').disabled && f.byId('cancel').disabled, 'observed cancellation releases controls');
  check(f.byId('status').textContent.includes('Nothing was saved or published'), 'no-effect preview cancellation');
  f.receive(id, 'completed', {result: {}});
  check(f.byId('preview-output').children.length === 0, 'stale result ignored after cancellation');
}
{
  const f = fixture();
  f.byId('preview').dispatch('click');
  const id = f.sent[0].id;
  f.receive(id, 'validating');
  check(f.byId('status').textContent.includes('No completion yet'), 'validation is explicit progress');
  const result = {operation: 'reopen', preview_content: '<script>not executed</script>', preview_format: 'utf8-text',
    envelope_sha256: 'a'.repeat(64), validated: {canonical_envelope: '{}', receipt: {binding: {owner: 'untrusted-preview'}},
      reference: {artifact_id: 'example', version: 1, content_sha256: 'b'.repeat(64), receipt_sha256: 'c'.repeat(64)}}};
  f.receive(id, 'completed', {result});
  check(f.byId('preview-output').children[0].textContent === result.preview_content, 'result is text, not active markup');
  check(f.document.activeElement.id === 'result-heading', 'completion has keyboard focus target');
  check(f.byId('source-grounding').textContent.includes('"authenticated_owner": false'), 'grounding data not owner authority');
  check(!f.byId('reuse-source').disabled, 'verified reopened source can be explicitly selected');
  f.byId('reuse-source').dispatch('click');
  check(f.byId('editor').value === result.preview_content && f.document.activeElement.id === 'editor', 'explicit reuse preserves exact text');
  f.byId('preview').dispatch('click');
  check(f.byId('reuse-source').disabled && f.byId('source-grounding').textContent === '', 'old result cannot be reused as current while another request runs');
  f.receive(f.sent.at(-1).id, 'failed');
  check(f.byId('error').textContent.includes('No completion is claimed'), 'failed request announces accessible error');
}
{
  const f = fixture();
  f.fail(true);
  f.byId('preview').dispatch('click');
  check(f.byId('preview').disabled && f.byId('error').textContent.includes('completion is unknown'), 'submission exception is not inferred no execution');
  f.document.dispatch('keydown', {key: 'Escape'});
  check(!f.byId('cancel').disabled && f.byId('error').textContent.includes('may still run'), 'failed cancel never claims termination');
}
{
  const f = fixture();
  f.byId('envelope').focus();
  f.byId('envelope').value = '{}';
  f.byId('envelope-hash').value = 'a'.repeat(64);
  f.document.dispatch('keydown', {key: 'Enter', ctrlKey: true});
  check(f.sent[0].operation === 'reopen' && f.sent[0].expected_envelope_sha256 === 'a'.repeat(64), 'focused envelope keyboard action does not run source preview');
  f.receive(f.sent[0].id, 'completed', {result: {operation: 'animation', rendering: {frames: [
    {canonical_svg: '<svg></svg>'}, {canonical_svg: '<svg><text>second</text></svg>'}]}}});
  check(!f.byId('animation-controls').hidden, 'manual frames available');
  f.byId('next-frame').dispatch('click');
  const frame = f.byId('preview-output').children[0];
  check(frame.getAttribute('sandbox') === '' && !frame.getAttribute('allow'), 'no iframe authority');
  check(f.byId('frame').getAttribute('aria-valuetext') === 'Frame 2 of 2', 'frame range has meaningful accessible value');
  check(f.byId('next-frame').disabled && !f.byId('previous-frame').disabled, 'manual frame bounds explicit');
  check(frame.srcdoc.includes("script-src 'none'"), 'preview documents cannot execute scripts');
  f.links[2].dispatch('click');
  check(f.document.activeElement.id === 'result-heading', 'section link moves actual keyboard focus');
}
{
  const f = fixture();
  check(f.cells().length === 9 && f.cells().filter(cell => cell.tabIndex === 0).length === 1, 'bounded source table uses one roving Tab target');
  f.cells()[0].dispatch('keydown', {key: 'ArrowRight'});
  check(f.byId('sheet-location').textContent === 'B1' && f.document.activeElement.getAttribute('aria-current') === 'true', 'arrow navigation moves selection and actual focus');
  f.cells()[1].dispatch('keydown', {key: 'End', ctrlKey: true});
  check(f.byId('sheet-location').textContent === 'C3', 'Control+End reaches exact last cell');
  f.cells()[8].dispatch('keydown', {key: 'Home', ctrlKey: true});
  f.cells()[0].dispatch('keydown', {key: 'F2'});
  check(f.document.activeElement.id === 'sheet-kind', 'F2 enters labeled native-source inspector');
  f.edit(0, 0, 'text', '=1+2 <script>never executed</script>');
  f.edit(0, 1, 'number', '2'); f.edit(0, 2, 'multiply', 'B1', '3');
  const model = f.copy();
  check(model.rows[0][0].kind === 'text' && model.rows[0][0].value.startsWith('='), 'formula-looking text remains explicitly typed text');
  check(model.rows[0][2].expression.left.row === 0 && model.rows[0][2].expression.left.column === 1, 'A1 reference converted to real zero-based Rust AST');
  check(f.sent.length === 0 && f.byId('engine').value === 'spreadsheet', 'editing and copying source never simulates calculation or submits work');
  f.byId('preview').dispatch('click');
  check(f.sent.length === 1 && f.sent[0].engine === 'spreadsheet' && f.sent[0].source === JSON.stringify(model), 'actual closed native preview receives exact generated typed source');
  check(f.byId('sheet-fields').disabled && f.cells().every(cell => cell.disabled), 'grid freezes while native result is pending');
  spreadsheetCases.push({name: 'literal-text-and-reference-multiply', source: f.sent[0].source,
    expected_first_row: [{kind: 'text', value: model.rows[0][0].value}, {kind: 'number', value: '2'}, {kind: 'number', value: '6'}]});
  f.receive(f.sent[0].id, 'started'); f.receive(f.sent[0].id, 'validating');
  check(f.byId('progress').getAttribute('data-phase') === 'validating' && f.byId('progress-events').children.length === 3, 'observed state history records queued/start/validation only');
  f.byId('cancel').dispatch('click');
  f.receive(f.sent[0].id, 'completed', {result: {operation: 'spreadsheet', calculation: {canonical_source: JSON.stringify(model), values: model.rows}}});
  check(f.byId('status').textContent.includes('before cancellation took effect') && f.byId('progress').getAttribute('data-phase') === 'completed', 'observed completion wins cancellation race without claiming cancelled');
  f.byId('sheet-load').dispatch('click');
  check(f.byId('sheet-status').textContent.includes('native-verified editable source loaded'), 'only observed native source is offered for grid reload');
  check(f.copy().rows[0][2].expression.operator === 'multiply', 'native typed formula survives source reload unchanged');
}
{
  const f = fixture();
  f.byId('sheet-kind').value = 'text'; f.byId('sheet-kind').dispatch('change');
  f.byId('sheet-value').value = 'pending'; f.byId('sheet-value').dispatch('input');
  f.byId('sheet-value').focus(); f.document.dispatch('keydown', {key: 'Enter', ctrlKey: true});
  check(f.sent.length === 0 && f.document.activeElement.id === 'sheet-use', 'structured-source shortcut never executes stale raw-editor source or silently applies pending edits');
  f.cells()[1].dispatch('click');
  check(f.byId('sheet-location').textContent === 'A1' && f.byId('sheet-status').textContent.includes('Apply or discard'), 'navigation cannot silently discard inspector draft');
  f.byId('sheet-use').dispatch('click');
  check(f.byId('editor').value.includes('Manual source'), 'pending cell is not silently copied or lost');
  f.byId('sheet-cell-discard').dispatch('click');
  check(f.byId('sheet-value').value === '' && f.byId('sheet-status').textContent.includes('source grid unchanged'), 'explicit discard affects pending inspector only');
  f.edit(2, 2, 'text', 'retained');
  f.byId('sheet-rows').value = '2'; f.byId('sheet-columns').value = '2'; f.byId('sheet-resize').dispatch('click');
  check(f.byId('sheet-status').textContent.includes('discard nonblank') && f.cells().length === 9, 'shrinking nonblank grid refuses instead of truncating');
  f.edit(2, 2, 'blank');
  f.byId('sheet-rows').value = '2'; f.byId('sheet-columns').value = '2'; f.byId('sheet-resize').dispatch('click');
  check(f.cells().length === 4 && f.copy().rows.length === 2, 'explicitly cleared blank area may shrink');
  for (const [rows, columns] of [['0','2'], ['65','2'], ['2','33'], ['2.5','2'], ['02','2'], ['2','1e1']]) {
    f.byId('sheet-rows').value = rows; f.byId('sheet-columns').value = columns; f.byId('sheet-resize').dispatch('click');
    check(f.cells().length === 4 && f.byId('sheet-status').textContent.includes('Source unchanged'), 'dimension refusal preserves data '+rows+'x'+columns);
  }
  const referenced = fixture(); referenced.edit(0, 0, 'reference', 'C3');
  referenced.byId('sheet-rows').value = '2'; referenced.byId('sheet-columns').value = '3'; referenced.byId('sheet-resize').dispatch('click');
  check(referenced.cells().length === 9 && referenced.byId('sheet-status').textContent.includes('outside the grid'), 'shrinking blank area cannot strand existing formula references');
}
{
  const f = fixture();
  f.byId('sheet-rows').value = '64'; f.byId('sheet-columns').value = '32'; f.byId('sheet-resize').dispatch('click');
  check(f.cells().length === 2048 && f.cells().filter(cell => cell.tabIndex === 0).length === 1, 'maximum native grid remains bounded with one Tab target');
  f.cells()[0].dispatch('keydown', {key: 'End', ctrlKey: true});
  check(f.byId('sheet-location').textContent === 'AF64', 'native maximum A1 coordinate has exact readable label');
  f.edit(0, 0, 'reference', 'AF64');
  const model = f.copy();
  check(model.rows[0][0].expression.row === 63 && model.rows[0][0].expression.column === 31, 'maximum reference converts exactly without spreadsheet expression evaluation');
  spreadsheetCases.push({name: 'maximum-grid-last-reference', source: JSON.stringify(model),
    expected_first_row: [{kind: 'number', value: '0'}, ...Array.from({length: 31}, () => ({kind: 'blank'}))]});
}
{
  const f = fixture();
  const unchanged = () => f.byId('sheet-status').textContent.includes('Source unchanged');
  for (const value of ['A0', 'A01', 'D1', 'A64', 'AF1', 'a1', '=A1', 'A1;fetch()', '/etc/passwd', '\u202eA1']) {
    f.edit(0, 0, 'reference', value); check(unchanged(), 'hostile/out-of-grid reference refused '+JSON.stringify(value));
    f.byId('sheet-cell-discard').dispatch('click');
  }
  for (const value of ['1e3', '01', '.1', '1.', '1.0000001', '1000000000000000000000001', '1000000000000000000000000.000001', 'Infinity', 'NaN', ' 2', '\u0000']) {
    f.edit(0, 0, 'number', value); check(unchanged(), 'non-native or out-of-bound decimal refused '+JSON.stringify(value));
    f.byId('sheet-cell-discard').dispatch('click');
  }
  for (const value of ['\u0000', '\uFEFFtext', 'bare\rcarriage', '\uD800', 'x'.repeat(4097), '😀'.repeat(1025)]) {
    f.edit(0, 0, 'text', value); check(unchanged(), 'invalid control/UTF8 text bound refused');
    f.byId('sheet-cell-discard').dispatch('click');
  }
  f.edit(0, 0, 'number', '-1000000000000000000000000');
  check(!unchanged(), 'exact native magnitude boundary accepted without float rounding');
  f.edit(0, 1, 'number', '0.000001');
  spreadsheetCases.push({name: 'exact-number-bounds', source: JSON.stringify(f.copy()),
    expected_first_row: [{kind: 'number', value: '-1000000000000000000000000'}, {kind: 'number', value: '0.000001'}, {kind: 'blank'}]});
}
{
  const f = fixture();
  f.edit(0, 0, 'number', '2'); f.edit(0, 1, 'number', '3'); f.edit(0, 2, 'sum', 'A1', 'B1');
  spreadsheetCases.push({name: 'typed-range-sum', source: JSON.stringify(f.copy()),
    expected_first_row: [{kind: 'number', value: '2'}, {kind: 'number', value: '3'}, {kind: 'number', value: '5'}]});
  f.edit(0, 2, 'average', 'B2', 'A1');
  check(f.byId('sheet-status').textContent.includes('top-left'), 'reversed rectangular range refused');
  f.byId('sheet-cell-discard').dispatch('click');
  f.edit(0, 0, 'reference', 'A1');
  spreadsheetCases.push({name: 'cycle-refused-only-by-native-engine', source: JSON.stringify(f.copy()), native_refusal_required: true,
    expected_native_error: 'spreadsheet contains a reference cycle'});
  f.edit(0, 0, 'divide', '1', '3');
  spreadsheetCases.push({name: 'non-exact-division-refused-only-by-native-engine', source: JSON.stringify(f.copy()), native_refusal_required: true,
    expected_native_error: 'spreadsheet result is not exact at six decimal places'});
  check(f.sent.length === 0, 'source building never computes even an invalid cycle or non-exact quotient');
}
{
  const f = fixture();
  check(f.byId('sheet-load').disabled, 'raw unverified JSON is never silently parsed into source grid');
  f.byId('preview').dispatch('click');
  const huge = {schema_version: 1, rows: Array.from({length: 64}, () => Array.from({length: 32}, () => ({kind: 'text', value: 'x'.repeat(600)})))};
  f.receive(f.sent[0].id, 'completed', {result: {operation: 'spreadsheet', calculation: {canonical_source: JSON.stringify(huge), values: [[{kind: 'blank'}]]}}});
  f.byId('sheet-load').dispatch('click');
  check(f.cells().length === 9 && f.byId('sheet-status').textContent.includes('1 MiB'), 'oversized source import leaves existing bounded grid intact');
  f.byId('preview').dispatch('click'); f.byId('cancel').dispatch('click');
  f.receive(f.sent.at(-1).id, 'cancelled');
  check(f.document.activeElement.id === 'preview', 'observed cancellation restores source action keyboard target');
}
const args = process.argv.slice(2);
assert.ok(args.length === 0 || ((args.length === 1 || args.length === 2) && args[0] === '--emit-spreadsheet-cases'), 'closed fixture arguments required');
const output = JSON.stringify({schema_version: 1, assertions, production_javascript_executed: true,
  graphical_webkit_qualified: false, authority_returned: false,
  ...(args.length ? {spreadsheet_cases: spreadsheetCases} : {})});
if (args.length === 2) {
  writeFileSync(args[1], output + '\n', {encoding: 'utf8', flag: 'wx', mode: 0o600});
  console.log(JSON.stringify({assertions, spreadsheet_cases: spreadsheetCases.length, output: args[1], authority_returned: false}));
} else console.log(output);
