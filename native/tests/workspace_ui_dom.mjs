// Actual production JS in a small deterministic DOM fixture, not a graphical
// WebKit/accessibility qualification. No dependencies or browser authority.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import vm from 'node:vm';

const source = readFileSync(fileURLToPath(new URL('../../web/native-workspace.js', import.meta.url)), 'utf8');
const html = readFileSync(fileURLToPath(new URL('../../web/native-workspace.html', import.meta.url)), 'utf8');
let assertions = 0;
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
  return {byId, sent, document, receive, links, window, fail(value) { failTransport = value; }};
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
console.log(JSON.stringify({schema_version: 1, assertions, production_javascript_executed: true,
  graphical_webkit_qualified: false, authority_returned: false}));
