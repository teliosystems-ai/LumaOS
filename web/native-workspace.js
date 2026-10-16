(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const encoder = new TextEncoder();
  const maximum = 1024 * 1024;
  let active = null;
  let sequence = 0;
  let frames = [];
  let reopened = null;
  const bridge = window.webkit?.messageHandlers?.workspace;
  const examples = {
    text: 'Manual source. No model or storage publication.\n',
    csv: 'Item,Quantity\nPencil,2\n',
    json: '{"message":"Manual source","schema_version":1}',
    spreadsheet: JSON.stringify({schema_version: 1, rows: [[{kind: 'number', value: '2'}, {kind: 'formula', expression: {op: 'binary', operator: 'multiply', left: {op: 'cell', row: 0, column: 0}, right: {op: 'number', value: '3'}}}]]}, null, 2),
    document: JSON.stringify({schema_version: 1, title: 'Manual document', blocks: [{kind: 'heading', level: 1, text: 'Reviewable source'}, {kind: 'paragraph', runs: [{kind: 'text', text: 'No scripts or external resources.'}]}]}, null, 2),
    diagram: JSON.stringify({schema_version: 1, title: 'Manual diagram', width: 400, height: 200, nodes: [], edges: []}, null, 2),
    animation: JSON.stringify({schema_version: 1, width: 320, height: 180, background: '#ffffff', frames_per_second: 1, frame_count: 2, sprites: []}, null, 2),
    collection: JSON.stringify({schema_version: 1, kind: 'luma-explicit-collection-v1', collection_id: 'manual', name: 'Manual collection', members: []}, null, 2),
  };

  function announce(message) { byId('status').textContent = message; }
  function busy(value) {
    byId('preview').disabled = value || !bridge;
    byId('reopen').disabled = value || !bridge;
    byId('cancel').disabled = !value;
    byId('progress').hidden = !value;
    byId('editor').setAttribute('aria-busy', String(value));
  }
  function clearPreview() {
    frames = [];
    byId('animation-controls').hidden = true;
    byId('preview-output').replaceChildren();
  }
  function textPreview(text) {
    const pre = document.createElement('pre');
    pre.tabIndex = 0;
    pre.textContent = text;
    byId('preview-output').append(pre);
  }
  function isolatedPreview(markup, title) {
    const frame = document.createElement('iframe');
    // No allow-scripts, allow-same-origin, forms, popups, navigation or downloads.
    frame.setAttribute('sandbox', '');
    frame.referrerPolicy = 'no-referrer';
    frame.title = title;
    const policy = "default-src 'none'; script-src 'none'; style-src 'none'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'";
    frame.srcdoc = `<meta http-equiv="Content-Security-Policy" content="${policy}">` + markup;
    byId('preview-output').append(frame);
  }
  function spreadsheetTable(values) {
    if (!Array.isArray(values) || values.length > 64 || values.some(row => !Array.isArray(row) || row.length > 32)) throw new Error('Invalid native table shape');
    const table = document.createElement('table');
    const caption = document.createElement('caption');
    caption.textContent = 'Exact calculated values; formula-looking text is inert';
    table.append(caption);
    const body = document.createElement('tbody');
    values.forEach((row, index) => {
      const tr = document.createElement('tr');
      const header = document.createElement('th');
      header.scope = 'row';
      header.textContent = String(index + 1);
      tr.append(header);
      row.forEach(cell => {
        const td = document.createElement('td');
        td.textContent = cell.kind === 'blank' ? '' : String(cell.value);
        tr.append(td);
      });
      body.append(tr);
    });
    table.append(body);
    byId('preview-output').append(table);
  }
  function showFrame(index) {
    const bounded = Math.max(0, Math.min(frames.length - 1, index));
    if (!frames.length) return;
    byId('frame').value = String(bounded);
    byId('preview-output').replaceChildren();
    isolatedPreview(frames[bounded].canonical_svg, `Animation frame ${bounded + 1} of ${frames.length}`);
    byId('frame-label').textContent = `${bounded + 1} / ${frames.length}`;
    byId('previous-frame').disabled = bounded === 0;
    byId('next-frame').disabled = bounded === frames.length - 1;
  }
  function display(result) {
    clearPreview();
    byId('result-data').textContent = JSON.stringify(result, null, 2);
    byId('result-note').textContent = 'Native process exited; source/result digests checked. Ephemeral preview only — not publication, membership authority or workflow completion.';
    if (result.operation === 'capture' || result.operation === 'reopen') {
      textPreview(result.preview_content);
      const artifact = result.validated || result.proposed;
      // Keep the exact full envelope, never a reconstructed partial object.
      byId('envelope').value = artifact.canonical_envelope;
      byId('envelope-hash').value = result.envelope_sha256;
      byId('result-note').textContent += ' The displayed envelope hash describes these bytes; independently verify it when selecting an external envelope.';
      if (result.operation === 'reopen') {
        reopened = {source: result.preview_content, engine: result.preview_format === 'utf8-text' ? 'text' : result.preview_format};
        // Managed native envelopes retain a typed editable-source wrapper.
        if (result.preview_format === 'json') {
          try {
            const wrapper = JSON.parse(result.preview_content);
            if (wrapper.schema_version === 1 && ['spreadsheet', 'document', 'diagram', 'animation'].includes(wrapper.engine) && typeof wrapper.source === 'object' && wrapper.source !== null) {
              reopened = {source: JSON.stringify(wrapper.source, null, 2), engine: wrapper.engine};
            }
          } catch { /* Ordinary JSON remains ordinary JSON, not an engine claim. */ }
        }
        byId('reuse-source').disabled = false;
      }
    } else if (result.operation === 'spreadsheet') {
      spreadsheetTable(result.calculation.values);
    } else if (result.operation === 'document') {
      isolatedPreview(result.rendering.canonical_html, 'Scriptless document preview');
    } else if (result.operation === 'diagram') {
      isolatedPreview(result.rendering.canonical_svg, 'Scriptless diagram preview');
    } else if (result.operation === 'animation') {
      frames = result.rendering.frames;
      byId('frame').max = String(frames.length - 1);
      byId('animation-controls').hidden = false;
      showFrame(0);
    } else {
      textPreview(result.canonical_source);
    }
  }
  function submit(operation) {
    if (!bridge || active !== null) return;
    const source = byId(operation === 'reopen' ? 'envelope' : 'editor').value;
    if (encoder.encode(source).length > (operation === 'reopen' ? maximum * 6 + 8192 : maximum)) {
      announce('Input exceeds the exact byte bound. Nothing was executed.');
      return;
    }
    const id = 'manual-' + (++sequence);
    const value = {schema_version: 1, id, operation, source};
    if (operation === 'preview') value.engine = byId('engine').value;
    else value.expected_envelope_sha256 = byId('envelope-hash').value;
    active = id;
    busy(true);
    clearPreview();
    byId('result-data').textContent = '';
    announce('Request submitted. Waiting for native process observation.');
    try { bridge.postMessage(JSON.stringify(value)); }
    catch { active = null; busy(false); announce('Native host transport refused; no completion is claimed.'); }
  }
  window.LumaWorkspace = Object.freeze({receive(event) {
    if (event.schema_version !== 1 || event.authority_returned !== false || event.committed !== false || event.owner_authenticated !== false || event.workflow_executed !== false || event.gate_closing !== false) {
      announce('Invalid native host response; result not displayed.');
      return;
    }
    if (event.id === 'protocol' && event.state === 'refused') {
      active = null; busy(false); announce('Closed preview protocol refused; no result accepted.'); return;
    }
    if (event.id !== active) return;
    if (event.state === 'started') announce('Native engine process started. Progress is observed state, not an estimated percentage.');
    else if (event.state === 'cancel-requested') { byId('cancel').disabled = true; announce('Cancellation requested; waiting for the process to exit.'); }
    else if (['completed', 'cancelled', 'failed'].includes(event.state)) {
      active = null; busy(false);
      if (event.state === 'completed') {
        try { display(event.result); announce('Native preview completed and digests verified. Nothing was saved or published.'); }
        catch { clearPreview(); announce('Native preview display refused. No result accepted.'); }
      } else announce(event.state === 'cancelled' ? 'Native process exited after cancellation. Nothing was saved or published.' : 'Native input, runtime, deadline or result refused. No completion is claimed.');
    }
  }});
  byId('preview').addEventListener('click', () => submit('preview'));
  byId('reopen').addEventListener('click', () => submit('reopen'));
  byId('cancel').addEventListener('click', () => {
    if (active !== null) bridge.postMessage(JSON.stringify({schema_version: 1, id: active, operation: 'cancel'}));
  });
  byId('example').addEventListener('click', () => { byId('editor').value = examples[byId('engine').value]; byId('editor').focus(); });
  byId('reuse-source').addEventListener('click', () => {
    if (reopened) { byId('editor').value = reopened.source; byId('engine').value = reopened.engine; byId('editor').focus(); announce('Exact reopened source copied to the editor. Recalculate explicitly; nothing is published.'); }
  });
  byId('frame').addEventListener('input', () => showFrame(Number(byId('frame').value)));
  byId('previous-frame').addEventListener('click', () => showFrame(Number(byId('frame').value) - 1));
  byId('next-frame').addEventListener('click', () => showFrame(Number(byId('frame').value) + 1));
  document.querySelector('.skip').addEventListener('click', event => { event.preventDefault(); byId('editor').focus(); });
  byId('editor').value = examples.text;
  busy(false);
  announce(bridge ? 'Manual native preview ready. No model, grants or private storage access.' : 'Installed native host unavailable. Preview execution is disabled; no browser substitute engine is used.');
})();
