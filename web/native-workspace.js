(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const encoder = new TextEncoder();
  const maximum = 1024 * 1024;
  let active = null;
  let sequence = 0;
  let frames = [];
  let reopened = null;
  let cancelRequested = false;
  let verifiedSheet = null;
  let lastSubmit = 'preview';
  let sheet = {schema_version: 1, rows: Array.from({length: 3}, () => Array.from({length: 3}, () => ({kind: 'blank'})))};
  let selectedCell = [0, 0];
  let sheetDirty = false;
  let sheetButtons = [];
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

  const binaryOperations = ['add', 'subtract', 'multiply', 'divide'];
  const aggregates = ['sum', 'minimum', 'maximum', 'average'];
  function columnName(column) { return (column >= 26 ? 'A' : '') + String.fromCharCode(65 + column % 26); }
  function cellName(row, column) { return columnName(column) + String(row + 1); }
  function exactFields(value, fields) {
    return value !== null && typeof value === 'object' && !Array.isArray(value) &&
      Object.keys(value).sort().join(',') === [...fields].sort().join(',');
  }
  function decimal(value) {
    if (typeof value !== 'string' || value.length > 40 || !/^-?(0|[1-9][0-9]{0,24})(\.[0-9]{1,6})?$/.test(value)) throw new Error('Use an exact decimal, not an exponent, expression or rounded value.');
    const [whole, fraction = ''] = value.replace(/^-/, '').split('.');
    const limit = 10n ** 24n;
    if (BigInt(whole) > limit || (BigInt(whole) === limit && /[1-9]/.test(fraction))) throw new Error('Decimal magnitude exceeds 10^24.');
    return value;
  }
  function textCell(value) {
    if (typeof value !== 'string' || encoder.encode(value).length > 4096 || value.startsWith('\uFEFF') || /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(value) || value.replace(/\r\n/g, '').includes('\r')) throw new Error('Text exceeds 4096 UTF-8 bytes or contains refused control characters.');
    for (const character of value) if (character.codePointAt(0) >= 0xD800 && character.codePointAt(0) <= 0xDFFF) throw new Error('Unpaired Unicode surrogate refused.');
    return value;
  }
  function reference(value, model = sheet) {
    const match = typeof value === 'string' && /^([A-Z]{1,2})([1-9][0-9]?)$/.exec(value);
    if (!match) throw new Error('Use an explicit current-grid cell reference such as A1.');
    const column = [...match[1]].reduce((prior, item) => prior * 26 + item.charCodeAt(0) - 64, 0) - 1;
    const row = Number(match[2]) - 1;
    if (row >= model.rows.length || column >= model.rows[0].length) throw new Error('Cell reference is outside the exact grid.');
    return {op: 'cell', row, column};
  }
  function operand(value) { return /^[A-Z]/.test(value) ? reference(value) : {op: 'number', value: decimal(value)}; }
  function validateSheet(model) {
    if (!exactFields(model, ['schema_version', 'rows']) || model.schema_version !== 1 || !Array.isArray(model.rows) || model.rows.length < 1 || model.rows.length > 64) throw new Error('Closed spreadsheet dimensions refused.');
    const width = model.rows[0]?.length;
    if (!Number.isInteger(width) || width < 1 || width > 32 || model.rows.some(row => !Array.isArray(row) || row.length !== width)) throw new Error('Source must be a rectangular grid of 1–64 by 1–32.');
    let nodes = 0;
    function coordinate(row, column) {
      if (!Number.isInteger(row) || !Number.isInteger(column) || row < 0 || column < 0 || row >= model.rows.length || column >= width) throw new Error('Typed formula reference is outside the grid.');
    }
    function expression(value, depth) {
      if (++nodes > 4096 || depth > 16 || value === null || typeof value !== 'object') throw new Error('Typed formula structural bounds exceeded.');
      if (value.op === 'number' && exactFields(value, ['op', 'value'])) decimal(value.value);
      else if (value.op === 'cell' && exactFields(value, ['op', 'row', 'column'])) coordinate(value.row, value.column);
      else if (value.op === 'negate' && exactFields(value, ['op', 'value'])) expression(value.value, depth + 1);
      else if (value.op === 'binary' && exactFields(value, ['op', 'operator', 'left', 'right']) && binaryOperations.includes(value.operator)) { expression(value.left, depth + 1); expression(value.right, depth + 1); }
      else if (value.op === 'aggregate' && exactFields(value, ['op', 'function', 'start_row', 'start_column', 'end_row', 'end_column']) && aggregates.includes(value.function)) {
        coordinate(value.start_row, value.start_column); coordinate(value.end_row, value.end_column);
        if (value.start_row > value.end_row || value.start_column > value.end_column) throw new Error('Range must run from top-left to bottom-right.');
      } else throw new Error('Unknown or extra typed formula fields refused.');
    }
    for (const row of model.rows) for (const cell of row) {
      if (cell?.kind === 'blank' && exactFields(cell, ['kind'])) continue;
      if (cell?.kind === 'text' && exactFields(cell, ['kind', 'value'])) textCell(cell.value);
      else if (cell?.kind === 'number' && exactFields(cell, ['kind', 'value'])) decimal(cell.value);
      else if (cell?.kind === 'formula' && exactFields(cell, ['kind', 'expression'])) expression(cell.expression, 0);
      else throw new Error('Unknown or extra cell fields refused.');
    }
    if (encoder.encode(JSON.stringify(model)).length > maximum) throw new Error('Whole spreadsheet source exceeds 1 MiB.');
    return model;
  }
  function sheetMessage(message) { byId('sheet-status').textContent = message; }
  function sheetFailure(error) { sheetMessage('Source unchanged: ' + error.message); }
  function inspectorKind() {
    const kind = byId('sheet-kind').value;
    byId('sheet-second-field').hidden = !binaryOperations.includes(kind) && !aggregates.includes(kind);
    byId('sheet-value').readOnly = kind === 'preserve';
    byId('sheet-value').disabled = active !== null || kind === 'blank';
  }
  function loadInspector() {
    const [row, column] = selectedCell;
    const cell = sheet.rows[row][column];
    byId('sheet-location').textContent = cellName(row, column);
    byId('sheet-kind').value = cell.kind === 'formula' ? 'preserve' : cell.kind;
    byId('sheet-value').value = cell.kind === 'formula' ? JSON.stringify(cell.expression) : cell.value || '';
    byId('sheet-second').value = '';
    sheetDirty = false;
    inspectorKind();
  }
  function renderSheet() {
    const table = byId('sheet-grid');
    table.replaceChildren();
    const caption = document.createElement('caption'); caption.textContent = 'Editable source; calculated values appear only after native completion'; table.append(caption);
    const head = document.createElement('thead'), headers = document.createElement('tr');
    const corner = document.createElement('th'); corner.textContent = 'Row'; headers.append(corner);
    sheet.rows[0].forEach((_cell, column) => { const th = document.createElement('th'); th.scope = 'col'; th.textContent = columnName(column); headers.append(th); });
    head.append(headers); table.append(head);
    const body = document.createElement('tbody'); sheetButtons = [];
    sheet.rows.forEach((row, index) => {
      const tr = document.createElement('tr'), header = document.createElement('th'); header.scope = 'row'; header.textContent = String(index + 1); tr.append(header);
      row.forEach((cell, column) => {
        const td = document.createElement('td'), button = document.createElement('button');
        button.type = 'button'; button.textContent = cell.kind === 'blank' ? '(blank)' : cell.kind === 'formula' ? 'Typed formula' : cell.value.slice(0, 80);
        button.setAttribute('aria-label', cellName(index, column) + ', ' + cell.kind + ': ' + button.textContent);
        button.setAttribute('data-sheet-cell', 'true');
        button.setAttribute('aria-current', String(index === selectedCell[0] && column === selectedCell[1]));
        button.tabIndex = index === selectedCell[0] && column === selectedCell[1] ? 0 : -1;
        button.disabled = active !== null;
        button.addEventListener('click', () => selectCell(index, column));
        button.addEventListener('keydown', event => {
          if (event.key === 'Enter' || event.key === 'F2') { event.preventDefault(); if (selectCell(index, column)) byId('sheet-kind').focus(); return; }
          let target = [index, column];
          if (event.key === 'ArrowLeft') target[1]--; else if (event.key === 'ArrowRight') target[1]++;
          else if (event.key === 'ArrowUp') target[0]--; else if (event.key === 'ArrowDown') target[0]++;
          else if (event.key === 'Home') target = [event.ctrlKey ? 0 : index, 0];
          else if (event.key === 'End') target = [event.ctrlKey ? sheet.rows.length - 1 : index, row.length - 1]; else return;
          event.preventDefault(); selectCell(Math.max(0, Math.min(sheet.rows.length - 1, target[0])), Math.max(0, Math.min(row.length - 1, target[1])));
        });
        sheetButtons.push(button); td.append(button); tr.append(td);
      }); body.append(tr);
    }); table.append(body);
    byId('sheet-rows').value = String(sheet.rows.length); byId('sheet-columns').value = String(sheet.rows[0].length);
  }
  function selectCell(row, column) {
    if (active !== null) return false;
    if (sheetDirty) { sheetMessage('Apply or discard pending inspector edits before changing cells.'); byId('sheet-cell-apply').focus(); return false; }
    selectedCell = [row, column]; renderSheet(); loadInspector();
    sheetButtons[row * sheet.rows[0].length + column].focus(); return true;
  }
  function applyCell() {
    if (active !== null) return;
    try {
      const kind = byId('sheet-kind').value, first = byId('sheet-value').value, second = byId('sheet-second').value;
      let cell;
      if (kind === 'blank') cell = {kind: 'blank'};
      else if (kind === 'text') cell = {kind, value: textCell(first)};
      else if (kind === 'number') cell = {kind, value: decimal(first)};
      else if (kind === 'reference') cell = {kind: 'formula', expression: reference(first)};
      else if (binaryOperations.includes(kind)) cell = {kind: 'formula', expression: {op: 'binary', operator: kind, left: operand(first), right: operand(second)}};
      else if (aggregates.includes(kind)) {
        const start = reference(first), end = reference(second);
        cell = {kind: 'formula', expression: {op: 'aggregate', function: kind, start_row: start.row, start_column: start.column, end_row: end.row, end_column: end.column}};
      } else if (kind === 'preserve' && sheet.rows[selectedCell[0]][selectedCell[1]].kind === 'formula') cell = sheet.rows[selectedCell[0]][selectedCell[1]];
      else throw new Error('Select an explicit supported cell type.');
      const candidate = {schema_version: 1, rows: sheet.rows.map(row => row.slice())};
      candidate.rows[selectedCell[0]][selectedCell[1]] = cell;
      sheet = validateSheet(candidate); renderSheet(); loadInspector();
      sheetMessage(cellName(...selectedCell) + ' source applied. No calculation or publication ran.');
    } catch (error) { sheetFailure(error); }
  }
  function resizeSheet() {
    if (active !== null) return;
    if (sheetDirty) { sheetMessage('Apply or discard pending inspector edits before resizing.'); return; }
    try {
      const rows = byId('sheet-rows').value, columns = byId('sheet-columns').value;
      if (!/^[1-9][0-9]?$/.test(rows) || !/^[1-9][0-9]?$/.test(columns) || Number(rows) > 64 || Number(columns) > 32) throw new Error('Dimensions must be integer rows 1–64 and columns 1–32.');
      const height = Number(rows), width = Number(columns);
      if (sheet.rows.some((row, r) => row.some((cell, c) => (r >= height || c >= width) && cell.kind !== 'blank'))) throw new Error('Resize would discard nonblank cells; clear them explicitly first.');
      const candidate = {schema_version: 1, rows: Array.from({length: height}, (_row, r) => Array.from({length: width}, (_cell, c) => sheet.rows[r]?.[c] || {kind: 'blank'}))};
      sheet = validateSheet(candidate); selectedCell = [Math.min(selectedCell[0], height - 1), Math.min(selectedCell[1], width - 1)];
      renderSheet(); loadInspector(); sheetMessage('Exact dimensions changed without discarding nonblank data. No native execution requested.');
    } catch (error) { sheetFailure(error); }
  }
  function announce(message) { byId('status').textContent = message; }
  function observed(phase, message) {
    byId('progress').setAttribute('data-phase', phase);
    const item = document.createElement('li'); item.textContent = message;
    const list = byId('progress-events');
    if (list.children.length >= 8) list.replaceChildren(...Array.from(list.children).slice(-7));
    list.append(item); announce(message);
  }
  function refuse(message) { announce(message); byId('error').textContent = message; }
  function busy(value) {
    byId('preview').disabled = value || !bridge;
    byId('reopen').disabled = value || !bridge;
    byId('cancel').disabled = !value || cancelRequested;
    byId('progress').hidden = !value;
    byId('editor').setAttribute('aria-busy', String(value));
    byId('preview-output').setAttribute('aria-busy', String(value));
    ['editor', 'engine', 'example', 'envelope', 'envelope-hash'].forEach(id => { byId(id).disabled = value; });
    byId('reuse-source').disabled = value || reopened === null;
    byId('sheet-fields').disabled = value; byId('sheet-dimensions').disabled = value;
    byId('sheet-use').disabled = value; byId('sheet-load').disabled = value || verifiedSheet === null;
    sheetButtons.forEach(button => { button.disabled = value; }); inspectorKind();
  }
  function clearPreview() {
    frames = [];
    byId('animation-controls').hidden = true;
    byId('preview-output').replaceChildren();
    byId('source-grounding').textContent = '';
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
    byId('frame').setAttribute('aria-valuetext', `Frame ${bounded + 1} of ${frames.length}`);
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
      byId('source-grounding').textContent = JSON.stringify({binding: artifact.receipt.binding, reference: artifact.reference,
        envelope_sha256: result.envelope_sha256, authenticated_owner: false, publication_proved: false}, null, 2);
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
      verifiedSheet = result.calculation.canonical_source;
      byId('sheet-load').disabled = typeof verifiedSheet !== 'string';
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
      refuse('Input exceeds the exact byte bound. Nothing was executed.');
      return;
    }
    const id = 'manual-' + (++sequence);
    const value = {schema_version: 1, id, operation, source};
    if (operation === 'preview') value.engine = byId('engine').value;
    else value.expected_envelope_sha256 = byId('envelope-hash').value;
    active = id;
    lastSubmit = operation === 'reopen' ? 'reopen' : 'preview';
    cancelRequested = false;
    reopened = null;
    verifiedSheet = null;
    byId('error').textContent = '';
    busy(true);
    clearPreview();
    byId('result-data').textContent = '';
    byId('result-note').textContent = 'No current result. Waiting for observed native exit and digest validation; nothing is saved or published.';
    byId('progress-events').replaceChildren();
    observed('queued', 'Request submitted. Waiting for native process observation.');
    try { bridge.postMessage(JSON.stringify(value)); }
    catch { refuse('Native host transport failed; completion is unknown. Wait for native observation, request cancellation, or close the workspace.'); }
  }
  function requestCancel() {
    if (active === null || cancelRequested || !bridge) return;
    cancelRequested = true;
    byId('cancel').disabled = true;
    observed('cancel-requested', 'Cancellation submitted; waiting for native acknowledgement and process exit. No completion is inferred.');
    try { bridge.postMessage(JSON.stringify({schema_version: 1, id: active, operation: 'cancel'})); }
    catch {
      cancelRequested = false;
      byId('cancel').disabled = false;
      refuse('Cancellation transport failed. The request may still run; no cancellation or completion is claimed.');
    }
  }
  window.LumaWorkspace = Object.freeze({receive(event) {
    if (event === null || typeof event !== 'object' || event.schema_version !== 1 || event.authority_returned !== false || event.committed !== false || event.owner_authenticated !== false || event.workflow_executed !== false || event.gate_closing !== false) {
      refuse('Invalid native host response; result not displayed. Active work is not assumed stopped.');
      return;
    }
    if (event.id === 'protocol' && event.state === 'refused') {
      refuse(active === null ? 'Closed preview protocol refused; no result accepted.' : 'Closed preview protocol refused. Active work is not assumed stopped; cancel or wait for its observed exit.'); return;
    }
    if (event.id !== active) return;
    if (event.state === 'started') observed('running', 'Native engine process started. Progress is observed state, not an estimated percentage.');
    else if (event.state === 'validating') observed('validating', 'Native process exited; validating exact source, engine, complete bytes and digests before display. No completion yet.');
    else if (event.state === 'cancel-requested') { cancelRequested = true; byId('cancel').disabled = true; observed('cancelling', 'Native cancellation acknowledged; waiting for the process to exit.'); }
    else if (['completed', 'cancelled', 'failed'].includes(event.state)) {
      const cancellationRaced = cancelRequested;
      active = null; cancelRequested = false; busy(false);
      byId('error').textContent = '';
      if (event.state === 'completed') {
        try { display(event.result); observed('completed', (cancellationRaced ? 'Completion was observed before cancellation took effect. ' : '') + 'Native preview completed and digests verified. Nothing was saved or published.'); byId('result-heading').focus(); }
        catch { clearPreview(); byId('result-data').textContent = ''; refuse('Native preview display refused. No result accepted.'); }
      } else if (event.state === 'cancelled') { observed('cancelled', 'Native process exited after cancellation. Nothing was saved or published.'); byId(lastSubmit).focus(); }
      else { observed('failed', 'Native input, runtime, deadline or result refused. No completion is claimed.'); refuse('Native input, runtime, deadline or result refused. No completion is claimed.'); byId('error').focus(); }
    }
  }});
  byId('preview').addEventListener('click', () => submit('preview'));
  byId('reopen').addEventListener('click', () => submit('reopen'));
  byId('cancel').addEventListener('click', requestCancel);
  byId('example').addEventListener('click', () => { byId('editor').value = examples[byId('engine').value]; byId('editor').focus(); });
  byId('reuse-source').addEventListener('click', () => {
    if (reopened) { byId('editor').value = reopened.source; byId('engine').value = reopened.engine; byId('editor').focus(); announce('Exact reopened source copied to the editor. Recalculate explicitly; nothing is published.'); }
  });
  byId('frame').addEventListener('input', () => showFrame(Number(byId('frame').value)));
  byId('previous-frame').addEventListener('click', () => showFrame(Number(byId('frame').value) - 1));
  byId('next-frame').addEventListener('click', () => showFrame(Number(byId('frame').value) + 1));
  byId('sheet-resize').addEventListener('click', resizeSheet);
  byId('sheet-cell-apply').addEventListener('click', applyCell);
  byId('sheet-cell-discard').addEventListener('click', () => { if (active === null) { loadInspector(); sheetMessage('Pending inspector edits discarded; source grid unchanged.'); } });
  ['sheet-kind', 'sheet-value', 'sheet-second'].forEach(id => byId(id).addEventListener(id === 'sheet-kind' ? 'change' : 'input', () => { sheetDirty = true; inspectorKind(); sheetMessage('Pending inspector edit, not yet applied to source grid.'); }));
  byId('sheet-use').addEventListener('click', () => {
    if (active !== null) return;
    if (sheetDirty) { sheetMessage('Apply or discard pending inspector edits before copying source.'); return; }
    try { byId('editor').value = JSON.stringify(validateSheet(sheet)); byId('engine').value = 'spreadsheet'; byId('editor').focus(); sheetMessage('Exact typed grid copied to source editor. Run native preview explicitly; nothing was calculated or published.'); }
    catch (error) { sheetFailure(error); }
  });
  byId('sheet-load').addEventListener('click', () => {
    if (active !== null || verifiedSheet === null) return;
    if (sheetDirty) { sheetMessage('Apply or discard pending inspector edits before replacing the grid.'); return; }
    try { const candidate = validateSheet(JSON.parse(verifiedSheet)); sheet = candidate; selectedCell = [0, 0]; renderSheet(); loadInspector(); sheetMessage('Actual native-verified editable source loaded. This is source data, not owner or workflow authority.'); }
    catch (error) { sheetFailure(error); }
  });
  document.querySelectorAll('a[href^="#"]').forEach(link => link.addEventListener('click', event => {
    event.preventDefault(); const target = byId(link.getAttribute('href').slice(1));
    if (target && !target.disabled) target.focus();
  }));
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && active !== null) { event.preventDefault(); requestCancel(); }
    else if (event.key === 'Enter' && event.ctrlKey && !event.altKey && !event.metaKey && !event.isComposing) {
      event.preventDefault();
      const focused = document.activeElement;
      if (focused?.id.startsWith('sheet-') || focused?.getAttribute('data-sheet-cell') === 'true') {
        sheetMessage(sheetDirty ? 'Apply or discard pending inspector edits before copying source; no native execution requested.' : 'Copy the grid to the source editor explicitly, then run native preview. No stale raw-editor source was executed.');
        byId('sheet-use').focus();
      } else submit(['envelope', 'envelope-hash', 'reopen'].includes(focused?.id) ? 'reopen' : 'preview');
    }
  });
  byId('editor').value = examples.text;
  renderSheet(); loadInspector(); sheetMessage('3 by 3 blank source grid. Select a cell to edit; only native execution calculates values.');
  busy(false);
  announce(bridge ? 'Manual native preview ready. No model, grants or private storage access.' : 'Installed native host unavailable. Preview execution is disabled; no browser substitute engine is used.');
})();
