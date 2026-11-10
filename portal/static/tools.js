'use strict';
/* PORTAL tools: scan history + "what changed", bulk triage, email header analyzer, "more" menu.
   Loaded after app.js and uses its globals. All server text is inserted with textContent. */

let autosave = store.get('portal.autosave', '1') !== '0';
let currentScanId = null, diffShown = false, diffDismissed = false, lastSavedSig = '';
const JSON_HDR = { 'Content-Type': 'application/json' };
const postJSON = (url, body) => api(url, { method: 'POST', headers: JSON_HDR, body: JSON.stringify(body) });
const fmtTime = iso => { try { return new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }); } catch { return String(iso); } };
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el('a', { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/* =====================================================================
   Modal and drawer plumbing
   ===================================================================== */
let modalEl = null, drawerEl = null;
function closeModal() { if (modalEl) { modalEl.remove(); modalEl = null; } }
function closeDrawer() { if (drawerEl) { drawerEl.remove(); drawerEl = null; } }
function openModal(title, content, cls = '') {
  closeModal(); sfx.click();
  const panel = el('div', { class: 'modal-panel ' + cls },
    el('header', {}, el('b', { text: title }), el('span', { class: 'spacer' }), el('button', { class: 'wbtn', text: '✕', onclick: closeModal })), content);
  modalEl = el('div', { class: 'modal', onpointerdown: e => { if (e.target === modalEl) closeModal(); } }, panel);
  document.body.append(modalEl);
  return panel;
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeModal(); closeDrawer(); } });

function miniRes(res) {
  const box = el('div', { class: 'mini' });
  if (res.highlights && res.highlights.length) box.append(el('div', { class: 'chips' }, res.highlights.map(chipEl)));
  for (const s of res.sections || []) box.append(sectionEl(s));
  if (res.note) box.append(el('p', { class: 'note', text: res.note }));
  return box;
}

/* =====================================================================
   History: auto-save, the "Changes" window, snapshots
   ===================================================================== */
hooks.reset = () => { currentScanId = null; diffShown = false; diffDismissed = false; lastSavedSig = ''; hideSnapBar(); };
hooks.closed = w => { if (w.id === 'diff') diffDismissed = true; };
hooks.done = () => { if (autosave && !snapshotMode) saveScan(); };

function snapshotPayload() {
  return [...wins.values()].filter(w => w.res && w.id !== 'root' && w.id !== 'diff').sort((a, b) => a.seq - b.seq).map(w => ({
    id: w.id, module: w.spec.module, q: w.spec.q ?? '', title: w.titleEl.textContent, sub: w.spec.sub ?? '',
    depth: w.depth, parent: w.parent ?? 'root', res: w.res }));
}

async function saveScan() {
  const windows = snapshotPayload();
  if (!windows.length || !lastQuery || snapshotMode) return;
  const sig = windows.length + ':' + JSON.stringify(windows).length;
  if (sig === lastSavedSig) return;
  lastSavedSig = sig;
  const root = wins.get('root');
  const r = await postJSON('/api/save', { id: currentScanId, query: lastQuery, type: scanType || 'text',
    label: root ? root.sub.textContent : '', windows });
  if (r.error) { lastSavedSig = ''; toast('History not saved: ' + r.error); return; }
  currentScanId = r.id;
  if (r.diff) showDiff(r.diff);
}

function diffToRes(d) {
  let add = 0, rem = 0, chg = 0;
  const sections = [];
  for (const m of d.modules) {
    const rows = [];
    if (m.sev.old !== m.sev.new) rows.push(['severity', { text: `${m.sev.old} → ${m.sev.new}`, tone: m.worse ? 'bad' : 'ok' }]);
    for (const t of m.added) { rows.push(['new', { text: t, tone: 'warn' }]); add++; }
    for (const t of m.removed) { rows.push(['gone', t]); rem++; }
    for (const c of m.changed) { rows.push(['changed', { text: `${c.k}: ${c.old} → ${c.new}`, tone: 'warn' }]); chg++; }
    if (rows.length) sections.push({ title: m.title, rows });
  }
  if (d.appeared.length) sections.push({ title: 'New windows', rows: d.appeared.map(t => ['appeared', { text: t, tone: 'warn' }]) });
  if (d.disappeared.length) sections.push({ title: 'Missing now', rows: d.disappeared.map(t => ['missing', t]) });
  const highlights = [];
  if (d.worse) highlights.push({ label: 'severity', value: 'worse', tone: 'bad' });
  if (add) highlights.push({ label: 'new', value: add, tone: 'warn' });
  if (chg) highlights.push({ label: 'changed', value: chg, tone: 'warn' });
  if (rem) highlights.push({ label: 'gone', value: rem, tone: 'info' });
  return { icon: 'Δ', severity: d.worse ? 'bad' : d.total ? 'warn' : 'ok', highlights, sections,
    note: d.total ? `Compared with the scan from ${fmtTime(d.prev.ts)}. Day-by-day values (days left, last seen) are ignored.`
                  : `No differences from the scan on ${fmtTime(d.prev.ts)}.` };
}

function showDiff(d) {
  if (!d.total) {
    if (!diffShown) { diffShown = true; toast(`No changes since ${fmtTime(d.prev.ts)}`, true); }
    return;
  }
  const res = diffToRes(d);
  const dw = wins.get('diff');
  if (dw) { renderBody(dw, res); relayout(); return; }
  if (diffDismissed) return;
  diffShown = true;
  const w = createWindow({ id: 'diff', title: 'Changes', icon: 'Δ', depth: 1, parent: 'root', sub: 'since ' + fmtTime(d.prev.ts) });
  w.el.classList.remove('loading');
  edges.push({ a: 'root', b: 'diff' });
  renderBody(w, res);
  relayout(); updateStatus();
}

function hideSnapBar() { const bar = $('#snapbar'); if (bar && !bar.hidden) { bar.hidden = true; bar.replaceChildren(); } }
function showSnapBar(r) {
  const bar = $('#snapbar');
  const canRescan = !['file', 'headers', 'bulk'].includes(r.type);
  bar.replaceChildren(el('span', { text: `Viewing a saved snapshot from ${fmtTime(r.ts)} — stored data, not a live scan.` }),
    canRescan ? el('button', { class: 'btn small', text: 'Re-scan live', onclick: () => { hideSnapBar(); input.value = r.query; search(r.query); } }) : null,
    el('button', { class: 'btn small', text: 'Close snapshot', onclick: () => { reset(); input.value = ''; } }));
  bar.hidden = false;
  relayout();
}

async function openSnapshot(id) {
  const r = await api('/api/scan/' + id);
  if (r.error) return toast(r.error);
  closeDrawer(); closeModal();
  reset();
  snapshotMode = true; scanType = r.type; lastQuery = r.query;
  empty.classList.add('gone');
  makeRoot({ label: 'Saved snapshot', value: `${r.query} · ${fmtTime(r.ts)}` });
  const ws = r.snapshot.windows.slice().sort((a, b) => a.depth - b.depth);
  for (const w of ws) {
    openWindow({ id: w.id, module: w.module, q: w.q, title: w.title, sub: w.sub, depth: w.depth, parent: w.parent || 'root',
                 loader: async () => w.res });
  }
  showSnapBar(r);
}

function noteEditor(i, extra, refresh) {
  const notes = el('textarea', { class: 'hta', placeholder: 'Notes about this scan…' });
  notes.value = i.notes || '';
  const tags = el('input', { class: 'hsearch', placeholder: 'tags, comma separated' });
  tags.value = i.tags || '';
  extra.replaceChildren(notes, tags, el('button', { class: 'btn small', text: 'Save note', onclick: async () => {
    await postJSON(`/api/scan/${i.id}/meta`, { notes: notes.value, tags: tags.value });
    sfx.click(); refresh();
  } }));
}

async function showChanges(i, extra) {
  const d = await api('/api/diff?new=' + i.id);
  extra.replaceChildren();
  if (d.error) extra.append(el('p', { class: 'note', text: d.error }));
  else extra.append(miniRes(diffToRes(d)));
}

function historyItem(i, refresh) {
  const extra = el('div', { class: 'hextra' });
  const counts = el('span', { class: 'hcounts' }, [['bad', i.bad], ['warn', i.warn], ['ok', i.ok]].filter(x => x[1])
    .map(([t, n]) => el('span', { class: `hc tone-${t}`, text: String(n), title: { bad: 'critical', warn: 'warnings', ok: 'clean' }[t] })));
  const tags = (i.tags || '').split(',').map(t => t.trim()).filter(Boolean);
  const btn = (text, fn) => el('button', { class: 'hbtn', text, onclick: fn });
  const canRescan = !['file', 'headers', 'bulk'].includes(i.type);
  return el('div', { class: 'hitem' },
    el('div', { class: 'hrow1' }, counts, el('b', { class: 'hq', text: i.query, title: i.query }), el('span', { class: 'htype', text: i.type })),
    el('div', { class: 'hrow2', text: fmtTime(i.ts) }),
    tags.length ? el('div', { class: 'htags' }, tags.map(t => el('span', { class: 'htag', text: t }))) : null,
    i.notes ? el('div', { class: 'hnote', text: i.notes }) : null,
    el('div', { class: 'hbtns' },
      btn('Open', () => openSnapshot(i.id)),
      canRescan ? btn('Re-scan', () => { closeDrawer(); input.value = i.query; search(i.query); }) : null,
      btn('Changes', () => showChanges(i, extra)),
      btn('Note', () => noteEditor(i, extra, refresh)),
      btn('Delete', async () => { await api('/api/scan/' + i.id, { method: 'DELETE' }); sfx.close(); refresh(); })),
    extra);
}

async function openHistory() {
  if (drawerEl) return closeDrawer();
  sfx.click();
  const list = el('div', { class: 'hlist' });
  const filt = el('input', { class: 'hsearch', placeholder: 'filter by target, tag or note…' });
  const foot = el('div', { class: 'hfoot' });
  let armed = false, items = [];
  const clearBtn = el('button', { class: 'btn small', text: 'Clear all' });
  clearBtn.addEventListener('click', async () => {
    if (!armed) { armed = true; clearBtn.textContent = 'Click again to delete all'; setTimeout(() => { armed = false; clearBtn.textContent = 'Clear all'; }, 4000); return; }
    await postJSON('/api/history/clear', { confirm: true });
    armed = false; clearBtn.textContent = 'Clear all'; refresh();
  });
  drawerEl = el('aside', { class: 'drawer' },
    el('header', {}, el('b', { text: 'Scan history' }), el('span', { class: 'spacer' }), clearBtn, el('button', { class: 'wbtn', text: '✕', onclick: closeDrawer })),
    filt, list, foot);
  document.body.append(drawerEl);
  const draw = () => {
    list.replaceChildren();
    const f = filt.value.toLowerCase();
    const shown = items.filter(i => !f || `${i.query} ${i.tags} ${i.notes}`.toLowerCase().includes(f));
    if (!shown.length) list.append(el('p', { class: 'note', text: items.length ? 'No matches.' : 'No saved scans yet. Scans are saved automatically when they finish.' }));
    shown.forEach(i => list.append(historyItem(i, refresh)));
  };
  async function refresh() {
    const r = await api('/api/history');
    if (r.error) { list.replaceChildren(el('div', { class: 'err', text: r.error })); return; }
    items = r.items; foot.textContent = 'Stored only on this computer: ' + r.dir;
    draw();
  }
  filt.addEventListener('input', draw);
  refresh();
}

/* =====================================================================
   Bulk triage
   ===================================================================== */
function parseItems(text) {
  const out = [], seen = new Set();
  for (const tok of text.split(/[\r\n,;]+/)) {
    const t = tok.trim();
    if (!t || seen.has(t.toLowerCase())) continue;
    seen.add(t.toLowerCase()); out.push(t);
  }
  return out.slice(0, 200);
}
const csvCell = v => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
function exportCsv(rows) {
  const lines = [['indicator', 'type', 'severity', 'findings', 'errors'].map(csvCell).join(',')];
  for (const r of rows) lines.push([r.item, r.type, r.severity, (r.chips || []).map(c => `${c.label}${c.value ? ': ' + c.value : ''}`).join('; '),
    (r.errors || []).join('; ')].map(csvCell).join(','));
  download('portal-triage.csv', lines.join('\n'), 'text/csv');
}

function openBulk(prefill = '') {
  const ta = el('textarea', { class: 'bulkta', spellcheck: 'false',
    placeholder: 'One per line (or comma separated)\n\n8.8.8.8\nexample.com\nhxxps://evil[.]example/login\nCVE-2024-3094\nd41d8cd98f00b204e9800998ecf8427e\n\nIPs, domains, URLs, hashes, emails and CVE IDs. Defanged indicators are fine.' });
  ta.value = prefill;
  const info = el('span', { class: 'muted' });
  const runBtn = el('button', { class: 'btn primary', text: 'Run triage' });
  const results = el('div', { class: 'bulkres' }); results.hidden = true;
  const form = el('div', { class: 'bulkform' }, ta, el('div', { class: 'brow' }, runBtn, info));
  openModal('Bulk triage', el('div', {}, form, results), 'wide');
  ta.focus();
  const upd = () => { info.textContent = `${parseItems(ta.value).length} indicators (max 200)`; };
  ta.addEventListener('input', upd); upd();
  runBtn.addEventListener('click', () => {
    const items = parseItems(ta.value);
    if (!items.length) return toast('Paste some indicators first');
    runBulk(items, form, results);
  });
}

async function runBulk(items, form, results) {
  form.hidden = true; results.hidden = false; results.replaceChildren();
  sfx.scan();
  const rows = items.map(item => ({ item, value: item, state: 'pending', type: '', severity: 'info', chips: [], errors: [], note: '' }));
  const prog = el('span', { class: 'muted', text: `0/${rows.length} checked` });
  const filter = el('input', { class: 'hsearch bfilter', placeholder: 'filter…' });
  const sevSel = el('select', { class: 'bsel' }, [['all', 'All'], ['bad', 'Critical'], ['warn', 'Warnings'], ['ok', 'Clean'], ['info', 'Info / unsupported']]
    .map(([v, t]) => el('option', { value: v, text: t })));
  const tbody = el('tbody');
  const table = el('table', { class: 'btable' }, el('thead', {}, el('tr', {}, ['', 'Indicator', 'Type', 'Findings', ''].map(h => el('th', { text: h })))), tbody);
  results.append(el('div', { class: 'brow' }, prog, el('span', { class: 'spacer' }), filter, sevSel,
    el('button', { class: 'btn small', text: 'Export CSV', onclick: () => exportCsv(rows) }),
    el('button', { class: 'btn small', text: 'Copy summary', onclick: () => copyText(rows.map(r => `${r.item}\t${r.type}\t${r.severity}\t${(r.chips || []).map(c => c.label + ': ' + c.value).join('; ')}`).join('\n')) }),
    el('button', { class: 'btn small', text: 'Edit list', onclick: () => { form.hidden = false; results.hidden = true; } })),
    el('div', { class: 'btablewrap' }, table));
  const RANK = { bad: 3, warn: 2, ok: 1, info: 0 };
  let finished = false;
  const draw = () => {
    const f = filter.value.toLowerCase(), sv = sevSel.value;
    let view = rows.map((r, i) => ({ r, i })).filter(({ r }) => (sv === 'all' || r.severity === sv) && (!f || r.item.toLowerCase().includes(f)));
    if (finished) view.sort((a, b) => RANK[b.r.severity] - RANK[a.r.severity] || a.i - b.i);
    tbody.replaceChildren(...view.map(({ r }) => el('tr', { class: `sev-${r.severity}${r.state === 'pending' ? ' pend' : ''}` },
      el('td', {}, el('span', { class: `sevdot sd-${r.severity}` })),
      el('td', { class: 'bitem', text: r.item, title: r.item }),
      el('td', { text: r.state === 'pending' ? '…' : (r.type || '') }),
      el('td', { class: 'bchips' }, r.state === 'pending' ? el('span', { class: 'muted', text: 'checking…' })
        : r.unsupported ? el('span', { class: 'muted', text: r.note })
        : [...(r.chips || []).map(chipEl), r.errors.length ? el('span', { class: 'muted', title: r.errors.join('\n'), text: `${r.errors.length} lookup(s) failed` }) : null]),
      el('td', {}, r.unsupported || r.state === 'pending' ? null
        : el('button', { class: 'hbtn', text: 'Open', onclick: () => { closeModal(); input.value = r.value || r.item; search(r.value || r.item); } })))));
  };
  filter.addEventListener('input', draw); sevSel.addEventListener('change', draw);
  draw();
  let next = 0, done = 0;
  const worker = async () => {
    while (next < rows.length) {
      const row = rows[next++];
      const r = await api('/api/triage?q=' + encodeURIComponent(row.item));
      Object.assign(row, r.error ? { state: 'done', severity: 'info', errors: [r.error], chips: [], type: 'error' } : { ...r, item: row.item, state: 'done' });
      done++;
      prog.textContent = `${done}/${rows.length} checked`;
      if (done === rows.length) finished = true;
      draw();
    }
  };
  await Promise.all(Array.from({ length: 6 }, worker));
  sfx.done(rows.some(r => r.severity === 'bad'));
}

/* =====================================================================
   Email header analyzer
   ===================================================================== */
function analyzeHeaders(text) {
  reset(); sfx.scan();
  scanType = 'headers'; lastQuery = 'email headers';
  empty.classList.add('gone');
  makeRoot({ label: 'Pasted email headers', value: `${text.split('\n').length} lines` });
  openWindow({ id: 'headers|' + Date.now(), module: 'headers', title: 'Email headers', sub: '', depth: 1, parent: 'root',
    loader: async () => { const r = await postJSON('/api/headers', { text }); if (r.key) lastQuery = 'headers:' + r.key; return r; } });
}

function openHeaders() {
  const ta = el('textarea', { class: 'bulkta', spellcheck: 'false', placeholder: 'Paste the full raw headers here…' });
  const help = el('p', { class: 'note', text: 'Gmail: ⋮ → Show original. Outlook: File → Properties → Internet headers. Thunderbird: View → Headers → All. Apple Mail: View → Message → All Headers. Only domains and IP addresses are looked up.' });
  const run = el('button', { class: 'btn primary', text: 'Analyze headers' });
  const paste = el('button', { class: 'btn', text: 'Paste from clipboard', onclick: async () => {
    try { ta.value = await navigator.clipboard.readText(); } catch { toast('Clipboard read was blocked: paste with Ctrl+V instead'); }
  } });
  openModal('Email header analyzer', el('div', {}, help, ta, el('div', { class: 'brow' }, run, paste)), 'wide');
  ta.focus();
  run.addEventListener('click', () => {
    const text = ta.value.trim();
    if (!text) return toast('Paste the headers first');
    closeModal(); analyzeHeaders(text);
  });
}

/* =====================================================================
   Wiring
   ===================================================================== */
$('#bulk').addEventListener('click', () => openBulk());
$('#headersBtn').addEventListener('click', openHeaders);
$('#history').addEventListener('click', openHistory);
$('#more').addEventListener('click', e => openMenu(e.currentTarget, [
  { label: 'Arrange windows (reset order)', run: () => { sfx.snap(); relayout(true); } },
  { label: (linesActive() ? '✓ ' : '') + 'Show all link lines', run: toggleLines },
  { label: (autosave ? '✓ ' : '') + 'Auto-save scans to history', run: () => {
    autosave = !autosave; store.set('portal.autosave', autosave ? '1' : '0');
    toast(autosave ? 'Scans are saved automatically' : 'Auto-save is off', true);
  } },
  { label: 'Save this scan now', run: () => { lastSavedSig = ''; saveScan().then(() => toast('Saved to history', true)); } },
]));
input.addEventListener('paste', e => {                    // pasting several lines into the search box opens bulk triage
  const t = (e.clipboardData && e.clipboardData.getData('text')) || '';
  if (/\n/.test(t.trim())) { e.preventDefault(); openBulk(t); }
});

// ---- optional AI summary (your own API key; nothing leaves until you press Send)
async function openExplain() {
  const text = reportText().split('\n').filter(l => !/^Generated:/.test(l)).join('\n');
  if (!wins.size || text.length < 40) return toast('Run a scan first');
  let st;
  try { st = await (await fetch('/api/ai/status', { headers: { 'X-Portal': '1' } })).json(); } catch { return toast('Could not reach the local server'); }
  if (!st.configured) {
    openModal('AI explanation is off', el('div', {},
      el('p', { class: 'note', text: 'Add your own Anthropic API key to enable this button. Create the file below (chmod 600), put one line in it, and restart PORTAL:' }),
      el('pre', { class: 'codeblk', text: st.config_file + '\nANTHROPIC_API_KEY=sk-ant-...' }),
      el('p', { class: 'note', text: 'The key is read by the local server only and is never sent to this page. You can also set the ANTHROPIC_API_KEY environment variable.' })));
    return;
  }
  const ta = el('textarea', { class: 'bulkta', spellcheck: 'false' });
  ta.value = text.slice(0, st.max_chars);
  const send = el('button', { class: 'btn primary', text: 'Send to Anthropic and explain' });
  const cnt = el('span', { class: 'note' });
  const upd = () => { cnt.textContent = `${ta.value.length.toLocaleString()} / ${st.max_chars.toLocaleString()} characters`; };
  ta.addEventListener('input', upd); upd();
  openModal('Explain these findings', el('div', {},
    el('p', { class: 'note', text: `This exact text will be sent to the Anthropic API using your key (model ${st.model}). Edit or delete anything you don't want to share, then press Send.` }),
    ta, el('div', { class: 'brow' }, send, cnt)), 'wide');
  send.addEventListener('click', () => { const body = ta.value.slice(0, st.max_chars); closeModal(); runExplain(body); });
}
async function runExplain(body) {
  let w = wins.get('ai');
  if (!w) {
    w = createWindow({ id: 'ai', title: 'AI summary', icon: '✦', depth: 1, parent: 'root', sub: 'your API key' });
    edges.push({ a: 'root', b: 'ai' });
  }
  w.el.classList.add('loading'); relayout(); updateStatus();
  let res;
  try {
    const r = await fetch('/api/ai', { method: 'POST', headers: { 'X-Portal': '1', 'Content-Type': 'application/json' }, body: JSON.stringify({ text: body }) });
    const d = await r.json();
    if (!r.ok || d.error) throw new Error(d.error || 'Request failed');
    const rows = d.text.split(/\n{2,}/).map(p => p.trim()).filter(Boolean).map(p => ['', p]);
    res = { icon: '✦', severity: 'info', highlights: [{ label: 'model', value: d.model, tone: 'info' }], sections: [{ title: 'Explanation and next steps', rows }],
            note: 'AI-generated from the findings on screen. Verify before acting.' };
  } catch (e) {
    res = { icon: '✦', severity: 'warn', error: String(e.message || e) };
  }
  w.el.classList.remove('loading');
  if (res.error) { toast(res.error); w.res = null; closeWindow(w); return; }
  renderBody(w, res); relayout(); updateStatus(); sfx.done(false);
}
$('#explain').addEventListener('click', openExplain);
