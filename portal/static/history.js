'use strict';
/* PORTAL: shared helpers (modal, drawer, postJSON), scan history, snapshots and "what changed".
   Loaded after app-search.js and uses its globals. bulk.js and menu.js follow. All server text is inserted with textContent. */

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
  return [...wins.values()].filter(w => w.res && w.id !== 'root' && w.id !== 'diff' && w.id !== 'next' && w.id !== 'surface' && w.id !== 'graph').sort((a, b) => a.seq - b.seq).map(w => ({
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
