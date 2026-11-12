'use strict';
/* PORTAL: the ... menu and the optional AI summary (your own API key). Loaded after bulk.js. */
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
  { label: 'Tool check (installed / missing)', run: () => openToolCheck() },
  { label: 'Link graph (how entities connect)', run: () => openGraph() },
  { label: 'Shared infrastructure (across saved scans)', run: () => openCorrelate() },
  { label: 'Report as HTML (printable, with link graph)', run: () => downloadHtmlReport() },
  { label: 'Watchlist' + (watchUnseen ? ` (${watchUnseen} new)` : ''), run: () => openWatchlist() },
  { label: 'Watch this target', run: () => (['domain', 'ip'].includes(scanType) ? openWatchlist(lastQuery) : toast('Only a domain or IP scan can be watched')) },
  { label: 'CTF workbench (decode, flags, crypto)', run: () => openCtf() },
  { label: 'Show next steps', run: () => showNextSteps() },
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
