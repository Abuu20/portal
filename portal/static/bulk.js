'use strict';
/* PORTAL: bulk triage (paste up to 200 indicators) and the email-header analyzer. Loaded after history.js. */
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
