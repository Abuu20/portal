'use strict';
/* PORTAL smart layer (loaded after tools.js, uses its globals):
   - Tool check: which optional tools are installed, with the exact install command for the missing ones.
   - Next steps: a ranked list of what to do with what is already on screen (e.g. WordPress found -> list plugins,
     risky open ports -> verify services). Suggestions are plain rules, nothing is sent anywhere, and nothing
     runs by itself: every tool still goes through the authorisation tick-box (and typed host for intrusive ones).
   All server text is inserted with textContent. */

let toolInfo = null, nextDismissed = false, lastNextSig = '';
const nextState = { auth: false, out: {} };
const txt = v => (v && typeof v === 'object' ? v.text : v);

async function loadToolInfo(force = false) {
  if (toolInfo && !force) return toolInfo;
  const r = await api('/api/toolstatus');
  toolInfo = r.error ? null : r;
  return toolInfo;
}

/* ---------------------------------------------------------------------
   Tool check
   --------------------------------------------------------------------- */
async function openToolCheck() {
  const info = await loadToolInfo(true);
  if (!info) return toast('Could not read the tool list from the local server');
  const cats = { recon: 'Recon', network: 'Network', web: 'Web', osint: 'OSINT' };
  const box = el('div', {});
  const missing = info.tools.filter(t => !t.installed);
  box.append(el('p', { class: 'note', text: missing.length
    ? `${info.tools.length - missing.length} of ${info.tools.length} tools installed. Missing tools never break PORTAL; their buttons simply stay hidden.`
    : 'Every optional tool is installed.' }));
  for (const [cat, label] of Object.entries(cats)) {
    const list = info.tools.filter(t => t.cat === cat);
    if (!list.length) continue;
    const tbl = el('table', {});
    for (const t of list) {
      tbl.append(el('tr', {},
        el('td', { text: t.bin, class: t.installed ? 'tone-ok' : 'tone-warn' }),
        el('td', { text: t.installed ? 'installed' : 'missing', class: t.installed ? 'tone-ok' : 'tone-warn' }),
        el('td', { text: t.tools.join(', ') }),
        el('td', {}, t.installed ? null : el('button', { class: 'btn small', text: 'Copy install', title: t.install,
          onclick: () => copyText(t.install) }))));
    }
    box.append(el('div', { class: 'sec' }, el('h4', { text: label }), tbl));
  }
  if (missing.length) {
    const all = [...new Set(missing.map(t => t.install))].join('\n');
    box.append(el('p', { class: 'note', text: 'All install commands for the missing tools:' }), el('pre', { class: 'codeblk', text: all }),
      el('button', { class: 'btn small', text: 'Copy all', onclick: () => copyText(all) }));
  }
  openModal('Tool check', box);
}

/* ---------------------------------------------------------------------
   Facts: read what is on screen
   --------------------------------------------------------------------- */
function gatherFacts() {
  const F = { bad: [], warn: [], tech: [], ports: [], risky: [], vulns: [], ip: null, web: null, login: false, hasCveWin: null };
  for (const w of wins.values()) {
    if (!w.res || ['root', 'next', 'diff', 'ai'].includes(w.id)) continue;
    const m = w.spec.module, r = w.res;
    if (w.sev === 'bad') F.bad.push(w); else if (w.sev === 'warn') F.warn.push(w);
    if (m === 'web') {
      F.web = w.spec.q;
      for (const s of r.sections || []) if (/^Technologies/.test(s.title)) for (const row of s.rows) F.tech.push(String(txt(row[1])));
      if ((r.highlights || []).some(c => c.label === 'Login form')) F.login = true;
    } else if (m === 'exposure') {
      F.ip = w.spec.q;
      for (const s of r.sections || []) {
        if (s.title === 'Open ports') for (const row of s.rows) {
          F.ports.push(String(row[0]));
          if (row[1] && typeof row[1] === 'object' && row[1].tone === 'bad') F.risky.push(String(row[0]));
        }
        if (s.title === 'Known vulnerabilities') for (const row of s.rows) F.vulns.push(String(txt(row[1])));
      }
    } else if (m === 'ip' && !F.ip) F.ip = w.spec.q;
    else if (m === 'cve' && !F.hasCveWin) F.hasCveWin = w;
  }
  return F;
}

function worstChip(w) {
  const rank = { bad: 3, warn: 2 };
  const cs = (w.res.highlights || []).filter(c => rank[c.tone]).sort((a, b) => rank[b.tone] - rank[a.tone]);
  return cs.length ? `${cs[0].label}${cs[0].value != null && cs[0].value !== '' ? ': ' + cs[0].value : ''}` : 'see the window for details';
}

/* ---------------------------------------------------------------------
   Rules -> ranked suggestions. prio: higher = earlier.
   act: {type:'tool', tool, target} | {type:'focus', id} | {type:'open', module, q}
   --------------------------------------------------------------------- */
function buildSuggestions(F) {
  const S = [];
  const add = (id, prio, tone, title, why, act) => S.push({ id, prio, tone, title, why, act });
  for (const w of F.bad.slice(0, 4))
    add('bad:' + w.id, 100, 'bad', `Review “${w.titleEl.textContent}”`, `Critical: ${worstChip(w)}`, { type: 'focus', id: w.id });
  if (F.risky.length && F.ip)
    add('risky', 95, 'bad', 'Verify the exposed services', `Risky ports reported: ${F.risky.slice(0, 4).join(', ')}. Confirm they are really open and which versions run.`,
        { type: 'tool', tool: 'nmap_services', target: F.ip });
  if (F.vulns.length)
    add('vulns', 90, 'bad', `${F.vulns.length} known CVE${F.vulns.length > 1 ? 's' : ''} on this host`, `Start with ${F.vulns.slice(0, 3).join(', ')}.`,
        F.hasCveWin ? { type: 'focus', id: F.hasCveWin.id } : { type: 'open', module: 'cve', q: F.vulns[0] });
  if (F.web && F.tech.some(t => /wordpress/i.test(t)))
    add('wp', 85, 'warn', 'WordPress detected: list its plugins', 'Outdated plugins are the most common way in. WPProbe lists them and matches known vulnerabilities.',
        { type: 'tool', tool: 'wpprobe', target: F.web });
  if (F.web && F.login)
    add('login', 70, 'warn', 'A login page is exposed: map the rest of the site', 'Crawl first to see which other endpoints and parameters sit around the login.',
        { type: 'tool', tool: 'katana_crawl', target: F.web });
  for (const w of F.warn.slice(0, 3))
    add('warn:' + w.id, 60, 'warn', `Look at “${w.titleEl.textContent}”`, worstChip(w), { type: 'focus', id: w.id });
  if (F.ip)
    add('ports', F.ports.length ? 55 : 50, 'info', F.ports.length ? 'Confirm the open ports and fingerprint the services' : 'Check the live open ports',
        'Shodan data can be days old. RustScan sweeps all ports in seconds and hands the open ones to Nmap.',
        { type: 'tool', tool: F.ports.length ? 'rustscan_nmap' : 'rustscan_ports', target: F.ip });
  if (F.web && !F.login)
    add('crawl', 40, 'info', 'Map the site: pages, scripts and parameters', 'Katana crawls two levels deep; uro removes near-duplicate URLs so the list stays readable.',
        { type: 'tool', tool: 'katana_crawl', target: F.web });
  if (F.web)
    add('xss', 30, 'info', 'Test the parameters for XSS (intrusive)', 'Sends attack-style payloads. Only for sites you own or are authorised to test; you will be asked to type the host.',
        { type: 'tool', tool: 'dalfox', target: F.web });
  return S.sort((a, b) => b.prio - a.prio).slice(0, 8);
}

/* ---------------------------------------------------------------------
   The "Next steps" window
   --------------------------------------------------------------------- */
async function runSuggested(item, meta, chk, out, btn) {
  if (meta.active && !chk.checked) return toast('Tick the authorisation box first');
  let typed = '';
  if (meta.intrusive) {
    const host = String(item.act.target).replace(/^https?:\/\//i, '').split(/[/:?#]/)[0];
    typed = prompt(`${meta.label} sends attack-style payloads.\nOnly continue if you are authorised to test this target.\n\nType the host (${host}) to confirm:`);
    if (typed == null) return;
  }
  sfx.click(); btn.disabled = true; out.hidden = false; out.textContent = `running ${meta.label}…`;
  const r = await postJSON('/api/tool', { tool: item.act.tool, target: item.act.target, confirm: chk.checked, confirm_target: typed });
  out.textContent = r.error ? '⚠ ' + r.error : `$ ${r.command}\n\n${r.output}`;
  nextState.out[item.id] = out.textContent;
  if (r.error) sfx.error(); else sfx.done(false);
  btn.disabled = false;
  const w = wins.get('next');
  if (w) w.extra = (w.extra || '') + `\n\n--- ${meta.label} ---\n${out.textContent}`;
}

function suggestionEl(n, item, info, chk) {
  const card = el('div', { class: `nx nx-${item.tone}` },
    el('div', { class: 'nx-h' }, el('span', { class: 'nx-n', text: String(n) }), el('b', { text: item.title })),
    el('p', { class: 'note', text: item.why }));
  const row = el('div', { class: 'links' });
  const act = item.act;
  if (act.type === 'focus') {
    row.append(el('button', { class: 'btn small', text: 'Show window', onclick: () => { const t = wins.get(act.id); if (t) { t.min ? restore(t) : flash(t); } } }));
  } else if (act.type === 'open') {
    row.append(el('button', { class: 'btn small', text: 'Open', onclick: () =>
      openWindow({ module: act.module, q: act.q, title: MODULE_TITLES[act.module] || act.module, depth: 2, parent: 'next' }) }));
  } else if (act.type === 'tool') {
    const meta = info && info.actions && info.actions[act.tool];
    const out = el('pre', { class: 'toolout' });
    out.hidden = !nextState.out[item.id];
    out.textContent = nextState.out[item.id] || '';
    if (!meta) return card;
    if (!meta.installed) {
      row.append(el('span', { class: 'muted', text: `${meta.bin} is not installed:` }),
                 el('button', { class: 'btn small', text: 'Copy install command', title: meta.install, onclick: () => copyText(meta.install) }));
    } else {
      const b = el('button', { class: 'btn small' + (meta.intrusive ? ' danger' : ''), text: 'Run ' + meta.label + (meta.intrusive ? ' ☠' : meta.active ? ' ⚠' : '') });
      b.addEventListener('click', () => runSuggested(item, meta, chk, out, b));
      row.append(b);
    }
    card.append(row, out);
    return card;
  }
  card.append(row);
  return card;
}

function fillNext(w, F, items, info) {
  const bad = F.bad.length, warn = F.warn.length;
  renderBody(w, { icon: '➤', severity: 'info', highlights: [
    { label: 'critical', value: bad, tone: bad ? 'bad' : 'info' },
    { label: 'warnings', value: warn, tone: warn ? 'warn' : 'info' },
    { label: 'suggestions', value: items.length, tone: 'info' }] });
  w.extra = '\nNext steps (ranked)\n' + items.map((i, n) => `  ${n + 1}. ${i.title} - ${i.why}`).join('\n');
  const chk = el('input', { type: 'checkbox' });
  chk.checked = nextState.auth;
  chk.addEventListener('change', () => { nextState.auth = chk.checked; });
  const list = el('div', { class: 'nxlist' }, items.map((it, n) => suggestionEl(n + 1, it, info, chk)));
  const hasTool = items.some(i => i.act.type === 'tool');
  w.body.append(
    hasTool ? el('label', { class: 'auth nxauth' }, chk, ' I own or am authorised to test this target (needed for ⚠ and ☠ tools)') : null,
    list,
    el('p', { class: 'note', text: 'Suggestions come from simple rules over the results on screen. Nothing runs until you press a button.' }));
}

async function buildNext(force = false) {
  if (snapshotMode || (nextDismissed && !force) || !wins.has('root')) return;
  if (['file', 'headers', 'bulk'].includes(scanType)) return;
  const sess = session;
  const info = await loadToolInfo();
  if (sess !== session) return;
  const F = gatherFacts();
  const items = buildSuggestions(F);
  if (!items.length) { if (force) toast('Nothing to suggest yet', true); return; }
  const sig = items.map(i => i.id).join('|') + (info ? Object.values(info.actions).filter(a => a.installed).length : '');
  let w = wins.get('next');
  if (w && sig === lastNextSig) return;
  lastNextSig = sig;
  if (!w) {
    w = createWindow({ id: 'next', title: 'Next steps', icon: '➤', depth: 1, parent: 'root', sub: 'ranked by risk' });
    w.el.classList.remove('loading');
    edges.push({ a: 'root', b: 'next' });
  }
  fillNext(w, F, items, info);
  relayout(); updateStatus();
  if (force) flash(w);
}

function showNextSteps() { nextDismissed = false; lastNextSig = ''; buildNext(true); }

const _prevDone = hooks.done, _prevReset = hooks.reset, _prevClosed = hooks.closed;
hooks.done = () => { _prevDone(); buildNext(); };
hooks.reset = () => { _prevReset(); nextDismissed = false; lastNextSig = ''; nextState.auth = false; nextState.out = {}; };
hooks.closed = w => { _prevClosed(w); if (w.id === 'next') nextDismissed = true; };
