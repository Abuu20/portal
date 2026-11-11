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
let toolFindings = [];           // structured results parsed from tools you ran (ports, endpoints, CVE ids, ...)
const RISKY_PORTS = { 21: 'FTP', 23: 'Telnet', 445: 'SMB', 1433: 'MSSQL', 2375: 'Docker API', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
  5900: 'VNC', 5984: 'CouchDB', 6379: 'Redis', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB' };
const WEB_PORTS = new Set([80, 443, 8080, 8443]);

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
  const F = { bad: [], warn: [], tech: [], ports: [], risky: [], vulns: [], ip: null, web: null, login: false, hasCveWin: null,
              epss: {}, kev: false, hasWebWin: false };
  for (const w of wins.values()) {
    if (!w.res || ['root', 'next', 'diff', 'ai'].includes(w.id)) continue;
    const m = w.spec.module, r = w.res;
    if (w.sev === 'bad') F.bad.push(w); else if (w.sev === 'warn') F.warn.push(w);
    Object.assign(F.epss, r.epss || {});
    if ((r.highlights || []).some(c => /^Known exploited/.test(c.label))) F.kev = true;
    if (m === 'web') F.hasWebWin = true;
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
  // what the tools you ran found (see /api/tool "findings")
  const fs = toolFindings;
  F.scanPorts = fs.filter(f => f.type === 'port');
  F.scanTarget = (fs.find(f => f.type === 'port') || {}).target || F.ip;
  F.scanRisky = F.scanPorts.filter(p => RISKY_PORTS[p.port]).map(p => `${p.port}/${RISKY_PORTS[p.port]}`);
  F.scanWeb = F.scanPorts.find(p => WEB_PORTS.has(p.port));
  F.endpoints = fs.filter(f => f.type === 'endpoint');
  F.paramUrls = F.endpoints.filter(e => e.params && e.params.length);
  F.findCves = [...new Set(fs.filter(f => f.type === 'cve').map(f => f.id))];
  F.verified = fs.filter(f => f.type === 'vuln');
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
  for (const v of F.verified.slice(0, 3))
    add('vuln:' + v.detail.slice(0, 40), 100, 'bad', `${v.tool} reports a possible vulnerability`, `${v.detail.slice(0, 160)}. Verify it by hand before treating it as real.`, { type: 'none' });
  for (const w of F.bad.slice(0, 4))
    add('bad:' + w.id, 100, 'bad', `Review “${w.titleEl.textContent}”`, `Critical: ${worstChip(w)}`, { type: 'focus', id: w.id });
  if (F.scanRisky.length)
    add('scanrisky', 97, 'bad', 'Your scan confirms risky services', `Open now: ${F.scanRisky.slice(0, 5).join(', ')}. Restrict them with a firewall or VPN, or check they need to be public.`, { type: 'none' });
  if (F.findCves.length)
    add('findcves', 92, 'bad', `${F.findCves.length} CVE id${F.findCves.length > 1 ? 's' : ''} in the plugin scan`, `Start with ${F.findCves.slice(0, 3).join(', ')}.`,
        { type: 'open', module: 'cve', q: F.findCves[0] });
  if (F.scanWeb && F.scanTarget && !F.hasWebWin)
    add('scanweb', 65, 'info', `A web service answers on port ${F.scanWeb.port}`, 'Fingerprint it: technologies, headers, cookies, robots.txt.',
        { type: 'open', module: 'web', q: F.scanTarget });
  if (F.risky.length && F.ip)
    add('risky', 95, 'bad', 'Verify the exposed services', `Risky ports reported: ${F.risky.slice(0, 4).join(', ')}. Confirm they are really open and which versions run.`,
        { type: 'tool', tool: 'nmap_services', target: F.ip });
  if (F.vulns.length)
    add('vulns', 90, 'bad', `${F.vulns.length} known CVE${F.vulns.length > 1 ? 's' : ''} on this host`, `Start with ${F.vulns.slice(0, 3).join(', ')}.`,
        F.hasCveWin ? { type: 'focus', id: F.hasCveWin.id } : { type: 'open', module: 'cve', q: F.vulns[0] });
  if (F.web && F.tech.some(t => /wordpress/i.test(t)))
    add('wp', 85, 'warn', 'WordPress detected: list its plugins', 'Outdated plugins are the most common way in. WPProbe lists them and matches known vulnerabilities.',
        { type: 'tool', tool: 'wpprobe', target: F.web });
  if (F.web && F.login && !F.endpoints.length)
    add('login', 70, 'warn', 'A login page is exposed: map the rest of the site', 'Crawl first to see which other endpoints and parameters sit around the login.',
        { type: 'tool', tool: 'katana_crawl', target: F.web });
  for (const w of F.warn.slice(0, 3))
    add('warn:' + w.id, 60, 'warn', `Look at “${w.titleEl.textContent}”`, worstChip(w), { type: 'focus', id: w.id });
  if (F.paramUrls.length) {
    const u = F.paramUrls[0];
    add('params', 75, 'warn', `${F.paramUrls.length} endpoint${F.paramUrls.length > 1 ? 's' : ''} take parameters`, `For example ${u.url.slice(0, 90)} (${u.params.join(', ')}). Parameters are where XSS and injection live; test one if you are authorised.`,
        { type: 'tool', tool: 'dalfox', target: u.url });
  }
  if (F.ip && !F.scanPorts.length)
    add('ports', F.ports.length ? 55 : 50, 'info', F.ports.length ? 'Confirm the open ports and fingerprint the services' : 'Check the live open ports',
        'Shodan data can be days old. RustScan sweeps all ports in seconds and hands the open ones to Nmap.',
        { type: 'tool', tool: F.ports.length ? 'rustscan_nmap' : 'rustscan_ports', target: F.ip });
  if (F.web && !F.login && !F.endpoints.length)
    add('crawl', 40, 'info', 'Map the site: pages, scripts and parameters', 'Katana crawls two levels deep; uro removes near-duplicate URLs so the list stays readable.',
        { type: 'tool', tool: 'katana_crawl', target: F.web });
  if (F.web && !F.paramUrls.length)
    add('xss', 30, 'info', 'Test the parameters for XSS (intrusive)', 'Sends attack-style payloads. Only for sites you own or are authorised to test; you will be asked to type the host.',
        { type: 'tool', tool: 'dalfox', target: F.web });
  return S.sort((a, b) => b.prio - a.prio).slice(0, 8);
}

/* ---------------------------------------------------------------------
   Risk score: a heuristic 0-100 with every contribution listed, so it can be argued with.
   It is not a CVSS rating; it only says how much on screen deserves attention first.
   --------------------------------------------------------------------- */
function computeRisk(F) {
  const reasons = [];
  const add = (pts, why) => { if (pts > 0) reasons.push([pts, why]); };
  add(Math.min(45, F.bad.length * 15), `${F.bad.length} critical finding${F.bad.length > 1 ? 's' : ''} on screen`);
  add(Math.min(18, F.warn.length * 6), `${F.warn.length} warning${F.warn.length > 1 ? 's' : ''} on screen`);
  if (F.kev) add(25, 'A CVE is on the CISA Known Exploited list');
  const top = Math.max(0, ...Object.values(F.epss));
  if (top >= 0.5) add(20, `EPSS: ${(top * 100).toFixed(0)}% chance a listed CVE is exploited within 30 days`);
  else if (top >= 0.1) add(10, `EPSS: ${(top * 100).toFixed(0)}% chance a listed CVE is exploited within 30 days`);
  const risky = [...new Set([...F.risky, ...F.scanRisky])];
  if (risky.length) add(15, `Risky services exposed: ${risky.slice(0, 4).join(', ')}`);
  if (F.verified.length) add(30, `${F.verified.length} possible vulnerability line${F.verified.length > 1 ? 's' : ''} from your scanners`);
  if (F.findCves.length) add(10, `${F.findCves.length} CVE id${F.findCves.length > 1 ? 's' : ''} found by the plugin scan`);
  const score = Math.min(100, reasons.reduce((s, r) => s + r[0], 0));
  const tone = score >= 70 ? 'bad' : score >= 40 ? 'warn' : score >= 15 ? 'info' : 'ok';
  return { score, tone, reasons };
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
  if (!r.error && r.findings && r.findings.length) hooks.findings(item.act.tool, item.act.target, r.findings);
  const w = wins.get('next');
  if (w) w.extra = nextExtra(w.extra);
}

// report text for the window: the ranked list plus whatever the tools printed (rebuilt, never appended, so reruns don't duplicate)
let lastRanked = '';
function nextExtra() {
  return lastRanked + Object.values(nextState.out).map(t => `\n\n--- tool output ---\n${t}`).join('');
}

function suggestionEl(n, item, info, chk) {
  const card = el('div', { class: `nx nx-${item.tone}` },
    el('div', { class: 'nx-h' }, el('span', { class: 'nx-n', text: String(n) }), el('b', { text: item.title })),
    el('p', { class: 'note', text: item.why }));
  const row = el('div', { class: 'links' });
  const act = item.act;
  if (act.type === 'none') return card;
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
  const risk = computeRisk(F);
  renderBody(w, { icon: '➤', severity: 'info', highlights: [
    { label: 'risk', value: `${risk.score}/100`, tone: risk.tone },
    { label: 'critical', value: bad, tone: bad ? 'bad' : 'info' },
    { label: 'warnings', value: warn, tone: warn ? 'warn' : 'info' },
    { label: 'suggestions', value: items.length, tone: 'info' }],
    sections: risk.reasons.length ? [{ title: 'Why this score (heuristic)', rows: risk.reasons.map(([p, why]) => [`+${p}`, why]) }] : [] });
  lastRanked = '\nNext steps (ranked)\n' + items.map((i, n) => `  ${n + 1}. ${i.title} - ${i.why}`).join('\n');
  w.extra = nextExtra();
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
  const sig = items.map(i => i.id).join('|') + (info ? Object.values(info.actions).filter(a => a.installed).length : '')
    + '|' + toolFindings.length + '|' + computeRisk(F).score;
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
hooks.reset = () => { _prevReset(); nextDismissed = false; lastNextSig = ''; nextState.auth = false; nextState.out = {}; toolFindings = []; };
hooks.findings = (tool, target, fs) => {
  toolFindings.push(...fs.map(f => ({ ...f, tool: f.tool || tool, target })));
  lastNextSig = ''; buildNext();
};
hooks.closed = w => { _prevClosed(w); if (w.id === 'next') nextDismissed = true; };
