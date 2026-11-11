'use strict';
/* PORTAL front end, part 3/4: turning a module result into a window body (chips, tables, toolbox, pivots, share menu). */
/* =====================================================================
 R endering r*esults
 ===================================================================== */
function chipEl(c) {
  return el('span', { class: `chip tone-${c.tone || 'info'}` },
            el('b', { text: c.label }), c.value != null && c.value !== '' ? el('span', { text: String(c.value) }) : null);
}

function copy(text, node) {
  try { navigator.clipboard.writeText(text); } catch { return; }
  sfx.click();
  const old = node.title; node.title = 'copied';
  setTimeout(() => { node.title = old; }, 900);
}

function sectionEl(s) {
  const t = el('table');
  for (const [k, v] of s.rows) {
    const text = typeof v === 'object' && v ? v.text : v;
    const tone = typeof v === 'object' && v ? v.tone : null;
    const td = el('td', { class: tone ? `tone-${tone}` : '', title: 'click to copy', text: String(text ?? '') });
    td.addEventListener('click', () => copy(String(text ?? ''), td));
    t.append(el('tr', {}, el('td', { text: String(k), title: String(k) }), td));
  }
  return el('div', { class: 'sec' }, el('h4', { text: s.title }), t);
}

function listEl(items) {
  const holder = el('div'), wrap = el('div', { class: 'listbox' });
  const draw = f => {
    holder.replaceChildren();
    items.filter(x => x.includes(f)).slice(0, 400).forEach(x => {
      const d = el('div', { class: 'li', text: x, title: 'click to copy' });
      d.addEventListener('click', () => copy(x, d));
      holder.append(d);
    });
  };
  if (items.length > 12) wrap.append(el('input', { placeholder: `filter ${items.length} entries…`, oninput: e => draw(e.target.value.toLowerCase()) }));
  wrap.append(holder);
  draw('');
  return wrap;
}

function mapEl(m) {
  const lat = Number(m.lat), lon = Number(m.lon);
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  let [w, s, e, n] = (m.bbox || []).map(Number);
  if (![w, s, e, n].every(Number.isFinite)) { w = lon - .02; e = lon + .02; s = lat - .015; n = lat + .015; }
  const src = `https://www.openstreetmap.org/export/embed.html?bbox=${w}%2C${s}%2C${e}%2C${n}&layer=mapnik&marker=${lat}%2C${lon}`;
  return el('div', { class: 'mapbox' },
            el('iframe', { src, loading: 'lazy', referrerpolicy: 'no-referrer', title: 'map', sandbox: 'allow-scripts allow-same-origin' }),
            m.label ? el('div', { class: 'maplabel', text: `${lat.toFixed(4)}, ${lon.toFixed(4)} · ${m.label}` }) : null);
}

const MODULE_TITLES = { ip: 'IP intelligence', dns: 'DNS records', rdap: 'Registration (RDAP)', tls: 'TLS certificate',
  coords: 'Location', rdap_ip: 'Network registration', links: 'Pivot links', exposure: 'Exposure (Shodan)',
  reputation: 'Reputation', web: 'Site intelligence', nearby: "What's nearby", entity: 'Encyclopedia match',
  cve: 'CVE details', place: 'Place search', product: 'Product', tools: 'Local toolbox', scholar: 'Papers & journals',
  news: 'News coverage', launch: 'Search the platforms', wikidata: 'Wikidata profile' };

  function pivotsEl(w, pivots) {
    const row = el('div', { class: 'pivots' }, el('span', { class: 'lbl', text: 'pivot →' }));
    for (const p of pivots) {
      row.append(el('button', { text: p.label, title: `${p.module}: ${p.q}`, onclick: () => {
        openWindow({ module: p.module, q: p.q, title: MODULE_TITLES[p.module] || p.module, depth: Math.min(w.depth + 1, 4), parent: w.id });
      } }));
    }
    return row;
  }

  function toolboxEl(w, res) {
    const box = el('div', { class: 'tbx' });
    if (!res.actions.length) {
      box.append(el('p', { class: 'note', text: res.target
        ? 'None of the supported tools are installed. Open ⋯ → Tool check for the exact install commands.'
        : 'The toolbox needs a single host or domain.' }));
      return box;
    }
    const chk = el('input', { type: 'checkbox' });
    const out = el('pre', { class: 'toolout' });
    out.hidden = true;
    const btns = el('div', { class: 'links' });
    for (const a of res.actions) {
      const b = el('button', { class: 'btn small' + (a.intrusive ? ' danger' : ''), text: a.label + (a.intrusive ? ' ☠' : a.active ? ' ⚠' : ''),
        title: a.intrusive ? 'sends attack-style payloads: tick the box AND type the host to confirm' : a.active ? 'sends traffic to the target' : 'passive / local' });
      b.addEventListener('click', async () => {
        if (a.active && !chk.checked) { toast('Tick the authorisation box first'); return; }
        let typed = '';
        if (a.intrusive) {
          typed = prompt(`${a.label} sends attack-style payloads.\nOnly continue if you are authorised to test this target.\n\nType the host (${res.target}) to confirm:`);
          if (typed == null) return;
        }
        sfx.click(); b.disabled = true; out.hidden = false; out.textContent = `running ${a.label}…`;
        const r = await api('/api/tool', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ tool: a.id, target: a.kind === 'url' ? (res.url || res.target) : res.target,
                                                   confirm: chk.checked, confirm_target: typed }) });
        out.textContent = r.error ? '⚠ ' + r.error : `$ ${r.command}\n\n${r.output}`;
        if (r.error) sfx.error(); else sfx.done(false);
        if (!r.error && r.findings && r.findings.length) hooks.findings(a.id, res.target, r.findings);
        w.extra = (w.extra || '') + `\n\n--- ${a.label} ---\n${out.textContent}`;
        b.disabled = false;
      });
      btns.append(b);
    }
    box.append(el('label', { class: 'auth' }, chk, ` I own or am authorised to test ${res.target} (needed for ⚠ tools)`), btns, out);
    return box;
  }

  function accountsEl(w, res) {
    const box = el('div', { class: 'accounts' });
    const accounts = Array.isArray(res.accounts) ? res.accounts : [];

    if (accounts.length) {
      box.append(el('h4', { text: `${accounts.length} ACCOUNTS FOUND` }));
      const list = el('div', { class: 'acctlist' });
      for (const a of accounts) {
        if (!a) continue;

        const img = a.image ? el('img', { src: a.image, class: 'acct-img', referrerpolicy: 'no-referrer', onerror: 'this.style.display="none"' }) : el('div', { class: 'acct-img acct-noimg', text: (a.site || '?')[0].toUpperCase() });

        const metaTable = el('table', { class: 'acct-meta-table' });
        if (a.meta && typeof a.meta === 'object') {
          for (const [k, v] of Object.entries(a.meta)) {
            if (v && typeof v !== 'object') {
              metaTable.append(el('tr', {}, el('th', { text: k }), el('td', { text: String(v) })));
            }
          }
        }

        const infoDiv = el('div', { class: 'acct-info' },
                           el('div', { class: 'acct-top' },
                              el('span', { class: 'acct-site', text: a.site || 'Unknown' }),
                              el('a', { class: 'acct-url', href: a.url || '#', target: '_blank', rel: 'noopener noreferrer', text: a.url || 'no url' })
                           ),
                           a.fullname ? el('div', { class: 'acct-fullname', text: a.fullname }) : null,
                           a.bio ? el('div', { class: 'acct-bio', text: a.bio }) : null,
                           a.tags && Array.isArray(a.tags) && a.tags.length ? el('div', { class: 'acct-tags', text: 'Tags: ' + a.tags.join(', ') }) : null,
                           metaTable.children.length ? metaTable : null
        );

        list.append(el('div', { class: 'acct' }, img, infoDiv));
      }
      box.append(list);
    } else if (!res.error) {
      box.append(el('p', { class: 'note', text: 'No accounts found with this exact handle.' }));
    }

    return box;
  }

  function renderBody(w, res) {
    const body = w.body;
    body.replaceChildren();
    w.el.classList.remove('loading', 'error');
    if (res.icon) w.icon.textContent = res.icon;
    if (res.error) {
      w.el.classList.add('error');
      setSev(w, 'info');
      body.append(el('div', { class: 'err', text: '⚠ ' + res.error }),
                  el('button', { class: 'btn small', text: 'Retry', onclick: () => load(w) }));
      sfx.error();
      return;
    }
    w.res = res;
    setSev(w, res.severity || 'info');
    sfx.arrive(w.sev);
    if (res.highlights && res.highlights.length) body.append(el('div', { class: 'chips' }, res.highlights.map(chipEl)));
    if (Array.isArray(res.accounts)) body.append(accountsEl(w, res));
    if (w.spec.module === 'coords') body.append(quickShare(w));
    if (res.image && /^(data:image\/(jpeg|png);base64,|https:\/\/)/.test(res.image))
      body.append(el('img', { class: 'thumb', src: res.image, alt: '', referrerpolicy: 'no-referrer' }));
    if (res.map) { const m = mapEl(res.map); if (m) { body.append(m); w.hasMap = true; } }
    for (const s of res.sections || []) body.append(sectionEl(s));
    if (res.list && res.list.length) body.append(listEl(res.list));
    if (res.note) body.append(el('p', { class: 'note', text: res.note }));
    if (res.links && res.links.length)
      body.append(el('div', { class: 'links' }, res.links.filter(l => /^https?:\/\//.test(l.url)).map(l =>
      el('a', { href: l.url, target: '_blank', rel: 'noopener noreferrer', text: l.label }))));
    if (res.actions) body.append(toolboxEl(w, res));
    if (res.pivots && res.pivots.length) body.append(pivotsEl(w, res.pivots));
  }

  function fitHeight(w) {
    if (layoutMode !== 'flow' || w.el.classList.contains('max')) return;
    w.el.style.height = 'auto';
    const cap = w.hasMap ? 520 : 460;
    if (w.el.offsetHeight > cap) w.el.style.height = cap + 'px';
  }

  /* =====================================================================
   S haring and* reports
   ===================================================================== */
  const cellText = v => (typeof v === 'object' && v ? v.text : v);

  function resText(w) {
    const r = w.res;
    if (!r) return '';
    const L = [`${w.titleEl.textContent}${w.spec.sub ? ' — ' + w.spec.sub : ''}`];
    for (const c of r.highlights || []) L.push(`• ${c.label}${c.value != null && c.value !== '' ? ': ' + c.value : ''}`);
    if (Array.isArray(r.accounts) && r.accounts.length) {
      L.push('', `Accounts found (${r.accounts.length})`);
      for (const a of r.accounts.slice(0, 80)) {
        const parts = [a.site, a.url];
        if (a.fullname) parts.push(`[${a.fullname}]`);
        if (a.bio) parts.push(`("${a.bio}")`);
        L.push('  ' + parts.join(' - '));
      }
    }
    for (const s of r.sections || []) { L.push('', s.title); for (const [k, v] of s.rows) L.push(`  ${k}: ${cellText(v)}`); }
    if (r.list && r.list.length) L.push('', ...r.list.slice(0, 60).map(x => '  ' + x));
    if (r.note) L.push('', r.note);
    for (const l of r.links || []) L.push(`${l.label}: ${l.url}`);
    if (w.extra) L.push(w.extra);
    return L.join('\n');
  }

  function locMessage(w) {
    const m = w.res && w.res.map;
    if (!m) return '';
    const lat = Number(m.lat), lon = Number(m.lon);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) return '';
    const near = (w.res.sections || []).flatMap(s => s.rows).find(x => x[0] === 'Nearest');
    const place = near ? String(cellText(near[1])) : '';
    return `Your location${place ? ': ' + place : ':'}\nhttps://www.google.com/maps?q=${lat},${lon}\n(${lat.toFixed(5)}, ${lon.toFixed(5)})`;
  }

  function copyText(text) {
    navigator.clipboard.writeText(text).then(() => { sfx.click(); toast('Copied', true); }, () => toast('Copy blocked by the browser'));
  }

  function shareItems(text, subject) {
    return [
      { label: 'WhatsApp', run: () => window.open('https://wa.me/?text=' + encodeURIComponent(text), '_blank', 'noopener') },
      { label: 'SMS', run: () => { location.href = 'sms:?body=' + encodeURIComponent(text); } },
      { label: 'Telegram', run: () => window.open('https://t.me/share/url?url=%20&text=' + encodeURIComponent(text), '_blank', 'noopener') },
      { label: 'Email', run: () => { location.href = 'mailto:?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(text); } },
      { label: 'Copy text', run: () => copyText(text) },
    ];
  }

  let menuEl = null;
  function closeMenu() { if (menuEl) { menuEl.remove(); menuEl = null; } }
  function openMenu(anchor, items) {
    closeMenu(); sfx.click();
    const r = anchor.getBoundingClientRect();
    menuEl = el('div', { class: 'smenu' }, items.map(i => el('button', { text: i.label, onclick: () => { closeMenu(); i.run(); } })));
    menuEl.style.left = Math.max(8, Math.min(r.left, innerWidth - 200)) + 'px';
    const below = r.bottom + 4, h = items.length * 33 + 12;
    menuEl.style.top = (below + h > innerHeight ? Math.max(8, r.top - h - 4) : below) + 'px';
    document.body.append(menuEl);
  }
  document.addEventListener('pointerdown', e => {
    if (menuEl && !e.target.closest('.smenu') && !e.target.closest('[data-share]')) closeMenu();
  }, true);

    function showShare(w, anchor) {
      if (!w.res) return toast('Nothing to share yet');
      openMenu(anchor, shareItems(resText(w), `Portal: ${w.titleEl.textContent}`));
    }

    function quickShare(w) {
      const go = fn => () => { const m = locMessage(w); if (m) fn(m); else toast('No coordinates to send'); };
      return el('div', { class: 'quick' },
                el('span', { class: 'lbl', text: 'Send this location →' }),
                el('button', { text: 'WhatsApp', onclick: go(m => window.open('https://wa.me/?text=' + encodeURIComponent(m), '_blank', 'noopener')) }),
                el('button', { text: 'SMS', onclick: go(m => { location.href = 'sms:?body=' + encodeURIComponent(m); }) }),
                el('button', { text: 'Copy', onclick: go(copyText) }));
    }
