'use strict';
/* PORTAL: watchlist window (re-scan domains / IPs on a schedule, alert on changes). Loaded after correlate.js. */
let watchUnseen = 0;
const hoursLabel = h => (h >= 168 ? 'week' : h >= 24 ? (h / 24) + ' day' + (h > 24 ? 's' : '') : h + ' hours');

async function refreshWatchBadge(announce) {
  let r; try { r = await api('/api/watch'); } catch { return null; }
  if (!r || r.error) return null;
  if (announce && r.unseen > watchUnseen) toast(`Watchlist: ${r.unseen} change${r.unseen > 1 ? 's' : ''} detected. Open ⋯ → Watchlist.`);
  watchUnseen = r.unseen;
  return r;
}

async function openWatchlist(addTarget) {
  const r = await refreshWatchBadge(false);
  if (!r) return toast('Could not reach the local server');
  const body = el('div', { class: 'watch' });
  const input = el('input', { class: 'hsearch', placeholder: 'domain or IP address to watch', value: addTarget || '' });
  const sel = el('select', { class: 'hsearch', style: 'width:auto' }, ...r.intervals.map(h => el('option', { value: String(h), text: 'every ' + hoursLabel(h), selected: h === 24 ? '' : null })));
  const add = el('button', { class: 'btn primary small', text: 'Watch' });
  add.addEventListener('click', async () => {
    const x = await postJSON('/api/watch', { target: input.value, interval_h: Number(sel.value) });
    if (x.error) return toast(x.error);
    toast('Watching ' + x.target + '. The first scan runs within a few minutes.', true); closeModal(); openWatchlist();
  });
  input.addEventListener('keydown', e => { if (e.key === 'Enter') add.click(); });
  body.append(el('p', { class: 'note', text: 'PORTAL re-scans these targets by itself (the same passive lookups as a normal scan, never the active tools) and tells you when something changed. It only runs while PORTAL is running. Domains and IP addresses only.' }),
    el('div', { class: 'brow' }, input, sel, add));
  if (r.items.length) {
    body.append(el('div', { class: 'lg-sec', text: `Watching (${r.items.length})` }));
    for (const w of r.items) {
      const run = el('button', { class: 'btn small', text: 'Scan now' });
      run.addEventListener('click', async () => {
        run.disabled = true; run.textContent = 'scanning…';
        const x = await postJSON(`/api/watch/${w.id}/run`, {});
        toast(x.alert ? 'Changes found for ' + w.target : 'No changes for ' + w.target, !x.alert); closeModal(); openWatchlist();
      });
      const rm = el('button', { class: 'btn small', text: 'Remove', onclick: async () => { await postJSON(`/api/watch/${w.id}/delete`, {}); closeModal(); openWatchlist(); } });
      body.append(el('div', { class: 'corr-card' },
        el('div', { class: 'corr-h' }, el('b', { text: w.target }), el('span', { class: 'note', text: `  every ${hoursLabel(w.interval_h)} · ` + (w.last_run ? 'last ' + fmtTime(w.last_run) : 'not scanned yet') })),
        w.error ? el('div', { class: 'note', style: 'color:var(--warn)', text: 'Last run failed: ' + w.error }) : null,
        el('div', { class: 'corr-scans' }, run, w.last_scan ? el('button', { class: 'btn small', text: 'Open last scan', onclick: () => openSnapshot(w.last_scan) }) : null, rm)));
    }
  }
  if (r.alerts.length) {
    body.append(el('div', { class: 'lg-sec', text: 'Changes detected' }));
    for (const a of r.alerts) {
      body.append(el('div', { class: 'corr-card' + (a.worse ? ' bad' : '') },
        el('div', { class: 'corr-h' }, a.seen ? null : el('span', { class: 'corr-tag', text: 'new' }), el('b', { text: ' ' + a.target }), el('span', { class: 'note', text: '  ' + fmtTime(a.ts) })),
        el('div', { class: 'note', text: a.summary }),
        el('div', { class: 'corr-scans' }, el('button', { class: 'btn small', text: 'Open this scan', onclick: () => openSnapshot(a.scan_id) }))));
    }
    if (r.unseen) { postJSON('/api/alerts/seen', {}).then(() => { watchUnseen = 0; }); }
  } else if (r.items.length) body.append(el('p', { class: 'note', text: 'No changes detected so far.' }));
  openModal('Watchlist', body, 'wide');
}

setTimeout(() => refreshWatchBadge(true), 4000);              // tell me about changes found while PORTAL was in the background
setInterval(() => refreshWatchBadge(true), 5 * 60 * 1000);
