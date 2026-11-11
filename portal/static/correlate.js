'use strict';
/* PORTAL: "Shared infrastructure" - what different saved scans have in common (IPs, networks, nameservers, CVEs...). */
async function openCorrelate() {
  const r = await api('/api/correlate');
  if (r.error) return toast(r.error);
  const body = el('div', { class: 'corr' });
  if (!r.groups.length) {
    body.append(el('p', { class: 'note', text: r.scans < 2
      ? 'Needs at least two saved scans of different targets. Scan a second target, then come back.'
      : `Compared ${r.scans} saved targets and found nothing shared yet. Shared IPs, networks, nameservers or vulnerabilities will show up here.` }));
  } else {
    body.append(el('p', { class: 'note', text: `Compared ${r.scans} saved targets (latest scan of each). Highest-value links first.` }));
    for (const g of r.groups) {
      const s = GRAPH_TYPES[g.type] || {};
      const names = el('div', { class: 'corr-scans' }, ...g.scans.map(sc => el('button', { class: 'btn small', text: sc.query, title: 'Open this saved scan', onclick: () => openSnapshot(sc.id) })));
      body.append(el('div', { class: 'corr-card' + (g.tone === 'bad' ? ' bad' : '') },
        el('div', { class: 'corr-h' }, el('i', { style: `color:${s.color || '#888'}`, text: (s.glyph || '•') + ' ' }), el('b', { text: g.label }),
          el('span', { class: 'note', text: `  ${s.name || g.type} · shared by ${g.scans.length} targets` }), g.common ? el('span', { class: 'corr-tag', text: 'common provider' }) : null),
        el('div', { class: 'note', text: 'via ' + g.via.join(', ') }), names));
    }
  }
  openModal('Shared infrastructure', body, 'wide');
}
