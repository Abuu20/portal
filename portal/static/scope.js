'use strict';
/* PORTAL: Scope & lab mode window. The list of hosts you may test, an optional lock for active tools, and lab mode for private ranges. */
async function openScope(prefill = '') {
  const r = await api('/api/scope');
  if (r.error) return toast(r.error);
  const body = el('div', { class: 'watch' });
  const input = el('input', { class: 'hsearch', placeholder: 'domain, IP or CIDR, e.g. target.htb or 10.10.10.0/24', value: prefill });
  const add = el('button', { class: 'btn primary small', text: 'Add' });
  add.addEventListener('click', async () => { const x = await postJSON('/api/scope', { entry: input.value }); if (x.error) return toast(x.error); closeModal(); openScope(); });
  input.addEventListener('keydown', e => { if (e.key === 'Enter') add.click(); });
  const toggle = (key, label, help) => {
    const cb = el('input', { type: 'checkbox' }); cb.checked = !!r[key];
    cb.addEventListener('change', async () => { await postJSON('/api/scope/settings', { [key]: cb.checked }); toast(cb.checked ? label + ' is ON' : label + ' is off', true); });
    return el('label', { class: 'nxauth' }, cb, el('span', {}, el('b', { text: label }), el('br'), el('span', { class: 'note', text: help })));
  };
  body.append(el('p', { class: 'note', text: 'List what you are allowed to test: the CTF machines, the programme’s in-scope assets. Nothing here is sent anywhere; it is stored on this computer.' }),
    el('div', { class: 'brow' }, input, add),
    toggle('enforce', 'Scope lock', 'Active tools and the attack-surface map refuse any host that is not on the list. Recommended for bug bounty.'),
    toggle('lab', 'Lab mode', 'Lets PORTAL’s site, URL and surface lookups reach PRIVATE addresses (for example HackTheBox 10.10.x.x over the VPN), but only for hosts on the list. Loopback and cloud-metadata addresses are never allowed.'));
  if (r.items.length) body.append(el('div', { class: 'lg-sec', text: `In scope (${r.items.length})` }), ...r.items.map(x => el('div', { class: 'corr-card' },
    el('b', { class: 'corr-h', text: x.entry }), el('div', { class: 'corr-scans' },
      el('button', { class: 'btn small', text: 'Scan', onclick: () => { closeModal(); $('#q').value = x.entry; $('#go').click(); } }),
      el('button', { class: 'btn small', text: 'Remove', onclick: async () => { await postJSON(`/api/scope/${x.id}/delete`, {}); closeModal(); openScope(); } })))));
  else body.append(el('p', { class: 'note', text: 'The list is empty. With Scope lock on, active tools stay blocked until you add a target.' }));
  openModal('Scope & lab mode', body, 'wide');
}
