'use strict';
/* PORTAL: Notebook window (local notes and evidence, exportable as Markdown). */
async function saveNote(title, body = '', tag = '') {
  const x = await postJSON('/api/notes', { title, body, tag });
  toast(x.error || 'Saved to notebook', !x.error);
}

async function openNotes() {
  const r = await api('/api/notes');
  if (r.error) return toast(r.error);
  const title = el('input', { class: 'hsearch', placeholder: 'title, e.g. “web-100: found /admin”' });
  const tag = el('input', { class: 'hsearch', placeholder: 'tag (optional): web, crypto, osint…', style: 'max-width:240px' });
  const text = el('textarea', { class: 'bulkta', placeholder: 'details, credentials found in the lab, flag candidates…' });
  const add = el('button', { class: 'btn primary small', text: 'Save note' });
  add.addEventListener('click', async () => { if (!title.value.trim()) return toast('Give the note a title'); await saveNote(title.value, text.value, tag.value); closeModal(); openNotes(); });
  const md = () => r.items.slice().reverse().map(n => `## ${n.title}${n.tag ? ' [' + n.tag + ']' : ''}\n_${n.ts}_\n\n${n.body}\n`).join('\n');
  const body = el('div', { class: 'watch' }, el('div', { class: 'brow' }, title, tag), text,
    el('div', { class: 'brow' }, add, el('button', { class: 'btn small', text: 'Export all as Markdown', onclick: () => { if (!r.items.length) return toast('No notes yet'); download('portal-notes.md', md(), 'text/markdown'); } })));
  for (const n of r.items) body.append(el('div', { class: 'corr-card' },
    el('div', { class: 'corr-h' }, el('b', { text: n.title }), n.tag ? el('span', { class: 'corr-tag', text: n.tag }) : null, el('span', { class: 'note', text: '  ' + fmtTime(n.ts) })),
    n.body ? el('pre', { class: 'codeblk', text: n.body }) : null,
    el('div', { class: 'corr-scans' }, el('button', { class: 'btn small', text: 'Copy', onclick: () => copyText((n.title + '\n' + n.body).trim()) }),
      el('button', { class: 'btn small', text: 'Delete', onclick: async () => { await postJSON(`/api/notes/${n.id}/delete`, {}); closeModal(); openNotes(); } }))));
  if (!r.items.length) body.append(el('p', { class: 'note', text: 'No notes yet. Flags found in the CTF workbench can be saved here with one click.' }));
  openModal('Notebook', body, 'wide');
}
