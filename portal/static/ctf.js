'use strict';
/* PORTAL: CTF workbench (decode anything, flag finder, hashes, JWT, RSA, classic ciphers). Offline helpers; nothing touches a target. */
const CTF_TOOLS = {
  magic:    { label: 'Decode anything', hint: 'Paste anything encoded. PORTAL tries base64, hex, binary, base32/58/85, URL, ROT13, Caesar, Atbash, Morse, XOR, gzip and chains them.', fields: ['text'], prefix: true },
  flags:    { label: 'Find flags', hint: 'Looks for flag{...}, HTB{...}, picoCTF{...} and your own prefix in pasted text.', fields: ['text'], prefix: true },
  hash:     { label: 'Identify hash', hint: 'Guesses the hash type and the hashcat mode to use.', fields: ['text'] },
  jwt:      { label: 'JWT', hint: 'Decodes the token (never verifies or forges it) and points out common weaknesses.', fields: ['text'] },
  rsa:      { label: 'RSA', hint: 'Tries the textbook weaknesses: p/q given, small e, close primes, Wiener, small factors. Numbers in decimal or 0x hex.', fields: ['n', 'e', 'c', 'p', 'q', 'd'] },
  vigenere: { label: 'Vigenère', hint: 'Recovers the key and text from ~40+ letters of ciphertext.', fields: ['text'] },
  xorkey:   { label: 'Repeating-key XOR', hint: 'Recovers the key from ~40+ bytes. Choose how the data is written.', fields: ['text', 'encoding'] },
};

function ctfResult(tool, r) {
  const box = el('div', { class: 'ctf-out' });
  if (r.error) { box.append(el('div', { class: 'err', text: r.error })); return box; }
  const flags = a => (a && a.length ? el('div', { class: 'ctf-flags' }, ...a.map(f => el('code', { class: 'ctf-flag', text: f, title: 'Click to copy', onclick: () => copyText(f) }))) : null);
  if (tool === 'magic') {
    box.append(flags(r.flags) || el('p', { class: 'note', text: 'No flag found automatically. Best decodings below.' }));
    for (const x of r.results) box.append(el('div', { class: 'corr-card' }, el('div', { class: 'note', text: x.chain.join(' → ') }), el('pre', { class: 'codeblk', text: x.text })));
    if (!r.results.length) box.append(el('p', { class: 'note', text: 'None of the decoders produced readable text.' }));
  } else if (tool === 'flags') {
    box.append(flags(r.flags) || el('p', { class: 'note', text: 'No flag-shaped text found. Try “Decode anything”, or add your CTF’s prefix.' }));
  } else if (tool === 'hash') {
    box.append(...(r.matches.length ? r.matches.map(m => el('div', { class: 'corr-card' }, el('b', { text: m.type }), m.hashcat ? el('span', { class: 'note', text: '  hashcat -m ' + m.hashcat }) : null)) : [el('p', { class: 'note', text: 'No known hash format matches.' })]));
  } else if (tool === 'jwt') {
    box.append(el('pre', { class: 'codeblk', text: JSON.stringify({ header: r.header, payload: r.payload }, null, 2) }), ...r.notes.map(n => el('p', { class: 'note', text: '• ' + n })), flags(r.flags));
  } else if (tool === 'rsa') {
    box.append(el('p', { class: 'note', text: 'Worked via: ' + r.method }), el('pre', { class: 'codeblk', text: r.text }), el('div', { class: 'note', text: 'hex: ' + r.plaintext_hex }), flags(r.flags));
  } else if (tool === 'vigenere') {
    box.append(el('p', { class: 'note', text: 'Key: ' + r.key }), el('pre', { class: 'codeblk', text: r.plaintext }), flags(r.flags));
  } else if (tool === 'xorkey') {
    for (const c of r.candidates) box.append(el('div', { class: 'corr-card' }, el('div', { class: 'note', text: `key length ${c.key_len} · key “${c.key_ascii}” (hex ${c.key_hex})` }), el('pre', { class: 'codeblk', text: c.plaintext }), flags(c.flags)));
  }
  return box;
}

function openCtf(tool = 'magic', prefill = '') {
  const t = CTF_TOOLS[tool], out = el('div'), form = el('div', { class: 'ctf' });
  const tabs = el('div', { class: 'lg-legend' }, ...Object.entries(CTF_TOOLS).map(([k, v]) => el('button', { class: 'lg-chip' + (k === tool ? '' : ' off'), text: v.label, onclick: () => { closeModal(); openCtf(k); } })));
  const inputs = {};
  for (const f of t.fields) {
    inputs[f] = f === 'encoding' ? el('select', { class: 'hsearch' }, ...['text', 'hex', 'base64'].map(x => el('option', { value: x, text: 'data is ' + x })))
      : f === 'text' ? el('textarea', { class: 'bulkta', spellcheck: 'false', placeholder: 'paste here…' })
      : el('input', { class: 'hsearch', placeholder: f + (['p', 'q', 'd'].includes(f) ? ' (optional)' : '') });
    if (f === 'e') inputs[f].value = '65537';
  }
  if (prefill && inputs.text) inputs.text.value = prefill;
  const pre = t.prefix ? el('input', { class: 'hsearch', placeholder: 'extra flag prefix, e.g. MYCTF (optional)' }) : null;
  const go = el('button', { class: 'btn primary', text: 'Run' });
  go.addEventListener('click', async () => {
    const body = {}; for (const [k, v] of Object.entries(inputs)) body[k] = v.value;
    if (pre) body.prefix = pre.value;
    out.replaceChildren(el('p', { class: 'note', text: 'working…' }));
    out.replaceChildren(ctfResult(tool, await postJSON('/api/ctf/' + tool, body)));
  });
  const screen = el('button', { class: 'btn', text: 'Scan everything on screen for flags', onclick: async () => {
    const text = reportText(); const r = await postJSON('/api/ctf/flags', { text, prefix: pre ? pre.value : '' }); out.replaceChildren(ctfResult('flags', r)); } });
  form.append(tabs, el('p', { class: 'note', text: t.hint }), ...Object.values(inputs), pre, el('div', { class: 'brow' }, go, screen), out);
  openModal('CTF workbench', form, 'wide');
}
