'use strict';
/* PORTAL link graph, part 3: the "Link graph" window (canvas, legend, inspector, timeline). Loaded after smart.js. */
const SVGNS = 'http://www.w3.org/2000/svg';
const sv = (tag, attrs = {}, ...kids) => {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  n.append(...kids.filter(Boolean)); return n;
};
const gv = { w: null, data: null, hidden: new Set(), sel: null, tf: { x: 0, y: 0, k: 1 }, pos: new Map(), sig: '' };

function openGraph() {
  if (!collectGraph().nodes.length) return toast('Nothing to connect yet. Run a scan on a domain or an IP first.');
  if (!gv.w || !wins.has('graph')) {
    gv.w = createWindow({ id: 'graph', title: 'Link graph', icon: '⌬', depth: 1, parent: 'root', sub: 'how the entities connect' });
    edges.push({ a: 'root', b: 'graph' });
    gv.w.el.classList.remove('loading');
    gv.w.body.replaceChildren(el('div', { class: 'lg' },
      el('div', { class: 'lg-main' }, el('div', { class: 'lg-legend' }), el('div', { class: 'lg-cv' }), el('div', { class: 'lg-tl' })),
      el('aside', { class: 'lg-ins' })));
    relayout(); updateStatus(); toggleMax(gv.w);      // a graph needs room: open zoomed
  }
  gv.sig = ''; drawGraph();
}

function drawGraph() {
  if (!gv.w || !wins.has('graph')) return;
  const d = collectGraph(), sig = d.nodes.map(n => n.id).join() + '#' + d.edges.length;
  if (sig === gv.sig) return;
  gv.sig = sig;
  gv.data = d;
  const old = gv.pos;
  d.nodes.forEach(n => { const p = old.get(n.id); if (p) { n.x = p.x; n.y = p.y; } });
  graphLayout(d.nodes, d.edges, { w: 860, h: 520 }, old.size ? 120 : 260);
  d.nodes.forEach(n => old.set(n.id, { x: n.x, y: n.y }));
  d.byId = new Map(d.nodes.map(n => [n.id, n]));
  const root = gv.w.body;
  gLegend($('.lg-legend', root), d); gCanvas($('.lg-cv', root), d); gTimeline($('.lg-tl', root), d); gInspect($('.lg-ins', root));
  gv.w.sub.textContent = `${d.nodes.length} entities · ${d.edges.length} links`;
}

function gLegend(box, d) {
  const counts = {};
  d.nodes.forEach(n => { counts[n.type] = (counts[n.type] || 0) + 1; });
  box.replaceChildren(...Object.keys(counts).map(t => {
    const s = GRAPH_TYPES[t];
    return el('button', { class: 'lg-chip' + (gv.hidden.has(t) ? ' off' : ''), title: 'Show or hide ' + s.name, onclick: () => {
      gv.hidden.has(t) ? gv.hidden.delete(t) : gv.hidden.add(t); gv.sig = ''; drawGraph();
    } }, el('i', { style: `color:${s.color}`, text: s.glyph }), ` ${s.name} `, el('b', { text: String(counts[t]) }));
  }));
}

function gCanvas(box, d) {
  const vis = d.nodes.filter(n => !gv.hidden.has(n.type)), ok = new Set(vis.map(n => n.id));
  const svg = sv('svg', { class: 'lg-svg', viewBox: '0 0 860 520' });
  const root = sv('g'); svg.append(root);
  const apply = () => root.setAttribute('transform', `translate(${gv.tf.x} ${gv.tf.y}) scale(${gv.tf.k})`); apply();
  const lines = [];
  for (const e of d.edges) {
    if (!ok.has(e.a) || !ok.has(e.b)) continue;
    const a = d.byId.get(e.a), b = d.byId.get(e.b);
    const ln = sv('line', { class: 'lg-edge', x1: a.x, y1: a.y, x2: b.x, y2: b.y });
    const tx = sv('text', { class: 'lg-rel', x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }, document.createTextNode(e.rel));
    root.append(ln, tx); lines.push({ e, ln, tx });
  }
  const move = n => {
    for (const l of lines) if (l.e.a === n.id || l.e.b === n.id) {
      const a = d.byId.get(l.e.a), b = d.byId.get(l.e.b);
      l.ln.setAttribute('x1', a.x); l.ln.setAttribute('y1', a.y); l.ln.setAttribute('x2', b.x); l.ln.setAttribute('y2', b.y);
      l.tx.setAttribute('x', (a.x + b.x) / 2); l.tx.setAttribute('y', (a.y + b.y) / 2);
    }
  };
  for (const n of vis) {
    const s = GRAPH_TYPES[n.type] || GRAPH_TYPES.domain, r = 13 + Math.min(n.deg, 8);
    const g = sv('g', { class: 'lg-node' + (gv.sel === n.id ? ' sel' : '') + (n.tone ? ' t-' + n.tone : ''), transform: `translate(${n.x} ${n.y})`, 'data-id': n.id },
      sv('circle', { r, fill: s.color + '33', stroke: n.tone === 'bad' ? '#ff4d6d' : n.tone === 'warn' ? '#ffb703' : s.color }),
      sv('text', { class: 'lg-g', y: 4 }, document.createTextNode(s.glyph)),
      sv('text', { class: 'lg-l', y: r + 12 }, document.createTextNode(n.label.length > 26 ? n.label.slice(0, 25) + '…' : n.label)));
    g.addEventListener('pointerdown', ev => {
      ev.stopPropagation(); let moved = false; const sx = ev.clientX, sy = ev.clientY, ox = n.x, oy = n.y;
      g.setPointerCapture(ev.pointerId);
      const mv = e2 => {
        const k = svg.getBoundingClientRect().width / 860 * gv.tf.k;
        if (Math.abs(e2.clientX - sx) + Math.abs(e2.clientY - sy) > 3) moved = true;
        n.x = ox + (e2.clientX - sx) / k; n.y = oy + (e2.clientY - sy) / k; n.pinned = true;
        g.setAttribute('transform', `translate(${n.x} ${n.y})`); move(n);
      };
      const up = () => { g.removeEventListener('pointermove', mv); g.removeEventListener('pointerup', up); gv.pos.set(n.id, { x: n.x, y: n.y });
        if (!moved) { gv.sel = n.id; box.querySelectorAll('.lg-node').forEach(x => x.classList.toggle('sel', x.dataset.id === n.id)); gInspect($('.lg-ins', gv.w.body)); } };
      g.addEventListener('pointermove', mv); g.addEventListener('pointerup', up);
    });
    root.append(g);
  }
  svg.addEventListener('wheel', ev => {                                  // zoom around the pointer
    ev.preventDefault(); const rc = svg.getBoundingClientRect(), f = rc.width / 860;
    const px = (ev.clientX - rc.left) / f, py = (ev.clientY - rc.top) / f, k0 = gv.tf.k, k1 = Math.min(3, Math.max(0.3, k0 * (ev.deltaY < 0 ? 1.15 : 0.87)));
    gv.tf.x = px - (px - gv.tf.x) * k1 / k0; gv.tf.y = py - (py - gv.tf.y) * k1 / k0; gv.tf.k = k1; apply();
  }, { passive: false });
  svg.addEventListener('pointerdown', ev => {                            // pan the background
    const sx = ev.clientX, sy = ev.clientY, ox = gv.tf.x, oy = gv.tf.y, f = svg.getBoundingClientRect().width / 860;
    svg.setPointerCapture(ev.pointerId);
    const mv = e2 => { gv.tf.x = ox + (e2.clientX - sx) / f; gv.tf.y = oy + (e2.clientY - sy) / f; apply(); };
    const up = () => { svg.removeEventListener('pointermove', mv); svg.removeEventListener('pointerup', up); };
    svg.addEventListener('pointermove', mv); svg.addEventListener('pointerup', up);
  });
  box.replaceChildren(svg);
}

function gTimeline(box, d) {
  const evs = d.events.filter(e => d.byId.has(e.node) && !gv.hidden.has(d.byId.get(e.node).type));
  if (!evs.length) { box.replaceChildren(el('span', { class: 'note', text: 'No dated events yet (registration and certificate dates appear here).' })); return; }
  box.replaceChildren(...evs.slice(0, 14).map(e => el('button', { class: 'lg-ev', title: 'Select ' + d.byId.get(e.node).label, onclick: () => {
    gv.sel = e.node; gv.sig = ''; drawGraph(); } }, el('b', { text: e.date }), ' ' + e.label + ' · ' + d.byId.get(e.node).label)));
}

function gInspect(box) {
  const d = gv.data, n = d && d.byId.get(gv.sel);
  if (!n) { box.replaceChildren(el('p', { class: 'note', text: 'Click an entity to see what it is connected to. Drag to move, scroll to zoom, drag the background to pan.' })); return; }
  const s = GRAPH_TYPES[n.type];
  const links = d.edges.filter(e => e.a === n.id || e.b === n.id).map(e => {
    const o = d.byId.get(e.a === n.id ? e.b : e.a), out = e.a === n.id;
    return el('li', {}, el('span', { class: 'lg-rel2', text: (out ? '→ ' : '← ') + e.rel }), ' ',
      el('a', { href: '#', text: o.label, onclick: ev => { ev.preventDefault(); gv.sel = o.id; gInspect(box); gv.w.body.querySelectorAll('.lg-node').forEach(x => x.classList.toggle('sel', x.dataset.id === o.id)); } }));
  });
  const btns = (s.mods || []).map(([m, label]) => el('button', { class: 'btn small', text: label + ' →', onclick: () => {
    openWindow({ module: m, q: graphQuery(n), title: MODULE_TITLES[m] || m, depth: 2, parent: 'graph' }); } }));
  box.replaceChildren(el('h4', {}, el('i', { style: `color:${s.color}`, text: s.glyph + ' ' }), n.label),
    el('div', { class: 'note', text: s.name + (n.tone ? ' · ' + (n.tone === 'bad' ? 'high risk' : 'needs attention') : '') }),
    el('div', { class: 'lg-sec', text: `Connections (${links.length})` }), el('ul', { class: 'lg-list' }, ...links),
    n.from.length ? el('div', { class: 'note', text: 'Seen in: ' + n.from.join(', ') }) : null,
    btns.length ? el('div', { class: 'lg-sec', text: 'Look up' }) : null, btns.length ? el('div', { class: 'brow' }, ...btns) : null);
}

/* keep the graph current as scans finish; forget it on a new scan */
const _gDone = hooks.done, _gReset = hooks.reset;
hooks.done = () => { _gDone(); drawGraph(); };
hooks.reset = () => { _gReset(); gv.pos = new Map(); gv.sel = null; gv.sig = ''; gv.tf = { x: 0, y: 0, k: 1 }; gv.w = null; };
