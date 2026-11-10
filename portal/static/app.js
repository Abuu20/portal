'use strict';
/* PORTAL front end: one query -> a window per module.
 L ayouts: "t*iles" fills the whole screen (binary space partition weighted by content),
 "flow" lays windows out in columns left to right.
 All server-provided text is inserted with textContent (never innerHTML). */

const $ = (s, r = document) => r.querySelector(s);
const el = (tag, props = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null) e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return e;
};
const api = (url, opts = {}) =>
fetch(url, { ...opts, headers: { 'X-Portal': '1', ...(opts.headers || {}) } }).then(async r => {
  let j;
  try { j = await r.json(); } catch { j = { error: `HTTP ${r.status}` }; }
  if (!r.ok && !j.error) j.error = `HTTP ${r.status}`;
  return j;
});
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } },
};

const stage = $('#stage'), canvas = $('#canvas'), wires = $('#wires'), layer = $('#layer'), empty = $('#empty');
const wins = new Map();            // id -> window object
let edges = [];                    // {a, b} window ids
let zTop = 10, seq = 0, session = 0, autoCount = 0;
let layoutMode = store.get('portal.layout', 'tiles') === 'flow' ? 'flow' : 'tiles';
let linesTiles = store.get('portal.linesTiles', '0') === '1';   // tiles: show every link (otherwise only on hover)
let linesFlow = store.get('portal.linesFlow', '1') !== '0';
let hoverId = null;                // tile under the pointer (glow on linked tiles)
let snapshotMode = false;          // viewing a saved snapshot: no live pivots, no auto-save
let scanType = '';                 // type of the current scan (ip, domain, file, headers, ...)
const hooks = { done() {}, reset() {}, closed() {} };   // filled in by tools.js
let hoverHead = null;              // title bar under the pointer (draws link lines in tiles mode)
const MAX_AUTO = 8, MAX_DEPTH = 3;
const GAP = 10, PAD = 12, MIN_W = 240, MIN_H = 150, SCALES = [1, 1.2, 1.45, 1.8, 2.3, 3];

/* =====================================================================
 S ound: tiny* synthesized UI sounds (WebAudio, no files)
 ===================================================================== */
const sfx = (() => {
  let ctx = null, master = null, next = 0;
  let on = store.get('portal.sound', '1') !== '0';
  function init() {
    if (ctx) return ctx;
    try {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return null;
      ctx = new AC();
      master = ctx.createGain(); master.gain.value = 0.16;
      const comp = ctx.createDynamicsCompressor();
      master.connect(comp); comp.connect(ctx.destination);
    } catch { ctx = null; }
    return ctx;
  }
  function start(span, droppable) {
    const c = init();
    if (!on || !c) return null;
    if (c.state === 'suspended') c.resume().catch(() => {});
    const t = Math.max(c.currentTime, next);
    if (droppable && t - c.currentTime > 0.9) return null;
    next = t + span;
    return t;
  }
  function tone(t, f, d, o = {}) {
    const c = ctx, osc = c.createOscillator(), g = c.createGain();
    osc.type = o.type || 'sine';
    osc.frequency.setValueAtTime(f, t);
    if (o.to) osc.frequency.exponentialRampToValueAtTime(o.to, t + d);
    const peak = o.gain ?? 1;
    g.gain.setValueAtTime(0.0001, t);
    g.gain.exponentialRampToValueAtTime(peak, t + 0.01);
    g.gain.exponentialRampToValueAtTime(0.0001, t + d);
    osc.connect(g); g.connect(master);
    osc.start(t); osc.stop(t + d + 0.03);
  }
  return {
    get on() { return on; },
             set(v) { on = !!v; store.set('portal.sound', on ? '1' : '0'); if (on) this.click(); },
             scan() { const t = start(0.22); if (t == null) return; tone(t, 360, 0.09, { type: 'triangle', to: 520, gain: .8 }); tone(t + 0.09, 520, 0.11, { type: 'triangle', to: 780, gain: .8 }); },
             arrive(sev) {
               const t = start(sev === 'bad' ? 0.32 : sev === 'warn' ? 0.22 : sev === 'ok' ? 0.17 : 0.1, true);
               if (t == null) return;
               if (sev === 'bad') { tone(t, 185, 0.16, { type: 'sawtooth', gain: .5 }); tone(t + 0.16, 147, 0.2, { type: 'sawtooth', gain: .5 }); }
               else if (sev === 'warn') { tone(t, 440, 0.11, { type: 'triangle' }); tone(t + 0.12, 440, 0.11, { type: 'triangle' }); }
               else if (sev === 'ok') { tone(t, 587, 0.09, { gain: .7 }); tone(t + 0.07, 784, 0.12, { gain: .7 }); }
               else tone(t, 660, 0.08, { gain: .45 });
             },
             done(bad) {
               const t = start(0.5);
               if (t == null) return;
               if (bad) [392, 330, 262].forEach((f, i) => tone(t + i * 0.12, f, 0.18, { type: 'triangle', gain: .8 }));
               else [523, 659, 784, 1047].forEach((f, i) => tone(t + i * 0.085, f, 0.2, { gain: .7 }));
             },
             error() { const t = start(0.34); if (t == null) return; tone(t, 160, 0.14, { type: 'square', gain: .3 }); tone(t + 0.17, 130, 0.16, { type: 'square', gain: .3 }); },
             click() { const t = start(0.04, true); if (t != null) tone(t, 900, 0.035, { gain: .3 }); },
             snap() { const t = start(0.1); if (t == null) return; tone(t, 170, 0.08, { to: 70, gain: .9 }); tone(t + 0.02, 1100, 0.03, { gain: .25 }); },
             close() { const t = start(0.07, true); if (t != null) tone(t, 300, 0.05, { to: 200, gain: .4 }); },
  };
})();

/* =====================================================================
 W indows    *
 ===================================================================== */
function createWindow(spec) {
  const w = { id: spec.id, spec, depth: spec.depth, parent: spec.parent, moved: false, sev: 'info',
    run: 0, session, seq: seq, order: seq++, min: false, rect: null };
    w.icon = el('span', { class: 'wicon', text: spec.icon || '◆' });
    w.titleEl = el('span', { class: 'wtitle', text: spec.title });
    w.sub = el('span', { class: 'wsub', text: spec.sub || '' });
    const bShare = el('button', { class: 'wbtn', title: 'Share this window', text: '⇪', 'data-share': '1',
      onclick: e => showShare(w, e.currentTarget) });
    const bMax = el('button', { class: 'wbtn', title: 'Zoom (or double-click the title bar)', text: '⤢', onclick: () => toggleMax(w) });
    const bMin = el('button', { class: 'wbtn', title: 'Minimise to the dock', text: '–', onclick: () => minimise(w) });
    const bClose = el('button', { class: 'wbtn', title: 'Close', text: '✕', onclick: () => closeWindow(w) });
    w.head = el('header', {}, el('span', { class: 'dot' }), w.icon, w.titleEl, w.sub, bShare, bMax, bMin, bClose);
    w.body = el('div', { class: 'wbody' }, el('div', { class: 'muted', text: 'querying…' }));
    w.el = el('section', { class: 'win loading enter', 'data-sev': 'info' }, w.head, w.body);
    w.el.addEventListener('animationend', e => { if (e.animationName === 'pop') w.el.classList.remove('enter'); });
    w.el.addEventListener('pointerdown', () => front(w));
    w.el.addEventListener('pointerenter', () => { hoverId = w.id; markLinked(); dirty(); });
    w.el.addEventListener('pointerleave', () => { if (hoverId === w.id) { hoverId = null; markLinked(); dirty(); } });
    w.head.addEventListener('dblclick', e => { if (!e.target.closest('button')) toggleMax(w); });
    w.head.addEventListener('pointerenter', () => { hoverHead = w.id; dirty(); });
    w.head.addEventListener('pointerleave', () => { if (hoverHead === w.id) { hoverHead = null; dirty(); } });
    w.head.addEventListener('pointerdown', e => startDrag(w, e));
    new ResizeObserver(() => dirty()).observe(w.el);
    layer.append(w.el);
    front(w);
    wins.set(w.id, w);
    empty.classList.add('gone');
    return w;
}

function front(w) { w.el.style.zIndex = ++zTop; }

function minimise(w) {
  if (w.el.classList.contains('max')) w.el.classList.remove('max');
  w.min = true; w.el.style.display = 'none';
  sfx.click(); renderDock(); relayout();
}
function restore(w) {
  w.min = false; w.el.style.display = '';
  front(w); sfx.click(); renderDock(); relayout(); flash(w);
}
function renderDock() {
  const d = $('#dock');
  d.replaceChildren(...[...wins.values()].filter(w => w.min).map(w =>
  el('button', { class: `dockchip sev-${w.sev}`, title: 'Restore', onclick: () => restore(w) },
     w.icon.textContent + ' ' + w.titleEl.textContent)));
}

function toggleMax(w) {
  const on = w.el.classList.toggle('max');
  if (on) front(w);
  sfx.click(); dirty();
}

function closeWindow(w) {
  hooks.closed(w);
  w.el.remove();
  wins.delete(w.id);
  edges = edges.filter(e => e.a !== w.id && e.b !== w.id);
  if (!wins.size) empty.classList.remove('gone');
  sfx.close(); renderDock(); updateRoot(); relayout();
}

function setSev(w, sev) {
  w.sev = sev;
  w.el.dataset.sev = sev;
  if (w.min) renderDock();
  dirty();
}

function flash(w) {
  w.el.classList.remove('flash'); void w.el.offsetWidth; w.el.classList.add('flash');
  if (layoutMode === 'flow') w.el.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
  front(w);
}

/* ---------- dragging: free in flow mode, swap-with-target in tiles mode ---------- */
function tileAt(clientX, clientY, self) {
  const cr = canvas.getBoundingClientRect();
  const x = clientX - cr.left, y = clientY - cr.top;
  for (const v of wins.values()) {
    if (v === self || v.min || !v.rect) continue;
    if (x >= v.rect.x && x <= v.rect.x + v.rect.w && y >= v.rect.y && y <= v.rect.y + v.rect.h) return v;
  }
  return null;
}

function startDrag(w, e) {
  if (e.target.closest('button') || w.el.classList.contains('max') || e.button !== 0) return;
  const tiles = layoutMode === 'tiles';
  const sx = e.clientX, sy = e.clientY, ox = w.el.offsetLeft, oy = w.el.offsetTop;
  let target = null, moved = false;
  w.head.setPointerCapture(e.pointerId);
  const mv = ev => {
    const dx = ev.clientX - sx, dy = ev.clientY - sy;
    if (!moved && Math.hypot(dx, dy) < 4) return;
    if (!moved) { moved = true; w.el.classList.add('dragging'); front(w); }
    w.el.style.left = Math.max(0, ox + dx) + 'px';
    w.el.style.top = Math.max(0, oy + dy) + 'px';
    if (tiles) {
      const t = tileAt(ev.clientX, ev.clientY, w);
      if (t !== target) { if (target) target.el.classList.remove('droptarget'); target = t; if (t) t.el.classList.add('droptarget'); }
    } else { w.moved = true; growCanvas(); }
    dirty();
  };
  const up = () => {
    w.head.removeEventListener('pointermove', mv);
    w.head.removeEventListener('pointerup', up);
    w.head.removeEventListener('pointercancel', up);
    w.el.classList.remove('dragging');
    if (target) target.el.classList.remove('droptarget');
    if (tiles) {
      if (moved && target) { [w.order, target.order] = [target.order, w.order]; sfx.snap(); }
      relayout();
    }
  };
  w.head.addEventListener('pointermove', mv);
  w.head.addEventListener('pointerup', up);
  w.head.addEventListener('pointercancel', up);
}

/* =====================================================================
 L ayout     *
 ===================================================================== */
const visibleWins = () => [...wins.values()].filter(w => !w.min).sort((a, b) => a.order - b.order);

function weightOf(w) {
  if (w.id === 'root') return 0.85;
  const r = w.res;
  if (!r) return 1;
  let x = 1;
  if (r.map) x += 1.1;
  if (r.image) x += 0.8;
  if (r.accounts && r.accounts.length) x += 0.8 + Math.min(r.accounts.length / 25, 1.2);
  const rows = (r.sections || []).reduce((n, s) => n + s.rows.length, 0) + (r.list ? Math.min(r.list.length, 20) : 0);
  x += Math.min(rows / 14, 1.2);
  if (r.actions && r.actions.length) x += 0.8;
  return Math.sqrt(x);
}

function bspBest(items, r) {
  const n = items.length;
  if (n === 1) return { score: Math.min((r.w - GAP) / MIN_W, (r.h - GAP) / MIN_H), map: new Map([[items[0].id, r]]) };
  const ws = items.map(weightOf), total = ws.reduce((x, y) => x + y, 0);
  const clampR = v => Math.min(0.68, Math.max(0.32, v));
  const sumTo = k => ws.slice(0, k).reduce((x, y) => x + y, 0);
  let acc = 0, kW = 1;
  for (kW = 1; kW < n; kW++) { acc += ws[kW - 1]; if (acc >= total / 2) break; }
  kW = Math.min(Math.max(kW, 1), n - 1);
  const cands = [{ k: kW, ratio: clampR(sumTo(kW) / total) }];
  if (n <= 14) {
    const kC = Math.min(Math.max(Math.round(n / 2), 1), n - 1);
    cands.push({ k: kC, ratio: clampR(kC / n) }, { k: kC, ratio: clampR(sumTo(kC) / total) });
  }
  let best = null;
  for (const { k, ratio } of cands) {
    const a = items.slice(0, k), b = items.slice(k);
    for (const vertical of (r.w >= r.h ? [true, false] : [false, true])) {
      const ra = vertical ? { x: r.x, y: r.y, w: r.w * ratio, h: r.h } : { x: r.x, y: r.y, w: r.w, h: r.h * ratio };
      const rb = vertical ? { x: r.x + ra.w, y: r.y, w: r.w - ra.w, h: r.h } : { x: r.x, y: r.y + ra.h, w: r.w, h: r.h - ra.h };
      const A = bspBest(a, ra), B = bspBest(b, rb), score = Math.min(A.score, B.score);
      if (!best || score > best.score + 0.02) best = { score, map: new Map([...A.map, ...B.map]) };
    }
  }
  return best;
}

function layoutTiles() {
  const list = visibleWins();
  if (!list.length) { canvas.style.width = '100%'; canvas.style.height = '100%'; return; }
  const H0 = stage.clientHeight;
  let W = stage.clientWidth, H = H0, out = new Map();
  for (const sc of SCALES) {
    H = Math.round(H0 * sc);
    stage.style.overflowY = sc > 1 ? 'auto' : 'hidden';
    W = stage.clientWidth;
    const res = bspBest(list, { x: PAD - GAP / 2, y: PAD - GAP / 2, w: W - 2 * PAD + GAP, h: H - 2 * PAD + GAP });
    out = res.map;
    if (res.score >= 1) break;
  }
  canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
  wires.setAttribute('width', W); wires.setAttribute('height', H);
  for (const w of list) {
    const r = out.get(w.id);
    const x = r.x + GAP / 2, y = r.y + GAP / 2, ww = r.w - GAP, hh = r.h - GAP;
    w.rect = { x, y, w: ww, h: hh };
    const s = w.el.style;
    s.left = x + 'px'; s.top = y + 'px'; s.width = ww + 'px'; s.height = hh + 'px';
    s.setProperty('--mapH', Math.round(Math.min(340, Math.max(110, (hh - 130) * 0.6))) + 'px');
    s.setProperty('--imgH', Math.round(Math.min(300, Math.max(100, (hh - 130) * 0.6))) + 'px');
  }
}

function arrangeFlow(force) {
  const colW = 420, gapX = 72, gapY = 18, pad = 24, cursor = {};
  for (const w of visibleWins()) {
    if (w.moved && !force) continue;
    if (force) w.moved = false;
    const d = w.depth;
    cursor[d] ??= pad;
    let y = cursor[d];
    const p = w.parent ? wins.get(w.parent) : null;
    if (p && d > 0 && !p.min) y = Math.max(y, p.el.offsetTop);
    w.el.style.left = (pad + d * (colW + gapX)) + 'px';
    w.el.style.top = y + 'px';
    cursor[d] = y + w.el.offsetHeight + gapY;
  }
  growCanvas();
}

function growCanvas() {
  if (layoutMode !== 'flow') return;
  let r = 0, b = 0;
  for (const w of visibleWins()) {
    r = Math.max(r, w.el.offsetLeft + w.el.offsetWidth);
    b = Math.max(b, w.el.offsetTop + w.el.offsetHeight);
  }
  canvas.style.width = Math.max(stage.clientWidth, r + 80) + 'px';
  canvas.style.height = Math.max(stage.clientHeight, b + 80) + 'px';
  wires.setAttribute('width', canvas.style.width);
  wires.setAttribute('height', canvas.style.height);
}

function relayout(force = false) {
  if (force) wins.forEach(w => { w.order = w.seq; w.moved = false; });
  if (layoutMode === 'tiles') layoutTiles(); else arrangeFlow(force);
  dirty();
}

function applyLayoutMode() {
  canvas.className = layoutMode;
  stage.style.overflowX = layoutMode === 'tiles' ? 'hidden' : 'auto';
  stage.style.overflowY = layoutMode === 'tiles' ? 'hidden' : 'auto';
  for (const w of wins.values()) {
    if (layoutMode === 'flow') {
      w.el.style.width = ''; w.el.style.height = '';
      w.el.style.removeProperty('--mapH'); w.el.style.removeProperty('--imgH');
    } else w.el.style.height = '';
  }
  $('#layout').textContent = layoutMode === 'tiles' ? '▦ Tiles' : '⇉ Flow';
  $('#layout').title = layoutMode === 'tiles' ? 'Tiles fill the screen. Click for Flow (columns).' : 'Flow lays windows out in columns. Click for Tiles (fits the screen).';
  if (layoutMode === 'flow') for (const w of wins.values()) fitHeight(w);
  relayout(false);
  if (layoutMode === 'flow') arrangeFlow(true);
}
const linesActive = () => (layoutMode === 'tiles' ? linesTiles : linesFlow);

/* =====================================================================
 L ink lines *
 ===================================================================== */
let wiresDirty = false;
function dirty() { if (!wiresDirty) { wiresDirty = true; requestAnimationFrame(drawWires); } }
const NS = 'http://www.w3.org/2000/svg';
function svg(tag, attrs) {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
}
const box = e => ({ x: e.offsetLeft, y: e.offsetTop, w: e.offsetWidth, h: e.offsetHeight });

function markLinked() {
  wins.forEach(x => x.el.classList.remove('linked'));
  if (!hoverId) return;
  for (const e of edges) {
    if (e.a === hoverId) wins.get(e.b)?.el.classList.add('linked');
    if (e.b === hoverId) wins.get(e.a)?.el.classList.add('linked');
  }
}

function drawWires() {
  wiresDirty = false;
  wires.replaceChildren();
  const tiles = layoutMode === 'tiles';
  if (!tiles && !linesFlow) return;
  if (tiles && !linesTiles && !hoverHead) return;
  for (const e of edges) {
    const a = wins.get(e.a), b = wins.get(e.b);
    if (!a || !b || a.min || b.min || a.el.classList.contains('max') || b.el.classList.contains('max')) continue;
    const hot = tiles ? (e.a === hoverHead || e.b === hoverHead) : (e.a === hoverId || e.b === hoverId);
    if (tiles && !hot && !linesTiles) continue;
    let d, x1, y1, x2, y2;
    if (tiles) {
      if (!a.rect || !b.rect) continue;
      x1 = a.rect.x + a.rect.w / 2; y1 = a.rect.y + 20; x2 = b.rect.x + b.rect.w / 2; y2 = b.rect.y + 20;
      const dx = x2 - x1, dy = y2 - y1, len = Math.hypot(dx, dy) || 1, bow = Math.min(90, len * 0.2);
      d = `M${x1} ${y1} Q${(x1 + x2) / 2 - dy / len * bow} ${(y1 + y2) / 2 + dx / len * bow} ${x2} ${y2}`;
    } else {
      const A = box(a.el), B = box(b.el), ay = A.y + 22, by = B.y + 22;
      if (B.x >= A.x + A.w - 24) {
        x1 = A.x + A.w; y1 = ay; x2 = B.x; y2 = by;
        const k = Math.max(40, (x2 - x1) / 2);
        d = `M${x1} ${y1} C${x1 + k} ${y1} ${x2 - k} ${y2} ${x2} ${y2}`;
      } else if (B.x + B.w <= A.x + 24) {
        x1 = A.x; y1 = ay; x2 = B.x + B.w; y2 = by;
        const k = Math.max(40, (x1 - x2) / 2);
        d = `M${x1} ${y1} C${x1 - k} ${y1} ${x2 + k} ${y2} ${x2} ${y2}`;
      } else {
        const down = B.y >= A.y;
        x1 = A.x + A.w / 2; x2 = B.x + B.w / 2;
        y1 = down ? A.y + A.h : A.y; y2 = down ? B.y : B.y + B.h;
        const k = Math.max(30, Math.abs(y2 - y1) / 2) * (down ? 1 : -1);
        d = `M${x1} ${y1} C${x1} ${y1 + k} ${x2} ${y2 - k} ${x2} ${y2}`;
      }
    }
    const faint = tiles && linesTiles && !hot;
    wires.append(svg('path', { d, class: `wire sev-${b.sev}${faint ? ' faint' : ''}` }));
    wires.append(svg('circle', { cx: x1, cy: y1, r: 3.5, class: `wdot sev-${a.sev}` }));
    wires.append(svg('circle', { cx: x2, cy: y2, r: 3.5, class: `wdot sev-${b.sev}` }));
  }
}

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
        ? 'None of the supported tools are installed. On Kali: sudo apt install nmap dnsutils whois whatweb traceroute'
        : 'The toolbox needs a single host or domain.' }));
      return box;
    }
    const chk = el('input', { type: 'checkbox' });
    const out = el('pre', { class: 'toolout' });
    out.hidden = true;
    const btns = el('div', { class: 'links' });
    for (const a of res.actions) {
      const b = el('button', { class: 'btn small', text: a.label + (a.active ? ' ⚠' : ''), title: a.active ? 'sends traffic to the target' : 'passive / local' });
      b.addEventListener('click', async () => {
        if (a.active && !chk.checked) { toast('Tick the authorisation box first'); return; }
        sfx.click(); b.disabled = true; out.hidden = false; out.textContent = `running ${a.label}…`;
        const r = await api('/api/tool', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ tool: a.id, target: res.target, confirm: chk.checked }) });
        out.textContent = r.error ? '⚠ ' + r.error : `$ ${r.command}\n\n${r.output}`;
        if (r.error) sfx.error(); else sfx.done(false);
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

    let lastQuery = '';
    function reportText() {
      const ws = [...wins.values()].filter(w => w.res && !w.res.error && w.id !== 'ai' && w.id !== 'diff').sort((a, b) => a.seq - b.seq);
      const L = ['PORTAL REPORT', `Generated: ${new Date().toISOString()}`, `Target: ${lastQuery || '(file)'}`, ''];
      for (const w of ws) L.push('='.repeat(60), resText(w), '');
      return L.join('\n');
    }

    function downloadReport() {
      if (![...wins.values()].some(w => w.res)) return toast('Run a scan first');
      const slug = (lastQuery || 'file').replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').slice(0, 40) || 'scan';
      const url = URL.createObjectURL(new Blob([reportText()], { type: 'text/plain' }));
      const a = el('a', { href: url, download: `portal-report-${slug}.txt` });
      document.body.append(a); a.click(); a.remove();
      sfx.click();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    }

    /* =====================================================================
     L oading, pi*vots, root window, status
     ===================================================================== */
    async function load(w) {
      w.el.classList.add('loading'); w.el.classList.remove('error');
      const run = ++w.run, sess = w.session;
      const res = await (w.spec.loader ? w.spec.loader()
      : api(`/api/run?module=${encodeURIComponent(w.spec.module)}&q=${encodeURIComponent(w.spec.q)}`));
      if (sess !== session || !wins.has(w.id) || run !== w.run) return;
      renderBody(w, res);
      fitHeight(w);
      updateRoot();
      relayout();
      if (!res.error) autoPivots(w, res);
    }

    function autoPivots(w, res) {
      if (snapshotMode || w.depth >= MAX_DEPTH) return;
      for (const p of res.pivots || []) {
        if (!p.auto || autoCount >= MAX_AUTO) continue;
        autoCount++;
        openWindow({ module: p.module, q: p.q, title: MODULE_TITLES[p.module] || p.module, depth: w.depth + 1, parent: w.id });
      }
    }

    function openWindow(spec) {
      const id = spec.id || `${spec.module}|${spec.q}`;
      const existing = wins.get(id);
      if (existing) {
        if (spec.parent && !edges.some(e => e.a === spec.parent && e.b === id)) edges.push({ a: spec.parent, b: id });
        if (existing.min) restore(existing); else flash(existing);
        dirty();
        return existing;
      }
      const w = createWindow({ ...spec, id, sub: spec.sub ?? (spec.module === 'file' ? '' : spec.q) });
      if (spec.parent) edges.push({ a: spec.parent, b: id });
      relayout();
      load(w);
      return w;
    }

    function makeRoot(plan) {
      const w = createWindow({ id: 'root', title: 'TARGET', icon: '◉', depth: 0, parent: null, sub: plan.label });
      w.el.classList.remove('loading');
      w.res = { highlights: [], sections: [{ title: plan.label, rows: [['Query', plan.value]] }] };
      w.body.replaceChildren(el('div', { class: 'chips', id: 'rootchips' }),
                             el('div', { class: 'sec' }, el('h4', { text: plan.label }),
                                el('table', {}, el('tr', {}, el('td', { text: 'Query' }), el('td', { text: plan.value, class: 'tone-info' })))));
      updateRoot();
      relayout();
    }

    let wasPending = false, doneTimer = null;
    function updateStatus() {
      let bad = 0, warn = 0, ok = 0, pending = 0, n = 0;
      for (const x of wins.values()) {
        if (x.id === 'root') continue;
        n++;
        if (x.el.classList.contains('loading')) pending++;
        else if (x.sev === 'bad') bad++;
        else if (x.sev === 'warn') warn++;
        else if (x.sev === 'ok') ok++;
      }
      $('#st-win').textContent = String(n);
      $('#st-bad').textContent = String(bad); $('#st-bad').parentElement.classList.toggle('on', bad > 0);
      $('#st-warn').textContent = String(warn); $('#st-warn').parentElement.classList.toggle('on', warn > 0);
      $('#st-ok').textContent = String(ok); $('#st-ok').parentElement.classList.toggle('on', ok > 0);
      $('#st-run').textContent = String(pending); $('#st-run').parentElement.classList.toggle('on', pending > 0);
      $('#progress').classList.toggle('on', pending > 0);
      return { bad, warn, ok, pending };
    }

    function updateRoot() {
      const { bad, warn, ok, pending } = updateStatus();
      clearTimeout(doneTimer);
      if (pending > 0) wasPending = true;
      else if (wasPending) {
        doneTimer = setTimeout(() => { if (updateStatus().pending === 0) { wasPending = false; sfx.done(bad > 0); hooks.done(); } }, 700);
      }
      const w = wins.get('root');
      if (!w) return;
      const c = $('#rootchips', w.body);
      if (!c) return;
      c.replaceChildren(...[
        chipEl({ label: 'critical', value: bad, tone: bad ? 'bad' : 'info' }),
                        chipEl({ label: 'warnings', value: warn, tone: warn ? 'warn' : 'info' }),
                        chipEl({ label: 'clean', value: ok, tone: ok ? 'ok' : 'info' }),
                        pending ? chipEl({ label: 'running', value: pending, tone: 'info' }) : null,
      ].filter(Boolean));
      setSev(w, bad ? 'bad' : warn ? 'warn' : pending ? 'info' : 'ok');
    }

    /* =====================================================================
     A ctions    *
     ===================================================================== */
    function reset() {
      session++; autoCount = 0; seq = 0; hoverId = null; hoverHead = null; wasPending = false;
      snapshotMode = false; hooks.reset();
      clearTimeout(doneTimer);
      wins.forEach(w => w.el.remove());
      wins.clear(); edges = [];
      wires.replaceChildren();
      empty.classList.remove('gone');
      renderDock(); updateStatus();
      relayout();
    }

    async function search(q) {
      q = q.trim();
      if (!q) return;
      reset();
      sfx.scan();
      const plan = await api('/api/plan?q=' + encodeURIComponent(q));
      if (plan.error) { sfx.error(); return toast(plan.error); }
      empty.classList.add('gone');
      lastQuery = plan.value; scanType = plan.type;
      makeRoot(plan);
      for (const m of plan.modules) openWindow({ module: m.module, q: m.q, title: m.title, depth: 1, parent: 'root' });
      try { history.replaceState(null, '', '#' + encodeURIComponent(q)); } catch { /* ignore */ }
    }

    function uploadFile(file) {
      if (!file) return;
      reset();
      sfx.scan();
      lastQuery = file.name; scanType = 'file';
      makeRoot({ label: 'Uploaded file', value: `${file.name} (${file.size.toLocaleString()} bytes)` });
      const fd = new FormData();
      fd.append('file', file, file.name);
      openWindow({ id: `file|${Date.now()}`, module: 'file', title: 'File analysis', sub: file.name, depth: 1, parent: 'root',
                 loader: () => api('/api/file', { method: 'POST', body: fd }) });
      $('#q').value = '';
    }

    let toastTimer;
    function toast(msg, good) {
      const t = $('#toast');
      t.textContent = msg; t.classList.toggle('good', !!good); t.classList.add('on');
      clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('on'), 3500);
    }

    function setLayout(mode) {
      layoutMode = mode;
      store.set('portal.layout', mode);
      sfx.click();
      applyLayoutMode();
    }
    function toggleLines() {
      if (layoutMode === 'tiles') { linesTiles = !linesTiles; store.set('portal.linesTiles', linesTiles ? '1' : '0'); }
      else { linesFlow = !linesFlow; store.set('portal.linesFlow', linesFlow ? '1' : '0'); }
      sfx.click(); dirty();
    }
    function syncSoundBtn() {
      const b = $('#sound');
      b.textContent = sfx.on ? '🔊' : '🔇';
      b.classList.toggle('off', !sfx.on);
      b.title = sfx.on ? 'Sound on (M to mute)' : 'Sound off (M to unmute)';
    }

    /* ---------- wiring ---------- */
    const input = $('#q');
    $('#go').addEventListener('click', () => search(input.value));
    input.addEventListener('keydown', e => { if (e.key === 'Enter') search(input.value); });
    $('#pick').addEventListener('click', () => { sfx.click(); $('#file').click(); });
    $('#file').addEventListener('change', e => { uploadFile(e.target.files[0]); e.target.value = ''; });
    $('#layout').addEventListener('click', () => setLayout(layoutMode === 'tiles' ? 'flow' : 'tiles'));
    $('#report').addEventListener('click', downloadReport);
    $('#shareAll').addEventListener('click', e => {
      if (![...wins.values()].some(w => w.res)) return toast('Run a scan first');
      openMenu(e.currentTarget, shareItems(reportText(), 'Portal report'));
    });
    $('#clear').addEventListener('click', () => { sfx.close(); reset(); input.value = ''; history.replaceState(null, '', location.pathname); });
    $('#sound').addEventListener('click', () => { sfx.set(!sfx.on); syncSoundBtn(); });

    document.addEventListener('keydown', e => {
      const typing = /^(INPUT|TEXTAREA)$/.test(document.activeElement?.tagName || '');
      if (e.key === '/' && !typing) { e.preventDefault(); input.focus(); input.select(); }
      else if (e.key === 'Escape') { const m = $('.win.max'); if (m) { m.classList.remove('max'); dirty(); } closeMenu(); }
      else if (!typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        if (e.key === 'l' || e.key === 'L') setLayout(layoutMode === 'tiles' ? 'flow' : 'tiles');
        else if (e.key === 'm' || e.key === 'M') { sfx.set(!sfx.on); syncSoundBtn(); }
      }
    });

    let dragDepth = 0;
    addEventListener('dragenter', e => { if (e.dataTransfer?.types.includes('Files')) { dragDepth++; $('#drop').classList.add('on'); } });
    addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; $('#drop').classList.remove('on'); } });
    addEventListener('dragover', e => e.preventDefault());
    addEventListener('drop', e => {
      e.preventDefault(); dragDepth = 0; $('#drop').classList.remove('on');
      const f = e.dataTransfer?.files?.[0];
      if (f) uploadFile(f);
    });
      addEventListener('paste', e => {
        const f = e.clipboardData?.files?.[0];
        if (f) { e.preventDefault(); uploadFile(f); }
      });
      let resizeTimer;
      addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => relayout(), 60); });
      stage.addEventListener('scroll', () => dirty());

      for (const x of ['8.8.8.8', 'example.com', 'admin@example.com', 'https://example.com', '-6.8160, 39.2803',
        'Dar es Salaam', 'CVE-2024-3094', '5449000000996', 'solar energy tanzania', '@torvalds']) {
        $('#examples').append(el('span', { class: 'ex', text: x, onclick: () => { input.value = x; search(x); } }));
        }

        syncSoundBtn();
      applyLayoutMode();
      if (location.hash.length > 1) {
        try { const q = decodeURIComponent(location.hash.slice(1)); input.value = q; search(q); } catch { /* ignore */ }
      }
      input.focus();
