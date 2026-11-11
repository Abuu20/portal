'use strict';
/* PORTAL front end, part 2/4: windows (create, minimise, drag), tile/flow layout and the link lines. */
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
  if (w.id === 'graph') return 3.2;
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
