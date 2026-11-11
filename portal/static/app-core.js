'use strict';
/* PORTAL front end, part 1/4 (core: helpers, state, sounds): one query -> a window per module.
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
const hooks = { done() {}, reset() {}, closed() {}, findings() {} };   // filled in by history.js / smart.js
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
