'use strict';
/* PORTAL: printable HTML report of everything on screen (one self-contained file, no scripts, no network). */
const hesc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SEV_LABEL = { bad: 'Critical', warn: 'Warning', ok: 'Clean', info: 'Info' };
const SEV_COLOR = { bad: '#c62839', warn: '#b7791f', ok: '#1f8a5b', info: '#2b6cb0' };

function reportGraphSvg() {                       // static picture of the link graph, if there is one
  const d = collectGraph();
  if (d.edges.length < 1) return '';
  const nodes = d.nodes.map(n => ({ ...n, x: undefined, y: undefined }));
  graphLayout(nodes, d.edges, { w: 860, h: 520 }, 260);
  const by = new Map(nodes.map(n => [n.id, n]));
  const lines = d.edges.map(e => { const a = by.get(e.a), b = by.get(e.b);
    return `<line x1="${a.x.toFixed(0)}" y1="${a.y.toFixed(0)}" x2="${b.x.toFixed(0)}" y2="${b.y.toFixed(0)}" stroke="#9aa9bf"/>` +
      `<text x="${((a.x + b.x) / 2).toFixed(0)}" y="${((a.y + b.y) / 2).toFixed(0)}" font-size="9" fill="#667" text-anchor="middle">${hesc(e.rel)}</text>`; }).join('');
  const dots = nodes.map(n => { const s = GRAPH_TYPES[n.type] || {}, c = n.tone === 'bad' ? '#c62839' : n.tone === 'warn' ? '#b7791f' : (s.color || '#468');
    return `<circle cx="${n.x.toFixed(0)}" cy="${n.y.toFixed(0)}" r="12" fill="#fff" stroke="${c}" stroke-width="2.5"/>` +
      `<text x="${n.x.toFixed(0)}" y="${(n.y + 4).toFixed(0)}" font-size="12" text-anchor="middle" fill="${c}">${hesc(s.glyph || '•')}</text>` +
      `<text x="${n.x.toFixed(0)}" y="${(n.y + 26).toFixed(0)}" font-size="10" text-anchor="middle" fill="#123">${hesc(n.label.slice(0, 28))}</text>`; }).join('');
  const legend = [...new Set(nodes.map(n => n.type))].map(t => `${hesc((GRAPH_TYPES[t] || {}).glyph || '')} ${hesc((GRAPH_TYPES[t] || {}).name || t)}`).join(' &nbsp;·&nbsp; ');
  return `<h2>How the entities connect</h2><p class="m">${legend}</p><svg viewBox="0 0 860 520" width="100%" style="border:1px solid #d5dbe5;border-radius:8px">${lines}${dots}</svg>`;
}

function buildHtmlReport() {
  const ws = [...wins.values()].filter(w => w.res && !w.res.error && !['root', 'ai', 'diff', 'next', 'graph'].includes(w.id)).sort((a, b) => a.seq - b.seq);
  const count = s => ws.filter(w => w.sev === s).length;
  let risk = null;
  try { risk = computeRisk(gatherFacts()); } catch { /* optional */ }
  const attention = ws.filter(w => w.sev === 'bad' || w.sev === 'warn').sort((a, b) => (a.sev === 'bad' ? 0 : 1) - (b.sev === 'bad' ? 0 : 1));
  const chips = r => (r.highlights || []).map(c => `<span class="chip t-${hesc(c.tone || 'info')}">${hesc(c.label)}${c.value ? ': <b>' + hesc(c.value) + '</b>' : ''}</span>`).join(' ');
  const win = w => {
    const r = w.res;
    const secs = (r.sections || []).map(s => `<h4>${hesc(s.title)}</h4><table>${s.rows.map(([k, v]) => `<tr><th>${hesc(k)}</th><td class="${v && v.tone ? 't-' + hesc(v.tone) : ''}">${hesc(txt(v))}</td></tr>`).join('')}</table>`).join('');
    const list = r.list && r.list.length ? `<h4>List (${r.list.length})</h4><p class="m">${r.list.slice(0, 60).map(hesc).join(', ')}${r.list.length > 60 ? ' …' : ''}</p>` : '';
    return `<section class="w"><h3><span class="dot" style="background:${SEV_COLOR[w.sev] || SEV_COLOR.info}"></span>${hesc(w.titleEl.textContent)} <small>${hesc(w.spec.sub || w.spec.q || '')}</small></h3>${chips(r)}${secs}${list}${r.note ? `<p class="m">${hesc(r.note)}</p>` : ''}</section>`;
  };
  const css = `body{font:14px/1.5 system-ui,Segoe UI,Arial,sans-serif;color:#14202e;max-width:960px;margin:24px auto;padding:0 18px}
h1{margin:0 0 2px}h2{margin:28px 0 8px;border-bottom:2px solid #14202e;padding-bottom:3px}h3{margin:0 0 6px}h4{margin:10px 0 3px;color:#456;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.m{color:#556;font-size:12px}.sum{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}.box{border:1px solid #d5dbe5;border-radius:8px;padding:8px 14px;min-width:90px}.box b{display:block;font-size:22px}
.w{border:1px solid #d5dbe5;border-radius:8px;padding:10px 14px;margin:10px 0;break-inside:avoid}.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px}
small{color:#667;font-weight:400}table{border-collapse:collapse;width:100%}th{width:32%;text-align:left;color:#456;font-weight:500;vertical-align:top;padding:2px 8px 2px 0}td{padding:2px 0;word-break:break-word}
tr{border-bottom:1px solid #eef1f6}.chip{display:inline-block;border:1px solid #c9d2e0;border-radius:12px;padding:1px 9px;font-size:12px;margin:0 3px 4px 0}
.t-bad{color:#c62839}.t-warn{color:#b7791f}.t-ok{color:#1f8a5b}ul{margin:4px 0 4px 18px}@media print{body{margin:0}}`;
  const reasons = risk && risk.reasons.length ? `<ul>${risk.reasons.map(r => `<li>+${r[0]} ${hesc(r[1])}</li>`).join('')}</ul>` : '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>PORTAL report - ${hesc(lastQuery || 'file')}</title><style>${css}</style></head><body>
<h1>PORTAL report</h1><p class="m">Target: <b>${hesc(lastQuery || '(file)')}</b> · Generated ${hesc(new Date().toLocaleString())} · lookups made from this computer</p>
<div class="sum"><div class="box"><b style="color:${SEV_COLOR.bad}">${count('bad')}</b>${SEV_LABEL.bad}</div><div class="box"><b style="color:${SEV_COLOR.warn}">${count('warn')}</b>${SEV_LABEL.warn}</div>
<div class="box"><b style="color:${SEV_COLOR.ok}">${count('ok')}</b>${SEV_LABEL.ok}</div>${risk ? `<div class="box"><b>${risk.score}/100</b>Risk score</div>` : ''}</div>
${reasons ? `<p class="m">Why this score (a heuristic to help you decide what to look at first, not a verdict):</p>${reasons}` : ''}
${attention.length ? `<h2>Needs attention</h2>${attention.map(win).join('')}` : ''}
${reportGraphSvg()}
<h2>All results</h2>${ws.filter(w => !attention.includes(w)).map(win).join('')}
<p class="m">Automated lookups against public sources. Verify anything important before acting on it.</p></body></html>`;
}

function downloadHtmlReport() {
  if (![...wins.values()].some(w => w.res && w.id !== 'root')) return toast('Run a scan first');
  const slug = (lastQuery || 'file').replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').slice(0, 40) || 'scan';
  download(`portal-report-${slug}.html`, buildHtmlReport(), 'text/html'); sfx.click();
}
