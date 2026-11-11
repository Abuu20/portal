'use strict';
/* PORTAL link graph, part 1: merge the graphs that scan windows carry (result.graph) into one set of entities. */
const GRAPH_TYPES = {                       // entity type -> look and the lookups a click can start
  domain:   { name: 'Domain',        glyph: '◍', color: '#4cc9f0', mods: [['dns', 'DNS'], ['web', 'Web'], ['tls', 'Certificate'], ['subs', 'Subdomains'], ['rdap', 'Registration']] },
  ip:       { name: 'IP address',    glyph: '⬢', color: '#3ddc97', mods: [['ip', 'IP info'], ['exposure', 'Exposure'], ['rdap_ip', 'Network']] },
  asn:      { name: 'Network (ASN)', glyph: '◈', color: '#b388ff', mods: [] },
  org:      { name: 'Organisation',  glyph: '▣', color: '#f59e0b', mods: [] },
  port:     { name: 'Open port',     glyph: '◆', color: '#ff8fab', mods: [] },
  cve:      { name: 'Vulnerability', glyph: '✱', color: '#ff4d6d', mods: [['cve', 'CVE record']] },
  weakness: { name: 'Weakness',      glyph: '△', color: '#ff9f6e', mods: [] },
  tech:     { name: 'Technology',    glyph: '⚙', color: '#7dd3c0', mods: [] },
  location: { name: 'Location',      glyph: '⌖', color: '#94a3b8', mods: [] },
  email:    { name: 'Email address', glyph: '✉', color: '#f472b6', mods: [['email', 'Email check']] },
};

/* Value to look up for a node (its id is "type:value"; ports carry "ip:port"). */
const graphValue = n => n.id.slice(n.type.length + 1);
const graphQuery = n => (n.type === 'cve' ? graphValue(n).toUpperCase() : n.type === 'port' ? graphValue(n).split(':')[0] : graphValue(n));

function collectGraph() {
  const nodes = new Map(), seen = new Set(), edgesOut = [], events = [], srcs = new Map();
  for (const w of wins.values()) {
    const g = w.res && w.res.graph;
    if (!g) continue;
    for (const n of g.nodes || []) {
      const have = nodes.get(n.id);
      if (!have) nodes.set(n.id, { ...n });
      else if (n.tone && (!have.tone || n.tone === 'bad')) have.tone = n.tone;
      (srcs.get(n.id) || srcs.set(n.id, new Set()).get(n.id)).add(w.titleEl ? w.titleEl.textContent : w.id);
    }
    for (const e of g.edges || []) {
      const k = e.a + '|' + e.rel + '|' + e.b;
      if (nodes.has(e.a) && nodes.has(e.b) && !seen.has(k)) { seen.add(k); edgesOut.push({ ...e }); }
    }
    for (const ev of g.events || []) events.push({ ...ev });
  }
  const deg = new Map();
  for (const e of edgesOut) { deg.set(e.a, (deg.get(e.a) || 0) + 1); deg.set(e.b, (deg.get(e.b) || 0) + 1); }
  const list = [...nodes.values()].map(n => ({ ...n, deg: deg.get(n.id) || 0, from: [...(srcs.get(n.id) || [])] }));
  events.sort((a, b) => a.date.localeCompare(b.date));
  return { nodes: list, edges: edgesOut, events };
}
