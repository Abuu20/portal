'use strict';
/* PORTAL link graph, part 2: a small force-directed layout (pure maths, no DOM, deterministic). */
function graphLayout(nodes, edges, size = { w: 800, h: 520 }, steps = 260) {
  const n = nodes.length, idx = new Map(nodes.map((d, i) => [d.id, i]));
  const cx = size.w / 2, cy = size.h / 2, R = Math.min(size.w, size.h) / 3;
  nodes.forEach((d, i) => {                                   // start on a circle (stable between runs)
    if (d.x == null || d.y == null) { const a = (i / Math.max(n, 1)) * Math.PI * 2; d.x = cx + R * Math.cos(a); d.y = cy + R * Math.sin(a); }
    d.vx = 0; d.vy = 0;
  });
  const es = edges.map(e => [idx.get(e.a), idx.get(e.b)]).filter(p => p[0] != null && p[1] != null);
  const k = Math.sqrt((size.w * size.h) / Math.max(n, 1)) * 0.6;   // ideal edge length (Fruchterman-Reingold)
  const t0 = size.w / 8;
  for (let s = 0; s < steps; s++) {
    const t = t0 * (1 - s / steps) + 1;                              // cooling: the largest move allowed this step
    for (const d of nodes) { d.vx = 0; d.vy = 0; }
    for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {     // every pair repels
      let dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y, d = Math.hypot(dx, dy);
      if (d < 0.01) { dx = (i - j) * 0.1; dy = 0.1; d = Math.hypot(dx, dy); }
      const f = (k * k) / d;
      nodes[i].vx += dx / d * f; nodes[i].vy += dy / d * f; nodes[j].vx -= dx / d * f; nodes[j].vy -= dy / d * f;
    }
    for (const [a, b] of es) {                                          // linked nodes attract
      const dx = nodes[b].x - nodes[a].x, dy = nodes[b].y - nodes[a].y, d = Math.hypot(dx, dy) || 1, f = (d * d) / k;
      nodes[a].vx += dx / d * f; nodes[a].vy += dy / d * f; nodes[b].vx -= dx / d * f; nodes[b].vy -= dy / d * f;
    }
    for (const d of nodes) {
      if (d.pinned) continue;
      d.vx += (cx - d.x) * 0.9; d.vy += (cy - d.y) * 0.9;              // gentle pull to the middle
      const m = Math.hypot(d.vx, d.vy) || 1, step = Math.min(m, t);
      d.x += d.vx / m * step; d.y += d.vy / m * step;
      d.x = Math.min(size.w - 50, Math.max(50, d.x)); d.y = Math.min(size.h - 40, Math.max(40, d.y));
    }
  }
  return nodes;
}
