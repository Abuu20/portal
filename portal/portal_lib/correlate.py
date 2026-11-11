"""Correlation across saved scans: which infrastructure is shared by different targets?

Reads the latest saved scan of each target, rebuilds its relationship graph (older saves get it recomputed from the
stored results) and reports the entities that appear in two or more different targets: the same IP, network,
nameserver, mail host, certificate issuer, CVE and so on. Local data only; nothing is fetched.
"""
from __future__ import annotations

import json
from contextlib import closing

from flask import jsonify

from .core import app
from .graph import EXTRACTORS, attach_graph
from .store import _db

WEIGHT = {"ip": 5, "asn": 3, "domain": 4, "cve": 4, "org": 2, "email": 4, "weakness": 1, "tech": 1, "port": 0, "location": 0}
MAX_SCANS = 200


def scan_graph(snap):
    """Merge the graphs of every window in one snapshot -> (nodes{id: node}, edges[])."""
    nodes, edges = {}, []
    for w in snap.get("windows") or []:
        res = w.get("res")
        if not isinstance(res, dict):
            continue
        if "graph" not in res and w.get("module") in EXTRACTORS:
            attach_graph(w["module"], str(w.get("q") or ""), res)
        g = res.get("graph")
        if not g:
            continue
        for n in g.get("nodes", []):
            nodes.setdefault(n["id"], n)
        edges.extend(g.get("edges", []))
    return nodes, edges


def correlate(rows):
    """rows: [{id, ts, query, type, snapshot(dict)}] newest first. Pure function so it can be tested."""
    seen, scans = set(), []
    for r in rows:                                   # keep only the newest scan per target
        k = (r["type"], r["query"].strip().lower())
        if k not in seen:
            seen.add(k)
            scans.append(r)
    index = {}
    for r in scans[:MAX_SCANS]:
        nodes, edges = scan_graph(r["snapshot"])
        own = {n for n in nodes if n == "domain:" + r["query"].strip().lower() or n == "ip:" + r["query"].strip().lower()}
        rel = {}
        for e in edges:
            for end, other in ((e["a"], e["b"]), (e["b"], e["a"])):
                rel.setdefault(end, set()).add(e["rel"])
        for nid, n in nodes.items():
            if nid in own:
                continue
            ent = index.setdefault(nid, {"id": nid, "type": n["type"], "label": n["label"], "tone": n.get("tone"), "scans": [], "via": set()})
            ent["scans"].append({"id": r["id"], "query": r["query"], "ts": r["ts"]})
            ent["via"] |= rel.get(nid, set())
    out = []
    for e in index.values():
        if len(e["scans"]) < 2 or WEIGHT.get(e["type"], 1) == 0:
            continue
        e["via"] = sorted(e["via"])
        e["score"] = WEIGHT.get(e["type"], 1) * len(e["scans"]) + (6 if e["tone"] == "bad" else 0)
        e["common"] = len(e["scans"]) >= max(4, int(len(scans) * 0.6))     # probably a big provider, not a link between owners
        out.append(e)
    out.sort(key=lambda e: (-e["score"], e["label"]))
    return {"groups": out[:60], "scans": len(scans)}


@app.get("/api/correlate")
def api_correlate():
    with closing(_db()) as con:
        rows = con.execute("SELECT id, ts, query, type, snapshot FROM scans ORDER BY id DESC LIMIT 500").fetchall()
    data = []
    for r in rows:
        try:
            data.append({"id": r["id"], "ts": r["ts"], "query": r["query"], "type": r["type"], "snapshot": json.loads(r["snapshot"])})
        except Exception:
            continue
    return jsonify(correlate(data))
