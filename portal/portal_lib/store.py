"""History: SQLite snapshots, change detection (diff) and the history endpoints."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from flask import jsonify, request

from .core import DATA_DIR, PLANS, TONE_RANK, app

DB_PATH = os.path.join(DATA_DIR, "portal.db")

_db_lock = threading.Lock()

_db_ready = False

MAX_SNAPSHOT = 3_000_000

SNAP_TYPES = set(PLANS) | {"file", "headers", "bulk"}

def _db():
    global _db_ready
    if not _db_ready:
        os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
        with closing(sqlite3.connect(DB_PATH, timeout=10)) as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, query TEXT NOT NULL, type TEXT NOT NULL, label TEXT DEFAULT '', bad INT DEFAULT 0, warn INT DEFAULT 0, ok INT DEFAULT 0, notes TEXT DEFAULT '', tags TEXT DEFAULT '', snapshot TEXT NOT NULL)")
            c.execute("CREATE INDEX IF NOT EXISTS scans_q ON scans(type, query, id)")
            c.commit()
        try:
            os.chmod(DB_PATH, 0o600)
        except OSError:
            pass
        _db_ready = True
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con

_VOLATILE_CHIPS = {"valid", "expires", "age", "latest", "running", "articles", "sources", "epss", "top epss"}

_VOLATILE_ROWS = {"last seen", "last analysed", "last reported", "last changed", "last update", "closest snapshot",
                  "size read", "content-length", "last-modified", "generated", "url"}

_DIFF_SKIP = {"links", "tools", "launch", "news", "scope", "hash", "diff", "nearby", "sherlock", "maigret", "wikidata"}

def snapshot_facts(res, title):
    f = {}
    def put(k, v):
        f.setdefault(k, set()).add(str(v))
    for c in res.get("highlights") or []:
        if str(c.get("label", "")).lower() not in _VOLATILE_CHIPS:
            put("● " + str(c.get("label", "")), c.get("value") or "")
    for s in res.get("sections") or []:
        for k, v in s.get("rows") or []:
            if str(k).lower() in _VOLATILE_ROWS:
                continue
            put(f"{s.get('title', '')} › {k}", v.get("text") if isinstance(v, dict) else v)
    for item in res.get("list") or []:
        put(f"{title} › {item}", "listed")
    return f

def diff_snapshots(old, new):
    ow = {f"{w.get('module')}|{w.get('q')}": w for w in old.get("windows", [])}
    nw = {f"{w.get('module')}|{w.get('q')}": w for w in new.get("windows", [])}
    mods, worse_any = [], False
    for key, n in nw.items():
        o = ow.get(key)
        if not o or n.get("module") in _DIFF_SKIP:
            continue
        title = n.get("title") or n.get("module")
        fo, fn = snapshot_facts(o.get("res", {}), title), snapshot_facts(n.get("res", {}), title)
        added, removed, changed = [], [], []
        for k in sorted(set(fo) | set(fn)):
            a, b = fo.get(k, set()), fn.get(k, set())
            if a == b:
                continue
            if len(a) == 1 and len(b) == 1:
                changed.append({"k": k, "old": next(iter(a)), "new": next(iter(b))})
            else:
                added += [f"{k}: {v}" if v and v != "listed" else k for v in sorted(b - a)]
                removed += [f"{k}: {v}" if v and v != "listed" else k for v in sorted(a - b)]
        so, sn = (o.get("res", {}).get("severity") or "info"), (n.get("res", {}).get("severity") or "info")
        worse = TONE_RANK.get(sn, 0) > TONE_RANK.get(so, 0)
        if added or removed or changed or so != sn:
            mods.append({"title": title, "module": n.get("module"), "added": added[:60], "removed": removed[:60],
                         "changed": changed[:60], "sev": {"old": so, "new": sn}, "worse": worse})
            worse_any = worse_any or (worse and sn in ("warn", "bad"))
    keyed = lambda d: {k: w for k, w in d.items() if w.get("module") not in _DIFF_SKIP}
    appeared = [w.get("title") for k, w in keyed(nw).items() if k not in ow]
    disappeared = [w.get("title") for k, w in keyed(ow).items() if k not in nw]
    total = sum(len(m["added"]) + len(m["removed"]) + len(m["changed"]) + (1 if m["sev"]["old"] != m["sev"]["new"] else 0) for m in mods) + len(appeared) + len(disappeared)
    return {"modules": mods, "appeared": appeared, "disappeared": disappeared, "total": total, "worse": worse_any}

def _prev_scan(con, typ, query, before_id):
    return con.execute("SELECT id, ts, snapshot FROM scans WHERE type=? AND query=? AND id<? ORDER BY id DESC LIMIT 1", (typ, query, before_id)).fetchone()

@app.post("/api/save")
def api_save():
    j = request.get_json(silent=True) or {}
    query, typ, label = str(j.get("query", ""))[:2000], str(j.get("type", ""))[:20], str(j.get("label", ""))[:200]
    wins_in = j.get("windows")
    if not query or typ not in SNAP_TYPES or not isinstance(wins_in, list) or not (1 <= len(wins_in) <= 80):
        return jsonify(error="Bad request"), 400
    clean, counts = [], {"bad": 0, "warn": 0, "ok": 0}
    for w in wins_in:
        if not isinstance(w, dict) or not isinstance(w.get("res"), dict) or w["res"].get("error"):
            continue
        item = {k: (w.get(k) if isinstance(w.get(k), (str, int)) or w.get(k) is None else None) for k in ("id", "module", "q", "title", "sub", "depth", "parent")}
        item["res"] = w["res"]
        clean.append(item)
        sev = w["res"].get("severity")
        if sev in counts:
            counts[sev] += 1
    if not clean:
        return jsonify(error="Nothing to save"), 400
    snap = {"v": 1, "query": query, "type": typ, "label": label, "windows": clean}
    blob = json.dumps(snap, separators=(",", ":"))
    if len(blob) > MAX_SNAPSHOT:
        return jsonify(error="Scan too large to save"), 413
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    sid = j.get("id") if isinstance(j.get("id"), int) else None
    with _db_lock, closing(_db()) as con:
        if sid:
            cur = con.execute("UPDATE scans SET ts=?, label=?, bad=?, warn=?, ok=?, snapshot=? WHERE id=? AND query=? AND type=?",
                              (ts, label, counts["bad"], counts["warn"], counts["ok"], blob, sid, query, typ))
            if cur.rowcount == 0:
                sid = None
        if not sid:
            cur = con.execute("INSERT INTO scans(ts, query, type, label, bad, warn, ok, snapshot) VALUES(?,?,?,?,?,?,?,?)",
                              (ts, query, typ, label, counts["bad"], counts["warn"], counts["ok"], blob))
            sid = cur.lastrowid
        con.commit()
        prev = _prev_scan(con, typ, query, sid)
    diff = None
    if prev:
        diff = diff_snapshots(json.loads(prev["snapshot"]), snap)
        diff["prev"] = {"id": prev["id"], "ts": prev["ts"]}
    return jsonify(id=sid, ts=ts, diff=diff)

@app.get("/api/history")
def api_history():
    needle = (request.args.get("q") or "").strip().lower()[:100]
    with closing(_db()) as con:
        rows = con.execute("SELECT id, ts, query, type, label, bad, warn, ok, notes, tags FROM scans ORDER BY id DESC LIMIT 300").fetchall()
    items = [dict(r) for r in rows]
    if needle:
        items = [i for i in items if needle in (i["query"] + " " + i["tags"] + " " + i["notes"]).lower()]
    return jsonify(items=items, dir=DATA_DIR)

@app.get("/api/scan/<int:sid>")
def api_scan(sid):
    with closing(_db()) as con:
        r = con.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    if not r:
        return jsonify(error="Not found"), 404
    d = dict(r)
    d["snapshot"] = json.loads(d["snapshot"])
    return jsonify(d)

@app.get("/api/diff")
def api_diff():
    try:
        new_id = int(request.args.get("new", ""))
        old_id = request.args.get("old")
        old_id = int(old_id) if old_id else None
    except ValueError:
        return jsonify(error="Bad request"), 400
    with closing(_db()) as con:
        n = con.execute("SELECT * FROM scans WHERE id=?", (new_id,)).fetchone()
        if not n:
            return jsonify(error="Not found"), 404
        o = con.execute("SELECT * FROM scans WHERE id=?", (old_id,)).fetchone() if old_id else _prev_scan(con, n["type"], n["query"], new_id)
    if not o:
        return jsonify(error="No earlier scan of this target to compare with"), 404
    d = diff_snapshots(json.loads(o["snapshot"]), json.loads(n["snapshot"]))
    d["prev"] = {"id": o["id"], "ts": o["ts"]}
    return jsonify(d)

@app.post("/api/scan/<int:sid>/meta")
def api_scan_meta(sid):
    j = request.get_json(silent=True) or {}
    notes, tags = str(j.get("notes", ""))[:2000], str(j.get("tags", ""))[:200]
    with _db_lock, closing(_db()) as con:
        cur = con.execute("UPDATE scans SET notes=?, tags=? WHERE id=?", (notes, tags, sid))
        con.commit()
    return jsonify(ok=cur.rowcount == 1)

@app.delete("/api/scan/<int:sid>")
def api_scan_delete(sid):
    with _db_lock, closing(_db()) as con:
        cur = con.execute("DELETE FROM scans WHERE id=?", (sid,))
        con.commit()
    return jsonify(ok=cur.rowcount == 1)

@app.post("/api/history/clear")
def api_history_clear():
    if (request.get_json(silent=True) or {}).get("confirm") is not True:
        return jsonify(error="Confirmation required"), 400
    with _db_lock, closing(_db()) as con:
        con.execute("DELETE FROM scans")
        con.commit()
    return jsonify(ok=True)
