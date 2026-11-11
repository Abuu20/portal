"""Watchlist: re-scan chosen domains / IPs on a schedule and raise an alert when something changed.

Only domains and IP addresses can be watched (infrastructure, never people). Each run is the same passive scan you
would start by hand (no active tools, nothing that needs the authorisation tick-box), saved to history and compared
with the previous scan of that target. The scheduler lives inside the PORTAL process, so it only runs while PORTAL
runs (the KDE background service keeps it running). Everything stays on this computer.
"""
from __future__ import annotations

import json
import threading
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone

from flask import jsonify, request

from .core import PLANS, app, detect
from .store import _db, _db_lock, _prev_scan, diff_snapshots

WATCH_TYPES = ("ip", "domain")
SKIP_MODULES = {"tools", "links"}              # local-only / link windows: nothing to compare
INTERVALS = (6, 12, 24, 72, 168)               # hours
MAX_WATCH = 25
_run_lock = threading.Lock()                   # one scan at a time, whether scheduled or "Run now"
_ready = False


def _con():
    global _ready
    con = _db()
    if not _ready:
        con.execute("CREATE TABLE IF NOT EXISTS watch(id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, type TEXT NOT NULL, interval_h INT NOT NULL, "
                    "added TEXT NOT NULL, last_run TEXT DEFAULT '', last_scan INT DEFAULT 0, last_error TEXT DEFAULT '')")
        con.execute("CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, watch_id INT, target TEXT NOT NULL, "
                    "summary TEXT NOT NULL, detail TEXT DEFAULT '', worse INT DEFAULT 0, scan_id INT, seen INT DEFAULT 0)")
        con.commit()
        _ready = True
    return con


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def summarize(diff):
    """One short human sentence plus the first few concrete changes."""
    bits = []
    for m in diff["modules"]:
        n = len(m["added"]) + len(m["removed"]) + len(m["changed"])
        if n:
            first = (m["changed"][0]["k"] + ": " + m["changed"][0]["old"] + " → " + m["changed"][0]["new"]) if m["changed"] else (
                ("+ " + m["added"][0]) if m["added"] else ("− " + m["removed"][0]))
            bits.append(f"{m['title']}: {first[:110]}" + (f" (+{n - 1} more)" if n > 1 else ""))
        elif m["sev"]["old"] != m["sev"]["new"]:
            bits.append(f"{m['title']}: {m['sev']['old']} → {m['sev']['new']}")
    for t in diff["appeared"]:
        bits.append(f"new section: {t}")
    for t in diff["disappeared"]:
        bits.append(f"missing now: {t}")
    head = f"{diff['total']} change{'s' if diff['total'] != 1 else ''}" + (" · got worse" if diff["worse"] else "")
    return head + " — " + "; ".join(bits[:4])[:420]


def scan_target(typ, value, run_module):
    """Run the passive modules for one target. Returns the list of window dicts (same shape the browser saves)."""
    out = []
    for m, title in PLANS[typ]:
        if m in SKIP_MODULES:
            continue
        res = run_module(m, value)
        if not isinstance(res, dict) or res.get("error"):
            continue
        out.append({"id": m, "module": m, "q": value, "title": title, "sub": "", "depth": 1, "parent": "root", "res": res})
    return out


def run_watch(wid, run_module=None):
    """Scan one watched target, save it to history, record an alert if it differs from last time. Returns the alert or None."""
    if run_module is None:
        from .routes import run_module
    with _run_lock:
        with closing(_con()) as con:
            w = con.execute("SELECT * FROM watch WHERE id=?", (wid,)).fetchone()
        if not w:
            return None
        windows, err = [], ""
        try:
            windows = scan_target(w["type"], w["target"], run_module)
            if not windows:
                err = "No module returned data (network problem?)"
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
        ts = _now().isoformat()
        alert = None
        with _db_lock, closing(_con()) as con:
            if err:
                con.execute("UPDATE watch SET last_run=?, last_error=? WHERE id=?", (ts, err[:200], wid))
                con.commit()
                return None
            counts = {"bad": 0, "warn": 0, "ok": 0}
            for x in windows:
                s = x["res"].get("severity")
                if s in counts:
                    counts[s] += 1
            snap = {"v": 1, "query": w["target"], "type": w["type"], "label": "watchlist", "windows": windows}
            blob = json.dumps(snap, separators=(",", ":"))
            cur = con.execute("INSERT INTO scans(ts, query, type, label, bad, warn, ok, tags, snapshot) VALUES(?,?,?,?,?,?,?,?,?)",
                              (ts, w["target"], w["type"], "watchlist", counts["bad"], counts["warn"], counts["ok"], "watchlist", blob))
            sid = cur.lastrowid
            prev = _prev_scan(con, w["type"], w["target"], sid)
            if prev:
                d = diff_snapshots(json.loads(prev["snapshot"]), snap)
                if d["total"] > 0:
                    summ = summarize(d)
                    detail = json.dumps({"modules": d["modules"][:12], "appeared": d["appeared"], "disappeared": d["disappeared"]})[:30000]
                    cur = con.execute("INSERT INTO alerts(ts, watch_id, target, summary, detail, worse, scan_id) VALUES(?,?,?,?,?,?,?)",
                                      (ts, wid, w["target"], summ, detail, 1 if d["worse"] else 0, sid))
                    alert = {"id": cur.lastrowid, "target": w["target"], "summary": summ, "worse": bool(d["worse"]), "scan_id": sid}
            con.execute("UPDATE watch SET last_run=?, last_scan=?, last_error='' WHERE id=?", (ts, sid, wid))
            con.commit()
        return alert


def due(now=None):
    """Ids of enabled watches whose interval has elapsed (never-run ones are due immediately)."""
    now = now or _now()
    out = []
    with closing(_con()) as con:
        for w in con.execute("SELECT id, interval_h, last_run FROM watch ORDER BY id").fetchall():
            try:
                last = datetime.fromisoformat(w["last_run"]) if w["last_run"] else None
            except ValueError:
                last = None
            if last is None or now - last >= timedelta(hours=w["interval_h"]):
                out.append(w["id"])
    return out


_started = False


def start_scheduler(poll_s=120):
    """Called once from server.main(). A daemon thread that runs due watches one after another."""
    global _started
    if _started:
        return
    _started = True

    def loop():
        time.sleep(20)                              # let the server settle first
        while True:
            try:
                for wid in due():
                    run_watch(wid)
                    time.sleep(5)                   # be gentle with the public services
            except Exception:
                pass
            time.sleep(poll_s)
    threading.Thread(target=loop, name="portal-watch", daemon=True).start()


# ---------------------------------------------------------------- API
def _item(w):
    nxt = ""
    try:
        if w["last_run"]:
            nxt = (datetime.fromisoformat(w["last_run"]) + timedelta(hours=w["interval_h"])).isoformat()
    except ValueError:
        pass
    return {"id": w["id"], "target": w["target"], "type": w["type"], "interval_h": w["interval_h"], "last_run": w["last_run"],
            "next_run": nxt, "last_scan": w["last_scan"], "error": w["last_error"]}


@app.get("/api/watch")
def api_watch():
    with closing(_con()) as con:
        items = [_item(w) for w in con.execute("SELECT * FROM watch ORDER BY id").fetchall()]
        alerts = [dict(a) for a in con.execute("SELECT id, ts, watch_id, target, summary, worse, scan_id, seen FROM alerts ORDER BY id DESC LIMIT 40").fetchall()]
        unseen = con.execute("SELECT COUNT(*) FROM alerts WHERE seen=0").fetchone()[0]
    return jsonify(items=items, alerts=alerts, unseen=unseen, intervals=list(INTERVALS))


@app.post("/api/watch")
def api_watch_add():
    j = request.get_json(silent=True) or {}
    target = str(j.get("target", "")).strip()[:253]
    hours = j.get("interval_h")
    d = detect(target) if target else {"type": ""}
    if d["type"] not in WATCH_TYPES:
        return jsonify(error="Only domains and IP addresses can be watched."), 400
    if hours not in INTERVALS:
        return jsonify(error="Pick one of: " + ", ".join(f"{h} h" for h in INTERVALS)), 400
    value = d["value"].lower() if d["type"] == "domain" else d["value"]
    with _db_lock, closing(_con()) as con:
        if con.execute("SELECT COUNT(*) FROM watch").fetchone()[0] >= MAX_WATCH:
            return jsonify(error=f"At most {MAX_WATCH} targets can be watched."), 400
        if con.execute("SELECT 1 FROM watch WHERE target=?", (value,)).fetchone():
            return jsonify(error="Already on the watchlist."), 409
        cur = con.execute("INSERT INTO watch(target, type, interval_h, added) VALUES(?,?,?,?)", (value, d["type"], hours, _now().isoformat()))
        con.commit()
    return jsonify(id=cur.lastrowid, target=value)


@app.post("/api/watch/<int:wid>/delete")
def api_watch_delete(wid):
    with _db_lock, closing(_con()) as con:
        con.execute("DELETE FROM watch WHERE id=?", (wid,))
        con.commit()
    return jsonify(ok=True)


@app.post("/api/watch/<int:wid>/run")
def api_watch_run(wid):
    alert = run_watch(wid)
    with closing(_con()) as con:
        w = con.execute("SELECT * FROM watch WHERE id=?", (wid,)).fetchone()
    return jsonify(item=_item(w) if w else None, alert=alert)


@app.get("/api/alert/<int:aid>")
def api_alert(aid):
    with closing(_con()) as con:
        a = con.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    if not a:
        return jsonify(error="Not found"), 404
    d = dict(a)
    d["detail"] = json.loads(d["detail"] or "{}")
    return jsonify(d)


@app.post("/api/alerts/seen")
def api_alerts_seen():
    with _db_lock, closing(_con()) as con:
        con.execute("UPDATE alerts SET seen=1")
        con.commit()
    return jsonify(ok=True)
