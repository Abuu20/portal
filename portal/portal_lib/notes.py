"""Notebook: short notes and evidence kept locally (a flag candidate, a credential you found in a lab, a TODO)."""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone

from flask import jsonify, request

from .core import app
from .store import _db, _db_lock

MAX_NOTES = 500
_ready = False


def _con():
    global _ready
    con = _db()
    if not _ready:
        con.execute("CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, tag TEXT DEFAULT '', title TEXT NOT NULL, body TEXT DEFAULT '')")
        con.commit()
        _ready = True
    return con


@app.get("/api/notes")
def api_notes():
    with closing(_con()) as con:
        rows = [dict(r) for r in con.execute("SELECT id, ts, tag, title, body FROM notes ORDER BY id DESC LIMIT 200").fetchall()]
    return jsonify(items=rows)


@app.post("/api/notes")
def api_notes_add():
    j = request.get_json(silent=True) or {}
    title, body, tag = str(j.get("title", "")).strip()[:200], str(j.get("body", ""))[:20000], str(j.get("tag", "")).strip()[:30]
    if not title:
        return jsonify(error="Give the note a title."), 400
    with _db_lock, closing(_con()) as con:
        if con.execute("SELECT COUNT(*) FROM notes").fetchone()[0] >= MAX_NOTES:
            return jsonify(error=f"At most {MAX_NOTES} notes. Export and delete some."), 400
        cur = con.execute("INSERT INTO notes(ts, tag, title, body) VALUES(?,?,?,?)", (datetime.now(timezone.utc).replace(microsecond=0).isoformat(), tag, title, body))
        con.commit()
    return jsonify(id=cur.lastrowid)


@app.post("/api/notes/<int:nid>/delete")
def api_notes_delete(nid):
    with _db_lock, closing(_con()) as con:
        con.execute("DELETE FROM notes WHERE id=?", (nid,))
        con.commit()
    return jsonify(ok=True)
