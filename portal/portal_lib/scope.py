"""Scope list and lab mode for CTFs, labs and bug-bounty programmes.

* Scope list: the hosts, domains and CIDR ranges you are allowed to test (for example 10.10.10.0/24 or *.target.htb).
* Scope lock (optional, off by default): active tools and the attack-surface map refuse anything not on the list.
* Lab mode (optional, off by default): server-side fetches (site, URL and surface modules) may reach PRIVATE addresses,
  but only for hosts on the list. Loopback and link-local addresses (PORTAL itself, cloud metadata) are never allowed.
Stored in the local history database; nothing leaves this computer.
"""
from __future__ import annotations

import ipaddress
from contextlib import closing
from datetime import datetime, timezone

from flask import jsonify, request

from . import core
from .core import DOMAIN_RE, app
from .store import _db, _db_lock

MAX_ENTRIES = 50
_ready = False


def _con():
    global _ready
    con = _db()
    if not _ready:
        con.execute("CREATE TABLE IF NOT EXISTS scope(id INTEGER PRIMARY KEY AUTOINCREMENT, entry TEXT UNIQUE NOT NULL, note TEXT DEFAULT '', added TEXT NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        con.commit()
        _ready = True
    return con


def normalise(raw):
    """Domain, IP or CIDR -> canonical text, or None. Very wide ranges are refused so 'scope' cannot mean 'everything'."""
    s = str(raw or "").strip().lower().lstrip("*.").rstrip(".")
    if not s or len(s) > 100:
        return None
    try:
        net = ipaddress.ip_network(s, strict=False)
        if net.prefixlen < (16 if net.version == 4 else 48):
            return None
        if net.is_multicast or net.is_unspecified or net.is_loopback or net.is_link_local:
            return None
        return str(net) if "/" in s else str(net.network_address)
    except ValueError:
        pass
    return s if DOMAIN_RE.match(s) else None


def _entries():
    with closing(_con()) as con:
        return [r["entry"] for r in con.execute("SELECT entry FROM scope").fetchall()]


def _setting(k):
    with closing(_con()) as con:
        r = con.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return bool(r and r["v"] == "1")


def matches(host, entry):
    host = str(host or "").strip().lower().strip("[]").rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        try:
            return ip in ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False                                   # an IP never matches a domain entry
    return host == entry or host.endswith("." + entry)


def in_scope(host):
    return any(matches(host, e) for e in _entries())


def scope_error(host):
    """None if an active action on `host` is allowed, else a message for the user."""
    if not _setting("enforce"):
        return None
    if not _entries():
        return "Scope lock is on and the scope list is empty. Add the host you are allowed to test (⋯ → Scope & lab mode)."
    return None if in_scope(host) else f"{host} is not on your scope list. Add it in ⋯ → Scope & lab mode if you are allowed to test it."


def lab_allows(hostname, ip):
    if not _setting("lab"):
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or not ip.is_private:
        return False
    return in_scope(hostname) or in_scope(str(ip))


core.LAB_HOOK = lab_allows


@app.get("/api/scope")
def api_scope():
    with closing(_con()) as con:
        items = [dict(r) for r in con.execute("SELECT id, entry, note, added FROM scope ORDER BY id").fetchall()]
    return jsonify(items=items, enforce=_setting("enforce"), lab=_setting("lab"))


@app.post("/api/scope")
def api_scope_add():
    j = request.get_json(silent=True) or {}
    entry = normalise(j.get("entry"))
    if not entry:
        return jsonify(error="Enter a domain, an IP address or a CIDR range of at least /16 (for example 10.10.10.0/24)."), 400
    with _db_lock, closing(_con()) as con:
        if con.execute("SELECT COUNT(*) FROM scope").fetchone()[0] >= MAX_ENTRIES:
            return jsonify(error=f"At most {MAX_ENTRIES} entries."), 400
        try:
            con.execute("INSERT INTO scope(entry, note, added) VALUES(?,?,?)", (entry, str(j.get("note", ""))[:200], datetime.now(timezone.utc).isoformat()))
            con.commit()
        except Exception:
            return jsonify(error="Already on the list."), 409
    return jsonify(ok=True, entry=entry)


@app.post("/api/scope/<int:sid>/delete")
def api_scope_delete(sid):
    with _db_lock, closing(_con()) as con:
        con.execute("DELETE FROM scope WHERE id=?", (sid,))
        con.commit()
    return jsonify(ok=True)


@app.post("/api/scope/settings")
def api_scope_settings():
    j = request.get_json(silent=True) or {}
    with _db_lock, closing(_con()) as con:
        for k in ("enforce", "lab"):
            if k in j:
                con.execute("INSERT INTO settings(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, "1" if j[k] is True else "0"))
        con.commit()
    return jsonify(ok=True, enforce=_setting("enforce"), lab=_setting("lab"))
