"""Module registry, the main /api/run and /api/plan endpoints, triage and static files."""
from __future__ import annotations

import re
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from flask import jsonify, request, send_from_directory

from .core import PLANS, STATIC, TONE_RANK, _cache, _cache_lock, app, detect
from .graph import attach_graph
from .net import mod_dns, mod_email, mod_ip, mod_rdap, mod_rdap_ip, mod_subs, mod_tls, mod_url
from .intel import mod_cve, mod_exposure, mod_hash, mod_reputation
from .web import mod_web
from .geo import mod_coords, mod_maplink, mod_nearby, mod_place
from .files import mod_imageurl
from .accounts import mod_maigret, mod_phone, mod_scope, mod_sherlock
from .lookups import (
    mod_entity,
    mod_launch,
    mod_links,
    mod_news,
    mod_product,
    mod_product_search,
    mod_scholar,
    mod_wikidata,
)
from .tools import mod_tools

MODULES = {
    "launch": mod_launch, "scholar": mod_scholar, "news": mod_news, "wikidata": mod_wikidata,
    "ip": mod_ip, "rdap_ip": mod_rdap_ip, "dns": mod_dns, "rdap": mod_rdap, "tls": mod_tls, "subs": mod_subs,
    "email": mod_email, "url": mod_url, "imageurl": mod_imageurl, "coords": mod_coords, "place": mod_place,
    "product": mod_product, "product_search": mod_product_search, "cve": mod_cve, "hash": mod_hash,
    "scope": mod_scope, "links": mod_links, "maplink": mod_maplink, "nearby": mod_nearby,
    "exposure": mod_exposure, "reputation": mod_reputation, "web": mod_web, "entity": mod_entity, "tools": mod_tools,
    "sherlock": mod_sherlock, "maigret": mod_maigret, "phone": mod_phone,
}

NO_CACHE = {"imageurl", "url", "tools", "sherlock", "maigret", "phone", "wikidata"}

@app.get("/")
def index():
    return send_from_directory(STATIC, "index.html")

@app.get("/static/<path:p>")
def static_files(p):
    return send_from_directory(STATIC, p)

@app.get("/api/plan")
def api_plan():
    q = (request.args.get("q") or "").strip()
    if not q or len(q) > 2000:
        return jsonify(error="Empty or too-long query"), 400
    d = detect(q)
    mods = [{"module": m, "q": d["value"], "title": t} for m, t in PLANS[d["type"]]]
    return jsonify(type=d["type"], label=d["label"], value=d["value"], modules=mods)

def run_module(m, q):
    fn = MODULES.get(m)
    key = f"mod|{m}|{q}"
    if m not in NO_CACHE:
        with _cache_lock:
            hit = _cache.get(key)
        if hit and time.time() - hit[0] < 300:
            return hit[1]
    try:
        res = fn(q)
    except urllib.error.HTTPError as e:
        res = {"error": f"Upstream service returned HTTP {e.code}"}
    except urllib.error.URLError as e:
        res = {"error": f"Network error: {e.reason}"}
    except Exception as e:
        res = {"error": f"{type(e).__name__}: {e}"}
    attach_graph(m, q, res)
    if "error" not in res and m not in NO_CACHE:
        with _cache_lock:
            _cache[key] = (time.time(), res)
    return res

@app.get("/api/run")
def api_run():
    m = request.args.get("module", "")
    q = (request.args.get("q") or "").strip()
    if m not in MODULES or not q or len(q) > 2000:
        return jsonify(error="Bad request"), 400
    return jsonify(run_module(m, q))

MODULES["email_nb"] = lambda q: mod_email(q, breaches=False)

TRIAGE_PLANS = {"ip": ["ip", "exposure", "reputation"], "domain": ["dns", "rdap", "reputation"],
                "url": ["url", "reputation"], "hash": ["reputation"], "email": ["email_nb"], "cve": ["cve"]}

def refang(s):
    s = s.strip().strip("\"'<>()[]{},;")
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    s = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", ".", s, flags=re.I)
    s = re.sub(r"\[:\]", ":", s)
    s = re.sub(r"\[@\]|\[at\]", "@", s, flags=re.I)
    return s

@app.get("/api/triage")
def api_triage():
    raw = (request.args.get("q") or "").strip()
    if not raw or len(raw) > 2000:
        return jsonify(error="Bad request"), 400
    q = refang(raw)
    d = detect(q)
    plan = TRIAGE_PLANS.get(d["type"])
    if not plan:
        return jsonify(item=raw, type=d["type"], label=d["label"], severity="info", chips=[], errors=[],
                       unsupported=True, note="Bulk handles IPs, domains, URLs, hashes, emails and CVE IDs.")
    with ThreadPoolExecutor(len(plan)) as ex:
        futs = {m: ex.submit(run_module, m, d["value"]) for m in plan}
        results = {m: f.result() for m, f in futs.items()}
    chips, errors, sev = [], [], "info"
    for m, r in results.items():
        if r.get("error"):
            errors.append(f"{m}: {r['error']}")
            continue
        if TONE_RANK.get(r.get("severity"), 0) > TONE_RANK[sev]:
            sev = r["severity"]
        chips += r.get("highlights") or []
    chips.sort(key=lambda c: -TONE_RANK.get(c.get("tone"), 0))
    seen, top = set(), []
    for c in chips:
        k = (c.get("label"), c.get("value"))
        if k not in seen:
            seen.add(k)
            top.append(c)
    return jsonify(item=raw, value=d["value"], type=d["type"], label=d["label"], severity=sev, chips=top[:6], errors=errors)
