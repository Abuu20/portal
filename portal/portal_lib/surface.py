"""Attack-surface map: probe and rank subdomains (needs the authorisation tick-box)."""
from __future__ import annotations

import re
import ssl
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from flask import jsonify, request

from .scope import scope_error
from .core import DOMAIN_RE, R, UA, _check_public, _opener, app, cached, chip, doh
from .net import mod_subs
from .web import TECH_HTML, _Page

# ---------------------------------------------------------------------------
# Attack-surface map: subdomains from CT logs -> which resolve -> one GET / each -> ranked table.
# Active (it contacts every probed host), so /api/surface needs the authorisation tick-box. Capped, public
# addresses only (_check_public), one request per scheme, no crawling, no payloads.
# ---------------------------------------------------------------------------
SURFACE_MAX = 40

SENSITIVE_LABELS = {"admin", "administrator", "adm", "dev", "develop", "test", "testing", "stage", "staging", "uat", "qa", "beta",
                    "internal", "intranet", "vpn", "jenkins", "gitlab", "git", "ci", "grafana", "kibana", "prometheus", "phpmyadmin",
                    "pma", "backup", "old", "legacy", "sandbox", "demo", "jira", "confluence", "db", "sql", "redis", "elastic", "sso",
                    "preprod", "pre", "stg", "debug", "console", "panel", "cpanel", "webmail"}

# (provider CNAME suffix, text a dead/unclaimed endpoint shows). Conservative list; a hit is reported as "possible".
TAKEOVER = [("github.io", "There isn't a GitHub Pages site here"), ("herokuapp.com", "No such app"),
            ("amazonaws.com", "NoSuchBucket"), ("azurewebsites.net", "Error 404 - Web app not found"),
            ("fastly.net", "Fastly error: unknown domain"), ("pantheonsite.io", "404 error unknown site"),
            ("readme.io", "Project doesnt exist"), ("surge.sh", "project not found")]

DEFAULT_PAGES = ("welcome to nginx", "apache2 ubuntu default page", "apache2 debian default page", "iis windows server",
                 "test page for the apache", "default web site page")

def _label_hit(host, domain):
    sub = host[: -len(domain)].rstrip(".") if host.endswith(domain) else host
    for lab in re.split(r"[.\-_]", sub):
        base = lab.rstrip("0123456789")
        if base in SENSITIVE_LABELS:
            return base
    return None

def _fetch_once(url, limit=200_000):
    """One request, no redirect following. Returns (status, headers, body, location); body is read for error statuses too."""
    _check_public(url)
    try:
        r = _opener.open(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=8)
        try:
            return r.status, r.headers, r.read(limit), None
        finally:
            r.close()
    except urllib.error.HTTPError as e:
        try:
            body = e.read(limit)
        except Exception:
            body = b""
        return e.code, e.headers, body, e.headers.get("Location")

def probe_host(host, domain):
    """DNS + one GET for a single subdomain. Never raises; returns a dict describing what was seen."""
    info = {"host": host, "ips": [], "cname": "", "alive": False, "scheme": "", "status": 0, "title": "", "server": "",
            "tech": [], "login": False, "redirect": "", "notes": []}
    try:
        info["ips"] = doh(host, "A")[:4] + doh(host, "AAAA")[:2]
        cn = doh(host, "CNAME")
        info["cname"] = cn[0].rstrip(".").lower() if cn else ""
    except Exception:
        pass
    last_err = ""
    for scheme in ("https", "http"):
        try:
            code, hdrs, body, loc = _fetch_once(f"{scheme}://{host}/")
        except ValueError as e:                      # non-public address: report, never connect
            info["notes"].append(str(e))
            break
        except Exception as e:
            last_err = type(e).__name__
            if scheme == "https" and isinstance(getattr(e, "reason", None), ssl.SSLError):
                info["notes"].append("TLS error on https")
            continue
        info.update(alive=True, scheme=scheme, status=code, server=(hdrs.get("Server") or "")[:60], redirect=(loc or "")[:200])
        text = body.decode("utf-8", "replace")
        page = _Page(f"{scheme}://{host}/")
        try:
            page.feed(text)
        except Exception:
            pass
        info["title"] = " ".join(page.title.split())[:80]
        info["login"] = bool(page.pw)
        low = text.lower()
        info["tech"] = [n for n, rx in TECH_HTML if re.search(rx, low)][:5]
        for suffix, phrase in TAKEOVER:
            if info["cname"].endswith(suffix) and phrase.lower() in low:
                info["notes"].append(f"possible takeover: CNAME {info['cname']} serves “{phrase}”")
        if "index of /" in info["title"].lower() or "<title>index of" in low[:2000]:
            info["notes"].append("directory listing")
        if any(d in low[:4000] for d in DEFAULT_PAGES):
            info["notes"].append("default web-server page")
        if scheme == "http":
            info["notes"].append("no HTTPS (only http answered)")
        break
    if not info["alive"] and info["cname"] and not info["ips"]:
        info["notes"].append(f"dangling CNAME → {info['cname']} (no address)")
    if not info["alive"] and last_err and info["ips"]:
        info["notes"].append(f"resolves but no web service answered ({last_err})")
    return info

def score_host(info, domain):
    """Heuristic 0-100 with every contribution listed. Says what deserves a look first, not that something is vulnerable."""
    pts = []
    def add(n, why):
        pts.append((n, why))
    lab = _label_hit(info["host"], domain)
    for note in info["notes"]:
        if note.startswith("possible takeover"):
            add(60, note)
        elif note.startswith("dangling CNAME"):
            add(25, note)
        elif note == "directory listing":
            add(30, "directory listing is enabled")
        elif note == "default web-server page":
            add(10, "default web-server page (unfinished or forgotten site)")
        elif note.startswith("no HTTPS"):
            add(15, "only plain http answers")
        elif note.startswith("Refusing to fetch non-public"):
            add(10, "public DNS name points at a private address")
        elif note == "TLS error on https":
            add(8, "https handshake fails")
    if lab and info["alive"]:
        add(25, f"name suggests a non-production or admin system (“{lab}”)")
    if info["login"]:
        add(15, "login form")
    if re.search(r"\d+\.\d+", info["server"]):
        add(8, f"discloses server version ({info['server'][:30]})")
    score = min(100, sum(n for n, _ in pts))
    return score, [f"+{n} {why}" for n, why in pts if n]

def surface_scan(domain, names):
    """Probe up to SURFACE_MAX subdomains (sensitive-looking names first) and return ranked hosts."""
    cand = sorted({n for n in names if n != domain and DOMAIN_RE.match(n) and n.endswith("." + domain)},
                  key=lambda n: (_label_hit(n, domain) is None, len(n), n))
    probe = cand[:SURFACE_MAX]
    hosts = []
    with ThreadPoolExecutor(8) as ex:
        futs = [ex.submit(probe_host, h, domain) for h in probe]
        for f in futs:
            try:
                hosts.append(f.result(timeout=60))
            except Exception:
                pass
    for h in hosts:
        h["score"], h["reasons"] = score_host(h, domain)
    hosts.sort(key=lambda h: (-h["score"], not h["alive"], h["host"]))
    return hosts, len(cand)

def surface_result(domain, hosts, total):
    alive = [h for h in hosts if h["alive"]]
    flagged = [h for h in hosts if h["score"] >= 40]
    chips = [chip("Subdomains probed", f"{len(hosts)} of {total}", "info"), chip("Answering on web", str(len(alive)), "info")]
    if flagged:
        chips.append(chip("Worth a look", str(len(flagged)), "bad" if any(h["score"] >= 60 for h in flagged) else "warn"))
    rows = []
    for h in hosts:
        if not (h["alive"] or h["notes"]):
            continue
        bits = [f"{h['score']:>3}", f"{h['status'] or '—'}", (h["title"] or h["server"] or "")[:40]] + [r for r in h["reasons"][:2]]
        rows.append([h["host"], {"text": "  ".join(b for b in bits if b), "tone": "bad" if h["score"] >= 60 else "warn" if h["score"] >= 30 else None}])
    quiet = [h["host"] for h in hosts if not h["alive"] and not h["notes"]]
    sections = [{"title": "Ranked by what to look at first", "rows": rows or [["", "nothing answered"]]}]
    pivots = [{"module": "web", "q": h["host"], "label": h["host"], "auto": False} for h in hosts[:5] if h["alive"]]
    note = (f"Probed {len(hosts)} of {total} names found in certificate logs: one request each, no crawling. "
            f"{len(quiet)} did not resolve or answer. Scores are a heuristic: they say what to look at first, not that something is vulnerable.")
    return R("Attack surface", "◈", highlights=chips, sections=sections, pivots=pivots, note=note)

_surface_gate = threading.Semaphore(1)

@app.post("/api/surface")
def api_surface():
    j = request.get_json(silent=True) or {}
    domain = str(j.get("domain", "")).strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        return jsonify(error="Enter a domain name"), 400
    if bad := scope_error(domain):
        return jsonify(error=bad), 403
    if j.get("confirm") is not True:
        return jsonify(error="Tick the authorisation box: this contacts every probed subdomain"), 400
    if not _surface_gate.acquire(blocking=False):
        return jsonify(error="Another surface scan is still running"), 429
    try:
        try:
            names = cached("subs|" + domain, 600, lambda: mod_subs(domain))["list"]
        except Exception as e:
            return jsonify(error=f"Could not read certificate-transparency logs: {e}"), 502
        hosts, total = surface_scan(domain, names)
        slim = [{k: h[k] for k in ("host", "alive", "status", "score", "reasons", "cname", "login", "title", "server")} for h in hosts]
        return jsonify(result=surface_result(domain, hosts, total), hosts=slim, total=total)
    finally:
        _surface_gate.release()
