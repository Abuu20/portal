"""Shared foundations: Flask app, request guard, cache, HTTP helpers, result builders, input detection, DNS-over-HTTPS and the SSRF-safe fetcher."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.request
from flask import Flask, abort, request
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urljoin, urlparse

try:
    from PIL import ExifTags, Image, ImageOps
    HAVE_PIL = True
except Exception:  # pragma: no cover
    HAVE_PIL = False

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STATIC = os.path.join(BASE, "static")

UA = "Mozilla/5.0 (X11; Linux x86_64) PortalLocal/1.0"

DATA_DIR = os.environ.get("PORTAL_DATA") or os.path.join(os.path.expanduser("~"), ".local", "share", "portal")

app = Flask(__name__, static_folder=None)

app.config["MAX_CONTENT_LENGTH"] = 300 * 1024 * 1024

@app.before_request
def _guard():
    host = urlparse("//" + (request.host or "")).hostname or ""
    if host not in ("127.0.0.1", "localhost", "::1"):
        abort(403)
    if request.path.startswith("/api/") and request.headers.get("X-Portal") != "1":
        abort(403)

@app.after_request
def _headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: https:; "
        "frame-src https://www.openstreetmap.org; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp

_cache: dict = {}

_cache_lock = threading.Lock()

def cached(key, ttl, fn):
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    val = fn()
    with _cache_lock:
        _cache[key] = (now, val)
    return val

def http_get(url, headers=None, timeout=10, limit=5_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read(limit)

def http_json(url, headers=None, timeout=10):
    _, _, body = http_get(url, {"Accept": "application/json", **(headers or {})}, timeout)
    return json.loads(body.decode("utf-8", "replace"))

TONE_RANK = {"info": 0, "ok": 1, "warn": 2, "bad": 3}

def chip(label, value=None, tone="info"):
    return {"label": label, "value": value, "tone": tone}

def row(k, v, tone=None):
    v = "" if v is None else str(v)
    return [k, v if tone is None else {"text": v, "tone": tone}]

def sev_of(chips):
    best = "info"
    for c in chips:
        if TONE_RANK.get(c["tone"], 0) > TONE_RANK[best]:
            best = c["tone"]
    return best

def R(title, icon="◆", sev=None, highlights=None, **kw):
    d = {"title": title, "icon": icon, "highlights": highlights or []}
    d["severity"] = sev or sev_of(d["highlights"])
    d.update(kw)
    return d

def parse_dt(s):
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def age_text(days):
    if days < 60:
        return f"{days} days"
    if days < 730:
        return f"{days // 30} months"
    return f"{days / 365.25:.1f} years"

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-']+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)$")

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9\-]{2,59})$"
)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

DOI_RE = re.compile(r"^(?:https?://(?:dx\.)?doi\.org/|doi:\s*)?(10\.\d{4,9}/\S+)$", re.I)

HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")

COORD_RE = re.compile(r"^\s*([+-]?\d{1,2}(?:\.\d+)?)\s*[,;\s]\s*([+-]?\d{1,3}(?:\.\d+)?)\s*$")

PHONE_RE = re.compile(r"^\+?[\d\s\-().]{7,20}$")

USERNAME_RE = re.compile(r"^@[A-Za-z0-9_.-]{2,30}$")

IMG_EXT = (".jpg", ".jpeg", ".png", ".webp", ".gif", ".tif", ".tiff", ".bmp")

SHORT_MAP_HOSTS = {"maps.app.goo.gl", "goo.gl"}

def is_maplink(url):
    p = urlparse(url)
    h = (p.hostname or "").lower()
    if h in ("maps.google.com", "maps.app.goo.gl", "maps.apple.com", "www.openstreetmap.org", "openstreetmap.org", "osm.org"):
        return True
    if h in ("www.google.com", "google.com") and p.path.startswith("/maps"):
        return True
    return h == "goo.gl" and p.path.startswith("/maps")

def coords_from_url(url):
    u = unquote(unquote(url))
    pats = (
        r"!3d(-?\d+(?:\.\d+)?)!4d(-?\d+(?:\.\d+)?)",
        r"@(-?\d+\.\d+),(-?\d+\.\d+)",
        r"[?&](?:q|ll|query|sll|center)=(-?\d+(?:\.\d+)?)[,+ ]\s*(-?\d+(?:\.\d+)?)",
        r"[?&]mlat=(-?\d+(?:\.\d+)?)&mlon=(-?\d+(?:\.\d+)?)",
        r"#map=\d+/(-?\d+(?:\.\d+)?)/(-?\d+(?:\.\d+)?)",
    )
    for pat in pats:
        m = re.search(pat, u)
        if m:
            lat, lon = float(m.group(1)), float(m.group(2))
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                return lat, lon
    return None

def detect(q):
    s = q.strip()
    if s.lower().startswith("geo:"):
        m = COORD_RE.match(s[4:].split(";")[0].split("?")[0])
        if m and -90 <= float(m.group(1)) <= 90 and -180 <= float(m.group(2)) <= 180:
            return {"type": "coords", "value": f"{float(m.group(1))}, {float(m.group(2))}", "label": "Coordinates (geo: link)"}
    if CVE_RE.match(s):
        return {"type": "cve", "value": s.upper(), "label": "CVE identifier"}
    m = DOI_RE.match(s)
    if m:
        return {"type": "doi", "value": m.group(1), "label": "DOI (scholarly paper)"}
    if re.match(r"^https?://", s, re.I):
        if is_maplink(s):
            return {"type": "maplink", "value": s, "label": "Map / shared-location link"}
        if urlparse(s).path.lower().endswith(IMG_EXT):
            return {"type": "imageurl", "value": s, "label": "Image URL"}
        return {"type": "url", "value": s, "label": "URL"}
    if EMAIL_RE.match(s):
        return {"type": "email", "value": s.lower(), "label": "Email address"}
    if USERNAME_RE.match(s):
        return {"type": "username", "value": s.lstrip("@"), "label": "Username / handle"}
    try:
        ip = ipaddress.ip_address(s.strip("[]"))
        return {"type": "ip", "value": str(ip), "label": f"IPv{ip.version} address"}
    except ValueError:
        pass
    m = COORD_RE.match(s)
    if m:
        lat, lon = float(m.group(1)), float(m.group(2))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            return {"type": "coords", "value": f"{lat}, {lon}", "label": "Coordinates"}
    if HASH_RE.match(s):
        return {"type": "hash", "value": s.lower(), "label": "File hash"}
    if re.fullmatch(r"\d{8}|\d{12,14}", s):
        return {"type": "barcode", "value": s, "label": "Barcode (EAN/UPC)"}
    if s.startswith("+") or (PHONE_RE.match(s) and sum(c.isdigit() for c in s) >= 7):
        return {"type": "phone", "value": s, "label": "Phone number"}
    d = s.lower().rstrip(".")
    if DOMAIN_RE.match(d):
        return {"type": "domain", "value": d, "label": "Domain"}
    return {"type": "text", "value": s, "label": "Free text"}

PLANS = {
    "ip": [
        ("ip", "IP intelligence"), ("exposure", "Exposure (Shodan)"), ("reputation", "Reputation"),
        ("rdap_ip", "Network registration"), ("tools", "Local toolbox"), ("links", "Pivot links"),
    ],
    "domain": [
        ("dns", "DNS records"), ("rdap", "Registration (RDAP)"), ("tls", "TLS certificate"),
        ("web", "Site intelligence"), ("subs", "Subdomains (CT logs)"), ("reputation", "Reputation"),
        ("tools", "Local toolbox"), ("links", "Pivot links"),
    ],
    "email": [("email", "Email analysis"), ("links", "Pivot links")],
    "url": [("url", "URL & headers"), ("web", "Site intelligence"), ("reputation", "Reputation"),
            ("tools", "Local toolbox"), ("links", "Pivot links")],
    "imageurl": [("imageurl", "Image analysis"), ("links", "Reverse-image pivots")],
    "coords": [("coords", "Location"), ("links", "Map links")],
    "maplink": [("maplink", "Shared location link")],
    "barcode": [("product", "Product"), ("links", "Lookup links")],
    "cve": [("cve", "CVE details"), ("links", "References")],
    "hash": [("hash", "Hash"), ("reputation", "Reputation"), ("links", "Lookup links")],
    "username": [("sherlock", "Sherlock OSINT"), ("maigret", "Maigret OSINT")],
    "phone": [("phone", "Phone intelligence")],
    "doi": [("scholar", "Paper")],
    "text": [
        ("entity", "Encyclopedia match"), ("wikidata", "Wikidata profile"), 
        ("scholar", "Papers & journals"), ("news", "News coverage"),
        ("launch", "Search the platforms"), ("place", "Place search"),
        ("product_search", "Product search"), ("links", "Search links"),
    ],
}

DNS_TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2, "TXT": 16, "CAA": 257, "SOA": 6}

def doh(name, rtype):
    d = http_json(
        f"https://cloudflare-dns.com/dns-query?name={quote(name)}&type={rtype}",
        {"Accept": "application/dns-json"},
        timeout=8,
    )
    out = []
    for a in d.get("Answer") or []:
        if a.get("type") == DNS_TYPES[rtype]:
            data = a.get("data", "")
            if rtype == "TXT":
                parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
                data = "".join(parts) if parts else data.strip('"')
            out.append(data)
    return out

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

_opener = urllib.request.build_opener(_NoRedirect)

LAB_HOOK = None          # set by scope.py: lets listed lab hosts (private ranges) through


def _check_public(url):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Only http(s) URLs are supported")
    port = p.port or (443 if p.scheme == "https" else 80)
    for info in socket.getaddrinfo(p.hostname, port, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            if LAB_HOOK and LAB_HOOK(p.hostname, ip):
                continue
            raise ValueError(f"Refusing to fetch non-public address {ip}")

def fetch_chain(url, max_hops=6, max_bytes=0):
    chain, cur = [], url
    code, hdrs, body = 0, {}, b""
    for _ in range(max_hops + 1):
        _check_public(cur)
        req = urllib.request.Request(cur, headers={"User-Agent": UA})
        try:
            r = _opener.open(req, timeout=10)
            code, hdrs = r.status, r.headers
            body = r.read(max_bytes) if max_bytes else b""
            r.close()
        except urllib.error.HTTPError as e:
            code, hdrs, body = e.code, e.headers, b""
        chain.append({"url": cur, "status": code})
        loc = hdrs.get("Location")
        if code in (301, 302, 303, 307, 308) and loc:
            cur = urljoin(cur, loc)
            continue
        break
    return chain, code, hdrs, body, cur

def _is_ip(s):
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False

def norm_url(t):
    """A host/IP becomes https://host/ (http for bare IPs); a full URL must be http(s) with a valid host and no credentials."""
    t = (t or "").strip()
    if not t or len(t) > 2000 or t.startswith("-") or any(ord(c) < 33 for c in t):
        return None
    if not re.match(r"^https?://", t, re.I):
        h = valid_target(t)
        if not h:
            return None
        host = f"[{h}]" if ":" in h else h
        return f"{'http' if _is_ip(h) else 'https'}://{host}/"
    p = urlparse(t)
    try:
        port = p.port
    except ValueError:
        return None
    if p.username or p.password or not p.hostname or valid_target(p.hostname) is None:
        return None
    return t

def valid_target(t):
    t = (t or "").strip()
    if not t or t.startswith("-") or len(t) > 253:
        return None
    try:
        ip = ipaddress.ip_address(t.strip("[]"))
        return None if ip.is_multicast or ip.is_unspecified else str(ip)
    except ValueError:
        pass
    t = t.lower().rstrip(".")
    return t if DOMAIN_RE.match(t) else None
