"""Relationship graph: turns a module's result into typed nodes and labelled edges.

Only infrastructure entities are modelled (domain, ip, asn, org, port, cve, weakness, tech, location, email).
Username, phone and social-profile lookups have their own windows and are not drawn in the graph (yet).

Each extractor reads the finished result of one module (its sections, chips and lists), so the modules
themselves stay untouched. The result gains   result["graph"] = {"nodes": [...], "edges": [...], "events": [...]}
and the browser merges the graphs of every open window into one picture.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from .core import DOMAIN_RE, TONE_RANK

MAX_NODES = 60          # per module, so one noisy result cannot flood the canvas
TYPES = ("domain", "ip", "asn", "org", "port", "cve", "weakness", "tech", "location", "email")


def _text(v):
    return str(v.get("text", "") if isinstance(v, dict) else (v if v is not None else "")).strip()


def _tone(v):
    return v.get("tone") if isinstance(v, dict) else None


def rows(res, title, prefix=False):
    """[(key, value, tone)] from the sections whose title matches."""
    out = []
    for s in res.get("sections") or []:
        t = s.get("title", "")
        if t == title or (prefix and t.startswith(title)):
            for r in s.get("rows") or []:
                if len(r) >= 2:
                    out.append((_text(r[0]), _text(r[1]), _tone(r[1])))
    return out


def chip_value(res, label):
    for c in res.get("highlights") or []:
        if c.get("label") == label:
            return _text(c.get("value")), c.get("tone")
    return None, None


class G:
    def __init__(self):
        self.nodes, self.edges, self.events, self._seen = {}, [], [], set()

    def node(self, kind, value, label=None, tone=None):
        v = str(value or "").strip().lower() if kind != "org" else str(value or "").strip()
        shown = str(value or "").strip()
        if kind == "domain":
            v = v.rstrip(".").lstrip("*.")
            shown = v
            if not DOMAIN_RE.match(v.replace("_", "x")):
                return None
        elif kind == "ip":
            try:
                v = str(ipaddress.ip_address(v.strip("[]")))
            except ValueError:
                return None
            shown = v
        elif kind in ("asn", "cve", "weakness"):
            v = shown = v.upper()
        if not v:
            return None
        nid = f"{kind}:{v.lower()}"
        if nid not in self.nodes:
            if len(self.nodes) >= MAX_NODES:
                return None
            self.nodes[nid] = {"id": nid, "type": kind, "label": (label or shown or v)[:60]}
        if tone in ("bad", "warn") and TONE_RANK.get(tone, 0) > TONE_RANK.get(self.nodes[nid].get("tone"), 0):
            self.nodes[nid]["tone"] = tone
        return nid

    def link(self, a, rel, b):
        if a and b and a != b and (a, rel, b) not in self._seen:
            self._seen.add((a, rel, b))
            self.edges.append({"a": a, "b": b, "rel": rel})

    def event(self, date, label, node):
        if node and re.match(r"^\d{4}-\d{2}-\d{2}", date or ""):
            self.events.append({"date": date[:10], "label": label, "node": node})

    def out(self):
        return {"nodes": list(self.nodes.values()), "edges": self.edges, "events": self.events}


def _host(q):
    q = (q or "").strip()
    return (urlparse(q).hostname if "://" in q else q.split("/")[0]) or q


def _dns(q, r):
    g = G(); d = g.node("domain", q)
    for t in ("A", "AAAA"):
        for _, v, _ in rows(r, t):
            g.link(d, t, g.node("ip", v))
    for _, v, _ in rows(r, "CNAME"):
        g.link(d, "CNAME", g.node("domain", v))
    for _, v, _ in rows(r, "MX"):
        g.link(d, "MX", g.node("domain", v.split()[-1] if v.split() else ""))
    for _, v, _ in rows(r, "NS"):
        g.link(d, "NS", g.node("domain", v))
    for _, v, _ in rows(r, "TXT"):
        if v.lower().startswith("v=spf1"):
            for inc in re.findall(r"include:(\S+)", v, re.I)[:8]:
                g.link(d, "SPF include", g.node("domain", inc))
    return g


def _rdap(q, r):
    g = G(); d = g.node("domain", q)
    for k, v, _ in rows(r, "Registration"):
        if k == "Registrar":
            g.link(d, "registrar", g.node("org", v))
        elif k == "Registered":
            g.event(v, "Domain registered", d)
        elif k == "Expires":
            g.event(v, "Domain expires", d)
        elif k == "Last changed":
            g.event(v, "Registration changed", d)
    for _, v, _ in rows(r, "Name servers"):
        g.link(d, "NS", g.node("domain", v))
    return g


def _tls(q, r):
    g = G(); d = g.node("domain", _host(q))
    for k, v, _ in rows(r, "Certificate"):
        if k == "Issuer" and v:
            g.link(d, "certificate issued by", g.node("org", v))
        elif k == "Not before":
            g.event(v, "Certificate issued", d)
        elif k == "Not after":
            g.event(v, "Certificate expires", d)
    for _, v, _ in rows(r, "Subject alt names", prefix=True):
        g.link(d, "SAN", g.node("domain", v))
    return g


def _subs(q, r):
    g = G(); d = g.node("domain", q)
    for h in (r.get("list") or [])[:40]:
        g.link(d, "subdomain", g.node("domain", h))
    return g


def _ip(q, r):
    g = G(); ip = g.node("ip", q)
    asn, _ = chip_value(r, "ASN")
    org, _ = chip_value(r, "Org")
    a = g.node("asn", asn) if asn and asn.upper().startswith("AS") else None
    g.link(ip, "announced by", a)
    if org:
        g.link(a or ip, "operated by", g.node("org", org))
    tor, _ = chip_value(r, "Tor exit node")
    if any(c.get("label") == "Tor exit node" for c in r.get("highlights") or []):
        g.node("ip", q, tone="bad")
    for k, v, _ in rows(r, "Details"):
        if k == "Reverse DNS" and v and v != "(none)":
            g.link(ip, "reverse DNS", g.node("domain", v))
        elif k == "Country" and v:
            g.link(ip, "located in", g.node("location", v))
    return g


def _rdap_ip(q, r):
    g = G(); ip = g.node("ip", q)
    name, _ = chip_value(r, "Network")
    if name and name != "?":
        g.link(ip, "network name", g.node("org", name))
    return g


def _exposure(q, r):
    g = G(); ip = g.node("ip", q)
    epss = r.get("epss") or {}
    for k, v, tone in rows(r, "Open ports"):
        port = k.split("/")[0]
        if port.isdigit():
            g.link(ip, "open port", g.node("port", f"{q}:{port}", label=k, tone=tone))
    for _, v, _ in rows(r, "Known vulnerabilities")[:15]:
        e = epss.get(v, 0)
        g.link(ip, "vulnerable to", g.node("cve", v.upper(), tone="bad" if e >= 0.5 else "warn" if e >= 0.1 else None))
    for _, v, _ in rows(r, "Hostnames")[:10]:
        g.link(ip, "hostname", g.node("domain", v))
    return g


def _cve(q, r):
    g = G()
    kev = any(str(c.get("label", "")).startswith("Known exploited") for c in r.get("highlights") or [])
    e = max((r.get("epss") or {}).values(), default=0)
    c = g.node("cve", q.upper(), tone="bad" if kev or e >= 0.5 else "warn" if e >= 0.1 else None)
    for _, v, _ in rows(r, "Record"):
        for cwe in re.findall(r"CWE-\d+", v):
            g.link(c, "weakness", g.node("weakness", cwe.upper()))
    return g


def _web(q, r):
    g = G(); d = g.node("domain", _host(q))
    for _, v, _ in rows(r, "Technologies (fingerprint)"):
        g.link(d, "runs", g.node("tech", re.sub(r"^[A-Za-z ]+:\s*", "", v)[:40]))
    for k, _, _ in rows(r, "Links to other domains", prefix=True)[:10]:
        g.link(d, "links to", g.node("domain", k))
    for k, v, _ in rows(r, "Page"):
        if k == "Final URL":
            fh = _host(v)
            if fh and fh.lower() != _host(q).lower():
                g.link(d, "redirects to", g.node("domain", fh))
    return g


def _url(q, r):
    g = G(); prev = g.node("domain", _host(q))
    for k, v, _ in rows(r, "Redirect chain"):
        m = re.search(r"https?://\S+", v)
        if m:
            cur = g.node("domain", _host(m.group(0)))
            g.link(prev, "redirects to", cur)
            prev = cur or prev
    return g


def _email(q, r):
    g = G(); addr = q.strip().lower()
    if "@" not in addr:
        return g
    e = g.node("email", addr)
    d = g.node("domain", addr.rsplit("@", 1)[1])
    g.link(e, "mailbox at", d)
    for _, v, _ in rows(r, "Mail servers"):
        g.link(d, "MX", g.node("domain", v.split()[-1] if v.split() else ""))
    return g


EXTRACTORS = {"dns": _dns, "rdap": _rdap, "tls": _tls, "subs": _subs, "ip": _ip, "rdap_ip": _rdap_ip,
              "exposure": _exposure, "cve": _cve, "web": _web, "url": _url, "email": _email}


def attach_graph(module, q, result):
    """Add result["graph"] when the module has relationships worth drawing. Never raises."""
    fn = EXTRACTORS.get(module)
    if not fn or not isinstance(result, dict) or "error" in result:
        return result
    try:
        out = fn(q, result).out()
    except Exception:
        return result
    if out["edges"]:
        result["graph"] = out
    return result
