"""Threat intelligence: CVE (with EPSS), file hashes, exposure (Shodan InternetDB) and reputation feeds."""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import urllib.request
from datetime import datetime, timezone
from urllib.parse import quote

from .core import CVE_RE, R, cached, chip, detect, http_json, row

def epss_scores(cves):
    """EPSS (FIRST.org): estimated probability that a CVE is exploited in the next 30 days.
    Returns {CVE: {"epss": 0..1, "pct": 0..1}}; empty on any failure so callers never break."""
    ids = sorted({str(c).upper() for c in cves if CVE_RE.match(str(c or ""))})[:50]
    if not ids:
        return {}
    def fetch():
        d = http_json("https://api.first.org/data/v1/epss?cve=" + ",".join(ids), timeout=10)
        out = {}
        for r in d.get("data") or []:
            try:
                out[str(r["cve"]).upper()] = {"epss": float(r["epss"]), "pct": float(r["percentile"])}
            except (KeyError, TypeError, ValueError):
                pass
        return out
    try:
        return cached("epss|" + ",".join(ids), 3600, fetch)
    except Exception:
        return {}

def epss_chip(p, label="EPSS"):
    return chip(label, f"{p * 100:.1f}% exploit chance (30 d)", "bad" if p >= 0.5 else "warn" if p >= 0.1 else "info")

def mod_cve(q):
    cid = q.upper()
    d = http_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote(cid)}", timeout=15)
    vulns = d.get("vulnerabilities") or []
    if not vulns:
        return R("CVE details", "☢", "warn", note="Not found in NVD (it may be reserved or not yet published).")
    c = vulns[0]["cve"]
    desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
    score = sev = vec = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        ms = (c.get("metrics") or {}).get(key)
        if ms:
            cd = ms[0]["cvssData"]
            score, vec = cd.get("baseScore"), cd.get("vectorString")
            sev = cd.get("baseSeverity") or ms[0].get("baseSeverity")
            break
    chips = []
    if score is not None:
        chips.append(chip("CVSS", f"{score} {sev or ''}".strip(), "bad" if score >= 7 else "warn" if score >= 4 else "info"))
    if c.get("cisaExploitAdd"):
        chips.append(chip("Known exploited (CISA KEV)", None, "bad"))
    ep = epss_scores([cid]).get(cid)
    if ep:
        chips.append(epss_chip(ep["epss"]))
    cwes = [dd["value"] for w in c.get("weaknesses", []) for dd in w.get("description", [])]
    rows = [row("ID", c.get("id")), row("Published", (c.get("published") or "")[:10]), row("Modified", (c.get("lastModified") or "")[:10]), row("Vector", vec), row("Weakness", ", ".join(cwes)), row("KEV due date", c.get("cisaActionDue")), row("KEV action", c.get("cisaRequiredAction"))]
    rows = [r for r in rows if r[1] not in ("", "None")]
    links = [{"label": (r["url"][:40] + "…") if len(r["url"]) > 40 else r["url"], "url": r["url"]} for r in (c.get("references") or [])[:6]]
    return R("CVE details", "☢", highlights=chips, sections=[{"title": "Record", "rows": rows}], note=desc[:1200], links=links,
             epss={cid: ep["epss"]} if ep else {})

def mod_hash(q):
    kinds = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
    k = kinds.get(len(q), "?")
    chips = [chip("Algorithm", k, "info")]
    if k != "SHA-256":
        chips.append(chip("Weak hash", "collisions possible", "warn"))
    return R("Hash", "#", highlights=chips, sections=[{"title": "Value", "rows": [row(k, q)]}], note="No offline database. Use the lookup links to check reputation sources.")

RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}

COMMON_PORTS = {22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "submission", 993: "IMAPS", 995: "POP3S", 8080: "HTTP-alt", 8443: "HTTPS-alt"}

def mod_exposure(q):
    ip = ipaddress.ip_address(q.strip())
    if not ip.is_global:
        return R("Exposure (Shodan)", "☢", "info", note="Non-public address; nothing to look up.")
    try:
        idb = http_json(f"https://internetdb.shodan.io/{ip}", timeout=10)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        idb = None
    full, note = None, "Passive data from Shodan's own scans; Portal sends nothing to the target."
    key = os.environ.get("SHODAN_API_KEY")
    if key:
        try:
            full = http_json(f"https://api.shodan.io/shodan/host/{ip}?key={quote(key)}", timeout=15)
        except urllib.error.HTTPError as e:
            if e.code != 404:
                note = f"Shodan API returned HTTP {e.code}; showing InternetDB only."
    else:
        note += " Set SHODAN_API_KEY for banners and product versions."
    if not idb and not full:
        return R("Exposure (Shodan)", "☢", "ok", highlights=[chip("Not indexed", "no known open services", "ok")], note=note)
    idb, full = idb or {}, full or {}
    ports = sorted(set(idb.get("ports", [])) | set(full.get("ports", [])))
    vulns = sorted(set(idb.get("vulns", [])) | set(full.get("vulns", []) or []))
    hosts = sorted(set(idb.get("hostnames", [])) | set(full.get("hostnames", [])))
    risky = [RISKY_PORTS[p] for p in ports if p in RISKY_PORTS]
    chips = [chip("Open ports", str(len(ports)), "bad" if risky else "warn" if len(ports) > 10 else "info")]
    if risky:
        chips.append(chip("Risky services", ", ".join(risky[:5]), "bad"))
    ep = epss_scores(vulns) if vulns else {}
    if vulns:
        vulns.sort(key=lambda v: (-ep.get(v, {}).get("epss", 0), v))     # most likely to be exploited first
        chips.append(chip("Known vulns", str(len(vulns)), "bad"))
        if ep:
            chips.append(epss_chip(max(e["epss"] for e in ep.values()), "Top EPSS"))
    for t in (idb.get("tags") or [])[:4]:
        chips.append(chip("Tag", t, "warn" if t in ("malware", "scanner", "compromised", "c2") else "info"))
    products = {}
    for s in full.get("data", []) or []:
        label = " ".join(x for x in (s.get("product"), s.get("version")) if x)
        if label:
            products[s.get("port")] = label
    def port_row(p):
        name = RISKY_PORTS.get(p) or COMMON_PORTS.get(p)
        val = products.get(p, "") or ("exposed service" if p in RISKY_PORTS else "")
        return [f"{p}/{name}" if name else str(p), {"text": val, "tone": "bad"} if p in RISKY_PORTS else val]

    sections = [{"title": "Open ports", "rows": [port_row(p) for p in ports]}]
    if vulns:
        sections.append({"title": "Known vulnerabilities",
                         "rows": [["CVE", v] for v in vulns[:30]]})
    if hosts:
        sections.append({"title": "Hostnames", "rows": [["host", h] for h in hosts[:15]]})
    if idb.get("cpes"):
        sections.append({"title": "Software (CPE)", "rows": [["cpe", c] for c in idb["cpes"][:15]]})
    if full.get("org") or full.get("os"):
        sections.append({"title": "Shodan host", "rows": [r for r in (row("Org", full.get("org")), row("OS", full.get("os")), row("Last seen", (full.get("last_update") or "")[:10])) if r[1] not in ("", "None")]})
    pivots = [{"module": "cve", "q": v, "label": v, "auto": i < 2} for i, v in enumerate(vulns[:6])]
    return R("Exposure (Shodan)", "☢", highlights=chips, sections=sections, pivots=pivots, note=note,
             epss={v: e["epss"] for v, e in ep.items()})

def _day(ts):
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).date().isoformat()
    except Exception:
        return None

def _vt(path):
    d = http_json(f"https://www.virustotal.com/api/v3/{path}", {"x-apikey": os.environ["VT_API_KEY"]}, timeout=15)
    a = (d.get("data") or {}).get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    mal, sus, tot = st.get("malicious", 0), st.get("suspicious", 0), sum(st.values())
    tone = "bad" if mal >= 3 else "warn" if (mal or sus) else "ok"
    chips = [chip("VirusTotal", f"{mal} malicious · {sus} suspicious / {tot}", tone)]
    rows = [row("Reputation", a.get("reputation")), row("Tags", ", ".join(a.get("tags", [])[:8])), row("Type", a.get("type_description")),
            row("Name", a.get("meaningful_name")), row("First seen", _day(a.get("first_submission_date"))),
            row("Last analysed", _day(a.get("last_analysis_date"))),
            row("Categories", ", ".join(sorted(set((a.get("categories") or {}).values()))[:6]))]
    return chips, [r for r in rows if r[1] not in ("", "None")]

def mod_reputation(q):
    d = detect(q)
    t, v = d["type"], d["value"]
    chips, sections, notes = [], [], []
    if t == "ip":
        try:
            try:
                g = http_json(f"https://api.greynoise.io/v3/community/{quote(v)}", timeout=10)
            except urllib.error.HTTPError as e:
                if e.code != 404:
                    raise
                g = json.loads(e.read().decode("utf-8", "replace") or "{}")
            cls = g.get("classification")
            if g.get("noise") or cls:
                chips.append(chip("GreyNoise", cls or "seen", {"malicious": "bad", "benign": "ok"}.get(cls, "warn" if g.get("noise") else "info")))
                if g.get("noise"):
                    chips.append(chip("Internet scanner", "seen scanning", "warn"))
                if g.get("riot"):
                    chips.append(chip("Common service", g.get("name") or "RIOT", "info"))
                sections.append({"title": "GreyNoise", "rows": [r for r in (row("Name", g.get("name")), row("Last seen", g.get("last_seen")), row("Link", g.get("link"))) if r[1] not in ("", "None")]})
            else:
                chips.append(chip("GreyNoise", "not observed", "ok"))
        except Exception as e:
            notes.append(f"GreyNoise: {e}")
        if os.environ.get("ABUSEIPDB_API_KEY"):
            try:
                a = http_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(v)}&maxAgeInDays=90", {"Key": os.environ["ABUSEIPDB_API_KEY"]}, timeout=12)["data"]
                s = a.get("abuseConfidenceScore", 0)
                chips.append(chip("AbuseIPDB", f"{s}% confidence", "bad" if s >= 75 else "warn" if s >= 25 else "ok"))
                sections.append({"title": "AbuseIPDB (90 days)", "rows": [r for r in (row("Reports", a.get("totalReports")), row("Distinct reporters", a.get("numDistinctUsers")), row("Usage type", a.get("usageType")), row("ISP", a.get("isp")), row("Last reported", (a.get("lastReportedAt") or "")[:10])) if r[1] not in ("", "None")]})
            except Exception as e:
                notes.append(f"AbuseIPDB: {e}")
    paths = {"ip": f"ip_addresses/{v}", "domain": f"domains/{v}", "hash": f"files/{v}"}
    if t == "url":
        paths["url"] = "urls/" + base64.urlsafe_b64encode(v.encode()).decode().strip("=")
    if os.environ.get("VT_API_KEY") and t in paths:
        try:
            c, r = _vt(paths[t])
            chips += c
            sections.append({"title": "VirusTotal", "rows": r})
        except urllib.error.HTTPError as e:
            chips.append(chip("VirusTotal", "not seen" if e.code == 404 else f"HTTP {e.code}", "info"))
        except Exception as e:
            notes.append(f"VirusTotal: {e}")
    missing = [k for k in ("VT_API_KEY", "ABUSEIPDB_API_KEY") if not os.environ.get(k) and (k == "VT_API_KEY" or t == "ip")]
    if missing:
        notes.append("Set " + " / ".join(missing) + " to add more reputation sources.")
    if not chips and not sections:
        return R("Reputation", "⚖", "info", note=" ".join(notes))
    return R("Reputation", "⚖", highlights=chips, sections=sections, note=" ".join(notes) or None)
