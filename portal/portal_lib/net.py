"""Network lookups: DNS, registration (RDAP), TLS certificate, subdomains (CT logs), IP, email and URL checks."""
from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

from .core import (
    DNS_TYPES,
    EMAIL_RE,
    R,
    age_text,
    cached,
    chip,
    doh,
    fetch_chain,
    http_get,
    http_json,
    parse_dt,
    row,
)

def mod_dns(q):
    domain = q.lower().rstrip(".")
    res, errs, note = {}, 0, None
    with ThreadPoolExecutor(9) as ex:
        futs = {t: ex.submit(doh, domain, t) for t in DNS_TYPES}
        futs["DMARC"] = ex.submit(doh, "_dmarc." + domain, "TXT")
        for t, f in futs.items():
            try:
                res[t] = f.result(timeout=15)
            except Exception:
                res[t] = []
                errs += 1
    if errs == len(futs):
        try:
            infos = socket.getaddrinfo(domain, None)
            res["A"] = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
            res["AAAA"] = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
            note = "DNS-over-HTTPS was unreachable; showing A/AAAA from the system resolver only."
        except Exception as e:
            raise RuntimeError(f"Could not resolve {domain}: {e}")
    chips = []
    ips = res["A"] + res["AAAA"]
    has_mail = bool(res["MX"])
    spf = any(t.lower().startswith("v=spf1") for t in res["TXT"])
    dmarc = any(t.lower().startswith("v=dmarc1") for t in res["DMARC"])
    if not ips and not res["CNAME"] and not res["NS"] and not note:
        chips.append(chip("No DNS records", "NXDOMAIN or empty zone", "warn"))
    else:
        chips.append(chip("Addresses", str(len(ips)), "info"))
    if has_mail:
        chips.append(chip("Mail", f"{len(res['MX'])} MX", "info"))
        chips.append(chip("SPF", "present" if spf else "missing", "ok" if spf else "warn"))
        chips.append(chip("DMARC", "present" if dmarc else "missing", "ok" if dmarc else "warn"))
    elif not note:
        chips.append(chip("Mail", "no MX", "info"))
    if res["CAA"]:
        chips.append(chip("CAA", "restricts issuers", "ok"))
    sections = []
    for t in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"):
        if res[t]:
            sections.append({"title": t, "rows": [[t, v] for v in res[t]]})
    if res["DMARC"]:
        sections.append({"title": "DMARC", "rows": [["_dmarc", v] for v in res["DMARC"]]})
    pivots = [{"module": "ip", "q": ip, "label": f"A → {ip}", "auto": True} for ip in res["A"][:2]] + [{"module": "ip", "q": ip, "label": f"A → {ip}", "auto": False} for ip in res["A"][2:6]]
    if res["A"]:
        pivots.append({"module": "exposure", "q": res["A"][0], "label": f"Exposure of {res['A'][0]}", "auto": True})
    return R("DNS records", "⌘", highlights=chips, sections=sections, pivots=pivots, note=note)

def _vcard_fn(ent):
    try:
        for item in ent["vcardArray"][1]:
            if item[0] == "fn":
                return item[3]
    except Exception:
        pass
    return None

def mod_rdap(q):
    domain = q.lower().rstrip(".")
    try:
        d = http_json(f"https://rdap.org/domain/{quote(domain)}", timeout=12)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return R("Registration", "§", "warn", note="No RDAP record: the TLD may not publish RDAP, or the domain is unregistered.")
        raise
    ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    created, expires, changed = (parse_dt(ev.get("registration")), parse_dt(ev.get("expiration")), parse_dt(ev.get("last changed")))
    now = datetime.now(timezone.utc)
    chips, rows = [], []
    if created:
        age = (now - created).days
        tone = "bad" if age < 30 else "warn" if age < 90 else "ok"
        chips.append(chip("Age", age_text(age), tone))
        if age < 30:
            chips.append(chip("Newly registered", None, "bad"))
        rows.append(row("Registered", created.date().isoformat()))
    if expires:
        left = (expires - now).days
        chips.append(chip("Expires", f"in {left} days" if left >= 0 else "EXPIRED", "warn" if left < 30 else "info"))
        rows.append(row("Expires", expires.date().isoformat()))
    if changed:
        rows.append(row("Last changed", changed.date().isoformat()))
    registrar = None
    for ent in d.get("entities", []):
        if "registrar" in (ent.get("roles") or []):
            registrar = _vcard_fn(ent)
            break
    if registrar:
        rows.insert(0, row("Registrar", registrar))
    status = d.get("status") or []
    if status:
        bad = any(s.lower() in ("clienthold", "serverhold", "pendingdelete", "redemptionperiod") for s in status)
        rows.append(row("Status", ", ".join(status), "warn" if bad else None))
        if bad:
            chips.append(chip("Status", "hold / pending delete", "warn"))
    sd = (d.get("secureDNS") or {}).get("delegationSigned")
    if sd is not None:
        rows.append(row("DNSSEC", "signed" if sd else "unsigned"))
    ns = [n.get("ldhName", "").lower() for n in d.get("nameservers", []) if n.get("ldhName")]
    sections = [{"title": "Registration", "rows": rows}]
    if ns:
        sections.append({"title": "Name servers", "rows": [["NS", n] for n in ns]})
    return R("Registration", "§", highlights=chips, sections=sections, note="Registrant contact details are intentionally not shown.")

def mod_tls(q):
    host = q.lower().rstrip(".")
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                cert, ver, cipher = t.getpeercert(), t.version(), t.cipher()
    except ssl.SSLCertVerificationError as e:
        return R("TLS certificate", "🔒", "bad", highlights=[chip("Verification failed", e.verify_message, "bad")], sections=[{"title": "Error", "rows": [row("Reason", e.verify_message, "bad")]}])
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return R("TLS certificate", "🔒", "info", note=f"No TLS service reachable on {host}:443 ({e}).")
    def flat(name):
        return {k: v for rdn in name for (k, v) in rdn}
    subj, iss = flat(cert.get("subject", ())), flat(cert.get("issuer", ()))
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
    left = (not_after - datetime.now(timezone.utc)).days
    chips = [chip("Valid", f"{left} days left", "bad" if left < 7 else "warn" if left < 21 else "ok")]
    if ver in ("TLSv1", "TLSv1.1"):
        chips.append(chip("Protocol", ver, "bad"))
    else:
        chips.append(chip("Protocol", ver, "info"))
    sans = [v for (k, v) in cert.get("subjectAltName", ()) if k == "DNS"]
    rows = [row("Subject CN", subj.get("commonName", "")), row("Issuer", iss.get("organizationName") or iss.get("commonName", "")), row("Issuer CN", iss.get("commonName", "")), row("Not before", not_before.date().isoformat()), row("Not after", not_after.date().isoformat()), row("Cipher", cipher[0] if cipher else "")]
    sections = [{"title": "Certificate", "rows": rows}]
    if sans:
        sections.append({"title": f"Subject alt names ({len(sans)})", "rows": [["SAN", s] for s in sans[:25]]})
    return R("TLS certificate", "🔒", highlights=chips, sections=sections)

def mod_subs(q):
    domain = q.lower().rstrip(".")
    data = http_json(f"https://crt.sh/?q=%25.{quote(domain)}&output=json", timeout=25)
    names = set()
    for e in data:
        for n in str(e.get("name_value", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain):
                names.add(n)
    names = sorted(names)
    chips = [chip("Names in CT logs", str(len(names)), "info")]
    return R("Subdomains (CT logs)", "⛓", highlights=chips, list=names[:300], note=("Showing first 300." if len(names) > 300 else None))

HOSTING_WORDS = ("amazon", "aws", "google", "microsoft", "azure", "digitalocean", "ovh", "hetzner", "linode", "akamai", "vultr", "cloudflare", "oracle", "alibaba", "contabo", "scaleway")

def _rdns(ip):
    ex = ThreadPoolExecutor(1)
    f = ex.submit(lambda: socket.gethostbyaddr(ip)[0])
    try:
        return f.result(timeout=3)
    except Exception:
        return None
    finally:
        ex.shutdown(wait=False)

def _tor_exits():
    def load():
        _, _, b = http_get("https://check.torproject.org/torbulkexitlist", timeout=10)
        return set(b.decode("utf-8", "replace").split())
    return cached("tor-exits", 3600, load)

def mod_ip(q):
    ip = ipaddress.ip_address(q.strip())
    if not ip.is_global:
        kind = ("loopback" if ip.is_loopback else "private (RFC 1918 / ULA)" if ip.is_private else "link-local" if ip.is_link_local else "reserved / non-routable")
        return R("IP intelligence", "◎", highlights=[chip("Scope", kind, "info")], sections=[{"title": "Address", "rows": [row("IP", ip), row("Version", f"IPv{ip.version}")]}], note="Non-public address; no external lookup performed.")
    g = http_json(f"https://ipwho.is/{quote(str(ip))}", timeout=10)
    if not g.get("success", False):
        raise RuntimeError(g.get("message", "lookup failed"))
    conn = g.get("connection") or {}
    tz = g.get("timezone") or {}
    rdns = _rdns(str(ip))
    org = conn.get("org") or conn.get("isp") or ""
    chips = [chip("Country", f"{g.get('country', '?')} {(g.get('flag') or {}).get('emoji', '')}".strip(), "info"), chip("ASN", f"AS{conn.get('asn')}" if conn.get("asn") else "?", "info")]
    if org:
        chips.append(chip("Org", org, "info"))
    if any(w in f"{org} {conn.get('isp', '')} {rdns or ''}".lower() for w in HOSTING_WORDS):
        chips.append(chip("Type", "cloud / hosting provider", "warn"))
    try:
        if str(ip) in _tor_exits():
            chips.append(chip("Tor exit node", None, "bad"))
    except Exception:
        pass
    rows = [row("IP", ip), row("Version", f"IPv{ip.version}"), row("Reverse DNS", rdns or "(none)"), row("Continent", g.get("continent")), row("Country", g.get("country")), row("Region", g.get("region")), row("City", g.get("city")), row("Postal", g.get("postal")), row("Coordinates", f"{g.get('latitude')}, {g.get('longitude')}"), row("Timezone", f"{tz.get('id', '')} (UTC{tz.get('utc', '')})"), row("ASN", conn.get("asn")), row("Organisation", conn.get("org")), row("ISP", conn.get("isp")), row("Domain", conn.get("domain"))]
    out = R("IP intelligence", "◎", highlights=chips, sections=[{"title": "Details", "rows": rows}], note="IP geolocation is approximate (city / ISP level), not a street location.")
    lat, lon = g.get("latitude"), g.get("longitude")
    if lat is not None and lon is not None:
        out["map"] = {"lat": lat, "lon": lon, "bbox": [lon - 0.35, lat - 0.25, lon + 0.35, lat + 0.25], "label": "approximate IP location"}
    return out

def mod_rdap_ip(q):
    try:
        d = http_json(f"https://rdap.org/ip/{quote(q)}", timeout=12)
    except urllib.error.HTTPError as e:
        if e.code in (404, 400):
            return R("Network registration", "▦", "info", note="No RDAP record for this address.")
        raise
    cidrs = []
    for c in d.get("cidr0_cidrs", []) or []:
        p = c.get("v4prefix") or c.get("v6prefix")
        if p:
            cidrs.append(f"{p}/{c.get('length')}")
    ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    rows = [row("Name", d.get("name")), row("Handle", d.get("handle")), row("Type", d.get("type")), row("Country", d.get("country")), row("Range", f"{d.get('startAddress')} – {d.get('endAddress')}"), row("CIDR", ", ".join(cidrs)), row("Parent", d.get("parentHandle")), row("Registered", (ev.get("registration") or "")[:10]), row("Last changed", (ev.get("last changed") or "")[:10])]
    rows = [r for r in rows if r[1] not in ("", "None", " – ")]
    chips = [chip("Network", d.get("name") or "?", "info")]
    return R("Network registration", "▦", highlights=chips, sections=[{"title": "Allocation", "rows": rows}])

FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com", "me.com", "proton.me", "protonmail.com", "aol.com", "gmx.com", "zoho.com", "yandex.com"}

DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "dispostable.com", "throwawaymail.com", "maildrop.cc", "temp-mail.org", "fakeinbox.com"}

ROLE_ACCOUNTS = {"admin", "administrator", "info", "support", "sales", "contact", "noreply", "no-reply", "postmaster", "abuse", "webmaster", "hostmaster", "security", "billing", "help", "office"}

def mod_email(q, breaches=True):
    email = q.strip().lower()
    if not EMAIL_RE.match(email):
        raise ValueError("Not a valid email address")
    local, domain = email.rsplit("@", 1)
    with ThreadPoolExecutor(3) as ex:
        f_mx = ex.submit(doh, domain, "MX")
        f_txt = ex.submit(doh, domain, "TXT")
        f_dm = ex.submit(doh, "_dmarc." + domain, "TXT")
        mx, txt, dm = [], [], []
        try:
            mx = f_mx.result(timeout=15)
            txt = f_txt.result(timeout=15)
            dm = f_dm.result(timeout=15)
        except Exception as e:
            raise RuntimeError(f"DNS lookup failed: {e}")
    spf = any(t.lower().startswith("v=spf1") for t in txt)
    dmarc = any(t.lower().startswith("v=dmarc1") for t in dm)
    chips = [chip("Syntax", "valid", "ok"), chip("MX", f"{len(mx)} server(s)", "ok") if mx else chip("MX", "none - cannot receive mail", "bad"), chip("SPF", "present" if spf else "missing", "ok" if spf else "warn"), chip("DMARC", "present" if dmarc else "missing", "ok" if dmarc else "warn")]
    if domain in DISPOSABLE:
        chips.append(chip("Disposable provider", None, "bad"))
    if domain in FREE_MAIL:
        chips.append(chip("Free provider", domain, "info"))
    if local.split("+")[0] in ROLE_ACCOUNTS:
        chips.append(chip("Role account", local, "info"))
    sections = [{"title": "Address", "rows": [row("Local part", local), row("Domain", domain)]}]
    if mx:
        sections.append({"title": "Mail servers", "rows": [["MX", m] for m in mx]})
    note = None
    key = os.environ.get("HIBP_API_KEY") if breaches else None
    if key:
        try:
            data = http_json(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false", {"hibp-api-key": key}, timeout=10)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                data = []
            else:
                raise
        if data:
            chips.append(chip("Breaches", str(len(data)), "bad"))
            sections.append({"title": "Breach exposure", "rows": [[b.get("Name", "?"), f"{b.get('BreachDate', '')} · {', '.join((b.get('DataClasses') or [])[:5])}"] for b in data[:20]]})
        else:
            chips.append(chip("Breaches", "none found", "ok"))
    else:
        note = "Set the HIBP_API_KEY environment variable to add breach-exposure results." if breaches else None
    pivots = [{"module": "dns", "q": domain, "label": f"Domain → {domain}", "auto": True}, {"module": "rdap", "q": domain, "label": "Domain registration", "auto": True}]
    return R("Email analysis", "✉", highlights=chips, sections=sections, pivots=pivots, note=note)

SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]

def mod_url(q):
    chain, code, hdrs, _, final = fetch_chain(q)
    p0, pf = urlparse(q), urlparse(final)
    chips = []
    chips.append(chip("HTTPS", "yes", "ok") if pf.scheme == "https" else chip("HTTPS", "no - plaintext", "warn"))
    chips.append(chip("Status", str(code), "ok" if code < 400 else "warn"))
    hops = len(chain) - 1
    if hops:
        chips.append(chip("Redirects", str(hops), "warn" if hops > 3 else "info"))
    if (p0.hostname or "") != (pf.hostname or ""):
        chips.append(chip("Cross-host redirect", pf.hostname, "warn"))
    missing = [h for h in SEC_HEADERS if h.lower() not in {k.lower() for k in hdrs.keys()}]
    chips.append(chip("Security headers", f"{len(SEC_HEADERS) - len(missing)}/{len(SEC_HEADERS)}", "warn" if len(missing) >= 4 else "info"))
    rows = [row(f"Hop {i}", f"{c['status']}  {c['url']}") for i, c in enumerate(chain)]
    info_rows = [row("Final URL", final), row("Server", hdrs.get("Server")), row("Powered by", hdrs.get("X-Powered-By")), row("Content-Type", hdrs.get("Content-Type")), row("Content-Length", hdrs.get("Content-Length")), row("Last-Modified", hdrs.get("Last-Modified"))]
    info_rows = [r for r in info_rows if r[1] not in ("", "None")]
    sections = [{"title": "Redirect chain", "rows": rows}, {"title": "Response", "rows": info_rows}]
    if missing:
        sections.append({"title": "Missing security headers", "rows": [["missing", m] for m in missing]})
    host = pf.hostname or ""
    pivots = []
    try:
        ipaddress.ip_address(host)
        pivots.append({"module": "ip", "q": host, "label": f"Host → {host}", "auto": True})
    except ValueError:
        pivots += [{"module": "dns", "q": host, "label": f"Host → {host}", "auto": True}, {"module": "rdap", "q": host, "label": "Domain registration", "auto": True}, {"module": "tls", "q": host, "label": "TLS certificate", "auto": False}]
    return R("URL & headers", "🔗", highlights=chips, sections=sections, pivots=pivots)
