"""Email-header analysis (hops, SPF/DKIM/DMARC alignment) and the /api/headers endpoint."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from email.parser import Parser as _EmailParser
from email import policy as _email_policy
from flask import jsonify, request
from email.utils import parseaddr, parsedate_to_datetime
from datetime import timezone

from .core import R, TONE_RANK, app, chip, row

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

_IPV6 = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]{3,45})\]")

_AUTH = {k: re.compile(rf"\b{k}=(pass|fail|softfail|hardfail|neutral|none|temperror|permerror|policy)\b", re.I) for k in ("spf", "dkim", "dmarc", "arc")}

def _addr_domain(addr):
    return addr.rsplit("@", 1)[1].strip(" <>").lower() if "@" in addr else ""

def _aligned(a, b):
    return bool(a and b and (a == b or a.endswith("." + b) or b.endswith("." + a)))

def _parse_received(raw):
    raw = " ".join(str(raw).split())
    ts, body = None, raw
    if ";" in raw:
        body, _, dt = raw.rpartition(";")
        try:
            ts = parsedate_to_datetime(dt.strip())
            ts = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        except Exception:
            ts = None
    mf, mb, mw = (re.search(p, body, re.I) for p in (r"\bfrom\s+(\S+)", r"\bby\s+(\S+)", r"\bwith\s+(\S+)"))
    ips = []
    for ip in _IPV4.findall(body) + _IPV6.findall(body):
        try:
            ipaddress.ip_address(ip)
            if ip not in ips:
                ips.append(ip)
        except ValueError:
            pass
    return {"from": mf.group(1) if mf else "", "by": mb.group(1) if mb else "", "with": mw.group(1) if mw else "",
            "ips": ips, "ts": ts}

def analyze_headers(text):
    text = (text or "").replace("\r\n", "\n").strip()
    if len(text) > 200_000:
        raise ValueError("Too long: paste only the header block")
    head = text.split("\n\n", 1)[0]
    msg = _EmailParser(policy=_email_policy.default).parsestr(head, headersonly=True)
    names = {n.lower() for n in msg.keys()}
    if not names & {"received", "from", "subject", "message-id", "return-path", "authentication-results", "date"}:
        raise ValueError("No email headers found. Paste the full raw headers (they start with lines like Received:, Return-Path: or From:).")
    def get(n):
        try:
            v = msg.get(n)
            return str(v).strip() if v is not None else ""
        except Exception:
            return ""
    def get_all(n):
        try:
            return [str(v).strip() for v in (msg.get_all(n) or [])]
        except Exception:
            return []
    flags, chips = [], []
    from_name, from_addr = parseaddr(get("from"))
    from_dom = _addr_domain(from_addr)
    rp = parseaddr(get("return-path"))[1] or get("return-path").strip("<> ")
    rp_dom = _addr_domain(rp)
    rt = parseaddr(get("reply-to"))[1]
    rt_dom = _addr_domain(rt)
    mid_dom = _addr_domain(get("message-id").strip("<> "))
    if from_name and "@" in from_name:
        nd = _addr_domain(re.sub(r".*?([\w.+-]+@[\w.-]+).*", r"\1", from_name))
        if nd and nd != from_dom:
            flags.append(("bad", f"Display name contains another address ({nd}) than the real sender ({from_dom})"))
    if from_dom.startswith("xn--") or any(ord(c) > 127 for c in from_dom):
        flags.append(("warn", "Sender domain is internationalised (possible look-alike characters)"))
    if rt_dom and not _aligned(rt_dom, from_dom):
        flags.append(("warn", f"Reply-To goes to a different domain ({rt_dom}) than From ({from_dom})"))
    ar = " ".join(get_all("authentication-results"))
    res = {}
    for k, rx in _AUTH.items():
        m = rx.search(ar)
        if m:
            res[k] = m.group(1).lower()
    rs = get("received-spf")
    if "spf" not in res and rs:
        m = re.match(r"\s*(pass|fail|softfail|neutral|none|temperror|permerror)", rs, re.I)
        if m:
            res["spf"] = m.group(1).lower()
    dkim_sigs = []
    for s in get_all("dkim-signature"):
        d = re.search(r"\bd=([^;\s]+)", s)
        sel = re.search(r"\bs=([^;\s]+)", s)
        if d:
            dkim_sigs.append((d.group(1).lower(), sel.group(1) if sel else ""))
    def auth_chip(name, val):
        if val is None:
            chips.append(chip(name, "not reported", "warn"))
        elif val == "pass":
            chips.append(chip(name, "pass", "ok"))
        elif val in ("fail", "hardfail", "permerror"):
            chips.append(chip(name, val, "bad"))
            flags.append(("bad", f"{name} {val}"))
        else:
            chips.append(chip(name, val, "warn"))
            flags.append(("warn", f"{name} {val}"))
    for k in ("spf", "dkim", "dmarc"):
        auth_chip(k.upper(), res.get(k))
    if not res:
        flags.append(("warn", "No authentication results in the headers (they may have been removed, or this is a copy from the sender's side)"))
    if dkim_sigs and not any(_aligned(d, from_dom) for d, _ in dkim_sigs):
        flags.append(("warn", f"DKIM is signed by {', '.join(sorted({d for d, _ in dkim_sigs}))}, not by the From domain"))
    if not dkim_sigs and res.get("dkim") is None:
        flags.append(("warn", "No DKIM signature present"))
    if from_dom and rp_dom and not _aligned(rp_dom, from_dom) and not any(_aligned(d, from_dom) for d, _ in dkim_sigs) and not _aligned(mid_dom, from_dom):
        flags.append(("bad", "The From domain matches none of Return-Path, DKIM or Message-ID: identity not backed by any technical sender"))
    hops = [_parse_received(r) for r in reversed(get_all("received"))]
    path_rows, prev, origin = [], None, None
    for i, h in enumerate(hops, 1):
        delay = ""
        if prev and h["ts"] and prev["ts"]:
            secs = int((h["ts"] - prev["ts"]).total_seconds())
            delay = f" · +{secs}s" if abs(secs) < 3600 else f" · +{secs // 3600}h{abs(secs) % 3600 // 60:02d}m"
            if secs > 3600:
                flags.append(("warn", f"{secs // 3600} hour delay between hop {i - 1} and hop {i}"))
        for ip in h["ips"]:
            try:
                if ipaddress.ip_address(ip).is_global and origin is None:
                    origin = ip
            except ValueError:
                pass
        stamp = h["ts"].strftime("%Y-%m-%d %H:%M:%S %Z") if h["ts"] else "no timestamp"
        path_rows.append([f"hop {i}", f"{h['from'] or '?'} → {h['by'] or '?'}  [{', '.join(h['ips']) or 'no IP'}]  {stamp}{delay}" + (f"  via {h['with']}" if h["with"] else "")])
        prev = h if h["ts"] else prev
    dt_hdr = None
    try:
        dt_hdr = parsedate_to_datetime(get("date"))
        dt_hdr = dt_hdr if dt_hdr.tzinfo else dt_hdr.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    first_ts = next((h["ts"] for h in hops if h["ts"]), None)
    if dt_hdr and first_ts and abs((first_ts - dt_hdr).total_seconds()) > 86400:
        flags.append(("warn", "The Date header differs from the first server timestamp by more than a day"))
    n_bad = sum(1 for t, _ in flags if t == "bad")
    n_warn = sum(1 for t, _ in flags if t == "warn")
    verdict = ("Likely spoofed or malicious" if n_bad else "Suspicious signs" if n_warn else "No red flags in the headers")
    chips.insert(0, chip("Verdict", verdict, "bad" if n_bad else "warn" if n_warn else "ok"))
    if origin:
        chips.append(chip("First public IP", origin, "info"))
    chips.append(chip("Hops", str(len(hops)), "info"))
    sections = []
    if flags:
        flags.sort(key=lambda f: -TONE_RANK[f[0]])
        sections.append({"title": "Findings", "rows": [[("red flag" if t == "bad" else "warning"), {"text": s, "tone": t}] for t, s in flags]})
    auth_rows = [row(k.upper(), res.get(k, "not reported"), {"pass": "ok", "fail": "bad", "hardfail": "bad", "permerror": "bad"}.get(res.get(k), "warn" if k not in res else None)) for k in ("spf", "dkim", "dmarc")]
    auth_rows += [row("DKIM signer", f"d={d} s={s}") for d, s in dkim_sigs[:4]]
    sections.append({"title": "Authentication", "rows": auth_rows})
    sections.append({"title": "Identity", "rows": [r for r in (row("From", f"{from_name} <{from_addr}>" if from_name else from_addr), row("Return-Path", rp), row("Reply-To", rt), row("Sender", get("sender")), row("Message-ID", get("message-id"))) if r[1] not in ("", "<>")]})
    sections.append({"title": "Message", "rows": [r for r in (row("Subject", get("subject")[:200]), row("Date", get("date")), row("Mailer", get("x-mailer") or get("user-agent")), row("X-Originating-IP", get("x-originating-ip")), row("Spam status", get("x-spam-status")[:160] or get("x-spam-score"))) if r[1]]})
    if path_rows:
        sections.append({"title": "Delivery path (oldest first)", "rows": path_rows})
    pivots, seen = [], set()
    def piv(module, q, label, auto):
        if q and (module, q) not in seen:
            seen.add((module, q))
            pivots.append({"module": module, "q": q, "label": label, "auto": auto})
    if origin:
        piv("ip", origin, f"Origin {origin}", True)
    piv("dns", from_dom, f"From domain {from_dom}", True)
    piv("rdap", from_dom, "From domain age", True)
    piv("rdap", rp_dom, f"Return-Path {rp_dom}", False)
    piv("rdap", rt_dom, f"Reply-To {rt_dom}", False)
    for d, _ in dkim_sigs[:2]:
        piv("dns", d, f"DKIM {d}", False)
    sev = "bad" if n_bad else "warn" if n_warn else "ok"
    return R("Email headers", "✉", sev, highlights=chips, sections=sections, pivots=pivots,
             note="Headers can be forged, so a clean result is not proof of authenticity; a failed check or mismatch is a strong signal.",
             key=hashlib.sha1(head.encode("utf-8", "replace")).hexdigest()[:10])

@app.post("/api/headers")
def api_headers():
    j = request.get_json(silent=True) or {}
    try:
        res = analyze_headers(str(j.get("text", "")))
    except ValueError as e:
        res = {"error": str(e)}
    except Exception as e:
        res = {"error": f"Could not parse the headers: {type(e).__name__}"}
    return jsonify(res)
