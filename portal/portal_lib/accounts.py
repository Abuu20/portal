"""Username (Sherlock/Maigret) and phone-number modules, plus the out-of-scope notice."""
from __future__ import annotations

import os
import re
import shutil
import subprocess

from .core import DATA_DIR, R, chip, http_json, row

def mod_scope(q):
    return R("Out of scope", "⛔", "info", note="Phone numbers usually belong to private individuals, and this portal does not look them up. For a business, check its website or official registry.")

def _username_valid(u):
    return bool(re.match(r"^[A-Za-z0-9_.-]{2,30}$", u))

# --------------------------------------------------------------------------
# Username OSINT: Sherlock + Maigret
# --------------------------------------------------------------------------
_USERNAME_RE = re.compile(r"\[\+\]\s*([^:–\-]+?)\s*[:–\-]\s*(https?://\S+)", re.UNICODE)

def _parse_sherlock_out(out):
    results = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("[+]"):
            continue
        m = _USERNAME_RE.match(line)
        if m:
            site = m.group(1).strip()
            url = m.group(2).rstrip(".,;").strip()
            if site and url:
                results.append({"site": site, "url": url, "fullname": None, "bio": None, "image": None, "meta": {}, "tags": []})
    return results

def _parse_maigret_text(out):
    """Parse Maigret's standard text output to extract rich data (fullname, bio, image)."""
    results = []
    current = None
    for line in out.splitlines():
        line = line.rstrip()
        if line.startswith("[+] "):
            m = re.match(r"\[\+\]\s*([^:]+):\s*(https?://\S+)", line)
            if m:
                if current:
                    results.append(current)
                current = {"site": m.group(1).strip(), "url": m.group(2).strip(), "fullname": None, "bio": None, "image": None, "meta": {}, "tags": []}
        elif current and (line.startswith(" ├─") or line.startswith(" └─")):
            m = re.match(r"\s*[├└]─\s*([a-zA-Z0-9_]+):\s*(.*)", line)
            if m:
                k, v = m.group(1).lower(), m.group(2).strip()
                if k == "fullname": current["fullname"] = v
                elif k in ("description", "bio", "about", "summary"): current["bio"] = v
                elif k == "image": current["image"] = v
                elif k == "tags": 
                    if isinstance(v, str): current["tags"] = [x.strip() for x in v.split(",")]
                else: current["meta"][k] = v
    if current:
        results.append(current)
    return results

def _run_username_tool(exe, username, kind, timeout=300):
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    tool_home = os.path.join(DATA_DIR, f"{kind}_home")
    os.makedirs(tool_home, mode=0o700, exist_ok=True)
    
    env = {
        **os.environ,
        "HOME": tool_home,
        "XDG_CACHE_HOME": os.path.join(tool_home, ".cache"),
        "TMPDIR": tool_home,
        "PYTHONUNBUFFERED": "1",
    }
    
    if kind == "sherlock":
        cmd = [exe, username, "--print-found", "--no-color", "--timeout", "8"]
    else:
        # Use standard text output, which is much more reliable for extracting rich data
        cmd = [exe, username, "--timeout", "8", "--no-progressbar", "--no-color"]
        
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=tool_home, env=env)
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired as e:
        out = ""
        for s in (e.stdout, e.stderr):
            if s:
                out += (s.decode("utf-8", "replace") if isinstance(s, bytes) else s) + "\n"
        return [], f"timed out after {timeout}s"
        
    results = []
    if kind == "maigret":
        results = _parse_maigret_text(out)
    else:
        results = _parse_sherlock_out(out)
    return results, None

def mod_sherlock(q):
    username = q.lstrip("@").strip()
    if not _username_valid(username):
        raise ValueError(f"'{q}' is not a valid username (2–30 chars, letters/digits/underscore/hyphen/dot)")
    sherlock = shutil.which("sherlock") or shutil.which("sherlock-project")
    if not sherlock:
        return R("Sherlock OSINT", "🔍", "warn",
                 highlights=[chip("Not installed", None, "warn")],
                 sections=[{"title": "Install", "rows": [["pipx install sherlock-project", ""]]}])
    
    chips = [chip("Username", "@" + username, "info")]
    sections, errors = [], []
    
    try:
        results, err = _run_username_tool(sherlock, username, "sherlock", timeout=120)
        if err:
            errors.append(f"Sherlock: {err}")
        elif results:
            chips.append(chip("Accounts found", str(len(results)), "warn" if len(results) > 10 else "info"))
    except Exception as e:
        errors.append(f"Sherlock: {type(e).__name__}: {e}")
        results = []

    if errors:
        sections.append({"title": "Warnings", "rows": [["warning", e] for e in errors]})

    note = "Fast scan (~400 sites). Use the Maigret window for deeper coverage and bios."
    if not results and not errors:
        note = "No public accounts found with this exact handle in Sherlock's sites."

    return R("Sherlock OSINT", "🔍", "info", highlights=chips, sections=sections, 
             accounts=results, note=note)

def mod_maigret(q):
    username = q.lstrip("@").strip()
    if not _username_valid(username):
        raise ValueError(f"'{q}' is not a valid username (2–30 chars, letters/digits/underscore/hyphen/dot)")
    maigret = shutil.which("maigret")
    if not maigret:
        return R("Maigret OSINT", "🔍", "warn",
                 highlights=[chip("Not installed", None, "warn")],
                 sections=[{"title": "Install", "rows": [["pipx install maigret", ""]]}])
    
    chips = [chip("Username", "@" + username, "info")]
    sections, errors = [], []
    
    try:
        results, err = _run_username_tool(maigret, username, "maigret", timeout=300)
        if err:
            errors.append(f"Maigret: {err}")
        elif results:
            chips.append(chip("Accounts found", str(len(results)), "warn" if len(results) > 10 else "info"))
    except Exception as e:
        errors.append(f"Maigret: {type(e).__name__}: {e}")
        results = []

    if errors:
        sections.append({"title": "Warnings", "rows": [["warning", e] for e in errors]})

    note = "Deep scan (3000+ sites). Slower, but extracts public names and bios where available."
    if not results and not errors:
        note = "No public accounts found with this exact handle in Maigret's sites."

    return R("Maigret OSINT", "🔍", "info", highlights=chips, sections=sections, 
             accounts=results, note=note)

def mod_phone(q):
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone as pn_tz
    except ImportError:
        return R("Phone intelligence", "📱", "info",
                 highlights=[chip("Library missing", "phonenumbers not installed", "warn")],
                 sections=[{"title": "Install", "rows": [["pip install phonenumbers", "or: sudo apt install python3-phonenumbers"]]}],
                 note="After installing, re-run this lookup.")
    raw = q.strip()
    try:
        pn = phonenumbers.parse(raw, None)
    except phonenumbers.NumberParseException as e:
        return R("Phone intelligence", "📱", "warn",
                 highlights=[chip("Parse error", str(e), "warn")],
                 sections=[{"title": "Input", "rows": [["Number", raw]]}],
                 note="Include the country code, e.g. +1 202 555 0143 or +254 700 000 000.")
    if not phonenumbers.is_possible_number(pn):
        return R("Phone intelligence", "📱", "warn",
                 highlights=[chip("Invalid", "not a possible number", "warn")],
                 sections=[{"title": "Input", "rows": [["Number", raw]]}])
    valid = phonenumbers.is_valid_number(pn)
    intl = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    e164 = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
    natl = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL)
    c = carrier.name_for_number(pn, "en") or ""
    loc = geocoder.description_for_number(pn, "en") or ""
    tzs = list(pn_tz.time_zones_for_number(pn))
    region = phonenumbers.region_code_for_number(pn)
    type_map = {
        phonenumbers.PhoneNumberType.MOBILE: "Mobile", phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed line",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed or mobile", phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium rate", phonenumbers.PhoneNumberType.SHARED_COST: "Shared cost",
        phonenumbers.PhoneNumberType.VOIP: "VoIP", phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal number",
        phonenumbers.PhoneNumberType.PAGER: "Pager", phonenumbers.PhoneNumberType.UAN: "UAN",
        phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail", phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
    }
    tname = type_map.get(phonenumbers.number_type(pn), "?")
    chips = [chip("Valid", "yes" if valid else "no", "ok" if valid else "warn")]
    if region:
        chips.append(chip("Region", region, "info"))
    if loc:
        chips.append(chip("Location", loc, "info"))
    if c:
        chips.append(chip("Carrier", c, "info"))
    chips.append(chip("Type", tname, "info"))
    sections = [
        {"title": "Format", "rows": [row("International", intl), row("E.164", e164), row("National", natl), row("Country code", f"+{pn.country_code}")]},
        {"title": "Allocation", "rows": [r for r in (row("Line type", tname), row("Carrier (original)", c), row("Location (original)", loc),
                                                       row("Timezone", ", ".join(tzs) if tzs else None)) if r[1] not in ("", "None")]},
    ]
    digits = re.sub(r"\D", "", e164)
    api_key = os.environ.get("NUMVERIFY_API_KEY")
    if api_key:
        try:
            api_res = http_json(f"http://apilayer.net/api/validate?access_key={api_key}&number={digits}")
            if api_res.get("valid"):
                live_rows = [row("Live Carrier", api_res.get("carrier")), row("Live Line type", api_res.get("line_type")),
                             row("Live Location", api_res.get("location"))]
                sections.append({"title": "Live Lookup (numverify)", "rows": [r for r in live_rows if r[1]]})
        except Exception:
            pass
    links = [
        {"label": "WhatsApp", "url": f"https://wa.me/{digits}"},
        {"label": "Telegram", "url": f"https://t.me/{digits}"},
        {"label": "Truecaller", "url": f"https://www.truecaller.com/search/{digits}"},
        {"label": "Sync.me", "url": f"https://sync.me/search/?number={digits}"},
        {"label": "SpyDialer", "url": f"https://www.spydialer.com/default.aspx?phone={digits}"},
        {"label": "NumLookup", "url": f"https://www.numlookup.com/?number={digits}"},
    ]
    return R("Phone intelligence", "📱", highlights=chips, sections=sections, links=links,
             note="Carrier and location reflect the number's original allocation (like a phone-book prefix), not the current owner. "
                  "WhatsApp/Telegram links open the app if installed.")
