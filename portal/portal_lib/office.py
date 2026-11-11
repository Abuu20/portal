"""Static analysis of Office documents (docx/xlsx/pptx and their macro variants, legacy .doc/.xls, RTF).

Nothing is ever opened, executed or rendered: the file is read as bytes / a zip and examined for the things that
make a document dangerous (macros, remote templates, DDE fields, embedded objects, Equation Editor, XLM sheets).
If the optional `olevba` command (oletools) is installed it is run on a temp copy for a deeper macro report.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from urllib.parse import urlparse

from .core import R, chip, row

MAX_ENTRY = 5 * 1024 * 1024        # never inflate more than this from one zip entry
MAX_TOTAL = 24 * 1024 * 1024
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
URL_RE = re.compile(r"""(?:https?|ftp|file)://[^\s"'<>\\)]+|\\\\[\w.$-]+\\[^\s"'<>]+""", re.I)
DDE_RE = re.compile(r"\b(DDEAUTO|DDE)\b[^<]{0,200}", re.I)
FIELD_URL_RE = re.compile(r"\b(INCLUDETEXT|INCLUDEPICTURE|LINK|IMPORT)\b[^<]{0,200}", re.I)
SUSPICIOUS_WORDS = [  # looked for in legacy OLE bytes (ASCII and UTF-16); VBA source itself is compressed there
    "AutoOpen", "Auto_Open", "Document_Open", "Workbook_Open", "AutoExec", "Shell", "WScript.Shell", "CreateObject",
    "powershell", "cmd.exe", "URLDownloadToFile", "XMLHTTP", "Environ", "MSXML2", "ADODB.Stream"]
EQUATION_CLSID = b"\x02\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"   # Equation Editor 3.0 (CVE-2017-11882 family)


def kind_of(head, names=None):
    if names is not None:
        if "[Content_Types].xml" not in names:
            return None
        if any(n.startswith("word/") for n in names): return "Word document (OOXML)"
        if any(n.startswith("xl/") for n in names): return "Excel workbook (OOXML)"
        if any(n.startswith("ppt/") for n in names): return "PowerPoint presentation (OOXML)"
        return None
    if head.startswith(OLE_MAGIC): return "Legacy Office / OLE2 file (doc, xls, ppt, msi...)"
    if head.lstrip().startswith(b"{\\rtf"): return "RTF document"
    return None


def _zip_read(z, name):
    try:
        info = z.getinfo(name)
        if info.file_size > MAX_ENTRY:
            return b""
        return z.read(name)
    except Exception:
        return b""


def _ooxml(path, f):
    """f: findings list of (tone, title, detail). Returns (rows, urls, meta)."""
    urls, meta, rows = [], [], []
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        names = [i.filename for i in infos]
        if sum(i.file_size for i in infos) > MAX_TOTAL * 10:
            f.append(("warn", "Unusually large when unpacked", "possible zip bomb; the content was not unpacked"))
            return rows, urls, meta, names
        for n in names:
            if n.startswith("/") or ".." in n.split("/"):
                f.append(("bad", "Unsafe path inside the zip", n))
        if "word/vbaProject.bin" in names or "xl/vbaProject.bin" in names or "ppt/vbaProject.bin" in names:
            f.append(("warn", "Contains VBA macros", "vbaProject.bin is present. Macros are the most common way Office files deliver malware."))
        if any(n.startswith("xl/macrosheets/") for n in names):
            f.append(("bad", "Contains Excel 4.0 (XLM) macro sheets", "an older macro format that many scanners miss"))
        for n in names:
            if n.startswith(("word/embeddings/", "xl/embeddings/", "ppt/embeddings/")):
                f.append(("warn", "Embedded object", n))
            elif "/activeX/" in n and n.endswith(".bin"):
                f.append(("warn", "ActiveX control", n))
        ct = _zip_read(z, "[Content_Types].xml").decode("utf-8", "replace")
        if "macroEnabled" in ct:
            f.append(("info", "Macro-enabled file type", "the content type allows macros (docm / xlsm / pptm)"))
        total = 0
        for n in names:                       # relationships: where the document reaches out to
            if not n.endswith(".rels"):
                continue
            x = _zip_read(z, n).decode("utf-8", "replace")
            total += len(x)
            if total > MAX_TOTAL:
                break
            for m in re.finditer(r"<Relationship\b([^>]*)>", x):
                a = m.group(1)
                if 'TargetMode="External"' not in a:
                    continue
                tgt = (re.search(r'Target="([^"]*)"', a) or [None, ""])[1]
                typ = (re.search(r'Type="([^"]*)"', a) or [None, ""])[1].rsplit("/", 1)[-1]
                urls.append(tgt)
                if typ == "attachedTemplate" and re.match(r"(?i)(https?|ftp|\\\\)", tgt):
                    f.append(("bad", "Remote template", f"the document loads a template from {tgt[:120]} when opened (template injection)"))
                elif typ in ("oleObject", "frame", "externalLink", "externalLinkPath"):
                    f.append(("warn", f"External {typ}", tgt[:140]))
                elif typ != "hyperlink":
                    f.append(("info", f"External {typ or 'reference'}", tgt[:140]))
        for part in ("word/document.xml", "word/footnotes.xml", "word/header1.xml"):
            if part in names:
                x = _zip_read(z, part).decode("utf-8", "replace")
                for m in DDE_RE.finditer(x):
                    f.append(("bad", "DDE field", re.sub(r"<[^>]+>", " ", m.group(0)).strip()[:160]))
                    break
                for m in FIELD_URL_RE.finditer(x):
                    txt = re.sub(r"<[^>]+>", " ", m.group(0)).strip()
                    if URL_RE.search(txt):
                        f.append(("warn", "Field that fetches content", txt[:160]))
                        break
        core = _zip_read(z, "docProps/core.xml").decode("utf-8", "replace")
        app = _zip_read(z, "docProps/app.xml").decode("utf-8", "replace")
        for label, src, tag in (("Created", core, "dcterms:created"), ("Modified", core, "dcterms:modified"),
                                ("Application", app, "Application"), ("App version", app, "AppVersion"),
                                ("Creator field", core, "dc:creator"), ("Last modified by", core, "cp:lastModifiedBy")):
            m = re.search(rf"<{tag}[^>]*>([^<]*)</{tag}>", src)
            if m and m.group(1).strip():
                meta.append(row(label, m.group(1).strip()[:100]))
    return rows, urls, meta, names


def _ole(data, f):
    low = data
    u16 = lambda s: s.encode("utf-16-le")
    if u16("_VBA_PROJECT") in low or u16("VBA") in low and u16("dir") in low:
        f.append(("warn", "Contains VBA macros", "VBA storage found. Source is compressed in legacy files; use olevba to read it."))
    if u16("Macros") in low and u16("ThisDocument") in low:
        f.append(("info", "Word macro project", "ThisDocument module present"))
    if u16("_VBA_PROJECT_CUR") in low and u16("Workbook") in low:
        f.append(("info", "Excel macro project", "Workbook module present"))
    hits = sorted({w for w in SUSPICIOUS_WORDS if w.encode() in low or u16(w) in low})
    if hits:
        f.append(("warn", "Suspicious keywords in the file", ", ".join(hits[:10])))
    if EQUATION_CLSID in low or b"Equation.3" in low or u16("Equation Native") in low:
        f.append(("bad", "Equation Editor object", "legacy Equation Editor is behind CVE-2017-11882 and related exploits"))
    if u16("Ole10Native") in low:
        f.append(("warn", "Packaged file inside the document", "Ole10Native stream: a file is embedded and may run on click"))
    return []


def _rtf(data, f):
    low = data.lower()
    if b"\\objdata" in low or b"\\objemb" in low:
        f.append(("warn", "Embedded object", "RTF object data (\\objdata)"))
    if b"\\objautlink" in low or b"\\objupdate" in low:
        f.append(("bad", "Auto-updating linked object", "\\objautlink / \\objupdate fetch content when opened"))
    m = re.search(rb"\\\*\\template\s+([^}]+)", data, re.I)
    if m and re.match(rb"(?i)\s*(https?|\\\\)", m.group(1)):
        f.append(("bad", "Remote template", m.group(1).decode("latin-1")[:120]))
    if b"equation.3" in low or b"0200000002000000" in low:
        f.append(("bad", "Equation Editor object", "associated with CVE-2017-11882 and similar exploits"))
    for u in URL_RE.findall(data.decode("latin-1")[:2_000_000])[:5]:
        f.append(("info", "URL in document", u[:140]))


def _olevba(path):
    """Optional deeper macro report from oletools. Returns lines (possibly empty); never raises."""
    exe = shutil.which("olevba")
    if not exe:
        return None
    try:
        p = subprocess.run([exe, path], capture_output=True, text=True, timeout=40)
    except Exception:
        return []
    out = []
    for ln in p.stdout.splitlines():
        parts = [x.strip() for x in ln.strip("|").split("|")]
        if ln.startswith("|") and len(parts) >= 3 and parts[0] in ("AutoExec", "Suspicious", "IOC", "Hex String", "Base64 String"):
            out.append((parts[0], parts[1][:60], parts[2][:120]))
    return out[:40]


def analyze_office(path, name, size, hashes, head):
    """Return a result dict for Office-type files, or None when the file is not one."""
    f, urls, meta, names, kind = [], [], [], None, None
    data = None
    if head.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(path) as z:
                kind = kind_of(head, z.namelist())
        except Exception:
            return None
        if not kind:
            return None
        _, urls, meta, names = _ooxml(path, f)
    else:
        kind = kind_of(head)
        if not kind:
            return None
        with open(path, "rb") as fh:
            data = fh.read(MAX_TOTAL)
        _rtf(data, f) if kind.startswith("RTF") else _ole(data, f)
    ov = _olevba(path) if any(t[1] == "Contains VBA macros" for t in f) else None
    if ov:
        for cat, what, why in ov:
            f.append(("warn" if cat != "IOC" else "info", f"olevba {cat}: {what}", why))
    bad = sum(1 for t in f if t[0] == "bad"); warn = sum(1 for t in f if t[0] == "warn")
    sev = "bad" if bad else "warn" if warn else "ok"
    verdict = "dangerous features found" if bad else "needs a look" if warn else "no active content found"
    rows = [row("Name", name), row("Size", f"{size:,} bytes"), row("Type", kind), row("MD5", hashes["md5"]),
            row("SHA-1", hashes["sha1"]), row("SHA-256", hashes["sha256"])]
    sections = [{"title": "File", "rows": rows}]
    if f:
        sections.insert(0, {"title": "Findings", "rows": [row(t, d, tone if tone != "info" else None) for tone, t, d in f]})
    if meta:
        sections.append({"title": "Document properties (as stored in the file)", "rows": meta})
    hosts = []
    for u in urls:
        h = urlparse(u).hostname
        if h and h not in hosts and "." in h:
            hosts.append(h)
    res = R("Office document", "▤", sev, highlights=[chip("Verdict", verdict, sev if sev != "ok" else "ok"),
            chip("Macros", "yes" if any(t[1] == "Contains VBA macros" for t in f) else "no", "warn" if any(t[1] == "Contains VBA macros" for t in f) else "ok"),
            chip("Findings", str(len(f)), "bad" if bad else "warn" if warn else "info")],
            sections=sections, pivots=[{"module": "dns", "q": h, "label": h, "auto": False} for h in hosts[:6]],
            links=[{"label": "VirusTotal (by hash)", "url": f"https://www.virustotal.com/gui/file/{hashes['sha256']}"}],
            note="Static analysis only: the file was never opened or run. " +
                 ("Macro report from olevba included. " if ov else "For macro source code install oletools (pip install oletools) and PORTAL will include the olevba report. ") +
                 "Treat anything marked red as hostile until proven otherwise.")
    return res
