"""Local toolbox: the tool catalogue, availability check, output parsers and the /api/tool endpoint.

Two kinds of target:
  * host / url — the usual PT/OSINT tools (nmap, whatweb, traceroute, katana, ...).
  * file        — file-based CTF tools (binwalk, exiftool, zsteg, upx, r2, ...). The target
                  must be the ``stored_path`` returned by POST /api/file; anything outside
                  PORTAL's own uploads folder is refused.
  * hash        — hashcat / john take the hash directly (john needs a temp file for it).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
from flask import jsonify, request
from urllib.parse import parse_qsl, urlparse

from .core import R, app, chip, norm_url, valid_target
from .scope import scope_error


# Tool catalog. Fields:
#   bin              executable
#   args             argument list; placeholders: {t}=target, {u}=url, {f}=file path,
#                    {w}=wordlist, {m}=hashcat mode, {j}=john format. Never through a shell.
#   kind             "host" (default) / "url" / "file" / "hash"
#   active           sends traffic to the target -> needs the authorisation tick-box
#   level            "intrusive" = attack-style payloads -> also type the target host to confirm
#   needs_wordlist   requires a wordlist ({w}); falls back to PORTAL's wordlist search
#   then             optional second command that filters the first one's output (e.g. katana | uro)
#   install          the exact command shown when the tool is missing
TOOLS = {
    "whois": {"label": "whois", "bin": "whois", "args": ["{t}"], "active": False, "timeout": 40,
              "install": "sudo apt install whois", "cat": "recon"},
    "dig": {"label": "dig records", "bin": "dig", "active": False, "timeout": 30,
            "install": "sudo apt install dnsutils", "cat": "recon",
            "args": ["+noall", "+answer", "{t}", "A", "{t}", "AAAA", "{t}", "MX", "{t}", "NS", "{t}", "TXT"]},
    "nmap_quick": {"label": "nmap top-100 ports", "bin": "nmap", "active": True, "timeout": 240,
                   "install": "sudo apt install nmap", "cat": "network",
                   "args": ["-Pn", "-T3", "-F", "--open", "{t}"]},
    "nmap_services": {"label": "nmap service versions", "bin": "nmap", "active": True, "timeout": 300,
                      "install": "sudo apt install nmap", "cat": "network",
                      "args": ["-Pn", "-T3", "-sV", "--version-light", "-F", "--open", "{t}"]},
    "whatweb": {"label": "whatweb", "bin": "whatweb", "active": True, "timeout": 90,
                "install": "sudo apt install whatweb", "cat": "web",
                "args": ["-a", "1", "--no-errors", "{t}"]},
    "traceroute": {"label": "traceroute", "bin": "traceroute", "active": True, "timeout": 90,
                   "install": "sudo apt install traceroute", "cat": "network",
                   "args": ["-m", "20", "-w", "2", "{t}"]},
    "rustscan_ports": {"label": "rustscan fast port sweep", "bin": "rustscan", "active": True, "timeout": 180,
                       "install": "sudo apt install rustscan", "cat": "network",
                       "args": ["-a", "{t}", "--ulimit", "5000", "-g"]},
    "rustscan_nmap": {"label": "rustscan → nmap versions", "bin": "rustscan", "active": True, "timeout": 420,
                      "install": "sudo apt install rustscan nmap", "cat": "network",
                      "args": ["-a", "{t}", "--ulimit", "5000", "--", "-sV", "--version-light", "-Pn"]},
    "katana_crawl": {"label": "katana crawl + uro dedupe", "bin": "katana", "kind": "url",
                     "active": True, "timeout": 180,
                     "args": ["-u", "{u}", "-d", "2", "-silent", "-rl", "20"],
                     "then": {"bin": "uro", "args": []},
                     "install": "sudo apt install katana uro", "cat": "web"},
    "wpprobe": {"label": "wpprobe plugin scan", "bin": "wpprobe", "kind": "url",
                "args": ["scan", "-u", "{u}"], "active": True, "timeout": 240,
                "install": "sudo apt install wpprobe", "cat": "web"},
    "dalfox": {"label": "dalfox XSS scan", "bin": "dalfox", "kind": "url", "level": "intrusive",
               "active": True, "timeout": 300,
               "args": ["url", "{u}", "--silence", "--no-spinner"],
               "install": "sudo apt install dalfox", "cat": "web"},
    "sstimap": {"label": "SSTImap template-injection scan", "bin": "sstimap", "kind": "url",
                "level": "intrusive", "active": True, "timeout": 300,
                "args": ["-u", "{u}"], "install": "sudo apt install sstimap", "cat": "web"},
    "xsstrike": {"label": "XSStrike XSS scan", "bin": "xsstrike", "kind": "url",
                 "level": "intrusive", "active": True, "timeout": 300,
                 "args": ["-u", "{u}", "--skip"], "install": "sudo apt install xsstrike", "cat": "web"},

    # ---- CTF: file-based tools (drop a file, then run against its stored_path) ----
    "binwalk_extract": {"label": "binwalk (identify + extract)", "bin": "binwalk", "kind": "file",
                        "args": ["-e", "-q", "{f}"], "active": False, "timeout": 120,
                        "install": "sudo apt install binwalk", "cat": "forensics"},
    "exiftool_full": {"label": "exiftool (full metadata)", "bin": "exiftool", "kind": "file",
                      "args": ["-q", "{f}"], "active": False, "timeout": 20,
                      "install": "sudo apt install libimage-exiftool-perl", "cat": "forensics"},
    "zsteg_scan": {"label": "zsteg -a (PNG/BMP LSB stego)", "bin": "zsteg", "kind": "file",
                   "args": ["-a", "{f}"], "active": False, "timeout": 60,
                   "install": "gem install zsteg", "cat": "forensics"},
    "upx_unpack": {"label": "upx -d (unpack if UPX-packed)", "bin": "upx", "kind": "file",
                   "args": ["-d", "{f}", "-o", "/tmp/portal_unpacked"],
                   "active": False, "timeout": 30, "install": "sudo apt install upx-ucl", "cat": "re"},
    "radare2_info": {"label": "r2 (aaa; afl; iz)", "bin": "r2", "kind": "file",
                     "args": ["-q", "-c", "aaa; afl; iz", "{f}"], "active": False, "timeout": 60,
                     "install": "sudo apt install radare2", "cat": "re"},
    "foremost_carve": {"label": "foremost (carve embedded files)", "bin": "foremost", "kind": "file",
                       "args": ["-i", "{f}", "-o", "/tmp/portal_carved"], "active": False,
                       "timeout": 120, "install": "sudo apt install foremost", "cat": "forensics"},
    "strings_ascii": {"label": "strings -n 6", "bin": "strings", "kind": "file",
                      "args": ["-n", "6", "{f}"], "active": False, "timeout": 20,
                      "install": "sudo apt install binutils", "cat": "re"},

    # ---- CTF: hash tools (pass the hash itself as target) ----
    "hashcat_quick": {"label": "hashcat (-m auto, rockyou)", "bin": "hashcat", "kind": "hash",
                      "args": ["-a", "0", "-m", "{m}", "--potfile-disable", "--quiet", "{t}", "{w}"],
                      "active": False, "needs_wordlist": True, "timeout": 600,
                      "install": "sudo apt install hashcat", "cat": "crypto"},
    "john_quick": {"label": "john the ripper (rockyou)", "bin": "john", "kind": "hash",
                   "args": ["--format={j}", "--wordlist={w}", "{t}"],
                   "active": False, "needs_wordlist": True, "timeout": 600,
                   "install": "sudo apt install john", "cat": "crypto"},
}

# helper-only binaries that are not buttons themselves but are worth reporting in the tool check
EXTRA_BINS = {"uro": ("sudo apt install uro", "web"),
              "sherlock": ("pipx install sherlock-project", "osint"),
              "maigret": ("pipx install maigret", "osint"),
              "sherlock-project": ("pipx install sherlock-project", "osint")}

_tool_gate = threading.Semaphore(1)


# --------------------------------------------------------------------------- #
# Target resolution
# --------------------------------------------------------------------------- #

def _tool_target(q):
    """Return (host, url, path). At most one is non-None."""
    q = (q or "").strip()
    if not q:
        return (None, None, None)
    if re.match(r"^https?://", q, re.I):
        url = norm_url(q)
        if not url:
            return (None, None, None)
        return (valid_target(urlparse(url).hostname), url, None)
    if os.path.isfile(q):
        return (None, None, q)
    h = valid_target(q)
    return (h, norm_url(q) if h else None, None)


def _is_safe_upload_path(path):
    try:
        from .files import is_safe_upload_path
        return is_safe_upload_path(path)
    except Exception:
        return False


def _hashcat_mode(h):
    return {32: "0", 40: "100", 64: "1400", 128: "1700"}.get(len((h or "").strip()), "0")


def _john_format(h):
    return {32: "raw-md5", 40: "raw-sha1", 64: "raw-sha256", 128: "raw-sha512"}.get(
        len((h or "").strip()), "raw-md5")


def file_tool_list():
    """File-based tool ids that are installed here."""
    return [k for k, v in TOOLS.items() if v.get("kind") == "file" and shutil.which(v["bin"])]


# --------------------------------------------------------------------------- #
# Catalog / availability
# --------------------------------------------------------------------------- #

def tool_status():
    seen, out = {}, []
    for k, v in TOOLS.items():
        b = v["bin"]
        if b not in seen:
            seen[b] = {"bin": b, "installed": bool(shutil.which(b)),
                       "install": v.get("install", f"sudo apt install {b}"),
                       "cat": v.get("cat", "recon"), "tools": []}
            out.append(seen[b])
        seen[b]["tools"].append(v["label"])
    for b, (cmd, cat) in EXTRA_BINS.items():
        if b not in seen:
            out.append({"bin": b, "installed": bool(shutil.which(b)),
                        "install": cmd, "cat": cat, "tools": []})
    return out


@app.get("/api/toolstatus")
def api_toolstatus():
    actions = {k: {"label": v["label"], "bin": v["bin"],
                   "installed": bool(shutil.which(v["bin"])),
                   "install": v.get("install", f"sudo apt install {v['bin']}"),
                   "active": v["active"], "intrusive": v.get("level") == "intrusive",
                   "kind": v.get("kind", "host")}
               for k, v in TOOLS.items()}
    return jsonify(tools=tool_status(), actions=actions)


# --------------------------------------------------------------------------- #
# Output parsers
# --------------------------------------------------------------------------- #

_NMAP_PORT = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open\S*\s+(\S+)\s*(.*)$")
_RUSTSCAN_G = re.compile(r"^(\S+)\s*->\s*\[([\d,\s]*)\]")
_CVE_ANY = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_WP_PLUGIN = re.compile(r"plugin\W+([a-z0-9][a-z0-9_-]+)\W+v?(\d+(?:\.\d+)+)", re.I)
_PORT_TOOLS = {"nmap_quick", "nmap_services", "rustscan_nmap", "rustscan_ports"}
_VULN_MARKERS = {
    "dalfox": re.compile(r"\[V\]"),
    "xsstrike": re.compile(r"vulnerable webpage", re.I),
    "sstimap": re.compile(r"identified the following injection point", re.I),
}


def parse_findings(tool, text):
    """Raw tool output -> structured findings (ports, endpoints, CVEs, vulns)."""
    out = []
    try:
        lines = [ln.strip() for ln in (text or "").splitlines()]
        if tool in _PORT_TOOLS:
            ports = {}
            for ln in lines:
                m = _NMAP_PORT.match(ln)
                if m and 0 < int(m.group(1)) < 65536:
                    ports[int(m.group(1))] = {"type": "port", "port": int(m.group(1)),
                                              "proto": m.group(2), "service": m.group(3)[:40],
                                              "version": m.group(4).strip()[:120]}
                    continue
                g = _RUSTSCAN_G.match(ln)
                if g:
                    for p in re.findall(r"\d+", g.group(2)):
                        if 0 < int(p) < 65536:
                            ports.setdefault(int(p), {"type": "port", "port": int(p),
                                                      "proto": "tcp", "service": "", "version": ""})
            out = [ports[p] for p in sorted(ports)][:200]
        elif tool == "katana_crawl":
            seen = set()
            for ln in lines:
                if not re.match(r"^https?://\S+$", ln) or ln in seen:
                    continue
                seen.add(ln)
                params = [k for k, _ in parse_qsl(urlparse(ln).query, keep_blank_values=True)]
                out.append({"type": "endpoint", "url": ln[:300],
                            "params": list(dict.fromkeys(params))[:10]})
                if len(out) >= 300:
                    break
        elif tool == "wpprobe":
            for cid in list(dict.fromkeys(c.upper() for c in _CVE_ANY.findall(text or "")))[:40]:
                out.append({"type": "cve", "id": cid})
            for ln in lines:
                m = _WP_PLUGIN.search(ln)
                if m:
                    out.append({"type": "plugin", "name": m.group(1).lower()[:60],
                                "version": m.group(2)})
        elif tool in _VULN_MARKERS:
            for ln in lines:
                if _VULN_MARKERS[tool].search(ln):
                    out.append({"type": "vuln", "tool": tool, "detail": ln[:300]})
                    if len(out) >= 20:
                        break
    except Exception:
        return []
    return out


def summarize_findings(fs):
    parts = []
    ports = [f for f in fs if f["type"] == "port"]
    eps = [f for f in fs if f["type"] == "endpoint"]
    cves = [f for f in fs if f["type"] == "cve"]
    plugins = [f for f in fs if f["type"] == "plugin"]
    vulns = [f for f in fs if f["type"] == "vuln"]
    if ports:
        parts.append(f"{len(ports)} open port(s): " + ", ".join(
            f"{p['port']}/{p['service'] or '?'}" for p in ports[:8]))
    if eps:
        parts.append(f"{len(eps)} endpoint(s), {sum(1 for e in eps if e['params'])} with parameters")
    if plugins:
        parts.append(f"{len(plugins)} plugin(s) listed")
    if cves:
        parts.append(f"{len(cves)} CVE id(s)")
    if vulns:
        parts.append(f"{len(vulns)} possible vulnerability line(s)")
    return "; ".join(parts)


# --------------------------------------------------------------------------- #
# /api/run module: the toolbox window for host/url targets
# --------------------------------------------------------------------------- #

def mod_tools(q):
    target, url, path = _tool_target(q)
    chips = [chip(s["bin"], "installed" if shutil.which(s["bin"]) else "not installed",
                  "ok" if shutil.which(s["bin"]) else "info")
             for s in {v["bin"]: v for v in TOOLS.values()}.values()]
    actions = [{"id": k, "label": v["label"], "active": v["active"],
                "kind": v.get("kind", "host"), "intrusive": v.get("level") == "intrusive"}
               for k, v in TOOLS.items()
               if shutil.which(v["bin"]) and v.get("kind", "host") in ("host", "url")]
    note = ("Active tools send traffic to the target. Use them only on systems you own or are authorised to test. "
            "Intrusive scanners (dalfox, SSTImap, XSStrike) also make you type the host to confirm. "
            "Edit TOOLS in portal_lib/tools.py to add more.")
    if not target:
        note = "Target is not a single host or domain. " + note
        actions = []
    return R("Local toolbox", "🧰", "info", highlights=chips, actions=actions,
             target=target, url=url, note=note)


# --------------------------------------------------------------------------- #
# /api/tool endpoint
# --------------------------------------------------------------------------- #

@app.post("/api/tool")
def api_tool():
    j = request.get_json(silent=True) or {}
    tool_id = j.get("tool")
    spec = TOOLS.get(tool_id)
    if not spec:
        return jsonify(error="Unknown tool"), 400

    kind = spec.get("kind", "host")
    target, url, path = _tool_target(str(j.get("target", "")))

    if kind == "file":
        if not path or not _is_safe_upload_path(path):
            return jsonify(error="File tool: pass stored_path from POST /api/file (upload first)"), 400
        if not os.path.isfile(path):
            return jsonify(error="Uploaded file is gone (expired after 30 minutes)"), 410
        scope_target = None
    elif kind == "url":
        if not url:
            return jsonify(error="Invalid URL target"), 400
        scope_target = target
    elif kind == "hash":
        if not str(j.get("target", "")).strip():
            return jsonify(error="Pass the hash as 'target'"), 400
        target = str(j["target"]).strip()
        scope_target = None
    else:  # host
        if not target:
            return jsonify(error="Invalid host target"), 400
        scope_target = target

    if spec["active"] and (bad := scope_error(scope_target or "")):
        return jsonify(error=bad), 403
    if spec["active"] and j.get("confirm") is not True:
        return jsonify(error="Tick the authorisation box before running active tools"), 400
    if spec.get("level") == "intrusive" and str(j.get("confirm_target", "")).strip().lower() != (target or ""):
        return jsonify(error=f"Intrusive scan: type the target host ({target}) to confirm"), 400

    exe = shutil.which(spec["bin"])
    if not exe:
        return jsonify(error=f"{spec['bin']} is not installed "
                             f"({spec.get('install', 'sudo apt install ' + spec['bin'])})"), 404

    # wordlist
    wordlist = None
    if spec.get("needs_wordlist"):
        try:
            from .ctf_files import WORDLIST_PATHS
        except Exception:
            WORDLIST_PATHS = []
        wordlist = j.get("wordlist") or next((p for p in WORDLIST_PATHS if os.path.isfile(p)), None)
        if not wordlist or not os.path.isfile(wordlist):
            return jsonify(error="No wordlist found. Install one (sudo apt install wordlists) "
                                 "or pass wordlist=<full path>"), 400

    if not _tool_gate.acquire(blocking=False):
        return jsonify(error="Another tool is still running"), 429

    # For john, the hash needs to be a file. Write it to a temp file and clean up after.
    hash_tempfile = None
    if kind == "hash" and spec["bin"] == "john":
        try:
            hash_tempfile = tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt")
            hash_tempfile.write(target + "\n")
            hash_tempfile.close()
            target_arg = hash_tempfile.name
        except Exception as e:
            _tool_gate.release()
            return jsonify(error=f"Could not write hash temp file: {e}"), 500
    else:
        target_arg = target or ""

    args = []
    try:
        for a in spec["args"]:
            a = (a.replace("{t}", target_arg).replace("{u}", url or "")
                   .replace("{f}", path or "").replace("{w}", wordlist or ""))
            if "{m}" in a:
                a = a.replace("{m}", _hashcat_mode(target or ""))
            if "{j}" in a:
                a = a.replace("{j}", _john_format(target or ""))
            args.append(a)
        cmd = " ".join([spec["bin"]] + args)
        p = subprocess.run([exe] + args, capture_output=True, text=True, timeout=spec["timeout"])
        text, err = p.stdout or "", (p.stderr or "").strip()
        then = spec.get("then")
        if then and text.strip():
            exe2 = shutil.which(then["bin"])
            if exe2:
                before = len(text.splitlines())
                p2 = subprocess.run([exe2] + then["args"], input=text,
                                    capture_output=True, text=True, timeout=60)
                text = (f"# {before} URLs found, {len(p2.stdout.splitlines())} after "
                        f"{then['bin']} dedupe\n") + (p2.stdout or "")
                cmd += f" | {then['bin']}"
            else:
                err = (err + "\n" if err else "") + (
                    f"({then['bin']} not installed, output not deduplicated: "
                    f"{EXTRA_BINS.get(then['bin'], ('',))[0]})")
        findings = parse_findings(tool_id, text)
        summary = summarize_findings(findings)
        if summary:
            text = f"# Parsed: {summary}\n" + text
        out = text + (("\n" + err) if err else "")
        return jsonify(output=out[:30000] or "(no output)", command=cmd,
                       code=p.returncode, findings=findings)
    except subprocess.TimeoutExpired:
        return jsonify(error=f"{spec['bin']} timed out after {spec['timeout']}s"), 504
    except Exception as e:
        return jsonify(error=f"{type(e).__name__}: {e}"), 500
    finally:
        if hash_tempfile is not None:
            try:
                os.unlink(hash_tempfile.name)
            except OSError:
                pass
        _tool_gate.release()
