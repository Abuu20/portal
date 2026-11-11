"""Local toolbox: the tool catalogue, availability check, output parsers and the /api/tool endpoint."""
from __future__ import annotations

import re
import shutil
import subprocess
import threading
from flask import jsonify, request
from urllib.parse import parse_qsl, urlparse

from .core import R, app, chip, norm_url, valid_target

# Tool catalog. Fields:
#   bin / args   executable and argument list ({t} = host or IP, {u} = URL); never run through a shell
#   active       sends traffic to the target -> needs the authorisation tick-box
#   level        "intrusive" = sends attack-style payloads -> also needs the target host typed to confirm
#   kind         "host" (default) or "url" (host is expanded to https://host/)
#   then         optional second command that filters the first one's output (e.g. katana | uro)
#   install      the exact command shown when the tool is missing
TOOLS = {
    "whois": {"label": "whois", "bin": "whois", "args": ["{t}"], "active": False, "timeout": 40,
              "install": "sudo apt install whois", "cat": "recon"},
    "dig": {"label": "dig records", "bin": "dig", "active": False, "timeout": 30, "install": "sudo apt install dnsutils",
            "cat": "recon", "args": ["+noall", "+answer", "{t}", "A", "{t}", "AAAA", "{t}", "MX", "{t}", "NS", "{t}", "TXT"]},
    "nmap_quick": {"label": "nmap top-100 ports", "bin": "nmap", "args": ["-Pn", "-T3", "-F", "--open", "{t}"], "active": True,
                   "timeout": 240, "install": "sudo apt install nmap", "cat": "network"},
    "nmap_services": {"label": "nmap service versions", "bin": "nmap", "active": True, "timeout": 300,
                      "install": "sudo apt install nmap", "cat": "network",
                      "args": ["-Pn", "-T3", "-sV", "--version-light", "-F", "--open", "{t}"]},
    "whatweb": {"label": "whatweb", "bin": "whatweb", "args": ["-a", "1", "--no-errors", "{t}"], "active": True, "timeout": 90,
                "install": "sudo apt install whatweb", "cat": "web"},
    "traceroute": {"label": "traceroute", "bin": "traceroute", "args": ["-m", "20", "-w", "2", "{t}"], "active": True,
                   "timeout": 90, "install": "sudo apt install traceroute", "cat": "network"},
    # --- added from Kali 2026.x ---
    "rustscan_ports": {"label": "rustscan fast port sweep", "bin": "rustscan", "args": ["-a", "{t}", "--ulimit", "5000", "-g"],
                       "active": True, "timeout": 180, "install": "sudo apt install rustscan", "cat": "network"},
    "rustscan_nmap": {"label": "rustscan → nmap versions", "bin": "rustscan", "active": True, "timeout": 420,
                      "install": "sudo apt install rustscan nmap", "cat": "network",
                      "args": ["-a", "{t}", "--ulimit", "5000", "--", "-sV", "--version-light", "-Pn"]},
    "katana_crawl": {"label": "katana crawl + uro dedupe", "bin": "katana", "kind": "url", "active": True, "timeout": 180,
                     "args": ["-u", "{u}", "-d", "2", "-silent", "-rl", "20"], "then": {"bin": "uro", "args": []},
                     "install": "sudo apt install katana uro", "cat": "web"},
    "wpprobe": {"label": "wpprobe plugin scan", "bin": "wpprobe", "kind": "url", "args": ["scan", "-u", "{u}"],
                "active": True, "timeout": 240, "install": "sudo apt install wpprobe", "cat": "web"},
    "dalfox": {"label": "dalfox XSS scan", "bin": "dalfox", "kind": "url", "level": "intrusive", "active": True,
               "timeout": 300, "args": ["url", "{u}", "--silence", "--no-spinner"],
               "install": "sudo apt install dalfox", "cat": "web"},
    "sstimap": {"label": "SSTImap template-injection scan", "bin": "sstimap", "kind": "url", "level": "intrusive", "active": True,
                "timeout": 300, "args": ["-u", "{u}"], "install": "sudo apt install sstimap", "cat": "web"},
    "xsstrike": {"label": "XSStrike XSS scan", "bin": "xsstrike", "kind": "url", "level": "intrusive", "active": True,
                 "timeout": 300, "args": ["-u", "{u}", "--skip"], "install": "sudo apt install xsstrike", "cat": "web"},
}

# helper-only binaries that are not buttons themselves but are worth reporting in the tool check
EXTRA_BINS = {"uro": ("sudo apt install uro", "web"), "sherlock": ("pipx install sherlock-project", "osint"),
              "maigret": ("pipx install maigret", "osint")}

_tool_gate = threading.Semaphore(1)

def _tool_target(q):
    """Split a query (host, IP or URL) into (host, url). host is None when the query is not a single valid target."""
    q = (q or "").strip()
    if re.match(r"^https?://", q, re.I):
        url = norm_url(q)
        return (valid_target(urlparse(url).hostname), url) if url else (None, None)
    return valid_target(q), norm_url(q)

def tool_status():
    """Which catalog tools are installed here, with the exact install command for the missing ones."""
    seen, out = {}, []
    for k, v in TOOLS.items():
        b = v["bin"]
        if b not in seen:
            seen[b] = {"bin": b, "installed": bool(shutil.which(b)), "install": v.get("install", f"sudo apt install {b}"),
                       "cat": v.get("cat", "recon"), "tools": []}
            out.append(seen[b])
        seen[b]["tools"].append(v["label"])
    for b, (cmd, cat) in EXTRA_BINS.items():
        if b not in seen:
            out.append({"bin": b, "installed": bool(shutil.which(b)), "install": cmd, "cat": cat, "tools": []})
    return out

@app.get("/api/toolstatus")
def api_toolstatus():
    actions = {k: {"label": v["label"], "bin": v["bin"], "installed": bool(shutil.which(v["bin"])),
                   "install": v.get("install", f"sudo apt install {v['bin']}"), "active": v["active"],
                   "intrusive": v.get("level") == "intrusive", "kind": v.get("kind", "host")}
               for k, v in TOOLS.items()}
    return jsonify(tools=tool_status(), actions=actions)

_NMAP_PORT = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open\S*\s+(\S+)\s*(.*)$")

_RUSTSCAN_G = re.compile(r"^(\S+)\s*->\s*\[([\d,\s]*)\]")

_CVE_ANY = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

_WP_PLUGIN = re.compile(r"plugin\W+([a-z0-9][a-z0-9_-]+)\W+v?(\d+(?:\.\d+)+)", re.I)

_PORT_TOOLS = {"nmap_quick", "nmap_services", "rustscan_nmap", "rustscan_ports"}

_VULN_MARKERS = {   # best-effort: phrases each scanner prints when it believes it found something
    "dalfox": re.compile(r"\[V\]"),
    "xsstrike": re.compile(r"vulnerable webpage", re.I),
    "sstimap": re.compile(r"identified the following injection point", re.I),
}

def parse_findings(tool, text):
    """Raw tool output -> structured findings (ports, endpoints, CVEs, vulns) the UI can reason about.
    Best effort and bounded; it never raises. Nmap/rustscan/katana formats are stable; wpprobe and the
    scanner markers are heuristics, so only CVE ids and marker lines are extracted from them."""
    out = []
    try:
        lines = [ln.strip() for ln in (text or "").splitlines()]
        if tool in _PORT_TOOLS:
            ports = {}
            for ln in lines:
                m = _NMAP_PORT.match(ln)
                if m and 0 < int(m.group(1)) < 65536:
                    ports[int(m.group(1))] = {"type": "port", "port": int(m.group(1)), "proto": m.group(2),
                                              "service": m.group(3)[:40], "version": m.group(4).strip()[:120]}
                    continue
                g = _RUSTSCAN_G.match(ln)
                if g:
                    for p in re.findall(r"\d+", g.group(2)):
                        if 0 < int(p) < 65536:
                            ports.setdefault(int(p), {"type": "port", "port": int(p), "proto": "tcp", "service": "", "version": ""})
            out = [ports[p] for p in sorted(ports)][:200]
        elif tool == "katana_crawl":
            seen = set()
            for ln in lines:
                if not re.match(r"^https?://\S+$", ln) or ln in seen:
                    continue
                seen.add(ln)
                params = [k for k, _ in parse_qsl(urlparse(ln).query, keep_blank_values=True)]
                out.append({"type": "endpoint", "url": ln[:300], "params": list(dict.fromkeys(params))[:10]})
                if len(out) >= 300:
                    break
        elif tool == "wpprobe":
            for cid in list(dict.fromkeys(c.upper() for c in _CVE_ANY.findall(text or "")))[:40]:
                out.append({"type": "cve", "id": cid})
            for ln in lines:
                m = _WP_PLUGIN.search(ln)
                if m:
                    out.append({"type": "plugin", "name": m.group(1).lower()[:60], "version": m.group(2)})
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
        parts.append(f"{len(ports)} open port(s): " + ", ".join(f"{p['port']}/{p['service'] or '?'}" for p in ports[:8]))
    if eps:
        parts.append(f"{len(eps)} endpoint(s), {sum(1 for e in eps if e['params'])} with parameters")
    if plugins:
        parts.append(f"{len(plugins)} plugin(s) listed")
    if cves:
        parts.append(f"{len(cves)} CVE id(s)")
    if vulns:
        parts.append(f"{len(vulns)} possible vulnerability line(s)")
    return "; ".join(parts)

def mod_tools(q):
    target, url = _tool_target(q)
    chips = [chip(s["bin"], "installed" if shutil.which(s["bin"]) else "not installed",
                  "ok" if shutil.which(s["bin"]) else "info")
             for s in {v["bin"]: v for v in TOOLS.values()}.values()]
    actions = [{"id": k, "label": v["label"], "active": v["active"], "kind": v.get("kind", "host"),
                "intrusive": v.get("level") == "intrusive"}
               for k, v in TOOLS.items() if shutil.which(v["bin"])]
    note = ("Active tools send traffic to the target. Use them only on systems you own or are authorised to test. "
            "Intrusive scanners (dalfox, SSTImap, XSStrike) also make you type the host to confirm. "
            "Edit TOOLS in portal_lib/tools.py to add more.")
    if not target:
        note = "Target is not a single host or domain. " + note
        actions = []
    return R("Local toolbox", "🧰", "info", highlights=chips, actions=actions, target=target, url=url, note=note)

@app.post("/api/tool")
def api_tool():
    j = request.get_json(silent=True) or {}
    spec = TOOLS.get(j.get("tool"))
    if not spec:
        return jsonify(error="Unknown tool"), 400
    target, url = _tool_target(str(j.get("target", "")))
    if not target or (spec.get("kind") == "url" and not url):
        return jsonify(error="Invalid target"), 400
    if spec["active"] and j.get("confirm") is not True:
        return jsonify(error="Tick the authorisation box before running active tools"), 400
    if spec.get("level") == "intrusive" and str(j.get("confirm_target", "")).strip().lower() != target:
        return jsonify(error=f"Intrusive scan: type the target host ({target}) to confirm"), 400
    exe = shutil.which(spec["bin"])
    if not exe:
        return jsonify(error=f"{spec['bin']} is not installed ({spec.get('install', 'sudo apt install ' + spec['bin'])})"), 404
    if not _tool_gate.acquire(blocking=False):
        return jsonify(error="Another tool is still running"), 429
    args = [a.replace("{t}", target).replace("{u}", url or "") for a in spec["args"]]
    cmd = " ".join([spec["bin"]] + args)
    try:
        p = subprocess.run([exe] + args, capture_output=True, text=True, timeout=spec["timeout"])
        text, err = p.stdout or "", (p.stderr or "").strip()
        then = spec.get("then")
        if then and text.strip():
            exe2 = shutil.which(then["bin"])
            if exe2:
                before = len(text.splitlines())
                p2 = subprocess.run([exe2] + then["args"], input=text, capture_output=True, text=True, timeout=60)
                text = f"# {before} URLs found, {len(p2.stdout.splitlines())} after {then['bin']} dedupe\n" + (p2.stdout or "")
                cmd += f" | {then['bin']}"
            else:
                err = (err + "\n" if err else "") + f"({then['bin']} not installed, output not deduplicated: {EXTRA_BINS.get(then['bin'], ('',))[0]})"
        findings = parse_findings(j.get("tool"), text)
        summary = summarize_findings(findings)
        if summary:
            text = f"# Parsed: {summary}\n" + text
        out = text + (("\n" + err) if err else "")
        return jsonify(output=out[:30000] or "(no output)", command=cmd, code=p.returncode, findings=findings)
    except subprocess.TimeoutExpired:
        return jsonify(error=f"{spec['bin']} timed out after {spec['timeout']}s"), 504
    finally:
        _tool_gate.release()
