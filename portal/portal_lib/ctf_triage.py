"""Adds the CTF triage sections (forensics + binary + crypto + network) to a dropped file.

Also runs external tools (binwalk, exiftool, zsteg, upx, r2) if they are installed.
"""
from __future__ import annotations

import shutil
import subprocess

from .core import chip, row
from .ctf_binary import triage as binary_triage
from .ctf_forensics import triage as forensic_triage
from .ctf_files import analyze_file as file_crypto
from .ctf_network import analyze as pcap_analyze
from .ctf_reverse import analyze as reverse_analyze

EXTERNAL = [
    ("binwalk", ["binwalk", "-q", "{f}"], 12, "binwalk",
     "sudo apt install binwalk"),
    ("exiftool", ["exiftool", "-q", "{f}"], 8, "exiftool",
     "sudo apt install libimage-exiftool-perl"),
    ("zsteg", ["zsteg", "-a", "{f}"], 15, "zsteg",
     "gem install zsteg"),
    ("upx", ["upx", "-t", "{f}"], 5, "upx test",
     "sudo apt install upx-ucl"),
    ("radare2", ["r2", "-q", "-c", "aaa; afl; iz~flag", "{f}"], 20, "radare2",
     "sudo apt install radare2"),
]


def add_ctf_triage(res, path, size, head):
    if not isinstance(res, dict) or size > 64 * 1024 * 1024:
        return res
    sections, flags, hints = [], [], []

    # binary (ELF / PE static triage)
    try:
        b = binary_triage(path)
        if b:
            sections.append({"title": "Executable triage (static)", "rows": [row(k, v, t) for k, v, t in b["rows"]]})
            hints += b["hints"]
    except Exception:
        pass

    # reverse-engineering helpers (capstone disassembly, flag strings, angr hint)
    try:
        with open(path, "rb") as f:
            raw = f.read(16 * 1024 * 1024)
        r = reverse_analyze(path, raw)
        if r:
            sections.append({"title": "Reverse-engineering hints", "rows": [row(k, v, t) for k, v, t in r["rows"]]})
            flags += r["flags"]
            hints += r["hints"]
    except Exception:
        pass

    # file-level crypto (openssl, zip, pdf, xor, aes)
    try:
        c = file_crypto(path, "upload.bin", head, size)
        if c:
            sections.append({"title": "File decryption attempts", "rows": [row(k, v, t) for k, v, t in c["rows"]]})
            flags += c["flags"]
            hints += c["hints"]
    except Exception:
        pass

    # forensics (embedded files, strings, LSB, flags)
    try:
        f = forensic_triage(path, size, head)
        shown = [r for r in f["rows"] if r[2] == "warn" or r[0].startswith(
            ("Interesting", "PNG text", "JPEG comment", "Data after", "Hidden", "LSB"))]
        if shown:
            sections.append({"title": "Hidden-data check", "rows": [row(k, v, t) for k, v, t in shown]})
        flags = list(dict.fromkeys(flags + f["flags"]))
        hints += f["hints"]
    except Exception:
        pass

    # PCAP
    try:
        with open(path, "rb") as f:
            raw = f.read(32 * 1024 * 1024)
        p = pcap_analyze(raw)
        if p:
            sections.append({"title": "PCAP analysis", "rows": [row(k, v, t) for k, v, t in p["rows"]]})
            flags = list(dict.fromkeys(flags + p["flags"]))
            hints += p["hints"]
    except Exception:
        pass

    # external tools
    ext_rows = []
    for binary, argv, timeout, label, install in EXTERNAL:
        if not shutil.which(argv[0]):
            hints.append(f"{label} not installed ({install})")
            continue
        try:
            p = subprocess.run([a.replace("{f}", path) for a in argv],
                               capture_output=True, text=True, timeout=timeout)
            out = (p.stdout or "").strip().splitlines()[:40]
            if out:
                ext_rows.append(row(label, "  |  ".join(out[:3])[:300], None))
                for ln in out:
                    if "flag" in ln.lower() or "CTF" in ln:
                        flags.append(ln[:200])
        except subprocess.TimeoutExpired:
            hints.append(f"{label} timed out")
        except Exception as e:
            hints.append(f"{label}: {type(e).__name__}")
    if ext_rows:
        sections.append({"title": "External tools", "rows": ext_rows})

    if flags:
        uniq = list(dict.fromkeys(flags))
        sections.insert(0, {"title": "Possible flags", "rows": [row("flag", fl, "ok") for fl in uniq[:15]]})
        res.setdefault("highlights", []).insert(0, chip("Flags found", str(len(uniq)), "ok"))
    if hints:
        sections.append({"title": "Next steps", "rows": [row("→", h) for h in dict.fromkeys(hints)]})
    old = res.get("sections") or []
    res["sections"] = (sections + old) if flags else (old + sections)
    return res
