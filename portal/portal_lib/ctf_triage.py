"""Adds the CTF triage sections (forensics + binary) to any file-analysis result, and raises a "Flags found" chip."""
from __future__ import annotations

from .core import chip, row
from .ctf_binary import triage as binary_triage
from .ctf_forensics import triage as forensic_triage


def add_ctf_triage(res, path, size, head):
    if not isinstance(res, dict) or size > 48 * 1024 * 1024:
        return res
    sections, flags, hints = [], [], []
    try:
        b = binary_triage(path)
        if b:
            sections.append({"title": "Executable triage (static)", "rows": [row(k, v, t) for k, v, t in b["rows"]]})
            hints += b["hints"]
    except Exception:
        pass
    try:
        f = forensic_triage(path, size, head)
        shown = [r for r in f["rows"] if r[2] == "warn" or r[0].startswith(("Interesting", "PNG text", "JPEG comment", "Data after", "Hidden"))]
        if shown:
            sections.append({"title": "Hidden-data check", "rows": [row(k, v, t) for k, v, t in shown]})
        flags, hints = f["flags"], hints + f["hints"]
    except Exception:
        pass
    if flags:
        sections.insert(0, {"title": "Possible flags", "rows": [row("flag", fl, "ok") for fl in flags[:15]]})
        res.setdefault("highlights", []).insert(0, chip("Flags found", str(len(flags)), "ok"))
    if hints:
        sections.append({"title": "Next steps", "rows": [row("→", h) for h in dict.fromkeys(hints)]})
    old = res.get("sections") or []
    res["sections"] = (sections + old) if flags else (old + sections)      # flags go on top
    return res
