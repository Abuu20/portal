"""CTF helpers, part 3: forensics triage for any file you drop on PORTAL (static; nothing is executed or extracted to disk).

Strings with flag hunting, hidden files inside the file (signature scan), data after the logical end of PNG / JPEG / GIF,
PNG text chunks, JPEG comments and a simple LSB check for images. A hit here is a lead, not proof.
"""
from __future__ import annotations

import re
import struct

from .ctf_decode import entropy, find_flags, magic, printable_ratio

MAX_READ = 32 * 1024 * 1024
SIGS = [(b"PK\x03\x04", "ZIP / Office / JAR archive"), (b"\x89PNG\r\n\x1a\n", "PNG image"), (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF8", "GIF image"), (b"%PDF-", "PDF document"), (b"\x7fELF", "ELF executable"), (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"Rar!\x1a\x07", "RAR archive"), (b"\x1f\x8b\x08", "gzip data"), (b"BZh", "bzip2 data"), (b"SQLite format 3\x00", "SQLite database"),
        (b"\xfd7zXZ\x00", "xz data"), (b"OggS", "Ogg media"), (b"fLaC", "FLAC audio"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 / old Office file"),
        (b"MZ\x90\x00", "Windows executable (MZ)"), (b"-----BEGIN ", "PEM key / certificate text"), (b"ustar", "tar archive (at offset 257)")]
INTERESTING = re.compile(rb"(?i)(https?://[\x21-\x7e]{6,}|[\w.+-]+@[\w-]+\.[\w.-]+|password[\x20-\x7e]{0,40}|passwd[\x20-\x7e]{0,40}|secret[\x20-\x7e]{0,40}|api[_-]?key[\x20-\x7e]{0,50}|BEGIN [A-Z ]*PRIVATE KEY)")
B64ISH = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")


def strings(data, minlen=6, cap=40000):
    out = [m.group(0) for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data)][:cap]
    u16 = [m.group(0).decode("utf-16-le", "ignore").encode() for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data)][:cap // 4]
    return out + u16


def find_embedded(data, is_zip_like=False):
    hits = []
    for sig, name in SIGS:
        if is_zip_like and sig.startswith(b"PK"):
            continue
        start = 0
        while len(hits) < 60:
            i = data.find(sig, start)
            if i < 0:
                break
            start = i + 1
            if sig == b"ustar":
                i -= 257
                if i < 0:
                    continue
            if i == 0:
                continue
            if sig in (b"BZh", b"GIF8", b"OggS", b"MZ\x90\x00") and not _plausible(data, i, sig):
                continue
            hits.append((i, name))
            if sig in (b"BZh", b"\x1f\x8b\x08") and len([h for h in hits if h[1] == name]) >= 3:
                break
    hits.sort()
    return hits[:30]


def _plausible(data, i, sig):
    if sig == b"BZh":
        return data[i + 3:i + 4] in b"123456789" and data[i + 4:i + 10] == b"1AY&SY"
    if sig == b"GIF8":
        return data[i + 4:i + 6] in (b"7a", b"9a")
    return True


def trailing(data, head):
    """Bytes after the logical end of the file, for formats that have one."""
    end = None
    if head.startswith(b"\x89PNG"):
        i = data.find(b"IEND")
        end = i + 8 if i >= 0 else None
    elif head.startswith(b"\xff\xd8"):
        i = data.rfind(b"\xff\xd9")
        end = i + 2 if i >= 0 else None
    elif head.startswith(b"GIF8"):
        i = data.rfind(b"\x3b")
        end = i + 1 if i >= 0 else None
    if end is not None and end < len(data) - 4:
        return end, data[end:]
    return None


def png_chunks(data):
    out, texts, i = [], [], 8
    while i + 8 <= len(data) and len(out) < 200:
        ln, typ = struct.unpack(">I4s", data[i:i + 8])
        body = data[i + 8:i + 8 + min(ln, 100000)]
        t = typ.decode("latin-1")
        out.append((t, ln))
        if t == "tEXt":
            texts.append(body.replace(b"\x00", b" = ", 1).decode("latin-1"))
        elif t == "zTXt" and b"\x00" in body:
            k, rest = body.split(b"\x00", 1)
            try:
                import zlib
                texts.append(k.decode("latin-1") + " = " + zlib.decompress(rest[1:]).decode("latin-1"))
            except Exception:
                pass
        elif t == "iTXt":
            texts.append(body.decode("utf-8", "replace").replace("\x00", " "))
        i += 12 + ln
        if t == "IEND":
            break
    return out, texts


def jpeg_comments(data):
    out, i = [], 2
    while i + 4 < len(data) and data[i] == 0xFF and len(out) < 10:
        m = data[i + 1]
        if m in (0xD9, 0xDA):
            break
        ln = struct.unpack(">H", data[i + 2:i + 4])[0]
        if m == 0xFE:
            out.append(data[i + 4:i + 2 + ln].decode("latin-1"))
        i += 2 + ln
    return out


def lsb_probe(path):
    """Read the lowest bit of each colour channel as bytes; report if it looks like text or hides a flag."""
    try:
        from PIL import Image
    except Exception:
        return None
    try:
        im = Image.open(path).convert("RGB")
        if im.width * im.height > 4_000_000:
            return None
        px = im.tobytes()[:60000 * 3]
    except Exception:
        return None
    out = []
    for order in ("RGB", "BGR"):
        bits = []
        for i in range(0, len(px) - 2, 3):
            ch = (px[i], px[i + 1], px[i + 2]) if order == "RGB" else (px[i + 2], px[i + 1], px[i])
            bits += [c & 1 for c in ch]
        raw = bytes(int("".join(map(str, bits[j:j + 8])), 2) for j in range(0, min(len(bits), 24000) - 7, 8))
        if find_flags(raw) or (printable_ratio(raw[:200]) > 0.9 and len(raw) >= 40):
            out.append((order, raw[:120].decode("latin-1"), find_flags(raw)))
    return out or None


def triage(path, size, head):
    """Return {"rows": [...(key,value,tone)], "flags": [...], "hints": [...]} for any file."""
    with open(path, "rb") as f:
        data = f.read(MAX_READ)
    rows, flags, hints = [], [], []
    ent = entropy(data[:1_000_000])
    rows.append(("Entropy", f"{ent:.2f} bits/byte" + (" (compressed or encrypted)" if ent > 7.5 else ""), "warn" if ent > 7.5 else None))
    zip_like = head.startswith(b"PK\x03\x04")
    for off, name in find_embedded(data, zip_like):
        rows.append((f"Hidden {name}", f"at offset {off} (0x{off:x})", "warn"))
        hints.append(f"Carve the data at offset {off}: dd if=FILE of=out bs=1 skip={off}")
    tr = trailing(data, head)
    if tr:
        off, blob = tr
        mg = [n for s, n in SIGS if blob.startswith(s)]
        rows.append(("Data after the end of the file", f"{len(blob)} bytes at offset {off}" + (f" · looks like {mg[0]}" if mg else ""), "warn"))
        flags += find_flags(blob)
        res = magic(blob[:5000])
        flags += [f for f in res["flags"] if f not in flags]
    if head.startswith(b"\x89PNG"):
        chunks, texts = png_chunks(data)
        odd = [c for c, _ in chunks if c not in ("IHDR", "PLTE", "IDAT", "IEND", "tEXt", "zTXt", "iTXt", "pHYs", "gAMA", "sRGB", "cHRM", "bKGD", "tIME", "sBIT", "iCCP", "tRNS", "eXIf")]
        if odd:
            rows.append(("Unusual PNG chunks", ", ".join(sorted(set(odd))[:8]), "warn"))
        for t in texts[:6]:
            rows.append(("PNG text chunk", t[:200], None)); flags += find_flags(t)
    if head.startswith(b"\xff\xd8"):
        for c in jpeg_comments(data):
            rows.append(("JPEG comment", c[:200], None)); flags += find_flags(c)
    if head[:4] in (b"\x89PNG", b"BM") or head.startswith(b"\xff\xd8") or head.startswith(b"GIF8"):
        for order, txt, fl in (lsb_probe(path) or []):
            rows.append((f"LSB data ({order})", txt[:100], "warn")); flags += fl
            hints.append("Text hidden in the low bits of pixels: try zsteg -a, stegsolve or steghide.")
    strs = strings(data)
    joined = b"\n".join(strs)
    flags += [f for f in find_flags(joined) if f not in flags]
    for m in B64ISH.finditer(joined[:400000]):
        r = magic(m.group(0), depth=3)
        for f in r["flags"]:
            if f not in flags:
                flags.append(f)
        if len(flags) > 20:
            break
    seen = set()
    for m in INTERESTING.finditer(joined[:2_000_000]):
        v = m.group(0).decode("latin-1")[:120]
        if v not in seen and len(seen) < 15:
            seen.add(v); rows.append(("Interesting string", v, None))
    rows.append(("Printable strings", f"{len(strs)} found (first: " + "; ".join(s.decode('latin-1')[:30] for s in strs[:3]) + ")", None))
    return {"rows": rows, "flags": flags[:30], "hints": hints[:6]}
