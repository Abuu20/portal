"""CTF helpers, part 1: flag finder and a "decode anything" engine (a small CyberChef-style magic).

Pure functions, no network. `magic(data)` tries many decoders breadth-first, chains them (base64 -> hex -> rot13 ...)
and ranks the outputs by how much they look like text or a flag.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import gzip
import html
import lzma
import re
import string
import urllib.parse
import zlib

KNOWN_PREFIXES = ("flag", "ctf", "htb", "thm", "picoctf", "flg", "dctf", "ductf", "csaw", "cyber", "hack", "key", "pwn",
                  "root", "rctf", "uoftctf", "n00b", "bsides", "inctf", "hxp", "justctf", "tjctf", "lactf", "idek", "corctf")
MAX_NODES = 400
MAX_OUT = 200_000
ENGLISH_COMMON = b" etaoinshrdlucmfwypvbgkqjxz"
WORDS = ("the ", " and ", "flag", "ctf", "that", "this", "with", "from", "have", "password", "secret", "http")
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MORSE = {".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g", "....": "h", "..": "i", ".---": "j",
         "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t",
         "..-": "u", "...-": "v", ".--": "w", "-..-": "x", "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2",
         "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9"}


def find_flags(data, prefixes=()):
    """Return unique flag-looking strings: PREFIX{...} for known prefixes and any you add (case-insensitive)."""
    s = data.decode("latin-1") if isinstance(data, (bytes, bytearray)) else str(data)
    names = sorted({p.strip().rstrip("{").lower() for p in (*KNOWN_PREFIXES, *prefixes) if p.strip()}, key=len, reverse=True)
    if not names:
        return []
    pat = re.compile(r"(?i)\b(?:" + "|".join(re.escape(n) for n in names) + r")\{[\x21-\x7e ]{1,200}?\}")
    seen, out = set(), []
    for m in pat.finditer(s):
        if m.group(0) not in seen:
            seen.add(m.group(0)); out.append(m.group(0))
    return out[:50]


def entropy(b):
    if not b:
        return 0.0
    from math import log2
    return -sum((n / len(b)) * log2(n / len(b)) for n in (b.count(x) for x in set(b)))


def printable_ratio(b):
    if not b:
        return 0.0
    ok = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return ok / len(b)


def english_score(b):
    """0..1-ish: share of common English letters/spaces plus a bonus for common words."""
    if not b:
        return 0.0
    low = b.lower()
    common = sum(1 for c in low if c in ENGLISH_COMMON[:14]) / len(low)
    txt = low.decode("latin-1")
    return min(1.0, common + 0.15 * sum(1 for w in WORDS if w in txt))


def _clean(s):
    return re.sub(r"\s+", "", s)


def _txt(b):
    return b.decode("latin-1")


def d_base64(b):
    s = _clean(_txt(b))
    if len(s) < 8 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        return None
    return base64.b64decode(s + "=" * (-len(s) % 4))


def d_base64url(b):
    s = _clean(_txt(b))
    if len(s) < 8 or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", s) or not re.search(r"[-_]", s):
        return None
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def d_base32(b):
    s = _clean(_txt(b)).upper()
    if len(s) < 8 or not re.fullmatch(r"[A-Z2-7]+=*", s):
        return None
    return base64.b32decode(s + "=" * (-len(s) % 8))


def d_base58(b):
    s = _clean(_txt(b))
    if len(s) < 6 or any(c not in BASE58 for c in s):
        return None
    n = 0
    for c in s:
        n = n * 58 + BASE58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + raw


def d_base85(b):
    s = _txt(b).strip()
    if len(s) < 8:
        return None
    for fn in (base64.b85decode, base64.a85decode):
        try:
            return fn(s)
        except Exception:
            pass
    return None


def d_hex(b):
    s = re.sub(r"(?i)0x|\\x|[\s:,-]", "", _txt(b))
    if len(s) < 4 or len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    return binascii.unhexlify(s)


def d_binary(b):
    s = _clean(_txt(b))
    if len(s) < 8 or len(s) % 8 or not re.fullmatch(r"[01]+", s):
        return None
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))


def d_decimal(b):
    parts = re.split(r"[\s,;]+", _txt(b).strip())
    if len(parts) < 3 or not all(p.isdigit() for p in parts):
        return None
    nums = [int(p) for p in parts]
    return bytes(nums) if all(n < 256 for n in nums) else None


def d_url(b):
    s = _txt(b)
    return urllib.parse.unquote_to_bytes(s) if re.search(r"%[0-9a-fA-F]{2}", s) else None


def d_html(b):
    s = _txt(b)
    return html.unescape(s).encode("utf-8", "replace") if re.search(r"&(#\d+|#x[0-9a-f]+|[a-z]+);", s, re.I) else None


def d_unicode_escape(b):
    s = _txt(b)
    return codecs.decode(s, "unicode_escape").encode("utf-8", "replace") if re.search(r"\\u[0-9a-fA-F]{4}", s) else None


def d_rot13(b):
    return codecs.encode(_txt(b), "rot13").encode("latin-1")


def _shift(b, k):
    out = bytearray(b)
    for i, c in enumerate(out):
        if 65 <= c <= 90: out[i] = (c - 65 + k) % 26 + 65
        elif 97 <= c <= 122: out[i] = (c - 97 + k) % 26 + 97
    return bytes(out)


def _wordlike(b):
    """Looks like a message in one case (not base64 / random mixed-case): worth trying letter substitutions on."""
    t = _txt(b)
    letters = [c for c in t if c.isalpha()]
    if len(letters) < 4 or len(letters) / len(t) < 0.6:
        return False
    up = sum(c.isupper() for c in letters)
    return max(up, len(letters) - up) / len(letters) >= 0.85


def d_caesar(b):
    if not _wordlike(b):
        return None
    base = english_score(b)
    best = max(range(1, 26), key=lambda k: english_score(_shift(b, k)) + (1 if find_flags(_shift(b, k)) else 0))
    out = _shift(b, best)
    return out if english_score(out) > base + 0.08 or find_flags(out) else None


def d_atbash(b):
    if not _wordlike(b):
        return None
    t = bytes.maketrans(string.ascii_lowercase.encode() + string.ascii_uppercase.encode(),
                        string.ascii_lowercase[::-1].encode() + string.ascii_uppercase[::-1].encode())
    out = b.translate(t)
    return out if english_score(out) > english_score(b) + 0.08 or find_flags(out) else None


def d_reverse(b):
    out = b[::-1]
    return out if len(b) >= 6 and (find_flags(out) and not find_flags(b) or english_score(out) > english_score(b) + 0.15) else None


def d_morse(b):
    toks = re.split(r"[\s/|]+", _txt(b).strip())
    if len(toks) < 3 or not all(re.fullmatch(r"[.-]+", t) for t in toks):
        return None
    out = "".join(MORSE.get(t, "?") for t in toks)
    return out.encode() if out.count("?") <= len(out) // 4 else None


def d_a1z26(b):
    parts = re.split(r"[\s,;-]+", _txt(b).strip())
    if len(parts) < 4 or not all(p.isdigit() and 1 <= int(p) <= 26 for p in parts):
        return None
    return "".join(chr(96 + int(p)) for p in parts).encode()


def d_xor_byte(b):
    if len(b) < 6 or (printable_ratio(b) > 0.9 and english_score(b) > 0.45):
        return None
    best, bk = 0.0, None
    for k in range(1, 256):
        o = bytes(c ^ k for c in b)
        sc = printable_ratio(o) * 0.5 + english_score(o) + (1 if find_flags(o) else 0)
        if sc > best:
            best, bk = sc, k
    if bk is None or best < 1.2:
        return None
    return bytes(c ^ bk for c in b)


def _decomp(fn):
    def run(b):
        if len(b) < 6:
            return None
        out = fn(b)
        return out[:MAX_OUT] if out else None
    return run


def _zlib(b):
    d = zlib.decompressobj(); return d.decompress(b, MAX_OUT)
def _gzip(b):
    if b[:2] != b"\x1f\x8b": return None
    return gzip.GzipFile(fileobj=__import__("io").BytesIO(b)).read(MAX_OUT)
def _bz2(b):
    if b[:3] != b"BZh": return None
    return bz2.BZ2Decompressor().decompress(b, MAX_OUT)
def _lzma(b):
    if b[:6] != b"\xfd7zXZ\x00" and b[:1] != b"\x5d": return None
    return lzma.LZMADecompressor().decompress(b, MAX_OUT)


DECODERS = [("base64", d_base64), ("base64url", d_base64url), ("base32", d_base32), ("base58", d_base58), ("base85", d_base85),
            ("hex", d_hex), ("binary", d_binary), ("decimal bytes", d_decimal), ("URL decode", d_url), ("HTML entities", d_html),
            ("unicode escapes", d_unicode_escape), ("ROT13", d_rot13), ("Caesar (best shift)", d_caesar), ("Atbash", d_atbash),
            ("reverse", d_reverse), ("Morse", d_morse), ("A1Z26", d_a1z26), ("XOR single byte", d_xor_byte),
            ("zlib", _decomp(_zlib)), ("gzip", _decomp(_gzip)), ("bzip2", _decomp(_bz2)), ("lzma/xz", _decomp(_lzma))]


def _looks_compressed(b):
    return b[:2] == b"\x1f\x8b" or b[:3] == b"BZh" or b[:6] == b"\xfd7zXZ\x00" or (len(b) > 2 and b[0] == 0x78 and b[1] in (0x01, 0x5e, 0x9c, 0xda))


def _score(b, prefixes):
    return (100 if find_flags(b, prefixes) else 0) + 10 * english_score(b) + 5 * printable_ratio(b)


def magic(data, prefixes=(), depth=5):
    """Breadth-first search over decoder chains. Returns {"results": [{chain, text, score, flags}], "flags": [...]}."""
    start = data.encode("utf-8", "replace") if isinstance(data, str) else bytes(data)
    start = start[:MAX_OUT]
    seen = {start}
    frontier = [(start, [])]
    found = []
    nodes = 0
    for _ in range(depth):
        nxt = []
        for cur, chain in frontier:
            for name, fn in DECODERS:
                if nodes >= MAX_NODES:
                    break
                try:
                    out = fn(cur)
                except Exception:
                    continue
                if not out or out == cur or out in seen:
                    continue
                seen.add(out); nodes += 1
                ok_text = printable_ratio(out) >= 0.85
                step = chain + [name]
                if ok_text:
                    found.append((_score(out, prefixes), step, out))
                if ok_text or _looks_compressed(out):
                    nxt.append((out, step))
        frontier = nxt
        if not frontier:
            break
    found.sort(key=lambda x: (-x[0], len(x[1])))
    results, flags = [], []
    for sc, chain, out in found:
        fl = find_flags(out, prefixes)
        if not fl and (english_score(out) < 0.3 or (len(out) >= 20 and b" " not in out and entropy(out) > 4.9)):
            continue                                  # unreadable noise is not worth showing
        if len(results) >= 8:
            break
        flags += [f for f in fl if f not in flags]
        results.append({"chain": chain, "text": out.decode("utf-8", "replace")[:4000], "score": round(sc, 1), "flags": fl})
    for f in find_flags(start, prefixes):
        if f not in flags:
            flags.insert(0, f)
    return {"results": results, "flags": flags, "tried": nodes}
