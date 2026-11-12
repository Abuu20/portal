"""CTF helper: decode anything. Single-step decoders plus a bounded search that chains them.

Pure Python, offline, deterministic. Every decoder takes bytes and returns bytes (or None when it does not apply).
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import time
import urllib.parse
import zlib
import gzip

MAX_BYTES = 200_000
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MORSE = {".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K",
         ".-..": "L", "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U", "...-": "V",
         ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5",
         "-....": "6", "--...": "7", "---..": "8", "----.": "9"}
COMMON = "etaoin shrdlu"
FLAG_WORDS = (b"flag", b"ctf", b"htb", b"thm", b"pico")


def _txt(b):
    try:
        return b.decode("ascii")
    except UnicodeDecodeError:
        return None


def _compact(s):
    return re.sub(r"\s+", "", s)


def d_base64(b):
    s = _txt(b)
    if not s or not re.fullmatch(r"[A-Za-z0-9+/=_\-\s]{8,}", s):
        return None
    c = _compact(s).replace("-", "+").replace("_", "/")
    c += "=" * (-len(c) % 4)
    try:
        return base64.b64decode(c, validate=True)
    except (binascii.Error, ValueError):
        return None


def d_base32(b):
    s = _txt(b)
    if not s or not re.fullmatch(r"[A-Za-z2-7=\s]{8,}", s):
        return None
    c = _compact(s).upper()
    c += "=" * (-len(c) % 8)
    try:
        return base64.b32decode(c)
    except (binascii.Error, ValueError):
        return None


def d_hex(b):
    s = _txt(b)
    if not s:
        return None
    c = re.sub(r"(?i)0x|\\x|[\s:,-]", "", s)
    if len(c) < 4 or len(c) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", c):
        return None
    return bytes.fromhex(c)


def d_binary(b):
    s = _txt(b)
    if not s:
        return None
    c = _compact(s)
    if len(c) < 8 or len(c) % 8 or not re.fullmatch(r"[01]+", c):
        return None
    return bytes(int(c[i:i + 8], 2) for i in range(0, len(c), 8))


def d_decimal(b):
    s = _txt(b)
    if not s or not re.fullmatch(r"\s*\d{1,3}([\s,]+\d{1,3}){2,}\s*", s):
        return None
    nums = [int(x) for x in re.split(r"[\s,]+", s.strip())]
    return bytes(nums) if all(n < 256 for n in nums) else None


def d_octal(b):
    s = _txt(b)
    if not s or not re.fullmatch(r"\s*[0-7]{2,3}([\s,]+[0-7]{2,3}){2,}\s*", s):
        return None
    nums = [int(x, 8) for x in re.split(r"[\s,]+", s.strip())]
    return bytes(nums) if all(n < 256 for n in nums) else None


def d_base58(b):
    s = _txt(b)
    if not s or len(s) < 6 or any(c not in B58 for c in s):
        return None
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + out


def d_base85(b):
    s = _txt(b)
    if not s or len(s) < 8:
        return None
    for fn in (base64.b85decode, base64.a85decode):
        try:
            return fn(s.strip())
        except (ValueError, binascii.Error):
            continue
    return None


def d_url(b):
    s = _txt(b)
    if not s or "%" not in s:
        return None
    return urllib.parse.unquote_to_bytes(s)


def d_html(b):
    s = _txt(b)
    if not s or "&" not in s or not re.search(r"&#?\w+;", s):
        return None
    return html.unescape(s).encode("utf-8", "replace")


def d_escapes(b):
    s = _txt(b)
    if not s or not re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", s):
        return None
    try:
        return s.encode("latin-1", "ignore").decode("unicode_escape").encode("utf-8", "replace")
    except Exception:
        return None


def d_morse(b):
    s = _txt(b)
    if not s or not re.fullmatch(r"[.\-/ \n]{5,}", s.strip()):
        return None
    words = re.split(r"\s*/\s*|\s{3,}", s.strip())
    out = [" ".join("") for _ in ()]
    res = []
    for w in words:
        letters = [MORSE.get(x) for x in w.split()]
        if any(x is None for x in letters):
            return None
        res.append("".join(letters))
    return " ".join(res).encode()


def d_reverse(b):
    return b[::-1] if len(b) >= 4 else None


def d_rot13(b):
    s = _txt(b)
    return codecs.encode(s, "rot13").encode() if s else None


def d_atbash(b):
    s = _txt(b)
    if not s:
        return None
    return s.translate(str.maketrans("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA")).encode()


def d_zlib(b):
    for fn in (zlib.decompress, lambda x: zlib.decompress(x, -15), gzip.decompress):
        try:
            d = zlib.decompressobj().decompress(b, MAX_BYTES) if fn is zlib.decompress else fn(b)
            return d[:MAX_BYTES]
        except Exception:
            continue
    return None


def d_qp(b):
    s = _txt(b)
    if not s or not re.search(r"=[0-9A-F]{2}", s):
        return None
    import quopri
    return quopri.decodestring(s.encode())


DECODERS = {"base64": d_base64, "base32": d_base32, "hex": d_hex, "binary": d_binary, "decimal bytes": d_decimal, "octal bytes": d_octal,
            "base58": d_base58, "base85": d_base85, "URL encoding": d_url, "HTML entities": d_html, "\\u / \\x escapes": d_escapes,
            "morse": d_morse, "reverse": d_reverse, "ROT13": d_rot13, "Atbash": d_atbash, "zlib / gzip": d_zlib, "quoted-printable": d_qp}


def caesar(s, k):
    return "".join(chr((ord(c) - 65 + k) % 26 + 65) if "A" <= c <= "Z" else chr((ord(c) - 97 + k) % 26 + 97) if "a" <= c <= "z" else c for c in s)


def score(b):
    """How much does this look like intended plaintext? 0..1 (flag-looking text scores highest)."""
    if not b:
        return 0.0
    sample = b[:2000]
    printable = sum(1 for x in sample if 32 <= x < 127 or x in (9, 10, 13)) / len(sample)
    if printable < 0.85:
        return printable * 0.3
    low = sample.lower()
    letters = sum(1 for x in low if 97 <= x <= 122 or x == 32)
    eng = sum(low.count(ord(c)) for c in COMMON) / max(len(low), 1)
    s = 0.45 * printable + 0.25 * (letters / len(sample)) + 0.3 * min(eng * 2.2, 1)
    if any(w in low for w in FLAG_WORDS) and b"{" in sample:
        s += 0.4
    return min(s, 1.0)


def xor_single(b):
    """Best single-byte XOR keys (for non-text input)."""
    best = []
    for k in range(1, 256):
        out = bytes(x ^ k for x in b[:4000])
        best.append((score(out), k))
    best.sort(reverse=True)
    return [(sc, k, bytes(x ^ k for x in b[:MAX_BYTES])) for sc, k in best[:2] if sc > 0.62]


def vigenere_decrypt(text, key):
    out, i = [], 0
    for c in text:
        if c.isalpha():
            k = ord(key[i % len(key)].lower()) - 97
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c) - base - k) % 26 + base))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def vigenere_crack(text, max_key=12):
    """Guess key by shifting each column to English letter frequency (needs a few hundred letters)."""
    letters = [c.lower() for c in text if c.isalpha()]
    if len(letters) < 40:
        return None
    freq = dict(zip("etaoinshrdlcumwfgypbvkjxqz", [12.7, 9.1, 8.2, 7.5, 7.0, 6.7, 6.3, 6.1, 6.0, 4.3, 4.0, 2.8, 2.8, 2.4, 2.4, 2.2, 2.0, 2.0, 1.9, 1.5, 1.0, 0.8, 0.15, 0.15, 0.1, 0.07]))
    best = None
    for n in range(2, max_key + 1):
        key = ""
        for col in range(n):
            chunk = letters[col::n]
            if not chunk:
                break
            sc = []
            for shift in range(26):
                sc.append((sum(freq.get(chr((ord(c) - 97 - shift) % 26 + 97), 0) for c in chunk) / len(chunk), shift))
            key += chr(max(sc)[1] + 97)
        plain = vigenere_decrypt(text, key)
        q = score(plain.encode())
        if best is None or q > best[0] + 0.02:           # prefer the shortest key that reads well
            best = (q, key, plain)
    return best if best and best[0] > 0.7 else None


def search(data, depth=4, budget=2.5, beam=40):
    """Chain decoders. Returns candidates [{chain, output, score}] best first (not including the untouched input)."""
    t0 = time.time()
    seen = {data}
    frontier = [([], data)]
    found = []
    for _ in range(depth):
        nxt = []
        for chain, cur in frontier:
            if time.time() - t0 > budget:
                break
            steps = list(DECODERS.items())
            if (_txt(cur) or "") and len(cur) < 5000:
                s = cur.decode("ascii")
                if re.search(r"[A-Za-z]{6,}", s):
                    best = max(range(1, 26), key=lambda k: score(caesar(s, k).encode()))
                    if score(caesar(s, best).encode()) > score(cur) + 0.1:
                        steps.append((f"Caesar +{best}", lambda x, k=best: caesar(x.decode("ascii"), k).encode()))
            for name, fn in steps:
                try:
                    out = fn(cur)
                except Exception:
                    out = None
                if not out or out in seen or len(out) > MAX_BYTES:
                    continue
                seen.add(out)
                item = (chain + [name], out)
                nxt.append(item)
                found.append({"chain": item[0], "output": out, "score": score(out)})
        nxt.sort(key=lambda it: -score(it[1]))
        frontier = nxt[:beam]
        if not frontier:
            break
    for sc, k, out in xor_single(data) if not _txt(data) or score(data) < 0.5 else []:
        found.append({"chain": [f"XOR 0x{k:02x}"], "output": out, "score": sc})
    found.sort(key=lambda c: (-c["score"], len(c["chain"])))
    return found
