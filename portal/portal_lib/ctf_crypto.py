"""CTF helpers, part 2: classic crypto aids. Everything here is offline maths on data you paste in.

Hash identification, JWT decoding (read only), RSA weak-parameter solvers (small e, p/q given, close primes, Wiener),
Vigenere and repeating-key XOR key recovery.
"""
from __future__ import annotations

import base64
import json
import math
import re

from .ctf_decode import english_score, find_flags, printable_ratio

HASHES = [  # (regex, name, hashcat mode or None)
    (r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", "bcrypt", "3200"), (r"\$6\$[^$]+\$[./A-Za-z0-9]{86}", "sha512crypt", "1800"),
    (r"\$5\$[^$]+\$[./A-Za-z0-9]{43}", "sha256crypt", "7400"), (r"\$1\$[^$]+\$[./A-Za-z0-9]{22}", "md5crypt", "500"),
    (r"\$argon2(id|i|d)\$.+", "Argon2", None), (r"\*[0-9A-Fa-f]{40}", "MySQL 4.1/5", "300"),
    (r"[0-9a-fA-F]{128}", "SHA-512 / Whirlpool", "1700"), (r"[0-9a-fA-F]{96}", "SHA-384", "10800"),
    (r"[0-9a-fA-F]{64}", "SHA-256", "1400"), (r"[0-9a-fA-F]{56}", "SHA-224", "1300"),
    (r"[0-9a-fA-F]{40}", "SHA-1", "100"), (r"[0-9a-fA-F]{32}", "MD5 (or NTLM / MD4)", "0 (MD5) / 1000 (NTLM)"),
    (r"[0-9a-fA-F]{16}", "MySQL 3.x / half-NTLM", "200"), (r"[0-9a-fA-F]{8}", "CRC32 / Adler32", None)]


def identify_hash(s):
    s = s.strip()
    return [{"type": n, "hashcat": m} for rx, n, m in HASHES if re.fullmatch(rx, s)]


def _b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decode_jwt(tok):
    """Decode (never verify or forge) a JWT and point out common weaknesses."""
    parts = tok.strip().split(".")
    if len(parts) not in (2, 3):
        return {"error": "Not a JWT (expected header.payload.signature)"}
    try:
        head, body = json.loads(_b64u(parts[0])), json.loads(_b64u(parts[1]))
    except Exception:
        return {"error": "Header or payload is not valid base64url JSON"}
    notes = []
    alg = str(head.get("alg", ""))
    if alg.lower() == "none" or len(parts) == 2 or not parts[2]:
        notes.append("Unsigned token (alg none / empty signature): the server may accept it without checking.")
    if alg.startswith("HS"):
        notes.append("HMAC-signed: the secret may be guessable with a wordlist (hashcat mode 16500 / john).")
    if alg.startswith("RS") or alg.startswith("ES"):
        notes.append("Asymmetric: check for algorithm-confusion (RS to HS) and a jku / kid / x5u header pointing somewhere you control.")
    for k in ("jku", "x5u", "kid"):
        if k in head:
            notes.append(f"Header has '{k}': {head[k]!r}, which the server uses to find the key.")
    if "exp" not in body:
        notes.append("No expiry (exp) claim.")
    return {"header": head, "payload": body, "signature_b64": parts[2] if len(parts) == 3 else "", "notes": notes,
            "flags": find_flags(json.dumps(body))}


def iroot(n, k):
    """Integer k-th root (floor)."""
    if n < 2:
        return n
    lo, hi = 1, 1 << (n.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        lo, hi = (mid, hi) if mid ** k <= n else (lo, mid - 1)
    return lo


def _bytes(m):
    return m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")


def _fermat(n, tries=300_000):
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(tries):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def _wiener(e, n):
    cf, a, b = [], e, n          # continued fraction of e/n
    while b:
        cf.append(a // b); a, b = b, a % b
    convs, h0, h1, k0, k1 = [], 0, 1, 1, 0
    for q in cf:
        h0, h1 = h1, q * h1 + h0
        k0, k1 = k1, q * k1 + k0
        convs.append((h1, k1))
    for k, d in convs:
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0 and math.isqrt(disc) ** 2 == disc and (s + math.isqrt(disc)) % 2 == 0:
            return d
    return None


def rsa_solve(n, e, c, p=None, q=None, d=None):
    """Try the standard textbook weaknesses. Returns {"method", "plaintext", "text", "flags"} or {"error"}."""
    def done(method, m):
        raw = _bytes(m)
        return {"method": method, "plaintext_hex": raw.hex(), "text": raw.decode("utf-8", "replace"), "flags": find_flags(raw)}
    if d:
        return done("private exponent d given", pow(c, d, n))
    if p and not q:
        q = n // p
    if p and q:
        return done("p and q given", pow(c, pow(e, -1, (p - 1) * (q - 1)), n))
    if e <= 64:                                           # a huge e would make the root computation explode
        m = iroot(c, e)
        if m ** e == c:
            return done(f"small exponent: m^{e} < n, so m is the plain integer root of c", m)
    r = _fermat(n)
    if r:
        p, q = r
        return done("Fermat factoring (p and q are close together)", pow(c, pow(e, -1, (p - 1) * (q - 1)), n))
    dd = _wiener(e, n)
    if dd:
        return done("Wiener attack (d is small)", pow(c, dd, n))
    for sp in range(3, 200_000, 2):                      # small trial division
        if n % sp == 0:
            p, q = sp, n // sp
            return done(f"small factor {sp}", pow(c, pow(e, -1, (p - 1) * (q - 1)), n))
    return {"error": "None of the quick weaknesses worked (small e, close primes, Wiener, small factor). Try factordb.com for n, or look for shared primes across several moduli."}


EN_FREQ = [8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41, 6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06,
           2.76, 0.98, 2.36, 0.15, 1.97, 0.07]


def _chi(col):
    n = len(col)
    return sum((col.count(97 + i) - n * EN_FREQ[i] / 100) ** 2 / (n * EN_FREQ[i] / 100) for i in range(26))


def _col_shift(col):
    """Caesar shift (0..25) of a column of lowercase letters that makes it look most like English (chi-squared)."""
    return min(range(26), key=lambda k: _chi(bytes((c - 97 - k) % 26 + 97 for c in col)))


BIGRAMS = [b'th', b'he', b'in', b'er', b'an', b're', b'nd', b'at', b'on', b'nt', b'ha', b'es', b'st', b'en', b'ed', b'to', b'it', b'ou', b'ea', b'hi']


def vigenere_crack(text, max_key=16):
    letters = bytes(ord(c) for c in text.lower() if "a" <= c <= "z")
    if len(letters) < 40:
        return {"error": "Need at least ~40 letters of ciphertext."}
    def ic(col):
        n = len(col)
        return sum(col.count(x) * (col.count(x) - 1) for x in set(col)) / (n * (n - 1)) if n > 1 else 0
    scores = []
    for L in range(1, max_key + 1):
        scores.append((sum(ic(letters[i::L]) for i in range(L)) / L, L))
    top = max(s for s, _ in scores)
    L = min(l for s, l in scores if s >= top * 0.92)
    cols = [letters[i::L] for i in range(L)]
    ranked = [sorted(range(26), key=lambda k, c=c: _chi(bytes((x - 97 - k) % 26 + 97 for x in c)))[:3] for c in cols]
    key = [r[0] for r in ranked]

    def total(kk):
        pl = bytes((x - 97 - kk[i % L]) % 26 + 97 for i, x in enumerate(letters))
        return sum(pl.count(bg) for bg in BIGRAMS) / len(pl) + 0.5 * english_score(pl[:400])
    for _ in range(2):                                             # refine one column at a time using the whole text
        for i in range(L):
            key[i] = max(ranked[i], key=lambda k: total(key[:i] + [k] + key[i + 1:]))
    out, j = [], 0
    for ch in text:
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            out.append(chr((ord(ch) - base - key[j % L]) % 26 + base)); j += 1
        else:
            out.append(ch)
    plain = "".join(out)
    return {"key": "".join(chr(97 + k) for k in key), "plaintext": plain[:4000], "flags": find_flags(plain)}


def _hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def xor_key_crack(data, max_key=32):
    """Repeating-key XOR (Hamming distance for the key length, then best byte per column)."""
    if len(data) < 40:
        return {"error": "Need at least ~40 bytes."}
    best = []
    for L in range(2, min(max_key, len(data) // 4) + 1):
        blocks = [data[i * L:(i + 1) * L] for i in range(min(8, len(data) // L))]
        pairs = [(blocks[i], blocks[i + 1]) for i in range(len(blocks) - 1)]
        if pairs:
            best.append((sum(_hamming(a, b) for a, b in pairs) / len(pairs) / L, L))
    best.sort()
    picks = []
    for _, L in best[:6]:                                          # multiples of the true length score alike, so try divisors too
        for dv in [L] + [d for d in range(2, L) if L % d == 0]:
            if dv not in picks:
                picks.append(dv)
    out = []
    for L in picks:
        key = bytearray()
        for i in range(L):
            col = data[i::L]
            key.append(max(range(256), key=lambda k: printable_ratio(bytes(c ^ k for c in col)) + english_score(bytes(c ^ k for c in col))))
        plain = bytes(c ^ key[i % L] for i, c in enumerate(data))
        out.append({"key_len": L, "key_hex": key.hex(), "key_ascii": "".join(chr(k) if 32 <= k < 127 else "." for k in key),
                    "plaintext": plain.decode("utf-8", "replace")[:4000], "flags": find_flags(plain),
                    "score": round(printable_ratio(plain) + english_score(plain), 2)})
    out.sort(key=lambda r: (-r["score"], r["key_len"]))
    return {"candidates": out[:4]}
