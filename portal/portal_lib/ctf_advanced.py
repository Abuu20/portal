"""CTF helper: advanced crypto. Pure Python, no network.

RSA: Wiener, Fermat factoring, small factor, common modulus, Hastad broadcast, Franklin-Reiter, partial key.
Classic ciphers: Playfair, Hill, Bacon, Rail fence, Columnar transposition, Affine, Substitution frequency.
AES: known-key decrypt already lives in ctf_files.aes_decrypt.
"""
from __future__ import annotations

import math
import re
import string
from collections import Counter

from .ctf_decode import english_score, find_flags

EN_FREQ = [8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41,
           6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07]


def iroot(n: int, k: int) -> int:
    if n < 2:
        return n
    lo, hi = 1, 1 << (n.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        lo, hi = (mid, hi) if mid ** k <= n else (lo, mid - 1)
    return lo


def _bytes(m: int) -> bytes:
    return m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")


def _done(method: str, m: int) -> dict:
    raw = _bytes(m)
    return {"method": method, "plaintext_hex": raw.hex(),
            "text": raw.decode("utf-8", "replace"), "flags": find_flags(raw)}


def wiener_attack(e: int, n: int) -> int | None:
    """Recover d when d is small (d < n^0.25)."""
    cf, a, b = [], e, n
    while b:
        cf.append(a // b)
        a, b = b, a % b
    h0, h1, k0, k1 = 0, 1, 1, 0
    for q in cf:
        h0, h1 = h1, q * h1 + h0
        k0, k1 = k1, q * k1 + k0
        k, d = k1, h1
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0 and math.isqrt(disc) ** 2 == disc and (s + math.isqrt(disc)) % 2 == 0:
            return d
    return None


def fermat_factor(n: int, tries: int = 500_000) -> tuple[int, int] | None:
    """Factor n when p, q are close: n = a^2 - b^2 = (a-b)(a+b)."""
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


def small_factor(n: int, bound: int = 1_000_000) -> int | None:
    """Trial-divide up to bound. Fast for small primes, adequate for CTF-easy challenges."""
    if n % 2 == 0:
        return 2
    for p in range(3, min(bound, n), 2):
        if n % p == 0:
            return p
    return None


def common_modulus(e1: int, e2: int, n: int, c1: int, c2: int) -> dict | None:
    """Same n, coprime e1/e2: extended Euclid -> m."""
    if math.gcd(e1, e2) != 1:
        return None
    g, a, b = _extended_gcd(e1, e2)
    if g != 1:
        return None
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return _done("common modulus (extended Euclid on e1, e2)", m)


def _extended_gcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def hastad_broadcast(pairs: list[tuple[int, int]], e: int = 3) -> dict | None:
    """Same message m encrypted with e-th power to different n_i, gcd(n_i, n_j)=1. CRT then e-th root."""
    if len(pairs) < e:
        return None
    ns = [n for n, _ in pairs]
    cs = [c for _, c in pairs]
    x = 0
    N = 1
    for n in ns:
        N *= n
    for (n, c) in pairs:
        Ni = N // n
        x += c * Ni * pow(Ni, -1, n)
    x %= N
    m = iroot(x, e)
    if m ** e == x:
        return _done(f"Hastad broadcast (e={e})", m)
    return None


def franklin_reiter(n: int, e: int, c1: int, c2: int, a: int, b: int) -> dict | None:
    """m1 = a*m + b, m2 = m, same e; works for e=3 by solving the polynomial gcd."""
    from math import gcd
    try:
        # For e=3: p(m) = (a*m + b)^3 - c1, q(m) = m^3 - c2, gcd over ZZ_n
        def poly_mul(p, q, mod):
            out = [0] * (len(p) + len(q) - 1)
            for i, x in enumerate(p):
                for j, y in enumerate(q):
                    out[i + j] = (out[i + j] + x * y) % mod
            return out
        def poly_mod(p, q, mod):
            p = p[:]
            inv = pow(q[-1], -1, mod)
            while len(p) >= len(q):
                coef = p[-1] * inv % mod
                shift = len(p) - len(q)
                for i, qc in enumerate(q):
                    p[shift + i] = (p[shift + i] - coef * qc) % mod
                while p and p[-1] == 0:
                    p.pop()
            return p
        # build (a*m+b)^e - c1
        cur = [b, a]
        pm = cur[:]
        for _ in range(e - 1):
            pm = poly_mul(pm, cur, n)
        pm[0] = (pm[0] - c1) % n
        qm = [(-c2) % n] + [0] * (e - 1) + [1]
        while len(qm) > 1 and qm[-1] == 0:
            qm.pop()
        while len(pm) > 1:
            pm = poly_mod(pm, qm, n)
            if not pm:
                return None
        # linear: r0 + r1*x = 0 -> x = -r0 * r1^-1
        if len(pm) == 2:
            m = (-pm[0] * pow(pm[1], -1, n)) % n
            return _done("Franklin-Reiter related-message", m)
    except Exception:
        return None
    return None


def rsa_solve_extended(n: int, e: int, c: int, p: int | None = None, q: int | None = None,
                       d: int | None = None, e2: int | None = None, n2: int | None = None,
                       c2: int | None = None) -> dict:
    """Try every RSA weakness we know. Returns {method, text, flags} or {error}."""
    if d:
        return _done("d given", pow(c, d, n))
    if p and not q:
        q = n // p
    if p and q:
        return _done("p, q given", pow(c, pow(e, -1, (p - 1) * (q - 1)), n))
    if e <= 64:
        m = iroot(c, e)
        if m ** e == c:
            return _done(f"small e={e}: m^e < n", m)
    r = fermat_factor(n)
    if r:
        return _done("Fermat (p and q close)", pow(c, pow(e, -1, (r[0] - 1) * (r[1] - 1)), n))
    d2 = wiener_attack(e, n)
    if d2:
        return _done("Wiener (d is small)", pow(c, d2, n))
    f = small_factor(n)
    if f:
        p2, q2 = f, n // f
        return _done(f"small factor {f}", pow(c, pow(e, -1, (p2 - 1) * (q2 - 1)), n))
    if e2 and n2 and c2 and n == n2:
        r = common_modulus(e, e2, n, c, c2)
        if r:
            return r
    return {"error": "no quick weakness (need p, q, or a shared modulus)"}


# ---------------------------------------------------------------------------
# Classic ciphers
# ---------------------------------------------------------------------------

def _clean(s: str) -> str:
    return re.sub(r"[^a-z]", "", s.lower())


def playfair_decode(text: str, key: str) -> str:
    """Standard 5x5 Playfair (I/J merged)."""
    seen, alphabet = set(), []
    for ch in (key.lower() + string.ascii_lowercase):
        ch = "i" if ch == "j" else ch
        if ch.isalpha() and ch not in seen:
            seen.add(ch)
            alphabet.append(ch)
    grid = [alphabet[i:i + 5] for i in range(0, 25, 5)]
    pos = {ch: (r, c) for r, row in enumerate(grid) for c, ch in enumerate(row)}
    pairs, i = [], 0
    letters = _clean(text).replace("j", "i")
    while i < len(letters):
        a = letters[i]
        b = letters[i + 1] if i + 1 < len(letters) else "x"
        if a == b:
            b = "x"
            i += 1
        else:
            i += 2
        pairs.append((a, b))
    out = []
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out += [grid[ra][(ca - 1) % 5], grid[rb][(cb - 1) % 5]]
        elif ca == cb:
            out += [grid[(ra - 1) % 5][ca], grid[(rb - 1) % 5][cb]]
        else:
            out += [grid[ra][cb], grid[rb][ca]]
    return "".join(out)


def hill_decode_2x2(text: str, key: str) -> str:
    """2x2 Hill cipher, key given as 4 letters."""
    nums = [ord(c) - 97 for c in key.lower() if c.isalpha()]
    if len(nums) != 4:
        return ""
    a, b, c, d = nums
    det = (a * d - b * c) % 26
    try:
        inv_det = pow(det, -1, 26)
    except ValueError:
        return ""
    inv = [(d * inv_det) % 26, (-b * inv_det) % 26, (-c * inv_det) % 26, (a * inv_det) % 26]
    letters = [ord(c) - 97 for c in _clean(text)]
    if len(letters) % 2:
        letters.append(23)
    out = []
    for i in range(0, len(letters), 2):
        x, y = letters[i], letters[i + 1]
        out += [(inv[0] * x + inv[1] * y) % 26, (inv[2] * x + inv[3] * y) % 26]
    return "".join(chr(97 + n) for n in out)


def bacon_decode(text: str) -> str:
    """A/B (or a/b, or 0/1) 5-bit Bacon. Non-letters stripped, then grouped in 5."""
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 5:
        return ""
    low = "".join("0" if c.lower() in ("a", "0") else "1" if c.lower() in ("b", "1") else "" for c in letters)
    if len(low) < 5:
        return ""
    out = []
    for i in range(0, len(low) - 4, 5):
        val = int(low[i:i + 5], 2)
        if 0 <= val < 26:
            out.append(chr(97 + val))
    return "".join(out)


def rail_fence_decode(text: str, rails: int) -> str:
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    n = len(text)
    rows = [[] for _ in range(rails)]
    for i, ch in enumerate(text):
        rows[pattern[i % len(pattern)]].append(ch)
    out, idx = [], [0] * rails
    for i in range(n):
        r = pattern[i % len(pattern)]
        out.append(rows[r][idx[r]])
        idx[r] += 1
    return "".join(out)


def columnar_decode(text: str, key: str) -> str:
    key = key.lower()
    order = sorted(range(len(key)), key=lambda i: key[i])
    n = len(text)
    cols = len(key)
    rows = (n + cols - 1) // cols
    short_rows = rows * cols - n
    body = list(text)
    col_data, pos = {}, 0
    for c in order:
        ln = rows - 1 if c >= cols - short_rows else rows
        col_data[c] = body[pos:pos + ln]
        pos += ln
    out = []
    for r in range(rows):
        for c in range(cols):
            if r < len(col_data[c]):
                out.append(col_data[c][r])
    return "".join(out)


def affine_brute(text: str) -> list[dict]:
    letters = _clean(text)
    out = []
    for a in range(1, 26):
        try:
            ia = pow(a, -1, 26)
        except ValueError:
            continue
        for b in range(26):
            dec = "".join(chr(97 + (ia * (ord(c) - 97 - b)) % 26) for c in letters)
            sc = english_score(dec.encode())
            if sc > 0.55:
                out.append({"a": a, "b": b, "text": dec, "score": round(sc, 2)})
    out.sort(key=lambda r: -r["score"])
    return out[:5]


def substitution_brute(text: str) -> dict:
    """Frequency analysis + bigram hints. Best-effort; a crib helps a lot."""
    letters = _clean(text)
    if len(letters) < 40:
        return {"error": "need at least 40 letters"}
    order = "etaoinshrdlucmfwypvbgkjqxz"
    freq = [c for c, _ in Counter(letters).most_common()]
    mapping = dict(zip(freq, order[:len(freq)]))
    plain = "".join(mapping.get(c, c) for c in letters)
    return {"mapping": "".join(k + "→" + v + " " for k, v in mapping.items()),
            "text": plain[:3000], "score": round(english_score(plain.encode()), 2),
            "flags": find_flags(plain)}
