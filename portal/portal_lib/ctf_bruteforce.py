"""CTF helper: brute force. Offline, no network.

- Hash cracking against wordlist + common transforms (leetspeak, case, suffix, reverse)
- Hash chains (e.g. "MD5(SHA1(x))")
- Numeric / PIN brute force
- Mask attack (hashcat-style "flag{?l?l?l?l}")
"""
from __future__ import annotations

import hashlib
import itertools
import re
import string


def _ntlm(pw: bytes) -> str:
    try:
        import hashlib as h
        return h.new("md4", pw.decode("utf-16-le").encode("utf-16-le")).hexdigest()
    except Exception:
        try:
            import Crypto.Hash.MD4 as M
            return M.new(pw.decode("utf-16-le").encode("utf-16-le")).hexdigest()
        except Exception:
            return ""


ALGOS = {
    "md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256,
    "sha512": hashlib.sha512, "sha224": hashlib.sha224, "sha384": hashlib.sha384,
    "ntlm": _ntlm,
}


def detect_hash_algos(h: str) -> list[str]:
    h = h.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", h):
        return []
    return {16: ["mysql"], 32: ["md5", "ntlm"], 40: ["sha1"], 56: ["sha224"],
            64: ["sha256"], 96: ["sha384"], 128: ["sha512"]}.get(len(h), [])


def _rule_variants(pw: bytes):
    yield pw
    yield pw.lower()
    yield pw.upper()
    yield pw.capitalize()
    yield pw[::-1]
    for suf in (b"1", b"123", b"!", b"2024", b"2025", b"2026", b"01", b"007"):
        yield pw + suf
    for pre in (b"!", b"@", b" "):
        yield pre + pw
    # leetspeak
    yield (pw.replace(b"a", b"4").replace(b"e", b"3").replace(b"i", b"1")
             .replace(b"o", b"0").replace(b"s", b"5").replace(b"t", b"7"))


def crack_hash(target_hex: str, words: list[bytes], algos: list[str] | None = None,
               limit: int = 200_000, transforms: bool = True) -> dict:
    target_hex = target_hex.strip().lower()
    algos = algos or detect_hash_algos(target_hex) or ["md5", "sha1", "sha256"]
    funcs = [(a, ALGOS[a]) for a in algos if a in ALGOS]
    tried = 0
    for pw in words[:limit]:
        tried += 1
        for name, fn in funcs:
            if fn(pw) == target_hex:
                return {"password": pw.decode("latin-1"), "algo": name, "tried": tried}
    if transforms:
        for pw in words[:50000]:
            for v in _rule_variants(pw):
                tried += 1
                for name, fn in funcs:
                    if fn(v) == target_hex:
                        return {"password": v.decode("latin-1"), "algo": name,
                                "tried": tried, "rule": "transform"}
    return {"error": f"not found after {tried} attempts", "tried": tried, "algos": algos}


def crack_hash_chain(target_hex: str, chain: list[str], words: list[bytes],
                     limit: int = 100_000) -> dict:
    target_hex = target_hex.strip().lower()
    for pw in words[:limit]:
        cur = pw
        for a in chain:
            fn = ALGOS.get(a)
            if not fn:
                return {"error": f"unknown algorithm {a}"}
            cur = bytes.fromhex(fn(cur))
        if cur.hex() == target_hex:
            return {"password": pw.decode("latin-1"), "chain": chain}
    return {"error": "not found", "chain": chain}


def pin_bruteforce(target: str, digits: int = 4, hash_algo: str | None = None) -> dict:
    if digits > 8:
        return {"error": "refusing > 8 digits (10^8 attempts)"}
    fn = ALGOS.get(hash_algo) if hash_algo else None
    target = target.strip().lower()
    for i in range(10 ** digits):
        code = str(i).zfill(digits).encode()
        if fn:
            if fn(code) == target:
                return {"pin": code.decode(), "tried": i + 1}
        elif code.decode() == target:
            return {"pin": code.decode(), "tried": i + 1}
    return {"error": "not found"}


MASK_CHARS = {"?d": string.digits, "?l": string.ascii_lowercase, "?u": string.ascii_uppercase,
              "?a": string.ascii_letters + string.digits,
              "?s": "!@#$%^&*()-_=+[]{};:,.<>/?",
              "?h": "0123456789abcdef"}


def mask_bruteforce(mask: str, target_hex: str, hash_algo: str, limit: int = 500_000) -> dict:
    """hashcat-style mask: 'flag{?l?l?l?l}'. Capped at limit attempts."""
    target_hex = target_hex.strip().lower()
    fn = ALGOS.get(hash_algo)
    if not fn:
        return {"error": f"unknown hash {hash_algo}"}
    parts, i, n = [], 0, len(mask)
    while i < n:
        if mask[i] == "?" and i + 1 < n and mask[i:i + 2] in MASK_CHARS:
            parts.append(MASK_CHARS[mask[i:i + 2]])
            i += 2
        else:
            parts.append(mask[i])
            i += 1
    total = 1
    for p in parts:
        total *= len(p) if isinstance(p, str) and len(p) > 1 else 1
    if total > limit:
        return {"error": f"mask would try {total:,} combinations (limit {limit:,})"}
    tried = 0
    for combo in itertools.product(*[list(p) if isinstance(p, str) and len(p) > 1 else [p] for p in parts]):
        tried += 1
        cand = "".join(combo).encode()
        if fn(cand) == target_hex:
            return {"password": cand.decode("latin-1"), "tried": tried}
    return {"error": f"not found after {tried:,} attempts"}
