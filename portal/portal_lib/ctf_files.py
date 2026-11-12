"""CTF helper: file-level analysis and decryption.

Handles the common 'suspicious file' challenges:
- OpenSSL salted blobs (``Salted__``) with password attempts
- Password-protected ZIP files (common wordlist / given password)
- PDF encryption checks and password attempts
- Single-byte XOR detection (known plaintext / common patterns)
- AES with a given key/IV (CBC, CTR, ECB, GCM)
- Base64/hex/gzip wrapped files (recursive unwrap)
- Known wrapper patterns (git objects, PCAP-in-PNG, etc.)
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import io
import re
import struct
import zipfile

from .ctf_decode import find_flags, magic
from .ctf_crypto import _bytes

MAX_READ = 64 * 1024 * 1024

# A short default wordlist for the most common CTF passwords. Bigger lists come from disk.
COMMON_PASSWORDS = [
    b"", b"password", b"123456", b"admin", b"flag", b"ctf", b"secret", b"root", b"toor",
    b"letmein", b"qwerty", b"abc123", b"p@ssw0rd", b"changeme", b"rockyou", b"1234",
    b"12345", b"12345678", b"123456789", b"admin123", b"root123", b"password1",
    b"password123", b"welcome", b"monkey", b"dragon", b"master", b"sunshine",
    b"123123", b"football", b"iloveyou", b"trustno1", b"letmein123", b"P@ssw0rd",
    b"P@ssw0rd!", b"Password1!", b"Passw0rd", b"test", b"testing", b"ctf2024",
    b"ctf2025", b"ctf2026", b"hackthebox", b"htb", b"tryhackme", b"thm", b"picoctf",
    b"flag{", b"letmein", b"openme", b"unlock", b"open", b"key", b"backup",
]

# Wordlist locations to auto-load from disk (first that exists wins).
WORDLIST_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "/usr/share/wordlists/dirb/common.txt",
]


def load_wordlist(limit: int = 200_000) -> list[bytes]:
    """Return up to `limit` lines from the first wordlist found on disk, plus COMMON_PASSWORDS."""
    words = list(COMMON_PASSWORDS)
    for p in WORDLIST_PATHS:
        try:
            with open(p, "rb") as f:
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    w = line.rstrip(b"\r\n")
                    if w and w not in words:
                        words.append(w)
            break
        except OSError:
            continue
    return words


# ---------------------------------------------------------------------------
# OpenSSL Salted__
# ---------------------------------------------------------------------------

def is_openssl_salted(data: bytes) -> bool:
    return data[:8] == b"Salted__" and len(data) > 16


def _openssl_key_iv(password: bytes, salt: bytes, key_len: int, iv_len: int) -> tuple[bytes, bytes]:
    """EVP_BytesToKey with MD5, one round (the historical default)."""
    out, prev = b"", b""
    while len(out) < key_len + iv_len:
        prev = hashlib.md5(prev + password + salt).digest()
        out += prev
    return out[:key_len], out[key_len:key_len + iv_len]


def openssl_decrypt(data: bytes, password: bytes, cipher: str = "aes-256-cbc"):
    """Return (plaintext, cipher_used) or None. ciphers: aes-{128,192,256}-{cbc,ecb,ctr,gcm} and des-ede3-cbc."""
    if not is_openssl_salted(data):
        return None
    salt, body = data[8:16], data[16:]
    m = re.match(r"(aes)-(\d+)-(cbc|ecb|ctr|gcm)", cipher)
    if m:
        key_len = int(m.group(2)) // 8
        mode = m.group(3).upper()
        iv_len = 0 if mode == "ECB" else (12 if mode == "GCM" else 16)
        key, iv = _openssl_key_iv(password, salt, key_len, iv_len)
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            if mode == "GCM":
                return AESGCM(key).decrypt(iv, body, None), cipher
            ci = Cipher(algorithms.AES(key), getattr(modes, mode)(iv))
            dec = ci.decryptor()
            return dec.update(body) + dec.finalize(), cipher
        except Exception:
            return None
    if cipher == "des-ede3-cbc":
        key, iv = _openssl_key_iv(password, salt, 24, 8)
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            ci = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
            dec = ci.decryptor()
            return dec.update(body) + dec.finalize(), cipher
        except Exception:
            return None
    return None


def try_openssl(data: bytes, words: list[bytes]):
    """Try each word + cipher. Return first plaintext that looks printable or has a flag."""
    if not is_openssl_salted(data):
        return []
    hits = []
    for pw in words[:5000]:
        for cipher in ("aes-256-cbc", "aes-128-cbc", "aes-256-ctr", "aes-128-ctr", "aes-256-ecb"):
            r = openssl_decrypt(data, pw, cipher)
            if not r:
                continue
            pt = r[0]
            if not pt:
                continue
            # filter: >= 85% printable OR a flag
            printable = sum(1 for b in pt[:4000] if 32 <= b < 127 or b in (9, 10, 13)) / max(1, len(pt[:4000]))
            flags = find_flags(pt)
            if printable > 0.85 or flags:
                hits.append({"password": pw.decode("latin-1"), "cipher": r[1],
                             "preview": pt[:400].decode("utf-8", "replace"), "flags": flags,
                             "size": len(pt)})
                if flags:
                    return hits
    return hits


# ---------------------------------------------------------------------------
# ZIP passwords
# ---------------------------------------------------------------------------

def is_encrypted_zip(path: str) -> bool:
    try:
        with zipfile.ZipFile(path) as z:
            return any(i.flag_bits & 0x1 for i in z.infolist())
    except Exception:
        return False


def crack_zip(path: str, words: list[bytes], limit: int = 200_000) -> dict:
    """Try passwords from the wordlist. Returns {password, files, flags} or {tried, error}."""
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if not any(i.flag_bits & 0x1 for i in z.infolist()):
                return {"error": "zip is not encrypted"}
            target = next((n for n in names if not n.endswith("/")), None)
            if not target:
                return {"error": "no files in zip"}
            tried = 0
            for pw in words[:limit]:
                tried += 1
                try:
                    with z.open(target, pwd=pw) as f:
                        body = f.read(4 * 1024 * 1024)
                except Exception:
                    continue
                flags = find_flags(body)
                return {"password": pw.decode("latin-1"), "files": names[:20],
                        "preview": body[:400].decode("utf-8", "replace"), "flags": flags,
                        "tried": tried}
            return {"error": f"password not found after {tried} attempts", "tried": tried, "files": names[:20]}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# PDF passwords
# ---------------------------------------------------------------------------

def is_encrypted_pdf(head: bytes) -> bool:
    return head.startswith(b"%PDF") and b"/Encrypt" in head[:65536]


def try_pdf_password(path: str, words: list[bytes]) -> dict:
    try:
        from pypdf import PdfReader
    except ImportError:
        return {"error": "install pypdf (pip install pypdf) to try PDF passwords"}
    try:
        r = PdfReader(path)
        if not r.is_encrypted:
            return {"error": "PDF is not encrypted"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    for pw in words[:20000]:
        try:
            rr = PdfReader(path)
            if rr.decrypt(pw):
                text = ""
                for page in rr.pages[:5]:
                    try:
                        text += page.extract_text() or ""
                    except Exception:
                        pass
                return {"password": pw.decode("latin-1"), "text": text[:4000],
                        "flags": find_flags(text.encode("utf-8", "replace"))}
        except Exception:
            continue
    return {"error": "password not found in wordlist"}


# ---------------------------------------------------------------------------
# XOR detection
# ---------------------------------------------------------------------------

def xor_with_key(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_known_plaintext_detect(data: bytes, known: bytes) -> dict | None:
    """Recover a repeating XOR key from a known plaintext prefix (CTF staple: 'flag{' or 'CTF{')."""
    n = min(len(known), len(data))
    if n < 4:
        return None
    key = bytes(data[i] ^ known[i] for i in range(n))
    # detect the period
    for L in range(1, n + 1):
        if all(key[i] == key[i % L] for i in range(n)):
            real = key[:L]
            dec = xor_with_key(data, real)
            return {"key_hex": real.hex(), "key_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in real),
                    "plaintext": dec[:2000].decode("utf-8", "replace"), "flags": find_flags(dec)}
    return None


def xor_brute_keylen(data: bytes, max_keylen: int = 32) -> list[dict]:
    """Return the best XOR key candidates ranked by English-ness of the plaintext."""
    from .ctf_crypto import xor_key_crack
    r = xor_key_crack(data[:20000], max_key=max_keylen)
    return r.get("candidates", [])


# ---------------------------------------------------------------------------
# AES with given key/IV
# ---------------------------------------------------------------------------

def aes_decrypt(data: bytes, key: bytes, iv: bytes = b"", mode: str = "cbc") -> bytes | None:
    """mode: cbc, ctr, ecb, gcm. Returns None on failure (bad length, missing dep)."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        mode = mode.lower()
        if mode == "gcm":
            return AESGCM(key).decrypt(iv, data, None)
        m = {"cbc": modes.CBC, "ctr": modes.CTR, "ecb": modes.ECB}[mode]
        ci = Cipher(algorithms.AES(key), m(iv) if mode != "ecb" else m())
        d = ci.decryptor()
        return d.update(data) + d.finalize()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Recursive unwrap (base64 → gzip → ...)
# ---------------------------------------------------------------------------

def unwrap(data: bytes, depth: int = 4) -> list[dict]:
    """Try base64/hex/gzip/zlib unwrapping, chaining. Returns [{steps, preview, flags, size}]."""
    out = []
    seen = {data}
    frontier = [([], data)]
    for _ in range(depth):
        nxt = []
        for chain, cur in frontier:
            tries = []
            if cur[:6] == b"\xfd7zXZ\x00" or cur[:2] == b"\x1f\x8b" or cur[:3] == b"BZh":
                r = magic(cur)
                for item in r.get("results", [])[:1]:
                    tries.append(("decompress", cur))
            c = re.sub(rb"\s+", b"", cur)
            if re.fullmatch(rb"[A-Za-z0-9+/=]{16,}", c):
                try:
                    d = base64.b64decode(c + b"=" * (-len(c) % 4))
                    if d not in seen:
                        tries.append(("base64", d))
                except Exception:
                    pass
            c2 = re.sub(rb"[\s:,-]|0x", b"", cur)
            if re.fullmatch(rb"[0-9a-fA-F]{16,}", c2) and len(c2) % 2 == 0:
                try:
                    d = bytes.fromhex(c2.decode())
                    if d not in seen:
                        tries.append(("hex", d))
                except Exception:
                    pass
            for name, nxt_bytes in tries:
                if nxt_bytes in seen or len(nxt_bytes) > MAX_READ:
                    continue
                seen.add(nxt_bytes)
                step = chain + [name]
                preview = nxt_bytes[:400].decode("utf-8", "replace")
                flags = find_flags(nxt_bytes)
                if flags or sum(1 for b in nxt_bytes[:400] if 32 <= b < 127) / max(1, len(nxt_bytes[:400])) > 0.85:
                    out.append({"steps": step, "preview": preview, "flags": flags, "size": len(nxt_bytes)})
                nxt.append((step, nxt_bytes))
        frontier = nxt
        if not frontier:
            break
    return out


# ---------------------------------------------------------------------------
# Main entry — called from ctf_triage.py on every dropped file
# ---------------------------------------------------------------------------

def analyze_file(path: str, name: str, head: bytes, size: int) -> dict | None:
    """Return a dict of findings or None if the file is not a decryptable/wrapped CTF file."""
    with open(path, "rb") as f:
        data = f.read(MAX_READ)
    rows, flags, hints = [], [], []
    words = load_wordlist()

    # 1) OpenSSL salted
    if is_openssl_salted(data):
        hits = try_openssl(data, words)
        if hits:
            for h in hits[:3]:
                rows.append(("OpenSSL decrypted", f"password={h['password']} cipher={h['cipher']} · {h['size']} bytes", "ok"))
                flags += h["flags"]
                rows.append(("Preview", h["preview"].replace("\n", " ")[:200], None))
        else:
            hints.append("OpenSSL Salted__ detected: no password matched the built-in wordlist. Try: openssl enc -d -aes-256-cbc -in file -pass pass:XXX")

    # 2) ZIP
    if zipfile.is_zipfile(path) and is_encrypted_zip(path):
        r = crack_zip(path, words, limit=50000)
        if "password" in r:
            rows.append(("ZIP password", r["password"], "ok"))
            rows.append(("ZIP contents", ", ".join(r["files"]), None))
            flags += r["flags"]
        else:
            hints.append(f"ZIP is encrypted ({r.get('error', '?')}). Install a bigger wordlist or try: john --wordlist=rockyou.txt hash.")

    # 3) PDF
    if is_encrypted_pdf(head):
        r = try_pdf_password(path, words)
        if "password" in r:
            rows.append(("PDF password", r["password"], "ok"))
            flags += r.get("flags", [])
            if r.get("text"):
                rows.append(("PDF text", r["text"][:300], None))
        else:
            hints.append(f"PDF is encrypted ({r.get('error', '?')}). Use qpdf --password=XXX --decrypt in.pdf out.pdf")

    # 4) XOR
    if not any((is_openssl_salted(data), zipfile.is_zipfile(path) and is_encrypted_zip(path), is_encrypted_pdf(head))):
        for known in (b"flag{", b"CTF{", b"HTB{", b"picoCTF{", b"<?xml", b"PK\x03\x04"):
            r = xor_known_plaintext_detect(data, known)
            if r:
                rows.append((f"XOR key (known prefix {known.decode('latin-1')})", r["key_ascii"], "ok"))
                rows.append(("XOR preview", r["plaintext"][:300], None))
                flags += r["flags"]
                break
        else:
            cands = xor_brute_keylen(data)
            for c in cands[:2]:
                rows.append((f"XOR key candidate (len {c['key_len']})", f"{c['key_ascii']}  preview: {c['plaintext'][:120]}", "warn"))
                flags += c.get("flags", [])

    # 5) Recursive unwrap
    for u in unwrap(data)[:3]:
        rows.append((f"Unwrapped via {' → '.join(u['steps'])}", u["preview"].replace("\n", " ")[:200], None))
        flags += u["flags"]

    if not rows and not flags:
        return None
    return {"rows": rows, "flags": flags, "hints": hints[:8]}
