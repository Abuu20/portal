"""CTF workbench API: thin JSON wrappers around the offline helpers in ctf_decode.py and ctf_crypto.py.

Everything here works on text you paste in; nothing is fetched and nothing touches a target.
"""
from __future__ import annotations

import base64
import binascii
import re

from flask import jsonify, request

from .core import app
from .ctf_crypto import decode_jwt, identify_hash, rsa_solve, vigenere_crack, xor_key_crack
from .ctf_decode import find_flags, magic

MAX_TEXT = 200_000


def _prefixes(j):
    return [p for p in re.split(r"[\s,]+", str(j.get("prefix", ""))) if p][:10]


def _int(v, name, required=True):
    v = str(v or "").strip().replace(" ", "")
    if not v:
        if required:
            raise ValueError(f"{name} is required")
        return None
    n = int(v, 16) if v.lower().startswith("0x") else int(v)
    if n.bit_length() > 8192:
        raise ValueError(f"{name} is too large (limit 8192 bits)")
    return n


def _raw(j):
    t = str(j.get("text", ""))
    enc = j.get("encoding", "text")
    if enc == "hex":
        return binascii.unhexlify(re.sub(r"[\s:]|0x", "", t))
    if enc == "base64":
        return base64.b64decode(t + "=" * (-len(t) % 4))
    return t.encode("utf-8", "replace")


@app.post("/api/ctf/<tool>")
def api_ctf(tool):
    j = request.get_json(silent=True) or {}
    text = str(j.get("text", ""))
    if len(text) > MAX_TEXT:
        return jsonify(error="Input too large (limit 200,000 characters)"), 413
    try:
        if tool == "magic":
            return jsonify(magic(text, _prefixes(j)))
        if tool == "flags":
            return jsonify(flags=find_flags(text, _prefixes(j)))
        if tool == "hash":
            return jsonify(matches=identify_hash(text))
        if tool == "jwt":
            return jsonify(decode_jwt(text))
        if tool == "rsa":
            return jsonify(rsa_solve(_int(j.get("n"), "n"), _int(j.get("e") or "65537", "e"), _int(j.get("c"), "c"),
                                     _int(j.get("p"), "p", False), _int(j.get("q"), "q", False), _int(j.get("d"), "d", False)))
        if tool == "vigenere":
            return jsonify(vigenere_crack(text))
        if tool == "xorkey":
            return jsonify(xor_key_crack(_raw(j)))
    except (ValueError, binascii.Error) as e:
        return jsonify(error=f"Bad input: {e}"), 400
    except ZeroDivisionError:
        return jsonify(error="Bad input: the numbers are inconsistent (check n, e, c, p, q)"), 400
    return jsonify(error="Unknown tool"), 404

from .ctf_advanced import (
    affine_brute, bacon_decode, columnar_decode, common_modulus, fermat_factor,
    franklin_reiter, hastad_broadcast, hill_decode_2x2, playfair_decode,
    rail_fence_decode, rsa_solve_extended, small_factor, substitution_brute, wiener_attack,
)
from .ctf_bruteforce import crack_hash, crack_hash_chain, detect_hash_algos, mask_bruteforce, pin_bruteforce
from .ctf_files import crack_zip, load_wordlist, openssl_decrypt, try_openssl
from .ctf_network import analyze as pcap_analyze


@app.post("/api/ctf/crack")
def api_crack():
    j = request.get_json(silent=True) or {}
    h = str(j.get("hash", "")).strip()
    if not h:
        return jsonify(error="Provide a hash"), 400
    words = load_wordlist(limit=int(j.get("limit") or 200_000))
    r = crack_hash(h, words, algos=j.get("algos"), limit=int(j.get("limit") or 200_000))
    return jsonify(r)


@app.post("/api/ctf/crack-chain")
def api_crack_chain():
    j = request.get_json(silent=True) or {}
    r = crack_hash_chain(str(j.get("hash", "")), list(j.get("chain") or []), load_wordlist())
    return jsonify(r)


@app.post("/api/ctf/pin")
def api_pin():
    j = request.get_json(silent=True) or {}
    return jsonify(pin_bruteforce(str(j.get("target", "")), int(j.get("digits") or 4), j.get("algo")))


@app.post("/api/ctf/mask")
def api_mask():
    j = request.get_json(silent=True) or {}
    return jsonify(mask_bruteforce(str(j.get("mask", "")), str(j.get("hash", "")),
                                    str(j.get("algo", "md5")), int(j.get("limit") or 500_000)))


def _rsa_int(j, key, required=True):
    v = j.get(key)
    if v in (None, ""):
        if required:
            raise KeyError(key)
        return None
    n = int(str(v), 0)
    if n.bit_length() > 8192:
        raise ValueError(f"{key} is too large (limit 8192 bits)")
    return n


@app.post("/api/ctf/rsa-advanced")
def api_rsa_advanced():
    j = request.get_json(silent=True) or {}
    try:
        return jsonify(rsa_solve_extended(
            _rsa_int(j, "n"), _rsa_int(j, "e"), _rsa_int(j, "c"),
            p=_rsa_int(j, "p", False), q=_rsa_int(j, "q", False), d=_rsa_int(j, "d", False),
            e2=_rsa_int(j, "e2", False), n2=_rsa_int(j, "n2", False), c2=_rsa_int(j, "c2", False),
        ))
    except (KeyError, ValueError) as ex:
        return jsonify(error=f"bad input: {ex}"), 400


@app.post("/api/ctf/classic/<cipher>")
def api_classic(cipher):
    j = request.get_json(silent=True) or {}
    text = str(j.get("text", ""))
    key = str(j.get("key", ""))
    if cipher == "playfair":
        return jsonify(text=playfair_decode(text, key))
    if cipher == "hill":
        return jsonify(text=hill_decode_2x2(text, key))
    if cipher == "bacon":
        return jsonify(text=bacon_decode(text))
    if cipher == "railfence":
        return jsonify(text=rail_fence_decode(text, int(j.get("rails") or 3)))
    if cipher == "columnar":
        return jsonify(text=columnar_decode(text, key))
    if cipher == "affine":
        return jsonify(candidates=affine_brute(text))
    if cipher == "substitution":
        return jsonify(substitution_brute(text))
    return jsonify(error="unknown cipher"), 404


@app.post("/api/ctf/openssl")
def api_openssl():
    j = request.get_json(silent=True) or {}
    import binascii
    data = binascii.unhexlify(j.get("data_hex", "")) if j.get("data_hex") else base64.b64decode(j.get("data_b64", ""))
    words = load_wordlist() if not j.get("password") else [str(j["password"]).encode()]
    hits = try_openssl(data, words)
    return jsonify(hits=hits)


@app.post("/api/ctf/pcap")
def api_pcap():
    j = request.get_json(silent=True) or {}
    import binascii
    data = binascii.unhexlify(j.get("data_hex", "")) if j.get("data_hex") else base64.b64decode(j.get("data_b64", ""))
    return jsonify(pcap_analyze(data))
