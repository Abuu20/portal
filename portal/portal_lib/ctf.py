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
