"""CTF helper: reverse-engineering assistants. Static; the binary is never run.

Uses capstone (if installed) for disassembly, angr (if installed) for symbolic execution,
and pattern-matches common CTF binary shapes (flag check, xor compare, strcmp chains).
"""
from __future__ import annotations

import hashlib
import re
import struct

from .ctf_decode import find_flags

# Strings an RE challenge usually contains near the flag check
HINT_STRINGS = [
    (rb"(?i)congrat", "congratulation message: likely the success path"),
    (rb"(?i)wrong|incorrect|nope|try again", "failure message: path is nearby"),
    (rb"(?i)flag|ctf", "flag-related string"),
    (rb"(?i)enter (the )?(flag|password)", "input prompt"),
    (rb"(?i)usage", "usage message: near main()"),
]

RISKY_C = {"gets", "strcpy", "strcat", "sprintf", "system", "popen", "execve", "ptrace", "mprotect"}
KEY_COMPARE = {"strcmp", "strncmp", "memcmp", "strcasecmp", "__isoc99_scanf", "scanf"}


def analyze(path: str, data: bytes) -> dict:
    rows, hints, flags = [], [], []
    is_elf = data[:4] == b"\x7fELF"
    is_pe = data[:2] == b"MZ"

    # strings worth showing
    for pattern, why in HINT_STRINGS:
        for m in re.finditer(pattern, data):
            s = data[m.start():m.start() + 80].split(b"\x00")[0]
            try:
                txt = s.decode("utf-8", "replace")
            except Exception:
                continue
            if 4 < len(txt) < 120:
                rows.append(("String hint", f"{why}: {txt}", "warn"))
            if len(rows) > 15:
                break
        if len(rows) > 15:
            break

    # imports: risky / comparison functions
    imports = _elf_imports(data) if is_elf else _pe_imports(data) if is_pe else set()
    if KEY_COMPARE & imports:
        rows.append(("Key comparison", ", ".join(sorted(KEY_COMPARE & imports)) + " — the flag is compared to user input", "warn"))
    risky = RISKY_C & imports
    if risky:
        rows.append(("Risky imports", ", ".join(sorted(risky)), "warn"))

    # hashes for reference
    rows.append(("MD5", hashlib.md5(data).hexdigest(), None))
    rows.append(("SHA-256", hashlib.sha256(data).hexdigest(), None))

    # capstone disassembly (first 60 instructions of .text / entry)
    dis = _disassemble_entry(data)
    if dis:
        rows.append(("Disassembly (first 60 instructions)", "", None))
        for addr, mnemonic, ops in dis:
            rows.append((f"0x{addr:x}", f"{mnemonic} {ops}".strip(), None))

    # angr availability (heavy; only tell the user how to use it)
    try:
        import angr  # noqa: F401
        hints.append("angr is installed. Script: `p = angr.Project('binary'); s = p.factory.entry_state(); "
                     "sm = p.factory.simulation_manager(s); sm.explore(find=0xADDR, avoid=0xBADDR)` — "
                     "use the success-message address as `find`.")
    except ImportError:
        hints.append("Install angr (pip install angr) for symbolic execution: it finds the input that reaches "
                     "a chosen 'success' address without you having to read the assembly.")

    # flags embedded in the binary
    flags += find_flags(data)

    if not rows:
        return {}
    return {"rows": rows, "flags": flags, "hints": hints}


def _elf_imports(data: bytes) -> set[str]:
    out = set()
    for name in ("gets", "strcpy", "strcat", "sprintf", "system", "popen", "execve", "ptrace",
                 "mprotect", "strcmp", "strncmp", "memcmp", "strcasecmp", "scanf", "__isoc99_scanf"):
        if name.encode() in data:
            out.add(name)
    return out


def _pe_imports(data: bytes) -> set[str]:
    out = set()
    for name in ("VirtualAlloc", "VirtualProtect", "IsDebuggerPresent", "GetProcAddress",
                 "LoadLibraryA", "LoadLibraryW", "CreateProcessA", "WinExec", "ShellExecuteA",
                 "lstrcmpA", "lstrcmpW", "memcmp"):
        if name.encode() in data:
            out.add(name)
    return out


def _disassemble_entry(data: bytes) -> list[tuple[int, str, str]]:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
        from capstone import CS_ARCH_ARM, CS_MODE_ARM
    except ImportError:
        return []
    try:
        if data[:4] == b"\x7fELF":
            is64 = data[4] == 2
            e = "<" if data[5] == 1 else ">"
            if is64:
                entry = struct.unpack(e + "Q", data[24:32])[0]
            else:
                entry = struct.unpack(e + "I", data[24:28])[0]
            # find .text — do a cheap scan for the code that follows the ELF header
            cs = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
            # For the entry, just disassemble the first 60 instructions from a likely location
            start = _find_text_offset(data)
            code = data[start:start + 2000]
            out = []
            for ins in cs.disasm(code, entry):
                out.append((ins.address, ins.mnemonic, ins.op_str))
                if len(out) >= 60:
                    break
            return out
    except Exception:
        return []
    return []


def _find_text_offset(data: bytes) -> int:
    """Heuristic: ELF section header string table is followed by .text; pick a safe offset."""
    # search for the section name ".text\0"
    i = data.find(b".text\x00")
    if i < 0:
        return 0x1000 if len(data) > 0x1000 else 0
    # section header table entries: look for the .text section header (offset 0x18 / 0x20)
    # rather than parse it exactly, use the marker after the section-name table
    return min(len(data), i + 0x1000)
