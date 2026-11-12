"""CTF helpers, part 4: static triage of ELF and PE executables for reverse-engineering challenges.

Parses headers with struct only (no execution, no disassembly): architecture, protections (NX, PIE, RELRO, canary),
sections with entropy (packer hints), imported functions flagged by risk, and what the binary was probably built with.
"""
from __future__ import annotations

import struct

from .ctf_decode import entropy

RISKY_C = {"gets": "unbounded read: classic buffer overflow", "strcpy": "no length check", "strcat": "no length check",
           "sprintf": "no length check / format string", "vsprintf": "no length check", "scanf": "%s without width overflows",
           "system": "runs a shell command", "popen": "runs a shell command", "execve": "starts a program", "execl": "starts a program",
           "ptrace": "anti-debug or tracing", "mprotect": "changes memory permissions (shellcode / unpacking)", "dlopen": "loads code at runtime",
           "memcpy": "check the length argument", "read": "check the size against the buffer", "printf": "format string if the format is user input",
           "fopen": "reads or writes files", "strcmp": "password / key comparison: look at the arguments", "strncmp": "password / key comparison",
           "rand": "predictable if seeded with time()", "srand": "seed: is it time(NULL)?", "ptrace": "anti-debug", "fork": "child process"}
RISKY_WIN = {"VirtualAlloc": "allocates memory (unpacking / shellcode)", "VirtualProtect": "changes memory permissions", "WriteProcessMemory": "process injection",
             "CreateRemoteThread": "process injection", "IsDebuggerPresent": "anti-debug", "CheckRemoteDebuggerPresent": "anti-debug",
             "LoadLibraryA": "loads DLLs at runtime", "LoadLibraryW": "loads DLLs at runtime", "GetProcAddress": "resolves APIs at runtime (hides imports)",
             "URLDownloadToFileA": "downloads a file", "URLDownloadToFileW": "downloads a file", "InternetOpenA": "network access", "InternetOpenUrlA": "network access",
             "WinExec": "runs a command", "ShellExecuteA": "runs a command", "ShellExecuteW": "runs a command", "CreateProcessA": "starts a program",
             "CreateProcessW": "starts a program", "RegSetValueExA": "persistence (registry)", "RegSetValueExW": "persistence (registry)",
             "CryptEncrypt": "encryption", "CryptDecrypt": "decryption", "SetWindowsHookExA": "keylogging / hooking", "GetAsyncKeyState": "keylogging",
             "NtUnmapViewOfSection": "process hollowing", "OpenProcess": "touches another process", "GetTickCount": "timing check (anti-debug)"}
ELF_MACHINE = {3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V", 21: "PowerPC64", 22: "S390"}
PE_MACHINE = {0x14c: "x86", 0x8664: "x86-64", 0x1c0: "ARM", 0xaa64: "ARM64", 0x1c4: "ARM Thumb-2"}
HINT_STRINGS = [(b"UPX!", "Packed with UPX: try `upx -d file`"), (b"Go build ID", "Go binary: symbols are kept, look for main.* functions in Ghidra"),
                (b"_MEIPASS", "PyInstaller bundle: extract with pyinstxtractor, then decompile the .pyc"), (b"PyInstaller", "PyInstaller bundle"),
                (b"Rust", "Rust binary (probably): long mangled symbol names"), (b"mono-", "Mono / .NET runtime"),
                (b"This program cannot be run in DOS mode", "Windows PE image")]


def _cstr(buf, off):
    end = buf.find(b"\0", off)
    return buf[off:end if end >= 0 else len(buf)].decode("latin-1")


def elf_triage(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    e = "<" if data[5] == 1 else ">"
    et, mach = struct.unpack(e + "HH", data[16:20])
    if is64:
        entry, phoff, shoff = struct.unpack(e + "QQQ", data[24:48])
        phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack(e + "HHHHH", data[54:64])
    else:
        entry, phoff, shoff = struct.unpack(e + "III", data[24:36])
        phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack(e + "HHHHH", data[42:52])
    rows = [("Format", f"ELF {64 if is64 else 32}-bit {'little' if e == '<' else 'big'}-endian · {ELF_MACHINE.get(mach, hex(mach))}", None),
            ("Type", {2: "EXEC (fixed address)", 3: "DYN (PIE or shared library)"}.get(et, str(et)), None), ("Entry point", hex(entry), None)]
    nx, relro, bindnow, canary = None, False, False, False
    interp = ""
    for i in range(min(phnum, 64)):
        o = phoff + i * phentsize
        if o + phentsize > len(data):
            break
        if is64:
            pt, fl, off, _, _, fsz, _, _ = struct.unpack(e + "IIQQQQQQ", data[o:o + 56])
        else:
            pt, off, _, _, fsz, _, fl, _ = struct.unpack(e + "IIIIIIII", data[o:o + 32])
        if pt == 0x6474e551:
            nx = not (fl & 1)
        elif pt == 0x6474e552:
            relro = True
        elif pt == 3:
            interp = _cstr(data, off)
    secs, imports, has_symtab = [], [], False
    names_off = None
    heads = []
    for i in range(min(shnum, 96)):
        o = shoff + i * shentsize
        if o + shentsize > len(data):
            break
        if is64:
            nm, tp, fl, addr, off, sz, link, info, al, es = struct.unpack(e + "IIQQQQIIQQ", data[o:o + 64])
        else:
            nm, tp, fl, addr, off, sz, link, info, al, es = struct.unpack(e + "IIIIIIIIII", data[o:o + 40])
        heads.append((nm, tp, fl, addr, off, sz, link, es))
    if heads and shstrndx < len(heads):
        names_off = heads[shstrndx][4]
    sec_names = {}
    for idx, (nm, tp, fl, addr, off, sz, link, es) in enumerate(heads):
        name = _cstr(data, names_off + nm) if names_off is not None else ""
        sec_names[idx] = name
        if tp in (1, 7, 8, 14, 15) or name.startswith("."):
            body = data[off:off + min(sz, 2_000_000)] if tp != 8 else b""
            if name in (".text", ".data", ".rodata", ".rdata", ".bss", ".init_array", ".got", ".got.plt", ".plt") or entropy(body) > 7.2 and sz > 512:
                secs.append((name, sz, entropy(body) if body else 0.0, fl))
        if tp == 2:
            has_symtab = True
        if tp in (2, 11):                                  # symtab / dynsym
            strtab = heads[link][4] if link < len(heads) else 0
            entsz = es or (24 if is64 else 16)
            for k in range(min(sz // entsz, 5000)):
                so = off + k * entsz
                if so + entsz > len(data):
                    break
                if is64:
                    sn, info, _, shndx = struct.unpack(e + "IBBH", data[so:so + 8])
                else:
                    sn, _, _, info, _, shndx = struct.unpack(e + "IIIBBH", data[so:so + 16])
                nme = _cstr(data, strtab + sn)
                if nme and tp == 11 and shndx == 0:
                    imports.append(nme.split("@")[0])
                if nme == "__stack_chk_fail" or nme == "__stack_chk_fail_local":
                    canary = True
    # Full RELRO needs BIND_NOW; the dynamic section flag is checked cheaply on the raw bytes (DT_FLAGS_1 / DF_BIND_NOW)
    if b"BIND_NOW" in data[:2_000_000] or b"\x1e\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00" in data[:2_000_000]:
        bindnow = True
    prot = [("NX (non-executable stack)", "yes" if nx else "NO: shellcode on the stack can run" if nx is not None else "unknown", None if nx else "warn"),
            ("PIE (random base address)", "yes" if et == 3 else "NO: fixed addresses, easier to exploit", None if et == 3 else "warn"),
            ("RELRO", ("full" if bindnow else "partial") if relro else "NO: GOT is writable", None if relro else "warn"),
            ("Stack canary", "yes" if canary else "NO: plain stack overflows are possible", None if canary else "warn"),
            ("Symbols", "kept (functions are named)" if has_symtab else "stripped (functions have no names)", None)]
    if interp:
        rows.append(("Interpreter", interp, None))
    return {"rows": rows + prot, "sections": secs, "imports": imports, "risky": RISKY_C, "hints": [] if has_symtab else ["Stripped: start from the entry point and from strings that are printed or compared."]}


def _rva2off(rva, secs):
    for va, vsz, raw, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return rva - va + raw
    return None


def pe_triage(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe = struct.unpack("<I", data[0x3c:0x40])[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        return None
    mach, nsec, ts, _, _, osz, chars = struct.unpack("<HHIIIHH", data[pe + 4:pe + 24])
    opt = pe + 24
    magic_ = struct.unpack("<H", data[opt:opt + 2])[0]
    is64 = magic_ == 0x20b
    entry = struct.unpack("<I", data[opt + 16:opt + 20])[0]
    dll_chars = struct.unpack("<H", data[opt + 70:opt + 72])[0]
    dd = opt + (112 if is64 else 96)
    dirs = [struct.unpack("<II", data[dd + 8 * i:dd + 8 * i + 8]) for i in range(min(16, (osz - (dd - opt)) // 8)) if dd + 8 * i + 8 <= len(data)]
    sec_off = opt + osz
    secs, out_secs = [], []
    for i in range(min(nsec, 40)):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        nm = data[o:o + 8].rstrip(b"\0").decode("latin-1")
        vsz, va, rsz, raw, _, _, _, _, fl = struct.unpack("<IIIIIIHHI", data[o + 8:o + 40])
        secs.append((va, vsz, raw, rsz))
        ent = entropy(data[raw:raw + min(rsz, 2_000_000)])
        out_secs.append((nm, rsz, ent, fl))
    imports = []
    if len(dirs) > 1 and dirs[1][0]:
        o = _rva2off(dirs[1][0], secs)
        while o is not None and o + 20 <= len(data) and len(imports) < 400:
            ot, _, _, nm_rva, _ = struct.unpack("<IIIII", data[o:o + 20])
            if not nm_rva:
                break
            dll = _cstr(data, _rva2off(nm_rva, secs) or 0)
            tbl = _rva2off(ot, secs) if ot else None
            step = 8 if is64 else 4
            while tbl is not None and tbl + step <= len(data) and len(imports) < 400:
                v = int.from_bytes(data[tbl:tbl + step], "little")
                if not v:
                    break
                if not v >> (step * 8 - 1):
                    no = _rva2off(v, secs)
                    if no is not None:
                        imports.append(_cstr(data, no + 2))
                tbl += step
            o += 20
    dotnet = len(dirs) > 14 and dirs[14][0] != 0
    rows = [("Format", f"PE {'64' if is64 else '32'}-bit · {PE_MACHINE.get(mach, hex(mach))} · {'DLL' if chars & 0x2000 else 'EXE'}" + (" · .NET assembly" if dotnet else ""), None),
            ("Compile timestamp", __import__("datetime").datetime.fromtimestamp(ts, __import__("datetime").timezone.utc).strftime("%Y-%m-%d %H:%M UTC") + " (can be forged)", None),
            ("Entry point (RVA)", hex(entry), None),
            ("ASLR", "yes" if dll_chars & 0x40 else "NO", None if dll_chars & 0x40 else "warn"),
            ("DEP / NX", "yes" if dll_chars & 0x100 else "NO", None if dll_chars & 0x100 else "warn")]
    hints = ["This is a .NET assembly: open it in dnSpy or ILSpy to get near-original C# source."] if dotnet else []
    return {"rows": rows, "sections": out_secs, "imports": imports, "risky": RISKY_WIN, "hints": hints}


def triage(path):
    with open(path, "rb") as f:
        data = f.read(48 * 1024 * 1024)
    t = elf_triage(data) if data[:4] == b"\x7fELF" else pe_triage(data) if data[:2] == b"MZ" else None
    if not t:
        return None
    rows = list(t["rows"])
    for nm, sz, ent, fl in t["sections"][:10]:
        tone = "warn" if ent > 7.2 else None
        rows.append((f"Section {nm or '(unnamed)'}", f"{sz:,} bytes · entropy {ent:.2f}" + (" · looks packed / encrypted" if ent > 7.2 else ""), tone))
    risky = [(n, t["risky"][n]) for n in dict.fromkeys(t["imports"]) if n in t["risky"]]
    for n, why in risky[:14]:
        rows.append((f"Imports {n}", why, "warn"))
    rest = [n for n in dict.fromkeys(t["imports"]) if n not in t["risky"]]
    if rest:
        rows.append((f"Other imports ({len(rest)})", ", ".join(rest[:30]) + (" …" if len(rest) > 30 else ""), None))
    hints = list(t["hints"])
    for sig, msg in HINT_STRINGS:
        if sig in data[:8_000_000] and msg not in hints and not msg.startswith("Windows PE"):
            hints.append(msg)
    hints.append("Next: open in Ghidra / radare2 / IDA Free; run `strings -n 8`, `ltrace` / `strace` if you may run it (in a VM only).")
    return {"rows": rows, "hints": hints}
