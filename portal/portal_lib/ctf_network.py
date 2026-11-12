"""CTF helper: PCAP / network traffic analysis. Static; nothing leaves the machine.

Uses scapy if installed for stream reassembly; a raw fallback extracts HTTP bodies,
DNS queries, and files carved from TCP payloads without any dependency.
"""
from __future__ import annotations

import re

from .ctf_decode import find_flags

HTTP_HOST = re.compile(rb"(?im)^Host:\s*(\S+)")
HTTP_URI = re.compile(rb"(?im)^(?:GET|POST|PUT|HEAD|DELETE)\s+(\S+)")
PNG = b"\x89PNG\r\n\x1a\n"
JPEG = b"\xff\xd8\xff"
PDF = b"%PDF-"
ZIP = b"PK\x03\x04"
GZIP = b"\x1f\x8b\x08"


def analyze(data: bytes) -> dict:
    rows, flags, hints = [], [], []
    # sanity: is this actually a pcap?
    magic = data[:4]
    is_pcap = magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    is_pcapng = magic == b"\x0a\x0d\x0d\x0a"
    if not (is_pcap or is_pcapng):
        return {}

    tmp_path = None
    try:
        from scapy.all import rdpcap, DNS, DNSQR, Raw, TCP, UDP
        tmp_path = _path_of(data)
        packets = rdpcap(tmp_path)
        rows.append(("Packets", str(len(packets)), None))
        hosts, dns_q, uris, streams = set(), [], set(), {}
        for pkt in packets:
            if pkt.haslayer(DNSQR):
                q = pkt[DNSQR].qname
                if isinstance(q, bytes):
                    dns_q.append(q.decode("latin-1", "replace").rstrip("."))
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                tcp = pkt[TCP]
                payload = bytes(pkt[Raw])
                if tcp.dport in (80, 8080):
                    m = HTTP_HOST.search(payload)
                    if m:
                        hosts.add(m.group(1).decode("latin-1"))
                    m = HTTP_URI.search(payload)
                    if m:
                        uris.add(m.group(1).decode("latin-1"))
                key = (pkt["IP"].src, tcp.sport, pkt["IP"].dst, tcp.dport)
                streams.setdefault(key, bytearray()).extend(payload)
        if dns_q:
            rows.append(("DNS queries", ", ".join(dict.fromkeys(dns_q))[:300], None))
        if hosts:
            rows.append(("HTTP hosts", ", ".join(sorted(hosts))[:300], None))
        if uris:
            rows.append(("HTTP URIs", ", ".join(sorted(uris)[:20])[:400], None))
        # extract files from streams
        carved = _carve_from_streams(streams)
        for name, body in carved[:6]:
            rows.append((f"Carved {name}", f"{len(body)} bytes from TCP stream", "ok"))
            flags += find_flags(body)
    except ImportError:
        rows.append(("scapy", "not installed (pip install scapy) — using raw fallback", "warn"))
    except Exception as e:
        rows.append(("parse error", f"{type(e).__name__}: {e}", "warn"))
    finally:
        if tmp_path:
            import os as _os
            try:
                _os.unlink(tmp_path)
            except OSError:
                pass

    # raw fallback: just carve common file magic from raw bytes
    for magic, name in ((PNG, "PNG"), (JPEG, "JPEG"), (PDF, "PDF"), (ZIP, "ZIP"), (GZIP, "gzip")):
        i = data.find(magic)
        if i >= 0:
            rows.append((f"Raw {name} signature", f"at offset {i}", "warn"))
    flags += find_flags(data[:5_000_000])

    hints.append("For deeper analysis: tshark -r capture.pcap -Y http -T fields -e http.file_data | xxd")
    hints.append("Extract HTTP objects: tshark -r capture.pcap --export-objects http,out_dir")
    return {"rows": rows, "flags": flags, "hints": hints}


def _path_of(data: bytes) -> str:
    import tempfile
    f = tempfile.NamedTemporaryFile(prefix="portal_pcap_", suffix=".pcap", delete=False)
    f.write(data)
    f.close()
    return f.name


def _carve_from_streams(streams: dict) -> list[tuple[str, bytes]]:
    out = []
    for key, payload in streams.items():
        data = bytes(payload)
        for magic, name in ((PNG, "png"), (JPEG, "jpg"), (PDF, "pdf"), (ZIP, "zip"), (GZIP, "gz")):
            i = data.find(magic)
            if i >= 0:
                out.append((name, data[i:i + 4 * 1024 * 1024]))
                break
    return out
