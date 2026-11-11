"""Local file analysis (type, hashes, EXIF/media metadata), the image-URL lookup and /api/file."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
from flask import jsonify, request
from urllib.parse import urlparse

from .core import ExifTags, HAVE_PIL, Image, ImageOps, R, app, chip, fetch_chain, row

MAGIC = [
    (b"\xff\xd8\xff", "JPEG image"), (b"\x89PNG\r\n\x1a\n", "PNG image"), (b"GIF8", "GIF image"),
    (b"%PDF", "PDF document"), (b"PK\x03\x04", "ZIP container (zip / docx / xlsx / apk / jar)"),
    (b"\x7fELF", "ELF executable"), (b"MZ", "Windows PE executable"), (b"Rar!", "RAR archive"),
    (b"\x1f\x8b", "gzip data"), (b"7z\xbc\xaf", "7-Zip archive"), (b"ID3", "MP3 audio"), (b"OggS", "Ogg container"),
    (b"\x1aE\xdf\xa3", "Matroska / WebM"), (b"SQLite format 3", "SQLite database"), (b"#!", "Script (shebang)"),
    (b"RIFF", "RIFF container (WAV / AVI / WebP)"),
]

def identify(head):
    if head[4:8] == b"ftyp":
        return "ISO media (MP4 / MOV / HEIC family)"
    for sig, name in MAGIC:
        if head.startswith(sig):
            return name
    return "unknown"

def _hashes(path):
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            for x in h.values():
                x.update(blk)
    return {k: v.hexdigest() for k, v in h.items()}

def _clean(v):
    if hasattr(v, "numerator") and hasattr(v, "denominator"):
        try:
            return round(float(v), 4)
        except Exception:
            return str(v)
    if isinstance(v, bytes):
        s = v.decode("utf-8", "replace").strip("\x00 ")
        return s[:200] if s.isprintable() else f"<{len(v)} bytes>"
    if isinstance(v, (tuple, list)):
        return [_clean(x) for x in v][:8]
    return str(v)[:300]

def _dms(v, ref):
    d, m, s = [float(x) for x in v]
    dec = d + m / 60 + s / 3600
    return -dec if str(ref).upper() in ("S", "W") else dec

EDITORS = re.compile(r"photoshop|lightroom|gimp|canva|snapseed|pixelmator|affinity|paint\.net|picsart|facetune", re.I)

AI_KEYS = ("parameters", "prompt", "workflow", "invokeai_metadata", "sd-metadata", "dream")

def _analyze_image(path, name, size, hashes):
    Image.MAX_IMAGE_PIXELS = 200_000_000
    with open(path, "rb") as f:
        raw = f.read(4_000_000)
    with Image.open(path) as im:
        fmt, (w, h) = im.format, im.size
        info = dict(im.info)
        exif = im.getexif()
        ifd0 = {ExifTags.TAGS.get(k, str(k)): v for k, v in exif.items()}
        try:
            exif_ifd = {ExifTags.TAGS.get(k, str(k)): v for k, v in exif.get_ifd(0x8769).items()}
        except Exception:
            exif_ifd = {}
        try:
            gps = {ExifTags.GPSTAGS.get(k, str(k)): v for k, v in exif.get_ifd(0x8825).items()}
        except Exception:
            gps = {}
        frames = getattr(im, "n_frames", 1)
        try:
            t = ImageOps.exif_transpose(im)
        except Exception:
            t = im.copy()
        t.thumbnail((520, 520))
        if t.mode not in ("RGB", "L"):
            t = t.convert("RGB")
        buf = io.BytesIO()
        t.save(buf, "JPEG", quality=80)
        thumb = "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()

    lat = lon = None
    try:
        if "GPSLatitude" in gps and "GPSLongitude" in gps:
            lat = _dms(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
            lon = _dms(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                lat = lon = None
    except Exception:
        lat = lon = None

    xmp_m = re.search(rb"<x:xmpmeta.*?</x:xmpmeta>", raw, re.S)
    xmp = xmp_m.group(0).decode("utf-8", "replace") if xmp_m else ""

    def xmp_val(tag):
        m = re.search(rf"{tag}=\"([^\"]+)\"|<{tag}>([^<]+)</{tag}>", xmp)
        return (m.group(1) or m.group(2)) if m else None

    creator_tool = xmp_val("xmp:CreatorTool")
    software = ifd0.get("Software") or creator_tool
    c2pa = b"c2pa" in raw or b"jumbf" in raw
    text_chunks = {k: v for k, v in info.items() if isinstance(v, str) and k.lower() not in ("exif", "icc_profile", "xmp") and not k.startswith("XML")}
    ai = [k for k in text_chunks if k.lower() in AI_KEYS]

    def pick(d, *keys):
        for k in keys:
            if d.get(k) not in (None, "", b""):
                return _clean(d[k])
        return None

    cam_rows = [row("Make", pick(ifd0, "Make")), row("Model", pick(ifd0, "Model")), row("Lens", pick(exif_ifd, "LensModel")),
                row("Captured", pick(exif_ifd, "DateTimeOriginal") or pick(ifd0, "DateTime")),
                row("Exposure (s)", pick(exif_ifd, "ExposureTime")), row("Aperture f/", pick(exif_ifd, "FNumber")),
                row("ISO", pick(exif_ifd, "ISOSpeedRatings", "PhotographicSensitivity")),
                row("Focal length (mm)", pick(exif_ifd, "FocalLength"))]
    cam_rows = [r for r in cam_rows if r[1] not in ("", "None")]
    soft_rows = [row("Software", software), row("Host computer", pick(ifd0, "HostComputer")),
                 row("XMP created", xmp_val("xmp:CreateDate")), row("XMP modified", xmp_val("xmp:ModifyDate"))]
    soft_rows = [r for r in soft_rows if r[1] not in ("", "None")]
    gps_rows = []
    if lat is not None:
        gps_rows = [row("Latitude", f"{lat:.6f}", "warn"), row("Longitude", f"{lon:.6f}", "warn")]
        for k in ("GPSAltitude", "GPSDateStamp", "GPSImgDirection", "GPSSpeed"):
            if k in gps:
                gps_rows.append(row(k.replace("GPS", ""), _clean(gps[k])))
    used = {"Make", "Model", "Software", "HostComputer", "DateTime"}
    other = [row(k, _clean(v)) for k, v in {**ifd0, **exif_ifd}.items() if k not in used and not isinstance(v, bytes) and k not in ("MakerNote", "PrintImageMatching")][:30]
    text_rows = [row(k, v[:300]) for k, v in text_chunks.items()][:10]
    file_rows = [row("Name", name), row("Format", f"{fmt} · {w}×{h}" + (f" · {frames} frames" if frames > 1 else "")),
                 row("Size", f"{size:,} bytes"), row("MD5", hashes["md5"]), row("SHA-1", hashes["sha1"]), row("SHA-256", hashes["sha256"])]

    chips = [chip("Image", f"{fmt} {w}×{h}", "info")]
    model = " ".join(x for x in (pick(ifd0, "Make"), pick(ifd0, "Model")) if x)
    if model:
        chips.append(chip("Device", model, "info"))
    if pick(exif_ifd, "DateTimeOriginal"):
        chips.append(chip("Captured", pick(exif_ifd, "DateTimeOriginal"), "info"))
    if lat is not None:
        chips.append(chip("GPS embedded", f"{lat:.5f}, {lon:.5f}", "warn"))
    if not ifd0 and not exif_ifd and not gps:
        chips.append(chip("No EXIF", "likely stripped", "info"))
    if software and EDITORS.search(str(software)):
        chips.append(chip("Edited", str(software), "warn"))
    if ai:
        chips.append(chip("AI-generation metadata", ", ".join(ai), "warn"))
    if c2pa:
        chips.append(chip("Content Credentials (C2PA)", "marker found", "ok"))

    sections = [{"title": t, "rows": r} for t, r in (("File", file_rows), ("Camera & capture", cam_rows), ("Software", soft_rows), ("GPS", gps_rows), ("Embedded text", text_rows), ("Other EXIF", other)) if r]
    pivots = []
    if lat is not None:
        pivots.append({"module": "coords", "q": f"{lat:.6f}, {lon:.6f}", "label": "GPS → location", "auto": True})
    return R("Image analysis", "▣", highlights=chips, image=thumb, sections=sections, pivots=pivots,
             links=[{"label": "VirusTotal (by hash)", "url": f"https://www.virustotal.com/gui/file/{hashes['sha256']}"}],
             note="Metadata shows how and where a file was made, not where it was posted. Social platforms usually strip EXIF, so missing metadata is normal.")

def _parse_iso6709(s):
    m = re.match(r"^\s*([+-]\d{1,3}(?:\.\d+)?)([+-]\d{1,3}(?:\.\d+)?)", str(s))
    if not m:
        return None
    lat, lon = float(m.group(1)), float(m.group(2))
    return (lat, lon) if -90 <= lat <= 90 and -180 <= lon <= 180 else None

def _analyze_media(path, name, size, hashes):
    p = subprocess.run(["ffprobe", "-v", "error", "-print_format", "json", "-show_format", "-show_streams", path], capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        return None
    j = json.loads(p.stdout or "{}")
    fmt, streams = j.get("format", {}), j.get("streams", [])
    if not streams:
        return None
    vs = next((s for s in streams if s.get("codec_type") == "video"), None)
    au = next((s for s in streams if s.get("codec_type") == "audio"), None)
    tags = {k.lower(): v for k, v in (fmt.get("tags") or {}).items()}
    for s in streams:
        for k, v in (s.get("tags") or {}).items():
            tags.setdefault(k.lower(), v)
    dur = float(fmt.get("duration") or 0)
    geo = None
    for k, v in tags.items():
        if "location" in k or "iso6709" in k:
            geo = _parse_iso6709(v)
            if geo:
                break

    def first(*keys):
        for k in keys:
            if tags.get(k):
                return tags[k]
        return None

    make = first("com.apple.quicktime.make", "make", "com.android.manufacturer")
    model = first("com.apple.quicktime.model", "model", "com.android.model")
    encoder = first("encoder", "com.apple.quicktime.software", "software")
    created = first("creation_time", "com.apple.quicktime.creationdate")
    kind = "Video" if vs else "Audio"
    chips = [chip(kind, fmt.get("format_long_name", fmt.get("format_name", "?")).split(",")[0], "info"),
             chip("Duration", f"{int(dur // 60)}:{int(dur % 60):02d}", "info")]
    if vs:
        chips.append(chip("Resolution", f"{vs.get('width')}×{vs.get('height')}", "info"))
    if make or model:
        chips.append(chip("Device", " ".join(x for x in (make, model) if x), "info"))
    if created:
        chips.append(chip("Created", str(created)[:19], "info"))
    if geo:
        chips.append(chip("GPS embedded", f"{geo[0]:.5f}, {geo[1]:.5f}", "warn"))
    if encoder and re.search(r"lavf|lavc|ffmpeg|handbrake", str(encoder), re.I):
        chips.append(chip("Re-encoded", str(encoder), "warn"))

    def fps(s):
        try:
            a, b = str(s.get("r_frame_rate", "0/1")).split("/")
            return round(float(a) / float(b), 2) if float(b) else None
        except Exception:
            return None

    rows = [row("Name", name), row("Container", fmt.get("format_long_name")), row("Size", f"{size:,} bytes"),
            row("Duration", f"{dur:.2f} s"), row("Bitrate", f"{int(fmt.get('bit_rate') or 0) // 1000} kb/s"),
            row("MD5", hashes["md5"]), row("SHA-1", hashes["sha1"]), row("SHA-256", hashes["sha256"])]
    srows = []
    if vs:
        srows += [row("Video codec", vs.get("codec_name")), row("Frame rate", fps(vs)), row("Pixel format", vs.get("pix_fmt"))]
    if au:
        srows += [row("Audio codec", au.get("codec_name")), row("Sample rate", au.get("sample_rate")), row("Channels", au.get("channels"))]
    srows = [r for r in srows if r[1] not in ("", "None")]
    trows = [row("Make", make), row("Model", model), row("Encoder / software", encoder), row("Created", created)]
    trows = [r for r in trows if r[1] not in ("", "None")]
    other = [row(k, str(v)[:200]) for k, v in tags.items()][:25]
    sections = [{"title": t, "rows": r} for t, r in (("File", rows), ("Streams", srows), ("Device & software", trows), ("All tags", other)) if r]
    if geo:
        sections.insert(2, {"title": "GPS", "rows": [row("Latitude", f"{geo[0]:.6f}", "warn"), row("Longitude", f"{geo[1]:.6f}", "warn")]})
    out = R(f"{kind} analysis", "▶", highlights=chips, sections=sections,
            links=[{"label": "VirusTotal (by hash)", "url": f"https://www.virustotal.com/gui/file/{hashes['sha256']}"}],
            note="Metadata shows how and where a file was made, not where it was posted.")
    if geo:
        out["pivots"] = [{"module": "coords", "q": f"{geo[0]:.6f}, {geo[1]:.6f}", "label": "GPS → location", "auto": True}]
    ff = shutil.which("ffmpeg")
    if ff and vs:
        for ss in ("1", "0"):
            try:
                pr = subprocess.run([ff, "-v", "error", "-ss", ss, "-i", path, "-frames:v", "1", "-vf", "scale=520:-2", "-f", "image2", "-c:v", "mjpeg", "pipe:1"], capture_output=True, timeout=25)
            except Exception:
                break
            if pr.stdout:
                out["image"] = "data:image/jpeg;base64," + base64.b64encode(pr.stdout).decode()
                break
    return out

def analyze_file(path, name):
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(4096)
    hashes = _hashes(path)
    res = None
    if HAVE_PIL:
        try:
            res = _analyze_image(path, name, size, hashes)
        except Exception:
            res = None
    if res is None and shutil.which("ffprobe"):
        try:
            res = _analyze_media(path, name, size, hashes)
        except Exception:
            res = None
    if res is None:
        magic = identify(head)
        rows = [row("Name", name), row("Size", f"{size:,} bytes"), row("Type (magic)", magic), row("MD5", hashes["md5"]), row("SHA-1", hashes["sha1"]), row("SHA-256", hashes["sha256"])]
        tone = "warn" if magic.startswith(("ELF", "Windows PE")) else "info"
        res = R("File analysis", "▢", highlights=[chip("Type", magic, tone), chip("Size", f"{size:,} B", "info")],
                sections=[{"title": "File", "rows": rows}],
                links=[{"label": "VirusTotal (by hash)", "url": f"https://www.virustotal.com/gui/file/{hashes['sha256']}"}],
                note="No format-specific parser for this type. Hashes are provided for threat-intel lookups.")
    return res

def mod_imageurl(q):
    chain, code, _, body, final = fetch_chain(q, max_bytes=25_000_000)
    if code != 200:
        raise RuntimeError(f"Image host returned HTTP {code}")
    d = tempfile.mkdtemp(prefix="portal_")
    try:
        path = os.path.join(d, "img.bin")
        with open(path, "wb") as f:
            f.write(body)
        res = analyze_file(path, os.path.basename(urlparse(final).path) or "image")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    host = urlparse(final).hostname or ""
    res["highlights"].insert(0, chip("Source", host, "info"))
    res.setdefault("pivots", []).append({"module": "dns", "q": host, "label": f"Host → {host}", "auto": False})
    return res

@app.post("/api/file")
def api_file():
    f = request.files.get("file")
    if not f:
        return jsonify(error="No file received"), 400
    d = tempfile.mkdtemp(prefix="portal_")
    try:
        path = os.path.join(d, "upload.bin")
        f.save(path)
        res = analyze_file(path, os.path.basename(f.filename or "file"))
    except Exception as e:
        res = {"error": f"{type(e).__name__}: {e}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return jsonify(res)
