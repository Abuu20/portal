"""Places and coordinates: reverse geocode, place search, what's nearby, map links."""
from __future__ import annotations

import math
import re
from urllib.parse import quote, unquote, urlparse

from .core import COORD_RE, R, SHORT_MAP_HOSTS, chip, coords_from_url, fetch_chain, http_json, row

def _nominatim(path):
    return http_json("https://nominatim.openstreetmap.org/" + path, {"Accept-Language": "en"}, timeout=12)

def mod_coords(q):
    m = COORD_RE.match(q)
    lat, lon = float(m.group(1)), float(m.group(2))
    d = _nominatim(f"reverse?format=jsonv2&lat={lat}&lon={lon}&zoom=16&addressdetails=1")
    a = d.get("address") or {}
    chips = [chip("Coordinates", f"{lat:.5f}, {lon:.5f}", "info")]
    if "error" in d:
        chips.append(chip("No address", "open water / remote area", "info"))
        rows = [row("Latitude", lat), row("Longitude", lon)]
    else:
        place = a.get("city") or a.get("town") or a.get("village") or a.get("suburb") or a.get("county")
        if place:
            chips.append(chip("Area", place, "info"))
        if a.get("country"):
            chips.append(chip("Country", a["country"], "info"))
        rows = [row("Latitude", lat), row("Longitude", lon), row("Nearest", d.get("display_name")), row("Road", a.get("road")), row("Suburb", a.get("suburb")), row("City / town", a.get("city") or a.get("town") or a.get("village")), row("State / region", a.get("state")), row("Postcode", a.get("postcode")), row("Country", a.get("country"))]
        rows = [r for r in rows if r[1] not in ("", "None")]
    return R("Location", "⌖", highlights=chips, sections=[{"title": "Reverse geocode", "rows": rows}], map={"lat": lat, "lon": lon, "bbox": [lon - 0.01, lat - 0.007, lon + 0.01, lat + 0.007], "label": "coordinates"}, note="Street-level detail only; house numbers are not resolved.", pivots=[{"module": "nearby", "q": f"{lat:.6f}, {lon:.6f}", "label": "What's nearby", "auto": True}])

def mod_place(q):
    data = _nominatim(f"search?format=jsonv2&limit=5&addressdetails=1&q={quote(q)}")
    if not data:
        return R("Place search", "⚑", "info", note=f"No place matches “{q}”.")
    top = data[0]
    lat, lon = float(top["lat"]), float(top["lon"])
    bb = top.get("boundingbox") or []
    bbox = [float(bb[2]), float(bb[0]), float(bb[3]), float(bb[1])] if len(bb) == 4 else [lon - 0.02, lat - 0.015, lon + 0.02, lat + 0.015]
    a = top.get("address") or {}
    chips = [chip("Match", top.get("type", "place"), "info")]
    if a.get("country"):
        chips.append(chip("Country", a["country"], "info"))
    rows = [[f"#{i + 1}", f"{p.get('display_name')}  ({p.get('lat')}, {p.get('lon')})"] for i, p in enumerate(data)]
    pivots = [{"module": "coords", "q": f"{float(p['lat'])}, {float(p['lon'])}", "label": f"Result #{i + 2}", "auto": False} for i, p in enumerate(data[1:4])]
    return R("Place search", "⚑", highlights=chips, sections=[{"title": "Matches (OpenStreetMap)", "rows": rows}], map={"lat": lat, "lon": lon, "bbox": bbox, "label": top.get("name") or q}, pivots=pivots)

def mod_maplink(q):
    host = (urlparse(q).hostname or "").lower()
    c = coords_from_url(q)
    urls = [q]
    if not c and host in SHORT_MAP_HOSTS | {"maps.google.com", "www.google.com", "google.com"}:
        try:
            chain, _, _, _, final = fetch_chain(q)
            urls = [h["url"] for h in chain] + [final]
            for u in urls:
                c = coords_from_url(u)
                if c:
                    break
        except Exception:
            urls = [q]
    if c:
        lat, lon = c
        chips = [chip("Source", host, "info"), chip("Coordinates", f"{lat:.5f}, {lon:.5f}", "ok")]
        return R("Shared location link", "⌖", highlights=chips,
                 pivots=[{"module": "coords", "q": f"{lat:.6f}, {lon:.6f}", "label": "Resolve location", "auto": True}],
                 note="Coordinates were read from the link itself.")
    for u in urls:
        m = re.search(r"[?&](?:q|query)=([^&#]+)", u) or re.search(r"/maps/place/([^/@?#]+)", u)
        if m:
            text = unquote(m.group(1).replace("+", " "))
            if text and not COORD_RE.match(text):
                return R("Shared location link", "⌖", "info",
                         highlights=[chip("Named place", text[:60], "info")],
                         pivots=[{"module": "place", "q": text, "label": f"Search “{text[:28]}”", "auto": True}],
                         note="The link names a place but carries no coordinates.")
    raise ValueError("No coordinates found in this link. Ask the person to share a 'current location' pin instead of a search result.")

def _hav(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    a = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2
    return 2 * 6371000 * math.asin(math.sqrt(a))

def mod_nearby(q):
    m = COORD_RE.match(q)
    lat, lon = float(m.group(1)), float(m.group(2))
    a = f"(around:500,{lat},{lon})"
    ql = f'[out:json][timeout:20];(nwr{a}[amenity~"^(police|hospital|clinic|pharmacy|fuel|bank|atm|place_of_worship|school|restaurant|cafe|marketplace|bus_station|taxi)$"][name];nwr{a}[highway=bus_stop][name];nwr{a}[railway~"^(station|halt|tram_stop)$"][name];nwr{a}[shop][name];nwr{a}[tourism~"^(hotel|guest_house|museum|attraction)$"][name];);out center 80;'
    data = http_json("https://overpass-api.de/api/interpreter?data=" + quote(ql), timeout=28)
    items, seen = [], set()
    for e in data.get("elements", []):
        t = e.get("tags", {})
        la = e.get("lat") if e.get("lat") is not None else (e.get("center") or {}).get("lat")
        lo = e.get("lon") if e.get("lon") is not None else (e.get("center") or {}).get("lon")
        if la is None or lo is None or not t.get("name"):
            continue
        kind = (t.get("amenity") or ("bus stop" if t.get("highway") == "bus_stop" else None) or t.get("railway") or t.get("tourism") or (("shop: " + t["shop"]) if t.get("shop") else "place"))
        key = (t["name"], kind)
        if key in seen:
            continue
        seen.add(key)
        items.append((_hav(lat, lon, la, lo), kind, t["name"]))
    items.sort()
    if not items:
        return R("What's nearby", "☷", "info", note="No named places within 500 m in OpenStreetMap.")
    def nearest(kinds, label):
        for d, k, n in items:
            if k in kinds:
                return chip(label, f"{n} · {int(d)} m", "ok")
        return None
    chips = [c for c in (nearest({"police"}, "Police"), nearest({"hospital", "clinic"}, "Medical"),
                         nearest({"bus stop", "bus_station", "station", "halt", "tram_stop"}, "Transit")) if c]
    rows = [[k, f"{n} · {int(d)} m"] for d, k, n in items[:25]]
    return R("What's nearby", "☷", highlights=chips or [chip("Places", str(len(items)), "info")],
             sections=[{"title": "Within 500 m (OpenStreetMap)", "rows": rows}],
             note="Public map data; coverage varies by area.")
