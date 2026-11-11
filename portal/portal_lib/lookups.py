"""Research lookups: products, encyclopedia, papers, news and the search-links launcher."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote

from .core import DOI_RE, R, cached, chip, detect, http_get, http_json, row

def mod_product(q):
    code = re.sub(r"\D", "", q)
    fields = "product_name,brands,quantity,categories,ingredients_text,image_front_url,nutriscore_grade,countries,labels,allergens"
    d = http_json(f"https://world.openfoodfacts.org/api/v2/product/{code}.json?fields={fields}", timeout=12)
    if d.get("status") != 1:
        return R("Product", "▤", "info", note=f"Barcode {code} is not in Open Food Facts (it covers food and drink). See the lookup links for general products.")
    p = d["product"]
    chips = [chip("Brand", p.get("brands") or "?", "info")]
    ns = (p.get("nutriscore_grade") or "").upper()
    if ns in "ABCDE" and ns:
        chips.append(chip("Nutri-Score", ns, {"A": "ok", "B": "ok", "C": "info", "D": "warn", "E": "bad"}[ns]))
    rows = [row("Name", p.get("product_name")), row("Brand", p.get("brands")), row("Quantity", p.get("quantity")), row("Categories", p.get("categories")), row("Sold in", p.get("countries")), row("Labels", p.get("labels")), row("Allergens", p.get("allergens", "").replace("en:", "")), row("Ingredients", (p.get("ingredients_text") or "")[:600])]
    rows = [r for r in rows if r[1] not in ("", "None")]
    return R("Product", "▤", highlights=chips, sections=[{"title": "Open Food Facts", "rows": rows}], image=p.get("image_front_url"))

def mod_product_search(q):
    d = http_json(f"https://world.openfoodfacts.org/cgi/search.pl?search_simple=1&action=process&json=1&page_size=6&fields=code,product_name,brands&search_terms={quote(q)}", timeout=15)
    prods = [p for p in d.get("products", []) if p.get("product_name")]
    if not prods:
        return R("Product search", "▤", "info", note="No food/drink products match this text.")
    rows = [[p.get("code", ""), f"{p.get('product_name')} - {p.get('brands', '')}"] for p in prods]
    pivots = [{"module": "product", "q": p["code"], "label": p["product_name"][:28], "auto": False} for p in prods[:4]]
    return R("Product search", "▤", highlights=[chip("Matches", str(len(prods)), "info")], sections=[{"title": "Open Food Facts", "rows": rows}], pivots=pivots)

def mod_links(q):
    d = detect(q)
    t, v, e = d["type"], d["value"], quote(d["value"], safe="")
    L = []
    if t == "ip":
        L = [("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{e}"), ("Shodan", f"https://www.shodan.io/host/{e}"), ("AbuseIPDB", f"https://www.abuseipdb.com/check/{e}"), ("Censys", f"https://search.censys.io/hosts/{e}"), ("GreyNoise", f"https://viz.greynoise.io/ip/{e}"), ("BGP.he.net", f"https://bgp.he.net/ip/{e}")]
    elif t == "domain":
        L = [("VirusTotal", f"https://www.virustotal.com/gui/domain/{e}"), ("urlscan", f"https://urlscan.io/search/#domain%3A{e}"), ("Shodan", f"https://www.shodan.io/search?query=hostname%3A{e}"), ("crt.sh", f"https://crt.sh/?q={e}"), ("Wayback", f"https://web.archive.org/web/*/{v}"), ("SecurityTrails", f"https://securitytrails.com/domain/{e}/dns"), ("BuiltWith", f"https://builtwith.com/{e}")]
    elif t == "email":
        dom = quote(v.split("@", 1)[1])
        L = [("HIBP", f"https://haveibeenpwned.com/account/{e}"), ("EmailRep", f"https://emailrep.io/{e}"), ("MXToolbox", f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{dom}")]
    elif t == "url":
        us_query = quote('page.url:"' + v + '"', safe="")
        L = [("VirusTotal", f"https://www.virustotal.com/gui/search/{e}"), ("Wayback", f"https://web.archive.org/web/*/{v}"), ("urlscan", "https://urlscan.io/search/#" + us_query)]
    elif t == "imageurl":
        L = [("Google Lens", f"https://lens.google.com/uploadbyurl?url={e}"), ("TinEye", f"https://tineye.com/search?url={e}"), ("Yandex Images", f"https://yandex.com/images/search?rpt=imageview&url={e}"), ("Bing Visual", f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{e}")]
    elif t == "coords":
        lat, lon = [x.strip() for x in v.split(",")]
        L = [("OpenStreetMap", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"), ("Google Maps", f"https://www.google.com/maps?q={lat},{lon}"), ("Google Earth", f"https://earth.google.com/web/@{lat},{lon},0a,1500d,35y,0h,0t,0r"), ("Mapillary", f"https://www.mapillary.com/app/?lat={lat}&lng={lon}&z=17")]
    elif t == "hash":
        L = [("VirusTotal", f"https://www.virustotal.com/gui/file/{e}"), ("MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search={e}"), ("Hybrid Analysis", f"https://www.hybrid-analysis.com/search?query={e}")]
    elif t == "cve":
        L = [("NVD", f"https://nvd.nist.gov/vuln/detail/{e}"), ("CVE.org", f"https://www.cve.org/CVERecord?id={e}"), ("Exploit-DB", f"https://www.exploit-db.com/search?cve={e}"), ("GitHub advisories", f"https://github.com/advisories?query={e}")]
    elif t == "barcode":
        L = [("UPCitemdb", f"https://www.upcitemdb.com/upc/{e}"), ("Barcode Lookup", f"https://www.barcodelookup.com/{e}"), ("Open Food Facts", f"https://world.openfoodfacts.org/product/{e}")]
    elif t == "username":
        L = [("WhatsMyName", f"https://whatsmyname.app/?q={e}"), ("Namechk", f"https://namechk.com/?q={e}"), ("Google", f"https://www.google.com/search?q=%22{e}%22")]
    elif t == "phone":
        digits = re.sub(r"\D", "", v)
        L = [("WhatsApp", f"https://wa.me/{digits}"), ("Telegram", f"https://t.me/{digits}"), ("Truecaller", f"https://www.truecaller.com/search/{digits}"), ("Sync.me", f"https://sync.me/search/?number={digits}"), ("SpyDialer", f"https://www.spydialer.com/default.aspx?phone={digits}"), ("NumLookup", f"https://www.numlookup.com/?number={digits}"), ("Google", f"https://www.google.com/search?q=%22{quote(v)}%22")]
    else:
        L = [("DuckDuckGo", f"https://duckduckgo.com/?q={e}"), ("OpenStreetMap", f"https://www.openstreetmap.org/search?query={e}"), ("Wikipedia", f"https://en.wikipedia.org/w/index.php?search={e}")]
    return R("Pivot links", "↗", "info", links=[{"label": a, "url": b} for a, b in L], note="These open third-party sites in your browser.")

def mod_entity(q):
    s = http_json("https://en.wikipedia.org/w/api.php?action=query&list=search&format=json&srlimit=3&srsearch=" + quote(q), timeout=10)
    hits = (s.get("query") or {}).get("search") or []
    if not hits:
        return R("Encyclopedia match", "📖", "info", note="No encyclopedia entry found. Portal does not search private individuals across social platforms or the wider web.")
    title = hits[0]["title"]
    d = http_json("https://en.wikipedia.org/api/rest_v1/page/summary/" + quote(title.replace(" ", "_"), safe=""), timeout=10)
    chips = [chip("Closest match", d.get("title", title), "info")]
    if d.get("description"):
        chips.append(chip("About", d["description"][:60], "info"))
    if d.get("type") == "disambiguation":
        chips.append(chip("Ambiguous", "multiple meanings", "warn"))
    url = ((d.get("content_urls") or {}).get("desktop") or {}).get("page")
    out = R("Encyclopedia match", "📖", highlights=chips,
            note=((d.get("extract") or "")[:700] + " (Closest encyclopedia match; it may not be who or what you mean.)").strip())
    if url:
        out["links"] = [{"label": "Wikipedia article", "url": url}]
    img = (d.get("thumbnail") or {}).get("source")
    if img:
        out["image"] = img
    out["pivots"] = [{"module": "entity", "q": h["title"], "label": h["title"][:26], "auto": False} for h in hits[1:]]
    return out

def mod_wikidata(q):
    s = http_json(f"https://en.wikipedia.org/w/api.php?action=query&list=search&format=json&srlimit=1&srsearch={quote(q)}", timeout=10)
    hits = (s.get("query") or {}).get("search") or []
    if not hits:
        return R("Wikidata profile", "🏛", "info", note="No structured data found.")
    title = hits[0]["title"]
    s2 = http_json(f"https://en.wikipedia.org/w/api.php?action=query&prop=pageprops&titles={quote(title)}&format=json", timeout=10)
    pages = s2.get("query", {}).get("pages", {})
    qid = None
    for pid, page in pages.items():
        if pid != "-1":
            qid = page.get("pageprops", {}).get("wikibase_item")
            break
    if not qid:
        return R("Wikidata profile", "🏛", "info", note="No Wikidata ID for this entity.")
    
    d = http_json(f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json", timeout=10)
    ent = d.get("entities", {}).get(qid, {})
    claims = ent.get("claims", {})
    
    def get_vals(prop):
        vals = claims.get(prop, [])
        out = []
        for v in vals:
            mainsnak = v.get("mainsnak", {})
            if mainsnak.get("snaktype") == "value":
                dv = mainsnak.get("datavalue", {})
                val = dv.get("value")
                if dv.get("type") == "time":
                    out.append(val.get("time", "").split("T")[0].lstrip("+"))
                elif dv.get("type") == "wikibase-entityid":
                    out.append(val.get("id"))
                elif dv.get("type") == "string":
                    out.append(val)
        return out

    ids_to_resolve = []
    for prop in ["P19", "P106", "P108", "P39"]:
        ids_to_resolve.extend(get_vals(prop))
        
    labels = {}
    if ids_to_resolve:
        try:
            ld = http_json(f"https://www.wikidata.org/w/api.php?action=wbgetentities&ids={'|'.join(set(ids_to_resolve))}&props=labels&languages=en&format=json")
            for eid, e in ld.get("entities", {}).items():
                labels[eid] = e.get("labels", {}).get("en", {}).get("value", eid)
        except: pass
        
    def lbl(ids):
        return ", ".join(labels.get(i, i) for i in ids) if ids else None

    rows = []
    if get_vals("P569"): rows.append(row("Born", get_vals("P569")[0]))
    if get_vals("P570"): rows.append(row("Died", get_vals("P570")[0]))
    if get_vals("P19"): rows.append(row("Place of birth", lbl(get_vals("P19"))))
    if get_vals("P106"): rows.append(row("Occupation", lbl(get_vals("P106"))))
    if get_vals("P108"): rows.append(row("Employer", lbl(get_vals("P108"))))
    if get_vals("P39"): rows.append(row("Position", lbl(get_vals("P39"))))

    socials = []
    for prop, name in [("P2002", "Twitter"), ("P2013", "Facebook"), ("P2003", "Instagram"), ("P2397", "YouTube"), ("P2037", "GitHub")]:
        for val in get_vals(prop):
            if name == "Twitter": socials.append({"label": "X / Twitter", "url": f"https://x.com/{val}"})
            elif name == "YouTube": socials.append({"label": "YouTube", "url": f"https://youtube.com/channel/{val}"})
            elif name == "GitHub": socials.append({"label": "GitHub", "url": f"https://github.com/{val}"})
            else: socials.append({"label": name, "url": f"https://{name.lower()}.com/{val}"})

    if not rows and not socials:
        return R("Wikidata profile", "🏛", "info", highlights=[chip("ID", qid, "info")], note="No detailed structured data available for this entity.")

    chips = [chip("Wikidata ID", qid, "info")]
    return R("Wikidata profile", "🏛", "info", highlights=chips, sections=[{"title": f"Structured data for {title}", "rows": rows}] if rows else [], links=socials, note="Data from Wikidata, an open knowledge base.")

_TOKEN = re.compile(r"[^\W\d_]+(?:[-'.][^\W\d_]+)*\.?")

def _norm(s):
    return re.sub(r"[^a-z0-9]+", " ", str(s).lower()).strip()

_TOPIC_WORDS = {"the", "and", "of", "in", "for", "on", "at", "to", "vs", "versus", "how", "what", "why", "near",
                "about", "with", "news", "price", "prices", "market", "review", "reviews", "best", "new",
                "latest", "update", "updates", "impact", "election", "festival", "conference", "summit",
                "company", "ltd", "inc", "limited", "bank", "university", "college", "hospital", "school",
                "ministry", "council", "association", "society", "foundation", "group", "services", "energy",
                "solar", "climate", "health", "policy", "law", "act", "report", "study", "research",
                "technology", "software"}

def name_shaped(q):
    toks = q.strip().split()
    if not (2 <= len(toks) <= 4 and all(_TOKEN.fullmatch(t) for t in toks)):
        return False
    return not any(t.lower().strip(".") in _TOPIC_WORDS for t in toks)

def public_subject(q):
    q = q.strip()
    def check():
        if not name_shaped(q):
            return True
        try:
            s = http_json("https://en.wikipedia.org/w/api.php?action=query&list=search&format=json&srlimit=3&srsearch=" + quote(q), timeout=8)
            for h in (s.get("query") or {}).get("search") or []:
                if _norm(h["title"]) == _norm(q):
                    d = http_json("https://en.wikipedia.org/api/rest_v1/page/summary/" + quote(h["title"].replace(" ", "_"), safe=""), timeout=8)
                    return d.get("type") == "standard" and bool(d.get("description"))
        except Exception:
            return False
        return False
    return cached(("public-subject", q.lower()), 3600, check)

GATE_NOTE = ("Not run: this looks like a private person's name with no encyclopedia entry of its own. Portal does not search "
             "people across news or social platforms. Topics, brands, organisations, events, hashtags, places and notable "
             "public subjects work.")

def mod_launch(q):
    if not public_subject(q):
        return R("Search the platforms", "🛰", "info", note=GATE_NOTE)
    e = quote(q.strip(), safe="")
    tag = re.sub(r"[^A-Za-z0-9_]", "", q) if (q.startswith("#") or len(q.split()) == 1) else ""
    L = [
        ("X", f"https://x.com/search?q={e}&f=live"), ("Facebook", f"https://www.facebook.com/search/top?q={e}"),
        ("Instagram tag", f"https://www.instagram.com/explore/tags/{tag}/") if tag else None,
        ("TikTok", f"https://www.tiktok.com/search?q={e}"), ("YouTube", f"https://www.youtube.com/results?search_query={e}"),
        ("Reddit", f"https://www.reddit.com/search/?q={e}"), ("LinkedIn", f"https://www.linkedin.com/search/results/all/?keywords={e}"),
        ("Google News", f"https://news.google.com/search?q={e}"), ("Google Scholar", f"https://scholar.google.com/scholar?q={e}"),
        ("Semantic Scholar", f"https://www.semanticscholar.org/search?q={e}"), ("PubMed", f"https://pubmed.ncbi.nlm.nih.gov/?term={e}"),
        ("arXiv", f"https://arxiv.org/search/?query={e}&searchtype=all"), ("Wikipedia", f"https://en.wikipedia.org/w/index.php?search={e}"),
    ]
    return R("Search the platforms", "🛰", "info", links=[{"label": a, "url": b} for a, b in filter(None, L)],
             note="Each link opens that site's own search in your browser, where you are already signed in. "
                  "Portal does not log in, scrape or automate anything on those platforms.")

def _strip_tags(s):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", str(s or ""))).strip()

def mod_scholar(q):
    q = q.strip()
    is_doi = bool(DOI_RE.match(q))
    doi = DOI_RE.match(q).group(1) if is_doi else None
    sel = "display_name,publication_year,cited_by_count,doi,primary_location,open_access,authorships"
    oa_url = (f"https://api.openalex.org/works?filter=doi:{quote(doi, safe='/')}&select={sel}" if is_doi else
              f"https://api.openalex.org/works?search={quote(q)}&per-page=8&select={sel}")
    cr_url = None if is_doi else (f"https://api.crossref.org/works?query={quote(q)}&rows=5&select=title,DOI,issued,container-title,is-referenced-by-count")
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(http_json, oa_url, None, 15)
        f2 = ex.submit(http_json, cr_url, None, 15) if cr_url else None
        items, errs, seen = [], [], set()
        try:
            for w in (f1.result(timeout=20).get("results") or []):
                d = (w.get("doi") or "").replace("https://doi.org/", "").lower()
                src = ((w.get("primary_location") or {}).get("source") or {}).get("display_name")
                au = ", ".join(a["author"]["display_name"] for a in (w.get("authorships") or [])[:3] if a.get("author"))
                items.append({"title": _strip_tags(w.get("display_name")), "year": w.get("publication_year"),
                              "venue": src, "cites": w.get("cited_by_count"), "doi": d,
                              "oa": (w.get("open_access") or {}).get("is_oa"), "authors": au})
                seen.add(d)
        except Exception as e:
            errs.append(f"OpenAlex: {e}")
        if f2:
            try:
                for w in ((f2.result(timeout=20).get("message") or {}).get("items") or []):
                    d = (w.get("DOI") or "").lower()
                    if d in seen:
                        continue
                    yr = ((w.get("issued") or {}).get("date-parts") or [[None]])[0][0]
                    items.append({"title": _strip_tags((w.get("title") or [""])[0]), "year": yr,
                                  "venue": (w.get("container-title") or [None])[0],
                                  "cites": w.get("is-referenced-by-count"), "doi": d, "oa": None, "authors": ""})
            except Exception as e:
                errs.append(f"Crossref: {e}")
    items = [i for i in items if i["title"]]
    if not items:
        if errs and len(errs) >= (1 if is_doi else 2):
            raise RuntimeError("; ".join(errs))
        return R("Papers & journals", "📚", "info", note="No scholarly works found.")
    chips = [chip("Works", str(len(items)), "info")]
    top = max(items, key=lambda i: i["cites"] or 0)
    if top["cites"]:
        chips.append(chip("Most cited", f"{top['cites']:,}", "info"))
    if any(i["oa"] for i in items):
        chips.append(chip("Open access", str(sum(1 for i in items if i["oa"])), "ok"))
    rows = [[f"{i['year'] or '?'} · {i['cites'] or 0} cites", f"{i['title']}" + (f" - {i['venue']}" if i["venue"] else "") + (f" ({i['authors']})" if i["authors"] else "")] for i in items]
    links = [{"label": (i["title"][:38] + "…") if len(i["title"]) > 38 else i["title"], "url": f"https://doi.org/{i['doi']}"} for i in items if i["doi"]][:8]
    return R("Papers & journals", "📚", highlights=chips, sections=[{"title": "OpenAlex + Crossref", "rows": rows}], links=links,
             note=(("Partial result: " + "; ".join(errs)) if errs else "Published research metadata only."))

def mod_news(q):
    if not public_subject(q):
        return R("News coverage", "📰", "info", note=GATE_NOTE)
    _, _, body = http_get(f"https://news.google.com/rss/search?q={quote(q.strip())}&hl=en&gl=US&ceid=US:en", timeout=12, limit=600_000)
    if re.search(rb"<!DOCTYPE|<!ENTITY", body, re.I):
        raise RuntimeError("Unexpected feed format")
    root = ET.fromstring(body)
    arts = []
    for it in root.iter("item"):
        t = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip()
        src = (it.findtext("source") or "").strip()
        try:
            dt = parsedate_to_datetime(it.findtext("pubDate") or "").astimezone(timezone.utc)
        except Exception:
            dt = None
        if t and link.startswith("https://"):
            arts.append((dt, src, t, link))
        if len(arts) >= 10:
            break
    if not arts:
        return R("News coverage", "📰", "info", note="No recent news articles found.")
    dated = [a[0] for a in arts if a[0]]
    chips = [chip("Articles", str(len(arts)), "info")]
    if dated:
        days = (datetime.now(timezone.utc) - max(dated)).days
        chips.append(chip("Latest", "today" if days <= 0 else f"{days} days ago", "info"))
    chips.append(chip("Sources", str(len({a[1] for a in arts if a[1]})), "info"))
    rows = [[f"{(a[0].date().isoformat() if a[0] else '')} {a[1]}".strip(), a[2]] for a in arts]
    links = [{"label": (a[2][:38] + "…") if len(a[2]) > 38 else a[2], "url": a[3]} for a in arts[:6]]
    return R("News coverage", "📰", highlights=chips, sections=[{"title": "Google News", "rows": rows}], links=links,
             note="Headlines from public news sources; open the links for the full articles.")
