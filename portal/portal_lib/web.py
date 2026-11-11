"""Website analysis: page parser, technology fingerprinting and the Site intelligence module."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urljoin, urlparse

from .core import R, chip, fetch_chain, http_json, row

class _Page(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.title, self._t = base, "", False
        self.meta, self.canonical, self.lang = {}, None, None
        self.links, self.scripts, self.forms, self.pw, self.iframes, self.mixed = [], [], 0, 0, 0, 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html":
            self.lang = a.get("lang")
        elif tag == "title":
            self._t = True
        elif tag == "meta":
            k = (a.get("name") or a.get("property") or "").lower()
            if k:
                self.meta.setdefault(k, a.get("content", ""))
        elif tag == "link":
            rel = a.get("rel", "").lower()
            if "canonical" in rel:
                self.canonical = a.get("href")
            if "stylesheet" in rel and urljoin(self.base, a.get("href", "")).startswith("http://"):
                self.mixed += 1
        elif tag == "a" and a.get("href"):
            self.links.append(urljoin(self.base, a["href"]))
        elif tag == "script" and a.get("src"):
            u = urljoin(self.base, a["src"])
            self.scripts.append(u)
            self.mixed += u.startswith("http://")
        elif tag == "form":
            self.forms += 1
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.pw += 1
        elif tag == "iframe":
            self.iframes += 1
            self.mixed += urljoin(self.base, a.get("src", "")).startswith("http://")
        elif tag == "img" and urljoin(self.base, a.get("src", "")).startswith("http://"):
            self.mixed += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._t = False

    def handle_data(self, data):
        if self._t and len(self.title) < 300:
            self.title += data

SOCIAL = {"facebook.com": "Facebook", "fb.com": "Facebook", "instagram.com": "Instagram", "x.com": "X", "twitter.com": "X", "linkedin.com": "LinkedIn", "youtube.com": "YouTube", "youtu.be": "YouTube", "tiktok.com": "TikTok", "github.com": "GitHub", "t.me": "Telegram", "wa.me": "WhatsApp", "pinterest.com": "Pinterest", "threads.net": "Threads"}

TECH_HTML = [("WordPress", r"wp-content|wp-includes|content=\"wordpress"), ("Joomla", r"content=\"joomla|/media/jui/"),
             ("Drupal", r"drupal\.settings|content=\"drupal"), ("Shopify", r"cdn\.shopify\.com|shopify\.theme"),
             ("Wix", r"wixstatic\.com"), ("Squarespace", r"squarespace\.com"),
             ("Magento", r"mage\.cookies|/static/frontend/magento"), ("Next.js", r"__next_data__|/_next/"),
             ("Nuxt", r"__nuxt__|/_nuxt/"), ("React", r"data-reactroot|react-dom"),
             ("Vue.js", r"vue(\.min)?\.js|data-v-[0-9a-f]{6}"), ("Angular", r"ng-version=|angular(\.min)?\.js"),
             ("jQuery", r"jquery[-.\d]*(\.min)?\.js"), ("Bootstrap", r"bootstrap(\.min)?\.(css|js)"),
             ("Google Tag Manager", r"googletagmanager\.com"),
             ("Google Analytics", r"google-analytics\.com|gtag\("),
             ("Facebook Pixel", r"connect\.facebook\.net|fbq\("), ("Stripe", r"js\.stripe\.com")]

COOKIE_TECH = {"phpsessid": "PHP", "jsessionid": "Java", "laravel_session": "Laravel", "csrftoken": "Django", "asp.net_sessionid": "ASP.NET", "_shopify_y": "Shopify"}

def _social_name(host):
    host = (host or "").lower()
    for d, n in SOCIAL.items():
        if host == d or host.endswith("." + d):
            return n
    return None

def _probe(base, path, n=20000):
    try:
        _, code, _, body, _ = fetch_chain(urljoin(base, path), max_bytes=n)
        text = body.decode("utf-8", "replace")
        if code == 200 and text.strip() and not text.lstrip().lower().startswith(("<!doctype", "<html")):
            return text
    except Exception:
        pass
    return None

def _wayback(host):
    try:
        d = http_json("https://archive.org/wayback/available?url=" + quote(host or ""), timeout=8)
        return (d.get("archived_snapshots") or {}).get("closest")
    except Exception:
        return None

def mod_web(q):
    given = bool(re.match(r"^https?://", q, re.I))
    url = q if given else f"https://{q}/"
    try:
        chain, code, hdrs, body, final = fetch_chain(url, max_bytes=1_000_000)
    except Exception:
        if given:
            raise
        chain, code, hdrs, body, final = fetch_chain(f"http://{q}/", max_bytes=1_000_000)
    ctype = hdrs.get("Content-Type", "") or ""
    pf = urlparse(final)
    text, page = "", None
    if body:
        cs = re.search(r"charset=([\w\-]+)", ctype, re.I)
        try:
            text = body.decode(cs.group(1) if cs else "utf-8", "replace")
        except LookupError:
            text = body.decode("utf-8", "replace")
        if "html" in ctype.lower() or "<html" in text[:3000].lower():
            page = _Page(final)
            try:
                page.feed(text)
            except Exception:
                pass
    base = f"{pf.scheme}://{pf.netloc}/"
    with ThreadPoolExecutor(3) as ex:
        f_rb, f_sec, f_wb = ex.submit(_probe, base, "robots.txt"), ex.submit(_probe, base, ".well-known/security.txt"), ex.submit(_wayback, pf.hostname)
        robots, sectxt, snap = f_rb.result(), f_sec.result(), f_wb.result()
    tech = []
    blob = text.lower() + " " + " ".join(page.scripts).lower() if page else ""
    for name, rx in TECH_HTML:
        if re.search(rx, blob):
            tech.append(name)
    gen = page.meta.get("generator") if page else None
    if gen:
        tech.insert(0, f"Generator: {gen[:40]}")
    hl = {k.lower(): v for k, v in hdrs.items()}
    if hl.get("server"):
        tech.append(f"Server: {hl['server'][:40]}")
    if hl.get("x-powered-by"):
        tech.append(f"Powered by: {hl['x-powered-by'][:40]}")
    for h, n in (("cf-ray", "Cloudflare"), ("x-vercel-id", "Vercel"), ("x-amz-cf-id", "CloudFront"),
                 ("x-github-request-id", "GitHub Pages"), ("x-served-by", "Fastly"), ("x-nf-request-id", "Netlify")):
        if h in hl:
            tech.append(n)
    cookies = []
    try:
        cookies = hdrs.get_all("Set-Cookie") or []
    except Exception:
        pass
    cookie_rows, weak = [], 0
    for c in cookies[:12]:
        parts = [p.strip() for p in c.split(";")]
        name, flags = parts[0].split("=", 1)[0], " ".join(p.lower() for p in parts[1:])
        if name.lower() in COOKIE_TECH:
            tech.append(COOKIE_TECH[name.lower()])
        ok = ("secure" in flags or pf.scheme != "https") and "httponly" in flags
        weak += not ok
        cookie_rows.append([name, {"text": ("Secure " if "secure" in flags else "") + ("HttpOnly " if "httponly" in flags else "") + ("SameSite" if "samesite" in flags else ""), "tone": None if ok else "warn"}])
    tech = list(dict.fromkeys(tech))
    chips = [chip("Status", str(code), "ok" if code < 400 else "warn")]
    if page and page.title.strip():
        chips.append(chip("Title", " ".join(page.title.split())[:50], "info"))
    if tech:
        chips.append(chip("Technologies", str(len(tech)), "info"))
    if page and page.pw:
        chips.append(chip("Login form", "password field", "warn" if pf.scheme != "https" else "info"))
    if page and page.mixed and pf.scheme == "https":
        chips.append(chip("Mixed content", f"{page.mixed} insecure resources", "warn"))
    if weak:
        chips.append(chip("Cookies", f"{weak} missing flags", "warn"))
    chips.append(chip("security.txt", "present" if sectxt else "absent", "ok" if sectxt else "info"))
    sections = []
    prow = []
    if page:
        for k, v in (("Title", " ".join(page.title.split())), ("Description", page.meta.get("description")),
                     ("Site name", page.meta.get("og:site_name")), ("Canonical", page.canonical),
                     ("Language", page.lang), ("Final URL", final)):
            if v:
                prow.append(row(k, v[:300]))
        prow += [row("Forms", page.forms), row("Iframes", page.iframes), row("External scripts", len(page.scripts))]
    else:
        prow = [row("Content-Type", ctype or "(none)"), row("Final URL", final), row("Size read", f"{len(body):,} bytes")]
    sections.append({"title": "Page", "rows": prow})
    if tech:
        sections.append({"title": "Technologies (fingerprint)", "rows": [["tech", t] for t in tech]})
    if cookie_rows:
        sections.append({"title": "Cookies", "rows": cookie_rows})
    if robots:
        dis = [ln.strip() for ln in robots.splitlines() if ln.lower().startswith(("disallow", "sitemap"))][:20]
        if dis:
            sections.append({"title": "robots.txt", "rows": [[ln.split(":", 1)[0], ln.split(":", 1)[1].strip()] for ln in dis if ":" in ln]})
    if sectxt:
        sections.append({"title": "security.txt", "rows": [[ln.split(":", 1)[0], ln.split(":", 1)[1].strip()] for ln in sectxt.splitlines() if ":" in ln and not ln.startswith("#")][:8]})
    if snap:
        sections.append({"title": "Web archive", "rows": [row("Closest snapshot", (snap.get("timestamp") or "")[:8]), row("URL", snap.get("url"))]})
    links, ext = [], {}
    social = {}
    if page:
        for u in page.links:
            p = urlparse(u)
            if p.scheme not in ("http", "https") or not p.hostname:
                continue
            n = _social_name(p.hostname)
            if n and not re.search(r"share|intent|sharer|dialog", u, re.I):
                social.setdefault(n, u)
            elif p.hostname != pf.hostname:
                ext[p.hostname] = ext.get(p.hostname, 0) + 1
        links = [{"label": n, "url": u} for n, u in social.items()]
        if ext:
            sections.append({"title": f"Links to other domains ({len(ext)})", "rows": [[h, f"{c} link(s)"] for h, c in sorted(ext.items(), key=lambda x: -x[1])[:20]]})
    pivots = [{"module": "dns", "q": h, "label": h[:26], "auto": False} for h in list(ext)[:4]]
    return R("Site intelligence", "🕸", highlights=chips, sections=sections, links=links, pivots=pivots,
             note="Social links shown are only those the page itself publishes." if links else None)
