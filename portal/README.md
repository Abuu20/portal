# PORTAL

One search box, many windows. Type an IP, domain, email, URL, `@username`, phone number,
coordinates, place name, barcode, CVE or file hash, or drop/paste an image, video or any file.
Each module opens in its own draggable window; related results are joined by lines and open
automatically (email -> its domain -> the server's IP -> where the server sits).

## Run (Kali)
    sudo apt install python3-flask python3-pil ffmpeg    # ffmpeg gives video thumbnails + ffprobe
    ./run.sh                                             # opens http://127.0.0.1:8137

Optional API keys (each switches on extra results; everything else works without them):

    export VT_API_KEY=...          # VirusTotal: IP / domain / URL / file hash
    export ABUSEIPDB_API_KEY=...   # AbuseIPDB: IP abuse score
    export SHODAN_API_KEY=...      # Shodan: banners and product versions (InternetDB is used without a key)
    export HIBP_API_KEY=...        # Have I Been Pwned: breach exposure for an email
    sudo apt install nmap dnsutils whois whatweb traceroute   # local toolbox

Optional OSINT tools (click-to-run inside PORTAL; no auto-run):

    pipx install sherlock-project   # ~400 sites, fast (10–30 s)   → used by the Username window
    pipx install maigret            # 3000+ sites, slower (1–3 min)
    pip install phonenumbers        # or: sudo apt install python3-phonenumbers  → phone lookups

## Layout, sound and controls
- **Tiles** (default) fills the whole screen with no scrolling: the screen is split into rectangles sized by how much each window has to show, and the splitter tries both directions at every cut to keep every tile readable. Past ~18 windows it falls back to a scrolling canvas.
- **Flow** is the column view (left to right by relationship, scrollable, windows resizable). Switch with the Tiles/Flow button or press `L`.
- **Drag** a title bar onto another window to swap their places. **Arrange** resets the order. **Minimise** (–) sends a window to the dock at the bottom; click its chip to restore.
- Hover a window to ring the windows linked to it; hover its title bar to draw the link lines. **Lines** shows all links at once.
- **Sound**: short synthesized tones for scan start, each result (different for info / clean / warning / critical), completion, errors and clicks. 🔊 or `M` mutes; the choice is remembered. Browsers only allow sound after you press a key or click, so a scan restored from the URL on page load is silent.
- The status bar counts windows, critical, warnings, clean and running.

## Using it
- `/` focuses the box. Enter scans. Double-click a title bar (or the zoom button) to enlarge a window, Esc to shrink.
- Drag windows by the title bar; resize from the bottom-right corner; Arrange re-flows them; Lines toggles the wires.
- Click any value to copy it. Red = critical, amber = warning, green = clean, cyan = info.

## Sharing and the lost-person flow
1. The person sends you their location pin (Google Maps, Apple Maps, OpenStreetMap or WhatsApp link, or a `geo:` link).
2. Paste it into the box. Portal reads the coordinates, resolves the address and shows what is within 500 m (police, clinics, bus stops, shops).
3. In the Location window press **WhatsApp**, **SMS** or **Copy** under "Send this location". It sends a ready message with the address and a map link.
Every window also has a share button (top right of its title bar), and **Share** / **Report** in the top bar share or download everything on screen as text.

## Username OSINT (`@handle`)
Type `@torvalds` in the box. Portal opens a **Username OSINT** window with two buttons:

- **Scan with Sherlock** — `~400 sites`, 10–30 s.
- **Deep scan with Maigret** — `3000+ sites`, 1–3 min, more coverage.

Both run locally on this machine and only check public sites for accounts that use the exact same handle.
The same handle on two sites is usually two different people — this is handle discovery, not identity lookup.
A Whatsmyname / Namechk / Google pivot is one click away for a second opinion. If neither tool is installed
the window shows the exact `pipx install …` command.

## Phone intelligence
Type a number with its country code, e.g. `+1 202 555 0143` or `+254 700 000 000`.
Uses the local `phonenumbers` library — no network, no API key — for:

- validity, line type (mobile / fixed / VoIP / toll-free / …), region
- original carrier and location (like a phone-book prefix, not the current owner)
- timezone, and canonical International / E.164 / National formats

One-click pivots to Truecaller / Sync.me / Google. Live carrier data needs a paid API (Twilio Lookup, numverify).

## Research (topics, brands, organisations, events, hashtags, DOIs)
Type a subject to get: papers and journals (OpenAlex + Crossref, or paste a DOI), news headlines (Google News RSS), and a
launcher that opens that subject's search page on X, Facebook, Instagram tags, TikTok, YouTube, Reddit, LinkedIn, Scholar, PubMed
and more, in your own browser where you are already signed in. Portal never logs in, scrapes or automates those platforms.
News and the launcher are not run for text that looks like a private person's name with no encyclopedia entry of its own.
This is a heuristic, not a guarantee: it errs toward blocking and fails closed when offline.

## History, bulk triage and email headers (v5)
- **History** (button): every scan is auto-saved locally. Re-scanning a target opens a **Changes** window showing what is new, gone or worse since last time (day-count values like "days left" are ignored). Add notes/tags, reopen any scan as a stored snapshot (no live requests), or delete it. Toggle auto-save under the ⋯ menu.
- **Bulk**: paste or drop a list (one indicator per line, or comma/semicolon separated) of IPs, domains, URLs, hashes, emails, CVEs. Up to 200, results sorted by severity, filterable, exported as CSV (formula-safe). Emails are not sent to breach services in bulk. Names/free text are listed as unsupported. Pasting several lines into the search box opens Bulk.
- **Headers**: paste raw email headers to get hop timeline with delays, SPF/DKIM/DMARC, spoof flags (display-name, Reply-To, lookalike/IDN domains) and one-click pivots on the origin IP and domains.
- Data lives in `~/.local/share/portal` (override with `PORTAL_DATA`), folder mode 0700, file 0600. Stays on this machine.

## Code layout (kept small on purpose)
No file is over about 330 lines, so each one can be read, edited and reviewed whole.

| Back end (`portal_lib/`) | What lives there |
|---|---|
| `core.py` | Flask app, request guard, cache, HTTP helpers, result builders, input detection, DNS-over-HTTPS, SSRF-safe fetch |
| `net.py` · `intel.py` · `web.py` · `geo.py` | DNS/RDAP/TLS/IP/email/URL · CVE+EPSS, exposure, reputation · site intelligence · places |
| `files.py` · `headers.py` · `accounts.py` · `lookups.py` | file analysis · email headers · usernames and phone · products, papers, news |
| `tools.py` · `surface.py` | local toolbox and output parsers · attack-surface map |
| `store.py` · `ai.py` · `routes.py` | history and diffs · optional AI summary · module registry and `/api/run` |

`server.py` is only the entry point. Front end (`static/`): `app-core.js` → `app-windows.js` → `app-render.js` → `app-search.js` → `history.js` → `bulk.js` → `menu.js` → `smart.js`, loaded in that order and sharing globals.

## Smart layer (v6): tool check, next steps, Kali 2026 tools
- **Next steps** window: after a scan, PORTAL reads the results on screen and ranks what to do next (critical findings first, then e.g. *WordPress detected → list plugins*, *risky open ports → verify services*, *login page → crawl the site*). It is plain rules, runs locally, sends nothing anywhere, and never runs a tool by itself. Reopen it from ⋯ → **Show next steps**.
- **Tool check** (⋯ menu): which optional tools are installed, with the exact install command for each missing one (and a *Copy all* button). Missing tools never break anything; their buttons just stay hidden.
- New click-to-run tools in the toolbox (from Kali 2026.1–2026.3), all behind the authorisation tick-box:
  - `rustscan` fast port sweep, and *rustscan → nmap versions*
  - `katana` crawl piped through `uro` to dedupe the URL list
  - `wpprobe` WordPress plugin enumeration
  - **Intrusive** (☠, attack-style payloads): `dalfox`, `sstimap`, `xsstrike`. These also make you **type the target host** before every run, and only exist for sites you own or are authorised to test.

      sudo apt install rustscan katana uro wpprobe dalfox sstimap xsstrike

- A pasted URL now also opens the Local toolbox (URL-based tools use the URL; host-based tools use its host).

### Results feed the next step (v6.1)
- **Parsed tool output:** nmap / rustscan ports, katana endpoints (with their parameter names), CVE ids from wpprobe, and `[V]`-style lines from dalfox / sstimap / xsstrike are turned into structured findings. A `# Parsed:` summary line appears above the raw output. Nmap, rustscan and katana formats are stable; wpprobe and the scanner markers are best-effort heuristics, so treat those as hints and verify by hand.
- **Next steps reacts to them:** a confirmed risky port, a web service found on a new port, endpoints that take parameters, or CVE ids from the plugin scan each create or reorder suggestions, and already-answered suggestions disappear.
- **EPSS** (FIRST.org, free, no key): CVE windows show the 30-day exploit probability, and the Exposure window sorts CVEs by it. If FIRST.org is unreachable PORTAL simply omits it.
- **Risk score 0-100:** a heuristic, not CVSS. It adds up what is on screen (critical findings, warnings, CISA KEV, high EPSS, risky services, scanner hits) and lists every contribution under *Why this score*, so you can argue with it.

### Attack-surface map (v6.2)
For a domain, the **Next steps** window offers *Map the attack surface* once the certificate-log subdomains are in. It takes up to 40 of them (dev / admin / staging-looking names first), checks which resolve, makes **one request per host** (https, then http), and shows one ranked table. No crawling, no payloads, public addresses only. Because it contacts every probed host it needs the authorisation tick-box.
- What lifts a host's score (each contribution is listed): a non-production or admin-style name, a login form, a directory listing, a forgotten default web-server page, plain-http-only, a server version in the `Server` header, a CNAME to a dead address, and **possible subdomain takeover** (a CNAME to GitHub Pages, Heroku, S3, Azure, Fastly, Pantheon, Readme or Surge whose page shows the "unclaimed" message).
- The score says what to look at first, not that something is vulnerable. A takeover hit is a strong lead, but confirm it before acting on it.
- Hosts scoring 40+ feed back into Next steps and the risk score, and the top hosts get one-click pivots into *Site intelligence*.

### Link graph (v6.3)

**⋯ → Link graph** opens a relationship window in the style of a link-analysis tool: entities are nodes
(domain, IP, ASN, organisation, open port, CVE, weakness, technology, location, email address), the lines are
labelled with the relationship ("A", "MX", "announced by", "vulnerable to", "certificate issued by" ...).
Drag nodes, scroll to zoom, drag the background to pan, click a legend chip to hide a type, click a node to see its
connections and to start a lookup on it. A timeline strip shows registration and certificate dates.
The graph is built from the scans already on screen and grows as new windows finish.
Only infrastructure entities exist as node types; there are no person, phone or social-profile nodes.

Code: `portal_lib/graph.py` (reads each module's finished result, so modules are untouched), and in `static/`
`graph-data.js` (merge), `graph-layout.js` (force layout), `graph-view.js` (window).

### Office document analysis (v6.4)

Drop a `.docx / .xlsx / .pptx / .docm / .xlsm`, a legacy `.doc / .xls`, or an `.rtf` on PORTAL. It is examined
**without opening or running anything** and reports: VBA macros, Excel 4.0 (XLM) macro sheets, remote templates
(template injection), DDE fields, auto-updating linked objects, embedded OLE objects and ActiveX, Equation Editor
objects (CVE-2017-11882 family), unsafe zip paths and zip bombs, plus the document's stored properties. External
hosts become DNS pivots. If `olevba` (`pip install oletools`) is installed it is run on a temp copy and its
AutoExec / Suspicious / IOC lines are added. Legacy `.doc/.xls` checks are keyword heuristics because their macro
source is compressed; olevba is the way to read it. The olevba output parsing is written from memory and has not
been checked against a real install.

Code: `portal_lib/office.py`.

### Shared infrastructure (v6.5)

**⋯ → Shared infrastructure** compares the latest saved scan of every target and lists what two or more of them
have in common: the same IP, network (ASN), nameserver or mail host, certificate issuer, CVE. Strongest links come
first, big shared providers are tagged "common provider", and each target is a button that opens its saved scan.
It uses only data already stored on this computer; nothing is fetched. Code: `portal_lib/correlate.py`, `static/correlate.js`.

## One-click launcher and background service (KDE)
Run `./install-kde.sh` once (no root; needs `python3-flask`). It copies PORTAL to `~/.local/opt/portal`, installs a systemd **user** service that starts at login (127.0.0.1 only, sandboxed), adds **PORTAL** to the application launcher (right-click: Restart / Stop; pin it to the panel) and a `portal` command. Clicking it starts the service if needed and opens an app-style window (Chromium if installed, otherwise your default browser). Re-run after updating; `./install-kde.sh --uninstall` removes it and keeps your history. Logs: `journalctl --user -u portal`. If you change `PORTAL_DATA`, add that path to `ReadWritePaths` in the unit.

## Optional AI explanation (your own key)
The **✦ Explain** button sends the findings on screen to the Anthropic API and shows "explain these findings and suggest next steps" in a window. It is off until you create `~/.config/portal/ai.env` (chmod 600) containing `ANTHROPIC_API_KEY=...` (or set that environment variable) and restart. The key stays on the server. Nothing is sent until you press Send in a preview where you can edit or redact the exact text. Override the model with `PORTAL_AI_MODEL`. Output is AI-generated: verify before acting.

## Modules
ip, network registration (RDAP), DNS (via DNS-over-HTTPS, no dig needed), domain registration, TLS certificate,
subdomains (certificate-transparency logs), email (MX/SPF/DMARC/disposable/role + optional breaches),
URL (redirect chain, security headers), place/coordinates + map, product barcode/name (Open Food Facts),
CVE (NVD + CISA KEV), site intelligence (title, metadata, tech fingerprint, cookies, robots.txt, security.txt,
social links the site itself publishes, outbound domains, web-archive snapshot), exposure (Shodan InternetDB: open ports,
known CVEs, tags), reputation (GreyNoise community, plus VirusTotal and AbuseIPDB with keys), shared-location links,
nearby places, encyclopedia match for notable people / organisations / places, a local toolbox (whois, dig, nmap, whatweb,
traceroute; tools marked with a warning sign send traffic and require the authorisation tick-box), hash pivots, file analysis (EXIF/GPS/software/AI-metadata for images,
container/device/GPS/encoder for video and audio, magic bytes + hashes for anything else), **username OSINT (Sherlock / Maigret,
run on click)**, and **phone intelligence (local `phonenumbers`) + allocation metadata**.

## Scope
Infrastructure, files, places, products, vulnerabilities, plus opt-in username and phone allocation lookups.
It still does not look up private individuals: a bare name only returns an encyclopedia match and place search,
phone numbers return *allocation* metadata (carrier / region / type) rather than owner identity,
and usernames only find *public accounts using that exact handle* — not the person behind them.

## Safety
Binds to 127.0.0.1 only, rejects other Host headers (DNS rebinding), and requires a custom header on every API call.
URL fetching refuses private/loopback/link-local addresses and re-checks every redirect hop.
Uploaded files are processed in a temp folder and deleted immediately.
Sherlock / Maigret run in a throw-away `$HOME` and `$TMPDIR` under `PrivateTmp=yes`; nothing is written to your real home.
