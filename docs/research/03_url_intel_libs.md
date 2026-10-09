# 03 — URL Threat Signals, Threat-Intel Sources, Python Libs, QR Libraries

Research for **QR Shield** (UPI-aware QR safety scanner, India). Compiled 2026-10-09.
Every claim has a source URL. Items marked **[probe 2026-10-09]** were verified by me with live `curl`/DNS requests from this machine on that date (no API keys used).

---

## A. URL threat signals

### A.0 Summary table (suggested weights for a rule-based score; tune on test data)

| # | Signal | How to detect | Evidence / why it works | Suggested weight |
|---|---|---|---|---|
| 1 | Hit on threat-intel list (GSB / URLhaus / PhishTank / OpenPhish / Phishing.Database) | Exact URL or host match (offline cache + online lookup) | Curated, verified feeds (see §B) | **Block** (score → max) |
| 2 | Non-http(s) scheme: `javascript:`, `data:`, `file:`, `intent:`, `vbscript:` | Parse scheme | Chrome blocked content-initiated top-frame `data:` navigations because they were "increasingly being used in spoofing and phishing attacks" — https://developer.chrome.com/blog/chrome-60-deprecations/ | **Block** (javascript:/data:) |
| 3 | Brand lookalike: homoglyph / IDN (punycode `xn--`) whose TR39 skeleton equals a brand domain's skeleton | `idna` decode + TR39 skeleton compare (§C) | Chrome itself shows punycode when "the skeleton of the registrable part of a hostname is identical to one of the top domains" — https://chromium.googlesource.com/chromium/src/+/main/docs/idn.md | High (+40) |
| 4 | Typosquat: Damerau-Levenshtein distance 1–2 to a brand's registrable label (and not the brand itself) | `rapidfuzz.distance.DamerauLevenshtein` | ~95% of domains studied (typos of top-500 sites) were actively targeted by typosquatters — NDSS 2015, https://www.ndss-symposium.org/ndss2015/ndss-2015-programme/seven-months-worth-mistakes-longitudinal-study-typosquatting-abuse/ | High (+35) |
| 5 | Brand name in subdomain/path but registrable domain is not the brand's (e.g. `sbi.co.in.verify-kyc.xyz`, `x.pages.dev/hdfc-login`) | `tldextract` registrable domain vs. brand map; token search in subdomain + path | Classic lexical feature in URL-classification literature (Ma et al., KDD 2009 "Beyond Blacklists", 95–99% accuracy using lexical + host features) — https://dblp1.uni-trier.de/rec/html/conf/kdd/MaSSV09 , slides https://engineering.purdue.edu/dcsl/reading/2010/gmh-malurls.pdf | High (+35) |
| 6 | Newly registered domain (< 30 days; < 7 days stronger) | RDAP `events[eventAction="registration"]` | Unit 42: >70% of NRDs were malicious/suspicious/NSFW vs ~7.6% of Alexa top-10k (≈10×); recommends treating domains < **32 days** as NRD — https://unit42.paloaltonetworks.com/newly-registered-domains-malicious-abuse-by-bad-actors/ . Interisle: 77% of phishing domains (May 2024–Apr 2025) were maliciously registered (i.e., registered by the criminal, not compromised) — https://interisle.net/press/pl2025-press-release , data https://www.cybercrimeinfocenter.org/phishing-activity-year-over-year-numbers-may-april-2026 . UCL study: phishing NRDs average lifetime 8.6 days — https://discovery.ucl.ac.uk/id/eprint/10209951 | <7d: +30, <30d: +20, <90d: +5 |
| 7 | High-abuse TLD | Suffix lookup in list (§A.3) | New gTLDs = 11% of market but 51% of phishing domains (Interisle 2025) — https://domainnamewire.com/2025/09/11/report-names-commonly-used-tlds-for-phishing-attacks/ | +10 to +20 (tiered) |
| 8 | Direct download of APK / EXE / MSI / BAT / SCR / JAR / APKS / XAPK | Path extension + `Content-Type: application/vnd.android.package-archive` / `Content-Disposition` on HEAD/GET | India-specific: RTO/e-Challan "VAHAN PARIVAHAN.apk"/"mParivahan.apk" campaigns steal OTPs, UPI PINs — https://www.cyfirma.com/research/rto-challan-fraud-a-technical-report-on-apk-based-financial-and-identity-theft , https://www.boomlive.in/amp/decode/scamcheck/fake-rto-e-challan-message-on-whatsapp-a-growing-apk-scam-29919 | **Danger** (+50) |
| 9 | IP-literal host (IPv4, IPv6, decimal/octal/hex forms like `http://3232235777/`) | `ipaddress.ip_address()` on host after normalisation | Standard lexical feature (Ma et al. above); legit Indian brands never use bare IPs | +25 (+ block if private/loopback) |
| 10 | `@` userinfo in authority (`https://onlinesbi.sbi@evil.tld/`) | `urlsplit().username` / `@` before host | RFC 3986 §3.2.1: `user:password` is deprecated; userinfo "misleadingly crafted to look like a trusted domain name" → see §7.6 Semantic Attacks — https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1 , https://www.rfc-editor.org/rfc/rfc3986#section-7.6 | +30 |
| 11 | URL shortener / dynamic-QR redirector | Host in shortener list (§A.4); then expand server-side | Hides final destination; must be expanded hop-by-hop (§C.5) | +10 (then score the final URL) |
| 12 | Redirect chain: >3 hops, cross-registrable-domain hops, http downgrade, hop to IP / private IP | Manual redirect loop | OWASP: disable automatic redirects, validate every hop — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html | +5 per extra hop; +15 cross-domain to high-risk |
| 13 | Free hosting / subdomain-provider abuse (`*.pages.dev`, `*.workers.dev`, `*.web.app`, `*.vercel.app`, `*.github.io`, blogspot …) | `tldextract(include_psl_private_domains=True)` → `is_private`; plus explicit list (§A.5) | Interisle 2025: subdomain providers top-10; Cloudflare `pages.dev/workers.dev/trycloudflare.com/r2.dev` phishing attacks +980% YoY — https://domainnamewire.com/wp-content/Interisle_Phishing-Landscape-2025.pdf ; subdomain-reseller attacks doubled to 432,990 (May 2025–Apr 2026) — https://www.cybercrimeinfocenter.org/phishing-activity-year-over-year-numbers-may-april-2026 | +15 (+25 if brand keyword also present) |
| 14 | Excessive subdomain depth (≥4 labels before registrable domain) or very long hostname (>50 chars), many hyphens/digits | Count labels | Lexical feature (Ma et al.) | +5 to +10 |
| 15 | `http://` (no TLS) for a page asking for login/payment | Scheme | Weak alone (TLS is free; phishing uses HTTPS widely) | +5 |
| 16 | Non-standard port (`:8080`, `:8443`, etc.) | `urlsplit().port` | Lexical feature | +5 |
| 17 | **Trust** signal: registrable domain under `.bank.in`, `.gov.in`, `.nic.in` (and exact match with brand map) | `tldextract` suffix | `.bank.in` limited to RBI-regulated banks via IDRBT (§A.6); `gov.in` limited to govt entities via NIC registry — https://registry.gov.in/registration_guidelines.php | −30 (never below "Caution" if TI hit) |

Note on parser differentials: Python `urlsplit()` "do[es] not perform validation of inputs" and pre-3.11.4 versions mis-parsed URLs with leading blanks (CVE-2023-24329, blocklist bypass) — https://kb.cert.org/vuls/id/127587 , https://thehackernews.com/2023/08/new-python-url-parsing-flaw-enables.html. **Strip whitespace/control chars, normalise `\` → `/`, lowercase host, IDNA-decode, and run on Python ≥ 3.12.4** before any signal evaluation.

### A.1 Homoglyph / IDN / Unicode confusables

- **UTS #39 (Unicode Security Mechanisms)** current version 18.0.0, Revision 34, dated 2026-08-27 — https://www.unicode.org/reports/tr39/
  - `skeleton(X)` = `bidiSkeleton(LTR, X)`; internalSkeleton: (1) NFD, (2) remove `Default_Ignorable_Code_Point` chars, (3) replace each char with its prototype from `confusables.txt`, (4) NFD again. Two strings are confusable iff skeletons are equal — https://www.unicode.org/reports/tr39/
  - Data files: https://www.unicode.org/Public/security/latest/ (versioned: https://www.unicode.org/Public/18.0.0/security/). Skeletons are **not stable across Unicode versions** → pin the file version and precompute brand skeletons at build time — https://www.unicode.org/reports/tr39/
  - Skeletons are for comparison only, "should definitely not be used as a 'normalization'" — https://www.unicode.org/reports/tr39/
  - Restriction levels (ASCII-Only → Single Script → Highly Restrictive → Moderately Restrictive …); mixed-script detection via Script_Extensions intersection; Cyrillic label may be fine under `.ru` but suspicious under `.com` — https://www.unicode.org/reports/tr39/
- **Chrome's IDN policy** (good blueprint to copy): show punycode if the label fails "Highly Restrictive" mixed-script check (with extra Latin restriction: Latin/Cyrillic/Greek can't mix), mixes numbering systems, or its skeleton matches a top domain; plus a full-page lookalike interstitial — https://chromium.googlesource.com/chromium/src/+/main/docs/idn.md . Chrome adds extra mappings beyond confusables.txt such as ł→l, ø→o, đ→d, [кĸκ]→k, п→n — https://codereview.chromium.org/2784933002/ (historical review; verify current list in `idn_spoof_checker.cc`).
- Practical rule for QR Shield:
  1. Host → `idna.decode()` (UTS-46) to get Unicode labels.
  2. If any label is non-ASCII: flag "IDN"; compute mixed-script; compute skeleton of registrable label; if skeleton ∈ `{skeleton(b) for b in brand_labels}` and domain ∉ brand official list → **lookalike** (high).
  3. Also compute skeleton for ASCII-only lookalikes like `rn`→`m`, `0`→`o`, `1`→`l` (confusables.txt includes `rn`↔`m`-type mappings only partially; add a small custom ASCII map: `0→o, 1→l, rn→m, vv→w, cl→d`).

### A.2 Typosquatting (edit distance)

- Use **Damerau-Levenshtein** (insert/delete/substitute/transpose) on the registrable label (e.g. `onlinesbi` vs `onlinesbl`), threshold ≤ 1 for labels ≤ 6 chars, ≤ 2 for longer. RapidFuzz provides `rapidfuzz.distance.DamerauLevenshtein` (C++ backed; v3.14.6 released 2026-08-30) — https://pypi.org/project/rapidfuzz/ , https://github.com/rapidfuzz/RapidFuzz
- Also check combo-squatting (brand + keyword: `sbi-kyc-update.com`, `hdfc-rewards.in`) by token containment, and `dnstwist`-style permutations for test-data generation — https://pypi.org/project/dnstwist/ (v20250130).
- Evidence: Agten et al., NDSS 2015 — tracked typo domains of top-500 sites for 7 months; ~95% of them actively targeted — https://www.ndss-symposium.org/ndss2015/ndss-2015-programme/seven-months-worth-mistakes-longitudinal-study-typosquatting-abuse/

### A.3 Suspicious TLDs (current data)

**Most current dataset — CybercrimeInfoCenter/Interisle, May 1 2025 – Apr 30 2026** (min 30k domains in TLD) — https://www.cybercrimeinfocenter.org/phishing-activity-in-tlds-may-april-2026

| Rank | By phishing score (per-capita) | Score | By raw count | Count |
|---|---|---|---|---|
| 1 | .xin | 5,910.0 | .com | 869,180 |
| 2 | .win | 1,640.7 | .top | 375,514 |
| 3 | .icu | 1,607.0 | .cn | 167,651 |
| 4 | .garden | 1,567.7 | .pro | 130,945 |
| 5 | .cfd | 1,387.4 | .info | 99,602 |
| 6 | .pro | 1,200.1 | .xyz | 93,987 |
| 7 | .help | 1,058.5 | .vip | 83,816 |
| 8 | .mom | 996.9 | .shop | 79,625 |
| 9 | .rest | 981.0 | .cc | 77,660 |
| 10 | .mobi | 845.1 | .icu | 74,786 |
| 11 | .qpon | 819.8 | .cfd | 70,944 |
| 12 | .live | 739.8 | .sbs | 63,518 |
| 13 | .ink | 718.4 | .net | 56,360 |
| 14 | .best | 706.6 | .online | 47,376 |
| 15 | .lat | 664.5 | .jp | 46,845 |
| 16 | .cyou | 661.6 | .bond | 41,594 |
| 17 | .top | 596.1 | .live | 41,523 |
| 18 | .wang | 540.8 | .click | 35,653 |
| 19 | .life | 525.9 | .org | 35,176 |
| 20 | .homes | 522.8 | .xin | 35,077 |

(.com score = 53.7 for comparison.)

**Interisle Phishing Landscape 2025** (May 2024–Apr 2025, released 2025-09-09) — https://interisle.net/PhishingLandscape2025 , PDF https://domainnamewire.com/wp-content/Interisle_Phishing-Landscape-2025.pdf :
- Top by score: .xin (10,810.2), .bond (1,759.0), .help (1,077.7), .win (796.1), .cfd (747.8). Top by count: .com 455,297; .top 187,749; .bond 79,875; .xyz 73,509; .shop 50,052.
- 5-year top-score history includes .cyou, .bar, .best, .casa, .buzz, .support, .shop, .work, .live, .rest, .ml, .lol, .top, .sbs.
- Maliciously-registered share: new gTLDs 87%, .com/.net 67%, ccTLDs 60%.
- 37% of phishing domains bought via bulk registration; new gTLDs priced < US$2 had the highest scores — https://domainnamewire.com/2025/09/11/report-names-commonly-used-tlds-for-phishing-attacks/

**Spamhaus**: Oct 2024–Mar 2025: 2.9M malicious domains, ".top remains a hotspot" — https://www.spamhaus.org/resource-hub/domain-reputation/domain-reputation-update-oct-2024-mar-2025/ ; Apr–Sep 2025: domain listings +48.3%, .top (+94%) and .xyz (+103%) among fastest-growing — https://www.spamhaus.org/resource-hub/domain-reputation/domain-reputation-update-april-september-2025/ . A secondary summary of the Oct 2025–Mar 2026 update cites new-domain churn .bond 98.6%, .lol 71.7%, .cyou 56.3%, .sbs 52.6%, .click 45.3%, .cfd 42.8% — https://webhosting.today/2026/07/09/which-top-level-domains-are-worth-carrying-the-abuse-data-most-registrars-never-book/ (unverified against Spamhaus PDF).

Freenom ccTLDs (.tk .ml .ga .cf .gq) stopped taking registrations after Freenom was sued; still seen in old lists — Interisle PDF above.

**Ready-to-paste suspicious TLD list (Python):**

```python
# Tier 1: highest per-capita phishing scores 2024-2026 (Interisle / CybercrimeInfoCenter) -> +20
SUSPICIOUS_TLDS_T1 = {
    "xin", "win", "icu", "garden", "cfd", "help", "mom", "rest", "qpon", "bond",
    "cyou", "sbs", "lol", "best", "lat", "wang", "homes", "ink", "click", "buzz",
    "bar", "casa", "support", "monster", "pics", "top", "vip",
}
# Tier 2: high volume / elevated score -> +10
SUSPICIOUS_TLDS_T2 = {
    "pro", "live", "life", "mobi", "xyz", "shop", "online", "site", "store", "cc",
    "info", "cn", "today", "work", "fyi", "zone", "digital", "finance", "link", "club",
    "space", "website", "fun", "cam", "run", "beauty", "hair", "skin", "quest", "boats",
}
# Legacy Freenom ccTLDs (registrations stopped; still appear in old campaigns) -> +10
SUSPICIOUS_TLDS_LEGACY = {"tk", "ml", "ga", "cf", "gq"}
```

(Tier-2 entries `site, store, fun, space, website, link, club, cam, run, beauty, hair, skin, quest, boats, digital, finance, fyi, zone, work` are drawn from the Interisle 5-year lists and common blocklists; the 2026 table above is the strongest evidence — keep weights low for Tier 2.)

### A.4 URL shorteners and dynamic-QR redirectors

- Maintained list: **PeterDaveHello/url-shorteners** — 1,465-line list, CC-BY-SA-4.0, last push 2026-09-06 — https://github.com/PeterDaveHello/url-shorteners (raw: https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/master/list) **[probe 2026-10-09]**. Bundle a snapshot; refresh weekly.
- goo.gl: Google kept actively-used goo.gl links working; only links flagged as inactive in late 2024 stopped working after 2025-08-25 — https://ppc.land/google-changes-course-on-goo-gl-shutdown-preserves-actively-used-links/ , https://developers.googleblog.com/2018/03/transitioning-google-url-shortener.html
- **Dynamic QR generators** act like shorteners (QR encodes a redirect URL, destination can be changed after printing) — treat as shortener + expand.

**Ready-to-paste shortener list** (all present in PeterDaveHello list unless marked `*`, checked **[probe 2026-10-09]**):

```python
URL_SHORTENERS = {
    # global
    "bit.ly", "bitly.com", "tinyurl.com", "is.gd", "v.gd", "t.ly", "cutt.ly", "rb.gy",
    "shorturl.at", "shorturl.asia", "s.id", "ow.ly", "buff.ly", "rebrand.ly", "t.co",
    "goo.gl", "tiny.cc", "surl.li", "lnkd.in", "qr.ae", "u.to", "clck.ru", "da.gd",
    "dub.sh", "short.gy", "tny.im", "inx.lv", "tiny.one", "bl.ink", "zpr.io", "urlz.fr",
    "amzn.to",
    "bit.do", "shrtco.de", "spoo.me",                         # * not in list; add manually
    # dynamic-QR redirectors
    "qrco.de",
    "l.ead.me", "me-qr.com", "qr-code-generator.com", "qr.codes", "qrfy.io", "scnv.io",  # * manual
    # app/deep-link redirectors frequently abused
    "page.link", "app.goo.gl", "linktr.ee", "wa.me", "t.me",   # * manual; wa.me/t.me = messaging, flag "opens chat"
}
```

### A.5 Free hosting / subdomain-provider abuse

Interisle 2025 Top-10 subdomain providers by phishing attacks (May 2024–Apr 2025) — https://domainnamewire.com/wp-content/Interisle_Phishing-Landscape-2025.pdf:

| Rank | Provider | Domains | 2025 attacks | Change |
|---|---|---|---|---|
| 1 | Cloudflare | pages.dev, workers.dev, trycloudflare.com, r2.dev | 43,857 | +157% (some sub-rows +980%) |
| 2 | Webflow | webflow.io | 33,418 | new entrant |
| 3 | Google | blogspot.com/blogspot.xx (66 ccTLDs), web.app, firebaseapp.com, page.link, googleapis.com, appspot.com, cloudfunctions.net, (sites.google.com, forms) | ~30,703 | |
| 4 | Weebly | weeblysite.com, weebly.com | 29,934 | +21% |
| 5 | GitBook | gitbook.io | 21,981 | new |
| 6 | Vercel | vercel.app (case study: `v3-pancakeswap.vercel.app`, `violation-policy-meta-…vercel.app`) | 21,442 | |
| 7 | GitHub | github.io | ~9,653 | |
| 8 | Duck DNS | duckdns.org | | |
| 9 | CentralNIC | ru.com, sa.com, uk.com, us.com, eu.com, de.com, cn.com, jp.com, br.com … | | |

(The table columns in the PDF text layer are mis-aligned; counts per row are approximate. 89% of subdomain-provider attacks were on just ten providers.) IPFS gateways (`dweb.link`, `ipfs.io`, `cf-ipfs.com`, `flk-ipfs.xyz`, `infura-ipfs.io`) also hosted phishing — same PDF.

Live evidence: OpenPhish feed today contains `…pages.dev`, `…s3.us-east-2.amazonaws.com`; PhishTank today contains `…z5.web.core.windows.net` **[probe 2026-10-09]**.

PSL note: most of these are **private** PSL suffixes (verified in PSL: `pages.dev`, `workers.dev`, `trycloudflare.com`, `r2.dev`, `web.app`, `firebaseapp.com`, `appspot.com`, `blogspot.com`, `github.io`, `vercel.app`, `netlify.app`, `ngrok.app`, `ngrok-free.app`, `ngrok.io`, `webflow.io`, `gitbook.io`, `duckdns.org`, `herokuapp.com`, `azurewebsites.net`, `web.core.windows.net`, `s3.amazonaws.com`, `onrender.com`, `replit.app`, `repl.co`, `surge.sh`, `wixsite.com`, `framer.app`, `fly.dev`, `translate.goog`) **[probe of https://publicsuffix.org/list/public_suffix_list.dat, 2026-10-09]**. `weebly.com`, `000webhostapp.com`, `glitch.me`, `sites.google.com`, `forms.gle`, `docs.google.com/forms` are **not** PSL suffixes → keep an explicit list.

```python
FREE_HOSTING_SUFFIXES = {
    "pages.dev", "workers.dev", "trycloudflare.com", "r2.dev",
    "web.app", "firebaseapp.com", "appspot.com", "cloudfunctions.net", "page.link",
    "blogspot.com", "sites.google.com", "forms.gle", "docs.google.com", "script.google.com",
    "storage.googleapis.com",
    "vercel.app", "netlify.app", "github.io", "gitbook.io", "webflow.io",
    "weebly.com", "weeblysite.com", "wixsite.com", "framer.app", "glitch.me",
    "000webhostapp.com", "onrender.com", "replit.app", "repl.co", "herokuapp.com",
    "fly.dev", "surge.sh", "azurewebsites.net", "web.core.windows.net",
    "s3.amazonaws.com", "amplifyapp.com", "duckdns.org",
    "ngrok.io", "ngrok.app", "ngrok-free.app", "ngrok-free.dev", "loca.lt", "serveo.net",
    "ipfs.io", "dweb.link", "cf-ipfs.com", "flk-ipfs.xyz", "infura-ipfs.io",
    "translate.goog",
}
```

### A.6 India: trust suffixes and brand → official domains

**`.bank.in`** — RBI circular RBI/2025-26/28 (2025-04-22): banks must register `.bank.in` via **IDRBT** (registrar authorised by NIXI/MeitY) and complete migration by **31 Oct 2025** — https://www.business-standard.com/amp/finance/news/rbi-asks-banks-to-complete-migration-to-bank-in-domain-by-october-31-2025-125042201515_1.html , https://www.businesstoday.in/amp/personal-finance/banking/story/rbi-mandates-banks-to-adopt-bankin-domains-for-safer-digital-access-check-faqs-473150-2025-04-22 . Status: "over 400 banks" migrated; all major PSU/private banks done though some missed the deadline — https://thepaypers.com/fraud-and-fincrime/news/over-400-indian-banks-migrate-to-bankin-domain . ICICI's NSE filing: domain changed from icicibank.com to icici.bank.in; net banking at retailnetbanking.icici.bank.in — https://nsearchives.nseindia.com/corporate/ICICI2022_28102025191027_NSEBSE.pdf . Early live list (icici, sbi, rbl, hdfc .bank.in) — https://www.digit.in/features/general/indian-banks-begin-switch-to-bank-in-domain-to-meet-rbis-cybersecurity-deadline.html . `.fin.in` reportedly planned for NBFCs — https://law.asia/rbi-domain-migration-mandate/ (status unverified). Both `bank.in` and `fin.in` are already ICANN-section PSL suffixes **[probe PSL 2026-10-09]**, so `tldextract` returns `sbi.bank.in` as the registrable domain.

**`.gov.in`** — NIC registry; eligible: central/state ministries & departments, attached offices, local self-govts; individuals ineligible; banks/PSU banks not eligible except exceptional sanction — https://registry.gov.in/registration_guidelines.php . `.nic.in` also NIC-operated (PSL suffix).

**Brand map** (✓ = redirect/DNS verified **[probe 2026-10-09]**; legacy domains kept because old QR codes/links still point there and redirect):

```python
INDIAN_BRANDS = {
  # --- Banks (new .bank.in primary; legacy still redirects) ---
  "SBI":            ["sbi.bank.in", "onlinesbi.sbi.bank.in", "sbi.co.in", "onlinesbi.sbi", "sbi"],  # onlinesbi.sbi -> onlinesbi.sbi.bank.in (307) ✓; .sbi is SBI's brand gTLD
  "HDFC Bank":      ["hdfc.bank.in", "hdfcbank.com", "hdfcbank.bank.in"],  # hdfcbank.com -> www.hdfc.bank.in ✓; hdfcbank.bank.in resolves (defensive)
  "ICICI Bank":     ["icici.bank.in", "icicibank.com"],           # -> www.icici.bank.in ✓ (+NSE filing)
  "Axis Bank":      ["axis.bank.in", "axisbank.com"],             # -> www.axis.bank.in ✓
  "Kotak Mahindra": ["kotak.bank.in", "kotak.com"],               # kotak.bank.in live ✓; kotak.com still serves
  "PNB":            ["pnb.bank.in", "pnbindia.in"],               # -> pnb.bank.in ✓
  "Bank of Baroda": ["bankofbaroda.bank.in", "bankofbaroda.in", "bankofbaroda.co.in"],  # -> bankofbaroda.bank.in ✓
  "Canara Bank":    ["canarabank.bank.in", "canarabank.com", "canarabank.in"],         # -> canarabank.bank.in ✓
  "Union Bank":     ["unionbankofindia.bank.in", "unionbankofindia.co.in"],            # ✓
  "Bank of India":  ["bankofindia.bank.in", "bankofindia.co.in"],                      # DNS ✓
  "Indian Overseas":["iob.bank.in", "iob.in"],                                         # ✓
  "Indian Bank":    ["indianbank.bank.in", "indianbank.in"],                           # ✓
  "Central Bank":   ["centralbank.bank.in", "centralbankofindia.co.in"],               # ✓
  "UCO Bank":       ["uco.bank.in", "ucobank.com"],                                    # uco.bank.in ✓
  "Yes Bank":       ["yes.bank.in", "yesbank.in"],                                     # ✓
  "IDFC First":     ["idfcfirst.bank.in", "idfcfirstbank.com"],                        # ✓
  "IndusInd":       ["indusind.bank.in", "indusind.com"],                              # ✓
  "Federal Bank":   ["federal.bank.in", "federalbank.co.in"],                          # DNS ✓ (bot-wall)
  "RBL Bank":       ["rbl.bank.in", "rblbank.com"],
  "IDBI Bank":      ["idbi.bank.in", "idbibank.in"],
  "Bandhan Bank":   ["bandhan.bank.in", "bandhanbank.com"],
  "AU Small Fin.":  ["au.bank.in", "aubank.in"],
  "IPPB":           ["ippbonline.bank.in", "ippbonline.com"],                          # DNS ✓
  "Airtel Payments Bank": ["airtelpayments.bank.in", "airtel.bank.in"],               # airtel.in/bank -> airtelpayments.bank.in ✓
  "Paytm Payments Bank":  ["paytm.bank.in", "paytmbank.com"],                         # ✓
  "RBI":            ["rbi.org.in"],
  # --- UPI / payments ---
  "Paytm":          ["paytm.com", "paytm.in"],
  "PhonePe":        ["phonepe.com"],
  "Google Pay":     ["pay.google.com", "wallet.google.com", "gpay.app.goo.gl"],  # pay.google.com -> wallet.google.com ✓
  "BHIM / NPCI":    ["bhimupi.org.in", "npci.org.in"],
  "BharatPe":       ["bharatpe.com"], "MobiKwik": ["mobikwik.com"], "CRED": ["cred.club"],
  # --- Government ---
  "Income Tax":     ["incometax.gov.in"],                 # ✓
  "UIDAI/Aadhaar":  ["uidai.gov.in", "myaadhaar.uidai.gov.in"],   # ✓
  "EPFO":           ["epfo.gov.in", "epfindia.gov.in", "unifiedportal-mem.epfindia.gov.in"],  # epfindia.gov.in -> epfo.gov.in ✓
  "DigiLocker":     ["digilocker.gov.in"],                # ✓
  "GST":            ["gst.gov.in"],                       # ✓
  "Parivahan/e-Challan": ["parivahan.gov.in", "echallan.parivahan.gov.in"],  # ✓
  "India Post":     ["indiapost.gov.in"],                 # ✓
  "IRCTC":          ["irctc.co.in"],
  "Cybercrime (1930)": ["cybercrime.gov.in"], "Sanchar Saathi": ["sancharsaathi.gov.in"],
  "LIC":            ["licindia.in"],
  # --- Commerce / telecom ---
  "Amazon":         ["amazon.in", "amazon.com", "amzn.to", "amzn.in"],
  "Flipkart":       ["flipkart.com", "fkrt.it"],
  "Myntra": ["myntra.com"], "Meesho": ["meesho.com"], "Swiggy": ["swiggy.com"], "Zomato": ["zomato.com"],
  "Jio":            ["jio.com"],
  "Airtel":         ["airtel.in"],
  # --- Electricity (common "bill disconnection" lures) ---
  "BSES (Rajdhani/Yamuna)": ["bsesdelhi.com"],
  "MSEDCL (MSEB)":  ["mahadiscom.in"],
  "Adani Electricity": ["adanielectricity.com"],
  "Tata Power":     ["tatapower.com", "tatapower-ddl.com"],
}
# Brand keywords for "brand-in-subdomain/path" detection (lowercase tokens):
BRAND_KEYWORDS = ["sbi","onlinesbi","yono","hdfc","icici","axis","kotak","pnb","baroda","bob","canara",
  "unionbank","indusind","idfc","yesbank","federal","paytm","phonepe","gpay","googlepay","bhim","npci","upi",
  "irctc","indiapost","incometax","itr","aadhaar","uidai","epfo","pf","digilocker","gst","parivahan","echallan",
  "challan","rto","vahan","amazon","flipkart","jio","airtel","bses","mseb","mahadiscom","adani","tatapower","kyc","rbi"]
```

Unverified items (no live probe): `gpay.app.goo.gl`, `amzn.in`, `fkrt.it`, `paytm.in`, `rblbank.com`, `idbibank.in`, `bandhanbank.com`, `aubank.in`, `canarabank.in`, `bankofbaroda.co.in` — verify before shipping (or keep only in an "allow-but-don't-boost" list).

---

## B. Free threat intelligence sources

### B.0 Status matrix (probed 2026-10-09)

| Source | Key needed? | Works now? | Limits | Offline cache? | Licence |
|---|---|---|---|---|---|
| Google Safe Browsing v4 Lookup | **Yes** (Cloud API key) | Yes (docs live; v5 also published) | Per-project default quota (Console); 500 URLs/request | Cache per `cacheDuration`; Update API for local hash-prefix DB | **Non-commercial only**; commercial → Web Risk |
| Google Web Risk | Yes (GCP billing) | Yes | `uris.search` free 100k calls/month, then $0.50/1k; 6000 SearchUris/min | Update API (`computeDiff` free) | Commercial OK |
| PhishTank | Not for CSV download / checkurl (rate-limited); **new registrations closed** | Yes **[probe]**: CSV 13.2 MB, checkurl JSON OK | checkurl: `X-Request-Limit: 250` per 300 s **[probe]** | Yes (hourly CSV) | Free incl. commercial, attribution |
| OpenPhish Community | No | Yes, ~300 URLs **[probe]** | Updated every 12 h | Yes | **Non-commercial only** |
| URLhaus (abuse.ch) | **API: yes (Auth-Key since 30 Jun 2025)**; bulk downloads: no | API w/o key → 401 **[probe]**; `csv_recent` 7.6 MB, `text_online` 2.8 MB 200 OK **[probe]** | Not documented | Yes | abuse.ch ToS (free, CC0-style for most data — verify) |
| PhishStats | Optional (`X-API-Key`) | Yes **[probe]** | Page: anon 50 req/day/IP; headers show 20/min | Partially | Not stated |
| Phishing.Database | No | Yes via GitHub raw **[probe]**; phish.co.za mirror returned 503 | — | Yes (11 MB ACTIVE domains) | MIT |
| RDAP (rdap.org / IANA bootstrap) | No | Yes; `.in` supported **[probe]** | rdap.org: 10 req / 10 s | Cache bootstrap JSON + per-domain results | Registry ToS |
| urlscan.io | Yes (free account) | — | Free: 5,000 public, 1,000 unlisted, 50 private scans/day; 1,000 searches; 10,000 results/day | Not a feed | ToS; no bulk scraping |
| Cloudflare Radar URL Scanner | Yes (CF account + API token) | — | Free: 5,000 public scans/month, 1 req / 10 s, no unlisted | No | CF ToS |

### B.1 Google Safe Browsing v4 Lookup API

- Endpoint `POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=API_KEY`; up to **500** URLs per request; empty `{}` when no match — https://developers.google.com/safe-browsing/v4/lookup-api
- Request:

```json
{
  "client": {"clientId": "qrshield", "clientVersion": "0.1.0"},
  "threatInfo": {
    "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
    "platformTypes": ["ANY_PLATFORM"],
    "threatEntryTypes": ["URL"],
    "threatEntries": [{"url": "http://example-site-a.net/"}]
  }
}
```

- Response (match): `{"matches":[{"threatType":"MALWARE","platformType":"WINDOWS","threatEntryType":"URL","threat":{"url":"..."},"cacheDuration":"300.000s"}]}` — https://developers.google.com/safe-browsing/v4/lookup-api
- Usage: "for non-commercial use only (meaning 'not for sale or revenue generating purposes')… If you need a solution for commercial purposes, please refer to Web Risk"; "There is no cost"; default quota per project, increase via Console — https://developers.google.com/safe-browsing/v4/usage-limits
- v5 (`urls.search`, `hashes.search`, "check-by-default" with a Global Cache) is documented alongside v4; no v4 sunset date found — https://developers.google.com/safe-browsing/reference
- Web Risk (commercial): Lookup `uris.search` free up to 100,000 calls/month then $0.50 / 1,000; `computeDiff` free — https://cloud.google.com/web-risk/pricing ; quotas 6000 SearchUris/min — https://docs.cloud.google.com/web-risk/quotas
- Hackathon: GSB v4 is fine (non-commercial demo). If QR Shield is commercialised, switch to Web Risk.

### B.2 PhishTank (Cisco Talos)

- Registration page: "New user registration temporarily disabled." — https://phishtank.org/register.php **[probe 2026-10-09]**. Closed since 2020 — https://en.wikipedia.org/wiki/PhishTank
- Still usable without key **[probe]**:
  - Bulk: `https://data.phishtank.com/data/online-valid.csv` → 302 to signed CDN URL, 13.2 MB, columns `phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target`. Also `.json`. Use a descriptive User-Agent (`phishtank/<yourname>`).
  - Lookup: `POST https://checkurl.phishtank.com/checkurl/` with `url=<urlencoded>&format=json` → `{"results":{"url":..., "in_database":true, "phish_id":..., "verified":false, "valid":false}}`; rate-limit headers `X-Request-Limit: 250`, `X-Request-Limit-Interval: 300 Seconds`.
- Data licence: free incl. commercial use under restrictive licence (attribution) — https://en.wikipedia.org/wiki/PhishTank ; privacy page notes API keys tied to registration — https://data.phishtank.com/privacy.php
- Recommendation: download CSV hourly → SQLite table `ti_urls(source, url, host, first_seen)`.

### B.3 OpenPhish Community feed

- `https://openphish.com/feed.txt` → 302 to `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt` **[probe]**; ~300 URLs, plain text one per line.
- "Updated every 12 hours", "Non-commercial use only", Terms: https://openphish.com/terms.html — https://github.com/openphish/public_feed
- Paid tiers update every 5 min — https://www.wiz.io/api/md/academy/threat-intel/must-follow-threat-intel-feeds

### B.4 URLhaus (abuse.ch)

- **Auth-Key mandatory since 30 June 2025** for the API — https://xsoar.pan.dev/docs/reference/integrations/feed-ur-lhaus ; confirmed: API without key returns `401 {"error":"Unauthorized"}` **[probe]**. Free key: https://auth.abuse.ch/ (same key for MalwareBazaar/ThreatFox).
- Endpoints (POST, header `Auth-Key`) — https://urlhaus-api.abuse.ch/ :

```bash
curl -H "Auth-Key: $KEY" -X POST https://urlhaus-api.abuse.ch/v1/url/  --data-urlencode "url=http://example.com/x"
curl -H "Auth-Key: $KEY" -X POST https://urlhaus-api.abuse.ch/v1/host/ -d "host=example.com"
```

  Response fields: `query_status` (`ok`, `no_results`, `invalid_url`…), `url_status` (`online/offline/unknown`), `threat` (e.g. `malware_download`), `tags`, `blacklists` (SURBL/Spamhaus DBL).
- **Bulk downloads still keyless** **[probe]**: `https://urlhaus.abuse.ch/downloads/csv_recent/` (last 30 days, 7.6 MB), `https://urlhaus.abuse.ch/downloads/text_online/` (online URLs, 2.8 MB). Good for offline matching (URLhaus is malware-distribution focused → catches APK/EXE payload URLs).

### B.5 PhishStats

- API `https://api.phishstats.info/api/phishing?_sort=-date&_size=…` works anonymously **[probe]**; response includes `url, ip, countrycode, asn, title, date, score, hash`.
- Limits: site says anon 50 req/day/IP, free key 150/day; DB updates every 90 min — https://phishstats.info/ . Live headers show `X-RateLimit-Limit-Minute: 20` **[probe]** — conflict; assume the stricter daily limit.
- Legacy CSV `https://phishstats.info:2096/phish_score.csv` did not respond **[probe]** → treat as discontinued.

### B.6 Phishing.Database (formerly mitchellkrogza/Phishing.Database)

- Repo moved to **Phishing-Database/Phishing.Database** (MIT, last push 2026-10-02) **[GitHub API probe]** — https://github.com/Phishing-Database/Phishing.Database
- Files: `phishing-domains-ACTIVE.txt` (11 MB), `phishing-domains-NEW-today.txt`, `phishing-links-ACTIVE-*.txt` via `https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/<file>` (200 OK **[probe]**); mirror `https://phish.co.za/latest/…` returned 503 **[probe]**. Validated with PyFunceble. Expect higher false-positive rate (aggregated; test against brand allowlist).

### B.7 RDAP (domain age)

- IANA bootstrap `https://data.iana.org/rdap/dns.json` (publication 2026-09-30) lists **`in` → `https://rdap.nixiregistry.in/rdap/`**; `com`/`net` Verisign, `xyz` CentralNic, `top` ZDNS, `app`/`dev` Google; **`io` not listed** — https://data.iana.org/rdap/dns.json
- `https://rdap.org/domain/sbi.co.in` → 302 to NIXI RDAP **[probe]**; response `events`: `{"eventAction":"registration","eventDate":"2002-10-30T19:05:33.000Z"}`, plus `expiration`, `last changed`, `transfer` **[probe]**.
- rdap.org: redirect-only bootstrap; limit 10 requests / 10 s, 429 beyond; recommends direct IANA bootstrap for volume — https://about.rdap.org/
- Implementation: cache `dns.json` locally (refresh daily), map TLD (longest match) → base URL, `GET {base}domain/{registrable}`, parse `events`. Cache result per domain in SQLite (age doesn't change). Python helper: `whoisit` (RDAP client, v4.0.5, 2026-09-21) — https://pypi.org/project/whoisit/ ; or ~30 lines with httpx. Fallback for TLDs without RDAP (e.g. `.io`): treat as "unknown" (no penalty) or WHOIS via `python-whois`.

### B.8 urlscan.io / Cloudflare Radar

- urlscan.io: `POST https://urlscan.io/api/v1/scan/` with `API-Key` header, body `{"url": "...", "visibility": "public|unlisted|private"}`; poll `GET /api/v1/result/{uuid}/` (404 until ready) — https://urlscan.io/docs/api/ ; free plan 50 private / 1,000 unlisted / 5,000 public scans/day, 1,000 searches, 10,000 result calls/day — https://urlscan.io/pricing/ . **Use `private`/`unlisted`** — public scans would leak users' scanned URLs (could include UPI handles / tokens).
- Cloudflare URL Scanner: account-scoped `…/accounts/{id}/urlscanner/v2/scan`; free 5,000 public scans/month, 1 per 10 s, **no unlisted** on free — https://developers.cloudflare.com/security-center/investigate/scan-limits/ . Not suitable for private user URLs on free tier.

---

## C. Python libraries & SSRF-safe fetching

### C.1 Library choices

| Need | Library | Version / status | Notes |
|---|---|---|---|
| Registrable domain / suffix | **tldextract** | 5.4.0, 2026-10-03, BSD-3 | `TLDExtract(suffix_list_urls=())` → no network, uses bundled snapshot; cache in `$HOME/.cache/python-tldextract` or `TLDEXTRACT_CACHE`/`cache_dir`; `include_psl_private_domains=True` makes `x.blogspot.com` → suffix `blogspot.com`, `is_private=True`; attribute `top_domain_under_public_suffix` — https://github.com/john-kurkowski/tldextract |
| IDNA / punycode | **idna** | 3.20, 2026-09-17 | IDNA2008 + UTS-46 (`idna.decode`, `uts46=True`) — https://pypi.org/project/idna/ |
| Confusables | **Own TR39 skeleton** over pinned `confusables.txt` (recommended) | — | ~40 lines; full control & versioning. `confusable_homoglyphs` 3.3.1 (2024-01-30) — GitHub repo **archived** (vhf/confusable_homoglyphs), ~406k downloads/week, uses block-based detection not skeletons — https://pypi.org/project/confusable-homoglyphs/ . `confusables` 1.2.0 (2021) stale — https://pypi.org/project/confusables/ . `disarm` 0.17.2 (2026-09-26, Rust core, TR39) is new/low adoption — https://pypi.org/project/disarm/ |
| Edit distance | **rapidfuzz** | 3.14.6, 2026-08-30, MIT | `from rapidfuzz.distance import DamerauLevenshtein` — https://github.com/rapidfuzz/RapidFuzz |
| HTTP | **httpx** | 0.28.1 (2024-12-06), last commit 2026-02 — slow but stable | No redirects by default ("Unlike requests, HTTPX does not follow redirects by default") — https://www.python-httpx.org/compatibility/ ; `extensions={"sni_hostname": host}` to connect to a pinned IP — https://www.python-httpx.org/advanced/extensions/ |
| RDAP | httpx + IANA bootstrap, or `whoisit` 4.0.5 | | |
| Typo generation (tests) | `dnstwist` 20250130 | | |

### C.2 TR39 skeleton sketch

```python
import unicodedata
def load_confusables(path):  # https://www.unicode.org/Public/security/latest/confusables.txt
    m = {}
    for line in open(path, encoding="utf-8-sig"):
        line = line.split("#", 1)[0].strip()
        if not line: continue
        src, tgt, *_ = [f.strip() for f in line.split(";")]
        m[chr(int(src, 16))] = "".join(chr(int(c, 16)) for c in tgt.split())
    return m
def skeleton(s, CONF, DEFAULT_IGNORABLE):
    s = unicodedata.normalize("NFD", s)
    s = "".join(c for c in s if c not in DEFAULT_IGNORABLE)
    s = "".join(CONF.get(c, c) for c in s)
    return unicodedata.normalize("NFD", s)
```

(Default_Ignorable_Code_Point set comes from `DerivedCoreProperties.txt`; bidiSkeleton step can be skipped for LTR-only hostnames.)

### C.3 tldextract offline usage

```python
import tldextract
EXTRACT_ICANN = tldextract.TLDExtract(suffix_list_urls=())                                  # offline snapshot
EXTRACT_PRIV  = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
r = EXTRACT_PRIV("https://sbi-kyc.pages.dev/login")   # suffix 'pages.dev', is_private True -> free-hosting signal
EXTRACT_ICANN("https://onlinesbi.sbi.bank.in").top_domain_under_public_suffix  # 'sbi.bank.in'
```

Note: the bundled snapshot ages with the installed version; for fresh suffixes (`bank.in`, `fin.in` already present in PSL today) ship a periodically downloaded PSL file and pass it via `suffix_list_urls=["file:///…/public_suffix_list.dat"]` — https://github.com/john-kurkowski/tldextract

### C.4 SSRF best practices (backend fetches user-supplied URLs to expand redirects)

From OWASP SSRF Prevention Cheat Sheet ("Case 2: any external IP/domain") — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html :
1. Allow only `http`/`https`.
2. Resolve **all** A/AAAA records; reject if **any** is non-public.
3. "checking DNS answers separately does not prevent DNS rebinding" → connect to the **validated IP**, keep hostname for Host header/SNI/cert verification; apply policy to retries.
4. Disable redirect following in the client; validate each hop yourself.
5. Minimum deny set: 169.254.169.254 & metadata hosts, 127.0.0.0/8, 0.0.0.0/8, ::1, 10/8, 172.16/12, 192.168/16, fc00::/7, fe80::/10, 224.0.0.0/4, ff00::/8. "Deny-lists are bypass-prone."
6. Network layer: egress firewall / segregation.

Python specifics:
- Use `ipaddress.ip_address(x).is_global` (handles IPv4-mapped IPv6 via `ipv4_mapped`; 100.64.0.0/10 is neither private nor global → reject anything not `is_global`) — https://docs.python.org/3/library/ipaddress.html . Requires **Python ≥ 3.12.4** (CVE-2024-4032 fixed outdated IANA registry data in `is_private`/`is_global`) — https://stack.watch/vuln/CVE-2024-4032/ ; Python 3.13 further corrected ranges (192.0.0.0/24, 64:ff9b:1::/48, 2002::/16) — https://docs.python.org/3/library/ipaddress.html
- Also reject `is_multicast`, `is_reserved`, `is_unspecified`, `is_link_local`, `is_loopback` explicitly (belt and braces), and NAT64 `64:ff9b::/96` if the server is on a NAT64 network (this machine's resolver returned `64:ff9b::` addresses **[probe]**).
- Ports: allow only 80/443 (optionally 8080/8443 for expansion but never internal).
- Timeouts: connect 3 s, read 5 s, total ≤ 10 s; max 5 hops; read at most first 64–256 KB (`client.stream()` + byte counter); never execute JS; send `HEAD` first, fall back to `GET` with `Range: bytes=0-0` if HEAD is rejected.

```python
import socket, ipaddress, httpx
from urllib.parse import urlsplit, urljoin
def _public_ips(host, port):
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = {ipaddress.ip_address(i[4][0].split('%')[0]) for i in infos}
    if not ips or any(not ip.is_global or ip.is_multicast for ip in ips): raise ValueError("non-public")
    return sorted(ips, key=lambda ip: ip.version)
def expand(url, max_hops=5):
    hops = []
    with httpx.Client(follow_redirects=False, timeout=httpx.Timeout(5, connect=3), trust_env=False) as c:
        for _ in range(max_hops + 1):
            u = urlsplit(url.strip())
            if u.scheme not in ("http", "https"): raise ValueError("scheme")
            port = u.port or (443 if u.scheme == "https" else 80)
            if port not in (80, 443): raise ValueError("port")
            ip = _public_ips(u.hostname, port)[0]
            target = u._replace(netloc=(f"[{ip}]" if ip.version == 6 else str(ip)) + f":{port}").geturl()
            r = c.head(target, headers={"Host": u.hostname, "User-Agent": "QRShield/0.1"},
                       extensions={"sni_hostname": u.hostname})
            hops.append((url, r.status_code, str(ip)))
            loc = r.headers.get("location")
            if r.is_redirect and loc: url = urljoin(url, loc); continue
            return hops
    raise ValueError("too many redirects")
```

(Also handle `<meta http-equiv=refresh>` / JS redirects by **not** executing; report "page may redirect further".)

---

## D. Frontend QR libraries

### D.1 Comparison (npm weekly = 2026-10-01..07; GitHub data via API, 2026-10-09)

| Library | Latest release | Last commit (default branch) | npm weekly | Status / notes |
|---|---|---|---|---|
| **html5-qrcode** | 2.3.8 (2023-04-15) | 2025-12-01 (README) | 1.53 M | README: "The project is in maintenance mode until further notice" + "Looking for new owners"; BarcodeDetector support is "experimental… not recommended for production"; iOS ≥ 15.1; file scanning supported — https://github.com/mebjas/html5-qrcode . iOS PWA camera freezes reported with it (iOS 17.5.1) — https://bugs.webkit.org/show_bug.cgi?id=275527 , https://bugs.webkit.org/show_bug.cgi?id=273046 |
| **@zxing/library** | 0.23.0 (2026-04-29) | 2026-04-29 | 1.97 M | "Project in Maintenance Mode Only… changes are driven by contributed patches" — https://github.com/zxing-js/library . Pure-JS port; slower than WASM |
| **@zxing/browser** | 0.2.1 (2026-07-06) | 2026-07-06 ("Bumped peer-dep") | 1.32 M | Thin browser layer over @zxing/library — https://github.com/zxing-js/browser |
| **qr-scanner** (nimiq) | 1.4.2 (2022-11-23) | 2022-11-23 | 0.40 M | Uses native BarcodeDetector if available (15.3 kB) else WebWorker jsQR-derived engine (59.3 kB); `scanImage()` accepts File/Blob/canvas/URL — https://github.com/nimiq/qr-scanner . **No release for ~4 years**, 109 open issues |
| **jsQR** | 1.4.0 (2021-04-24) | 2021-08-24 | 3.37 M | Pure JS decoder on ImageData; no camera handling; unmaintained — https://github.com/cozmo/jsQR |
| **Native BarcodeDetector** | — | — | — | Chrome Android ≥ 83 ✓; desktop Chrome only macOS/ChromeOS (not Windows/Linux); Firefox ✗; Safari 17+ **behind "Shape Detection API" flag only**, iOS mirrors — MDN BCD https://raw.githubusercontent.com/mdn/browser-compat-data/main/api/BarcodeDetector.json ; experimental, secure context only — https://developer.mozilla.org/en-US/docs/Web/API/BarcodeDetector . Broken even with flag on iOS 18; still flagged in iOS 26 beta — https://bugs.webkit.org/show_bug.cgi?id=281848 |
| **zxing-wasm** (Sec-ant) | 3.1.5 (2026-10-06) | 2026-10-06 | 2.79 M | ZXing-C++ → WASM; `readBarcodes()` accepts Blob/File/ArrayBuffer/Uint8Array/ImageData; `zxing-wasm/reader` ≈1.04 MiB wasm; self-host via `prepareZXingModule({overrides:{locateFile}})` — https://github.com/Sec-ant/zxing-wasm |
| **barcode-detector** (Sec-ant) | 3.2.2 (2026-08-16) | 2026-08-16 | 2.33 M | Spec-compliant BarcodeDetector **polyfill/ponyfill** on zxing-wasm; `barcode-detector/polyfill` registers only if no native one exists; wasm defaults to jsDelivr — self-host via `prepareZXingModule` for offline PWA/CSP — https://github.com/Sec-ant/barcode-detector |
| React wrappers | `@yudiel/react-qr-scanner` 2.6.0 (2026-05-13, 263k/wk), `react-zxing` 3.0.0 (2026-06-01, 102k/wk) | | | Both depend on `barcode-detector` **[npm registry probe]** |

### D.2 Recommendation: **`barcode-detector` (polyfill) + own thin camera loop** (or `@yudiel/react-qr-scanner` if you want a ready React component)

Why:
1. **Actively maintained** (releases Aug–Oct 2026) and highest-momentum stack (zxing-wasm 2.8 M/wk, barcode-detector 2.3 M/wk), unlike html5-qrcode (maintenance mode, last release 2023), qr-scanner (2022) and jsQR (2021).
2. **Native where it exists, WASM elsewhere**: on Chrome Android (most Indian UPI users) the native, hardware-accelerated `BarcodeDetector` is used; on iOS Safari (no native API without flag, broken on iOS 18) and Windows Chrome / Firefox the ZXing-C++ WASM engine is used — same API everywhere.
3. **ZXing-C++ decoder** is more robust on damaged / low-contrast / inverted QR (sticker-over-sticker QR fraud) than JS ports; supports other formats if needed later.
4. **File/image upload** is trivial: `await detector.detect(await createImageBitmap(file))` (or pass the Blob) — covers "scan a screenshot of a QR from WhatsApp", which matters a lot in India.
5. **Offline PWA**: self-host the `.wasm` (Vite `?url` import + `prepareZXingModule({ overrides: { locateFile: () => wasmUrl } })`) and precache it with the service worker; no third-party CDN at runtime.

iOS reliability tips (library-independent; from WebKit bug reports): request camera from a user gesture; keep one `MediaStream` alive instead of restarting on route/hash changes in standalone PWA mode; listen for track `ended` and re-acquire; always offer **"Upload image"** fallback — https://bugs.webkit.org/show_bug.cgi?id=252465 , https://bugs.webkit.org/show_bug.cgi?id=282327 , https://developer.apple.com/forums/thread/724683

Fallback option if time is short: `qr-scanner` (simplest API, small, has `scanImage`) — accept that it's unmaintained.

---

## Uncertainties

1. **Spamhaus** per-TLD rankings for Apr–Sep 2025 and Oct 2025–Mar 2026 not read from the primary PDFs; churn figures come from a secondary blog.
2. **Interisle 2025 subdomain-provider table**: PDF text layer is column-misaligned; per-provider counts in §A.5 are approximate. Provider ranking order is reliable.
3. **No primary 2025–26 statistic on "time from registration to phishing use"** was found; the 32-day NRD guidance is from Unit 42 (2019). The 77% / ~74% "maliciously registered" figures are about registration intent, not age.
4. **PhishStats limits** conflict (50/day on site vs 20/min in headers). Legacy CSV endpoint appears dead.
5. **URLhaus/abuse.ch data licence** and API rate limits were not confirmed from abuse.ch's own ToS page.
6. **PhishTank keyless access** works today (CSV + checkurl) but is undocumented for unregistered users and could be tightened at any time.
7. **Safe Browsing v4 → v5**: no deprecation date found; v4 currently documented and usable.
8. **`.fin.in` for NBFCs**: only a secondary source (law.asia, page returned 403 to me); timeline unverified.
9. **Brand map**: items marked unverified above; some banks block bots (Federal, BoI) so only DNS was confirmed. `hdfcbank.bank.in` resolves but did not respond — likely defensive; HDFC's canonical is `www.hdfc.bank.in` (legacy hdfcbank.com redirects there).
10. **Safari 26 BarcodeDetector**: last evidence is a June 2025 iOS 26 beta comment (still flagged). Re-test on a real iPhone.
11. **Free-hosting list** beyond Interisle's top-10 (ngrok, glitch, 000webhost, onrender, etc.) is based on PSL presence and general practice, not ranked abuse data.
