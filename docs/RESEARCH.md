# QR Shield: Research Findings

Research date: 2026-10-09. This is the synthesis. The four raw research files, with every source URL and full tables, are in [`docs/research/`](research/):

| File | Covers |
|---|---|
| [01_scam_patterns.md](research/01_scam_patterns.md) | Indian advisories, 13 attack patterns with real cases, statistics, scam keyword lists |
| [02_upi_spec.md](research/02_upi_spec.md) | NPCI UPI linking spec, every `upi://` parameter, signed QR, mandates, 181 UPI handles, VPA rules |
| [03_url_intel_libs.md](research/03_url_intel_libs.md) | URL threat signals with evidence, threat-intel APIs (probed live), Python libs, SSRF, QR libraries |
| [04_payloads_competitors.md](research/04_payloads_competitors.md) | WiFi/tel/sms/vCard/intent/mandate/Bharat QR risks, competitor gap analysis, merchant tamper mitigations |

Convention: **UNVERIFIED** marks single-source or unconfirmed claims. "(inference)" marks our own reasoning.

---

## 1. The problem in numbers (for the Problem Analysis slide)

| Metric | Value | Source |
|---|---|---|
| UPI volume | **24.07 billion transactions, ₹29.37 lakh crore** in Sep 2026 (+23% YoY) | NPCI data via https://startuptalky.com/upi-transactions-september-2026/ |
| UPI QR codes in circulation | **731 million (~73 crore)** in CY2025, +15% YoY | Worldline India via https://ianslive.in/upi-payments-surge-33-pc-to-2285-billion-transactions-in-2025-bharat-billpay-up-40-pc--20260406141107 |
| UPI fraud | **12.64 lakh cases, ₹981 cr** (FY25); **10.64 lakh cases, ₹805 cr** in Apr–Nov 2025 alone (~1.3 lakh/month) | MoS Finance, Lok Sabha, Dec 2025, via https://the420.in/india-upi-fraud-data-fy26-parliament-digital-payments/ |
| QR-specific fraud | **14,625 (FY22) → 39,638 (FY24)** cases, **2.7× in two years**; ₹56.34 cr in FY24 | Lok Sabha USQ 2245, 9 Dec 2024, via https://www.medianama.com/2024/12/223-qr-code-based-fraud-in-fy-2024-25-less-than-half-of-last-year-with-over-18000-incidents-mos-finance-in-lok-sabha/ |
| All cyber financial fraud | **₹22,845 cr lost in 2024**, 3× the 2023 figure; 36.37 lakh incidents | MoS Home, Lok Sabha, 22 Jul 2025, via https://www.theweek.in/wire-updates/business/2025/07/22/del23-lsq-cyber-fraud.html |
| Global quishing | Malicious-QR emails **>5× in 3 months** (46,969 → 249,723, Aug–Nov 2025) | https://www.kaspersky.co.za/about/press-releases/kaspersky-detected-a-fivefold-surge-in-qr-code-phishing-attacks-in-the-second-half-of-2025 |

**Do not use** RBI's card/internet fraud series on slides: RBI counts only frauds ≥ ₹1 lakh, so it misses almost all QR scams (FY26 shows only 293 cases).

**Before submitting:** the Lok Sabha figures come from several consistent news reports; the sansad.in PDFs could not be machine-read. Open https://eparlib.sansad.in/bitstream/123456789/3000350/1/AU2245_EPISR0.pdf manually to confirm the QR numbers.

### The key structural insight

NPCI **banned P2P "collect" requests from 1 Oct 2025** (circular dated 29 Jul 2025, https://www.businesstoday.in/amp/personal-finance/banking/story/npci-to-tighten-upi-rules-peer-to-peer-collect-feature-to-end-in-october-489244-2025-08-13). That killed the "approve this request to get your refund" trick. The scammer's remaining pull lever is to get the victim to **scan a QR and pay**. So the QR is now the main social-engineering route in UPI fraud (inference, well supported).

Every regulator gives the same advice and no tool:

- RBI: *"Transactions involving receipt of money do not require scanning barcodes / QR codes or entering MPIN."* (https://www.rbi.org.in/scripts/BS_PressReleaseDisplay.aspx?prid=53185)
- NPCI Safety Shield: "UPI PIN is NOT required for receiving money".
- SBI: "You don't receive money when you scan a QR code."
- The Delhi Police, Maharashtra Cyber (advisory dated 2 Oct 2026), Bengaluru and Hyderabad police all say "don't scan unknown QR codes".

All of these rely on the user's judgement at the moment of scanning. **No official or consumer tool inspects the QR payload before the payment app opens.**

---

## 2. Real attack patterns and what a scanner can detect

Full table with 13 patterns and sources: [01_scam_patterns.md §2](research/01_scam_patterns.md).

| Pattern | Real Indian case | Detectable from the payload |
|---|---|---|
| **"Scan to receive money"** (OLX/Quikr, fake army buyer) | Delhi Police MO page; Bengaluru CCB solved ~200 cases | Any `upi://pay` means PAYING. Prefilled locked `am` (no `mam`), receive words in `tn`/`pn`, personal VPA. **If the user says "I'm receiving money", any UPI QR is a scam by definition.** |
| **Swapped shop / petrol pump stickers** | Khajuraho Jan 2025 (payee showed "Chhotu Tiwari"); Aizawl petrol pump Nov 2024; Hyderabad Jul 2024; Chennai 2022 | Personal VPA (no `mc`, person's `pn`) where a merchant is expected; VPA changed from the shop's enrolled VPA (**Shopkeeper mode**) |
| **Insider swap** | Goa, Mar 2026: employee allegedly diverted ₹49.68 lakh | Same as above. Shopkeeper mode catches it. |
| **Fake parking attendant QR** | Mumbai Fort, Aug 2026 (fake BMC attendants, QR linked to an individual) | Personal VPA + `pn` claiming a civic body |
| **Fake customer-care refund QR** | Hyderabad: fake Zomato care, ₹50,000 lost | Brand in `pn` (Zomato, Amazon, SBI) with a non-brand personal VPA; "refund" in `tn` |
| **Lottery / KBC "processing fee"** | Hyderabad Oct 2025 (₹4.4 lakh); Mangaluru Jul 2025 (₹7.76 lakh) | prize, KBC, inaam, jeeta, GST, fee in `tn`/`pn` |
| **Fake donation QR** | Ram Mandir Dec 2023; Badrinath-Kedarnath 2023; PM CARES lookalikes `pmcare@sbi`, `pmoindia@sbi` (68 fake IDs) | Edit distance to known official VPAs; temple/relief/daan words + personal handle |
| **Fake job registration fee** | Delhi: fake IndiGo recruiters with lookalike UPI IDs | registration, joining fee, naukri + brand in VPA |
| **Quishing → fake bank/KYC page** | Kerala Police KYC phishing warning, Sep 2024 | Lookalike/typosquat domains, brand in subdomain, risky TLD, new domain |
| **QR/link → APK** | Microsoft (Nov 2023): fake bank KYC APKs; CERT-In Drinik; RTO e-Challan "mParivahan.apk" campaigns | `.apk` path or `application/vnd.android.package-archive` content type; remote-access app names (anydesk, teamviewer, rustdesk) |
| **Electricity disconnection scam** | Nagpur ₹1.68 lakh; DoT press release | bijli, MSEDCL, disconnection words + non-utility VPA/domain |
| **Fake e-challan / India Post** | PIB fact-check; Cyble report on rotating e-challan domains | "gov" content not on a `.gov.in`/`.nic.in` domain |

**Not confirmed in India (be honest in the pitch):** a QR delivering an APK specifically (it's well documented via SMS/WhatsApp), and fake EV-charger QRs (documented in Europe only).

### Scam keywords (for `tn` / `pn`)

English, Hindi/Hinglish (romanised + Devanagari) and Marathi lists are in [01 §4](research/01_scam_patterns.md#4-keyword-lists-for-tn--pn--url-scoring). Examples: refund, cashback, prize, KYC, inaam / इनाम, jeeta / जीता, paisa wapas / पैसा वापस, bijli kat / बिजली कट, बक्षीस, परतावा, वीज बिल. **These lists are our compilation, not an official lexicon (UNVERIFIED as to frequency).**

---

## 3. UPI deep link format

Best source: **NPCI "UPI Linking Specifications v1.6 (Draft)", Nov 2017**, mirrored at https://www.labnol.org/files/linking.pdf. NPCI's own site blocks scripted access, and no newer public version was found. Full table: [02 §1.3](research/02_upi_spec.md#13-parameter-table).

Format: `upi://pay?pa=<vpa>&pn=<name>&am=<amount>&...`

| Param | Meaning | Rules that matter for us |
|---|---|---|
| `pa` | Payee VPA | **Mandatory.** `local@handle` |
| `pn` | Payee name | **Mandatory.** Chosen by whoever made the QR, so attacker-controlled. The UPI app shows the bank-registered name, which may differ. |
| `am` | Amount | Optional in static, mandatory in dynamic QRs. "Decimal format" (`10` and `10.00` both appear). |
| `mam` | Minimum amount | **If absent, the amount is NOT editable.** So `am` without `mam` = locked amount. |
| `cu` | Currency | Only `INR` |
| `mc` | Merchant category code | 4-digit MCC; spec examples use `0000` for P2P. Real-world `mc=516` exists, so non-4-digit is a soft flag only. |
| `tr` | Transaction ref | Required for merchant/dynamic QRs |
| `tn` | Note | Free text, attacker-controlled. **Prime social-engineering field.** |
| `url` | Reference URL | Must be http(s), "related to the transaction". A phishing vector. |
| `mode` | Initiation mode | 00 default, 01 QR, 02 secure QR, 03 Bharat QR (Juspay), 04 intent, 05 secure intent. Most static QRs omit it. |
| `sign`, `orgid` | Signature | Base64 RSA-SHA256, must be last. **We cannot verify it**: keys only reach PSPs through NPCI APIs. We say "signature present/absent", never "verified". |

Other schemes:

- **`upi://mandate`** = AutoPay, a **recurring debit** (`recur=MONTHLY`, `amrule=MAX`, `validityend`, `rev=N` = cannot be cancelled). Always high risk to a casual scanner.
- **`upi://collect`** has no spec; collect is a network pull flow and cannot travel in a QR. If seen, flag it as anomalous.
- **Bharat QR** is an EMVCo TLV string starting `000201` with a CRC16 at tag `63`; the UPI VPA sits in a merchant template (AID `A000000524`, VPA in sub-tag `01`, per a Razorpay sample). Parse it, validate the CRC, extract the VPA.

**Correction to our brief:** mode `15` is *not* Bharat QR (it's SEBI in 1.6, or offline dynamic QR per Juspay).

### UPI handles

There are **181 handles** in tiers, in [02 §5](research/02_upi_spec.md#5-upi-handle-list), with paste-ready lists:

- **NPCI official TPAP list:** 67, e.g. `ybl`, `ibl`, `axl` (PhonePe), `okaxis`, `okhdfcbank`, `okicici`, `oksbi` (GPay), `paytm`, `ptyes`, `ptsbi` (Paytm). Source: a 2026-10-05 mirror of NPCI's member data plus a Wayback copy dated 2025-09-25.
- **NPCI PPI wallets:** 37.
- **Bank apps from the SEBI/NPCI IPO list:** 29, e.g. `upi` (BHIM), `sbi`, `pnb`, `kotak`.
- **Aggregator + legacy:** 48.
- **SEBI-verified `@valid<bank>` handles:** a positive trust signal.

**Rule:**

| Handle | Treatment |
|---|---|
| Exact match | Known |
| Within edit distance ≤ 2, or a known handle plus extra characters (`@okaxisbank`, `@ybI`, `@paytm1`) | **Typo-squat, high** |
| Otherwise unknown | **Soft** warning. Real acquirer handles like `@icic` (Razorpay) are on no public list. |

**VPA format:** no NPCI grammar is public. Allow `[A-Za-z0-9._-]` in the local part, letters/digits in the handle, exactly one `@`. Don't hard-fail at 35 characters, because real merchant VPAs are longer.

---

## 4. URL threat signals

Evidence and weights: [03 §A](research/03_url_intel_libs.md#a-url-threat-signals).

| Signal | Evidence |
|---|---|
| `javascript:` / `data:` scheme | Chrome blocked top-frame `data:` navigation for phishing (https://developer.chrome.com/blog/chrome-60-deprecations/) |
| Homoglyph / IDN lookalike (Unicode TR39 skeleton) | Chrome's own IDN spoof policy uses skeleton matching (https://chromium.googlesource.com/chromium/src/+/main/docs/idn.md) |
| Typosquat (Damerau-Levenshtein 1–2) | NDSS 2015: ~95% of typo domains of top sites were actively targeted |
| Brand in subdomain/path, not registrable domain (`sbi.co.in.verify-kyc.xyz`) | Classic lexical feature (Ma et al., KDD 2009) |
| Newly registered domain (<30 days) | Unit 42: >70% of newly registered domains are malicious, suspicious or NSFW, ~10× the top-10k rate |
| High-abuse TLD | Interisle/CybercrimeInfoCenter (May 2025–Apr 2026): top per capita are .xin, .win, .icu, .garden, .cfd; by volume .top, .xyz |
| APK/EXE download | Indian RTO e-Challan APK campaigns (Cyfirma, BoomLive) |
| Free hosting (`pages.dev`, `vercel.app`, `web.app`, …) | Interisle 2025: Cloudflare pages.dev/workers.dev is #1 subdomain provider for phishing, +157% YoY |
| IP-literal host, `@` userinfo trick, shortener, redirect chain, non-standard port, http | RFC 3986 §7.6, OWASP |

**Trust signals:** **`.bank.in`**, RBI's exclusive bank domain. RBI set a migration deadline of 31 Oct 2025, over 400 banks have migrated, and live redirects for SBI, HDFC, ICICI, Axis, PNB, BoB and others were confirmed by probe. **`.gov.in` / `.nic.in`** are restricted by NIC. A brand-to-official-domain map for 50+ Indian banks, payment apps, government sites, utilities and e-commerce is in [03 §A.6](research/03_url_intel_libs.md#a6-india-trust-suffixes-and-brand--official-domains).

---

## 5. Threat intelligence sources (probed live on 2026-10-09)

| Source | Key? | Status | Our use |
|---|---|---|---|
| Google Safe Browsing v4 | Yes (free) | Works; non-commercial only (commercial = Web Risk) | Optional, if `GSB_API_KEY` is set |
| URLhaus API | **Yes since 30 Jun 2025** (free key) | API returns 401 without key; **bulk `text_online` CSV is keyless** | Keyless bulk feed cached + optional API |
| OpenPhish community | No | Works; ~300 URLs, 12 h updates, non-commercial | Cached feed |
| PhishTank | No for CSV (registration closed) | Hourly CSV (13 MB) works; undocumented, could be tightened | Cached feed |
| Phishing.Database | No | GitHub raw works (MIT) | Optional; higher false-positive rate |
| RDAP (domain age) | No | Works; `.in` supported via NIXI; rdap.org 10 req/10 s; `.io` unsupported | Domain-age signal, cached per domain |
| urlscan.io | Yes | Not used. Public scans would leak user URLs. | Future scope |

**Design rule:** feeds are downloaded into SQLite on startup and on a timer. All lookups are local, with a short-timeout online check on top. If everything is offline, heuristics still give a verdict.

---

## 6. Other QR payload types

Full table: [04 §A](research/04_payloads_competitors.md#a2-payload--risk--warning-table).

| Payload | Warn about |
|---|---|
| `WIFI:` open/`nopass` or WEP | Anyone nearby can see traffic; no UPI/banking. CERT-In advises against transactions on public WiFi. |
| `WIFI:` lookalike SSID | Indian Railways' real SSID is exactly **"RailWire"** with OTP login, no QR needed |
| `WIFI:` `H:true` | Hidden network, can't verify it |
| `tel:` with `*`/`#` | **Block.** DoT warned (Jan 2024) about the `*401*` call-forwarding scam that diverts bank OTP calls. |
| `tel:` foreign code | Wangiri / premium callback cost |
| `tel:` "bank helpline" on a mobile number | Banks now *call from* 1600/1601 numbers (TRAI 2025); helplines come from official apps. 1930 is the cyber helpline. |
| `sms:` / `SMSTO:` | Show recipient + body; flag short codes and foreign numbers |
| `market://`, `intent://`, Play links | Show the package; flag remote-access apps (AnyDesk, TeamViewer, RustDesk) |
| `wa.me`, `t.me` | Show the pre-typed message |
| vCard / MECARD | "Bank Support" contact with a personal mobile number |
| `FIDO:/` passkey | Only approve if *you* are signing in right now |
| `bitcoin:` / `ethereum:` | Irreversible; verify the address another way |
| `upi://mandate` | AutoPay, recurring; `rev=N` = cannot cancel |
| Bharat QR (`000201…`) | CRC check; then UPI checks |

India has no authoritative list of domestic premium-rate number ranges, so key on foreign codes, short codes and USSD characters instead.

---

## 7. Existing solutions and the gap

Full table: [04 §B](research/04_payloads_competitors.md#b-existing-solutions-and-their-gaps).

| Product | What it misses |
|---|---|
| Kaspersky QR Scanner, Trend Micro (no updates since 2023), Avira | URL reputation only. No UPI semantics, no Indian context. New domains slip through. |
| Norton Snap | Retired in 2019 |
| iOS Camera, Google Lens, Samsung | Show a preview only. No verdict, no reasons. |
| GPay, PhonePe Protect (Nov 2025), Paytm | Warnings only *inside* their own app at payment time. PhonePe Protect screens **mobile numbers** against DoT FRI, not QR/VPA. No explanation of non-UPI QR types. |
| Soundbox (Paytm, GPay SoundPod) | Confirms money *after* it arrives. A swapped sticker shows up only as silence, after the loss. |
| DoT FRI, I4C Suspect Registry, RBIH MuleHunter.AI | Bank-side only; no public API found |
| Chakshu, cybercrime.gov.in | Reporting *after* fraud |
| Atomic Asher (Jan 2024, "multilingual QR safety app") | Closest Indian competitor; its UPI feature was "coming soon"; current status unknown |
| Academic QR-phishing papers (arXiv 2025) | URL phishing only, no explanations, no UPI |

**No RBI or NPCI advisory tells merchants to periodically verify their own QR.** Bank Indonesia and Bahrain police do advise it. That's the gap for Shopkeeper mode.

---

## 8. Technology choices informed by research

| Decision | Choice | Why |
|---|---|---|
| QR decoding | **`barcode-detector` polyfill (ZXing-C++ → WASM)** instead of html5-qrcode | html5-qrcode is in "maintenance mode, looking for new owners" (last release 2023); qr-scanner last released 2022; jsQR 2021. `barcode-detector` released Aug 2026 and uses native `BarcodeDetector` on Chrome Android (most Indian UPI users) and WASM on iOS Safari, where the native API is still behind a flag. One-call decoding of gallery images. The WASM can be self-hosted for offline PWA. |
| Registrable domain | `tldextract` 5.4 offline (`suffix_list_urls=()`, private domains on) | No network; already knows `bank.in`; flags free-hosting suffixes |
| Homoglyphs | **Own ~40-line TR39 skeleton** over pinned `confusables.txt` | `confusable_homoglyphs` repo is archived; `confusables` stale since 2021 |
| Edit distance | `rapidfuzz.distance.DamerauLevenshtein` | Fast, maintained |
| Redirect expansion | `httpx` with `follow_redirects=False`, manual per-hop validation, IP pinning + SNI | OWASP SSRF cheat sheet: validate every hop, connect to the validated IP to stop DNS rebinding |
| SSRF IP check | `ipaddress.ip_address(x).is_global` | Requires Python ≥ 3.12.4 (CVE-2024-4032). We have 3.13.7. |
| Domain age | Direct RDAP via cached IANA bootstrap | Keyless; `.in` supported |

---

## 9. Open uncertainties (carry into the build)

1. The UPI linking spec is a 2017 draft. Newer parameters (`purpose`, `qrMedium`, `ver`) come from vendor docs only.
2. `mode` codes 15–18 conflict between sources. Don't rely on them for scoring.
3. Merchant VPA patterns (`Q…@ybl`, `paytmqr…@paytm`, `BHARATPE…@fbpe`) are UNVERIFIED, so "looks like a merchant VPA" stays a weak signal.
4. We cannot see the bank-registered name behind a VPA, which needs PSP access. We compare `pn` to the VPA text and tell the user to check the name their UPI app shows.
5. The NPCI signed-QR algorithm and keys are not public. We never claim "verified".
6. Scam keyword lists are compiled, not measured.
7. PhishTank keyless access is undocumented and may break. It's one of several feeds, and none is a hard dependency.
8. The CERT-In QR advisory itself was not located (secondary only).
9. Exact launch date of NPCI's verified-name display: sources conflict (Jun 2025 vs Jun 2026).
