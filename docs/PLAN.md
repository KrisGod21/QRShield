# QR Shield: Build Plan

This plan is based on [RESEARCH.md](RESEARCH.md). Goals, in priority order:
1. A live demo that never breaks: a phone scans a printed QR and gets a verdict in under 3 seconds.
2. A unique, India/UPI-first product.
3. A polished, mobile-first UI.

## 1. Architecture

```
 Phone / laptop browser (PWA)                      FastAPI server (Python 3.13)
 ┌────────────────────────────────┐   same origin  ┌────────────────────────────────────────┐
 │ React + TS + Vite              │   HTTPS        │ /api/analyze                           │
 │ barcode-detector (ZXing WASM)  │ ─────────────▶ │   classify(payload)                    │
 │  camera loop + gallery upload  │  {payload,     │   → analyzer (upi / emv / url / wifi / │
 │ Intent chips                   │   intent}      │       tel / sms / vcard / app / text…) │
 │ Result card (EN / हि / मरा)     │ ◀───────────── │   → signals[] (code, weight, params)   │
 │ History  (localStorage)        │  verdict,      │   → engine: score 0–100 → verdict      │
 │ Shopkeeper mode (localStorage) │  summary,      │   → i18n: text {en, hi, mr} per signal │
 └────────────────────────────────┘  signals       │ SQLite: intel feeds, RDAP cache,       │
                                                   │   reports (sha256), shops              │
                                                   │ Online (parallel, ≤2.5 s budget):      │
                                                   │   RDAP age · SSRF-safe redirect expand │
                                                   │   · Safe Browsing · URLhaus (if keys)  │
                                                   │ DEMO_MODE: virtual web for *.test      │
                                                   └────────────────────────────────────────┘
```

**Principles**
- **Never open the destination on the phone.** The phone sends only the decoded text. All fetching happens server-side, through the SSRF guard.
- **Deterministic and explainable.** Each rule produces a signal with a fixed weight, and every signal carries plain-language text in three languages.
- **Degrade gracefully.** Every online check has its own timeout, and the whole analysis has a time budget. If a check fails, it is reported as `skipped`/`timeout` and the heuristics still decide.
- **One origin.** FastAPI serves the built PWA, so the phone needs only one HTTPS link (a cloudflared tunnel, or a self-signed cert on the LAN).

## 2. Payload classification

The rules are applied in this order:

| Kind | Rule |
|---|---|
| `upi_pay` | scheme `upi`, host `pay` (case-insensitive) |
| `upi_mandate` | `upi://mandate` |
| `upi_other` | `upi://collect` or another host (anomalous) |
| `bharat_qr` | starts with `000201` (EMVCo TLV) |
| `url` | `http(s)://`, or a bare `www.` / domain-like string |
| `dangerous_scheme` | `javascript:`, `data:`, `file:`, `vbscript:` |
| `wifi` | `WIFI:` |
| `tel` | `tel:` |
| `sms` | `sms:`, `smsto:`, `mms:`, `mmsto:` |
| `email` | `mailto:`, `MATMSG:` |
| `geo` | `geo:` |
| `vcard` | `BEGIN:VCARD`, `MECARD:` |
| `event` | `BEGIN:VEVENT` |
| `app` | `market://`, `intent://`, `play.google.com/store/apps` (as URL + app signal) |
| `chat` | `wa.me`, `t.me`, `whatsapp://`, `tg://` |
| `crypto` | `bitcoin:`, `ethereum:`, `litecoin:`, … |
| `fido` | `FIDO:/` |
| `otp` | `otpauth://` |
| `text` | anything else; embedded URLs and UPI IDs are extracted and analysed as well |

## 3. Signals and weights

Each signal has a `code`, a `severity` (info / low / medium / high / critical), a `weight` and `params`. Score = clamp(Σ weights, 0, 100).

**Verdict:**
- SAFE if the score is below 25
- CAUTION if the score is 25–59
- DANGER if the score is 60 or above

Some signals carry `force="DANGER"`. This override wins regardless of score.

### UPI (`upi_pay`, `upi_mandate`, Bharat QR)
| Code | Weight | Trigger |
|---|---|---|
| `UPI_PAY_INFO` | 0 | Always. "You will PAY ₹X to NAME (VPA). Scanning never receives money." |
| `UPI_RECEIVE_INTENT` | 100, **force** | The user picked "I'm receiving money" and the QR is a UPI payment |
| `UPI_MANDATE` | 60 | `upi://mandate` (AutoPay recurring debit) |
| `UPI_MANDATE_IRREVOCABLE` | 30 | `rev=N` |
| `UPI_COLLECT_SCHEME` | 60 | `upi://collect` or another unknown host |
| `UPI_MISSING_PA` | 70, **force** | No payee VPA |
| `UPI_MALFORMED_VPA` | 50 | Bad characters, two `@`, spaces, empty parts, non-ASCII |
| `UPI_DUPLICATE_PARAM` | 50 | The same key appears twice (parser-confusion trick) |
| `UPI_BAD_CURRENCY` | 40 | `cu` is not `INR` |
| `UPI_BAD_AMOUNT` | 30 | `am` is not a positive decimal |
| `UPI_HANDLE_TYPO` | 45 | Handle is close to a known handle (edit distance ≤ 2, or a known handle plus extra characters) |
| `UPI_HANDLE_UNKNOWN` | 12 | Handle is not in the 181-handle list |
| `UPI_HANDLE_VERIFIED` | −15 | A SEBI `@valid…` handle |
| `UPI_SCAM_KEYWORD` | 35 per category (max 2 categories) | refund / prize / KYC / receive / bill / job / … in `pn`, `tn` or the VPA (EN + HI + MR) |
| `UPI_IMPERSONATION` | 40 | `pn` names a bank, regulator, government body or big brand while the VPA is a consumer handle that doesn't contain the brand |
| `UPI_BRAND_IN_VPA` | 30 | Brand/authority word inside the local part of a consumer-handle VPA (`sbi.refund@ybl`) |
| `UPI_OFFICIAL_LOOKALIKE` | 60 | Within edit distance 1–2 of an official VPA (`pmcares@sbi`, …) but not identical |
| `UPI_PREFILLED_P2P` | 20 | `am` set, no `mam` (locked), and a P2P-looking QR (no `mc`, or `mc=0000`) |
| `UPI_BUSINESS_NAME_PERSONAL_VPA` | 15 | `pn` looks like a business but the VPA is a mobile number |
| `UPI_HIGH_AMOUNT` | 20 | Over ₹1,00,000 on a P2P QR, or over ₹5,00,000 on any QR |
| `UPI_REF_URL` | 15 + nested URL signals | `url=` parameter present |
| `UPI_NOTE_CONTACT` | 15 | `tn` contains a URL or phone number |
| `UPI_SIGNED` | −5 | `sign` present (not verified; never claimed as verified) |
| `UPI_SIGN_MALFORMED` | 20 | `sign` is not Base64 |
| `UPI_RISKY_MCC` | 15 | Gambling, crypto/quasi-cash or debt-collection MCC |
| `EMV_CRC_INVALID` | 45 | Bharat QR checksum mismatch (the code may have been edited) |

### URL
| Code | Weight | Trigger |
|---|---|---|
| `URL_DANGEROUS_SCHEME` | 100, **force** | `javascript:`, `data:`, `vbscript:`, `file:` |
| `URL_INTEL_HIT` | 100, **force** | On Safe Browsing, URLhaus, OpenPhish or PhishTank |
| `URL_APK_DOWNLOAD` | 70, **force** | `.apk`, `.xapk` or `.apks` path, or an APK content-type |
| `URL_EXE_DOWNLOAD` | 50 | `.exe`, `.msi`, `.bat`, `.scr`, `.jar` |
| `URL_REMOTE_ACCESS_APP` | 50 | anydesk, teamviewer, quicksupport, rustdesk, airdroid in the URL |
| `URL_HOMOGLYPH` | 50 | Unicode TR39 skeleton of the domain equals a brand's official domain |
| `URL_TYPOSQUAT` | 40 | Domain label within Damerau-Levenshtein 1–2 of a brand's official label |
| `URL_BRAND_MISUSE` | 35 | Brand keyword in the subdomain, path or registrable label, but the domain isn't official |
| `URL_GOV_IMPERSONATION` | 30 | Government words (gov, challan, parivahan, aadhaar, …) but not `.gov.in` / `.nic.in` |
| `URL_NEW_DOMAIN` | 35 (<7 d), 25 (<30 d), 8 (<90 d) | RDAP registration date |
| `URL_USERINFO` | 35 | `user@host` trick |
| `URL_IP_HOST` | 30 | IP-literal host |
| `URL_RISKY_TLD` | 20 (tier 1) / 10 (tier 2) | Interisle / Spamhaus lists |
| `URL_FREE_HOSTING` | 12 | pages.dev, vercel.app, web.app, ngrok, … |
| `URL_PUNYCODE` | 15 | IDN / `xn--` host |
| `URL_SHORTENER` | 10 | Known shortener or dynamic-QR redirector |
| `URL_REDIRECTS` | 5 per hop beyond 1, +15 if it crosses domains | Redirect chain |
| `URL_SUSPICIOUS_WORDS` | 8 each (max 16) | kyc, verify, login, refund, reward, … in the path or host |
| `URL_MANY_SUBDOMAINS` | 8 | 4 or more subdomain labels, or a host over 50 characters |
| `URL_NO_HTTPS` | 8 | `http://` |
| `URL_ODD_PORT` | 8 | Port not 80/443 |
| `URL_OFFICIAL` | −30 | Exact match to an official brand domain, or `.bank.in` / `.gov.in` / `.nic.in` |
| `URL_OPENS_CHAT` | 10 | wa.me / t.me, showing the pre-typed text |
| `URL_APP_INSTALL` | 15 | Play Store / `market://` / `intent://` |

### Other payloads
| Code | Weight | Trigger |
|---|---|---|
| `WIFI_OPEN` | 35 | `T:nopass` or no `T` |
| `WIFI_WEP` | 30 | WEP |
| `WIFI_LOOKALIKE` | 40 | SSID resembles RailWire, an airport, or a "free/public" network |
| `WIFI_HIDDEN` | 15 | `H:true` |
| `TEL_USSD` | 90, **force** | `*` or `#` in the number; call forwarding (`*401*`, `*21*`, `**21*`, …) is named explicitly |
| `TEL_FOREIGN` | 25 | Country code isn't +91 |
| `TEL_SHORTCODE` | 15 | 3–6 digit number (1930 / 1909 are info) |
| `TEL_OFFICIAL_INFO` | 0 | 1930 cyber helpline, 1600 series explained |
| `SMS_SHORTCODE` | 25 | SMS to a short code |
| `SMS_FOREIGN` | 25 | SMS to a foreign number |
| `SMS_SCAM_KEYWORD` | 30 | Scam words in the prefilled body |
| `VCARD_BANK_PERSONAL` | 35 | Contact name claims bank/support/govt, but the number is a personal mobile |
| `CRYPTO_PAYMENT` | 30 | Irreversible crypto payment |
| `FIDO_LOGIN` | 30 | Passkey sign-in for another device |
| `OTP_SECRET` | 20 | 2FA secret visible |
| `APP_REMOTE_ACCESS` | 60 | App install / intent for a remote-control app package |
| `INTENT_SCHEME` | 25 | Android `intent://` |
| `TEXT_SCAM_KEYWORD` | 25 | Scam words in plain text |
| `EMBEDDED_*` | (nested) | URL or UPI inside text: nested analysis, worst result wins |
| `COMMUNITY_REPORTED` | 20 + 10 × min(n, 4) | This exact payload hash has been reported n times |
| `CHECK_SKIPPED` | 0 | An online check was skipped or timed out (shown greyed) |

## 4. API

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | `/api/analyze` | `{payload: str, intent?: "pay_shop"\|"receive"\|"pay_bill"\|"check", source?: "camera"\|"image"\|"text"}` | `{id, kind, verdict, score, headline{en,hi,mr}, summary{...}, signals[{code,severity,weight,params,text{en,hi,mr}}], checks[{name,status,ms}], reports{count}, payload_hash, elapsed_ms, demo}` |
| POST | `/api/report` | `{payload, reason}` | `{payload_hash, count}` |
| GET | `/api/reports/{hash}` | n/a | `{count, reasons}` |
| POST | `/api/shop/register` | `{payload, shop_name}` | `{shop_code, vpa, pn}` |
| POST | `/api/shop/verify` | `{payload, shop_code? , expected_vpa?, expected_name?}` | `{match: bool, expected{vpa,pn}, found{vpa,pn}, changes[], text{en,hi,mr}}` |
| GET | `/api/health` | n/a | `{ok, demo, feeds{source: count, updated}, keys{gsb, urlhaus}}` |
| GET | `/demo/sheet` | n/a | Printable demo QR sheet (HTML) |

**Limits:** payloads are capped at 4 KB. `/api/report` is rate-limited per IP in memory.

## 5. Online checks (all optional; time-boxed with `asyncio.wait_for`)

| Check | Time budget | Cache |
|---|---|---|
| **Redirect expansion** | 2.5 s total, 5 hops, connect 1.5 s / read 2 s | per URL, 1 h |
| **RDAP** | 2 s | per domain, forever |
| **Safe Browsing v4** | 1.5 s | per URL, 30 min |
| **URLhaus API** | 1.5 s | per URL, 30 min |
| **Feeds** | downloaded at startup and every 6 h in the background | SQLite `intel` table |

**Redirect expansion:** uses `httpx`, HEAD first and GET fallback, reading at most 64 KB. Each hop goes through the SSRF guard. The final URL is re-scored lexically.

**RDAP:** IANA bootstrap from a cached file → `domain/{registrable}` → the `registration` event.

**Safe Browsing v4** runs only if `GSB_API_KEY` is set. **The URLhaus API** runs only if `URLHAUS_AUTH_KEY` is set.

**Feeds** (`FEEDS=1`):
- OpenPhish `feed.txt`
- PhishTank `online-valid.csv`
- URLhaus `text_online`

Any failure is logged and the feed is skipped.

### SSRF guard (`ssrf.py`)
1. Allow `http`/`https` only, ports 80/443 only, and no userinfo when fetching.
2. Resolve every A/AAAA record. Reject the URL if *any* record is not `is_global`, or is multicast, reserved, link-local, loopback or unspecified. Also reject `64:ff9b::/96` and `100.64.0.0/10`.
3. Connect to the validated IP, with `Host` and SNI set to the original hostname (stops DNS rebinding).
4. Never follow redirects automatically: each `Location` is validated as a new hop.
5. Never execute JS. Cap the body size. Use short timeouts.

## 6. DEMO_MODE

`DEMO_MODE=1` loads `backend/app/demo_fixtures.py`, a **virtual web for `.test` domains** that are reserved by RFC 2606 and never resolve:
- registration ages (e.g. `onlinesbl.test` registered 3 days ago)
- redirect chains (`qrs.test/x7Kp` → `hdfcbank-rewards.test/claim`)
- content-types (APK)
- one demo threat-feed entry

The fixtures also give fixed ages for the real official domains used in the samples, so every sample QR gets the same verdict with **no internet**. The SSRF guard is never bypassed: `.test` hosts are answered from fixtures and never fetched. Demo community reports are seeded on startup.

## 7. Frontend
- **Tabs:** Scan · History · Shop. There is a language toggle (EN / हिं / मरा) in the header.
- **Scan:**
  - full-width camera with a scan frame, using `barcode-detector`; native BarcodeDetector on Android Chrome, ZXing WASM elsewhere, with the WASM self-hosted
  - a gallery upload button
  - "paste text" for desktop
  - intent chips: *Paying a shop · Receiving money · Paying a bill · Just checking*
- **Result:**
  - verdict banner (green/amber/red with icon and score)
  - headline sentence
  - kind-specific summary: a UPI payment card shows a big ₹ amount, payee and VPA, plus the "Scanning a QR never gives you money" ribbon
  - reasons list sorted by weight
  - checks row
  - "Reported N times" badge
- **Actions:** **Don't open** (primary) and **Open anyway**. For DANGER, *Open anyway* first shows a confirm step ("I understand the risk"). Then it does the right thing for the kind:
  - URL: open a new tab
  - UPI: open the UPI app
  - WiFi: show the password to copy
  - tel: open the dialer, blocked for USSD
- There is also a **Report** button.
- **History:** the last 50 scans in localStorage, with verdict chips.
- **Shop:** "Register my QR" scans and stores `{shop_name, vpa, pn, shop_code}` locally and on the server. "Check my sticker" scans and shows ✅ or 🚨 full-screen, with what changed.
- **PWA:** manifest, icons and a service worker that precaches the app shell and the WASM, so it is installable and opens offline (analysis needs the server).

## 8. Build order (with commits)
1. Backend skeleton: config, models, classify, data lists (handles, brands, TLDs, keywords), i18n
2. UPI analyzer + EMV (Bharat QR) + tests
3. URL analyzer: lexical, homoglyph, typosquat + tests
4. SSRF guard + redirect expander + RDAP + intel feeds + tests
5. Other payloads (wifi, tel, sms, vcard, app, crypto, fido, otp, text) + tests
6. Engine + API + reports + shops + DEMO_MODE fixtures + API tests
7. Frontend: scanner, result card, i18n, history, shop mode, PWA
8. Demo kit: sample QR sheet generator + expected verdicts + an end-to-end verification script
9. README, `.env.example`, phone-over-HTTPS instructions, DEMO_SCRIPT.md
10. PPT (6 slides, CodeAstra template)

## 9. Risks and mitigations
| Risk | Mitigation |
|---|---|
| Venue WiFi is down | DEMO_MODE fixtures + offline heuristics; laptop hotspot; gallery upload fallback |
| iOS camera quirks | Gallery upload; WASM decoder; a single kept-alive MediaStream |
| HTTPS needed for the camera | cloudflared quick tunnel; or a self-signed LAN cert; or demo from the laptop webcam (localhost counts as a secure context) |
| False positives on real QRs | Unknown handles get only soft warnings; trust signals for official domains; tune with tests |
| Translation quality | Native-speaker review of `i18n.py` before the event |
