# QR Shield: UPI-aware QR code safety scanner

CodeAstra 2.0 hackathon prototype. Scan a QR **before** it opens and see, in plain English, हिंदी or मराठी, what it will make you do and whether it is a scam. The scanner is focused on the scams Indians actually face: UPI "scan to receive money", swapped shop stickers, AutoPay traps, lookalike bank sites, APKs and `*401#` call-forwarding codes.

The UI now has a responsive dark/gold design with an animated QR/shield hero, a scan workspace, illustrative samples, local history and merchant sticker comparison. Motion respects the user's reduced-motion preference. Analysis highlights risk signals; it does not guarantee safety or verify bank ownership.

**Vercel:** Import the repository root using the committed `vercel.json`. Scanning works without API keys; add a server-side PostgreSQL `DATABASE_URL` for durable community reporting. See [docs/VERCEL_DEPLOYMENT.md](docs/VERCEL_DEPLOYMENT.md) for settings, storage behavior and validation.

- Research: [docs/RESEARCH.md](docs/RESEARCH.md)
- Pitch points: [docs/DIFFERENTIATION.md](docs/DIFFERENTIATION.md)
- Architecture and signal weights: [docs/PLAN.md](docs/PLAN.md)
- 3-minute demo script: [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md)
- Slides: [docs/ppt/QR_Shield_CodeAstra.pptx](docs/ppt/QR_Shield_CodeAstra.pptx)

## One-command setup (Windows, Python 3.12.4+ and Node 18+)

```bash
python -m venv backend/.venv && backend/.venv/Scripts/pip install -r backend/requirements.txt && (cd frontend && npm install && npm run build) && backend/.venv/Scripts/python demo/generate_sheet.py
```

On macOS or Linux, use `backend/.venv/bin/...` instead of `backend/.venv/Scripts/...`.

## Run

```bash
backend/.venv/Scripts/python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000
```

| Page | URL |
|---|---|
| App | http://localhost:8000 |
| Printable demo QR sheet | http://localhost:8000/demo/sheet |
| Health and feed status | http://localhost:8000/api/health |

On a laptop, `localhost` counts as a secure origin, so the webcam works with no extra setup.

## Phone over HTTPS (camera needs HTTPS)

**Option A, simplest:** use a Cloudflare quick tunnel. It needs no account. Install `cloudflared`, then run:

```bash
cloudflared tunnel --url http://localhost:8000
```

Open the printed `https://….trycloudflare.com` URL on the phone. Tap Share, then Add to Home Screen, to install it as an app.

**Option B, no internet:** serve HTTPS on the LAN with a self-signed cert, for example `mkcert` or `openssl`. Then run:

```bash
backend/.venv/Scripts/python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

Then open `https://<laptop-LAN-IP>:8443` on the phone and accept the certificate warning. A laptop hotspot works if the venue Wi-Fi blocks devices from seeing each other.

**Fallback:** the **Upload QR image** button works on plain HTTP, with screenshots or gallery photos.

## Configuration (`.env`, all optional)

Copy `.env.example` to `.env`.

| Variable | Default | Meaning |
|---|---|---|
| `DEMO_MODE` | `1` | Fixed results for the `.test` demo domains, plus seeded community reports |
| `ONLINE_CHECKS` | `1` | Redirect expansion, RDAP domain age and API lookups. `0` = heuristics only. |
| `FEEDS` | `1` | Download OpenPhish, PhishTank and URLhaus feeds into SQLite at startup |
| `GSB_API_KEY` | (none) | Google Safe Browsing v4 key (free, non-commercial) |
| `URLHAUS_AUTH_KEY` | (none) | abuse.ch Auth-Key for the URLhaus API |
| `TIME_BUDGET` | `2.2` | Seconds allowed for all online checks of one scan |

Every external service is optional. If a key is missing or a service is down, the offline rules still produce a verdict.

## Tests and demo verification

```bash
cd backend && .venv/Scripts/python -m pytest -q
```

That runs 154 tests covering the UPI parser, Bharat QR CRC, homoglyphs, typosquats, scoring, the SSRF guard, i18n completeness, the API and safety regressions. Ordinary AutoPay mandates receive caution; malformed or unresolved links never receive a reassuring green result; unverified signatures do not reduce risk; report counts alone cannot establish danger.

With the server running, this checks every demo QR end to end:

```bash
backend/.venv/Scripts/python demo/verify_demo.py http://127.0.0.1:8000
```

## How it works (short)

1. **Decode on the phone.** `barcode-detector` uses the native scanner on Android Chrome and ZXing-C++ compiled to WASM elsewhere. The WASM file is self-hosted, so decoding works offline.
2. **Send only the decoded text** to `/api/analyze`. The link is never opened on the phone.
3. **Classify the payload:** UPI pay or AutoPay, Bharat QR, URL, Wi-Fi, tel/SMS, vCard, app intent, crypto, FIDO, OTP or text.
4. **Run the analyzer for that type.** Each one emits signals with fixed weights. Total score 0–24 = SAFE, 25–59 = CAUTION, 60 or more = DANGER. Some hard rules force DANGER, for example "receiving money" combined with any UPI QR.
5. **Explain.** Every signal carries text in English, Hindi and Marathi.

The URL fetching guard follows the OWASP SSRF cheat sheet:
- only http and https on ports 80/443
- every DNS answer is checked, and only public IPs are kept
- the connection is pinned to the checked IP, with Host and SNI kept
- each redirect hop is validated, up to a maximum of 5
- no JavaScript is executed, and response bodies are capped at 64 KB

## Layout

```
backend/app/        FastAPI app, engine, analyzers/, data/ (handles, brands, keywords, PSL, confusables)
backend/tests/      pytest suite
frontend/src/       React PWA (scanner, result card, history, shop mode, i18n)
demo/               sample QRs, printable sheet generator, end-to-end verifier
docs/               research, plan, pitch, demo script, slides
```
