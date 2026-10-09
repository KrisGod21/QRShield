# Deploy QR Shield on Vercel

The repository now contains a Vite frontend, a FastAPI serverless entry at `api/index.py`, root runtime requirements, a pinned Python version and `vercel.json`. The frontend and API share one origin, so camera/image/text scans do not need a separate backend URL or a browser CORS workaround.

## Import settings

1. Push this folder to your Git repository, excluding `.runtime`, `.env`, `.venv`, `node_modules`, private data and the inspiration HTML/video. `.gitignore` and `.vercelignore` cover runtime/deployment artifacts.
2. Import the repository in Vercel.
3. Set **Root Directory to the repository root**, not `frontend`.
4. Use the **Vite** framework preset. The committed configuration supplies:
   - Install: `npm ci --prefix frontend`
   - Build: `npm run build --prefix frontend`
   - Output: `frontend/dist`
   - Python: 3.13
5. Deploy. Test `/`, `/api/health` and an uploaded QR image using the HTTPS deployment URL. HTTPS permits the browser camera API, subject to device support and user permission.

No public deployment was created during this implementation; there are no Vercel credentials or a linked deployment in this checkout.

## Environment variables

| Variable | Deployment behavior |
|---|---|
| `DEMO_MODE` | Defaults to `0` in the Vercel entry. Set `1` only for an explicitly labeled demonstration with synthetic domain-age/redirect/report fixtures. |
| `ONLINE_CHECKS` | Defaults to `1`. Enables bounded redirect/domain-age checks and any configured keyed services. |
| `FEEDS` | Defaults to `0` on Vercel. Do not rely on background startup downloads finishing inside serverless requests. |
| `DATABASE_URL` | Optional server-side PostgreSQL URL, such as a managed Neon connection string with TLS. Enables shared, durable reports, cached intelligence and server-side shop records. |
| `GSB_API_KEY` | Optional Google Safe Browsing key. |
| `URLHAUS_AUTH_KEY` | Optional keyed URLhaus lookup. |
| `TIME_BUDGET` | Default `2.2` seconds for online scan checks. |

Do not expose secrets as `VITE_` variables, commit `.env`, or override Vercel's `DB_PATH` to a project-file path. The Python entry uses in-memory SQLite when no external database is configured, avoiding writes to the deployment filesystem.

## With and without PostgreSQL

**Without credentials:** QR decoding and analysis work. Scan history and the merchant's trusted baseline stay in the browser. Merchant comparison sends the saved baseline directly for verification, so it survives serverless cold starts without relying on a process-local shop code. Shared reporting is explicitly unavailable; the UI shows an inline message instead of pretending the report was saved permanently.

**With `DATABASE_URL`:** The backend initializes the same tables in PostgreSQL and stores shared reports, intelligence/cache and shop records there. Use a managed database connection string and redeploy after setting the variable. The health endpoint reports `storage: "postgres"` and `shared_reports: true`. This adapter was implemented and its imports verified, but no real database connection was tested because this workspace has no database credentials.

SQLite project files are not shared durable storage for serverless functions. See [Vercel's storage guidance](https://vercel.com/kb/guide/is-sqlite-supported-in-vercel). Python ASGI handlers and bundle exclusions are documented in [Vercel's Python runtime reference](https://vercel.com/docs/functions/runtimes/python).

Bulk threat feeds work on the local long-running server. On Vercel, configure keyed lookups or populate an external database using a separately scheduled worker if you need continuously refreshed bulk-feed data. Empty feeds are displayed as skipped, not as a completed clean check.

## Verification before and after deployment

Local checks performed during implementation:

- Production TypeScript/Vite/PWA build passed.
- 183 backend tests passed, including query ambiguity, embedded destinations, HTTPS downgrades, merchant metadata, signature limitations and invisible display controls.
- The existing live demo verifier passed all 15 QR scans and both shop sticker checks.
- Actual browser decoding plus API analysis passed on 25 generated QR PNGs at several sizes.
- Desktop, tablet and narrow phone layouts were checked with real iframe viewport sizes; the initial phone scan-panel overflow was fixed.
- `demo/verify_serverless.py` passed with demo mode off, no credentials and no filesystem persistence.
- `vercel.json` validated against the fetched official configuration schema using a validator supporting its newer schema keywords.

These are implementation checks, not a measured real-world fraud-detection accuracy. Physical camera performance, a live PostgreSQL connection and an actual Vercel-hosted function remain to be checked after deployment.

For a live deployment, verify:

1. Health succeeds and `demo` is false for ordinary use.
2. A benign shop payment shows the expected payee; the same QR with receiving-money intent gives danger.
3. An uploaded PNG decodes without a third-party WASM request.
4. A normal subscription gives caution, while a deceptive AutoPay sample gives danger.
5. An invalid URL never shows green.
6. Merchant registration and changed-sticker comparison work after refreshing the page.
7. If PostgreSQL is enabled, a report persists across separate browsers/function instances.
8. Check function logs and network timeouts; do not present incomplete checks as proof of safety.

## Local development and image test harness

Run the backend as described in `README.md`, then run `npm run dev` from `frontend`. Open `http://127.0.0.1:5173`.

Generate test images using `backend/.venv/Scripts/python demo/generate_validation.py`. Open `http://127.0.0.1:5173/tests/decoder.html` and select **Run QR validation**. This exercises the actual `scanner.ts` module and live `/api/analyze` endpoint. The test page and fixtures are development-only and are excluded from the production build/deployment.

The visual direction takes inspiration from the supplied Nrok Behance layout: dark surfaces, warm gold light, large typography and floating security objects. The QR/shield artwork is original SVG/CSS created for this project; the reference screenshots and video are not shipped as product assets. Attribution: [Nrok design reference](https://www.behance.net/gallery/244867607/Nrok-Cybersecurity-Landing-Page-UIUX-Design).
