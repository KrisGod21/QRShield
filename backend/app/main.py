"""QR Shield API + static PWA host."""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
import unicodedata
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from . import demo_fixtures, i18n, intel
from .analyzers.emv import extract_vpa, parse_tlv, crc_ok
from .analyzers.upi import split_upi, vpa_problems
from .config import ROOT, settings
from .db import DB, PostgresDB
from .engine import analyze
from .models import AnalyzeRequest, ReportRequest, ShopRegisterRequest, ShopVerifyRequest
from .util import payload_hash
from .models import Analysis
from .technical import add as evidence, text as audit_text

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("qrshield")

db = PostgresDB(settings.database_url) if settings.database_url else DB(settings.db_path)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.demo_mode:
        demo_fixtures.seed(db)
    # Load the PSL and confusables now so the first scan on stage is fast.
    from .analyzers.url import _brand_skeletons
    from .domainutil import host_info
    host_info("warmup.example.com")
    _brand_skeletons()
    task = None
    if settings.feeds and settings.online_checks:
        task = asyncio.create_task(intel.refresh_feeds(db))
    log.info("QR Shield ready (demo=%s, online=%s, feeds=%s, gsb=%s, urlhaus=%s)",
             settings.demo_mode, settings.online_checks, settings.feeds,
             bool(settings.gsb_api_key), bool(settings.urlhaus_auth_key))
    yield
    if task and not task.done():
        task.cancel()


app = FastAPI(title="QR Shield", version="1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])

_report_hits: dict[str, deque] = defaultdict(deque)


def _rate_limited(ip: str, limit: int = 10, window: float = 60.0) -> bool:
    q = _report_hits[ip]
    now = time.time()
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


# ------------------------------------------------------------------ API
@app.get("/api/refresh-app", include_in_schema=False)
async def refresh_app():
    """Bootstrap outside old service workers' navigation fallback."""
    target = settings.frontend_dist / "index.html"
    if not target.is_file():
        raise HTTPException(503, "Build the frontend before opening the app.")
    return FileResponse(target, headers={"Cache-Control": "no-store"})


@app.get("/api/health")
async def health():
    return {"ok": True, "demo": settings.demo_mode, "online": settings.online_checks,
            "feeds": intel.feed_status(db),
            "storage": "postgres" if settings.database_url else "sqlite" if db.persistent else "memory",
            "shared_reports": not settings.serverless or db.persistent,
            "keys": {"gsb": bool(settings.gsb_api_key), "urlhaus": bool(settings.urlhaus_auth_key)}}


@app.post("/api/analyze")
async def api_analyze(req: AnalyzeRequest):
    if not req.payload.strip():
        raise HTTPException(400, "empty payload")
    return await analyze(req.payload, req.intent, req.source, db, settings)


@app.post("/api/report")
async def api_report(req: ReportRequest, request: Request):
    if settings.serverless and not db.persistent:
        raise HTTPException(503, "Community reporting is unavailable right now. Your scan still works.")
    if not req.payload.strip():
        raise HTTPException(400, "empty payload")
    ip = request.client.host if request.client else "?"
    if _rate_limited(ip):
        raise HTTPException(429, "too many reports, try again in a minute")
    h = payload_hash(req.payload)
    return {"payload_hash": h, "count": db.add_report(h, req.reason.strip()[:300])}


@app.get("/api/reports/{h}")
async def api_reports(h: str):
    if not re.fullmatch(r"[0-9a-f]{64}", h):
        raise HTTPException(400, "bad hash")
    return {"count": db.report_count(h), "reasons": db.report_reasons(h)}


def _upi_identity(payload: str) -> tuple[str, str] | None:
    p = payload.strip()
    if p.lower().startswith("upi:"):
        action, params, duplicates = split_upi(p)
        if action == "pay" and params.get("pa") and not duplicates and not vpa_problems(params["pa"]):
            return params["pa"], params.get("pn", "")
    elif p.startswith("000201"):
        tlv = parse_tlv(p) or {}
        vpa = extract_vpa(tlv)
        if vpa and crc_ok(p) and not vpa_problems(vpa):
            return vpa, tlv.get("59", "")
    return None


def _norm_name(s: str) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFKC", s).casefold()
                   if unicodedata.category(ch)[0] in "LNM")


def _identity_metadata(payload: str) -> dict[str, str]:
    if payload.strip().lower().startswith("upi:"):
        _, params, _ = split_upi(payload)
        return {"mcc": params.get("mc", ""), "currency": params.get("cu", "INR").upper() or "INR"}
    tlv = parse_tlv(payload.strip()) or {}
    return {"mcc": tlv.get("52", ""), "currency": "INR" if tlv.get("53", "356") == "356" else tlv.get("53", "")}


@app.post("/api/shop/register")
async def shop_register(req: ShopRegisterRequest):
    ident = _upi_identity(req.payload)
    if not ident:
        raise HTTPException(400, "Not a UPI payment QR")
    vpa, pn = ident
    metadata = _identity_metadata(req.payload)
    if settings.serverless and not db.persistent:
        return {"shop_code": "", "vpa": vpa, "pn": pn, "shop_name": req.shop_name.strip() or pn, **metadata}
    code = "".join(secrets.choice("ABCDEFGHJKMNPQRSTUVWXYZ23456789") for _ in range(6))
    db.shop_put(code, req.shop_name.strip() or pn, vpa, pn)
    return {"shop_code": code, "vpa": vpa, "pn": pn, "shop_name": req.shop_name.strip() or pn, **metadata}


@app.post("/api/shop/verify")
async def shop_verify(req: ShopVerifyRequest):
    if req.shop_code:
        row = db.shop_get(req.shop_code)
        if not row:
            raise HTTPException(404, "Unknown shop code")
        exp_vpa, exp_pn = row["vpa"], row["pn"] or ""
    elif req.expected_vpa:
        exp_vpa, exp_pn = req.expected_vpa, req.expected_name or ""
    else:
        raise HTTPException(400, "shop_code or expected_vpa required")
    if vpa_problems(exp_vpa):
        raise HTTPException(400, "Invalid saved UPI address")

    analysis = await analyze(req.payload, "pay_shop", "text", db, settings)

    ident = _upi_identity(req.payload)
    if not ident:
        return {"match": False, "expected": {"vpa": exp_vpa, "pn": exp_pn}, "found": None,
                "changes": ["not_upi"], "text": i18n.render("SHOP_NOT_UPI"), "verdict": "DANGER",
                "technical": [], "analysis": analysis}
    vpa, pn = ident
    metadata = _identity_metadata(req.payload)
    changes = []
    if vpa.lower() != exp_vpa.lower():
        changes.append("vpa")
    if exp_pn and _norm_name(pn) != _norm_name(exp_pn):
        changes.append("name")
    if req.expected_mcc is not None and req.expected_mcc != metadata["mcc"]:
        changes.append("mcc")
    if req.expected_currency and req.expected_currency.upper() != metadata["currency"]:
        changes.append("currency")
    match = "vpa" not in changes
    text = i18n.render("SHOP_MATCH", {"vpa": vpa}) if match else \
        i18n.render("SHOP_MISMATCH", {"expected": exp_vpa, "found": vpa})
    extra = i18n.render("SHOP_NAME_CHANGED", {"expected": exp_pn, "found": pn}) if "name" in changes else None
    baseline = Analysis(kind="merchant")
    detail = audit_text(
        "Compared with the QR saved by you. A matching baseline does not verify bank ownership; amounts and transaction references may legitimately change.",
        "आपके सहेजे QR से तुलना। मिलान बैंक स्वामित्व साबित नहीं करता; रकम और लेनदेन संदर्भ बदल सकते हैं।",
        "तुमच्या जतन केलेल्या QR शी तुलना. जुळल्याने बँक मालकी सिद्ध होत नाही; रक्कम आणि व्यवहार संदर्भ बदलू शकतात.")
    for code, before, after, changed in (
        ("baseline_vpa", exp_vpa, vpa, "vpa" in changes),
        ("baseline_name", exp_pn, pn, "name" in changes),
        ("baseline_mcc", req.expected_mcc, metadata["mcc"], "mcc" in changes),
        ("baseline_currency", req.expected_currency or "", metadata["currency"], "currency" in changes),
    ):
        known = before is not None if code == "baseline_mcc" else bool(before)
        evidence(baseline, code, "fail" if changed and code == "baseline_vpa" else "warn" if changed else "pass" if known else "unavailable",
                 f"{before or ('Not supplied' if known else 'No saved value')} → {after or 'Missing'}", detail)
    rank = {"SAFE": 0, "CAUTION": 1, "DANGER": 2}
    baseline_verdict = "DANGER" if not match else "CAUTION" if changes else "SAFE"
    verdict = max((baseline_verdict, analysis["verdict"]), key=rank.get)
    return {"match": match, "expected": {"vpa": exp_vpa, "pn": exp_pn, "mcc": req.expected_mcc, "currency": req.expected_currency},
            "found": {"vpa": vpa, "pn": pn, **metadata}, "changes": changes, "text": text,
            "name_text": extra, "verdict": verdict, "technical": baseline.technical, "analysis": analysis}


# ------------------------------------------------------------------ demo sheet + PWA
@app.get("/demo/sheet", response_class=HTMLResponse)
async def demo_sheet():
    sheet = ROOT / "demo" / "sheet.html"
    if not sheet.exists():
        return HTMLResponse("<p>Run <code>python demo/generate_sheet.py</code> first.</p>", 404)
    return HTMLResponse(sheet.read_text(encoding="utf-8"))


dist: Path = settings.frontend_dist


@app.get("/{path:path}", include_in_schema=False)
async def spa(path: str):
    if path.startswith("api/"):
        return JSONResponse({"detail": "Not Found"}, 404)
    if not dist.exists():
        return HTMLResponse("<h3>QR Shield API is running.</h3><p>Build the frontend: "
                            "<code>cd frontend && npm run build</code></p>")
    target = (dist / path).resolve()
    if path and target.is_file() and dist.resolve() in target.parents:
        return FileResponse(target)
    return FileResponse(dist / "index.html", headers={"Cache-Control": "no-cache"})
