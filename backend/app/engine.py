"""Classify a decoded QR payload, run the right analyzer, score and explain it."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

from . import i18n
from .analyzers import other
from .analyzers.emv import analyze_emv
from .analyzers.upi import analyze_upi, analyze_upi_params
from .analyzers.url import Ctx, analyze_url, merge
from .config import Settings
from .db import DB
from .models import Analysis, Signal
from .util import payload_hash, truncate

SAFE_MAX = 24      # score <= 24 -> SAFE
CAUTION_MAX = 59   # 25..59 -> CAUTION, >= 60 -> DANGER

_DOMAIN_RE = re.compile(r"^(www\.)?[a-z0-9\-]+(\.[a-z0-9\-]+)*\.[a-z]{2,}(:\d+)?([/?#]\S*)?$", re.I)
_CRYPTO = ("bitcoin:", "ethereum:", "litecoin:", "dogecoin:", "bitcoincash:", "monero:", "tron:", "usdt:")


def classify(payload: str) -> str:
    p = payload.strip()
    low = p.lower()
    if low.startswith("upi:"):
        return "upi"
    if p.startswith("000201"):
        return "bharat_qr"
    if low.startswith(("javascript:", "data:", "vbscript:", "file:")):
        return "dangerous_scheme"
    if low.startswith("wifi:"):
        return "wifi"
    if low.startswith("tel:"):
        return "tel"
    if low.startswith(("sms:", "smsto:", "mms:", "mmsto:")):
        return "sms"
    if low.startswith(("mailto:", "matmsg:")):
        return "email"
    if low.startswith("geo:"):
        return "geo"
    if low.startswith(("begin:vcard", "mecard:")):
        return "vcard"
    if low.startswith(("begin:vevent", "begin:vcalendar")):
        return "event"
    if low.startswith(("market://", "intent:")):
        return "app"
    if low.startswith(("whatsapp://", "tg://")):
        return "chat"
    if low.startswith(_CRYPTO):
        return "crypto"
    if low.startswith("fido:/"):
        return "fido"
    if low.startswith("otpauth://"):
        return "otp"
    if low.startswith(("http://", "https://")) or (" " not in p and "\n" not in p and _DOMAIN_RE.match(p)):
        return "url"
    return "text"


def score(signals: list[Signal]) -> tuple[int, str]:
    total = max(0, min(100, sum(s.weight for s in signals)))
    if any(s.force == "DANGER" for s in signals):
        return max(total, 60), "DANGER"
    verdict = "SAFE" if total <= SAFE_MAX else "CAUTION" if total <= CAUTION_MAX else "DANGER"
    if verdict == "SAFE" and any(s.force == "CAUTION" for s in signals):
        verdict, total = "CAUTION", max(total, SAFE_MAX + 1)
    # A single strong red flag is never hidden by trust signals.
    if verdict == "SAFE" and any(s.weight >= 35 for s in signals):
        verdict, total = "CAUTION", max(total, SAFE_MAX + 1)
    return total, verdict


async def analyze(payload: str, intent: str, source: str, db: DB, settings: Settings) -> dict[str, Any]:
    t0 = time.monotonic()
    payload = payload.strip()
    ctx = Ctx(db=db, demo=settings.demo_mode, online=settings.online_checks,
              deadline=t0 + settings.time_budget, intent=intent)
    kind = classify(payload)
    a = Analysis(kind=kind)
    nested_urls: list[str] = []
    nested_vpas: list[str] = []

    if kind == "upi":
        nested_urls = analyze_upi(payload, intent, a)
    elif kind == "bharat_qr":
        nested_urls = analyze_emv(payload, intent, a)
    elif kind == "url":
        await analyze_url(payload, a, ctx)
    elif kind == "dangerous_scheme":
        scheme = payload.split(":", 1)[0].lower()
        a.summary.update({"scheme": scheme, "content": truncate(payload, 120)})
        a.headline_code = "HEAD_DANGEROUS_SCHEME"
        a.add("URL_DANGEROUS_SCHEME", 100, force="DANGER", scheme=scheme)
    elif kind == "wifi":
        other.analyze_wifi(payload, a)
    elif kind == "tel":
        other.analyze_tel(payload, a)
    elif kind == "sms":
        nested_urls = other.analyze_sms(payload, a)
    elif kind == "email":
        nested_urls = other.analyze_email(payload, a)
    elif kind == "geo":
        other.analyze_geo(payload, a)
    elif kind == "vcard":
        nested_urls = other.analyze_vcard(payload, a)
    elif kind == "event":
        nested_urls = other.analyze_event(payload, a)
    elif kind == "app":
        nested_urls = other.analyze_app(payload, a)
    elif kind == "chat":
        app = "WhatsApp" if payload.lower().startswith("whatsapp") else "Telegram"
        m = re.search(r"phone=([+\d]+)", payload)
        target = m.group(1) if m else "?"
        a.summary["chat"] = {"app": app, "target": target, "text": ""}
        a.headline_code, a.headline_params = "HEAD_CHAT", {"app": app, "target": target}
        a.add("URL_OPENS_CHAT", 10, app=app, target=target)
    elif kind == "crypto":
        other.analyze_crypto(payload, a)
    elif kind == "fido":
        other.analyze_fido(payload, a)
    elif kind == "otp":
        other.analyze_otp(payload, a)
    else:
        nested_urls, nested_vpas = other.analyze_text(payload, a)

    # Links and UPI IDs found inside other payloads are analysed too; their red flags count.
    nested_report = []
    for u in nested_urls[:2]:
        sub = Analysis(kind="url")
        await analyze_url(u, sub, ctx)
        merge(a, sub, positive_only=True)
        nested_report.append({"url": truncate(u, 80), "score": score(sub.signals)[0]})
    for v in nested_vpas[:2]:
        sub = Analysis(kind="upi_pay")
        analyze_upi_params("pay", {"pa": v, "pn": ""}, [], "check", sub)
        sub.signals = [s for s in sub.signals if s.code != "UPI_PAY_INFO"]
        merge(a, sub, positive_only=True)
    if nested_report:
        a.summary["nested"] = nested_report

    h = payload_hash(payload)
    reports = db.report_count(h)
    if reports:
        # Unverified report counts are advisory, never proof of maliciousness.
        a.add("COMMUNITY_REPORTED", 15, force="CAUTION", count=reports)

    total, verdict = score(a.signals)
    ordered = sorted(a.signals, key=lambda s: (s.force != "DANGER", -s.weight if s.weight > 0 else 1000 - s.weight))
    return {
        "id": uuid.uuid4().hex[:12],
        "kind": a.kind,
        "verdict": verdict,
        "score": total,
        "headline": i18n.render(a.headline_code, a.headline_params),
        "summary": a.summary,
        "signals": [{
            "code": s.code, "severity": s.severity, "weight": s.weight, "params": s.params,
            "variant": s.variant, "text": i18n.render(s.code, s.params, s.variant),
        } for s in ordered],
        "checks": [{"name": c.name, "status": c.status, "ms": c.ms} for c in a.checks],
        "technical": a.technical,
        "reports": {"count": reports},
        "payload_hash": h,
        "intent": intent,
        "source": source,
        "elapsed_ms": int((time.monotonic() - t0) * 1000),
        "demo": settings.demo_mode,
    }
