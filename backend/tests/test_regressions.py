"""Safety regressions and stateless serverless behavior, beyond fixed demo fixtures."""
import pytest
from app.engine import analyze
from app.models import Signal
from app.engine import score
from app.analyzers.upi import analyze_upi
from app.models import Analysis


@pytest.mark.parametrize("payload", ["https://", "http://", "https://[broken", "https://bad host.example"])
async def test_invalid_url_never_green(db, offline, payload):
    result = await analyze(payload, "check", "text", db, offline)
    assert result["verdict"] == "CAUTION"
    assert result["summary"]["invalid_url"] is True
    assert "URL_INVALID" in {s["code"] for s in result["signals"]}


async def test_unresolved_short_link_never_green(db, offline):
    result = await analyze("https://bit.ly/qr-test", "check", "image", db, offline)
    assert result["verdict"] == "CAUTION"
    assert "URL_UNVERIFIED" in {s["code"] for s in result["signals"]}
    assert any(c["name"] == "redirects" and c["status"] == "skipped" for c in result["checks"])


async def test_normal_subscription_is_caution_not_scam(db, offline):
    result = await analyze("upi://mandate?pa=subscription@ybl&pn=Music%20Subscription&am=99&recur=MONTHLY&rev=Y", "check", "text", db, offline)
    assert result["verdict"] == "CAUTION"
    assert result["summary"]["mandate"]["revocable"] is True


async def test_subscription_receive_mismatch_still_danger(db, offline):
    result = await analyze("upi://mandate?pa=subscription@ybl&pn=Music&am=99&recur=MONTHLY&rev=Y", "receive", "text", db, offline)
    assert result["verdict"] == "DANGER"


def test_unverified_signature_has_no_trust_weight():
    result = Analysis(kind="upi")
    analyze_upi("upi://pay?pa=person@ybl&pn=Person&sign=YWJj", "check", result)
    assert next(s for s in result.signals if s.code == "UPI_SIGNED").weight == 0


def test_caution_override_survives_trust_signal():
    assert score([Signal("UNKNOWN", 25, force="CAUTION"), Signal("TRUST", -30)]) == (25, "CAUTION")


async def test_report_counts_do_not_manufacture_danger(db, offline):
    from app.util import payload_hash
    payload = "upi://pay?pa=someone@ybl&pn=Someone"
    for _ in range(25):
        db.add_report(payload_hash(payload), "Unverified allegation")
    result = await analyze(payload, "check", "text", db, offline)
    assert result["verdict"] == "CAUTION"
    assert result["reports"]["count"] == 25


def test_shop_rejects_parser_confusion_and_bad_identity():
    from app.main import _upi_identity
    assert _upi_identity("upi://pay?pa=good@ybl&pa=bad@axl&pn=Shop") is None
    assert _upi_identity("upi://pay?pa=bad@@ybl&pn=Shop") is None


async def test_official_start_does_not_skip_redirect_inspection(db, offline, monkeypatch):
    from app import ssrf, rdap
    calls = []
    async def expand(url, **kwargs):
        calls.append(url)
        return ssrf.ExpandResult(hops=[ssrf.Hop(url, 302), ssrf.Hop("https://evil.test/payload.apk", 200)], final_url="https://evil.test/payload.apk", status="ok")
    monkeypatch.setattr(ssrf, "expand", expand)
    async def lookup(*args, **kwargs):
        return "unsupported", None
    monkeypatch.setattr(rdap, "lookup_created", lookup)
    result = await analyze("https://sbi.co.in/go", "check", "text", db, offline)
    # Enable online behavior without relying on the real network.
    if not calls:
        from dataclasses import replace
        result = await analyze("https://sbi.co.in/go", "check", "text", db, replace(offline, online_checks=True))
    assert calls
    assert result["verdict"] == "DANGER"
