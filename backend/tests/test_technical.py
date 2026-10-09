"""Technical evidence and tampering regressions using deterministic responses."""
from dataclasses import replace
from urllib.parse import quote

import httpx
import pytest

from app import rdap, ssrf
from app.analyzers.emv import crc16_ccitt, crc_ok, parse_tlv, extract_vpa
from app.engine import analyze


def codes(result):
    return {s["code"] for s in result["signals"]}


async def test_query_conflicts_cannot_be_cancelled_by_official_domain(db, offline):
    r = await analyze("https://onlinesbi.sbi.bank.in/?next=/a&next=/b", "check", "text", db, offline)
    assert r["verdict"] != "SAFE"
    assert "URL_QUERY_CONFLICT" in codes(r)
    assert any(f["id"] == "query" and f["status"] == "warn" for f in r["technical"])


async def test_identical_query_duplicates_are_not_conflicts(db, offline):
    r = await analyze("https://example.test/?tag=a&tag=a", "check", "text", db, offline)
    assert "URL_QUERY_CONFLICT" not in codes(r)


@pytest.mark.parametrize("target", ["https://download.test/payload.apk", "javascript:alert(1)"])
async def test_double_encoded_destinations_receive_lexical_inspection(db, offline, target):
    url = "https://example.test/?next=" + quote(quote(target, safe=""), safe="")
    r = await analyze(url, "check", "text", db, offline)
    assert r["verdict"] == "DANGER"
    assert "URL_EMBEDDED_DESTINATION" in codes(r)
    assert any(f["id"] == "embedded" and "not an observed redirect" in f["detail"]["en"] for f in r["technical"])


async def test_embedded_destination_is_never_fetched(db, offline, monkeypatch):
    seen = []
    async def expand(url, **kwargs):
        seen.append(url)
        return ssrf.ExpandResult(hops=[ssrf.Hop(url, 200)], final_url=url)
    async def age(*args, **kwargs):
        return "unsupported", None
    monkeypatch.setattr(ssrf, "expand", expand)
    monkeypatch.setattr(rdap, "lookup_created", age)
    url = "https://example.test/?next=https%3A%2F%2Fother.test%2F"
    await analyze(url, "check", "text", db, replace(offline, online_checks=True))
    assert seen == [url]


@pytest.mark.parametrize("raw", ["https://example.test\\@evil.test/", "https://exam\nple.test/"])
async def test_ambiguous_parser_input_disables_open(db, offline, raw):
    r = await analyze(raw, "check", "text", db, offline)
    assert "URL_PARSER_AMBIGUITY" in codes(r)
    assert r["summary"]["invalid_url"] is True


@pytest.mark.parametrize("status,ctype,extra", [(200, "text/html", "URL_HTTPS_DOWNGRADE"),
    (403, "text/html", "URL_UNVERIFIED"),
    (200, "application/x-msdownload", "URL_EXE_DOWNLOAD")])
async def test_observed_response_risks(db, offline, monkeypatch, status, ctype, extra):
    async def expand(url, **kwargs):
        return ssrf.ExpandResult(hops=[ssrf.Hop(url, 302, "8.8.8.8"), ssrf.Hop("http://landing.test/", status, "1.1.1.1")],
            final_url="http://landing.test/", content_type=ctype)
    async def age(*args, **kwargs):
        return "unsupported", None
    monkeypatch.setattr(ssrf, "expand", expand)
    monkeypatch.setattr(rdap, "lookup_created", age)
    r = await analyze("https://example.test/", "check", "text", db, replace(offline, online_checks=True))
    assert extra in codes(r)
    assert r["verdict"] != "SAFE"
    assert r["summary"]["hops"][1]["ip"] == "1.1.1.1"


async def test_offline_and_demo_evidence_never_claim_live_tls(db, offline):
    for url in ("https://example.test/", "https://onlinesbi.sbi.bank.in/"):
        r = await analyze(url, "check", "text", db, offline)
        assert all(f["status"] != "pass" for f in r["technical"] if f["id"] == "transport")
        assert any(f["id"] == "api" and f["status"] == "unavailable" for f in r["technical"])


@pytest.mark.parametrize("params,signal", [("&mc=ABCD", "UPI_BAD_MCC"), ("&am=10&mam=20", "UPI_BAD_MIN_AMOUNT"),
    ("&mam=oops", "UPI_BAD_MIN_AMOUNT"), ("&mam=0", "UPI_BAD_MIN_AMOUNT")])
async def test_payment_metadata_validation(db, offline, params, signal):
    r = await analyze("upi://pay?pa=shop@ybl&pn=Shop" + params, "pay_shop", "image", db, offline)
    assert signal in codes(r)
    assert r["verdict"] != "SAFE"


async def test_signature_presence_does_not_authenticate_owner(db, offline):
    r = await analyze("upi://pay?pa=shop@ybl&pn=Shop&sign=YWJj", "check", "text", db, offline)
    assert any(f["id"] == "signature" and f["status"] == "unavailable" for f in r["technical"])
    assert any(f["id"] == "ownership" and f["status"] == "unavailable" for f in r["technical"])
    assert next(s for s in r["signals"] if s["code"] == "UPI_SIGNED")["weight"] == 0


@pytest.mark.parametrize("payload,changes,verdict", [
    ("upi://pay?pa=shop@ybl&pn=Store&mc=5411&am=20", [], "SAFE"),
    ("upi://pay?pa=attacker@ybl&pn=Store&mc=5411", ["vpa"], "DANGER"),
    ("upi://pay?pa=shop@ybl&pn=Other&mc=5411", ["name"], "CAUTION"),
    ("upi://pay?pa=shop@ybl&pn=Store&mc=5999", ["mcc"], "CAUTION"),
    ("upi://pay?pa=shop@ybl&mc=5411", ["name"], "CAUTION"),
])
async def test_merchant_comparison_and_dynamic_amount(db, offline, monkeypatch, payload, changes, verdict):
    from app import main
    from app.models import ShopVerifyRequest
    monkeypatch.setattr(main, "db", db)
    monkeypatch.setattr(main, "settings", offline)
    r = await main.shop_verify(ShopVerifyRequest(payload=payload, expected_vpa="shop@ybl", expected_name="Store", expected_mcc="5411", expected_currency="INR"))
    assert r["changes"] == changes
    assert r["verdict"] == verdict
    assert r["analysis"]["technical"]
    assert len(r["technical"]) == 4


@pytest.mark.parametrize("expected,found", [("राम", "सीता"), ("राम", "रामा")])
async def test_unicode_merchant_name_change_is_detected(db, offline, monkeypatch, expected, found):
    from app import main
    from app.models import ShopVerifyRequest
    monkeypatch.setattr(main, "db", db)
    monkeypatch.setattr(main, "settings", offline)
    r = await main.shop_verify(ShopVerifyRequest(payload=f"upi://pay?pa=shop@ybl&pn={found}", expected_vpa="shop@ybl", expected_name=expected))
    assert "name" in r["changes"]


def test_crc_and_tlv_parser_reject_trailing_data_and_duplicate_tags():
    body = "0002015904Shop6304"
    qr = body + crc16_ccitt(body.encode())
    assert crc_ok(qr)
    assert not crc_ok(qr + "9901x")
    assert parse_tlv("000201000201") is None
    assert extract_vpa({"26": "0004CARD0110shop@icici"}) is None


async def test_private_redirect_stops_before_request_and_has_evidence(db, offline, monkeypatch):
    async def expand(url, **kwargs):
        return ssrf.ExpandResult(hops=[ssrf.Hop(url, 302, "8.8.8.8"), ssrf.Hop("http://127.0.0.1/admin", error="private-ip")],
            final_url="http://127.0.0.1/admin", status="blocked", reason="private-ip")
    async def age(*args, **kwargs):
        return "unsupported", None
    monkeypatch.setattr(ssrf, "expand", expand)
    monkeypatch.setattr(rdap, "lookup_created", age)
    r = await analyze("https://example.test/", "check", "text", db, replace(offline, online_checks=True))
    assert any(f["id"] == "dns" and f["status"] == "warn" for f in r["technical"])
    assert r["verdict"] != "SAFE"


async def test_explicit_personal_category_baseline_detects_added_mcc(db, offline, monkeypatch):
    from app import main
    from app.models import ShopVerifyRequest
    monkeypatch.setattr(main, "db", db)
    monkeypatch.setattr(main, "settings", offline)
    r = await main.shop_verify(ShopVerifyRequest(payload="upi://pay?pa=shop@ybl&pn=Shop&mc=5411", expected_vpa="shop@ybl", expected_name="Shop", expected_mcc=""))
    assert "mcc" in r["changes"]
    assert r["verdict"] == "CAUTION"


async def test_matching_merchant_still_reports_embedded_link_danger(db, offline, monkeypatch):
    from app import main
    from app.models import ShopVerifyRequest
    monkeypatch.setattr(main, "db", db)
    monkeypatch.setattr(main, "settings", offline)
    r = await main.shop_verify(ShopVerifyRequest(payload="upi://pay?pa=shop@ybl&pn=Shop&url=https%3A%2F%2Ffiles.test%2Fapp.apk", expected_vpa="shop@ybl", expected_name="Shop"))
    assert r["match"] is True
    assert r["verdict"] == "DANGER"
    assert "URL_APK_DOWNLOAD" in codes(r["analysis"])


async def test_bidi_payee_controls_are_reviewed_without_flagging_hindi(db, offline):
    r = await analyze("upi://pay?pa=shop@ybl&pn=Shop%E2%80%AE", "check", "image", db, offline)
    assert "UPI_DISPLAY_CONTROL" in codes(r)
    assert r["verdict"] != "SAFE"
    r = await analyze("upi://pay?pa=shop@ybl&pn=राम", "check", "image", db, offline)
    assert "UPI_DISPLAY_CONTROL" not in codes(r)


async def test_malformed_redirect_destination_does_not_crash_evidence(db, offline, monkeypatch):
    async def expand(url, **kwargs):
        return ssrf.ExpandResult(hops=[ssrf.Hop(url, 302), ssrf.Hop("https://[broken", error="ValueError")],
            final_url="https://[broken", status="error", reason="ValueError")
    async def age(*args, **kwargs):
        return "unsupported", None
    monkeypatch.setattr(ssrf, "expand", expand)
    monkeypatch.setattr(rdap, "lookup_created", age)
    r = await analyze("https://example.test/", "check", "text", db, replace(offline, online_checks=True))
    assert r["verdict"] != "SAFE"
    assert r["summary"]["invalid_url"] is True


@pytest.mark.parametrize("payload,secret", [
    ("WIFI:S:Home;T:WPA;P:private-password-789;;", "private-password-789"),
    ("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"),
    ("tel:*401*9876543210#", ""),
    ("https://", ""),
])
async def test_every_result_exposes_inspection_without_secrets(db, offline, payload, secret):
    import json
    r = await analyze(payload, "check", "text", db, offline)
    assert r["technical"]
    assert any(f["status"] == "unavailable" for f in r["technical"])
    if secret:
        assert secret not in json.dumps(r["technical"])
