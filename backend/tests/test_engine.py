import ast
import pathlib

import pytest
from fastapi.testclient import TestClient

from app import i18n
from app.analyzers.other import parse_wifi
from app.engine import analyze, classify, score
from app.models import Signal
from app.util import format_inr

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"


# ------------------------------------------------------------------ classification
@pytest.mark.parametrize("payload,kind", [
    ("upi://pay?pa=a@ybl", "upi"), ("UPI://PAY?pa=a@ybl", "upi"), ("000201010211", "bharat_qr"),
    ("https://x.com", "url"), ("www.example.com", "url"), ("example.co.in/path", "url"),
    ("javascript:alert(1)", "dangerous_scheme"), ("data:text/html,hi", "dangerous_scheme"),
    ("WIFI:S:x;T:WPA;P:y;;", "wifi"), ("tel:123", "tel"), ("SMSTO:123:hi", "sms"),
    ("mailto:a@b.com", "email"), ("geo:1,2", "geo"), ("BEGIN:VCARD\nFN:A\nEND:VCARD", "vcard"),
    ("MECARD:N:A;;", "vcard"), ("BEGIN:VEVENT\nSUMMARY:x\nEND:VEVENT", "event"),
    ("market://details?id=x", "app"), ("intent://scan/#Intent;package=x;end", "app"),
    ("bitcoin:bc1qxyz", "crypto"), ("FIDO:/1234", "fido"), ("otpauth://totp/A:b?secret=X", "otp"),
    ("hello world", "text"), ("whatsapp://send?phone=91999", "chat"),
])
def test_classify(payload, kind):
    assert classify(payload) == kind


# ------------------------------------------------------------------ scoring
def test_score_thresholds():
    assert score([Signal("A", 10)]) == (10, "SAFE")
    assert score([Signal("A", 25)]) == (25, "CAUTION")
    assert score([Signal("A", 59)]) == (59, "CAUTION")
    assert score([Signal("A", 60)]) == (60, "DANGER")
    assert score([Signal("A", 80), Signal("B", 80)]) == (100, "DANGER")


def test_score_force_and_floor():
    assert score([Signal("A", 5, force="DANGER")])[1] == "DANGER"
    # A strong red flag is not cancelled by a trust signal.
    assert score([Signal("A", 40), Signal("B", -30)])[1] == "CAUTION"
    assert score([Signal("A", -30)]) == (0, "SAFE")


def test_format_inr():
    assert format_inr("4999.00") == "₹4,999"
    assert format_inr("100000") == "₹1,00,000"
    assert format_inr("12345678.5") == "₹1,23,45,678.50"
    assert format_inr("10") == "₹10"


# ------------------------------------------------------------------ other payloads
def test_wifi_escapes():
    f = parse_wifi(r'WIFI:T:WPA;S:my\;net;P:pa\:ss;H:true;;')
    assert f == {"T": "WPA", "S": "my;net", "P": "pa:ss", "H": "true"}


async def _verdict(payload, db, offline, intent="check"):
    r = await analyze(payload, intent, "camera", db, offline)
    return r["verdict"], {s["code"] for s in r["signals"]}


@pytest.mark.parametrize("payload,verdict,code", [
    ("WIFI:S:Cafe_Guest;T:nopass;;", "CAUTION", "WIFI_OPEN"),
    ("WIFI:S:Free_Airport_WiFi;T:nopass;;", "DANGER", "WIFI_LOOKALIKE"),
    ("WIFI:S:Home;T:WEP;P:x;;", "CAUTION", "WIFI_WEP"),
    ("WIFI:S:Home;T:WPA;P:secret;;", "SAFE", "WIFI_INFO"),
    ("tel:*401*9876543210#", "DANGER", "TEL_USSD"),
    ("tel:**21*9876543210%23", "DANGER", "TEL_USSD"),
    ("tel:+923001234567", "CAUTION", "TEL_FOREIGN"),
    ("tel:1930", "SAFE", "TEL_HELPLINE_1930"),
    ("SMSTO:56767:START GAME", "CAUTION", "SMS_SHORTCODE"),
    ("BEGIN:VCARD\nFN:SBI Customer Care\nTEL:9876543210\nEND:VCARD", "CAUTION", "VCARD_BANK_PERSONAL"),
    ("market://details?id=com.anydesk.anydeskandroid", "DANGER", "APP_REMOTE_ACCESS"),
    ("javascript:fetch('//x.test')", "DANGER", "URL_DANGEROUS_SCHEME"),
    ("bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq?amount=0.1", "CAUTION", "CRYPTO_PAYMENT"),
    ("FIDO:/1234567890123456789", "CAUTION", "FIDO_LOGIN"),
    ("Congratulations! You won KBC lottery. Visit http://kbc-prize.top/claim", "DANGER", "TEXT_SCAM_KEYWORD"),
])
async def test_other_payload_verdicts(db, offline, payload, verdict, code):
    v, codes = await _verdict(payload, db, offline)
    assert code in codes
    assert v == verdict, codes


async def test_text_with_embedded_vpa(db, offline):
    v, codes = await _verdict("Pay your refund fee to sbi.refund@ybI now", db, offline)
    assert "UPI_HANDLE_TYPO" in codes and v == "DANGER"


async def test_upi_ref_url_is_analysed(db, offline):
    v, codes = await _verdict("upi://pay?pa=verify.account@ibl&pn=NPCI%20Verification&am=1"
                              "&tn=Verify%20to%20receive%20cashback&url=http://bit.ly/claim-upi-reward",
                              db, offline)
    assert {"UPI_REF_URL", "URL_SHORTENER"} <= codes and v == "DANGER"


async def test_community_reports_raise_score(db, offline):
    p = "upi://pay?pa=someone@oksbi&pn=Someone"
    v0, _ = await _verdict(p, db, offline)
    from app.util import payload_hash
    for _ in range(5):
        db.add_report(payload_hash(p), "scam")
    v1, codes = await _verdict(p, db, offline)
    assert v0 == "SAFE" and v1 == "CAUTION" and "COMMUNITY_REPORTED" in codes


# ------------------------------------------------------------------ i18n completeness
def _codes_used_in_source() -> set[str]:
    codes = set()
    for f in APP_DIR.rglob("*.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "add" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.isupper():
                    codes.add(arg.value)
    return codes


def test_every_signal_has_three_languages():
    used = _codes_used_in_source()
    assert len(used) > 50
    missing = [c for c in used if c not in i18n.M and not any(k.startswith(c + ".") for k in i18n.M)]
    assert missing == []
    for key, t in i18n.M.items():
        assert set(t) == set(i18n.LANGS), key
        assert all(t[lang].strip() for lang in i18n.LANGS), key


def test_keyword_variants_cover_all_categories():
    from app.data.keywords import SCAM_KEYWORDS
    for cat in SCAM_KEYWORDS:
        assert f"UPI_SCAM_KEYWORD.{cat}" in i18n.M, cat


def test_render_placeholders_filled():
    out = i18n.render("UPI_HANDLE_TYPO", {"handle": "ybI", "similar": "ybl"})
    assert "@ybI" in out["en"] and "@ybl" in out["hi"] and "@ybl" in out["mr"]
    assert "{" not in "".join(out.values())


# ------------------------------------------------------------------ API
@pytest.fixture
def client(tmp_path, monkeypatch):
    import app.main as main
    from app.db import DB
    from app import demo_fixtures
    test_db = DB(tmp_path / "t.sqlite3")
    demo_fixtures.seed(test_db)
    monkeypatch.setattr(main, "db", test_db)
    monkeypatch.setattr(main, "settings", main.settings.__class__(demo_mode=True, online_checks=False, feeds=False))
    with TestClient(main.app) as c:
        yield c


def test_api_analyze(client):
    r = client.post("/api/analyze", json={"payload": "tel:*401*99#", "intent": "check"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "DANGER"
    assert set(body["headline"]) == {"en", "hi", "mr"}
    assert body["signals"][0]["text"]["mr"]


def test_api_rejects_bad_input(client):
    assert client.post("/api/analyze", json={"payload": "  "}).status_code == 400
    assert client.post("/api/analyze", json={"payload": "x" * 5000}).status_code == 422
    assert client.post("/api/analyze", json={"payload": "x", "intent": "hack"}).status_code == 422


def test_api_report_roundtrip(client):
    p = "upi://pay?pa=new.scam@ybl&pn=Scam"
    r1 = client.post("/api/report", json={"payload": p, "reason": "fake"}).json()
    r2 = client.post("/api/report", json={"payload": p, "reason": "fake again"}).json()
    assert r2["count"] == r1["count"] + 1
    info = client.get(f"/api/reports/{r2['payload_hash']}").json()
    assert info["count"] == r2["count"] and "fake again" in info["reasons"]
    res = client.post("/api/analyze", json={"payload": p}).json()
    assert res["reports"]["count"] == r2["count"]


def test_api_shop_register_and_verify(client):
    good = "upi://pay?pa=qrshield.demo.kirana@ybl&pn=Ramesh%20Kirana%20Store"
    swapped = "upi://pay?pa=chhotu.t9921@axl&pn=Ramesh%20Kirana%20Store"
    reg = client.post("/api/shop/register", json={"payload": good, "shop_name": "Ramesh Kirana"}).json()
    code = reg["shop_code"]
    ok = client.post("/api/shop/verify", json={"payload": good, "shop_code": code}).json()
    assert ok["match"] is True
    bad = client.post("/api/shop/verify", json={"payload": swapped, "shop_code": code.lower()}).json()
    assert bad["match"] is False and bad["changes"] == ["vpa"]
    assert "chhotu.t9921@axl" in bad["text"]["en"]
    notupi = client.post("/api/shop/verify", json={"payload": "https://x.test", "expected_vpa": "a@ybl"}).json()
    assert notupi["match"] is False and notupi["changes"] == ["not_upi"]
    assert client.post("/api/shop/register", json={"payload": "hello"}).status_code == 400


def test_api_health(client):
    h = client.get("/api/health").json()
    assert h["ok"] and h["demo"] is True
