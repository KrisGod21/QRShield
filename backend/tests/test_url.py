import time

import pytest

from app.analyzers.url import Ctx, analyze_url, lexical, normalize_url
from app.domainutil import host_info, parse_ip
from app.homoglyph import skeleton
from app.models import Analysis


@pytest.fixture
def ctx(db):
    return Ctx(db=db, demo=True, online=False, deadline=time.monotonic() + 5)


def codes_for(url, ctx):
    a = Analysis(kind="url")
    lexical(normalize_url(url), a, ctx)
    return a, {s.code for s in a.signals}


# ------------------------------------------------------------------ homoglyphs
def test_skeleton_maps_lookalikes():
    assert skeleton("onlinesbі") == skeleton("onlinesbi")      # Cyrillic і
    assert skeleton("pаytm") == skeleton("paytm")              # Cyrillic а
    assert skeleton("paytrn") == skeleton("paytm")             # rn -> m
    assert skeleton("0nlinesbi") == skeleton("onlinesbi")      # zero -> o
    assert skeleton("hdfcbank") != skeleton("icicibank")


def test_homoglyph_domain(ctx):
    _, codes = codes_for("https://onlinesbі.test/login", ctx)
    assert "URL_HOMOGLYPH" in codes and "URL_PUNYCODE" in codes


def test_digit_homoglyph(ctx):
    _, codes = codes_for("https://0nlinesbi.com/", ctx)
    assert "URL_HOMOGLYPH" in codes


# ------------------------------------------------------------------ typosquat + brand
def test_typosquat(ctx):
    a, codes = codes_for("https://onlinesbl.test/kyc", ctx)
    assert "URL_TYPOSQUAT" in codes
    sig = next(s for s in a.signals if s.code == "URL_TYPOSQUAT")
    assert sig.params["brand"] == "SBI"


def test_brand_in_subdomain(ctx):
    _, codes = codes_for("http://sbi.co.in.verify-kyc.xyz/login", ctx)
    assert {"URL_BRAND_MISUSE", "URL_RISKY_TLD", "URL_SUSPICIOUS_WORDS"} <= codes


def test_brand_on_free_hosting(ctx):
    _, codes = codes_for("https://hdfc-netbanking-login.pages.dev/", ctx)
    assert {"URL_BRAND_MISUSE", "URL_FREE_HOSTING"} <= codes


def test_gov_impersonation(ctx):
    _, codes = codes_for("https://echallan-parivahan.test/pay", ctx)
    assert "URL_GOV_IMPERSONATION" in codes


# ------------------------------------------------------------------ trust signals
@pytest.mark.parametrize("url", [
    "https://onlinesbi.sbi.bank.in/", "https://www.hdfc.bank.in/", "https://www.hdfcbank.com/",
    "https://www.incometax.gov.in/iec/foportal/", "https://www.irctc.co.in/", "https://www.amazon.in/",
])
def test_official_sites_are_clean(ctx, url):
    a, codes = codes_for(url, ctx)
    assert codes & {"URL_OFFICIAL", "URL_BANK_IN", "URL_GOV_IN"}
    assert not [s for s in a.signals if s.weight > 0], a.signals


def test_user_pages_on_big_platforms_are_not_official(ctx):
    a, codes = codes_for("https://sites.google.com/view/sbi-kyc-update", ctx)
    assert "URL_OFFICIAL" not in codes and "URL_FREE_HOSTING" in codes
    _, codes = codes_for("https://pay.google.com/", ctx)
    assert "URL_OFFICIAL" in codes


def test_any_bank_in_is_trusted(ctx):
    _, codes = codes_for("https://newbank.bank.in/", ctx)
    assert "URL_BANK_IN" in codes


def test_unrelated_normal_site_has_no_flags(ctx):
    a, _ = codes_for("https://www.wikipedia.org/wiki/India", ctx)
    assert not [s for s in a.signals if s.weight > 0]


# ------------------------------------------------------------------ lexical tricks
def test_userinfo_trick(ctx):
    a, codes = codes_for("https://onlinesbi.sbi@evil-site.test/login", ctx)
    assert "URL_USERINFO" in codes
    assert a.summary["host"] == "evil-site.test"


def test_ip_host_and_decimal_ip(ctx):
    _, codes = codes_for("http://192.0.2.10/pay", ctx)
    assert "URL_IP_HOST" in codes
    assert str(parse_ip("3232235777")) == "192.168.1.1"
    _, codes = codes_for("http://3232235777/", ctx)
    assert "URL_IP_HOST" in codes


def test_risky_tld_shortener_port(ctx):
    _, codes = codes_for("https://bit.ly/abc", ctx)
    assert "URL_SHORTENER" in codes
    _, codes = codes_for("http://prize.claim-now.top:8080/", ctx)
    assert {"URL_RISKY_TLD", "URL_ODD_PORT", "URL_NO_HTTPS"} <= codes


def test_apk_and_remote_access(ctx):
    a, codes = codes_for("https://files.example.test/SBI_KYC.apk", ctx)
    assert any(s.code == "URL_APK_DOWNLOAD" and s.force == "DANGER" for s in a.signals)
    _, codes = codes_for("https://download.anydesk.test/AnyDesk.exe", ctx)
    assert {"URL_EXE_DOWNLOAD", "URL_REMOTE_ACCESS_APP"} <= codes


def test_play_store_remote_access(ctx):
    _, codes = codes_for("https://play.google.com/store/apps/details?id=com.anydesk.anydeskandroid", ctx)
    assert "APP_REMOTE_ACCESS" in codes


def test_whatsapp_chat_link(ctx):
    a, codes = codes_for("https://wa.me/919876543210?text=Pay%20task%20fee", ctx)
    assert "URL_OPENS_CHAT" in codes
    assert a.summary["chat"]["target"] == "+919876543210"


def test_normalize():
    assert normalize_url("  www.example.com/x ") == "http://www.example.com/x"
    assert normalize_url("https://a.test\\@evil.test/") == "https://a.test/@evil.test/"
    assert normalize_url("HTTPS://Example.com") == "https://Example.com"


def test_host_info_bank_in():
    h = host_info("onlinesbi.sbi.bank.in")
    assert h.registrable == "sbi.bank.in" and h.suffix == "bank.in"


# ------------------------------------------------------------------ full async path (demo fixtures)
async def test_demo_redirect_chain(ctx):
    a = Analysis(kind="url")
    await analyze_url("http://qrs.test/x7Kp", a, ctx)
    codes = {s.code for s in a.signals}
    assert {"URL_SHORTENER", "URL_REDIRECTS", "URL_BRAND_MISUSE", "URL_NEW_DOMAIN"} <= codes
    assert a.summary["final_host"] == "hdfcbank-rewards.test"


async def test_demo_apk_by_content_type(ctx):
    a = Analysis(kind="url")
    await analyze_url("https://echallan-parivahan.test/pay/mParivahan.apk", a, ctx)
    assert any(s.code == "URL_APK_DOWNLOAD" for s in a.signals)


async def test_demo_intel_hit(ctx):
    a = Analysis(kind="url")
    await analyze_url("http://free-recharge-offer.test/jio-399-free", a, ctx)
    assert any(s.code == "URL_INTEL_HIT" and s.force == "DANGER" for s in a.signals)
