from app.analyzers.emv import analyze_emv, crc16_ccitt, crc_ok, extract_vpa, parse_tlv
from app.analyzers.upi import _closest_handle, analyze_upi, parse_query, split_upi, vpa_problems
from app.models import Analysis


def run(payload, intent="check"):
    a = Analysis(kind="upi")
    analyze_upi(payload, intent, a)
    return a, {s.code for s in a.signals}


# ------------------------------------------------------------------ parsing
def test_split_basic_and_case_insensitive_scheme():
    action, params, dups = split_upi("UPI://Pay?pa=shop@ybl&pn=Ram%20Store&am=10.00")
    assert action == "pay"
    assert params == {"pa": "shop@ybl", "pn": "Ram Store", "am": "10.00"}
    assert dups == []


def test_plus_is_space_only_in_free_text():
    params, _ = parse_query("pa=a+b@ybl&pn=Ram+Kumar&tn=hello+there")
    assert params["pn"] == "Ram Kumar" and params["tn"] == "hello there"
    assert params["pa"] == "a+b@ybl"


def test_bare_percent_does_not_crash():
    params, _ = parse_query("pa=x@ybl&pn=100%&tn=50% off")
    assert params["pa"] == "x@ybl"


def test_duplicate_param_detected():
    _, codes = run("upi://pay?pa=shop@paytm&pn=Shop&pa=attacker99@axl&am=500")
    assert "UPI_DUPLICATE_PARAM" in codes


def test_identical_duplicate_is_not_flagged():
    _, codes = run("upi://pay?pa=shop@paytm&pa=shop@paytm&pn=Shop")
    assert "UPI_DUPLICATE_PARAM" not in codes


# ------------------------------------------------------------------ VPA + handle
def test_vpa_validation():
    assert not vpa_problems("ramesh.kirana-1@okicici")
    assert vpa_problems("help desk@sbi")
    assert vpa_problems("a@@sbi")
    assert vpa_problems("a@b@c")
    assert vpa_problems("@ybl")
    assert vpa_problems("x..y@ybl")
    assert vpa_problems("shop@yb.l")
    assert vpa_problems("shop@уbl")  # Cyrillic у


def test_handle_typo_variants():
    assert _closest_handle("okaxisbank") == "okaxis"
    assert _closest_handle("ybI") == "ybl"          # capital I for l
    assert _closest_handle("paytm1") == "paytm"
    assert _closest_handle("oksbii") is not None
    assert _closest_handle("zz") is None


def test_known_handle_is_quiet():
    _, codes = run("upi://pay?pa=ramesh@oksbi&pn=Ramesh")
    assert not codes & {"UPI_HANDLE_TYPO", "UPI_HANDLE_UNKNOWN"}


def test_unknown_handle_soft_warning():
    a, codes = run("upi://pay?pa=merchant123@zzbank&pn=Merchant")
    assert "UPI_HANDLE_UNKNOWN" in codes
    assert next(s for s in a.signals if s.code == "UPI_HANDLE_UNKNOWN").weight < 25


def test_sebi_valid_handle_is_positive():
    a, codes = run("upi://pay?pa=abc.brk@validhdfc&pn=ABC%20Broking")
    assert "UPI_HANDLE_VERIFIED" in codes


def test_missing_pa_forces_danger():
    a, _ = run("upi://pay?pn=Someone&am=10")
    assert any(s.code == "UPI_MISSING_PA" and s.force == "DANGER" for s in a.signals)


# ------------------------------------------------------------------ semantics
def test_receive_intent_is_always_danger():
    a, _ = run("upi://pay?pa=friend@oksbi&pn=Friend", intent="receive")
    assert any(s.code == "UPI_RECEIVE_INTENT" and s.force == "DANGER" for s in a.signals)


def test_refund_scam_signals():
    a, codes = run("upi://pay?pa=refund.desk2291@ybl&pn=Amazon%20Refund%20Dept&am=4999.00"
                   "&tn=Scan%20to%20receive%20your%20refund")
    assert {"UPI_IMPERSONATION", "UPI_PREFILLED_P2P", "UPI_SCAM_KEYWORD"} <= codes
    cats = {s.variant for s in a.signals if s.code == "UPI_SCAM_KEYWORD"}
    assert cats & {"refund", "receive"}
    assert a.summary["amount_fmt"] == "₹4,999" and a.summary["amount_locked"] is True


def test_hindi_and_marathi_keywords():
    _, codes = run("upi://pay?pa=x@ybl&pn=X&tn=%E0%A4%87%E0%A4%A8%E0%A4%BE%E0%A4%AE")  # इनाम
    assert "UPI_SCAM_KEYWORD" in codes
    _, codes = run("upi://pay?pa=x@ybl&pn=X&tn=" + "परतावा")
    assert "UPI_SCAM_KEYWORD" in codes


def test_normal_merchant_qr_is_clean():
    a, codes = run("upi://pay?pa=dmart.razorpay@hdfcbank&pn=DMart&tr=RZP123&am=100&cu=INR&mc=5411")
    bad = [s for s in a.signals if s.weight > 0]
    assert bad == [], bad


def test_brand_on_own_handle_is_not_impersonation():
    _, codes = run("upi://pay?pa=amazonpaygrocery@apl&pn=Amazon%20Pay&mc=5411")
    assert "UPI_IMPERSONATION" not in codes


def test_amount_editable_with_mam_is_not_locked():
    a, codes = run("upi://pay?pa=x@ybl&pn=X&am=500&mam=100")
    assert a.summary["amount_locked"] is False
    assert "UPI_PREFILLED_P2P" not in codes


def test_bad_currency_and_amount():
    _, codes = run("upi://pay?pa=x@ybl&pn=X&am=1,000&cu=USD")
    assert {"UPI_BAD_AMOUNT", "UPI_BAD_CURRENCY"} <= codes


def test_mandate_irrevocable():
    a, codes = run("upi://mandate?pa=s@ybl&pn=Subs&am=9999&recur=MONTHLY&validityend=09102036&rev=N")
    assert {"UPI_MANDATE", "UPI_MANDATE_IRREVOCABLE"} <= codes
    assert a.kind == "upi_mandate"
    assert a.summary["mandate"]["until"] == "09/10/2036"


def test_collect_scheme_flagged():
    a, codes = run("upi://collect?pa=army.officer@ptyes&pn=Army&am=5000")
    assert "UPI_COLLECT_SCHEME" in codes and a.kind == "upi_other"


def test_official_vpa_lookalike():
    _, codes = run("upi://pay?pa=pmcare@sbi&pn=PM%20CARES")
    assert "UPI_OFFICIAL_LOOKALIKE" in codes
    _, codes = run("upi://pay?pa=pmcares@sbi&pn=PM%20CARES")
    assert "UPI_OFFICIAL_LOOKALIKE" not in codes


def test_business_name_on_mobile_number_vpa():
    _, codes = run("upi://pay?pa=9876543210@ybl&pn=Sharma%20Medical%20Store")
    assert "UPI_BUSINESS_NAME_PERSONAL_VPA" in codes


def test_signature_presence():
    _, codes = run("upi://pay?pa=x@ybl&pn=X&mode=02&orgid=159761&sign=aGVsbG8gd29ybGQ=")
    assert "UPI_SIGNED" in codes
    _, codes = run("upi://pay?pa=x@ybl&pn=X&sign=not*base64!")
    assert "UPI_SIGN_MALFORMED" in codes


def test_ref_url_returned_for_nested_analysis():
    a = Analysis(kind="upi")
    nested = analyze_upi("upi://pay?pa=v@ibl&pn=NPCI&url=http://bit.ly/claim", "check", a)
    assert nested == ["http://bit.ly/claim"]


# ------------------------------------------------------------------ Bharat QR (EMVCo)
def _emv(fields: list[tuple[str, str]]) -> str:
    body = "".join(f"{t}{len(v):02d}{v}" for t, v in fields) + "6304"
    return body + crc16_ccitt(body.encode())


def test_crc16_known_vector():
    assert crc16_ccitt(b"123456789") == "29B1"  # CRC-16/CCITT-FALSE check value


def test_bharat_qr_vpa_extraction_and_crc():
    upi_tmpl = "0010A00000052401" + f"{len('shop@icici'):02d}shop@icici"
    qr = _emv([("00", "01"), ("01", "11"), ("26", upi_tmpl), ("52", "5411"), ("53", "356"),
               ("58", "IN"), ("59", "RAMESH STORE"), ("60", "MUMBAI")])
    assert crc_ok(qr)
    assert extract_vpa(parse_tlv(qr)) == "shop@icici"
    a = Analysis(kind="bharat_qr")
    analyze_emv(qr, "check", a)
    assert a.summary["vpa"] == "shop@icici"
    assert not any(s.code == "EMV_CRC_INVALID" for s in a.signals)


def test_bharat_qr_tampered_crc():
    upi_tmpl = "0010A0000005240110shop@icici"
    qr = _emv([("00", "01"), ("26", upi_tmpl), ("59", "RAMESH STORE")])
    tampered = qr.replace("shop@icici", "scam@icici")
    a = Analysis(kind="bharat_qr")
    analyze_emv(tampered, "check", a)
    assert any(s.code == "EMV_CRC_INVALID" for s in a.signals)
