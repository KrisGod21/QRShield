"""UPI deep-link analyzer: upi://pay, upi://mandate and anything else under upi://.

Spec: NPCI UPI Linking Specification 1.6 (docs/research/02_upi_spec.md).
Key facts used here:
  * pa (payee VPA) and pn (payee name) are mandatory.
  * If 'mam' is absent the amount is NOT editable (locked).
  * cu must be INR.
  * A QR is always a PAY flow; collect requests cannot travel in a QR.
"""

from __future__ import annotations

import base64
import binascii
import re
from decimal import Decimal, InvalidOperation
from urllib.parse import unquote, unquote_plus

from rapidfuzz.distance import DamerauLevenshtein

from ..data.domains import BRAND_KEYWORDS
from ..data.keywords import (AUTHORITY_NAMES, BUSINESS_WORDS, RISKY_MCC, STRONG_CATEGORIES,
                             find_keyword_categories)
from ..data.upi_handles import CONSUMER_HANDLES, KNOWN_HANDLES, OFFICIAL_VPAS, handle_tier
from ..homoglyph import skeleton
from ..models import Analysis
from ..util import MOBILE_RE, PHONE_IN_TEXT_RE, URL_IN_TEXT_RE, format_inr, truncate
from ..technical import add as evidence, text

LOCAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
HANDLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
AMOUNT_RE = re.compile(r"^\d+(\.\d{1,2})?$")

# Consumer-app handles that legitimately belong to a brand, so "Amazon" on
# @apl is not impersonation.
BRAND_OWN_HANDLES = {
    "amazon": {"apl", "yapl", "rapl", "amazonpay"},
    "paytm": {"paytm", "ptyes", "pthdfc", "ptsbi", "ptaxis"},
    "phonepe": {"ybl", "ibl", "axl", "phonepe"},
    "google pay": {"okaxis", "okhdfcbank", "okicici", "oksbi"},
    "gpay": {"okaxis", "okhdfcbank", "okicici", "oksbi"},
    "flipkart": {"fkaxis"},
    "jio": {"jio"},
    "airtel": {"airtel", "mairtel"},
}

RECUR_TEXT = {"ONETIME": "one time", "DAILY": "daily", "WEEKLY": "weekly", "FORTNIGHTLY": "fortnightly",
              "MONTHLY": "monthly", "BIMONTHLY": "every 2 months", "QUARTERLY": "quarterly",
              "HALFYEARLY": "half-yearly", "YEARLY": "yearly", "ASPRESENTED": "whenever they ask"}


def parse_query(query: str) -> tuple[dict[str, str], list[str]]:
    """Parse a UPI query string. Keys are lower-cased; returns (params, duplicate_keys).

    The spec says a bare '%' should be tolerated as a space, so decoding never fails.
    """
    params: dict[str, str] = {}
    dups: list[str] = []
    for part in query.split("&"):
        if not part:
            continue
        key, _, value = part.partition("=")
        k = unquote(key).strip().lower()
        if not k:
            continue
        # pn / tn are free text where '+' usually means space.
        v = unquote_plus(value) if k in ("pn", "tn", "mn") else unquote(value)
        v = v.strip()
        if k in params:
            if params[k] != v:
                dups.append(k)
            continue
        params[k] = v
    return params, dups


def split_upi(payload: str) -> tuple[str, dict[str, str], list[str]]:
    """Return (action, params, duplicate_keys) for a upi:// URI."""
    rest = payload.strip()[len("upi:"):]
    rest = rest.lstrip("/")
    action, _, query = rest.partition("?")
    return action.strip("/").lower(), *parse_query(query)


def _closest_handle(handle: str) -> str | None:
    """Find a known handle that this unknown handle imitates."""
    h = handle.lower()
    # Known handle plus extra characters: okaxisbank, paytm1, ybl-pay ...
    prefix = [k for k in KNOWN_HANDLES if len(k) >= 3 and h.startswith(k) and h != k]
    if prefix:
        return max(prefix, key=len)
    # Look-alike letters (ybI -> ybl).
    sk = skeleton(handle)
    for k in KNOWN_HANDLES:
        if skeleton(k) == sk:
            return k
    if len(h) < 3:
        return None
    # Edit distance 1 for short handles; 2 only for long ones sharing the first letter.
    limit = 1 if len(h) <= 6 else 2
    best, best_d = None, limit + 1
    for k in KNOWN_HANDLES:
        if abs(len(k) - len(h)) > limit:
            continue
        d = DamerauLevenshtein.distance(h, k, score_cutoff=limit)
        if d == 2 and k[0] != h[0]:
            continue
        if d <= limit and d < best_d:
            best, best_d = k, d
    return best


def _word_in(text: str, word: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", text) is not None


def vpa_problems(vpa: str) -> bool:
    """True if the VPA is malformed."""
    if not vpa or any(c.isspace() for c in vpa) or not vpa.isascii():
        return True
    if vpa.count("@") != 1:
        return True
    local, handle = vpa.split("@")
    if not local or not handle or ".." in local:
        return True
    return not (LOCAL_RE.match(local) and HANDLE_RE.match(handle))


def analyze_upi_params(action: str, params: dict[str, str], dups: list[str], intent: str,
                       a: Analysis, source_label: str = "upi") -> list[str]:
    """Add UPI signals to `a`. Returns nested URLs (from the 'url' param) to analyse."""
    nested: list[str] = []
    vpa = params.get("pa", "")
    pn = params.get("pn", "")
    tn = params.get("tn", "")
    mc = params.get("mc", "")
    am_raw = params.get("am", "")
    mam = params.get("mam", "")
    cu = params.get("cu", "")

    local, _, handle = vpa.partition("@")
    handle_l = handle.lower()

    amount: Decimal | None = None
    if am_raw and am_raw.lower() != "null":
        if AMOUNT_RE.match(am_raw):
            amount = Decimal(am_raw)
            if amount <= 0:
                a.add("UPI_BAD_AMOUNT", 30, raw=am_raw)
                amount = None
        else:
            a.add("UPI_BAD_AMOUNT", 30, raw=am_raw)
    locked = amount is not None and (not mam or mam.lower() == "null")
    p2p_like = not mc or mc == "0000"

    tier = handle_tier(handle) if handle else None
    a.summary.update({
        "action": action, "vpa": vpa, "pn": pn, "note": tn, "handle": handle_l,
        "handle_tier": tier, "amount": str(amount) if amount is not None else None,
        "amount_fmt": format_inr(amount) if amount is not None else None,
        "amount_locked": locked, "mc": mc or None, "tr": params.get("tr") or None,
        "currency": cu or "INR", "signed": bool(params.get("sign")), "merchant": not p2p_like,
        "source": source_label,
    })

    # --- what this QR does
    if action == "pay":
        a.add("UPI_PAY_INFO", 0)
        if amount is not None:
            a.headline_code, a.headline_params = "HEAD_UPI_PAY_AMOUNT", {
                "amount": format_inr(amount), "pn": pn or "?", "vpa": vpa or "?"}
        else:
            a.headline_code, a.headline_params = "HEAD_UPI_PAY", {"pn": pn or "?", "vpa": vpa or "?"}
    elif action == "mandate":
        recur = params.get("recur", "").upper()
        until = params.get("validityend", "")
        if re.fullmatch(r"\d{8}", until):
            until = f"{until[:2]}/{until[2:4]}/{until[4:]}"
        amt = format_inr(amount) if amount is not None else "?"
        a.summary["mandate"] = {"recur": recur or None, "until": until or None,
                                "revocable": params.get("rev", "Y").upper() != "N",
                                "amount_rule": params.get("amrule", "").upper() or None}
        a.add("UPI_PAY_INFO", 0)
        a.add("UPI_MANDATE", 25, force="CAUTION", amount=amt, recur=RECUR_TEXT.get(recur, recur.lower() or "repeating"),
              until=until or "?")
        if params.get("rev", "").upper() == "N":
            a.add("UPI_MANDATE_IRREVOCABLE", 30)
        a.headline_code, a.headline_params = "HEAD_UPI_MANDATE", {"amount": amt, "pn": pn or "?"}
    else:
        a.add("UPI_COLLECT_SCHEME", 60, action=action or "?")
        a.headline_code = "HEAD_UPI_OTHER"

    if intent == "receive" and action in ("pay", "mandate", "collect"):
        a.add("UPI_RECEIVE_INTENT", 100, force="DANGER")

    # --- structure
    if not vpa:
        a.add("UPI_MISSING_PA", 70, force="DANGER")
    elif vpa_problems(vpa):
        a.add("UPI_MALFORMED_VPA", 50, vpa=truncate(vpa, 40))
    for k in dups[:1]:
        a.add("UPI_DUPLICATE_PARAM", 50, param=k)
    if cu and cu.upper() != "INR":
        a.add("UPI_BAD_CURRENCY", 40, currency=cu)
    if not pn:
        a.add("UPI_MISSING_NAME", 12, force="CAUTION")
    if any(ch in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" for ch in pn + tn):
        a.add("UPI_DISPLAY_CONTROL", 35, force="CAUTION")
    if mc and not re.fullmatch(r"\d{4}", mc):
        a.add("UPI_BAD_MCC", 25, force="CAUTION", mcc=mc)
    if mam and mam.lower() != "null" and (not AMOUNT_RE.fullmatch(mam) or Decimal(mam) <= 0
            or (amount is not None and Decimal(mam) > amount)):
        a.add("UPI_BAD_MIN_AMOUNT", 25, force="CAUTION")
    sign = params.get("sign")
    if sign:
        try:
            base64.b64decode(sign + "=" * (-len(sign) % 4), validate=True)
            a.add("UPI_SIGNED", 0)
        except (binascii.Error, ValueError):
            a.add("UPI_SIGN_MALFORMED", 20)

    # --- handle
    if handle and HANDLE_RE.match(handle):
        if tier == "sebi_valid":
            a.add("UPI_HANDLE_VERIFIED", -15, handle=handle_l)
        elif tier is None:
            similar = _closest_handle(handle)
            if similar:
                a.add("UPI_HANDLE_TYPO", 45, handle=handle, similar=similar)
            else:
                a.add("UPI_HANDLE_UNKNOWN", 12, handle=handle_l)
    elif handle and not handle.isascii():
        similar = _closest_handle(handle)
        if similar:
            a.add("UPI_HANDLE_TYPO", 45, handle=handle, similar=similar)

    consumerish = handle_l in CONSUMER_HANDLES or tier is None

    # --- lookalike of an official collection VPA (PM CARES etc.)
    vpa_l = vpa.lower()
    if vpa_l and vpa_l not in OFFICIAL_VPAS:
        for official, name in OFFICIAL_VPAS.items():
            if DamerauLevenshtein.distance(vpa_l, official) <= 2:
                a.add("UPI_OFFICIAL_LOOKALIKE", 60, vpa=vpa, official=official, name=name)
                break

    # --- social-engineering words (EN/HI/MR) in name, note and VPA
    local_words = re.sub(r"[._\-\d]+", " ", local)
    cats = find_keyword_categories(pn, tn, local_words)
    ranked = sorted(cats.items(), key=lambda kv: kv[0] not in STRONG_CATEGORIES)
    for cat, word in ranked[:2]:
        a.add("UPI_SCAM_KEYWORD", 35 if cat in STRONG_CATEGORIES else 20, variant=cat,
              word=word, category=cat)

    # --- impersonation: official-sounding name on an ordinary app handle
    pn_l = pn.lower()
    authority = next((w for w in AUTHORITY_NAMES if _word_in(pn_l, w)), None)
    if authority and consumerish and handle_l not in BRAND_OWN_HANDLES.get(authority, set()):
        a.add("UPI_IMPERSONATION", 40, pn=truncate(pn, 40), authority=authority, handle=handle_l or "?")

    # --- brand word inside the VPA on a consumer handle
    if consumerish and local:
        tokens = [t for t in re.split(r"[^a-z]+", local.lower()) if t]
        brand = next((k for t in tokens for k in BRAND_KEYWORDS
                      if (t == k) or (len(k) >= 4 and k in t)), None)
        if brand and handle_l not in BRAND_OWN_HANDLES.get(BRAND_KEYWORDS[brand].lower(), set()):
            a.add("UPI_BRAND_IN_VPA", 30, brand=BRAND_KEYWORDS[brand], vpa=vpa)

    # --- amount patterns
    if amount is not None:
        if locked and p2p_like and action == "pay":
            a.add("UPI_PREFILLED_P2P", 20, amount=format_inr(amount))
        if (p2p_like and amount > 100000) or amount > 500000:
            a.add("UPI_HIGH_AMOUNT", 20, amount=format_inr(amount))

    if pn and MOBILE_RE.match(local or "") and any(_word_in(pn_l, w) for w in BUSINESS_WORDS):
        a.add("UPI_BUSINESS_NAME_PERSONAL_VPA", 15, pn=truncate(pn, 40), vpa=vpa)

    if mc in RISKY_MCC:
        a.add("UPI_RISKY_MCC", 15, mcc=mc, category=RISKY_MCC[mc])

    if tn and (URL_IN_TEXT_RE.search(tn) or PHONE_IN_TEXT_RE.search(tn)):
        a.add("UPI_NOTE_CONTACT", 15)

    ref_url = params.get("url")
    if ref_url:
        a.add("UPI_REF_URL", 15, url=truncate(ref_url, 50))
        nested.append(ref_url)

    scope = vpa or source_label
    evidence(a, "vpa", "fail" if vpa_problems(vpa) else "pass", vpa or "Missing pa", text(
        "Checks local-part, ASCII characters, separators and the single @ boundary. Syntax does not verify that this account exists.",
        "प्रारूप, ASCII अक्षर और एक @ की जांच। यह खाता मौजूद होने की पुष्टि नहीं है।",
        "स्वरूप, ASCII अक्षरे आणि एक @ तपासले. खाते अस्तित्वात असल्याची ही खात्री नाही."), scope)
    evidence(a, "handle", "pass" if tier else "warn", f"@{handle_l} | {tier or 'Unknown to bundled list'}", text(
        "Matched against the bundled PSP handle list and checked for lookalikes. Recognising a handle does not authenticate its account holder.",
        "PSP सूची और मिलते-जुलते हैंडल की जांच। हैंडल पहचानने से खाताधारक की पुष्टि नहीं होती।",
        "PSP सूची आणि समान हँडल तपासले. हँडल ओळखल्याने खातेदाराची खात्री होत नाही."), scope)
    name_flags = {"UPI_IMPERSONATION", "UPI_BUSINESS_NAME_PERSONAL_VPA", "UPI_BRAND_IN_VPA", "UPI_OFFICIAL_LOOKALIKE", "UPI_DISPLAY_CONTROL"}
    evidence(a, "name", "warn" if not pn or any(s.code in name_flags for s in a.signals) else "info", pn or "Missing pn", text(
        "The name is self-declared inside the QR. Name / VPA inconsistencies and authority impersonation rules were inspected.",
        "नाम QR में खुद लिखा गया है। नाम, VPA और नकली अधिकार पहचान की जांच हुई।",
        "नाव QR मध्ये स्वतः घोषित आहे. नाव, VPA आणि बनावट अधिकृत ओळख तपासली."), scope)
    evidence(a, "mcc", "warn" if a.has("UPI_BAD_MCC") or a.has("UPI_RISKY_MCC") else "info", mc or "Not supplied (personal-style QR)", text(
        "A four-digit MCC describes the declared merchant category. It is not a merchant registration or KYC certificate.",
        "चार अंकों का MCC घोषित व्यापारी श्रेणी है, पंजीकरण या KYC प्रमाणपत्र नहीं।",
        "चार अंकी MCC ही घोषित व्यापारी श्रेणी आहे, नोंदणी किंवा KYC प्रमाणपत्र नाही."), scope)
    constraint_flags = {"UPI_BAD_AMOUNT", "UPI_BAD_MIN_AMOUNT", "UPI_BAD_CURRENCY", "UPI_RECEIVE_INTENT", "UPI_MANDATE_IRREVOCABLE"}
    evidence(a, "payment", "warn" if any(s.code in constraint_flags for s in a.signals) else "info",
             f"{action} | {cu or 'INR'} | amount={am_raw or 'payer enters'} | mam={mam or 'absent'}", text(
        "Checks debit intent, currency, amount precision, minimum amount and recurring-payment constraints.",
        "पैसे कटने की मंशा, मुद्रा, रकम, न्यूनतम रकम और बार-बार भुगतान की जांच।",
        "डेबिट हेतू, चलन, रक्कम, किमान रक्कम आणि आवर्ती पेमेंट अटी तपासल्या."), scope)
    evidence(a, "params", "fail" if dups else "pass", ", ".join(dups) or "No conflicting duplicate fields", text(
        "Conflicting repeated parameters can hide a different payee or amount across payment applications.",
        "दोहराए गए अलग मान अलग ऐप में प्राप्तकर्ता या रकम बदल सकते हैं।",
        "पुनरावृत्तीतील वेगवेगळी मूल्ये ॲपनुसार प्राप्तकर्ता किंवा रक्कम बदलू शकतात."), scope)
    evidence(a, "signature", "warn" if a.has("UPI_SIGN_MALFORMED") else "unavailable",
             "Malformed Base64 signature" if a.has("UPI_SIGN_MALFORMED") else "Signature present; cryptographic verification unavailable" if sign else "Unsigned QR", text(
        "Only signature encoding is inspected. NPCI / issuer public keys and cryptographic signature verification are not integrated. No trust points are awarded.",
        "केवल encoding की जांच। NPCI / issuer कुंजी और क्रिप्टोग्राफिक पुष्टि उपलब्ध नहीं। भरोसे के अंक नहीं दिए जाते।",
        "फक्त encoding तपासले. NPCI / issuer की आणि क्रिप्टोग्राफिक पडताळणी उपलब्ध नाही. विश्वासाचे गुण दिले जात नाहीत."), scope)
    evidence(a, "ownership", "unavailable", "Account existence / bank-verified name / KYC not checked", text(
        "Confirm the beneficiary in your payment app and with the merchant. This prototype has no bank account-resolution API.",
        "पेमेंट ऐप और व्यापारी से प्राप्तकर्ता की पुष्टि करें। बैंक खाता पुष्टि API उपलब्ध नहीं है।",
        "पेमेंट ॲप आणि व्यापाऱ्याकडून प्राप्तकर्त्याची खात्री करा. बँक खाते पडताळणी API उपलब्ध नाही."), scope)

    return nested


def analyze_upi(payload: str, intent: str, a: Analysis) -> list[str]:
    action, params, dups = split_upi(payload)
    a.kind = "upi_mandate" if action == "mandate" else ("upi_pay" if action == "pay" else "upi_other")
    return analyze_upi_params(action, params, dups, intent, a)
