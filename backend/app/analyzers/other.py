"""Non-UPI, non-URL payloads: WiFi, tel, sms, email, geo, vCard/MECARD, calendar,
app links (market:// intent://), crypto, FIDO passkey, otpauth, plain text.

Formats: ZXing "Barcode Contents" wiki; risks: docs/research/04_payloads_competitors.md.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urlsplit

from ..data.domains import REMOTE_ACCESS_PACKAGES
from ..data.keywords import find_keyword_categories
from ..models import Analysis
from ..util import MOBILE_RE, URL_IN_TEXT_RE, VPA_IN_TEXT_RE, truncate

# ------------------------------------------------------------------ WiFi

def parse_wifi(payload: str) -> dict[str, str]:
    body = payload[5:]
    fields: dict[str, str] = {}
    key, buf, in_key, esc = "", [], True, False
    for ch in body:
        if esc:
            buf.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif in_key and ch == ":":
            key, buf, in_key = "".join(buf).strip().upper(), [], False
        elif ch == ";":
            if key:
                fields.setdefault(key, "".join(buf))
            key, buf, in_key = "", [], True
        else:
            buf.append(ch)
    if key and not in_key:
        fields.setdefault(key, "".join(buf))
    return fields


_PUBLIC_SSID = (
    (re.compile(r"rail|irctc|station"), "RailWire"),
    (re.compile(r"airport|terminal|lounge"), "the airport's official Wi-Fi"),
    (re.compile(r"metro"), "the metro's official Wi-Fi"),
    (re.compile(r"\b(jio|airtel|bsnl|vi)\b|jionet|airtelwifi"), "your telecom operator's Wi-Fi"),
    (re.compile(r"bank|sbi|hdfc|icici|govt|gov|municipal|smartcity"), "an official public network"),
    (re.compile(r"free.?wi.?fi|public.?wi.?fi|free.?internet"), "a public hotspot"),
)


def analyze_wifi(payload: str, a: Analysis) -> None:
    a.kind = "wifi"
    f = parse_wifi(payload)
    ssid = f.get("S", "")
    t = f.get("T", "").upper()
    hidden = f.get("H", "").lower() == "true"
    security = {"": "open", "NOPASS": "open", "WEP": "WEP", "WPA": "WPA/WPA2", "WPA2": "WPA2",
                "SAE": "WPA3", "WPA3": "WPA3", "WPA2-EAP": "WPA2-Enterprise"}.get(t, t or "open")
    a.summary.update({"ssid": ssid, "security": security, "hidden": hidden,
                      "password": f.get("P", "") or None})
    a.headline_code, a.headline_params = "HEAD_WIFI", {"ssid": ssid or "?"}
    a.add("WIFI_INFO", 0, ssid=ssid, security=security)
    if security == "open":
        a.add("WIFI_OPEN", 35, ssid=ssid)
    elif security == "WEP":
        a.add("WIFI_WEP", 30)
    norm = ssid.lower()
    if ssid != "RailWire":
        for pattern, real in _PUBLIC_SSID:
            if pattern.search(norm):
                a.add("WIFI_LOOKALIKE", 40, ssid=ssid, real=real)
                break
    if hidden:
        a.add("WIFI_HIDDEN", 15)


# ------------------------------------------------------------------ tel / sms

COUNTRY_CODES = {"1": "USA/Canada", "7": "Russia", "44": "UK", "62": "Indonesia", "63": "Philippines",
                 "92": "Pakistan", "93": "Afghanistan", "95": "Myanmar", "855": "Cambodia",
                 "856": "Laos", "880": "Bangladesh", "971": "UAE", "977": "Nepal", "234": "Nigeria",
                 "256": "Uganda", "257": "Burundi", "265": "Malawi", "252": "Somalia", "84": "Vietnam",
                 "86": "China", "60": "Malaysia", "65": "Singapore", "94": "Sri Lanka", "966": "Saudi Arabia"}


def _country(number: str) -> str:
    digits = number.lstrip("+")
    for n in (3, 2, 1):
        if digits[:n] in COUNTRY_CODES:
            return f"+{digits[:n]} {COUNTRY_CODES[digits[:n]]}"
    return "+" + digits[:3]


def _check_number(number: str, a: Analysis, sms: bool = False) -> None:
    clean = re.sub(r"[\s\-().]", "", number)
    if "*" in clean or "#" in clean:
        a.add("TEL_USSD", 90, force="DANGER", number=clean)
        return
    if clean.startswith("+") and not clean.startswith("+91"):
        a.add("SMS_FOREIGN" if sms else "TEL_FOREIGN", 25, number=clean, country=_country(clean))
        return
    if clean.startswith("00") and not clean.startswith("0091"):
        a.add("SMS_FOREIGN" if sms else "TEL_FOREIGN", 25, number=clean, country=_country(clean[2:]))
        return
    digits = clean.lstrip("+")
    if digits == "1930":
        a.add("TEL_HELPLINE_1930", -10)
    elif re.fullmatch(r"160[01]\d{6}", digits):
        a.add("TEL_1600_INFO", 0)
    elif re.fullmatch(r"\d{3,6}", digits) and digits not in ("100", "101", "102", "108", "112", "1909"):
        a.add("SMS_SHORTCODE" if sms else "TEL_SHORTCODE", 25 if sms else 15, number=digits)


def analyze_tel(payload: str, a: Analysis) -> None:
    a.kind = "tel"
    number = unquote(payload.split(":", 1)[1]).strip()
    a.summary["number"] = number
    a.headline_code, a.headline_params = "HEAD_TEL", {"number": number}
    _check_number(number, a)


def analyze_sms(payload: str, a: Analysis) -> list[str]:
    a.kind = "sms"
    scheme, _, rest = payload.partition(":")
    body = ""
    if scheme.lower() in ("smsto", "mmsto"):
        number, _, body = rest.partition(":")
    else:
        number, _, query = rest.partition("?")
        if query:
            body = parse_qs(query).get("body", [""])[0]
        elif ":" in number:
            number, _, body = number.partition(":")
    number, body = unquote(number).strip(), unquote(body).strip()
    a.summary.update({"number": number, "body": body})
    a.headline_code, a.headline_params = "HEAD_SMS", {"number": number}
    a.add("SMS_INFO", 0, number=number, body=truncate(body, 80))
    _check_number(number, a, sms=True)
    _text_keywords(body, a, 30)
    return URL_IN_TEXT_RE.findall(body)


# ------------------------------------------------------------------ email / geo / event

def analyze_email(payload: str, a: Analysis) -> list[str]:
    a.kind = "email"
    if payload.upper().startswith("MATMSG:"):
        f = dict(re.findall(r"(TO|SUB|BODY):((?:\\;|[^;])*)", payload[7:], re.I))
        to, subject, body = f.get("TO", ""), f.get("SUB", ""), f.get("BODY", "")
    else:
        p = urlsplit(payload)
        to = unquote(p.path)
        qs = parse_qs(p.query)
        subject, body = qs.get("subject", [""])[0], qs.get("body", [""])[0]
    a.summary.update({"to": to, "subject": subject, "body": body})
    a.headline_code, a.headline_params = "HEAD_EMAIL", {"to": to or "?"}
    _text_keywords(f"{subject} {body}", a, 25)
    return URL_IN_TEXT_RE.findall(f"{subject} {body}")


def analyze_geo(payload: str, a: Analysis) -> None:
    a.kind = "geo"
    coords = payload[4:].split("?")[0]
    a.summary["coords"] = coords
    a.headline_code = "HEAD_GEO"


def analyze_event(payload: str, a: Analysis) -> list[str]:
    a.kind = "event"
    title = (re.search(r"^SUMMARY[^:]*:(.*)$", payload, re.M | re.I) or [None, ""])[1].strip()
    a.summary["title"] = title
    a.headline_code, a.headline_params = "HEAD_EVENT", {"title": truncate(title, 50) or "?"}
    _text_keywords(payload, a, 25)
    return URL_IN_TEXT_RE.findall(payload)


# ------------------------------------------------------------------ contacts

_SUPPORT_NAME = re.compile(r"(?i)bank|care|support|help|customer|sbi|hdfc|icici|axis|paytm|phonepe|"
                           r"gpay|amazon|flipkart|kyc|refund|rbi|npci|police|cyber|official")


def analyze_vcard(payload: str, a: Analysis) -> list[str]:
    a.kind = "vcard"
    if payload.upper().startswith("MECARD:"):
        f = dict(re.findall(r"(N|TEL|EMAIL|URL|ORG):((?:\\;|[^;])*)", payload[7:], re.I))
        name = f.get("N", "").replace(",", " ").strip()
        phones = [f["TEL"]] if f.get("TEL") else []
        org = f.get("ORG", "")
    else:
        name = (re.search(r"^FN[^:]*:(.*)$", payload, re.M | re.I) or
                re.search(r"^N[^:]*:(.*)$", payload, re.M | re.I) or [None, ""])[1].replace(";", " ").strip()
        phones = [m.strip() for m in re.findall(r"^TEL[^:]*:(.*)$", payload, re.M | re.I)]
        org = (re.search(r"^ORG[^:]*:(.*)$", payload, re.M | re.I) or [None, ""])[1]
    a.summary.update({"name": name, "phones": phones, "org": org})
    a.headline_code, a.headline_params = "HEAD_VCARD", {"name": truncate(name or org, 40) or "?"}
    label = f"{name} {org}"
    for ph in phones:
        digits = re.sub(r"[\s\-()]", "", ph)
        if _SUPPORT_NAME.search(label) and MOBILE_RE.match(digits):
            a.add("VCARD_BANK_PERSONAL", 35, name=truncate(name or org, 40), number=ph)
            break
        if "*" in digits or "#" in digits:
            a.add("TEL_USSD", 90, force="DANGER", number=digits)
    return URL_IN_TEXT_RE.findall(payload)


# ------------------------------------------------------------------ app links

def analyze_app(payload: str, a: Analysis) -> list[str]:
    a.kind = "app"
    nested: list[str] = []
    low = payload.lower()
    pkg = ""
    if low.startswith("market://"):
        pkg = parse_qs(urlsplit(payload).query).get("id", [""])[0]
    elif low.startswith("intent:"):
        m = re.search(r"[;#]package=([^;]+)", payload)
        pkg = m.group(1) if m else ""
        fb = re.search(r"S\.browser_fallback_url=([^;]+)", payload)
        if fb:
            nested.append(unquote(fb.group(1)))
        a.add("INTENT_SCHEME", 25, package=pkg or "?")
    a.summary["package"] = pkg
    a.headline_code, a.headline_params = "HEAD_APP", {"package": pkg or "?"}
    if pkg.lower().startswith(REMOTE_ACCESS_PACKAGES) or any(
            w in pkg.lower() for w in ("anydesk", "teamviewer", "rustdesk", "quicksupport")):
        a.add("APP_REMOTE_ACCESS", 60, package=pkg)
    elif low.startswith("market://"):
        a.add("URL_APP_INSTALL", 15, package=pkg or "?")
    return nested


# ------------------------------------------------------------------ crypto / fido / otp

def analyze_crypto(payload: str, a: Analysis) -> None:
    a.kind = "crypto"
    coin, _, rest = payload.partition(":")
    address = rest.split("?")[0]
    amount = parse_qs(urlsplit(payload).query).get("amount", [""])[0] if "?" in rest else ""
    a.summary.update({"coin": coin.lower(), "address": address, "amount": amount or None})
    a.headline_code, a.headline_params = "HEAD_CRYPTO", {"coin": coin.lower()}
    short = address if len(address) <= 16 else f"{address[:8]}…{address[-6:]}"
    a.add("CRYPTO_PAYMENT", 30, coin=coin.lower(), address=short)


def analyze_fido(payload: str, a: Analysis) -> None:
    a.kind = "fido"
    a.headline_code = "HEAD_FIDO"
    a.add("FIDO_LOGIN", 30)


def analyze_otp(payload: str, a: Analysis) -> None:
    a.kind = "otp"
    p = urlsplit(payload)
    label = unquote(p.path.lstrip("/"))
    issuer = parse_qs(p.query).get("issuer", [label.split(":")[0]])[0]
    a.summary.update({"issuer": issuer, "account": label})
    a.headline_code, a.headline_params = "HEAD_OTP", {"issuer": issuer or "?"}
    a.add("OTP_SECRET", 20, issuer=issuer or "?")


# ------------------------------------------------------------------ text

def _text_keywords(text: str, a: Analysis, weight: int) -> None:
    cats = find_keyword_categories(text)
    if cats:
        word = next(iter(cats.values()))
        a.add("TEXT_SCAM_KEYWORD", weight, word=word)


def embedded_items(text: str) -> tuple[list[str], list[str]]:
    urls = URL_IN_TEXT_RE.findall(text)
    vpas = [v for v in VPA_IN_TEXT_RE.findall(text)
            if not re.search(re.escape(v) + r"\.[A-Za-z]", text)]  # skip e-mail addresses
    return urls, vpas


def analyze_text(payload: str, a: Analysis) -> tuple[list[str], list[str]]:
    a.kind = "text"
    a.summary["text"] = truncate(payload, 300)
    a.headline_code = "HEAD_TEXT"
    _text_keywords(payload, a, 25)
    urls, vpas = embedded_items(payload)
    for item in (urls + vpas)[:3]:
        a.add("TEXT_CONTAINS", 0, item=truncate(item, 50))
    return urls[:3], vpas[:3]
