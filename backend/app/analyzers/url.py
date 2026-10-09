"""URL analyzer: lexical heuristics first, then time-boxed online checks.

Lexical (always, offline): dangerous schemes, userinfo trick, IP hosts, ports,
official-domain / .bank.in / .gov.in trust, homoglyph (TR39 skeleton) and
typosquat (Damerau-Levenshtein) against Indian brands, brand misuse, gov
impersonation, risky TLDs, free hosting, shorteners, file downloads, bait words.

Online (parallel, each with its own timeout inside the request budget):
SSRF-safe redirect expansion, RDAP domain age, local threat feeds, Google Safe
Browsing and URLhaus (only if keys are configured).
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import parse_qs, parse_qsl, unquote, urlsplit

from rapidfuzz.distance import DamerauLevenshtein

from .. import intel, rdap, ssrf
from ..data.domains import (APK_EXTENSIONS, BRAND_KEYWORDS, BRAND_LABELS, EXE_EXTENSIONS,
                            FREE_HOSTING_SUFFIXES, GOV_WORDS, OFFICIAL_DOMAINS, REMOTE_ACCESS_PACKAGES,
                            REMOTE_ACCESS_WORDS, SUSPICIOUS_TLDS_T1, SUSPICIOUS_TLDS_T2,
                            SUSPICIOUS_URL_WORDS, URL_SHORTENERS)
from ..db import DB
from ..domainutil import HostInfo, host_info, icann_registrable, parse_ip, to_unicode
from ..homoglyph import skeleton
from ..models import Analysis, Check
from ..util import truncate
from ..technical import add as evidence, text

DESTINATION_KEYS = {"url", "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
                    "return_url", "next", "continue", "target", "dest", "destination", "callback"}


def query_details(query: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Decode at most twice; never fetch embedded destinations automatically."""
    values: dict[str, set[str]] = {}
    destinations = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        key = key.lower()
        values.setdefault(key, set()).add(value)
        if key not in DESTINATION_KEYS:
            continue
        for _ in range(2):
            decoded = unquote(value)
            if decoded == value:
                break
            value = decoded
        if value.startswith("//"):
            value = "https:" + value
        if re.match(r"^(https?://|javascript:|data:|file:)", value, re.I):
            destinations.append((key, value))
    return [key for key, vals in values.items() if len(vals) > 1], destinations[:2]

# Big shared infrastructure whose names contain brand words (amazonaws, googleapis ...).
BRAND_SAFE_INFRA = {"amazonaws.com", "cloudfront.net", "googleapis.com", "googleusercontent.com",
                    "gstatic.com", "googlevideo.com", "akamaized.net", "azureedge.net"}

CHAT_HOSTS = {"wa.me": "WhatsApp", "api.whatsapp.com": "WhatsApp", "chat.whatsapp.com": "WhatsApp",
              "t.me": "Telegram", "telegram.me": "Telegram"}


@dataclass
class Ctx:
    db: DB
    demo: bool
    online: bool
    deadline: float
    intent: str = "check"

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())


@lru_cache(maxsize=1)
def _brand_skeletons() -> dict[str, tuple[str, str]]:
    """skeleton(label) -> (brand, an official domain using that label)."""
    out: dict[str, tuple[str, str]] = {}
    for domain, brand in OFFICIAL_DOMAINS.items():
        label = domain.split(".")[0]
        if len(label) >= 4:
            out.setdefault(skeleton(label), (brand, domain))
    for kw, brand in BRAND_KEYWORDS.items():
        if len(kw) >= 5:
            official = next((d for d, b in OFFICIAL_DOMAINS.items() if b == brand), kw)
            out.setdefault(skeleton(kw), (brand, official))
    return out


def _official_for(brand: str) -> str:
    return next((d for d, b in OFFICIAL_DOMAINS.items() if b == brand), brand)


def normalize_url(raw: str) -> str:
    s = "".join(ch for ch in raw.strip() if ch >= " " and ch != "\x7f")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", s) or re.match(r"^[^/:]+\.[^/:]+:\d", s):
        s = "http://" + s
    scheme, sep, rest = s.partition("://")
    if sep:
        auth_end = len(rest)
        for ch in "/?#":
            i = rest.find(ch)
            if i >= 0:
                auth_end = min(auth_end, i)
        rest = rest[:auth_end].replace("\\", "/") + rest[auth_end:]
        s = f"{scheme.lower()}://{rest}"
    return s


def _tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


def _find_brand(tokens: list[str]) -> str | None:
    for t in tokens:
        for kw, brand in BRAND_KEYWORDS.items():
            if t == kw or (len(kw) >= 4 and kw in t):
                return brand
    return None


@dataclass
class Lexical:
    url: str
    info: HostInfo | None
    official: bool
    shortener: bool
    blocked: bool  # a hard verdict already (e.g. APK) - skip nothing, just informational


def lexical(url: str, a: Analysis, ctx: Ctx, stage: str = "") -> Lexical:
    """Add lexical URL signals. `stage` is '' for the scanned URL, 'final' after redirects."""
    try:
        p = urlsplit(url)
        host = p.hostname or ""
        port = p.port
    except ValueError:
        a.add("URL_INVALID", 45, force="CAUTION")
        a.summary["invalid_url"] = True
        return Lexical(url, None, False, False, False)
    if not host or p.scheme not in ("http", "https") or any(ch.isspace() for ch in host):
        a.add("URL_INVALID", 45, force="CAUTION")
        a.summary["invalid_url"] = True
        return Lexical(url, None, False, False, False)

    info = host_info(host)
    path = unquote(p.path or "")
    query = unquote(p.query or "")
    path_l = (path + "?" + query).lower()
    scope = f"{stage or 'scanned'}: {info.unicode_host}"
    conflicts, destinations = query_details(p.query)
    if conflicts:
        a.add("URL_QUERY_CONFLICT", 25, force="CAUTION", keys=", ".join(conflicts[:4]))
    evidence(a, "domain", "info", f"{info.host} | {info.registrable}", text(
        "ASCII host and registrable domain from the public suffix list. Subdomains do not prove brand ownership.",
        "ASCII होस्ट और असली पंजीकरण डोमेन। सबडोमेन से ब्रांड स्वामित्व साबित नहीं होता।",
        "ASCII होस्ट आणि नोंदणी डोमेन. सबडोमेन ब्रँड मालकी सिद्ध करत नाही."), scope)
    evidence(a, "query", "warn" if conflicts else "pass", ", ".join(conflicts) or "No conflicting duplicate keys", text(
        "Conflicting duplicate values can be read differently by different applications.",
        "एक ही पैरामीटर के अलग मान अलग ऐप में अलग पढ़े जा सकते हैं।",
        "एकाच पॅरामीटरची वेगवेगळी मूल्ये वेगवेगळ्या ॲप्समध्ये वेगळी वाचली जाऊ शकतात."), scope)
    for key, dest in destinations:
        try:
            target = urlsplit(dest)
            cross = target.scheme not in ("http", "https") or (
                target.hostname and host_info(target.hostname).registrable != info.registrable)
        except ValueError:
            cross = True
        if cross:
            a.add("URL_EMBEDDED_DESTINATION", 15, key=key, destination=truncate(dest, 100))
        evidence(a, "embedded", "warn" if cross else "info", f"{key}: {dest}", text(
            "Destination declared in the query, not an observed redirect. Its address is inspected without requesting it.",
            "URL में दिया गया गंतव्य, वास्तविक रीडायरेक्ट नहीं। इसे खोले बिना पता जांचा गया।",
            "URL मधील गंतव्य, प्रत्यक्ष रीडायरेक्ट नाही. ते न उघडता पत्ता तपासला."), scope)

    if stage == "":
        a.summary.setdefault("url", url)
        a.summary.setdefault("host", info.unicode_host)
        a.summary.setdefault("registrable", info.registrable)
        a.summary.setdefault("https", p.scheme == "https")
    else:
        a.summary["final_url"] = url
        a.summary["final_host"] = info.unicode_host

    # --- disguise tricks
    if "@" in p.netloc:
        shown = p.netloc.rsplit("@", 1)[0]
        a.add("URL_USERINFO", 35, shown=truncate(shown, 40), real=info.unicode_host)
    if port and port not in (80, 443):
        a.add("URL_ODD_PORT", 8, port=port)
    if p.scheme == "http":
        a.add("URL_NO_HTTPS", 8)

    free_host = _is_free_host(info)
    official = False
    if info.is_ip:
        a.add("URL_IP_HOST", 30, host=host)
    else:
        brand = OFFICIAL_DOMAINS.get(info.registrable) or OFFICIAL_DOMAINS.get(info.host)
        icann = icann_registrable(info.host)
        if free_host:
            brand = None  # user-published pages on sites.google.com etc. are never "official"
        if brand and not info.is_private_suffix:
            a.add("URL_OFFICIAL", -30, domain=info.registrable, brand=brand)
            official = True
        elif info.suffix == "bank.in":
            a.add("URL_BANK_IN", -30, domain=info.registrable)
            official = True
        elif info.suffix in ("gov.in", "nic.in") or info.host.endswith((".gov.in", ".nic.in")):
            a.add("URL_GOV_IN", -30, domain=info.registrable)
            official = True
        if official:
            a.summary.setdefault("official_brand", brand)

    shortener = (info.host in URL_SHORTENERS or info.registrable in URL_SHORTENERS
                 or (ctx.demo and info.registrable in _demo_shorteners()))

    if not info.is_ip and not official:
        uni_label = to_unicode(info.label) if info.label.startswith("xn--") else info.label
        if not info.host.isascii() or "xn--" in info.host:
            a.add("URL_PUNYCODE", 15, unicode=info.unicode_host)
        flagged_brand = None
        sk = skeleton(uni_label)
        hit = _brand_skeletons().get(sk)
        if hit and uni_label.lower() not in BRAND_LABELS and uni_label.lower() not in BRAND_KEYWORDS:
            a.add("URL_HOMOGLYPH", 50, domain=info.unicode_host, official=hit[1], brand=hit[0])
            flagged_brand = hit[0]
        else:
            best = None
            for label, brand in BRAND_LABELS.items():
                limit = 1 if len(label) <= 6 else 2
                if abs(len(label) - len(uni_label)) > limit:
                    continue
                if len(label) <= 6 and uni_label[:1].lower() != label[:1]:
                    continue
                d = DamerauLevenshtein.distance(uni_label.lower(), label, score_cutoff=limit)
                if 1 <= d <= limit and (best is None or d < best[0]):
                    best = (d, label, brand)
            if best:
                official_dom = next((dm for dm, b in OFFICIAL_DOMAINS.items()
                                     if b == best[2] and dm.split(".")[0] == best[1]), _official_for(best[2]))
                a.add("URL_TYPOSQUAT", 40, domain=info.unicode_host, official=official_dom, brand=best[2])
                flagged_brand = best[2]

        host_tokens = [] if info.registrable in BRAND_SAFE_INFRA else _tokens(info.subdomain) + _tokens(info.label)
        bait = [w for w in SUSPICIOUS_URL_WORDS if w in path_l or w in info.host]
        brand = _find_brand(host_tokens) or (_find_brand(_tokens(path_l)) if bait else None)
        if brand and brand != flagged_brand:
            a.add("URL_BRAND_MISUSE", 35, brand=brand, domain=info.registrable)

        gov = [w for w in GOV_WORDS if any(t == w or (len(w) >= 4 and w in t) for t in host_tokens)]
        if gov:
            a.add("URL_GOV_IMPERSONATION", 30, domain=info.registrable)

        tld = icann.rsplit(".", 1)[-1] if "." in icann else info.host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS_T1:
            a.add("URL_RISKY_TLD", 20, tld=tld)
        elif tld in SUSPICIOUS_TLDS_T2:
            a.add("URL_RISKY_TLD", 10, tld=tld)

        if free_host:
            a.add("URL_FREE_HOSTING", 12, host=info.unicode_host)

        if bait:
            a.add("URL_SUSPICIOUS_WORDS", min(16, 8 * len(bait)), words=", ".join(bait[:3]))

        if info.subdomain.count(".") >= 3 or len(info.host) > 50:
            a.add("URL_MANY_SUBDOMAINS", 8, host=truncate(info.unicode_host, 50))

    if shortener and stage == "":
        a.add("URL_SHORTENER", 10, host=info.host)

    # --- what the link delivers
    fname = path.rsplit("/", 1)[-1]
    if path.lower().endswith(APK_EXTENSIONS):
        a.add("URL_APK_DOWNLOAD", 70, force="DANGER", file=truncate(fname, 40))
    elif path.lower().endswith(EXE_EXTENSIONS):
        a.add("URL_EXE_DOWNLOAD", 50, file=truncate(fname, 40))
    remote = next((w for w in REMOTE_ACCESS_WORDS if w in info.host or w in path_l), None)
    if remote:
        a.add("URL_REMOTE_ACCESS_APP", 50, app=remote)

    # --- chat and app-store links
    if info.host in CHAT_HOSTS and stage == "":
        qs = parse_qs(p.query)
        target = path.strip("/").split("/")[0] or qs.get("phone", ["?"])[0]
        if CHAT_HOSTS[info.host] == "WhatsApp" and target.isdigit():
            target = "+" + target
        chat_text = qs.get("text", [""])[0]
        a.summary["chat"] = {"app": CHAT_HOSTS[info.host], "target": target, "text": chat_text}
        a.add("URL_OPENS_CHAT", 10, app=CHAT_HOSTS[info.host], target=target)
        a.headline_code, a.headline_params = "HEAD_CHAT", {"app": CHAT_HOSTS[info.host], "target": target}
    if info.host == "play.google.com" and path.startswith("/store/apps"):
        pkg = parse_qs(p.query).get("id", [""])[0]
        if pkg:
            a.summary["package"] = pkg
            if pkg.lower().startswith(REMOTE_ACCESS_PACKAGES):
                a.add("APP_REMOTE_ACCESS", 60, package=pkg)
            else:
                a.add("URL_APP_INSTALL", 15, package=pkg)

    identity_codes = {"URL_HOMOGLYPH", "URL_TYPOSQUAT", "URL_BRAND_MISUSE", "URL_GOV_IMPERSONATION", "URL_USERINFO"}
    identity_flags = [s.code for s in a.signals if s.code in identity_codes]
    evidence(a, "identity", "warn" if identity_flags else "pass", ", ".join(identity_flags) or "No configured impersonation rules matched", text(
        "Unicode confusables, edit distance, brand tokens and userinfo are inspected against the bundled rules. This is not proof of ownership.",
        "Unicode समान अक्षर, टाइपो, ब्रांड और userinfo की जांच। यह स्वामित्व का प्रमाण नहीं है।",
        "Unicode समान अक्षरे, टायपो, ब्रँड आणि userinfo तपासले. हा मालकीचा पुरावा नाही."), scope)

    return Lexical(url, info, official, shortener, False)


def _is_free_host(info: HostInfo) -> bool:
    return (info.is_private_suffix and info.suffix in FREE_HOSTING_SUFFIXES) or \
        any(info.host == fh or info.host.endswith("." + fh) for fh in FREE_HOSTING_SUFFIXES)


def _demo_shorteners() -> set[str]:
    from ..demo_fixtures import DEMO_SHORTENERS
    return DEMO_SHORTENERS


async def _domain_age(domain: str, ctx: Ctx, a: Analysis) -> None:
    t0 = time.monotonic()
    if ctx.demo:
        from ..demo_fixtures import DOMAIN_AGE_DAYS
        if domain in DOMAIN_AGE_DAYS:
            _age_signal(domain, DOMAIN_AGE_DAYS[domain], a)
            _age_evidence(domain, DOMAIN_AGE_DAYS[domain], "demo", a)
            a.checks.append(Check("domain_age", "demo", int((time.monotonic() - t0) * 1000)))
            return
    if not ctx.online:
        a.checks.append(Check("domain_age", "skipped"))
        _age_evidence(domain, None, "unavailable", a)
        return
    if ctx.remaining() < 0.25:
        a.checks.append(Check("domain_age", "skipped", 0, "budget"))
        _age_evidence(domain, None, "unavailable", a)
        return
    status, created = await rdap.lookup_created(domain, ctx.db, timeout=min(1.5, ctx.remaining()))
    ms = int((time.monotonic() - t0) * 1000)
    days = None
    if created:
        days = rdap.age_days(created)
        if days is not None:
            _age_signal(domain, days, a)
    _age_evidence(domain, days, "warn" if days is not None and days < 90 else "info" if days is not None else "unavailable", a)
    a.checks.append(Check("domain_age", status if status in ("ok", "cached", "timeout", "error") else "skipped",
                          ms, status))


def _age_evidence(domain: str, days: int | None, status: str, a: Analysis) -> None:
    evidence(a, "age", status, f"{days} days" if days is not None else "No registration date available", text(
        "RDAP registration age is context, not a safety guarantee. Demo values are fixture data; an unavailable lookup is not a clean result.",
        "RDAP उम्र संदर्भ है, सुरक्षा की गारंटी नहीं। Demo उम्र नमूना है; उपलब्ध न होना सुरक्षित होने का प्रमाण नहीं।",
        "RDAP वय संदर्भ आहे, सुरक्षिततेची हमी नाही. Demo वय नमुना आहे; अनुपलब्ध तपासणी स्वच्छ निकाल नाही."), domain)


def _age_signal(domain: str, days: int, a: Analysis) -> None:
    a.summary["domain_age_days"] = days
    if days < 7:
        a.add("URL_NEW_DOMAIN", 35, domain=domain, days=days)
    elif days < 30:
        a.add("URL_NEW_DOMAIN", 25, domain=domain, days=days)
    elif days < 90:
        a.add("URL_NEW_DOMAIN", 8, domain=domain, days=days)


async def _intel(urls: list[str], ctx: Ctx, a: Analysis) -> None:
    t0 = time.monotonic()
    for u in urls:
        src = intel.lookup_local(ctx.db, u)
        if src:
            a.add("URL_INTEL_HIT", 100, force="DANGER", source=src)
            a.checks.append(Check("threat_feeds", "ok", int((time.monotonic() - t0) * 1000), src))
            evidence(a, "feeds", "demo" if "demo" in src.lower() else "fail", src, text(
                "Matched a locally loaded threat entry. Demo entries are labelled separately.",
                "लोड किए गए खतरे के रिकॉर्ड से मिलान। Demo रिकॉर्ड अलग चिन्हित हैं।",
                "लोड केलेल्या धोक्याच्या नोंदीशी जुळले. Demo नोंदी वेगळ्या दर्शवल्या आहेत."), urls[-1])
            return
    available = any(feed.get("count", 0) > 0 for feed in intel.feed_status(ctx.db).values())
    a.checks.append(Check("threat_feeds", "ok" if available else "skipped", int((time.monotonic() - t0) * 1000)))
    sources = intel.feed_status(ctx.db)
    counts = ", ".join(f"{name}: {feed.get('count', 0)}" for name, feed in sources.items() if feed.get("count", 0))
    evidence(a, "feeds", "info" if available else "unavailable", counts or "No loaded feed entries", text(
        "No match in the loaded entries. Feed absence or a miss does not establish safety.",
        "लोड किए गए रिकॉर्ड में मिलान नहीं। रिकॉर्ड न होना या मिलान न होना सुरक्षा साबित नहीं करता।",
        "लोड केलेल्या नोंदीत जुळले नाही. नोंदी नसणे किंवा न जुळणे सुरक्षितता सिद्ध करत नाही."), urls[-1])
    for name, enabled in (("Google Safe Browsing", bool(intel.settings.gsb_api_key)), ("URLhaus API", bool(intel.settings.urlhaus_auth_key))):
        if not enabled or not ctx.online:
            evidence(a, "api", "unavailable", name, text(
                "Not run: API credential or online checks are unavailable.",
                "जांच नहीं हुई: API कुंजी या ऑनलाइन जांच उपलब्ध नहीं।",
                "तपासले नाही: API की किंवा ऑनलाइन तपासणी उपलब्ध नाही."), urls[-1])
    if not ctx.online:
        return
    apis = []
    if intel.settings.gsb_api_key:
        apis.append(("safe_browsing", lambda: intel.gsb_lookup(urls, min(1.5, ctx.remaining()))))
    if intel.settings.urlhaus_auth_key:
        apis.append(("urlhaus", lambda: intel.urlhaus_lookup(urls[-1], min(1.5, ctx.remaining()))))
    for name, make in apis:
        t1 = time.monotonic()
        try:
            src = await asyncio.wait_for(make(), max(0.1, min(1.5, ctx.remaining())))
        except asyncio.TimeoutError:
            a.checks.append(Check(name, "timeout"))
            _api_evidence(a, name, "unavailable", "Timeout", urls[-1])
            continue
        except Exception:  # noqa: BLE001 - external API problems must not break analysis
            a.checks.append(Check(name, "error"))
            _api_evidence(a, name, "unavailable", "Service error", urls[-1])
            continue
        a.checks.append(Check(name, "ok", int((time.monotonic() - t1) * 1000)))
        _api_evidence(a, name, "fail" if src else "info", src or "No threat match returned", urls[-1])
        if src:
            a.add("URL_INTEL_HIT", 100, force="DANGER", source=src)
            return


def _api_evidence(a: Analysis, name: str, status: str, value: str, scope: str) -> None:
    evidence(a, "api", status, f"{name}: {value}", text(
        "External service result at scan time. A successful lookup with no match is not proof of safety.",
        "स्कैन के समय बाहरी सेवा का परिणाम। मिलान न होना सुरक्षा का प्रमाण नहीं है।",
        "स्कॅनच्या वेळी बाह्य सेवेचा निकाल. न जुळणे सुरक्षिततेचा पुरावा नाही."), scope)


async def _expand(url: str, lex: Lexical, ctx: Ctx, a: Analysis) -> str | None:
    """Follow redirects safely. Returns the final URL if it differs."""
    t0 = time.monotonic()
    virtual = None
    if ctx.demo:
        from ..demo_fixtures import VIRTUAL_WEB
        virtual = VIRTUAL_WEB
    if not ctx.online and not (virtual and url in virtual):
        a.checks.append(Check("redirects", "skipped"))
        a.add("URL_UNVERIFIED", 25, force="CAUTION")
        _network_evidence(a, url, None)
        return None
    res = await ssrf.expand(url, timeout=max(0.2, min(2.5, ctx.remaining())), virtual=virtual)
    ms = int((time.monotonic() - t0) * 1000)
    a.checks.append(Check("redirects", res.status if res.status != "blocked" else "error", ms, res.reason))
    if res.status in ("timeout", "error", "blocked") or (res.hops and (res.hops[-1].status or 0) >= 400):
        a.add("URL_UNVERIFIED", 25, force="CAUTION")
    a.summary["hops"] = [{"url": h.url, "status": h.status, "ip": h.ip, "error": h.error} for h in res.hops]
    _network_evidence(a, url, res)
    if any(before.url.partition(":")[0].lower() == "https" and after.url.partition(":")[0].lower() == "http"
           for before, after in zip(res.hops, res.hops[1:])):
        a.add("URL_HTTPS_DOWNGRADE", 35, force="CAUTION")
    ctype = (res.content_type or "").lower()
    if "android.package-archive" in ctype or ".apk" in (res.content_disposition or "").lower():
        if not a.has("URL_APK_DOWNLOAD"):
            fname = res.final_url.rsplit("/", 1)[-1] or "app.apk"
            a.add("URL_APK_DOWNLOAD", 70, force="DANGER", file=truncate(fname, 40))
    elif any(t in ctype for t in ("application/x-msdownload", "application/x-dosexec", "application/vnd.microsoft.portable-executable")):
        if not a.has("URL_EXE_DOWNLOAD"):
            a.add("URL_EXE_DOWNLOAD", 50, file="Executable response")
    if res.redirects >= 1:
        try:
            final_host = urlsplit(res.final_url).hostname or ""
        except ValueError:
            a.add("URL_INVALID", 45, force="CAUTION")
            a.summary["invalid_url"] = True
            return None
        first, final = lex.info, host_info(final_host)
        # A shortener normally hops to another domain; only count it when it lands on
        # free hosting or a bare IP.
        cross = first.registrable != final.registrable and (
            not lex.shortener or _is_free_host(final) or final.is_ip)
        weight = 5 * max(0, res.redirects - 1) + (15 if cross else 0)
        a.add("URL_REDIRECTS", weight, hops=res.redirects, final=truncate(final.unicode_host, 50))
        if res.final_url != url:
            return res.final_url
    return None


def _network_evidence(a: Analysis, url: str, res: ssrf.ExpandResult | None) -> None:
    observed = res is not None and res.status == "ok"
    demo = res is not None and res.status == "demo"
    state = "demo" if demo else "pass" if observed else "unavailable"
    ips = ", ".join(dict.fromkeys(h.ip for h in res.hops if h.ip)) if res else ""
    blocked = res is not None and res.status == "blocked"
    dns_state = "warn" if blocked else "demo" if demo else "pass" if observed and ips else "unavailable"
    evidence(a, "dns", dns_state, ips or ("Fixture only; no DNS query" if demo else res.reason or "No public IP observed" if res else "Online check disabled"), text(
        "Each requested hop resolves to a public IP and connects to that pinned IP. Private / metadata targets, credentials and unsupported ports are blocked.",
        "हर अनुरोध सार्वजनिक IP से जुड़ता है। निजी IP, metadata, credentials और अस्वीकृत पोर्ट रोके जाते हैं।",
        "प्रत्येक विनंती सार्वजनिक IP शी जोडली जाते. खासगी IP, metadata, credentials आणि अमान्य पोर्ट रोखले जातात."), url)
    final = res.final_url if res else url
    secure = final.partition(":")[0].lower() == "https"
    tls = bool(res and res.tls_verified and observed and secure)
    evidence(a, "transport", "pass" if tls else "demo" if demo else "warn" if not secure else "unavailable",
             "TLS certificate / hostname validated" if tls else "HTTP (unencrypted)" if not secure else "HTTPS declared; live TLS not verified", text(
        "HTTPS alone does not prove legitimacy. Live TLS validation is reported only after a successful certificate-verified connection.",
        "HTTPS से असली वेबसाइट साबित नहीं होती। TLS पुष्टि केवल सफल प्रमाणपत्र जांच के बाद दिखाई जाती है।",
        "HTTPS मुळे वेबसाइट खरी ठरत नाही. TLS पडताळणी यशस्वी प्रमाणपत्र तपासणीनंतरच दाखवली जाते."), final)
    chain = " → ".join(f"{h.status or h.error or '?'} {_display_host(h.url)}" for h in res.hops) if res else "Not requested"
    evidence(a, "redirects", state, chain, text(
        "At most five redirects. Every hop is revalidated; no JavaScript is executed. Demo chains are simulated.",
        "अधिकतम पांच रीडायरेक्ट। हर पते की फिर जांच होती है; JavaScript नहीं चलता। Demo श्रृंखला नकली नमूना है।",
        "जास्तीत जास्त पाच रीडायरेक्ट. प्रत्येक पत्ता पुन्हा तपासला जातो; JavaScript चालत नाही. Demo साखळी नमुना आहे."), url)
    code = res.hops[-1].status if res and res.hops else None
    evidence(a, "response", "warn" if code and code >= 400 else "info" if observed else state,
             f"HTTP {code or '?'} | {(res.content_type or 'Content type unavailable') if res else 'No response'}", text(
        "Observed response headers, not a full page audit. Forms, scripts and malware binaries are not executed or submitted.",
        "प्रतिक्रिया headers की जांच, पूरी वेबसाइट की नहीं। Form, script और malware नहीं चलाए जाते।",
        "प्रतिसाद headers तपासले, संपूर्ण वेबसाइट नाही. Form, script आणि malware चालवले जात नाहीत."), final)


def _display_host(url: str) -> str:
    try:
        return urlsplit(url).hostname or url
    except ValueError:
        return "Malformed redirect destination"


async def analyze_url(raw: str, a: Analysis, ctx: Ctx) -> None:
    url = normalize_url(raw)
    if any(ord(ch) < 32 or ch == "\\" or ord(ch) == 127 for ch in raw.strip()):
        a.add("URL_PARSER_AMBIGUITY", 35, force="CAUTION")
        a.summary["invalid_url"] = True
    a.kind = a.kind if a.kind not in ("", "text") else "url"
    lex = lexical(url, a, ctx)
    if lex.info is None:
        a.headline_code, a.headline_params = "HEAD_URL", {"host": truncate(raw, 40)}
        return
    if a.headline_code == "HEAD_TEXT":
        a.headline_code, a.headline_params = "HEAD_URL", {"host": lex.info.unicode_host}

    for _, destination in query_details(urlsplit(url).query)[1]:
        sub = Analysis(kind="url")
        if destination.lower().startswith(("javascript:", "data:", "file:")):
            sub.add("URL_DANGEROUS_SCHEME", 100, force="DANGER", scheme=destination.split(":", 1)[0])
        else:
            lexical(destination, sub, ctx, stage="embedded")
        merge(a, sub, positive_only=True)

    jobs = [_intel([url], ctx, a)]
    if not lex.info.is_ip:
        jobs.append(_domain_age(lex.info.registrable, ctx, a))
    final_task = asyncio.create_task(_expand(url, lex, ctx, a))
    await asyncio.gather(*jobs)
    final = await final_task if final_task else None

    if final:
        sub = Analysis(kind="url")
        flex = lexical(final, sub, ctx, stage="final")
        follow = [_intel([final], ctx, sub)]
        if flex.info and not flex.info.is_ip and flex.info.registrable != lex.info.registrable:
            follow.append(_domain_age(flex.info.registrable, ctx, sub))
        await asyncio.gather(*follow)
        merge(a, sub, positive_only=False)
        a.summary.update({k: v for k, v in sub.summary.items() if k.startswith("final") or k == "domain_age_days"})


def merge(dst: Analysis, src: Analysis, positive_only: bool = True) -> None:
    seen = {(s.code, tuple(sorted((k, str(v)) for k, v in s.params.items()))) for s in dst.signals}
    for s in src.signals:
        key = (s.code, tuple(sorted((k, str(v)) for k, v in s.params.items())))
        if key in seen or (positive_only and s.weight <= 0):
            continue
        if s.code in ("URL_NO_HTTPS",) and dst.has(s.code):
            continue
        dst.signals.append(s)
        seen.add(key)
    dst.checks.extend(c for c in src.checks if c.name not in {x.name for x in dst.checks})
    dst.technical.extend(src.technical)
