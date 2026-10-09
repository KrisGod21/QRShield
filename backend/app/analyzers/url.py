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
from urllib.parse import parse_qs, unquote, urlsplit

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
        text = qs.get("text", [""])[0]
        a.summary["chat"] = {"app": CHAT_HOSTS[info.host], "target": target, "text": text}
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
            a.checks.append(Check("domain_age", "demo", int((time.monotonic() - t0) * 1000)))
            return
    if not ctx.online:
        a.checks.append(Check("domain_age", "skipped"))
        return
    if ctx.remaining() < 0.25:
        a.checks.append(Check("domain_age", "skipped", 0, "budget"))
        return
    status, created = await rdap.lookup_created(domain, ctx.db, timeout=min(1.5, ctx.remaining()))
    ms = int((time.monotonic() - t0) * 1000)
    if created:
        days = rdap.age_days(created)
        if days is not None:
            _age_signal(domain, days, a)
    a.checks.append(Check("domain_age", status if status in ("ok", "cached", "timeout", "error") else "skipped",
                          ms, status))


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
            return
    available = any(feed.get("count", 0) > 0 for feed in intel.feed_status(ctx.db).values())
    a.checks.append(Check("threat_feeds", "ok" if available else "skipped", int((time.monotonic() - t0) * 1000)))
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
            continue
        except Exception:  # noqa: BLE001 - external API problems must not break analysis
            a.checks.append(Check(name, "error"))
            continue
        a.checks.append(Check(name, "ok", int((time.monotonic() - t1) * 1000)))
        if src:
            a.add("URL_INTEL_HIT", 100, force="DANGER", source=src)
            return


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
        return None
    res = await ssrf.expand(url, timeout=max(0.2, min(2.5, ctx.remaining())), virtual=virtual)
    ms = int((time.monotonic() - t0) * 1000)
    a.checks.append(Check("redirects", res.status if res.status != "blocked" else "error", ms, res.reason))
    if res.status in ("timeout", "error", "blocked"):
        a.add("URL_UNVERIFIED", 25, force="CAUTION")
    a.summary["hops"] = [{"url": truncate(h.url, 80), "status": h.status} for h in res.hops]
    ctype = (res.content_type or "").lower()
    if "android.package-archive" in ctype or ".apk" in (res.content_disposition or "").lower():
        if not a.has("URL_APK_DOWNLOAD"):
            fname = res.final_url.rsplit("/", 1)[-1] or "app.apk"
            a.add("URL_APK_DOWNLOAD", 70, force="DANGER", file=truncate(fname, 40))
    if res.redirects >= 1:
        first, final = host_info(urlsplit(url).hostname or ""), host_info(urlsplit(res.final_url).hostname or "")
        # A shortener normally hops to another domain; only count it when it lands on
        # free hosting or a bare IP.
        cross = first.registrable != final.registrable and (
            not lex.shortener or _is_free_host(final) or final.is_ip)
        weight = 5 * max(0, res.redirects - 1) + (15 if cross else 0)
        a.add("URL_REDIRECTS", weight, hops=res.redirects, final=truncate(final.unicode_host, 50))
        if res.final_url != url:
            return res.final_url
    return None


async def analyze_url(raw: str, a: Analysis, ctx: Ctx) -> None:
    url = normalize_url(raw)
    a.kind = a.kind if a.kind not in ("", "text") else "url"
    lex = lexical(url, a, ctx)
    if lex.info is None:
        a.headline_code, a.headline_params = "HEAD_URL", {"host": truncate(raw, 40)}
        return
    if a.headline_code == "HEAD_TEXT":
        a.headline_code, a.headline_params = "HEAD_URL", {"host": lex.info.unicode_host}

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
