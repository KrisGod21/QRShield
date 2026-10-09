"""Host / registrable-domain helpers built on an offline, pinned Public Suffix List."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import idna
import tldextract

_PSL = (Path(__file__).parent / "data" / "public_suffix_list.dat").resolve().as_uri()

# RFC 2606 / 6761 reserved names behave like public suffixes, so demo domains
# such as onlinesbl.test parse as domain="onlinesbl", suffix="test".
_RESERVED = ("test", "example", "invalid", "localhost")

_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(_PSL,),
    cache_dir=None,
    include_psl_private_domains=True,
    extra_suffixes=_RESERVED,
    fallback_to_snapshot=True,
)
_EXTRACT_ICANN = tldextract.TLDExtract(
    suffix_list_urls=(_PSL,), cache_dir=None, extra_suffixes=_RESERVED, fallback_to_snapshot=True,
)


@dataclass(frozen=True)
class HostInfo:
    host: str            # lowercase ASCII (punycode) host
    unicode_host: str    # decoded IDN form for display / skeleton
    subdomain: str
    label: str           # registrable label, e.g. "onlinesbi"
    suffix: str          # public suffix, e.g. "bank.in" or "pages.dev"
    registrable: str     # label + "." + suffix (or the host for IPs)
    is_private_suffix: bool
    is_ip: bool


def to_unicode(host: str) -> str:
    try:
        return idna.decode(host, uts46=True)
    except (idna.IDNAError, UnicodeError, ValueError):
        try:
            return host.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            return host


def to_ascii(host: str) -> str:
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError, ValueError):
        try:
            return host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return host


def parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    # Decimal / hex / octal IPv4 forms such as http://3232235777/ or 0xC0A80101.
    try:
        if h.isdigit():
            n = int(h)
        elif h.lower().startswith("0x"):
            n = int(h, 16)
        else:
            return None
        if 0 <= n <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(n)
    except ValueError:
        return None
    return None


@lru_cache(maxsize=4096)
def host_info(host: str) -> HostInfo:
    host = host.strip().rstrip(".").lower()
    if parse_ip(host) is not None:
        return HostInfo(host, host, "", host, "", host, False, True)
    ascii_host = to_ascii(host)
    uni = to_unicode(ascii_host)
    r = _EXTRACT(ascii_host)
    label, suffix = r.domain, r.suffix
    registrable = f"{label}.{suffix}" if label and suffix else ascii_host
    return HostInfo(
        host=ascii_host,
        unicode_host=uni,
        subdomain=r.subdomain,
        label=label,
        suffix=suffix,
        registrable=registrable,
        is_private_suffix=bool(getattr(r, "is_private", False)),
        is_ip=False,
    )


def icann_registrable(host: str) -> str:
    """Registrable domain ignoring private suffixes (x.pages.dev -> pages.dev)."""
    r = _EXTRACT_ICANN(host)
    return f"{r.domain}.{r.suffix}" if r.domain and r.suffix else host
