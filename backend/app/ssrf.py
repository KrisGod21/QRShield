"""SSRF-safe redirect expansion.

Follows OWASP's SSRF Prevention Cheat Sheet, case 2 ("any external URL"):
  1. Only http/https and ports 80/443. No credentials in the URL.
  2. Resolve every A/AAAA record and keep only globally routable addresses;
     refuse if none remain.
  3. Connect to that validated IP (Host header + TLS SNI keep the real name),
     so a second DNS answer cannot point us at an internal address (DNS rebinding).
  4. Never auto-follow redirects; every Location is validated as a new hop.
  5. Never execute JavaScript, cap the body size, short timeouts.
Requires Python >= 3.12.4 for correct ipaddress.is_global data (CVE-2024-4032).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable
from urllib.parse import urljoin, urlsplit

import httpx

MAX_HOPS = 5
MAX_BODY = 64 * 1024
ALLOWED_PORTS = {80, 443}
USER_AGENT = "QRShield/1.0 (+safety scanner; no JS)"

_EXTRA_BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.0.0.0/24", "198.18.0.0/15",
    "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "fc00::/7", "fe80::/10",
)]


class BlockedURL(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def ip_allowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if not ip.is_global:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local \
            or ip.is_unspecified or ip.is_private:
        return False
    return not any(ip in net for net in _EXTRA_BLOCKED if net.version == ip.version)


def check_url_shape(url: str) -> tuple[str, str, int]:
    """Validate scheme / port / userinfo. Returns (scheme, host, port)."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise BlockedURL("scheme")
    if parts.username or parts.password:
        raise BlockedURL("userinfo")
    host = parts.hostname
    if not host:
        raise BlockedURL("no-host")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise BlockedURL("bad-port")
    if port not in ALLOWED_PORTS:
        raise BlockedURL("port")
    return scheme, host, port


Resolver = Callable[[str, int], Awaitable[list[str]]]


async def system_resolve(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


async def resolve_public(host: str, port: int, resolver: Resolver = system_resolve):
    """Resolve and return the validated IPs. Raises BlockedURL if any is non-public."""
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
        addrs = [str(literal)]
    except ValueError:
        try:
            addrs = await resolver(host, port)
        except (socket.gaierror, OSError) as e:
            raise BlockedURL("dns") from e
    if not addrs:
        raise BlockedURL("dns")
    # Keep only globally routable answers. We then connect to one of these exact
    # IPs (pinning), so a mixed or rebinding DNS answer can never reach an
    # internal address. NAT64 resolvers (64:ff9b::/96) are why we filter rather
    # than reject on the first non-public record.
    ips = [ip for ip in (ipaddress.ip_address(a.split("%")[0]) for a in addrs) if ip_allowed(ip)]
    if not ips:
        raise BlockedURL("private-ip")
    ips.sort(key=lambda i: i.version)  # prefer IPv4
    return ips


@dataclass
class Hop:
    url: str
    status: int | None = None
    ip: str | None = None
    error: str | None = None


@dataclass
class ExpandResult:
    hops: list[Hop] = field(default_factory=list)
    final_url: str = ""
    content_type: str = ""
    content_disposition: str = ""
    status: str = "ok"         # ok | timeout | error | blocked | demo
    reason: str = ""
    tls_verified: bool = False

    @property
    def redirects(self) -> int:
        return max(0, len(self.hops) - 1)


# A virtual web used in DEMO_MODE: url -> (status, location_or_content_type)
VirtualWeb = dict[str, tuple[int, str]]


async def expand(url: str, timeout: float = 2.5, virtual: VirtualWeb | None = None,
                 resolver: Resolver = system_resolve,
                 transport: httpx.AsyncBaseTransport | None = None) -> ExpandResult:
    res = ExpandResult(final_url=url)
    deadline = time.monotonic() + timeout
    used_virtual = False
    async with httpx.AsyncClient(follow_redirects=False, trust_env=False, transport=transport,
                                 timeout=httpx.Timeout(min(2.0, timeout), connect=min(1.5, timeout)),
                                 headers={"User-Agent": USER_AGENT, "Accept": "*/*"}) as client:
        current = url
        for _ in range(MAX_HOPS + 1):
            hop = Hop(url=current)
            res.hops.append(hop)
            res.final_url = current

            if virtual is not None and current in virtual:
                used_virtual = True
                status, extra = virtual[current]
                hop.status = status
                if 300 <= status < 400:
                    current = urljoin(current, extra)
                    continue
                res.content_type = extra
                res.status = "demo"
                return res

            remaining = deadline - time.monotonic()
            if remaining <= 0.05:
                res.status, res.reason = "timeout", "budget"
                return res
            try:
                scheme, host, port = check_url_shape(current)
                ips = await asyncio.wait_for(resolve_public(host, port, resolver), remaining)
                ip = ips[0]
                hop.ip = str(ip)
                netloc = f"[{ip}]" if ip.version == 6 else str(ip)
                parts = urlsplit(current)
                target = parts._replace(netloc=f"{netloc}:{port}").geturl()
                headers = {"Host": parts.netloc.rsplit("@", 1)[-1]}
                ext = {"sni_hostname": host} if scheme == "https" else {}
                resp = await asyncio.wait_for(
                    client.request("HEAD", target, headers=headers, extensions=ext),
                    deadline - time.monotonic())
                if resp.status_code in (403, 405, 501) or resp.status_code >= 500:
                    resp = await asyncio.wait_for(
                        _limited_get(client, target, headers, ext), deadline - time.monotonic())
            except BlockedURL as e:
                hop.error = e.reason
                res.status, res.reason = ("blocked", e.reason) if e.reason != "dns" else ("error", "dns")
                return res
            except (asyncio.TimeoutError, httpx.TimeoutException):
                hop.error = "timeout"
                res.status, res.reason = "timeout", "timeout"
                return res
            except (httpx.HTTPError, OSError, ValueError) as e:
                hop.error = type(e).__name__
                res.status, res.reason = "error", type(e).__name__
                return res

            hop.status = resp.status_code
            res.tls_verified = scheme == "https" and transport is None
            loc = resp.headers.get("location")
            if resp.is_redirect and loc:
                current = urljoin(current, loc)
                continue
            res.content_type = resp.headers.get("content-type", "")
            res.content_disposition = resp.headers.get("content-disposition", "")
            res.status = "demo" if used_virtual else "ok"
            return res
    res.status, res.reason = "error", "too-many-redirects"
    return res


async def _limited_get(client: httpx.AsyncClient, target: str, headers: dict, ext: dict) -> httpx.Response:
    async with client.stream("GET", target, headers={**headers, "Range": "bytes=0-65535"},
                             extensions=ext) as r:
        size = 0
        async for chunk in r.aiter_raw():
            size += len(chunk)
            if size >= MAX_BODY:
                break
        return r
