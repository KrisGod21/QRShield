import ipaddress

import httpx
import pytest

from app.ssrf import BlockedURL, check_url_shape, expand, ip_allowed, resolve_public

PUBLIC = "93.184.215.14"


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0",
    "100.64.0.1", "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
    "64:ff9b::a00:1", "198.18.0.1", "255.255.255.255",
])
def test_private_and_special_ips_blocked(ip):
    assert not ip_allowed(ipaddress.ip_address(ip))


@pytest.mark.parametrize("ip", ["93.184.215.14", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_ips_allowed(ip):
    assert ip_allowed(ipaddress.ip_address(ip))


@pytest.mark.parametrize("url,reason", [
    ("ftp://example.com/", "scheme"),
    ("file:///etc/passwd", "scheme"),
    ("gopher://example.com/", "scheme"),
    ("http://user:pass@example.com/", "userinfo"),
    ("http://example.com:22/", "port"),
    ("http://example.com:6379/", "port"),
])
def test_url_shape_rejections(url, reason):
    with pytest.raises(BlockedURL) as e:
        check_url_shape(url)
    assert e.value.reason == reason


def test_url_shape_ok():
    assert check_url_shape("https://example.com/x") == ("https", "example.com", 443)


def fake_resolver(table):
    async def resolve(host, port):
        if host not in table:
            raise OSError("nxdomain")
        return table[host]
    return resolve


async def test_resolve_drops_private_records_and_pins_public():
    # A rebinding-style answer mixing public and private: only the public IP is ever used.
    r = fake_resolver({"mixed.test": ["10.0.0.5", PUBLIC, "64:ff9b::a00:5"]})
    assert [str(i) for i in await resolve_public("mixed.test", 80, r)] == [PUBLIC]


async def test_resolve_rejects_all_private():
    r = fake_resolver({"internal.test": ["10.0.0.5", "fd00::1"]})
    with pytest.raises(BlockedURL) as e:
        await resolve_public("internal.test", 80, r)
    assert e.value.reason == "private-ip"


async def test_ip_literal_loopback_blocked():
    with pytest.raises(BlockedURL):
        await resolve_public("127.0.0.1", 80, fake_resolver({}))


def _transport(routes):
    """routes: {(ip, path): (status, headers)}; asserts we connect to the pinned IP."""
    seen = []

    def handler(request: httpx.Request):
        seen.append((request.url.host, request.headers.get("host")))
        status, headers = routes.get((request.url.host, request.url.path), (404, {}))
        return httpx.Response(status, headers=headers)
    return httpx.MockTransport(handler), seen


async def test_redirect_to_private_ip_is_blocked():
    transport, seen = _transport({(PUBLIC, "/go"): (302, {"location": "http://internal.test/admin"})})
    resolver = fake_resolver({"short.test": [PUBLIC], "internal.test": ["192.168.0.10"]})
    res = await expand("http://short.test/go", resolver=resolver, transport=transport)
    assert res.status == "blocked" and res.reason == "private-ip"
    assert len(res.hops) == 2 and res.hops[1].error == "private-ip"
    # We connected by IP but sent the real Host header (no DNS re-resolution).
    assert seen == [(PUBLIC, "short.test")]


async def test_redirect_to_metadata_literal_is_blocked():
    transport, _ = _transport({(PUBLIC, "/"): (301, {"location": "http://169.254.169.254/latest/meta-data"})})
    res = await expand("http://a.test/", resolver=fake_resolver({"a.test": [PUBLIC]}), transport=transport)
    assert res.status == "blocked"


async def test_redirect_to_non_http_scheme_is_blocked():
    transport, _ = _transport({(PUBLIC, "/"): (302, {"location": "file:///etc/passwd"})})
    res = await expand("http://a.test/", resolver=fake_resolver({"a.test": [PUBLIC]}), transport=transport)
    assert res.status == "blocked" and res.reason == "scheme"


async def test_follows_public_chain_and_reports_final():
    other = "93.184.215.15"
    transport, _ = _transport({
        (PUBLIC, "/x"): (301, {"location": "https://dest.test/landing"}),
        (other, "/landing"): (200, {"content-type": "text/html"}),
    })
    res = await expand("http://short.test/x", transport=transport,
                       resolver=fake_resolver({"short.test": [PUBLIC], "dest.test": [other]}))
    assert res.status == "ok"
    assert res.final_url == "https://dest.test/landing"
    assert res.redirects == 1 and res.content_type == "text/html"


async def test_redirect_loop_stops_at_max_hops():
    transport, _ = _transport({(PUBLIC, "/loop"): (302, {"location": "/loop"})})
    res = await expand("http://loop.test/loop", resolver=fake_resolver({"loop.test": [PUBLIC]}),
                       transport=transport)
    assert res.status == "error" and res.reason == "too-many-redirects"
    assert len(res.hops) == 6


async def test_virtual_web_never_touches_network():
    def boom(request):
        raise AssertionError("network used")
    res = await expand("http://v.test/a", virtual={"http://v.test/a": (301, "http://v.test/b"),
                                                  "http://v.test/b": (200, "text/html")},
                       transport=httpx.MockTransport(boom))
    assert res.status == "demo" and res.final_url == "http://v.test/b"
