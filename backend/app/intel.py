"""Threat intelligence: cached public feeds in SQLite + optional keyed APIs.

Feeds (all keyless; docs/research/03_url_intel_libs.md section B):
  * OpenPhish community feed (non-commercial)
  * PhishTank online-valid CSV (keyless download still works; registration closed)
  * URLhaus text_online (keyless bulk; the URLhaus *API* needs URLHAUS_AUTH_KEY)
Optional APIs: Google Safe Browsing v4 (GSB_API_KEY), URLhaus API (URLHAUS_AUTH_KEY).
Nothing here is a hard dependency: any failure just means "no hit".
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import time
from urllib.parse import urlsplit

import httpx

from .config import settings
from .db import DB

log = logging.getLogger("qrshield.intel")

FEEDS = {
    "OpenPhish": "https://openphish.com/feed.txt",
    "PhishTank": "https://data.phishtank.com/data/online-valid.csv",
    "URLhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
}
REFRESH_SECONDS = 6 * 3600


def normalize_url(url: str) -> str:
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return url.strip()
    host = (p.hostname or "").lower()
    port = f":{p.port}" if p.port and p.port not in (80, 443) else ""
    path = p.path or "/"
    q = f"?{p.query}" if p.query else ""
    return f"{p.scheme.lower()}://{host}{port}{path}{q}".rstrip("/")


def _entry(url: str, source: str) -> tuple | None:
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        return None
    try:
        p = urlsplit(url)
    except ValueError:
        return None
    host = (p.hostname or "").lower()
    if not host:
        return None
    is_root = int(p.path in ("", "/") and not p.query)
    return (normalize_url(url), host, is_root, source, time.time())


def lookup_local(db: DB, url: str) -> str | None:
    """Exact URL match, or host match when the feed listed the whole host."""
    n = normalize_url(url)
    rows = db.execute("SELECT source FROM intel WHERE url=? LIMIT 1", (n,))
    if rows:
        return rows[0]["source"]
    host = (urlsplit(url).hostname or "").lower()
    rows = db.execute("SELECT source FROM intel WHERE host=? AND is_root=1 LIMIT 1", (host,))
    return rows[0]["source"] if rows else None


def store_entries(db: DB, source: str, urls: list[str]) -> int:
    rows = [e for e in (_entry(u, source) for u in urls) if e]
    db.execute("DELETE FROM intel WHERE source=?", (source,))
    db.executemany("INSERT INTO intel(url, host, is_root, source, added) VALUES (?,?,?,?,?)", rows)
    db.execute("INSERT INTO feeds(source, count, updated) VALUES (?,?,?) "
               "ON CONFLICT(source) DO UPDATE SET count=excluded.count, updated=excluded.updated",
               (source, len(rows), time.time()))
    return len(rows)


def _parse(source: str, text: str) -> list[str]:
    if source == "PhishTank":
        return [row["url"] for row in csv.DictReader(io.StringIO(text)) if row.get("url")]
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]


async def refresh_feeds(db: DB, force: bool = False) -> dict[str, int]:
    done: dict[str, int] = {}
    async with httpx.AsyncClient(timeout=30, follow_redirects=True,
                                 headers={"User-Agent": "phishtank/qrshield-hackathon"}) as client:
        for source, url in FEEDS.items():
            rows = db.execute("SELECT updated FROM feeds WHERE source=?", (source,))
            if rows and not force and time.time() - rows[0]["updated"] < REFRESH_SECONDS:
                continue
            try:
                r = await client.get(url)
                r.raise_for_status()
                done[source] = await asyncio.to_thread(store_entries, db, source, _parse(source, r.text))
                log.info("feed %s: %d entries", source, done[source])
            except Exception as e:  # noqa: BLE001 - a feed failing must never break startup
                log.warning("feed %s failed: %s", source, e)
    return done


def feed_status(db: DB) -> dict[str, dict]:
    return {r["source"]: {"count": r["count"], "updated": r["updated"]}
            for r in db.execute("SELECT * FROM feeds")}


async def gsb_lookup(urls: list[str], timeout: float) -> str | None:
    if not settings.gsb_api_key:
        return None
    body = {
        "client": {"clientId": "qrshield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                         params={"key": settings.gsb_api_key}, json=body)
        r.raise_for_status()
        return "Google Safe Browsing" if r.json().get("matches") else None


async def urlhaus_lookup(url: str, timeout: float) -> str | None:
    if not settings.urlhaus_auth_key:
        return None
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                         headers={"Auth-Key": settings.urlhaus_auth_key})
        r.raise_for_status()
        return "URLhaus" if r.json().get("query_status") == "ok" else None
