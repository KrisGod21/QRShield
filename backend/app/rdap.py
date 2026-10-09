"""Domain registration date via RDAP (keyless; IANA bootstrap snapshot in app/data)."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import httpx

from .db import DB

_BOOTSTRAP = Path(__file__).parent / "data" / "rdap_dns.json"


@lru_cache(maxsize=1)
def _services() -> dict[str, str]:
    data = json.loads(_BOOTSTRAP.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for tlds, urls in data["services"]:
        base = next((u for u in urls if u.startswith("https://")), urls[0])
        for t in tlds:
            out[t.lower()] = base if base.endswith("/") else base + "/"
    return out


def rdap_base(domain: str) -> str | None:
    labels = domain.lower().split(".")
    svc = _services()
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in svc:
            return svc[cand]
    return None


def parse_registration(data: dict) -> str | None:
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            return ev["eventDate"]
    return None


def age_days(created_iso: str, now: datetime | None = None) -> int | None:
    try:
        created = datetime.fromisoformat(created_iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return max(0, (now - created).days)


async def lookup_created(domain: str, db: DB, timeout: float = 2.0,
                         client: httpx.AsyncClient | None = None) -> tuple[str, str | None]:
    """Return (status, created_iso). status: ok | cached | unsupported | error | timeout."""
    hit, created = db.rdap_get(domain)
    if hit:
        return "cached", created
    base = rdap_base(domain)
    if not base:
        return "unsupported", None
    own = client is None
    client = client or httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                         headers={"Accept": "application/rdap+json"})
    try:
        r = await asyncio.wait_for(client.get(f"{base}domain/{domain}"), timeout)
        if r.status_code == 404:
            db.rdap_put(domain, None)
            return "ok", None
        r.raise_for_status()
        created = parse_registration(r.json())
        db.rdap_put(domain, created)
        return "ok", created
    except (asyncio.TimeoutError, httpx.TimeoutException):
        return "timeout", None
    except (httpx.HTTPError, ValueError):
        return "error", None
    finally:
        if own:
            await client.aclose()
