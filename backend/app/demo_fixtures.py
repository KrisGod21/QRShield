"""DEMO_MODE fixtures: a small virtual web for reserved `.test` domains.

`.test` is reserved by RFC 2606/6761 and never resolves on the real internet,
so the malicious demo samples can't point at a live phishing site. With
DEMO_MODE=1 the analyzer reads domain ages, redirects and content types for
these hosts from here instead of the network. The detection rules themselves
are the same ones used for real URLs. The SSRF guard is never bypassed:
fixture hosts are answered from this table and never fetched.
"""

from __future__ import annotations

from .db import DB
from .util import payload_hash

# Registrable domain -> age in days.
DOMAIN_AGE_DAYS: dict[str, int] = {
    "onlinesbl.test": 3,
    "xn--onlinesb-0hh.test": 4,      # onlinesbі.test (Cyrillic і)
    "hdfcbank-rewards.test": 5,
    "echallan-parivahan.test": 2,
    "free-recharge-offer.test": 6,
    "qrs.test": 412,
    # Real official domains used by the safe samples (fixed so the demo is stable offline).
    "sbi.bank.in": 365 * 2,          # .bank.in launched 2025
    "irctc.co.in": 365 * 24,
}

# URL -> (HTTP status, Location for 3xx or Content-Type for 2xx).
VIRTUAL_WEB: dict[str, tuple[int, str]] = {
    "https://onlinesbi.sbi.bank.in/": (200, "text/html"),
    "http://qrs.test/x7Kp": (301, "https://hdfcbank-rewards.test/claim-reward?ref=qr"),
    "https://hdfcbank-rewards.test/claim-reward?ref=qr": (200, "text/html; charset=utf-8"),
    "https://onlinesbl.test/kyc-update/login": (200, "text/html; charset=utf-8"),
    "https://echallan-parivahan.test/pay/mParivahan.apk": (200, "application/vnd.android.package-archive"),
    "http://free-recharge-offer.test/jio-399-free": (200, "text/html"),
}

# Hosts treated as shorteners in demo mode (in addition to the real list).
DEMO_SHORTENERS = {"qrs.test"}

# A demo threat-feed entry (labelled as demo so it's never confused with live data).
DEMO_INTEL = {"http://free-recharge-offer.test/jio-399-free": "OpenPhish (demo feed)"}

# Community reports seeded for the demo: payload -> (count, reason).
SEEDED_REPORTS: dict[str, tuple[int, str]] = {
    "upi://pay?pa=kbc.lottery.dept@axl&pn=KBC%20Lottery%20Winner&am=12500&tn=GST%20charge%20to%20release%20prize%20Rs%2025%20lakh":
        (14, "Called me saying I won KBC lottery, asked to pay GST"),
    "upi://pay?pa=refund.desk2291@ybl&pn=Amazon%20Refund%20Dept&am=4999.00&cu=INR&tn=Scan%20to%20receive%20your%20refund":
        (6, "Fake customer care sent this on WhatsApp"),
}


def seed(db: DB) -> None:
    from .intel import _entry

    for url, source in DEMO_INTEL.items():
        if not db.execute("SELECT 1 FROM intel WHERE source=? LIMIT 1", (source,)):
            e = _entry(url, source)
            if e:
                db.executemany("INSERT INTO intel(url, host, is_root, source, added) VALUES (?,?,?,?,?)", [e])
    for payload, (count, reason) in SEEDED_REPORTS.items():
        h = payload_hash(payload)
        existing = db.execute("SELECT COUNT(*) AS n FROM reports WHERE hash=? AND seeded=1", (h,))[0]["n"]
        for _ in range(count - existing):
            db.add_report(h, reason, seeded=True)
