from __future__ import annotations

import hashlib
import re
from decimal import Decimal, InvalidOperation


def format_inr(value: Decimal | float | str | None) -> str:
    """Indian digit grouping: 100000 -> ₹1,00,000; 4999.5 -> ₹4,999.50."""
    if value is None:
        return ""
    try:
        d = Decimal(str(value))
    except InvalidOperation:
        return str(value)
    neg = d < 0
    d = abs(d)
    whole = int(d)
    frac = d - whole
    s = str(whole)
    if len(s) > 3:
        head, tail = s[:-3], s[-3:]
        groups = []
        while len(head) > 2:
            groups.insert(0, head[-2:])
            head = head[:-2]
        if head:
            groups.insert(0, head)
        s = ",".join(groups) + "," + tail
    out = "₹" + s
    if frac:
        out += "." + f"{frac:.2f}".split(".")[1]
    return ("-" if neg else "") + out


def normalize_payload(payload: str) -> str:
    """Normalisation used for hashing community reports and cache keys."""
    return payload.strip().replace("\r\n", "\n")


def payload_hash(payload: str) -> str:
    return hashlib.sha256(normalize_payload(payload).encode("utf-8")).hexdigest()


MOBILE_RE = re.compile(r"^(?:\+?91)?[6-9]\d{9}$")
URL_IN_TEXT_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
VPA_IN_TEXT_RE = re.compile(r"\b[A-Za-z0-9._-]{2,256}@[A-Za-z][A-Za-z0-9]{1,63}\b")
PHONE_IN_TEXT_RE = re.compile(r"(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}")


def truncate(s: str, n: int = 60) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"
