"""Bharat QR / EMVCo merchant-presented QR (TLV string starting with '000201').

Layout: 2-digit tag, 2-digit length, value. Tag 63 holds a CRC16/CCITT-FALSE
over everything up to and including '6304'. Merchant account templates are
tags 26-51; the UPI one carries AID A000000524 (or 'UPI') in sub-tag 00 and
the VPA in sub-tag 01 (Razorpay sample, docs/research/04_payloads_competitors.md).
"""

from __future__ import annotations

from ..models import Analysis
from .upi import analyze_upi_params
from ..technical import add as evidence, text


def parse_tlv(data: str) -> dict[str, str] | None:
    out: dict[str, str] = {}
    i = 0
    while i < len(data):
        if i + 4 > len(data):
            return None
        tag, length = data[i:i + 2], data[i + 2:i + 4]
        if not (tag.isdigit() and length.isdigit()) or tag in out:
            return None
        n = int(length)
        value = data[i + 4:i + 4 + n]
        if len(value) != n:
            return None
        out.setdefault(tag, value)
        i += 4 + n
    return out


def crc16_ccitt(data: bytes) -> str:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return f"{crc:04X}"


def crc_ok(payload: str) -> bool:
    idx = payload.rfind("6304")
    if idx < 0 or len(payload) != idx + 8 or parse_tlv(payload) is None:
        return False
    expected = payload[idx + 4: idx + 8].upper()
    return crc16_ccitt(payload[: idx + 4].encode("utf-8")) == expected


def extract_vpa(tlv: dict[str, str]) -> str | None:
    candidates: set[str] = set()
    for tag in range(26, 52):
        tmpl = tlv.get(f"{tag:02d}")
        if not tmpl:
            continue
        sub = parse_tlv(tmpl) or {}
        gui = sub.get("00", "").upper()
        v = sub.get("01", "")
        if gui in ("A000000524", "UPI") and "@" in v:
            candidates.add(v)
    return next(iter(candidates)) if len(candidates) == 1 else None


def analyze_emv(payload: str, intent: str, a: Analysis) -> list[str]:
    a.kind = "bharat_qr"
    data = payload.strip()
    tlv = parse_tlv(data) or {}
    name = tlv.get("59", "")
    a.summary.update({"emv_name": name, "emv_city": tlv.get("60"), "emv_mcc": tlv.get("52")})
    if not crc_ok(data):
        a.add("EMV_CRC_INVALID", 45)
    evidence(a, "crc", "pass" if crc_ok(data) else "fail", "CRC16/CCITT-FALSE + unique TLV tags", text(
        "Validates structure and checksum, including an end-of-payload CRC. CRC detects corruption, not merchant authenticity.",
        "प्रारूप और अंत के checksum की जांच। CRC खराब डेटा पहचानता है, व्यापारी की असलियत नहीं।",
        "स्वरूप आणि शेवटचा checksum तपासला. CRC खराब डेटा ओळखतो, व्यापाऱ्याची सत्यता नाही."), name)
    vpa = extract_vpa(tlv)
    if not vpa:
        a.add("EMV_NO_UPI", 0)
        a.headline_code, a.headline_params = "HEAD_BHARAT_QR_CARD", {"pn": name or "?"}
        return []
    params = {"pa": vpa, "pn": name, "mc": tlv.get("52", "")}
    if tlv.get("54"):
        params["am"] = tlv["54"]
    if tlv.get("53") and tlv["53"] != "356":
        params["cu"] = tlv["53"]
    return analyze_upi_params("pay", params, [], intent, a, source_label="bharat_qr")
