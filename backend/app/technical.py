"""Observed evidence, separate from the risk score and external verification."""
from __future__ import annotations

from .models import Analysis


def text(en: str, hi: str, mr: str) -> dict[str, str]:
    return {"en": en, "hi": hi, "mr": mr}


LABELS = {
    "domain": text("Domain boundary", "डोमेन सीमा", "डोमेन सीमा"),
    "identity": text("Lookalike / impersonation", "नकली पहचान की जांच", "बनावट ओळख तपासणी"),
    "transport": text("Transport encryption", "कनेक्शन एन्क्रिप्शन", "कनेक्शन एन्क्रिप्शन"),
    "query": text("Query parameter consistency", "URL पैरामीटर जांच", "URL पॅरामीटर तपासणी"),
    "embedded": text("Embedded destination", "छिपा हुआ गंतव्य", "लपवलेले गंतव्य"),
    "dns": text("DNS / network boundary", "DNS और नेटवर्क सीमा", "DNS आणि नेटवर्क सीमा"),
    "response": text("HTTP response / content", "HTTP प्रतिक्रिया और सामग्री", "HTTP प्रतिसाद आणि सामग्री"),
    "redirects": text("Redirect chain", "रीडायरेक्ट श्रृंखला", "रीडायरेक्ट साखळी"),
    "age": text("Domain registration age", "डोमेन की पंजीकरण उम्र", "डोमेन नोंदणीचे वय"),
    "feeds": text("Threat intelligence", "खतरे के डेटाबेस", "धोक्याचे डेटाबेस"),
    "api": text("External reputation service", "बाहरी सुरक्षा सेवा", "बाह्य सुरक्षा सेवा"),
    "vpa": text("Payee address syntax", "प्राप्तकर्ता पते का प्रारूप", "प्राप्तकर्ता पत्त्याचे स्वरूप"),
    "handle": text("PSP handle recognition", "PSP हैंडल पहचान", "PSP हँडल ओळख"),
    "name": text("Merchant display name", "व्यापारी का नाम", "व्यापाऱ्याचे नाव"),
    "mcc": text("Merchant category code", "व्यापारी श्रेणी कोड", "व्यापारी श्रेणी कोड"),
    "payment": text("Payment constraints", "भुगतान की शर्तें", "पेमेंट अटी"),
    "params": text("Payment parameter integrity", "भुगतान पैरामीटर जांच", "पेमेंट पॅरामीटर तपासणी"),
    "signature": text("QR signature verification", "QR हस्ताक्षर की पुष्टि", "QR स्वाक्षरी पडताळणी"),
    "ownership": text("Bank / merchant ownership", "बैंक और व्यापारी स्वामित्व", "बँक आणि व्यापारी मालकी"),
    "crc": text("Bharat QR integrity", "भारत QR की अखंडता", "भारत QR अखंडता"),
    "baseline_vpa": text("Saved payee comparison", "सहेजे गए प्राप्तकर्ता की तुलना", "जतन केलेल्या प्राप्तकर्त्याची तुलना"),
    "baseline_name": text("Saved name comparison", "सहेजे गए नाम की तुलना", "जतन केलेल्या नावाची तुलना"),
    "baseline_mcc": text("Saved category comparison", "सहेजी गई श्रेणी की तुलना", "जतन केलेल्या श्रेणीची तुलना"),
    "baseline_currency": text("Saved currency comparison", "सहेजी गई मुद्रा की तुलना", "जतन केलेल्या चलनाची तुलना"),
}


def add(a: Analysis, code: str, status: str, value: str, detail: dict[str, str],
        scope: str = "") -> None:
    a.technical.append({"id": code, "label": LABELS[code], "status": status,
                        "value": value[:1200], "detail": detail, "scope": scope[:255]})
