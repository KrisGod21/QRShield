"""Observed evidence, separate from the risk score and external verification."""
from __future__ import annotations

from .models import Analysis


def text(en: str, hi: str, mr: str) -> dict[str, str]:
    return {"en": en, "hi": hi, "mr": mr}


LABELS = {
    "payload": text("Payload classification", "QR सामग्री का प्रकार", "QR सामग्रीचा प्रकार"),
    "rules": text("Payload rule findings", "सामग्री के नियमों की जांच", "सामग्री नियमांचे निष्कर्ष"),
    "limits": text("Verification scope", "पुष्टि का दायरा", "पडताळणीची व्याप्ती"),
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


def ensure_evidence(a: Analysis) -> None:
    """Give all payload types evidence without exposing Wi-Fi / OTP secrets."""
    if a.technical:
        return
    add(a, "payload", "info", a.kind.replace("_", " "), text(
        "Classified from the decoded QR content. No action is executed automatically.",
        "QR की सामग्री से प्रकार पहचाना गया। कोई क्रिया अपने आप नहीं चलती।",
        "QR सामग्रीवरून प्रकार ओळखला. कोणतीही कृती आपोआप चालत नाही."))
    warnings = sum(s.weight > 0 for s in a.signals)
    add(a, "rules", "warn" if warnings else "info", f"{warnings} warning signals", text(
        "The verdict uses the applicable payload rules. The reasons below explain each signal. No warning does not guarantee safety.",
        "लागू सामग्री नियमों से नतीजा निकाला। नीचे हर संकेत का कारण है। चेतावनी न होना सुरक्षा की गारंटी नहीं।",
        "लागू सामग्री नियमांवरून निकाल दिला. खाली प्रत्येक संकेताचे कारण आहे. इशारा नसणे सुरक्षिततेची हमी नाही."))
    add(a, "limits", "unavailable", "Payload inspection only", text(
        "This result does not authenticate a network, contact, account or device. Credentials and one-time secrets are excluded from this panel.",
        "यह नेटवर्क, संपर्क, खाते या डिवाइस की असलियत की पुष्टि नहीं है। पासवर्ड और गोपनीय कोड यहां नहीं दिखाए जाते।",
        "यातून नेटवर्क, संपर्क, खाते किंवा डिवाइसची सत्यता पडताळली नाही. पासवर्ड आणि गोपनीय कोड येथे दाखवले नाहीत."))
