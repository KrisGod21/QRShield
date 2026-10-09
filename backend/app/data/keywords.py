"""Scam keyword categories in English, Hindi/Hinglish (Roman + Devanagari) and Marathi.

Themes come from documented Indian cases (docs/research/01_scam_patterns.md section 4).
The non-English word forms are our compilation of common usage, not an official
lexicon, so treat matches as a heuristic.
"""

SCAM_KEYWORDS: dict[str, list[str]] = {
    "refund": ["refund", "reversal", "money back", "sent by mistake", "wrong transfer",
               "paisa wapas", "paise wapas", "wapsi", "galti se", "पैसा वापस", "वापसी", "रिफंड",
               "परतावा", "पैसे परत"],
    "receive": ["receive", "receiving", "to get money", "credit to you", "get payment",
                "payment received", "paise milenge", "prapt karein", "प्राप्त", "पैसे मिलेंगे",
                "पैसे मिळतील", "advance payment"],
    "prize": ["prize", "lottery", "lucky draw", "winner", "won", "jackpot", "kbc", "kaun banega",
              "inaam", "jeeta", "jeete", "bumper", "इनाम", "जीता", "लॉटरी", "बक्षीस", "उपहार"],
    "cashback": ["cashback", "cash back", "reward", "bonus", "voucher", "gift card",
                 "कैशबैक", "बोनस", "कॅशबॅक"],
    "kyc": ["kyc", "verify", "verification", "account blocked", "account block", "suspend",
            "unblock", "pan update", "aadhaar update", "re-kyc", "khata band", "केवायसी",
            "खाता बंद", "खाते बंद"],
    "bill": ["electricity", "bijli", "disconnection", "power cut", "connection kat",
             "बिजली", "वीज", "वीज बिल", "बिजली बिल"],
    "fee": ["processing fee", "registration fee", "joining fee", "clearance", "gst charge",
            "release fee", "customs", "shulk", "शुल्क", "नोंदणी शुल्क"],
    "job": ["job offer", "naukri", "work from home", "task fee", "नौकरी", "नोकरी"],
    "support": ["customer care", "customer support", "helpdesk", "help desk", "support team",
                "refund dept", "refund department"],
    "authority": ["army", "crpf", "military", "police", "cbi", "arrest", "digital arrest"],
}

# Categories that alone justify a strong warning; the rest are weaker hints.
STRONG_CATEGORIES = {"refund", "receive", "prize", "kyc", "fee", "support"}

# Words that make a payee name look like a business rather than a person.
BUSINESS_WORDS = ("store", "stores", "mart", "shop", "kirana", "medical", "pharmacy", "petrol",
                  "fuel", "pump", "restaurant", "hotel", "cafe", "traders", "enterprises", "ltd",
                  "limited", "pvt", "services", "agency", "bank", "dept", "department", "fund",
                  "trust", "mandir", "temple", "electricity", "board", "corporation", "municipal",
                  "parking", "toll")

# Payee-name words that claim an official body. Combined with a consumer handle
# these suggest impersonation.
AUTHORITY_NAMES = ("sbi", "state bank", "hdfc", "icici", "axis bank", "kotak", "pnb", "bank of baroda",
                   "canara", "union bank", "rbi", "reserve bank", "npci", "bhim", "paytm", "phonepe",
                   "google pay", "gpay", "amazon", "flipkart", "zomato", "swiggy", "irctc", "india post",
                   "income tax", "aadhaar", "uidai", "epfo", "gst", "customs", "police", "cyber cell",
                   "army", "government", "govt", "pm cares", "cm relief", "electricity board",
                   "msedcl", "mahavitaran", "bses", "tata power", "adani electricity", "jio", "airtel",
                   "kbc", "lic")

# MCC (merchant category code) values that deserve a second look.
RISKY_MCC = {"7995": "gambling", "6051": "crypto / quasi-cash", "7322": "debt collection",
             "4829": "money transfer", "6540": "stored-value card load"}


def find_keyword_categories(*texts: str) -> dict[str, str]:
    """Return {category: first matching word} across the given texts."""
    hay = " ".join(t.lower() for t in texts if t)
    found: dict[str, str] = {}
    if not hay:
        return found
    for cat, words in SCAM_KEYWORDS.items():
        for w in words:
            if _contains_word(hay, w.lower()):
                found[cat] = w
                break
    return found


def _contains_word(hay: str, word: str) -> bool:
    """Whole-word match for ASCII words, substring match for Indic scripts."""
    if not word.isascii():
        return word in hay
    start = 0
    while True:
        i = hay.find(word, start)
        if i < 0:
            return False
        before = hay[i - 1] if i > 0 else " "
        after = hay[i + len(word)] if i + len(word) < len(hay) else " "
        if not before.isalnum() and not after.isalnum():
            return True
        start = i + 1
