"""Domain lists: Indian brand official domains, risky TLDs, shorteners, free hosting.

Sources: docs/research/03_url_intel_libs.md sections A.3 to A.6.
"""

# Brand -> official registrable domains. Legacy domains are kept because old
# QR codes still point there and redirect to the new .bank.in domains.
INDIAN_BRANDS: dict[str, list[str]] = {
    "SBI": ["sbi.bank.in", "sbi.co.in", "onlinesbi.sbi", "sbi", "onlinesbi.com", "sbicard.com"],
    "HDFC Bank": ["hdfc.bank.in", "hdfcbank.com", "hdfcbank.bank.in"],
    "ICICI Bank": ["icici.bank.in", "icicibank.com"],
    "Axis Bank": ["axis.bank.in", "axisbank.com"],
    "Kotak Mahindra Bank": ["kotak.bank.in", "kotak.com"],
    "Punjab National Bank": ["pnb.bank.in", "pnbindia.in"],
    "Bank of Baroda": ["bankofbaroda.bank.in", "bankofbaroda.in", "bankofbaroda.co.in"],
    "Canara Bank": ["canarabank.bank.in", "canarabank.com", "canarabank.in"],
    "Union Bank of India": ["unionbankofindia.bank.in", "unionbankofindia.co.in"],
    "Bank of India": ["bankofindia.bank.in", "bankofindia.co.in"],
    "Indian Overseas Bank": ["iob.bank.in", "iob.in"],
    "Indian Bank": ["indianbank.bank.in", "indianbank.in"],
    "Central Bank of India": ["centralbank.bank.in", "centralbankofindia.co.in"],
    "UCO Bank": ["uco.bank.in", "ucobank.com"],
    "Yes Bank": ["yes.bank.in", "yesbank.in"],
    "IDFC First Bank": ["idfcfirst.bank.in", "idfcfirstbank.com"],
    "IndusInd Bank": ["indusind.bank.in", "indusind.com"],
    "Federal Bank": ["federal.bank.in", "federalbank.co.in"],
    "RBL Bank": ["rbl.bank.in", "rblbank.com"],
    "IDBI Bank": ["idbi.bank.in", "idbibank.in"],
    "Bandhan Bank": ["bandhan.bank.in", "bandhanbank.com"],
    "AU Small Finance Bank": ["au.bank.in", "aubank.in"],
    "India Post Payments Bank": ["ippbonline.bank.in", "ippbonline.com"],
    "Airtel Payments Bank": ["airtelpayments.bank.in", "airtel.bank.in"],
    "RBI": ["rbi.org.in"],
    "Paytm": ["paytm.com", "paytm.in", "paytm.bank.in"],
    "PhonePe": ["phonepe.com"],
    "Google Pay": ["pay.google.com", "wallet.google.com"],
    "BHIM / NPCI": ["bhimupi.org.in", "npci.org.in"],
    "BharatPe": ["bharatpe.com"],
    "MobiKwik": ["mobikwik.com"],
    "CRED": ["cred.club"],
    "Income Tax Dept": ["incometax.gov.in"],
    "UIDAI / Aadhaar": ["uidai.gov.in"],
    "EPFO": ["epfo.gov.in", "epfindia.gov.in"],
    "DigiLocker": ["digilocker.gov.in"],
    "GST": ["gst.gov.in"],
    "Parivahan / e-Challan": ["parivahan.gov.in"],
    "India Post": ["indiapost.gov.in"],
    "IRCTC": ["irctc.co.in"],
    "Cybercrime Portal": ["cybercrime.gov.in"],
    "LIC": ["licindia.in"],
    "Amazon": ["amazon.in", "amazon.com", "amzn.to", "amzn.in"],
    "Flipkart": ["flipkart.com", "fkrt.it"],
    "Myntra": ["myntra.com"],
    "Meesho": ["meesho.com"],
    "Swiggy": ["swiggy.com"],
    "Zomato": ["zomato.com"],
    "Jio": ["jio.com"],
    "Airtel": ["airtel.in"],
    "BSES": ["bsesdelhi.com"],
    "MSEDCL (Mahavitaran)": ["mahadiscom.in"],
    "Adani Electricity": ["adanielectricity.com"],
    "Tata Power": ["tatapower.com", "tatapower-ddl.com"],
}

OFFICIAL_DOMAINS: dict[str, str] = {d: brand for brand, ds in INDIAN_BRANDS.items() for d in ds}

# Brand keyword -> brand name. Used to spot a brand in a subdomain, path or a
# lookalike label. Keep keywords >= 3 chars to avoid noise.
BRAND_KEYWORDS: dict[str, str] = {
    "onlinesbi": "SBI", "sbi": "SBI", "yono": "SBI",
    "hdfc": "HDFC Bank", "icici": "ICICI Bank", "axisbank": "Axis Bank", "kotak": "Kotak Mahindra Bank",
    "pnb": "Punjab National Bank", "bankofbaroda": "Bank of Baroda", "canara": "Canara Bank",
    "unionbank": "Union Bank of India", "indusind": "IndusInd Bank", "idfc": "IDFC First Bank",
    "yesbank": "Yes Bank", "federalbank": "Federal Bank", "rbi": "RBI",
    "paytm": "Paytm", "phonepe": "PhonePe", "gpay": "Google Pay", "googlepay": "Google Pay",
    "bhim": "BHIM / NPCI", "npci": "BHIM / NPCI", "bharatpe": "BharatPe", "mobikwik": "MobiKwik",
    "irctc": "IRCTC", "indiapost": "India Post", "incometax": "Income Tax Dept",
    "aadhaar": "UIDAI / Aadhaar", "aadhar": "UIDAI / Aadhaar", "uidai": "UIDAI / Aadhaar",
    "epfo": "EPFO", "digilocker": "DigiLocker", "parivahan": "Parivahan / e-Challan",
    "echallan": "Parivahan / e-Challan", "amazon": "Amazon", "flipkart": "Flipkart",
    "myntra": "Myntra", "meesho": "Meesho", "swiggy": "Swiggy", "zomato": "Zomato",
    "jio": "Jio", "airtel": "Airtel", "mahadiscom": "MSEDCL (Mahavitaran)", "msedcl": "MSEDCL (Mahavitaran)",
    "bses": "BSES", "tatapower": "Tata Power", "licindia": "LIC",
}

# Labels used for typosquat / homoglyph comparison (registrable label -> brand).
# Only distinctive labels of length >= 5 to keep edit-distance false positives low.
BRAND_LABELS: dict[str, str] = {}
for _d, _b in OFFICIAL_DOMAINS.items():
    _label = _d.split(".")[0]
    if len(_label) >= 5 and _label not in {"google", "wallet"}:
        BRAND_LABELS[_label] = _b
for _k, _b in BRAND_KEYWORDS.items():
    if len(_k) >= 5:
        BRAND_LABELS.setdefault(_k, _b)

TRUSTED_SUFFIXES = ("bank.in", "gov.in", "nic.in")

GOV_WORDS = ("gov", "govt", "sarkar", "challan", "parivahan", "aadhaar", "aadhar", "uidai",
             "incometax", "itr-refund", "epfo", "pmkisan", "pm-kisan", "ayushman", "rto", "vahan")

# Interisle / CybercrimeInfoCenter May 2025 - Apr 2026 and Spamhaus.
SUSPICIOUS_TLDS_T1 = {
    "xin", "win", "icu", "garden", "cfd", "help", "mom", "rest", "qpon", "bond", "cyou", "sbs",
    "lol", "best", "lat", "wang", "homes", "ink", "click", "buzz", "bar", "casa", "support",
    "monster", "pics", "top", "vip", "tk", "ml", "ga", "cf", "gq",
}
SUSPICIOUS_TLDS_T2 = {
    "pro", "live", "life", "mobi", "xyz", "shop", "online", "site", "store", "cc", "info", "cn",
    "today", "work", "fyi", "zone", "digital", "finance", "link", "club", "space", "website",
    "fun", "cam", "run", "beauty", "hair", "skin", "quest", "boats",
}

URL_SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "is.gd", "v.gd", "t.ly", "cutt.ly", "rb.gy",
    "shorturl.at", "shorturl.asia", "s.id", "ow.ly", "buff.ly", "rebrand.ly", "t.co", "goo.gl",
    "tiny.cc", "surl.li", "lnkd.in", "qr.ae", "u.to", "clck.ru", "da.gd", "dub.sh", "short.gy",
    "tny.im", "inx.lv", "tiny.one", "bl.ink", "zpr.io", "urlz.fr", "bit.do", "shrtco.de",
    "spoo.me", "qrco.de", "l.ead.me", "me-qr.com", "qr-code-generator.com", "qr.codes",
    "qrfy.io", "scnv.io", "page.link", "app.goo.gl", "linktr.ee",
}

FREE_HOSTING_SUFFIXES = {
    "pages.dev", "workers.dev", "trycloudflare.com", "r2.dev", "web.app", "firebaseapp.com",
    "appspot.com", "cloudfunctions.net", "blogspot.com", "sites.google.com", "forms.gle",
    "docs.google.com", "script.google.com", "storage.googleapis.com", "vercel.app",
    "netlify.app", "github.io", "gitbook.io", "webflow.io", "weebly.com", "weeblysite.com",
    "wixsite.com", "framer.app", "glitch.me", "000webhostapp.com", "onrender.com",
    "replit.app", "repl.co", "herokuapp.com", "fly.dev", "surge.sh", "azurewebsites.net",
    "web.core.windows.net", "s3.amazonaws.com", "amplifyapp.com", "duckdns.org", "ngrok.io",
    "ngrok.app", "ngrok-free.app", "ngrok-free.dev", "loca.lt", "serveo.net", "ipfs.io",
    "dweb.link", "cf-ipfs.com", "infura-ipfs.io", "translate.goog",
}

REMOTE_ACCESS_WORDS = ("anydesk", "teamviewer", "quicksupport", "rustdesk", "airdroid",
                       "screenshare", "screen-share", "ammyy", "supremo", "alpemix")
REMOTE_ACCESS_PACKAGES = ("com.anydesk", "com.teamviewer", "com.rustdesk", "com.sand.airdroid",
                          "com.ammyy", "com.nanosystems.supremo")

APK_EXTENSIONS = (".apk", ".xapk", ".apks", ".aab")
EXE_EXTENSIONS = (".exe", ".msi", ".bat", ".scr", ".jar", ".cmd", ".ps1", ".vbs", ".dmg")

SUSPICIOUS_URL_WORDS = ("kyc", "verify", "verification", "login", "signin", "otp", "reward",
                        "refund", "cashback", "claim", "prize", "lottery", "kbc", "redeliver",
                        "update-pan", "unblock", "suspend", "bonus", "winner", "gift")
