"""Demo QR codes with the verdict each one must get. Malicious ones use reserved
.test domains and fake VPAs, so nothing here points at a real phishing site."""

SAMPLES = [
    # (id, title, payload, intent, expected verdict, what to say)
    ("S1", "SBI official site", "https://onlinesbi.sbi.bank.in/", "check", "SAFE",
     "Real SBI on RBI's new .bank.in domain: trusted."),
    ("S2", "Kirana shop UPI QR", "upi://pay?pa=qrshield.demo.kirana@ybl&pn=Ramesh%20Kirana%20Store", "pay_shop", "SAFE",
     "Normal shop QR: no amount, known handle. Shows 'you PAY Ramesh Kirana Store'."),
    ("S3", "Home Wi-Fi (WPA2)", "WIFI:S:Sharma_Home;T:WPA;P:chai1234;;", "check", "SAFE",
     "Password-protected network: fine."),
    ("C1", "Cafe open Wi-Fi", "WIFI:S:Cafe_Guest;T:nopass;;", "check", "CAUTION",
     "Open network: warns not to do UPI/banking on it."),
    ("D1", "'Refund' UPI request", "upi://pay?pa=refund.desk2291@ybl&pn=Amazon%20Refund%20Dept&am=4999.00&cu=INR&tn=Scan%20to%20receive%20your%20refund", "check", "DANGER",
     "Classic scam: 'refund' but you PAY Rs 4,999; fake Amazon name on a personal ID; reported 6 times."),
    ("D2", "Fake SBI KYC, typo handle", "upi://pay?pa=sbi.kyc.update@okaxisbank&pn=SBI%20KYC%20Helpdesk&am=10&tn=KYC%20verification%20fee%20to%20unblock%20account", "check", "DANGER",
     "@okaxisbank is a misspelling of the real @okaxis."),
    ("D3", "AutoPay trap", "upi://mandate?pa=subs.collect@ybl&pn=Cashback%20Activation&am=9999&amrule=MAX&recur=ASPRESENTED&validitystart=09102026&validityend=09102036&rev=N&purpose=14&tn=Activate%20cashback", "check", "DANGER",
     "Looks like cashback, actually a 10-year non-cancellable AutoPay."),
    ("D4", "KBC lottery 'GST'", "upi://pay?pa=kbc.lottery.dept@axl&pn=KBC%20Lottery%20Winner&am=12500&tn=GST%20charge%20to%20release%20prize%20Rs%2025%20lakh", "check", "DANGER",
     "Prize + fee + reported 14 times by the community."),
    ("D5", "Lookalike bank domain", "https://onlinesbl.test/kyc-update/login", "check", "DANGER",
     "onlinesbl vs onlinesbi, registered 3 days ago."),
    ("D6", "Cyrillic homoglyph", "https://onlinesbі.test/login", "check", "DANGER",
     "The 'і' is Cyrillic: looks identical to SBI, detected by Unicode TR39."),
    ("D7", "Short link -> fake HDFC", "http://qrs.test/x7Kp", "check", "DANGER",
     "We expand the short link safely on the server: lands on a 5-day-old HDFC lookalike."),
    ("D8", "e-Challan APK", "https://echallan-parivahan.test/pay/mParivahan.apk", "check", "DANGER",
     "Fake government app download (real RTO-APK scam pattern)."),
    ("D9", "Fake RailWire Wi-Fi", "WIFI:S:RailWire_Free;T:nopass;;", "check", "DANGER",
     "Real station Wi-Fi is exactly 'RailWire' with OTP login, never a QR."),
    ("D10", "*401# call-forward code", "tel:*401*9876543210%23", "check", "DANGER",
     "Diverts your calls (incl. bank OTP calls). DoT warned about this in Jan 2024."),
    ("D11", "Same kirana QR, but 'I'm receiving money'", "upi://pay?pa=qrshield.demo.kirana@ybl&pn=Ramesh%20Kirana%20Store", "receive", "DANGER",
     "Pick the 'Receiving money' chip, then scan S2 again: instant red stop."),
]

# Shopkeeper demo: register SHOP_GENUINE, then scan SHOP_SWAPPED.
SHOP_GENUINE = "upi://pay?pa=qrshield.demo.kirana@ybl&pn=Ramesh%20Kirana%20Store"
SHOP_SWAPPED = "upi://pay?pa=chhotu.t9921@axl&pn=Ramesh%20Kirana%20Store"
