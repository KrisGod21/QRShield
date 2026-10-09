# What makes QR Shield different

**One line:** Other QR scanners ask *"is this link on a blacklist?"*. QR Shield asks *"what will this QR make you do, and is that what you think you're doing?"*. In India, that question is usually about money.

## The pitch (7 points)

1. **Built for how Indians actually get cheated: UPI, not links.**
   UPI handles **24 billion transactions a month** across **73 crore QR codes**. QR-code fraud cases rose **2.7× in two years**, from 14,625 to 39,638 (Lok Sabha, Dec 2024). Since NPCI banned P2P collect requests on 1 Oct 2025, a scammer's main remaining trick is getting you to scan and pay. Kaspersky, Trend Micro and the phone camera only check URLs. QR Shield fully decodes UPI payloads (`upi://pay`, `upi://mandate`, Bharat QR) **before** your payment app opens.

2. **It kills the #1 scam in one sentence: "Scanning a QR never gives you money."**
   Every result shows *"You are about to PAY ₹4,999 to 'SBI Refund Dept' (sbirefund123@ybl)"*. If you tell the app you're expecting to *receive* money, any UPI QR becomes an instant red stop. This is the rule RBI, NPCI and SBI all state, enforced at the moment it matters.

3. **It explains why, in plain Hindi, Marathi and English.**
   It doesn't just say "Unsafe". It says *"This QR asks you to pay ₹4,999. Its note says 'refund', but you never pay to get a refund."* or *"This website was made 3 days ago and looks like sbi.co.in."* The wording is written for a shopkeeper or a parent, not a security engineer.

4. **Shopkeeper Mode catches swapped stickers *before* customers pay.**
   Sticker swaps hit Khajuraho, Aizawl, Hyderabad and Goa (one case ~₹49.68 lakh). A soundbox only reveals the swap through *silence*, after the money is gone, and no RBI or NPCI advisory tells merchants to check their own QR. A shopkeeper registers their QR once; a 2-second scan each morning says "✅ Still yours" or "🚨 This is NOT your QR".

5. **It understands every kind of QR code, not just links.**
   - AutoPay mandates disguised as small payments ("this sets up a recurring debit you cannot cancel")
   - `*401#` call-forwarding codes (DoT warning, Jan 2024)
   - fake "RailWire" Wi-Fi and open networks
   - APK and remote-access app installs (AnyDesk)
   - lookalike UPI handles (`@okaxisbank`, `@ybI`)
   - Bharat QR checksum tampering

6. **It catches brand-new scams that blacklists haven't seen yet.**
   Lookalike-letter domains, typosquats of 50+ Indian banks and government sites, domains registered days ago, and abused TLDs and free hosting. It also knows the new RBI-mandated **`.bank.in`** domain as a trust signal. Threat feeds (Google Safe Browsing, URLhaus, OpenPhish, PhishTank) are added on top. **If the internet drops, the heuristics still give a verdict.**

7. **Community-powered, private by design.**
   A "Report this QR" button stores only a **hash** of the code, so the next person sees *"⚠ Reported 12 times by other users"*. India's fraud databases (DoT FRI, I4C Suspect Registry) are closed to the public; QR Shield gives citizens their own. The destination is **never opened on your phone**: all analysis runs server-side with SSRF-safe redirect expansion.

## Honest boundaries (say these if asked, because judges respect it)

- We **can't verify NPCI's QR signature**, because the keys are only available to banks and payment apps. We show "signature present/absent", never "verified".
- We **can't see the bank-registered name** behind a UPI ID. We compare the QR's name to the UPI ID and tell you to check the name your UPI app shows.
- QR Shield works *alongside* your UPI app's own checks, *before* you open it. It does not replace them.
