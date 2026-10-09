# QR Shield: Demo Script

## Before the demo (checklist)
- Start the server: `uvicorn … --port 8000`. Run `demo/verify_demo.py`; it must print **ALL PASS**.
- Phone open on the tunnel URL and added to the home screen. Language set to EN.
- Printed demo sheet (`/demo/sheet` → Print). A second phone or a laptop tab is a fallback.
- In the Shop tab, **don't** register yet. You'll do it live.

## 1-minute pitch

> India runs on QR codes: 24 billion UPI payments a month and 73 crore QR codes. QR-code fraud cases rose 2.7× in two years. Since NPCI shut down P2P collect requests last October, a scammer's main trick is getting you to scan and pay.
>
> RBI, NPCI and the police all say "don't scan unknown QRs". But nobody gives people a tool to check one. Existing scanners just match links against a blacklist. They don't understand UPI.
>
> **QR Shield** reads the QR *before* your payment app opens. It tells you, in English, Hindi or Marathi, exactly what will happen: "You are about to PAY ₹4,999 to Amazon Refund Dept." Then it explains *why* that's a scam.
>
> It catches lookalike UPI IDs, AutoPay traps, fake bank sites, dangerous app downloads and call-forwarding codes. It has a Shopkeeper Mode that catches swapped stickers before customers pay. And it still works if the internet drops.

## 3-minute live demo

| Time | Do | Say |
|---|---|---|
| 0:00 | Scan **S2** (kirana QR) | "A normal shop QR is green. Notice it still says *you PAY Ramesh Kirana Store*." |
| 0:20 | Tap the **Receiving money** chip, scan **S2** again | "Now I'm an OLX seller who was told 'scan to receive'. Same QR: instant red. Scanning a QR never gives you money. That's RBI's own rule, built into the app." |
| 0:45 | Chip back to *Just checking*. Scan **D1** (refund) | "Fake customer care. ₹4,999 locked, 'refund' in the note, Amazon's name on a personal UPI ID, and 6 community reports." Tap **हिं**, then **मरा**: "The same reasons in Hindi and Marathi, for my parents." |
| 1:20 | Scan **D2** | "@okaxisbank looks real, but Google Pay's handle is @okaxis. We know all 181 real UPI handles." |
| 1:35 | Scan **D3** | "This says 'cashback'. It's actually a 10-year AutoPay you can't cancel." |
| 1:50 | Scan **D6** | "This looks exactly like onlinesbi. The 'і' is Cyrillic. We use Unicode's own confusables standard to catch it." |
| 2:05 | Scan **D7** | "A short link. We follow it safely on *our* server, never on your phone. It lands on a 5-day-old HDFC lookalike." |
| 2:20 | Shop tab: register **SH1**, then verify **SH2** | "Shopkeeper Mode: register your QR once. Someone pastes a sticker overnight, as in Khajuraho in 2025, and a 2-second scan in the morning shows a red screen." |
| 2:45 | Optional: scan **D10** | "And a QR with `*401#` would forward your bank OTP calls. Blocked." |
| 2:55 | Close | "Explainable, multilingual and UPI-aware: a QR scanner built for how India actually pays." |

## If something goes wrong
- **The camera won't start.** Use **Upload QR image** with a photo of the sheet, or paste the payload under *Paste QR text*.
- **No internet.** DEMO_MODE results don't need it. Say: "the heuristics work offline."
- **Judge asks "is this real data?"** Malicious samples use reserved `.test` domains, so we never point at live phishing sites. The same rules run on real URLs; scan any real link to show it.

## Likely judge questions
- **Can you verify NPCI signatures?** No. The keys go only to PSPs, so we say "signature present" and never "verified".
- **Can you see the account holder's real name?** Not without PSP access. We compare the QR's name with the UPI ID and tell users to check the name their UPI app shows.
- **Why not ML?** Rules are explainable, reproducible and work offline. ML scoring is a later phase.
- **False positives?** Unknown UPI handles only get a soft warning. Official domains, `.bank.in` and `.gov.in` reduce the score.
