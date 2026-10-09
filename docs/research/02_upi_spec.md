# 02: UPI deep link / QR format, UPI handles, and VPA rules

Research date: 2026-10-09. Every claim has a URL. Where a source is secondary (a vendor doc, blog or mirror), it is marked. Where we could not verify something, it is marked **UNVERIFIED**. All of these are collected in [Uncertainties](#8-uncertainties).

---

## 0. TL;DR for the scanner

- A UPI QR is a URI string: `upi://pay?pa=...&pn=...&...`. Scanning it makes the scanner the **payer**. Nobody ever needs to scan a QR or enter a UPI PIN to **receive** money. RBI and ICICI both say this in writing (§3).
- Only `pa` (payee VPA) and `pn` (payee name) are mandatory in every mode. `am` is optional in static QRs and mandatory in dynamic ones. `cu` can only be `INR`. In the spec's own examples, `mc=0000` marks a P2P (person) payee (§1).
- The 1.6 spec defines a signed QR (`sign=` holding a Base64 RSA-SHA256 signature over the rest of the URI). A scanner cannot verify it offline, because the public keys are only distributed to PSP servers through NPCI APIs (§1.4).
- NPCI's official list of TPAP handles (third-party payment apps such as PhonePe and Google Pay), plus the PPI (wallet) and IPO-app lists, gives about 135 handles. Aggregators add bank-app handles, for about 175 in total (§5). An **unknown handle should be a soft warning, not a hard failure**: merchant VPAs issued by acquiring banks can use handles that are on no public list.
- P2P collect requests were banned by NPCI from 2025-10-01. Collect has never been a QR flow: a QR is always a *pay* intent (§3.2).

---

## 1. The NPCI UPI Linking Specification

### 1.1 Sources

| Doc | Status | URL |
|---|---|---|
| **NPCI "UPI Linking Specifications Version 1.6 (Draft)", Nov 2017** ("Common URL Specifications for Deep Linking and Proximity Integration"), 14 pp. **Best available full text.** | Third-party mirror of an NPCI PDF, marked "Draft" | https://www.labnol.org/files/linking.pdf |
| Same document | Mirror | https://studylib.net/doc/27265723/upi.linking.specs-ver-1.6 |
| Parameter table, likely from v1.5.x (fewer params) | Community wiki | https://github.com/bgagan911/RandomDocs/wiki/NPCI-UPI---Specifications-for-Deep-Linking |
| NPCI Circular OC 37 (1 Nov 2017): apps must comply with "UPI Deep Linking Specs 1.5.1" | NPCI (could not fetch, NPCI blocks bots; content via search snippet) | https://www.npci.org.in/PDF/npci/upi/circular/2017/Circular%20on%20Non-compliance%20of%20UPI%20apps%20to%20Deeplinking%20specs%20Circular%2037-%201.11.2017.pdf |
| NPCI Circular OC 28 (Aug 2017): "UPI linking specs for Bharat QR_V1.5.2" (PSP apps must read UPI credentials from Bharat QRs) | NPCI (same) | https://www.npci.org.in/PDF/npci/upi/circular/2017/Circular28-Scanning-integrated-Bharat-through-UPI.pdf |
| Initiation-mode code table (newer than 1.6) | Vendor (Juspay) | https://juspay.io/in/docs/upi-consumer-stack/docs/resources/initiation-mode |
| Purpose code table | Vendor (Juspay) | https://juspay.io/in/docs/upi-consumer-stack/docs/resources/purpose-code |

We found no public copy of a linking spec newer than 1.6. Newer parameters (`ver`, `purpose`, `qrMedium`, `gstBrkUp`, `invoiceNo`, `QRexpire`, `mandate` params) are known only from PSP and PG docs (PSP = payment service provider bank, PG = payment gateway). See §1.3.

### 1.2 URI format

The spec, §1.2 (https://www.labnol.org/files/linking.pdf) says:

```
upi://pay?parm-name=param-value&param-name=pram-value&...
```

Rules from the same spec:

- All PSP apps "must mandatorily implement listening to 'UPI' links" for QR, intent, NFC, BLE, UHF and other channels.
- When reading a QR or intent, "all parameters must be read and passed to online message". If a tag is not present, "it can be dropped or passed as null".
- **Null values**: `mam=null` and similar must be treated as null. The literal string "null" must not be sent.
- **Spaces** must be encoded as `%20` (RFC 3986 §2.1). For backward compatibility, PSPs should also accept a bare `%` as a space. **This means a parser must tolerate `%` followed by non-hex characters.**
- `url` values "shall begin with http or https".
- `sign`, "shall be last tag of the intent".
- Static vs dynamic: "a real small one person shop could simply print a static QR code containing the payee address and name". With a static QR, the customer enters the amount.

### 1.3 Parameter table

M = mandatory, C = conditional, O = optional. "1.6" means the field is in the 1.6 spec table (https://www.labnol.org/files/linking.pdf). "Vendor" means it is seen only in PSP or PG docs (sources inline).

| Param | Meaning | Static / Dynamic | Format and constraints | Source |
|---|---|---|---|---|
| `pa` | Payee VPA (maps to `Payee->addr`) | **M / M** | String, `handle@psp`. The spec gives no length or charset rules (see §6). | 1.6 |
| `pn` | Payee name (`Payee->name`) | **M / M** | String, percent-encoded. Note: the name **in the QR** is chosen by whoever generated the QR. The payer's app normally displays the name returned by the bank lookup. | 1.6 |
| `mc` | Payee merchant code, i.e. the MCC (merchant category code) (`Payee->mcc`) | O / O | String. "If present then needs to be passed as it is." Spec examples use **`mc=0000` for a P2P / PSP-app-generated QR** ("bivekrath@npci with mcc 0000") and `9999` for a test merchant. Real merchant examples: `5411` (grocery), `5811` (restaurant), `5311`. 4-digit ISO 18245 MCC. | 1.6, [Razorpay](https://razorpay.com/docs/api/qr-codes/image-content/entity), [PhonePe DQR](https://developer.phonepe.com/offline-integration/dynamic-qr-solution/dqr-init-api) |
| `tid` | Transaction ID (`Txn->id`) | O / O | "This must be PSP generated id when present". Merchants may get it from their PSP. Passed as-is. | 1.6 |
| `tr` | Transaction reference ID (`Txn->refId`): order no., bill ID, booking ID, etc. | O / **C** | "Mandatory for Merchant transactions and dynamic URL generation." | 1.6 |
| `tn` | Transaction note (`Txn->note`) | O / O | Free text, a "short description". **This is attacker-controlled, so it is a prime field for social-engineering text such as "refund" or "KYC".** | 1.6 |
| `am` | Amount (`Payee->Amount->value`) | O / **M** | "Transaction amount in decimal format. If 'am' is not present then field is editable." The spec does not require exactly 2 decimals: its own examples use `am=10`, while PhonePe uses `am=10.00`. Recommended validation: `^\d+(\.\d{1,2})?$`, > 0. | 1.6, [PhonePe DQR](https://developer.phonepe.com/offline-integration/dynamic-qr-solution/dqr-init-api) |
| `mam` | Minimum amount (`Txn->Rules->MINAMOUNT`) | O / C | If `mam` is absent, `null` or empty, **the amount field must NOT be editable**. If present, the amount is editable but cannot go below `mam` (UPI declines it). | 1.6 §1.4 note 2 |
| `cu` | Currency (`Payee->Amount->curr`) | O / O | "Currently ONLY 'INR' is the supported value." | 1.6 |
| `url` | Reference URL (`TxnrefUrl`): bill, invoice, ticket, or digital-goods delivery | O / O | "MUST BE related to the particular transaction and MUST NOT be used to send unsolicited information". Must start with `http` or `https`. PSP apps show it as "view invoice" (the "Bill in the Box" feature). | 1.6 |
| `mode` | Transaction initiation mode (`Txn initiationMode`) | M / M (per the 1.6 table, **but real static P2P QRs from GPay, PhonePe and others usually omit it**) | 2 digits. Values in §1.5. | 1.6, Juspay |
| `sign` | Base64 digital signature | M / M per the 1.6 table (in practice it appears only in "secure" QRs and intents) | Base64. Must be the last parameter. See §1.4. | 1.6 |
| `orgid` | Org ID of the signer | M / M per the 1.6 table | 6 digits. `000000` = merchant-generated, signed with the merchant key. Any other value = the PSP app's org ID. Note: the spec's §2 examples also contain the 5-digit `orgid=00000`, which is inconsistent. A Juspay international example uses `orgId=1800420001` (10 digits, capital I). | 1.6, [Juspay QR validation](https://docs.juspay.io/upi-consumer-stack/docs/advance-features/qr-validation) |
| `mid` | Merchant ID | O / O | Max 20 characters. Echoed for reconciliation. | 1.6 |
| `msid` | Merchant store ID | O / O | Max 20. | 1.6 |
| `mtid` | Merchant terminal ID | O / O | Max 20. | 1.6 |
| `Query` | Reserved | O / O | "future use", JSON, max 99. | 1.6 |
| `ver` | QR spec version | n/a | Seen as `ver=01` in a Juspay international (`upiGlobal://`) sample. **Meaning UNVERIFIED.** | [Juspay](https://docs.juspay.io/upi-consumer-stack/docs/advance-features/qr-validation) |
| `purpose` | Purpose code | n/a | 2 characters. See §1.6. Seen as `purpose=00` in PhonePe DQR and `purpose=11` (Global UPI) in Juspay. | [Juspay purpose codes](https://juspay.io/in/docs/upi-consumer-stack/docs/resources/purpose-code) |
| `qrMedium` | Medium on which the QR is displayed | n/a | Seen as `qrMedium=04` (Juspay) and `qrMedium=06` (PayU, Adyen). **Value meanings UNVERIFIED.** | [Juspay](https://docs.juspay.io/upi-consumer-stack/docs/advance-features/qr-validation), [PayU](https://docs.payu.in/reference/print-invoice-qr-api) |
| `QRexpire` / `qrexpire`, `QRts` | QR expiry and timestamp | n/a | Seen in mandate deeplinks (`qrexpire` maps to `TxnQRExpireTs`). **Exact format UNVERIFIED.** | [Juspay mandate intent](https://juspay.io/in/docs/upi-merchant-stack/docs/mandates/register-mandate-intent) |
| `gstBrkUp` | GST breakup | n/a | e.g. `GST:1.0\|CGST:0.25\|SGST:0.25\|IGST:0.25\|CESS:0.25\|GSTIncentive:1.0\|GSTPCT:10.0` (PhonePe) or `GST:40%7CSGST:20%7CCGST:20%7CCESS:0` (Razorpay) | [PhonePe DQR](https://developer.phonepe.com/offline-integration/dynamic-qr-solution/dqr-init-api), [Razorpay](https://razorpay.com/docs/api/qr-codes/image-content/entity) |
| `invoiceNo`, `invoiceDate`, `invoiceName`, `gstIn` | Invoice data for GST B2C dynamic QRs | n/a | `invoiceDate` is ISO-8601 with offset, e.g. `2021-09-29T13:42:35+05:30`. `gstIn` is a 15-character GSTIN. | Same as above. Background: [GST e-invoice B2C QR](https://einvoice6.gst.gov.in/content/e-invoice-b2c-qr-code-applicability-penalty-contents-generation-exemption-list/) |
| `cc`, `bCurr` | Country code and base currency (international QR) | n/a | Only in `upiGlobal://pay` samples. | [Juspay](https://docs.juspay.io/upi-consumer-stack/docs/advance-features/qr-validation) |

### 1.4 How a signed QR (`sign=`) works (spec §1.3)

From https://www.labnol.org/files/linking.pdf:

1. **Merchant-initiated.** The merchant (or its acquiring bank) generates an RSA key pair. The acquirer uploads the public key to UPI with the **Manage VAE API** (VAE = verified address entry, NPCI's registry of verified merchant addresses). The merchant signs the **entire URI string except `&sign=`** with "SHA256 with RSA" (the spec writes "SHA256withRSA512"), Base64-encodes the result and appends `&sign=<b64>` as the last tag. These intents use `orgid=000000`. In the spec's own merchant example, which is a mobile intent, `mode=05`.
2. **Customer- or PSP-initiated** (P2P QRs generated by PSP apps). The PSP signs with its own key, which is shared with NPCI offline and published through the **List Keys API**. `orgid` = the PSP's org ID. The spec's example is `mode=02` (secure QR) with `mc=0000`.
3. **Verification by the payer PSP.** The PSP downloads all keys daily (6 AM recommended) and caches them. It looks up the key by `orgid` + payee VPA (merchant) or by `orgid` (PSP), then verifies the signature over the URI minus `&sign=`.
4. **Actions**:
   - (a) If verification succeeds, "the application should bypass passcode page".
   - (b) If it fails, decline with "intent is tampered or corrupt".
   - (c) If there is no signature, "show warning message ... 'source of intent could not be verified'".

**Implication for QR Shield:** we **cannot** verify signatures, because the keys come from NPCI APIs that only PSPs can reach. We can (i) detect whether `sign` is present and is well-formed Base64, (ii) check that it is the last parameter, and (iii) check that `orgid` and `mode` are consistent (for example, `mode=02/05` without `sign` is suspicious). A UPI 2.0 explainer describes signed QR as letting users "check the authenticity of merchants" (https://journalsofindia.com/upi-2-0/?print=pdf, secondary).

Related verified-merchant UX: SEBI's `@valid` handles (e.g. `abc.brk@validhdfc`, `xyz.mf@validicici`) show a **thumbs-up inside a green triangle** in UPI apps (SEBI and NPCI, 2025; https://www.moneylife.in/article/sebi-launches-at-valid-upi-handles-and-checking-tool-to-curb-payment-frauds/78469.html, https://teamleaseregtech.com/updates/article/44225/npci-issued-standardized-upi-ids-with-validbankpsp-handle-mandated-for/, which covers NPCI/UPI/OC/217/2025-26).

### 1.5 `mode` (initiationMode) values

The two sources disagree on 15–18. The 1.6 draft is older. Juspay's table reflects later NPCI circulars, but it is a secondary source.

| Code | 1.6 draft (2017) | Juspay table (current, secondary) |
|---|---|---|
| 00 | Default txn | Default |
| 01 | QR Code | QR Code |
| 02 | Secure QR Code | Secure QR Code |
| 03 | (not listed) | **Bharat QR** |
| 04 | Intent | Intent |
| 05 | Secure Intent | Secure Intent |
| 06 | NFC | NFC |
| 07 | BLE | BLE |
| 08 | UHF | UHF |
| 09 | n/a | Aadhaar |
| 10 | n/a | SDK |
| 11 | n/a | UPI Mandate (execution only) |
| 12 | n/a | FIR (Foreign Inward Remittance) |
| 13 | n/a | Static Secure QR Mandate (offline) |
| 14 | n/a | Restricted |
| 15 | **SEBI** | **Dynamic QR Code (offline)** |
| 16 | future use | Dynamic Secure QR Code (offline) |
| 17 | future use | Dynamic Secure QR Mandate (offline) |
| 18 | future use | ATM QR (dynamic) |
| 19 | n/a | Online static QR |
| 20 | n/a | Online static secure QR |
| 21 | n/a | Online static QR mandate |
| 22 | n/a | Online dynamic QR |
| 23 | n/a | Online dynamic secure QR |
| 24 | n/a | Online dynamic secure QR mandate |

Sources: https://www.labnol.org/files/linking.pdf, https://juspay.io/in/docs/upi-consumer-stack/docs/resources/initiation-mode

**Note:** the brief's suggested "15 = BharatQR" is wrong according to both sources. Bharat QR is 03 (Juspay), and 15 is either SEBI (1.6) or offline dynamic QR (Juspay).

### 1.6 `purpose` codes (Juspay, secondary)

Values seen on https://juspay.io/in/docs/upi-consumer-stack/docs/resources/purpose-code:

- 00 Default
- 01 SEBI (IPO)
- 02 AMC
- 03 Travel
- 04 Hospitality
- 05 Hospital
- 06 Telecom
- 07 Insurance
- 08 Education
- 09 Gifting
- 10 BBPS
- 11 Global UPI
- 12/13 ATM QR
- 14 SI (standing instruction / mandate)
- 15 Corporate disbursement
- 20 B2B
- 25 RBI Retail Direct
- 41–50 UPI Lite flows
- 59 Full delegation
- 60–66 International
- 71/82 UPI Lite Autopay
- 76/77 SBMD (single-block multiple-debit)
- 87 Delegate
- 92 e-Rupee (CBDC)
- BH IoT
- AZ Autopay interop
- BR Bioauth
- BF FX retail via BBPS

For a consumer scanner, **`purpose=14`, `purpose=AZ`, or any mandate-type purpose code in a scanned QR is a red flag**, because it means a recurring debit authorization rather than a one-time payment.

### 1.7 Other schemes: `upi://mandate`, `upi://collect`, `upiGlobal://`

- **`upi://mandate?...`** is used for UPI AutoPay registration via intent or QR. It is not in the 1.6 spec. Parameters come from Juspay (https://juspay.io/in/docs/upi-merchant-stack/docs/mandates/register-mandate-intent), with some marked mandatory:
  - `amrule` (MAX or FIXED), `am`, `validitystart` and `validityend` (DDMMYYYY in the examples), `recur` (`ONETIME`, `DAILY`, `WEEKLY`, `MONTHLY`, `ASPRESENTED`, etc.), `purpose`, `mode`, `txnType=CREATE`. These are mandatory.
  - Plus `recurtype`, `recurvalue`, `rev` (revocable `Y`/`N`), `block`, `fam` (first debit amount), `mn` (mandate name), `orgid`, `qrexpire`, `qrmedium`, `pa`, `pn`, `mc`, `tr`, `tid`, `tn`, `cu`.
  - `amrule` semantics: https://docs.decentro.tech/reference/payments_api-upi-autopay-create-mandate
  - Recurrence examples: https://docs.setu.co/payments/umap/mandates/recur/create
  - **Scanner rule: any `upi://mandate` is high-risk to a casual user.** It authorizes repeated debits up to `am` until `validityend`. `rev=N` (non-revocable) is an extra flag.
- **`upi://collect`**: we found **no specification** for a `upi://collect` URI. Collect is a server-side "pull" flow: the payee's PSP sends a request to the payer's VPA through the NPCI network (spec §1, https://www.labnol.org/files/linking.pdf: "...instead of a collect request via the PSP network"). **A QR cannot carry a collect request.** If you see `upi://collect` in a QR, treat it as anomalous (UNVERIFIED whether any app handles it).
- **`upiGlobal://pay?...`** is the international QR variant. It carries `ver`, `mode`, `purpose=11`, `orgId`, `cc`, `bCurr`, `qrMedium` and `sign` (https://docs.juspay.io/upi-consumer-stack/docs/advance-features/qr-validation). Also note that NPCI disabled "QR share & pay" for international P2M (person-to-merchant) and capped domestic share-and-pay to non-verified offline merchants at ₹2,000 (circular dated 8 Apr 2025, via https://caalley.com/news-updates/indian-news/no-more-international-upi-transactions-via-qr-share-pay-says-npci).
- **Other schemes.** Android intent filters also see `tez://upi/pay`, `phonepe://pay` and `paytmmp://pay`. These are app-specific schemes that we did not research. A plain `upi://pay` is what every PSP app must handle (1.6 §1.2).

### 1.8 Bharat QR relation

- BharatQR was developed by NPCI, Mastercard and Visa (launched 2016–17). It is interoperable across RuPay, Mastercard, Visa and Amex, and also accepts UPI (https://en.wikipedia.org/wiki/BharatQR).
- It is an EMVCo merchant-presented TLV string beginning `000201...`, not a `upi://` URI. Tags 26–51 are merchant-account templates (https://mvallim.github.io/emv-qrcode/docs/EMVCo-Merchant-Presented-QR-Specification-v1.1.pdf).
- One library labels **tag 26 as the "UPI VPA Template" with RuPay RID `A000000524`** (https://pkg.go.dev/github.com/hussainpithawala/emv-merchant-qr-lib/emvqr). **The sub-tag that holds the VPA is UNVERIFIED.**
- NPCI circular OC 28 (2017) pointed to "UPI linking specs for Bharat QR_V1.5.2" so UPI apps can read the UPI credentials embedded in Bharat QRs (search snippet of the NPCI PDF above).
- A dev handbook says all BharatQR codes generated after 15 Sep 2017 must embed a UPI VPA (https://hasgeek.gitbook.io/50p-handbook/upi-bharat-qr-integration, secondary).
- **Scanner implication:** also parse EMVCo strings starting `000201`, extract the VPA from tag 26 (or other templates 26–51), and run the same VPA checks.

---

## 2. Sample legitimate URIs (verbatim from official or vendor docs)

```text
# NPCI spec 1.6, hyperlink/QR sample (P2P-style, mc=0000; note sign= is NOT last here despite spec rule)
upi://pay?pa=nadeem@npci&pn=nadeem%20chinna&mc=0000&tid=cxnkjcnkjdfdvjndkjfvn&tr=4894398cndhcd23&tn=Pay%20to%20mystar%20store&am=10&mam=null&cu=INR&url=https://mystar.com/orderid=9298yw89e8973e87389e78923ue892&mode=00&sign=aagshd4542bdhhvdshsbvqfqttsvsvsbsjn&orgid=00000&mid=1234&msid=3432&mtid=1212

# NPCI spec 1.6, signed merchant intent (mode=05, orgid=000000)
upi://pay?pa=bivek@npci&pn=bivek%20rath&mc=9999&tid=cxnkjcnkjdfdvjndkjfvn&tr=4894398cndhcd23&tn=Pay%20to%20mystar%20store&am=10&mam=null&cu=INR&url=https://mystar.com&mode=05&orgid=000000&mid=1234&msid=3432&mtid=1212&sign=gynybu6K6ozUrHSySDhBK6rfiRE+VBMLnsxs3d7B/ddeGu43M6sxaY33ZVE4Utc4E1kbCcjgYhfJCUeYLdFp/UKckByYang6C99L337zp4/2mfYyEVg2E+6+G9Y3+RaGYA2iz9cQU43+O0esOuDcc5crmQOLoD+X22D21Dl5IKI=
```
Source: https://www.labnol.org/files/linking.pdf

```text
# Razorpay QR (merchant, dynamic, grocery MCC 5411)
upi://pay?pa=dmart.razorpay@hdfcbank&pn=TestAccount&tr=RZPGT5viB4WHeoUuuqrv2&tn=TestAccountRaftarSoft&am=100&cu=INR&mc=5411

# Razorpay QR with GST invoice params (MCC 5811 restaurant)
upi://pay?pa=rzr.qrfoodapp54462255833@icic&pn=FoodApp&tr=RZPI39xhFWWLO4wjMqrv2&tn=PaymenttoFoodApp&cu=INR&mc=5811&am=3&invoiceNo=INV001&invoiceDate=2021-09-29T13:42:35+05:30&invoiceName=GauravKumar&gstIn=22AAAAA0000A1Z5&gstBrkUp=GST:40%7CSGST:20%7CCGST:20%7CCESS:0
```
Source: https://razorpay.com/docs/api/qr-codes/image-content/entity. Note the `@icic` handle, which is **not** on any public handle list. This is evidence that acquirer merchant handles exist outside the TPAP list.

```text
# PhonePe offline Dynamic QR (DQR) — mode=04, purpose=00, mam=am (fixed amount)
upi://pay?pa=MERCHANTUAT@ybl&pn=Test%20MerchantTT&am=10.00&mam=10.00&tr=TX32321849644234&tn=Payment%20for%20TX32321849644234&mc=5311&mode=04&purpose=00&gstBrkUp=GST:1.0|CGST:0.25|SGST:0.25|IGST:0.25|CESS:0.25|GSTIncentive:1.0|GSTPCT:10.0&invoiceNo=...&invoiceDate=2021-06-29T15:43:54+05:30&invoiceName=...
```
Source: https://developer.phonepe.com/offline-integration/dynamic-qr-solution/dqr-init-api

```text
# Juspay instant-delivery deep link
upi://pay?tr=mandate_juspay-TEST_ORDER-1&mc=516&pa=test@ybl&pn=test&am=1.00&cu=INR
```
Source: https://juspay.io/upi-qr-code/docs/scan--pay/instant-delivery-qr. Note `mc=516`, which is 3 digits. Real-world `mc` values are not always 4 digits, so treat a non-4-digit `mc` as a soft warning only.

```text
# Typical static P2P QR from a consumer app (illustrative of the minimal format the spec allows)
upi://pay?pa=someone@oksbi&pn=Some%20One
```
Basis: the spec says a static QR may hold just address and name (https://www.labnol.org/files/linking.pdf). Apps' static QRs typically carry no amount (https://labnol.org/dynamic-upi-qr-codes-220426).

### Merchant VPA patterns seen in the wild

| Pattern | Status |
|---|---|
| `rzr.<name><digits>@icic`, `<name>.razorpay@hdfcbank` (Razorpay) | Verified in Razorpay docs (above) |
| `MERCHANTUAT@ybl` (PhonePe test merchant) | Verified in PhonePe docs (above) |
| PhonePe Business static QR: `Q<digits>@ybl` | **UNVERIFIED** (common observation, no doc found) |
| Paytm merchant: `paytmqr<alnum>@paytm` (or `@ptys`) | **UNVERIFIED.** One forum report says Paytm merchant IDs are 20-character mixed case (https://wordpress.org/support/?p=16886952). |
| BharatPe merchant: `BHARATPE.<digits>@fbpe` (or `@unitype`) | **UNVERIFIED.** The only evidence is a consumer complaint mentioning `BHARATPE.…@fbpe` (https://www.consumercomplaints.in/bharatpe-unauthorised-upi-id-created-by-bharatpe-user-with-my-phone-number-c3045227). BharatPe's *consumer* TPAP handle is `@bpunity` (NPCI list). |
| SEBI intermediaries: `<name>.brk@valid<bank>`, `<name>.mf@valid<bank>` | Verified (SEBI PR 64/2025 via https://www.moneylife.in/article/sebi-launches-at-valid-upi-handles-and-checking-tool-to-curb-payment-frauds/78469.html; Razorpay https://razorpay.com/docs/payments/payments/payment-methods/upi) |

---

## 3. Semantics for user warnings

### 3.1 Scanning means paying. PIN is never needed to receive.

- **RBI** ("Consumer Awareness – Cyber Threats and Frauds", 28 Jan 2022) says: *"Transactions involving receipt of money do not require scanning barcodes / QR codes or entering MPIN."* https://www.rbi.org.in/scripts/BS_PressReleaseDisplay.aspx?prid=53185
- **ICICI Bank** safe-banking page says: "You need to enter PIN only for sending money", "Do not 'Pay' or enter your UPI PIN to receive money", "Never scan QR code for receiving payments", and "QR code needs to be scanned only to make payments". https://www.icici.bank.in/online-safe-banking/mobile-banking
- **NPCI spec**: the QR flow shows the payer a pre-filled pay screen. The payer "verifies the info on screen and click pay to complete the payment" (1.6 §1.1, https://www.labnol.org/files/linking.pdf).
- RBI's BE(A)WARE booklet (Mar 2022) also covers these frauds: https://website.rbi.org.in/web/rbi/-/press-releases/be-a-ware-a-booklet-on-modus-operandi-of-financial-frauds-53372
- **Nuance**: a PIN is also used for balance enquiry and UPI Lite top-up. UPI Lite pays small amounts without a PIN (https://www.npci.org.in/product/upi, via search). So "PIN means debit" is not literally always true, but **"PIN to receive" is always false.**

### 3.2 Is there a "collect request via QR"? No.

- **Pay (push)** is initiated by the payer: QR, intent or entering a VPA. **Collect (pull)** is initiated by the payee. The payee's PSP sends a request through the NPCI switch to the payer, who approves or declines it with their UPI PIN. BHIM says the receiver of the request "can pay or decline the collect request by authenticating it with their UPI PIN" (https://www.bhimupi.org.in/faq-s). The spec contrasts intent and QR with "a collect request via the PSP network" (https://www.labnol.org/files/linking.pdf).
- So a QR is always a **pay** flow. The QR scam and the collect scam are two different routes to the same lie ("approve this to receive money").
- **P2P collect banned**: NPCI circular dated 29 Jul 2025 says "by October 1, 2025 UPI P2P collect shall not be allowed to be processed in UPI". Merchant collect continues (https://www.outlookmoney.com/banking/npci-to-end-upi-p2p-collect-requests-from-october-1-to-reduce-fraud, https://www.businesstoday.in/amp/personal-finance/banking/story/npci-to-tighten-upi-rules-peer-to-peer-collect-feature-to-end-in-october-489244-2025-08-13).
- **Merchant collect is also mostly deprecated.** Razorpay says the UPI Collect flow is deprecated from 28 Feb 2026 "according to NPCI guidelines". Exceptions remain for MCC 6012/6211 (IPO and secondary market), iOS and mobile web, mandate execute/modify/revoke, eRupi, and cross-border (https://razorpay.com/docs/payments/payment-gateway/s2s-integration/payment-methods/upi/collect/).
- **Warning copy suggestion:** "Scanning this QR will SEND ₹X from your account to <pn>. You never need to scan a QR or enter your UPI PIN to receive money. (Source: RBI)"

---

## 4. Risk signals a scanner can compute

The weights below are suggestions. Each signal cites its basis.

### 4.1 Structural and malformed (high confidence)

| Signal | Why | Severity |
|---|---|---|
| Scheme is not `upi` (e.g. `upi:/pay`, `UPI://Pay`, `upi://pay/`, homoglyphs) or the host is not `pay`/`mandate` | Spec format §1.2. Case-insensitive match is OK, but flag lookalikes. | Med–High |
| `pa` missing, empty, no `@`, multiple `@`, spaces, or illegal characters | `pa` is mandatory (1.6). VPA rules in §6. | High (invalid) |
| `pn` missing | Mandatory (1.6) | Med |
| Duplicate parameters (e.g. two `pa=` or two `am=`) | The spec defines single values. Different apps may pick the first or the last value, a known parsing-confusion trick (inference). | High |
| `cu` present and not `INR` | "Currently ONLY INR" (1.6). Exception: `upiGlobal://`. | High |
| `am` not matching `^\d+(\.\d{1,2})?$`, or ≤ 0, or containing commas or currency symbols | "decimal format" (1.6) | High |
| `mam` > `am` | Logically invalid (inference from 1.6 semantics) | Med |
| `url` not http(s), or not on the same domain as the merchant, or a shortener, `.apk`, or IP-literal | 1.6: must relate to the transaction, http/https only, no unsolicited info. A phishing vector. | High |
| `sign` present but not Base64, or not last; or `mode=02/05/16/23` with no `sign` | 1.6 §1.3 | Med |
| `upi://collect` or other unknown hosts | No collect URI spec. A QR cannot carry a collect request (§3.2). | High |
| Very long `tn`, or `tn` containing URLs or phone numbers | Social engineering | Med |

### 4.2 Semantic and social engineering

| Signal | Basis | Severity |
|---|---|---|
| **`upi://mandate`**, or `purpose` ∈ {14, AZ, 76, 77} or `mode` ∈ {11, 13, 17, 21, 24} | Recurring debit authorization (§1.6–1.7). Flag `rev=N` and a large `am` with `amrule=MAX` too. | **High** |
| `tn` or `pn` matches refund, cashback, prize, lottery, reward, KYC, "receive", "verify", "unlock", "electricity disconnect", "customs", "army", "OLX", "SBI/RBI/NPCI/Income Tax/Govt", job or task | RBI and ICICI guidance says receiving money never requires a scan or PIN (§3.1), and RBI lists KYC-update frauds (https://factly.in/explainer-rbi-releases-the-beaware-booklet-listing-the-common-modus-operandi-of-online-financial-fraud) | **High** |
| `pn` impersonates a bank, government or regulator (RBI, NPCI, SBI, "Customer Care", "Helpdesk", "Refund Dept") while `pa` is a consumer TPAP handle (`@ybl`, `@okaxis`, `@paytm`, …) | Real institutions collect through merchant or acquiring VPAs. SEBI-regulated entities use `@valid…` handles. | High |
| `pn` vs `pa` mismatch (e.g. `pn=Amazon` with `pa=rahul1998@ybl`). Use a token-overlap or fuzzy score. | The QR's `pn` is chosen by whoever generated the QR. The payer's app shows the name from the bank lookup, so a mismatch is a classic tell. | Med–High |
| **Prefilled `am` on a P2P-looking QR** (no `mc`, or `mc=0000`, and a personal-looking VPA, and an `am` the user did not agree to) | Static P2P QRs normally carry no amount (spec §1.1; https://labnol.org/dynamic-upi-qr-codes-220426). Fixed-amount P2P QRs are the core of "scan to receive ₹X" scams. | High |
| `mc` is a merchant code but the VPA looks personal (`firstname.lastname123@okhdfcbank`, a 10-digit mobile `@ybl`) | Merchant QRs come from acquirers or PGs with merchant-style VPAs (§2). Inference, not a spec rule. | Med |
| `mc` not 4 digits, or `mc` = 6211/6012 (securities/IPO) outside a broker context, or 7322 (debt collection), 4829 (money transfer), 6051 (quasi-cash/crypto), 7995 (gambling) | Unusual or high-risk MCCs (ISO 18245; inference) | Med |
| Amount > ₹1,00,000 on a P2P-looking QR, or any amount > ₹5,00,000 | The P2P limit stays at ₹1 lakh. ₹5 lakh/txn only for verified merchants in specific categories (NPCI circular 28 Aug 2025, effective 15 Sep 2025, via https://www.outlookmoney.com/banking/npci-changes-upi-transaction-limits-for-key-categories-from-september-15-2025-know-the-details) | Med–High |
| Handle not in the known list (§5) | It could be a typo-squat like `@okaxisbank`, `@ybI` (capital I), `@paytrn` or `@sbiupi`. Use Levenshtein ≤ 2 against the list. An exact unknown handle may still be a real acquirer handle (e.g. `@icic`), so make it a soft warning. | Med (High if it is a near-miss of a known handle) |
| VPA local part contains brand words (`sbi.refund@ybl`, `rbi-kyc@axl`, `amazon.cashback@ibl`) | Impersonation | High |
| Handle is a `@valid…` handle | Positive signal (SEBI and NPCI verified) | Lower risk |
| `sign` present with consistent `orgid`/`mode` | A weak positive signal (we cannot verify it) | Slightly lower risk |

---

## 5. UPI handle list

### 5.1 Sources and method

1. **NPCI "UPI 3rd Party Apps" table**: https://www.npci.org.in/what-we-do/upi/3rd-party-apps (live page returns 403 to scripts)
   - Archived copy, 25 Sep 2025: https://web.archive.org/web/20250925164656/https://www.npci.org.in/what-we-do/upi/3rd-party-apps (37 TPAPs)
   - More recent copy: data saved from NPCI's `all-members` API (https://www.npci.org.in/product/upi/all-members) in the GitHub repo `nishal21/upi-Down`, file `data/npci-upi-members.json`, last commit **2026-10-05** (66 TPAP rows, 37 PPI rows, 36 IPO-app rows, 109 PSP members): https://github.com/nishal21/upi-Down/blob/HEAD/data/npci-upi-members.json. This is a third-party mirror of NPCI data, which the README says was saved from the NPCI site via a browser.
2. **SEBI "List of mobile applications for using UPI in Public Issues"** (as on 07 Mar 2025), which matches NPCI's "UPI apps live on IPO": https://www.sebi.gov.in/sebiweb/other/OtherAction.do?doRecognisedFpi=yes&intmId=43
3. **Aggregators (lower confidence)**:
   - https://e-banking.in/lists/upi-apps-handles-banks/ ("updated 2 years ago")
   - https://www.chargebee.com/docs/payments/2.0/kb/billing/razorpay-upi-autopay-supported-applications-and-their-handles
   - https://upi.pe/upi-handles
   - https://github.com/BiswajeetRay7/UPI-INT ("upi handel list.txt")
   - https://en.wikipedia.org/wiki/List_of_UPI_Apps

**Conflict resolved in favour of NPCI:** `@ibl` is PhonePe on **ICICI Bank** (NPCI). upi.pe says IDFC, which is wrong.

### 5.2 Tier A: NPCI official TPAP list (third-party apps)

Snapshot from 2026-10-05 via the mirror; most entries are also in the 2025-09-25 Wayback copy.

| App | PSP bank | Handle(s) |
|---|---|---|
| Aditya Birla Capital Digital | ICICI | `abcdicici` |
| Amazon Pay | Axis / RBL / Yes | `apl`, `rapl`, `yapl` |
| Bajaj Finserv | Axis | `abfspay` |
| BharatPe | Unity SFB | `bpunity` |
| ChangeJar | Unity SFB | `jarunity` |
| Cheq (Jun 2026) | Axis | `cqaxis` |
| CRED | Yes / Axis | `yescred`, `axisb` |
| Curie Money | Yes | `yescurie` |
| FamApp by Trio | Yes | `yesfam` |
| Fave (Dec 2025) | Axis | `fvaxis` |
| Flipkart UPI | Axis | `fkaxis` |
| Freo | ICICI | `freoicici` |
| GoodScore (Jul 2026) | Axis | `gsaxis` |
| **Google Pay** | Axis / HDFC / ICICI / SBI | `okaxis`, `okhdfcbank`, `okicici`, `oksbi` |
| Groww | Yes | `yesg` |
| Hero FinCorp | Axis | `hfaxis` |
| IND Money | HDFC | `inhdfc` |
| JUMPP | Yes | `jpyes` |
| Jupiter Money | Axis | `jupiteraxis` |
| Kiwi | Axis | `goaxb` |
| KreditBee | Axis | `kbaxis` |
| Kredit.Pe | HDFC | `kphdfc` |
| MobiKwik | HDFC / NSDL | `ikwik`, `mbkns` |
| Money View | HDFC | `mvhdfc` |
| Multipl | Yes | `mlyes` |
| Navi | Axis / Yes | `naviaxis`, `nyes` |
| Novio | DCB | `nvdcb` |
| Lxme UPI | Axis | `lxaxis` |
| OneCard | Yes | `oneyes` |
| **Paytm** | Yes / HDFC / SBI / Axis | `paytm`, `ptyes`, `pthdfc`, `ptsbi`, `ptaxis` |
| **PhonePe** | Yes / ICICI / Axis | `ybl`, `ibl`, `axl` |
| POP UPI | Yes | `yespop` |
| Rediff | Axis | `rpaxis` |
| Refyne | Unity SFB | `rfunity` |
| Rio Money | RBL | `rmrbl` |
| Samsung Pay | Axis | `pingpay` |
| salaryse | Yes | `seyes` |
| Saathi (PayNearby) | Yes | `pnyes` |
| Scapia | Axis | `tlaxis` |
| Shriram One | HDFC | `shriramhdfcbank` |
| Snapmint | Yes | `smyes` |
| Stashfin | Unity SFB | `sfunity` |
| super.money | Yes | `superyes` |
| Tata Neu | ICICI / Axis | `tapicici`, `tnaxis` |
| TimePay | Cosmos Co-op | `timecosmos` |
| T Wallet (Telangana govt) | Axis | `axisbank` |
| **WhatsApp** | ICICI / Axis / HDFC / SBI | `waicici`, `icici`, `waaxis`, `wahdfcbank`, `wasbi` |
| ZET | RBL | `ztrbl` |

In the 2025-09-25 Wayback copy but missing from the 2026 mirror: Fi Money `fifederal` and Ultracash `idfcbank`. Treat both as legacy-valid.

### 5.3 Tier A2: NPCI PPI (wallet) apps

From the same NPCI dataset:

| PPI issuer / app | Handle |
|---|---|
| ICICI Pockets | `pockets` |
| IDFC First ₹UPI | `idfcpay` |
| Amazon Pay (wallet) | `amazonpay` |
| BHIM SpicePay | `spicepay` |
| OmniCard | `omni` |
| Dhani | `dhani` |
| Bajaj Finserv wallet | `bpaywallet` |
| Cheq (Transcorp) | `trans` |
| FamApp | `fam` |
| Fave (Pine Labs) | `pinelabs` |
| MobiKwik wallet | `mbk` |
| Digikhata | `digikhata` |
| QuikWallet | `liv` |
| Unimoni | `paymoni` |
| NYE (RapiPay) | `nye` |
| Citrus/PayU | `payu` |
| EbixCash | `ebixcash` |
| True Balance | `tbl` |
| Paul Pay | `paulpay` |
| Cashbook (Obopay) | `obopay` |
| PhonePe wallet | `phonepe` |
| Yes Pay Lite | `yesgo` |
| Mufinpay | `mufin` |
| Topay | `topay` |
| Payworld | `payworld` |
| TA one | `tapay` |
| PayZapp wallet | `pzw` |
| CRED wallet | `cred` |
| Jupiter wallet | `jupiter` |
| iMoney Pay | `imoney` |
| Zokudo | `zokudo` |
| Revolut India | `revolut` |
| Makash | `makash` |
| The Card Company | `thecardco` |
| CTRLPay (Mswipe) | `mswipe` |
| Consumer Choice Payments | `yourisg` |
| EnKash | `enkash` |

### 5.4 Tier B: Bank and other apps on NPCI/SEBI "UPI apps live on IPO"

Sources: https://www.sebi.gov.in/sebiweb/other/OtherAction.do?doRecognisedFpi=yes&intmId=43 and the NPCI dataset above.

| App | Handle(s) | Type |
|---|---|---|
| BHIM (NPCI) | `upi` | NPCI app |
| BHIM Baroda Pay | `barodampay` | Bank |
| BHIM PayWiz / IDBI GO Mobile+ | `idbi` | Bank |
| BHIM AUPay | `aubank` | Bank |
| BHIM Bandhan | `bandhan` | Bank |
| BHIM DLB / DhanSmart | `dlb` | Bank |
| BHIM IndusPay | `indus` | Bank |
| Indie (IndusInd) | `indie` | Bank |
| BHIM KBL | `kbl` | Bank |
| BHIM Lotza (Federal) | `federal` | Bank |
| BHIM PNB | `pnb` | Bank |
| BHIM SBI Pay | `sbi` | Bank |
| BHIM UCO | `uco` | Bank |
| Citi Mobile | `citi`, `citigold` | Bank |
| DBS digibank | `dbs` | Bank |
| Freecharge | `freecharge` | TPAP (Axis) |
| HSBC Simply Pay | `hsbc` | Bank |
| ICICI iMobile | `icici` | Bank |
| IndOASIS (Indian Bank) | `indianbank`, `allbank` | Bank |
| Kotak | `kotak` | Bank |
| Union Bank | `unionbankofindia`, `uboi`, `unionbank` | Bank |
| PayZapp (HDFC) | `pz` | Bank |
| SIB Mirror+ | `sib` | Bank |
| YES Pay Next | `yespay` | Bank |
| TMB mBank | `tmb` | Bank |
| Slice | `slc` | Bank (Slice SFB) |

### 5.5 Tier C: aggregator-only (lower confidence; likely valid, verify before hard-coding as "trusted")

| Handle | Bank / app per aggregator | Source |
|---|---|---|
| `hdfcbank` | HDFC Bank (MobileBanking, PayZapp, SmartHub) | e-banking.in, upi.pe |
| `axisbank` | Axis Bank (also NPCI for T Wallet) | e-banking.in |
| `yesbank` | Yes Bank | e-banking.in, upi.pe |
| `rbl` | RBL Bank | e-banking.in, upi.pe |
| `boi` | Bank of India | e-banking.in, chargebee |
| `cnrb` | Canara Bank | e-banking.in, chargebee |
| `centralbank` | Central Bank of India | e-banking.in |
| `mahb` | Bank of Maharashtra | e-banking.in |
| `iob` | Indian Overseas Bank | e-banking.in |
| `psb` | Punjab & Sind Bank | e-banking.in |
| `jkb` | J&K Bank | e-banking.in |
| `kvb` | Karur Vysya Bank | e-banking.in |
| `equitas` | Equitas SFB | e-banking.in |
| `finobank` | Fino Payments Bank | e-banking.in |
| `airtel` | Airtel Payments Bank (`mairtel` also reported) | e-banking.in; https://www.codeforbanks.com/fastag/banks-upi-handles/ |
| `jio` | Jio Payments Bank | e-banking.in |
| `csbpay` | CSB Bank | e-banking.in, Wikipedia |
| `scb`, `s2b` | Standard Chartered | e-banking.in |
| `jsb` | Janata Sahakari Bank | e-banking.in |
| `tjsb` | TJSB | e-banking.in |
| `dcb` | DCB Bank | e-banking.in |
| `kmbl`, `kaypay` | Kotak | e-banking.in |
| `myicici`, `zoicici` | ICICI (Mi Pay, Zomato) | e-banking.in |
| `hdfcbankjd`, `rmhdfcbank` | HDFC (Justdial, FinShell) | e-banking.in |
| `axisgo` | Axis (Ola) | e-banking.in |
| `sliceaxis` | Axis (slice, older) | e-banking.in, chargebee |
| `fbl` | Federal (CoinTab / older Fi) | e-banking.in, upi.pe |
| `nsdl` | NSDL Payments Bank | chargebee |
| `postbank` | India Post Payments Bank (DakPay) | chargebee |
| `barodamp`, `bob` | Bank of Baroda (older) | e-banking.in |
| `okhdfc` | Google Pay (HDFC, older) | upi.pe |
| `fifederal`, `idfcbank` | Fi Money, Ultracash | NPCI Wayback 2025 |
| `valid<bank>` family (e.g. `validhdfc`, `validicici`) | SEBI-verified intermediaries | SEBI PR via moneylife |
| `icic` | Seen in a Razorpay merchant QR example (acquirer handle) | Razorpay docs |

**Legacy handles of merged public sector banks** (probably no longer issued; may still appear on old printed QRs):

| Handle | Bank |
|---|---|
| `andb` | Andhra Bank |
| `denabank` | Dena Bank |
| `lvb` | Lakshmi Vilas Bank |
| `obc` | Oriental Bank of Commerce |
| `syndicate` | Syndicate Bank |
| `united`, `ubi`, `utbi` | United Bank of India |
| `vijb` | Vijaya Bank |

Source: https://e-banking.in/lists/upi-apps-handles-banks/

### 5.6 Paste-ready lists (lowercase, no `@`)

**Tier A, NPCI TPAP (67):**
```
abcdicici,apl,rapl,yapl,abfspay,bpunity,jarunity,cqaxis,yescred,axisb,yescurie,yesfam,fvaxis,fkaxis,freoicici,gsaxis,okaxis,okhdfcbank,okicici,oksbi,yesg,hfaxis,inhdfc,jpyes,jupiteraxis,goaxb,kbaxis,kphdfc,ikwik,mbkns,mvhdfc,mlyes,naviaxis,nyes,nvdcb,lxaxis,oneyes,paytm,ptyes,pthdfc,ptsbi,ptaxis,ybl,ibl,axl,yespop,rpaxis,rfunity,rmrbl,pingpay,seyes,pnyes,tlaxis,shriramhdfcbank,smyes,sfunity,superyes,tapicici,tnaxis,timecosmos,axisbank,waicici,icici,waaxis,wahdfcbank,wasbi,ztrbl
```

**Tier A2, NPCI PPI (37):**
```
pockets,idfcpay,amazonpay,spicepay,omni,dhani,bpaywallet,trans,fam,pinelabs,mbk,digikhata,liv,paymoni,nye,payu,ebixcash,tbl,paulpay,obopay,phonepe,yesgo,mufin,topay,payworld,tapay,pzw,cred,jupiter,imoney,zokudo,revolut,makash,thecardco,mswipe,yourisg,enkash
```

**Tier B, NPCI/SEBI IPO apps (handles not already above, 29):**
```
upi,barodampay,idbi,aubank,bandhan,dlb,indus,indie,kbl,federal,pnb,sbi,uco,citi,citigold,dbs,freecharge,hsbc,indianbank,allbank,kotak,unionbankofindia,uboi,unionbank,pz,sib,yespay,tmb,slc
```

**Tier C, aggregator/legacy (48: 39 aggregator handles + 9 legacy merged-bank handles):**
```
hdfcbank,yesbank,rbl,boi,cnrb,centralbank,mahb,iob,psb,jkb,kvb,equitas,finobank,airtel,mairtel,jio,csbpay,scb,s2b,jsb,tjsb,dcb,kmbl,kaypay,myicici,zoicici,hdfcbankjd,rmhdfcbank,axisgo,sliceaxis,fbl,nsdl,postbank,barodamp,bob,okhdfc,fifederal,idfcbank,icic,andb,denabank,lvb,obc,syndicate,united,ubi,utbi,vijb
```

That is 67 + 37 + 29 + 48 = **181 handles**. Also add the **prefix rule** `^valid[a-z]+$` for SEBI `@valid` handles.

**Bank vs TPAP classification:** Tier A = TPAP (non-bank apps riding on a sponsor bank). A2 = PPI wallets. Tier B and Tier C are mostly bank-own apps, except `freecharge` (TPAP, Axis), `upi` (NPCI's BHIM), `slc` (Slice SFB, a bank since 2025) and the merchant/aggregator handles noted above. NPCI's member list has 109 entities flagged "PSP" (banks plus PPI issuers) in the same dataset.

**Recommended scanner logic:**
- Exact match in A/A2/B is a known PSP.
- Exact match in C is "probably valid".
- Not found but within Levenshtein ≤ 2 of any known handle, or containing a known handle as a substring with extra characters (`okaxisbank`, `ybl-pay`, `paytm1`): **typo-squat warning (high)**.
- Otherwise: "unknown handle (could be a merchant acquirer handle)", a soft warning.

---

## 6. VPA format rules

No primary NPCI document we could access states a formal grammar. Here is the evidence:

| Rule | Source |
|---|---|
| Format `username@handle`, exactly one `@` | BHIM FAQ (default `mobilenumber@upi`): https://www.bhimupi.org.in/faq-s; toolsarena guide (secondary): https://toolsarena.in/guides/upi-id-validator-guide |
| Username "between 3-35 characters". Alphabetic, numeric or alphanumeric. No special characters "except dot(.) and hyphen(-)". | NSDL Payments Bank FAQ (bank primary, but that bank's own policy): https://nsdlpayments.bank.in/frequently_asked_questions.php |
| Some sources also allow underscore. Paytm says the allowed specials "depend on the UPI provider". | https://www.oxigenwallet.com/upi/upi-id-special-characters/, https://paytm.com/support/upi/upi-id-format-rules-valid-structure |
| Length up to 255 for `pa` claimed by one guide (UNVERIFIED) | https://meshworld.in/blog/web-dev/upi-qr-code-architecture-guide/ |
| Handles are case-insensitive in practice (`@BARODAMPAY` is listed in uppercase by SEBI). The uppercase `MERCHANTUAT@ybl` is a valid PhonePe merchant VPA. | SEBI list above; PhonePe DQR doc |
| PhonePe constraints on related IDs: storeId < 38 characters, no spaces, commas or `@`. transactionId < 35 characters, only `_` and `-` as specials. | https://developer.phonepe.com/offline-integration/dynamic-qr-solution/dqr-init-api |

**Recommended validator (lenient on legit, strict on garbage):**
```
VPA  := LOCAL "@" HANDLE
LOCAL  := [A-Za-z0-9][A-Za-z0-9._-]{0,98}[A-Za-z0-9]? ;  hard-fail outside [A-Za-z0-9._-]; warn if len<3 or len>50
HANDLE := [A-Za-z][A-Za-z0-9]{1,63}                    ;  hard-fail on dots/hyphens/spaces in handle (no known handle has them); compare lowercase
Hard-fail: whitespace, 2+ '@', empty parts, '..' , percent-encoded '@' (%40) inside pa after one decode, non-ASCII/homoglyph chars.
```
Real merchant VPAs can have long local parts (`rzr.qrfoodapp54462255833`, 25 characters, from Razorpay), so do not hard-fail at 35.

---

## 7. Sample scam URIs (illustrative, fabricated, for test fixtures)

The VPAs below are invented to show each pattern. Do not treat them as real accounts.

```text
# 1. "Scan to receive refund": P2P handle, prefilled amount, refund text
upi://pay?pa=refund.desk2291@ybl&pn=Amazon%20Refund%20Dept&am=4999.00&cu=INR&tn=Scan%20to%20receive%20your%20refund

# 2. Bank/KYC impersonation, typo-squatted handle (@okaxisbank is not a real handle; real is @okaxis)
upi://pay?pa=sbi.kyc.update@okaxisbank&pn=SBI%20KYC%20Helpdesk&am=10&tn=KYC%20verification%20fee%20to%20unblock%20account

# 3. Lookalike handle with capital I instead of l (@ybI), "prize"
upi://pay?pa=9876543210@ybI&pn=KBC%20Lottery%20Winner&am=15000&tn=Pay%20GST%20to%20release%20prize%2025%20lakh

# 4. Merchant MCC but personal VPA + name mismatch
upi://pay?pa=rahul.k1998@oksbi&pn=Indian%20Oil%20Petrol%20Pump&mc=5541&am=2000.00&cu=INR

# 5. Non-INR currency + duplicate pa (parser confusion)
upi://pay?pa=shop@paytm&pn=Shop&pa=attacker99@axl&am=500&cu=USD

# 6. Phishing url param + "verify" note
upi://pay?pa=verify.account@ibl&pn=NPCI%20Verification&am=1&tn=Verify%20to%20receive%20cashback&url=http://bit.ly/claim-upi-reward

# 7. AutoPay mandate disguised as a small payment (recurring MAX debit, non-revocable)
upi://mandate?pa=subs.collect@ybl&pn=Cashback%20Activation&am=9999&amrule=MAX&recur=ASPRESENTED&validitystart=09102026&validityend=09102036&rev=N&purpose=14&mode=13&txnType=CREATE&tn=Activate%20cashback

# 8. Malformed: two @, space, amount with comma
upi://pay?pa=help desk@@sbi&pn=Help&am=1,000

# 9. "collect" scheme (no spec; anomalous)
upi://collect?pa=army.officer@ptyes&pn=Army%20Canteen&am=5000&tn=Receive%20advance%20payment
```

---

## 8. Uncertainties

1. **Spec version.** The only full text we found is the **1.6 Draft (Nov 2017)** from a third-party mirror. NPCI's own site blocks scripted access (HTTP 403), so we could not confirm whether a newer public linking spec (2.x) exists or changes any field definitions.
2. **`mode` 15–18 conflict.** The 1.6 draft says 15 = SEBI and 16–18 = future. Juspay (secondary) says 15 = offline dynamic QR, 16 = offline dynamic secure QR, 17 = dynamic secure QR mandate, 18 = ATM QR, and 03 = Bharat QR. We believe Juspay reflects later NPCI circulars, but this is **UNVERIFIED against an NPCI primary source**.
3. **`mode`/`sign`/`orgid` marked "M" in 1.6**, yet most consumer static QRs omit them. Treat their absence as normal.
4. **`ver`, `qrMedium`, `QRexpire`/`QRts`.** We have seen the values but have no official definitions. `qrMedium` value meanings are unknown.
5. **`am` decimals.** The spec only says "decimal format", and its examples use integers. Exactly-2-decimals is a vendor convention, not a confirmed spec rule.
6. **`mc` length.** It is usually a 4-digit MCC, but Juspay's example has `mc=516`. "0000 = P2P" comes from spec examples, not an explicit rule.
7. **`upi://collect`.** No spec found. Its existence or handling in apps is unverified. Collect is a network flow, not a URI.
8. **`upi://mandate` param names, casing and date format** (DDMMYYYY) come from vendor docs only.
9. **Bharat QR internals.** Tag 26 = UPI VPA template with RID `A000000524` comes from one library. The VPA sub-tag ID and the exact BharatQR v1.5.2 linking annex are unverified.
10. **Merchant VPA patterns** (`Q…@ybl` PhonePe, `paytmqr…@paytm`, `BHARATPE…@fbpe`/`@unitype`) are **UNVERIFIED**. They are commonly observed but no authoritative doc was found.
11. **Handle list freshness.** Tier A is from a third-party mirror of NPCI data (commit 2026-10-05), cross-checked with the Wayback copy from 2025-09-25. Tier C comes from aggregators, some years old. Merged-bank handles may be retired. `@icic` (Razorpay sample) may be a test-only or acquirer-internal handle.
12. **VPA length and charset.** Sources conflict: 3–35 characters with `.`/`-` (NSDL) versus underscore allowed (others) versus 255 maximum (one blog). There is no NPCI primary rule.
13. **P2P limit wording.** Sources disagree on whether ₹1 lakh is per transaction or per day.
14. **Merchant collect status after Feb 2026.** This rests on Razorpay's notice citing "NPCI guidelines". We did not see the NPCI circular itself.
