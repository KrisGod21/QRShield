import type { Lang } from "./api";

const T = {
  tagline: {
    en: "Check a QR before it checks your wallet",
    hi: "QR खोलने से पहले जांचें",
    mr: "QR उघडण्यापूर्वी तपासा",
  },
  scan: { en: "Scan", hi: "स्कैन", mr: "स्कॅन" },
  history: { en: "History", hi: "इतिहास", mr: "इतिहास" },
  shop: { en: "My Shop", hi: "मेरी दुकान", mr: "माझे दुकान" },
  whatDoing: {
    en: "What are you doing?",
    hi: "आप क्या कर रहे हैं?",
    mr: "तुम्ही काय करत आहात?",
  },
  check: { en: "Just checking", hi: "बस जांच", mr: "फक्त तपासणी" },
  pay_shop: {
    en: "Paying a shop",
    hi: "दुकान को भुगतान",
    mr: "दुकानाला पेमेंट",
  },
  receive: { en: "Receiving money", hi: "पैसे लेने हैं", mr: "पैसे मिळवायचे" },
  pay_bill: { en: "Paying a bill", hi: "बिल भरना", mr: "बिल भरणे" },
  startCamera: {
    en: "Tap to scan",
    hi: "स्कैन करने के लिए टैप करें",
    mr: "स्कॅन करण्यासाठी टॅप करा",
  },
  pointCamera: {
    en: "Point at a QR code",
    hi: "QR कोड की ओर कैमरा करें",
    mr: "QR कोडकडे कॅमेरा धरा",
  },
  upload: { en: "Upload QR image", hi: "QR फ़ोटो चुनें", mr: "QR फोटो निवडा" },
  paste: { en: "Paste QR text", hi: "QR टेक्स्ट डालें", mr: "QR मजकूर टाका" },
  analyze: { en: "Check", hi: "जांचें", mr: "तपासा" },
  checking: {
    en: "Checking safely on our server…",
    hi: "सर्वर पर सुरक्षित जांच हो रही है…",
    mr: "सर्व्हरवर सुरक्षित तपासणी सुरू आहे…",
  },
  noQr: {
    en: "No QR code found in that image.",
    hi: "इस फ़ोटो में QR कोड नहीं मिला।",
    mr: "या फोटोमध्ये QR कोड सापडला नाही.",
  },
  camError: {
    en: "Camera not available here. Use 'Upload QR image' instead (camera needs HTTPS).",
    hi: "कैमरा उपलब्ध नहीं है। 'QR फ़ोटो चुनें' का उपयोग करें।",
    mr: "कॅमेरा उपलब्ध नाही. 'QR फोटो निवडा' वापरा.",
  },
  netError: {
    en: "Could not reach the QR Shield server. Don't open this QR until you can check it.",
    hi: "QR Shield सर्वर से संपर्क नहीं हुआ। जांच होने तक यह QR न खोलें।",
    mr: "QR Shield सर्व्हरशी संपर्क झाला नाही. तपासणी होईपर्यंत हा QR उघडू नका.",
  },
  SAFE: { en: "Looks safe", hi: "सुरक्षित लगता है", mr: "सुरक्षित वाटते" },
  CAUTION: { en: "Be careful", hi: "सावधान रहें", mr: "सावध राहा" },
  DANGER: {
    en: "Danger — do not open",
    hi: "ख़तरा — न खोलें",
    mr: "धोका — उघडू नका",
  },
  neverReceive: {
    en: "Scanning a QR never gives you money",
    hi: "QR स्कैन करने से कभी पैसे नहीं मिलते",
    mr: "QR स्कॅन करून कधीही पैसे मिळत नाहीत",
  },
  youPay: { en: "YOU PAY", hi: "आप देंगे", mr: "तुम्ही द्याल" },
  amountYou: {
    en: "You type the amount",
    hi: "रकम आप डालेंगे",
    mr: "रक्कम तुम्ही टाकाल",
  },
  locked: { en: "amount locked", hi: "रकम लॉक", mr: "रक्कम लॉक" },
  to: { en: "to", hi: "को", mr: "ला" },
  why: { en: "Why", hi: "क्यों", mr: "का" },
  noFlags: {
    en: "No red flags found. Still check the name your UPI app shows before paying.",
    hi: "कोई ख़तरे का संकेत नहीं मिला। फिर भी भुगतान से पहले UPI ऐप में दिखने वाला नाम जांचें।",
    mr: "धोक्याची कोणतीही खूण सापडली नाही. तरीही पैसे भरण्यापूर्वी UPI ॲपमधील नाव तपासा.",
  },
  dontOpen: { en: "Don't open", hi: "न खोलें", mr: "उघडू नका" },
  openAnyway: { en: "Open anyway", hi: "फिर भी खोलें", mr: "तरीही उघडा" },
  confirmRisk: {
    en: "I understand this may be a scam and I could lose money.",
    hi: "मैं समझता/समझती हूँ कि यह धोखा हो सकता है और मेरे पैसे जा सकते हैं।",
    mr: "हे फसवणूक असू शकते आणि माझे पैसे जाऊ शकतात हे मला समजते.",
  },
  continue: { en: "Continue", hi: "आगे बढ़ें", mr: "पुढे जा" },
  report: {
    en: "Report this QR",
    hi: "इस QR की शिकायत करें",
    mr: "या QR ची तक्रार करा",
  },
  reported: {
    en: "Thanks! Reported",
    hi: "धन्यवाद! शिकायत दर्ज",
    mr: "धन्यवाद! तक्रार नोंदवली",
  },
  reportedBy: {
    en: "Community reports: {n} (unverified)",
    hi: "सामुदायिक शिकायतें: {n} (अपुष्ट)",
    mr: "समुदायाच्या तक्रारी: {n} (अपुष्ट)",
  },
  scanAgain: {
    en: "Scan another",
    hi: "दूसरा स्कैन करें",
    mr: "दुसरा स्कॅन करा",
  },
  checks: { en: "Checks", hi: "जांचें", mr: "तपासण्या" },
  helpline: {
    en: "Lost money? Call 1930 or visit cybercrime.gov.in",
    hi: "पैसे गए? 1930 पर कॉल करें या cybercrime.gov.in पर जाएं",
    mr: "पैसे गेले? 1930 वर कॉल करा किंवा cybercrime.gov.in ला भेट द्या",
  },
  emptyHistory: {
    en: "No scans yet.",
    hi: "अभी तक कोई स्कैन नहीं।",
    mr: "अजून कोणताही स्कॅन नाही.",
  },
  clear: { en: "Clear", hi: "मिटाएं", mr: "पुसा" },
  shopIntro: {
    en: "Shopkeepers: register your genuine UPI QR once. Then scan your counter sticker any time to make sure nobody has swapped it.",
    hi: "दुकानदार: अपना असली UPI QR एक बार रजिस्टर करें। फिर कभी भी काउंटर का स्टिकर स्कैन करके पक्का करें कि किसी ने उसे बदला नहीं है।",
    mr: "दुकानदार: तुमचा खरा UPI QR एकदा नोंदवा. नंतर कधीही काउंटरवरील स्टिकर स्कॅन करून खात्री करा की कोणी तो बदललेला नाही.",
  },
  shopName: { en: "Shop name", hi: "दुकान का नाम", mr: "दुकानाचे नाव" },
  register: {
    en: "Scan & register my QR",
    hi: "मेरा QR स्कैन करके रजिस्टर करें",
    mr: "माझा QR स्कॅन करून नोंदवा",
  },
  verify: {
    en: "Check my counter sticker",
    hi: "काउंटर का स्टिकर जांचें",
    mr: "काउंटरवरील स्टिकर तपासा",
  },
  registeredAs: { en: "Registered", hi: "रजिस्टर्ड", mr: "नोंदणीकृत" },
  reset: {
    en: "Register a different QR",
    hi: "दूसरा QR रजिस्टर करें",
    mr: "दुसरा QR नोंदवा",
  },
  shopCode: { en: "Shop code", hi: "दुकान कोड", mr: "दुकान कोड" },
  cancel: { en: "Cancel", hi: "रद्द करें", mr: "रद्द करा" },
  password: { en: "Password", hi: "पासवर्ड", mr: "पासवर्ड" },
  copied: { en: "Copied", hi: "कॉपी हुआ", mr: "कॉपी झाले" },
  demo: { en: "Demo mode", hi: "डेमो मोड", mr: "डेमो मोड" },
  reasonPrompt: {
    en: "What happened? (optional)",
    hi: "क्या हुआ? (वैकल्पिक)",
    mr: "काय झाले? (ऐच्छिक)",
  },
} satisfies Record<string, Record<Lang, string>>;

export type Key = keyof typeof T;
export const t = (
  lang: Lang,
  key: Key,
  vars: Record<string, string | number> = {},
) => T[key][lang].replace(/\{(\w+)\}/g, (_, k) => String(vars[k] ?? ""));

export const CHECK_NAMES: Record<string, string> = {
  threat_feeds: "Threat feeds",
  domain_age: "Domain age",
  redirects: "Redirects",
  safe_browsing: "Safe Browsing",
  urlhaus: "URLhaus",
};
