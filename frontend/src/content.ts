import type { Lang } from "./api";
const C = {
  eyebrow: [
    "YOUR FIRST LINE OF QR DEFENSE",
    "QR सुरक्षा की पहली ढाल",
    "QR सुरक्षेची पहिली ढाल",
  ],
  heroOne: ["Behind every QR.", "हर QR के पीछे।", "प्रत्येक QR मागे."],
  heroTwo: [
    "Know what’s next.",
    "जानें आगे क्या है।",
    "पुढे काय आहे ते जाणून घ्या.",
  ],
  heroBody: [
    "A payment. A website. A clever disguise. Reveal what a QR really does before it gets near your wallet.",
    "भुगतान, वेबसाइट या धोखे का जाल। अपने पैसे सुरक्षित रखने के लिए पहले जानें कि QR असल में क्या करेगा।",
    "पेमेंट, वेबसाइट किंवा फसवणूक. तुमच्या पैशांपर्यंत पोहोचण्यापूर्वी QR नेमके काय करतो ते जाणून घ्या.",
  ],
  scanCta: ["Check a QR", "QR जांचें", "QR तपासा"],
  how: ["How it works", "कैसे काम करता है", "हे कसे कार्य करते"],
  merchant: ["For shopkeepers", "दुकानदारों के लिए", "दुकानदारांसाठी"],
  assurance: [
    "No automatic opening. You stay in control.",
    "अपने आप कुछ नहीं खुलता। नियंत्रण आपके हाथ में।",
    "आपोआप काही उघडत नाही. नियंत्रण तुमच्या हातात.",
  ],
  signalOne: [
    "UNDERSTAND THE ACTION",
    "जानें QR क्या करेगा",
    "QR ची कृती समजून घ्या",
  ],
  signalTwo: [
    "CHECK BEFORE YOU PAY",
    "भुगतान से पहले जांचें",
    "पेमेंटपूर्वी तपासा",
  ],
  signalThree: [
    "EXPLAINED IN YOUR LANGUAGE",
    "आपकी भाषा में जानकारी",
    "तुमच्या भाषेत स्पष्टीकरण",
  ],
  workspace: ["THE SCAN DESK", "स्कैन डेस्क", "स्कॅन डेस्क"],
  workspaceTitle: [
    "One scan. A clearer picture.",
    "एक स्कैन। साफ़ जानकारी।",
    "एक स्कॅन. स्पष्ट माहिती.",
  ],
  workspaceBody: [
    "Decode the destination. Understand the payment. Make your next move with more confidence.",
    "मंज़िल पहचानें, भुगतान समझें और जानकारी के साथ आगे बढ़ें।",
    "गंतव्य ओळखा, पेमेंट समजून घ्या आणि माहितीसह पुढे जा.",
  ],
  camera: ["Scan with camera", "कैमरे से स्कैन करें", "कॅमेऱ्याने स्कॅन करा"],
  cameraBody: [
    "Point your camera at a QR. We’ll read it before anything opens.",
    "कैमरा QR पर रखें। कुछ खुलने से पहले हम उसे पढ़ेंगे।",
    "कॅमेरा QR वर धरा. काही उघडण्यापूर्वी आम्ही तो वाचू.",
  ],
  stopCamera: ["Stop camera", "कैमरा बंद करें", "कॅमेरा बंद करा"],
  uploadBody: [
    "A screenshot works, too",
    "स्क्रीनशॉट भी चलेगा",
    "स्क्रीनशॉटही चालेल",
  ],
  inputHint: [
    "QR text or website address",
    "QR टेक्स्ट या वेबसाइट का पता",
    "QR मजकूर किंवा वेबसाइटचा पत्ता",
  ],
  demoTitle: ["Try a sample", "नमूना आज़माएं", "नमुना वापरून पहा"],
  sampleShop: ["Shop payment", "दुकान भुगतान", "दुकान पेमेंट"],
  sampleRefund: ["Refund trap", "रिफंड का जाल", "परताव्याचे आमिष"],
  sampleUrl: ["Lookalike website", "नकली वेबसाइट", "नक्कल वेबसाइट"],
  sampleNote: [
    "Illustrative samples · no payment is made",
    "उदाहरण के नमूने · कोई भुगतान नहीं होगा",
    "उदाहरण नमुने · कोणतेही पेमेंट होत नाही",
  ],
  guardTitle: [
    "Small code. Big consequences.",
    "छोटा कोड। बड़ा असर।",
    "छोटा कोड. मोठे परिणाम.",
  ],
  guardBody: [
    "QRs can open more than websites. Check the action as well as the address.",
    "QR सिर्फ वेबसाइट नहीं खोलते। पते के साथ उसकी कार्रवाई भी जांचें।",
    "QR फक्त वेबसाइट उघडत नाहीत. पत्त्यासह त्याची कृतीही तपासा.",
  ],
  intentTitle: ["Intent matters", "इरादा ज़रूरी है", "उद्देश महत्त्वाचा"],
  intentBody: [
    "Expecting a refund? A payment QR sends money. Tell us what you’re doing so we can spot that mismatch.",
    "रिफंड मिलने की उम्मीद है? भुगतान QR पैसे भेजता है। हमें अपना इरादा बताएं।",
    "परतावा अपेक्षित आहे? पेमेंट QR पैसे पाठवतो. आम्हाला तुमचा उद्देश सांगा.",
  ],
  langTitle: [
    "Clarity, in three languages",
    "तीन भाषाओं में स्पष्टता",
    "तीन भाषांत स्पष्टता",
  ],
  langBody: [
    "Read the reasons in English, Hindi or Marathi. No security jargon required.",
    "अंग्रेज़ी, हिंदी या मराठी में कारण पढ़ें। तकनीकी शब्दों की ज़रूरत नहीं।",
    "इंग्रजी, हिंदी किंवा मराठीत कारणे वाचा. तांत्रिक शब्दांची गरज नाही.",
  ],
  shopTitle: [
    "Same shop. Different wallet?",
    "वही दुकान। अलग खाता?",
    "तीच दुकान. वेगळे खाते?",
  ],
  shopBody: [
    "Save your genuine UPI QR, then check your counter sticker for a changed payment destination.",
    "अपना असली UPI QR सहेजें और काउंटर स्टिकर में बदली मंज़िल जांचें।",
    "तुमचा खरा UPI QR जतन करा आणि काउंटर स्टिकरचा बदललेला पत्ता तपासा.",
  ],
  stepOne: ["Bring a QR", "QR लाएं", "QR आणा"],
  stepOneBody: [
    "Use your camera, an image or the decoded text.",
    "कैमरा, फ़ोटो या QR टेक्स्ट इस्तेमाल करें।",
    "कॅमेरा, फोटो किंवा QR मजकूर वापरा.",
  ],
  stepTwo: [
    "Read between the squares",
    "कोड के पीछे की बात समझें",
    "कोडमागील अर्थ समजून घ्या",
  ],
  stepTwoBody: [
    "We inspect the payload and explain the signals.",
    "हम QR जांचकर संकेतों का मतलब बताते हैं।",
    "आम्ही QR तपासून संकेत स्पष्ट करतो.",
  ],
  stepThree: [
    "Choose your next move",
    "अपना अगला कदम चुनें",
    "पुढील कृती निवडा",
  ],
  stepThreeBody: [
    "Review the result before opening a link or payment app.",
    "लिंक या भुगतान ऐप खोलने से पहले नतीजा पढ़ें।",
    "लिंक किंवा पेमेंट ॲप उघडण्यापूर्वी निकाल वाचा.",
  ],
  scope: [
    "A second look, not a guarantee",
    "दोबारा जांच, गारंटी नहीं",
    "पुन्हा तपासणी, हमी नाही",
  ],
  scopeBody: [
    "QR Shield highlights risk signals. It cannot confirm a bank account’s owner or guarantee a destination is safe. Analysis needs a connection to the server; some extra checks need internet access.",
    "QR Shield ख़तरे के संकेत बताता है। यह बैंक खातेदार की पहचान या सुरक्षा की गारंटी नहीं देता। जांच के लिए सर्वर से संपर्क आवश्यक है।",
    "QR Shield धोक्याचे संकेत दाखवतो. खातेदाराची ओळख किंवा सुरक्षिततेची हमी देत नाही. तपासणीसाठी सर्व्हरशी जोडणी आवश्यक आहे.",
  ],
  result: ["SCAN RESULTS", "स्कैन का नतीजा", "स्कॅन निकाल"],
  risk: ["Risk score", "जोखिम स्कोर", "धोका गुण"],
  evidence: ["Check details", "जांच की जानकारी", "तपासणी तपशील"],
  payload: ["Decoded payload", "पढ़ा गया QR टेक्स्ट", "वाचलेला QR मजकूर"],
  saveLocal: [
    "Saved on this device",
    "इस डिवाइस पर सहेजा गया",
    "या डिव्हाइसवर जतन केले",
  ],
  historyBody: [
    "Your recent scans live in this browser. Tap one to check it again with its original intent.",
    "हाल के स्कैन इसी ब्राउज़र में हैं। मूल इरादे के साथ दोबारा जांचने के लिए चुनें।",
    "अलीकडील स्कॅन या ब्राउझरमध्ये आहेत. मूळ उद्देशासह पुन्हा तपासण्यासाठी निवडा.",
  ],
  reportError: [
    "Could not save the report. Please try again.",
    "शिकायत सहेजी नहीं गई। फिर कोशिश करें।",
    "तक्रार जतन झाली नाही. पुन्हा प्रयत्न करा.",
  ],
  reportHelp: [
    "Describe what looked suspicious. Please don’t include personal details.",
    "संदेह का कारण बताएं। निजी जानकारी न लिखें।",
    "संशयाचे कारण सांगा. वैयक्तिक माहिती देऊ नका.",
  ],
  localShop: [
    "Your trusted baseline stays on this device. This checks for changes, not bank ownership.",
    "आपका मूल QR इसी डिवाइस पर है। यह बदलाव जांचता है, बैंक खाते का मालिक नहीं।",
    "तुमचा मूळ QR या डिव्हाइसवर आहे. ही बदलांची तपासणी आहे, खात्याच्या मालकीची नाही.",
  ],
  shopMatch: [
    "Your sticker matches.",
    "आपका स्टिकर मेल खाता है।",
    "तुमचा स्टिकर जुळतो.",
  ],
  shopMismatch: [
    "Something has changed.",
    "कुछ बदल गया है।",
    "काहीतरी बदलले आहे.",
  ],
  expected: ["Saved UPI ID", "सहेजी हुई UPI ID", "जतन केलेला UPI ID"],
  found: ["Scanned UPI ID", "स्कैन हुई UPI ID", "स्कॅन केलेला UPI ID"],
  footer: [
    "Look closer. Pay smarter.",
    "ध्यान से देखें। समझकर भुगतान करें।",
    "नीट पाहा. समजून पेमेंट करा.",
  ],
  privacy: [
    "Images decoded on your device",
    "फ़ोटो आपके डिवाइस पर पढ़ी जाती है",
    "फोटो तुमच्या डिव्हाइसवर वाचले जातात",
  ],
  secret: [
    "Sensitive QR content is not saved in history",
    "निजी QR जानकारी इतिहास में नहीं सहेजी जाती",
    "संवेदनशील QR माहिती इतिहासात जतन होत नाही",
  ],
} as const;
export type ContentKey = keyof typeof C;
export function c(lang: Lang, key: ContentKey): string {
  return C[key][lang === "en" ? 0 : lang === "hi" ? 1 : 2];
}
