"""Plain-language reason texts in English, Hindi and Marathi.

Every signal code (and every headline) maps to {en, hi, mr} templates with
{param} placeholders. A code may also have per-category variants, keyed as
"CODE.category" (used for scam-keyword categories).

The Hindi and Marathi texts are written for a non-technical reader. They should
be reviewed by a native speaker before the event.
"""

from __future__ import annotations

LANGS = ("en", "hi", "mr")

M: dict[str, dict[str, str]] = {
    "UPI_DISPLAY_CONTROL": {
        "en": "The payee name or note contains invisible text-direction controls that can change how it is displayed. Confirm the full beneficiary identity in your payment app.",
        "hi": "नाम या नोट में अदृश्य अक्षर दिशा बदलते हैं। पेमेंट ऐप में प्राप्तकर्ता की पूरी पहचान जांचें।",
        "mr": "नाव किंवा नोंदीतील अदृश्य अक्षरे मजकुराची दिशा बदलतात. पेमेंट ॲपमध्ये प्राप्तकर्त्याची पूर्ण ओळख तपासा.",
    },
    "URL_QUERY_CONFLICT": {
        "en": "This link repeats query fields with conflicting values ({keys}). Different services may read different destinations or actions.",
        "hi": "इस लिंक में अलग मान वाले दोहराए पैरामीटर हैं ({keys})। अलग सेवाएं अलग गंतव्य या क्रिया पढ़ सकती हैं।",
        "mr": "या लिंकमध्ये वेगवेगळ्या मूल्यांचे पुनरावृत्त पॅरामीटर आहेत ({keys}). वेगवेगळ्या सेवा वेगळी कृती वाचू शकतात.",
    },
    "URL_EMBEDDED_DESTINATION": {
        "en": "The '{key}' parameter contains another destination: {destination}. This is a declared target, not proof that a redirect occurred.",
        "hi": "'{key}' में दूसरा गंतव्य है: {destination}। यह दिया गया पता है, वास्तविक रीडायरेक्ट का प्रमाण नहीं।",
        "mr": "'{key}' मध्ये दुसरे गंतव्य आहे: {destination}. हा घोषित पत्ता आहे, प्रत्यक्ष रीडायरेक्टचा पुरावा नाही.",
    },
    "URL_HTTPS_DOWNGRADE": {
        "en": "The redirect chain switches from encrypted HTTPS to unencrypted HTTP. Data sent to that destination could be intercepted.",
        "hi": "रीडायरेक्ट HTTPS से बिना एन्क्रिप्शन HTTP पर जाता है। भेजा गया डेटा बीच में पढ़ा जा सकता है।",
        "mr": "रीडायरेक्ट HTTPS वरून एन्क्रिप्शन नसलेल्या HTTP वर जातो. पाठवलेला डेटा मध्ये वाचला जाऊ शकतो.",
    },
    "URL_PARSER_AMBIGUITY": {
        "en": "Control characters or backslashes make this address ambiguous across URL parsers. Opening is disabled; request a clean URL.",
        "hi": "कंट्रोल अक्षर या बैकस्लैश से पता अलग-अलग पढ़ा जा सकता है। खोलना बंद है; साफ पता मांगें।",
        "mr": "कंट्रोल अक्षरे किंवा बॅकस्लॅशमुळे पत्ता वेगवेगळा वाचला जाऊ शकतो. उघडणे बंद आहे; स्वच्छ पत्ता मागा.",
    },
    "UPI_MISSING_NAME": {
        "en": "The payee display name is missing. Confirm the beneficiary name in your payment app before paying.",
        "hi": "प्राप्तकर्ता का नाम नहीं है। भुगतान से पहले पेमेंट ऐप में नाम की पुष्टि करें।",
        "mr": "प्राप्तकर्त्याचे नाव नाही. पेमेंट करण्यापूर्वी पेमेंट ॲपमध्ये नावाची खात्री करा.",
    },
    "UPI_BAD_MCC": {
        "en": "The merchant category '{mcc}' is not a four-digit MCC. The declared merchant metadata is malformed.",
        "hi": "व्यापारी श्रेणी '{mcc}' चार अंकों का MCC नहीं है। व्यापारी डेटा का प्रारूप गलत है।",
        "mr": "व्यापारी श्रेणी '{mcc}' चार अंकी MCC नाही. व्यापारी डेटाचे स्वरूप चुकीचे आहे.",
    },
    "UPI_BAD_MIN_AMOUNT": {
        "en": "The minimum amount is invalid or greater than the declared payment amount. Payment constraints are inconsistent.",
        "hi": "न्यूनतम रकम गलत है या भुगतान रकम से अधिक है। भुगतान की शर्तें मेल नहीं खातीं।",
        "mr": "किमान रक्कम चुकीची आहे किंवा पेमेंट रकमेपेक्षा जास्त आहे. पेमेंट अटी जुळत नाहीत.",
    },
    "URL_INVALID": {
        "en": "This is not a valid website address. Do not open it; check the original QR or enter a complete URL.",
        "hi": "यह सही वेबसाइट पता नहीं है। इसे न खोलें; मूल QR या पूरा पता जांचें।",
        "mr": "हा वैध वेबसाइट पत्ता नाही. तो उघडू नका; मूळ QR किंवा पूर्ण पत्ता तपासा.",
    },
    "URL_UNVERIFIED": {
        "en": "We could not verify this link's destination. Some checks were unavailable or did not finish; do not assume the link is safe.",
        "hi": "इस लिंक की मंज़िल की पुष्टि नहीं हो पाई। कुछ जांचें पूरी नहीं हुईं; इसे सुरक्षित न मानें।",
        "mr": "या लिंकच्या गंतव्याची खात्री झाली नाही. काही तपासण्या पूर्ण झाल्या नाहीत; लिंक सुरक्षित समजू नका.",
    },
    # ---------------------------------------------------------------- UPI
    "UPI_PAY_INFO": {
        "en": "Scanning a UPI QR always means YOU PAY. You never need to scan a QR or enter your UPI PIN to receive money.",
        "hi": "UPI QR स्कैन करने का मतलब हमेशा आप पैसे देते हैं। पैसे लेने के लिए कभी भी QR स्कैन करने या UPI PIN डालने की ज़रूरत नहीं होती।",
        "mr": "UPI QR स्कॅन करणे म्हणजे नेहमी तुम्ही पैसे देता. पैसे मिळवण्यासाठी कधीही QR स्कॅन करण्याची किंवा UPI PIN टाकण्याची गरज नसते.",
    },
    "UPI_RECEIVE_INTENT": {
        "en": "You said you are expecting to RECEIVE money, but this QR will TAKE money from your account. This is the most common UPI scam. Do not pay.",
        "hi": "आपने कहा कि आपको पैसे मिलने वाले हैं, लेकिन यह QR आपके खाते से पैसे काटेगा। यह सबसे आम UPI धोखा है। भुगतान न करें।",
        "mr": "तुम्हाला पैसे मिळणार आहेत असे तुम्ही सांगितले, पण हा QR तुमच्या खात्यातून पैसे कापेल. ही सर्वात सामान्य UPI फसवणूक आहे. पैसे भरू नका.",
    },
    "UPI_MANDATE": {
        "en": "This QR sets up AUTOPAY: repeated debits of up to {amount} ({recur}) until {until}. It is not a one-time payment.",
        "hi": "यह QR ऑटोपे (AUTOPAY) चालू करता है: {until} तक बार-बार ({recur}) {amount} तक पैसे कटेंगे। यह एक बार का भुगतान नहीं है।",
        "mr": "हा QR ऑटोपे (AUTOPAY) सुरू करतो: {until} पर्यंत वारंवार ({recur}) {amount} पर्यंत पैसे कापले जातील. हे एकदाच होणारे पेमेंट नाही.",
    },
    "UPI_MANDATE_IRREVOCABLE": {
        "en": "This AutoPay is marked as NON-cancellable. You may not be able to stop it later.",
        "hi": "यह ऑटोपे 'रद्द नहीं हो सकता' के रूप में सेट है। बाद में इसे रोकना मुश्किल हो सकता है।",
        "mr": "हे ऑटोपे 'रद्द करता येणार नाही' असे सेट केले आहे. नंतर ते थांबवणे कठीण होऊ शकते.",
    },
    "UPI_COLLECT_SCHEME": {
        "en": "This is not a normal UPI payment QR ('{action}'). Real UPI QR codes only use 'pay'. Treat it as suspicious.",
        "hi": "यह सामान्य UPI भुगतान QR नहीं है ('{action}')। असली UPI QR केवल 'pay' का उपयोग करते हैं। इसे संदिग्ध मानें।",
        "mr": "हा नेहमीचा UPI पेमेंट QR नाही ('{action}'). खरे UPI QR फक्त 'pay' वापरतात. याला संशयास्पद समजा.",
    },
    "UPI_MISSING_PA": {
        "en": "This UPI QR has no receiver UPI ID. It is broken or has been tampered with.",
        "hi": "इस UPI QR में पैसे पाने वाले की UPI ID नहीं है। यह खराब है या इससे छेड़छाड़ की गई है।",
        "mr": "या UPI QR मध्ये पैसे घेणाऱ्याचा UPI ID नाही. तो खराब आहे किंवा त्यात छेडछाड केली आहे.",
    },
    "UPI_MALFORMED_VPA": {
        "en": "The UPI ID '{vpa}' is not in a valid format. Genuine UPI apps never create IDs like this.",
        "hi": "UPI ID '{vpa}' सही फ़ॉर्मेट में नहीं है। असली UPI ऐप ऐसी ID नहीं बनाते।",
        "mr": "UPI ID '{vpa}' योग्य स्वरूपात नाही. खरी UPI ॲप्स असे ID तयार करत नाहीत.",
    },
    "UPI_DUPLICATE_PARAM": {
        "en": "This QR contains the field '{param}' twice. Different apps may read different values, a known trick to hide the real receiver or amount.",
        "hi": "इस QR में '{param}' दो बार है। अलग-अलग ऐप अलग मान पढ़ सकते हैं। असली प्राप्तकर्ता या रकम छिपाने की यह एक जानी-मानी चाल है।",
        "mr": "या QR मध्ये '{param}' दोनदा आहे. वेगवेगळी ॲप्स वेगवेगळी किंमत वाचू शकतात. खरा प्राप्तकर्ता किंवा रक्कम लपवण्याची ही ओळखीची युक्ती आहे.",
    },
    "UPI_BAD_CURRENCY": {
        "en": "The currency is '{currency}'. UPI in India only uses INR (₹).",
        "hi": "मुद्रा '{currency}' है। भारत में UPI केवल INR (₹) का उपयोग करता है।",
        "mr": "चलन '{currency}' आहे. भारतात UPI फक्त INR (₹) वापरते.",
    },
    "UPI_BAD_AMOUNT": {
        "en": "The amount '{raw}' is not a valid number.",
        "hi": "रकम '{raw}' सही संख्या नहीं है।",
        "mr": "रक्कम '{raw}' योग्य संख्या नाही.",
    },
    "UPI_HANDLE_TYPO": {
        "en": "'@{handle}' looks like a misspelling of the real UPI handle '@{similar}'. Scammers use near-identical handles to look genuine.",
        "hi": "'@{handle}' असली UPI हैंडल '@{similar}' की गलत स्पेलिंग जैसा दिखता है। ठग असली जैसे दिखने वाले हैंडल इस्तेमाल करते हैं।",
        "mr": "'@{handle}' हे खऱ्या UPI हँडल '@{similar}' चे चुकीचे स्पेलिंग वाटते. फसवणूक करणारे खऱ्यासारखे दिसणारे हँडल वापरतात.",
    },
    "UPI_HANDLE_UNKNOWN": {
        "en": "'@{handle}' is not on our list of known UPI apps and banks. It may be a shop's bank handle, so check the name your UPI app shows.",
        "hi": "'@{handle}' हमारी जानी-मानी UPI ऐप और बैंकों की सूची में नहीं है। यह किसी दुकान के बैंक का हैंडल हो सकता है, इसलिए अपने UPI ऐप में दिखने वाला नाम ज़रूर जांचें।",
        "mr": "'@{handle}' आमच्या ओळखीच्या UPI ॲप्स आणि बँकांच्या यादीत नाही. हे एखाद्या दुकानाच्या बँकेचे हँडल असू शकते, म्हणून तुमच्या UPI ॲपमध्ये दिसणारे नाव नक्की तपासा.",
    },
    "UPI_HANDLE_VERIFIED": {
        "en": "'@{handle}' is a SEBI-verified '@valid' handle used by registered brokers and mutual funds.",
        "hi": "'@{handle}' SEBI द्वारा सत्यापित '@valid' हैंडल है, जिसे पंजीकृत ब्रोकर और म्यूचुअल फंड इस्तेमाल करते हैं।",
        "mr": "'@{handle}' हे SEBI-सत्यापित '@valid' हँडल आहे, जे नोंदणीकृत ब्रोकर आणि म्युच्युअल फंड वापरतात.",
    },
    "UPI_SCAM_KEYWORD.refund": {
        "en": "It says '{word}'. You never PAY to get a refund. Real refunds come to you automatically.",
        "hi": "इसमें '{word}' लिखा है। रिफंड पाने के लिए कभी भुगतान नहीं करना पड़ता। असली रिफंड अपने-आप आता है।",
        "mr": "यात '{word}' लिहिले आहे. रिफंड मिळवण्यासाठी कधीही पैसे भरावे लागत नाहीत. खरा रिफंड आपोआप येतो.",
    },
    "UPI_SCAM_KEYWORD.receive": {
        "en": "It says '{word}', but scanning this QR SENDS your money. You cannot receive money by scanning.",
        "hi": "इसमें '{word}' लिखा है, लेकिन यह QR स्कैन करने पर आपके पैसे जाते हैं। स्कैन करके पैसे नहीं मिलते।",
        "mr": "यात '{word}' लिहिले आहे, पण हा QR स्कॅन केल्यावर तुमचे पैसे जातात. स्कॅन करून पैसे मिळत नाहीत.",
    },
    "UPI_SCAM_KEYWORD.prize": {
        "en": "It mentions '{word}'. Real prizes and lotteries never ask you to pay first.",
        "hi": "इसमें '{word}' का ज़िक्र है। असली इनाम या लॉटरी में पहले पैसे नहीं मांगे जाते।",
        "mr": "यात '{word}' चा उल्लेख आहे. खरी बक्षिसे किंवा लॉटरी आधी पैसे मागत नाहीत.",
    },
    "UPI_SCAM_KEYWORD.cashback": {
        "en": "It mentions '{word}'. Cashback is credited by the app itself. You never pay a stranger to get it.",
        "hi": "इसमें '{word}' का ज़िक्र है। कैशबैक ऐप खुद देता है। इसके लिए किसी अनजान को पैसे नहीं देने होते।",
        "mr": "यात '{word}' चा उल्लेख आहे. कॅशबॅक ॲप स्वतः देते. त्यासाठी अनोळखी व्यक्तीला पैसे द्यावे लागत नाहीत.",
    },
    "UPI_SCAM_KEYWORD.kyc": {
        "en": "It mentions '{word}'. Banks never ask you to pay through a QR for KYC or to unblock an account.",
        "hi": "इसमें '{word}' का ज़िक्र है। बैंक KYC या खाता चालू करने के लिए कभी QR से भुगतान नहीं मांगते।",
        "mr": "यात '{word}' चा उल्लेख आहे. बँका KYC साठी किंवा खाते सुरू करण्यासाठी कधीही QR ने पैसे मागत नाहीत.",
    },
    "UPI_SCAM_KEYWORD.bill": {
        "en": "It mentions '{word}'. Pay electricity bills only in your official power company or bank app, never through a QR someone sent you.",
        "hi": "इसमें '{word}' का ज़िक्र है। बिजली बिल केवल आधिकारिक बिजली कंपनी या बैंक ऐप से भरें, किसी के भेजे QR से कभी नहीं।",
        "mr": "यात '{word}' चा उल्लेख आहे. वीज बिल फक्त अधिकृत वीज कंपनी किंवा बँक ॲपमधून भरा, कोणी पाठवलेल्या QR ने कधीही नाही.",
    },
    "UPI_SCAM_KEYWORD.fee": {
        "en": "It asks for a '{word}'. 'Pay a fee to release your money or prize' is a classic scam.",
        "hi": "इसमें '{word}' मांगा गया है। 'पैसा या इनाम पाने के लिए फीस भरो' एक पुराना धोखा है।",
        "mr": "यात '{word}' मागितले आहे. 'पैसे किंवा बक्षीस मिळवण्यासाठी शुल्क भरा' ही जुनी फसवणूक आहे.",
    },
    "UPI_SCAM_KEYWORD.job": {
        "en": "It mentions '{word}'. Genuine employers never ask candidates to pay.",
        "hi": "इसमें '{word}' का ज़िक्र है। असली नौकरी देने वाले कभी उम्मीदवार से पैसे नहीं मांगते।",
        "mr": "यात '{word}' चा उल्लेख आहे. खरे नोकरी देणारे उमेदवाराकडून कधीही पैसे मागत नाहीत.",
    },
    "UPI_SCAM_KEYWORD.support": {
        "en": "It claims to be '{word}'. Real customer care never sends you a QR to pay.",
        "hi": "यह खुद को '{word}' बताता है। असली कस्टमर केयर आपको भुगतान के लिए QR नहीं भेजता।",
        "mr": "हा स्वतःला '{word}' म्हणवतो. खरे कस्टमर केअर तुम्हाला पैसे भरण्यासाठी QR पाठवत नाही.",
    },
    "UPI_SCAM_KEYWORD.authority": {
        "en": "It mentions '{word}'. Scammers often pose as army officers, police or officials to gain trust.",
        "hi": "इसमें '{word}' का ज़िक्र है। ठग भरोसा जीतने के लिए अक्सर सेना अधिकारी, पुलिस या अफ़सर बनकर आते हैं।",
        "mr": "यात '{word}' चा उल्लेख आहे. विश्वास मिळवण्यासाठी फसवणूक करणारे अनेकदा सैन्य अधिकारी, पोलीस किंवा अधिकारी असल्याचे भासवतात.",
    },
    "UPI_IMPERSONATION": {
        "en": "The name says '{pn}', but the money goes to an ordinary app UPI ID (@{handle}) that anyone can create. Banks, government offices and big companies don't collect money this way.",
        "hi": "नाम '{pn}' लिखा है, लेकिन पैसा एक साधारण ऐप UPI ID (@{handle}) में जाएगा जिसे कोई भी बना सकता है। बैंक, सरकारी दफ़्तर और बड़ी कंपनियां ऐसे पैसे नहीं लेतीं।",
        "mr": "नाव '{pn}' आहे, पण पैसे एका साध्या ॲप UPI ID (@{handle}) मध्ये जातील, जो कोणीही तयार करू शकतो. बँका, सरकारी कार्यालये आणि मोठ्या कंपन्या अशा प्रकारे पैसे घेत नाहीत.",
    },
    "UPI_BRAND_IN_VPA": {
        "en": "The UPI ID '{vpa}' contains '{brand}' to look official, but it sits on a personal app handle.",
        "hi": "UPI ID '{vpa}' में आधिकारिक दिखने के लिए '{brand}' जोड़ा गया है, लेकिन यह एक निजी ऐप हैंडल पर है।",
        "mr": "UPI ID '{vpa}' मध्ये अधिकृत वाटावे म्हणून '{brand}' जोडले आहे, पण ते वैयक्तिक ॲप हँडलवर आहे.",
    },
    "UPI_OFFICIAL_LOOKALIKE": {
        "en": "'{vpa}' differs by only a letter or two from the official '{official}' ({name}). This is a lookalike.",
        "hi": "'{vpa}' आधिकारिक '{official}' ({name}) से बस एक-दो अक्षर अलग है। यह नकली है।",
        "mr": "'{vpa}' हे अधिकृत '{official}' ({name}) पेक्षा फक्त एक-दोन अक्षरांनी वेगळे आहे. हे बनावट आहे.",
    },
    "UPI_PREFILLED_P2P": {
        "en": "The amount {amount} is already filled in and locked, and the receiver looks like a person, not a shop. Fixed-amount QRs from strangers are a common trick.",
        "hi": "रकम {amount} पहले से भरी और लॉक है, और पाने वाला दुकान नहीं बल्कि कोई व्यक्ति लगता है। अनजान लोगों के फिक्स रकम वाले QR एक आम चाल हैं।",
        "mr": "रक्कम {amount} आधीच भरलेली आणि लॉक आहे, आणि घेणारा दुकान नसून व्यक्ती वाटतो. अनोळखी लोकांचे ठरलेल्या रकमेचे QR ही सामान्य युक्ती आहे.",
    },
    "UPI_BUSINESS_NAME_PERSONAL_VPA": {
        "en": "'{pn}' sounds like a business, but the UPI ID '{vpa}' is a personal mobile number. At a shop, this can mean the sticker was swapped.",
        "hi": "'{pn}' किसी दुकान या संस्था का नाम लगता है, लेकिन UPI ID '{vpa}' एक निजी मोबाइल नंबर है। दुकान पर ऐसा हो तो स्टिकर बदला गया हो सकता है।",
        "mr": "'{pn}' हे दुकान किंवा संस्थेचे नाव वाटते, पण UPI ID '{vpa}' हा वैयक्तिक मोबाइल नंबर आहे. दुकानात असे असल्यास स्टिकर बदललेले असू शकते.",
    },
    "UPI_HIGH_AMOUNT": {
        "en": "Very large amount: {amount}. Double-check before paying.",
        "hi": "बहुत बड़ी रकम: {amount}। भुगतान से पहले दोबारा जांचें।",
        "mr": "खूप मोठी रक्कम: {amount}. पैसे भरण्यापूर्वी पुन्हा तपासा.",
    },
    "UPI_REF_URL": {
        "en": "This payment QR also carries a web link ({url}). We checked it too.",
        "hi": "इस भुगतान QR में एक वेब लिंक ({url}) भी है। हमने उसे भी जांचा।",
        "mr": "या पेमेंट QR मध्ये एक वेब लिंक ({url}) सुद्धा आहे. आम्ही तीही तपासली.",
    },
    "UPI_NOTE_CONTACT": {
        "en": "The payment note contains a phone number or link. Scammers use this to pull you into a call or chat.",
        "hi": "भुगतान नोट में फ़ोन नंबर या लिंक है। ठग इससे आपको कॉल या चैट में खींचते हैं।",
        "mr": "पेमेंट नोटमध्ये फोन नंबर किंवा लिंक आहे. फसवणूक करणारे याद्वारे तुम्हाला कॉल किंवा चॅटमध्ये ओढतात.",
    },
    "UPI_SIGNED": {
        "en": "This QR carries a digital signature. Your UPI app can verify it but we cannot, so still check the name your app shows.",
        "hi": "इस QR में डिजिटल सिग्नेचर है। आपका UPI ऐप इसे जांच सकता है, हम नहीं, इसलिए ऐप में दिखने वाला नाम फिर भी जांचें।",
        "mr": "या QR मध्ये डिजिटल सही आहे. तुमचे UPI ॲप ती तपासू शकते, आम्ही नाही, म्हणून ॲपमध्ये दिसणारे नाव तरीही तपासा.",
    },
    "UPI_SIGN_MALFORMED": {
        "en": "The QR's signature field is broken. The code may have been edited.",
        "hi": "QR का सिग्नेचर हिस्सा खराब है। शायद इसमें बदलाव किया गया है।",
        "mr": "QR चा सही (सिग्नेचर) भाग खराब आहे. कदाचित त्यात बदल केला आहे.",
    },
    "UPI_RISKY_MCC": {
        "en": "Merchant type code {mcc} means '{category}', a high-risk category.",
        "hi": "मर्चेंट कोड {mcc} का मतलब '{category}' है, जो जोखिम वाली श्रेणी है।",
        "mr": "मर्चंट कोड {mcc} म्हणजे '{category}', ही जोखमीची श्रेणी आहे.",
    },
    "EMV_CRC_INVALID": {
        "en": "This Bharat QR's built-in checksum does not match. The code was edited or damaged.",
        "hi": "इस भारत QR का अंदरूनी चेकसम मेल नहीं खाता। कोड बदला गया है या खराब है।",
        "mr": "या भारत QR चा अंतर्गत चेकसम जुळत नाही. कोड बदललेला किंवा खराब आहे.",
    },
    "EMV_NO_UPI": {
        "en": "This Bharat QR has no UPI ID inside. It is meant for card payments.",
        "hi": "इस भारत QR में कोई UPI ID नहीं है। यह कार्ड भुगतान के लिए है।",
        "mr": "या भारत QR मध्ये UPI ID नाही. हा कार्ड पेमेंटसाठी आहे.",
    },
    # ---------------------------------------------------------------- URL
    "URL_DANGEROUS_SCHEME": {
        "en": "This QR contains '{scheme}:' code instead of a normal web link. It can run hidden code, so never open it.",
        "hi": "इस QR में सामान्य वेब लिंक की जगह '{scheme}:' कोड है। यह छिपा कोड चला सकता है, इसे कभी न खोलें।",
        "mr": "या QR मध्ये साध्या वेब लिंकऐवजी '{scheme}:' कोड आहे. तो लपलेला कोड चालवू शकतो, तो कधीही उघडू नका.",
    },
    "URL_INTEL_HIT": {
        "en": "This link is on the {source} list of known phishing or malware sites.",
        "hi": "यह लिंक {source} की ज्ञात फ़िशिंग या मैलवेयर साइटों की सूची में है।",
        "mr": "ही लिंक {source} च्या ओळखीच्या फिशिंग किंवा मालवेअर साइट्सच्या यादीत आहे.",
    },
    "URL_APK_DOWNLOAD": {
        "en": "This link downloads an Android app file ({file}) from outside the Play Store. Fake bank, e-challan and KYC apps steal OTPs and UPI PINs this way.",
        "hi": "यह लिंक Play Store के बाहर से एक Android ऐप फ़ाइल ({file}) डाउनलोड करता है। नकली बैंक, ई-चालान और KYC ऐप इसी तरह OTP और UPI PIN चुराते हैं।",
        "mr": "ही लिंक Play Store बाहेरून एक Android ॲप फाइल ({file}) डाउनलोड करते. बनावट बँक, ई-चलान आणि KYC ॲप्स अशाच प्रकारे OTP आणि UPI PIN चोरतात.",
    },
    "URL_EXE_DOWNLOAD": {
        "en": "This link downloads a program file ({file}). Don't run files from unknown QR codes.",
        "hi": "यह लिंक एक प्रोग्राम फ़ाइल ({file}) डाउनलोड करता है। अनजान QR की फ़ाइलें न चलाएं।",
        "mr": "ही लिंक एक प्रोग्राम फाइल ({file}) डाउनलोड करते. अनोळखी QR मधील फाइल्स चालवू नका.",
    },
    "URL_REMOTE_ACCESS_APP": {
        "en": "This leads to '{app}', a screen-sharing app. Scammers use it to watch your screen and steal your UPI PIN.",
        "hi": "यह '{app}' की ओर ले जाता है, जो स्क्रीन शेयर करने वाला ऐप है। ठग इससे आपकी स्क्रीन देखकर UPI PIN चुराते हैं।",
        "mr": "हे '{app}' कडे नेते, जे स्क्रीन शेअर करणारे ॲप आहे. फसवणूक करणारे याद्वारे तुमची स्क्रीन पाहून UPI PIN चोरतात.",
    },
    "URL_HOMOGLYPH": {
        "en": "'{domain}' uses look-alike letters to imitate '{official}' ({brand}). It is NOT the real site.",
        "hi": "'{domain}' एक जैसे दिखने वाले अक्षरों से '{official}' ({brand}) की नकल करता है। यह असली साइट नहीं है।",
        "mr": "'{domain}' सारख्या दिसणाऱ्या अक्षरांनी '{official}' ({brand}) ची नक्कल करते. ही खरी साइट नाही.",
    },
    "URL_TYPOSQUAT": {
        "en": "'{domain}' is a near-copy of '{official}' ({brand}) with a small spelling change. Fake sites use this trick.",
        "hi": "'{domain}' छोटे से स्पेलिंग बदलाव के साथ '{official}' ({brand}) की लगभग नकल है। नकली साइटें यही चाल चलती हैं।",
        "mr": "'{domain}' हे छोट्या स्पेलिंग बदलासह '{official}' ({brand}) ची जवळपास नक्कल आहे. बनावट साइट्स हीच युक्ती वापरतात.",
    },
    "URL_BRAND_MISUSE": {
        "en": "The link uses the name '{brand}', but the real website address is '{domain}', which does not belong to {brand}.",
        "hi": "लिंक में '{brand}' का नाम है, लेकिन असली वेबसाइट पता '{domain}' है, जो {brand} का नहीं है।",
        "mr": "लिंकमध्ये '{brand}' चे नाव आहे, पण खरा वेबसाइट पत्ता '{domain}' आहे, जो {brand} चा नाही.",
    },
    "URL_GOV_IMPERSONATION": {
        "en": "This looks like a government service, but '{domain}' is not a .gov.in website. Real government sites end in .gov.in or .nic.in.",
        "hi": "यह सरकारी सेवा जैसा दिखता है, लेकिन '{domain}' .gov.in वेबसाइट नहीं है। असली सरकारी साइटें .gov.in या .nic.in पर होती हैं।",
        "mr": "ही सरकारी सेवा वाटते, पण '{domain}' ही .gov.in वेबसाइट नाही. खऱ्या सरकारी साइट्स .gov.in किंवा .nic.in ने संपतात.",
    },
    "URL_NEW_DOMAIN": {
        "en": "'{domain}' was registered only {days} days ago. Most scam sites are brand new.",
        "hi": "'{domain}' सिर्फ़ {days} दिन पहले बनाई गई है। ज़्यादातर धोखेबाज़ साइटें बिल्कुल नई होती हैं।",
        "mr": "'{domain}' फक्त {days} दिवसांपूर्वी तयार झाली आहे. बहुतेक फसव्या साइट्स अगदी नवीन असतात.",
    },
    "URL_USERINFO": {
        "en": "The link is disguised: it starts with '{shown}' but actually opens '{real}'.",
        "hi": "लिंक छिपाया गया है: शुरुआत में '{shown}' दिखता है, लेकिन असल में '{real}' खुलता है।",
        "mr": "लिंक लपवली आहे: सुरुवातीला '{shown}' दिसते, पण प्रत्यक्षात '{real}' उघडते.",
    },
    "URL_IP_HOST": {
        "en": "The link uses a bare number address ({host}) instead of a website name. Genuine banks and shops never do this.",
        "hi": "लिंक में वेबसाइट नाम की जगह सिर्फ़ नंबर वाला पता ({host}) है। असली बैंक या दुकान ऐसा नहीं करते।",
        "mr": "लिंकमध्ये वेबसाइटच्या नावाऐवजी फक्त आकड्यांचा पत्ता ({host}) आहे. खऱ्या बँका किंवा दुकाने असे करत नाहीत.",
    },
    "URL_RISKY_TLD": {
        "en": "The website ending '.{tld}' is cheap and very often used for scam sites.",
        "hi": "वेबसाइट का अंत '.{tld}' सस्ता है और अक्सर धोखेबाज़ साइटों के लिए इस्तेमाल होता है।",
        "mr": "वेबसाइटचा शेवट '.{tld}' स्वस्त आहे आणि अनेकदा फसव्या साइट्ससाठी वापरला जातो.",
    },
    "URL_FREE_HOSTING": {
        "en": "This page is on a free hosting service ({host}) where anyone can publish a site in minutes.",
        "hi": "यह पेज मुफ़्त होस्टिंग ({host}) पर है, जहाँ कोई भी मिनटों में साइट बना सकता है।",
        "mr": "हे पेज मोफत होस्टिंगवर ({host}) आहे, जिथे कोणीही काही मिनिटांत साइट तयार करू शकतो.",
    },
    "URL_PUNYCODE": {
        "en": "The address contains special non-English letters ({unicode}), which are sometimes used to fake a familiar name.",
        "hi": "पते में विशेष गैर-अंग्रेज़ी अक्षर ({unicode}) हैं, जिनसे कभी-कभी जाने-पहचाने नाम की नकल की जाती है।",
        "mr": "पत्त्यात विशेष इंग्रजी नसलेली अक्षरे ({unicode}) आहेत, ज्यांनी कधी कधी ओळखीच्या नावाची नक्कल केली जाते.",
    },
    "URL_SHORTENER": {
        "en": "This short link ({host}) hides the destination. Review the redirect check before opening it.",
        "hi": "यह छोटा लिंक ({host}) मंज़िल छिपाता है। खोलने से पहले रीडायरेक्ट जांच देखें।",
        "mr": "ही छोटी लिंक ({host}) गंतव्य लपवते. उघडण्यापूर्वी रीडायरेक्ट तपासणी पहा.",
    },
    "URL_REDIRECTS": {
        "en": "The link jumps through {hops} redirect(s) and ends at '{final}'.",
        "hi": "लिंक {hops} बार आगे भेजता है और आखिर में '{final}' पर पहुंचता है।",
        "mr": "लिंक {hops} वेळा पुढे पाठवते आणि शेवटी '{final}' वर पोहोचते.",
    },
    "URL_SUSPICIOUS_WORDS": {
        "en": "The address contains bait words: {words}.",
        "hi": "पते में लालच वाले शब्द हैं: {words}।",
        "mr": "पत्त्यात आमिष दाखवणारे शब्द आहेत: {words}.",
    },
    "URL_MANY_SUBDOMAINS": {
        "en": "The address '{host}' is unusually long and layered, a way to hide the real site name.",
        "hi": "पता '{host}' असामान्य रूप से लंबा और कई हिस्सों वाला है। यह असली साइट का नाम छिपाने का तरीका है।",
        "mr": "पत्ता '{host}' असामान्यपणे लांब आणि अनेक भागांचा आहे. खऱ्या साइटचे नाव लपवण्याचा हा मार्ग आहे.",
    },
    "URL_NO_HTTPS": {
        "en": "The link is not secure (http, not https). Never enter passwords, OTP or card details on it.",
        "hi": "लिंक सुरक्षित नहीं है (https नहीं, http)। इस पर पासवर्ड, OTP या कार्ड की जानकारी कभी न डालें।",
        "mr": "लिंक सुरक्षित नाही (https नाही, http). त्यावर पासवर्ड, OTP किंवा कार्डची माहिती कधीही टाकू नका.",
    },
    "URL_ODD_PORT": {
        "en": "The link uses an unusual port ({port}) that normal websites don't need.",
        "hi": "लिंक असामान्य पोर्ट ({port}) का उपयोग करता है, जिसकी सामान्य वेबसाइटों को ज़रूरत नहीं होती।",
        "mr": "लिंक असामान्य पोर्ट ({port}) वापरते, ज्याची साध्या वेबसाइट्सना गरज नसते.",
    },
    "URL_OFFICIAL": {
        "en": "'{domain}' is the official website of {brand}.",
        "hi": "'{domain}' {brand} की आधिकारिक वेबसाइट है।",
        "mr": "'{domain}' ही {brand} ची अधिकृत वेबसाइट आहे.",
    },
    "URL_BANK_IN": {
        "en": "'{domain}' uses .bank.in, a domain that only RBI-regulated banks can get.",
        "hi": "'{domain}' .bank.in का उपयोग करता है, जो केवल RBI द्वारा नियंत्रित बैंकों को मिलता है।",
        "mr": "'{domain}' .bank.in वापरते, जे फक्त RBI-नियंत्रित बँकांनाच मिळते.",
    },
    "URL_GOV_IN": {
        "en": "'{domain}' is an official Indian government website (.gov.in / .nic.in).",
        "hi": "'{domain}' भारत सरकार की आधिकारिक वेबसाइट (.gov.in / .nic.in) है।",
        "mr": "'{domain}' ही भारत सरकारची अधिकृत वेबसाइट (.gov.in / .nic.in) आहे.",
    },
    "URL_OPENS_CHAT": {
        "en": "Opens a {app} chat with {target}. Be careful if anyone there asks for money, an OTP or a 'task fee'.",
        "hi": "यह {target} के साथ {app} चैट खोलता है। अगर वहाँ कोई पैसे, OTP या 'टास्क फीस' मांगे तो सावधान रहें।",
        "mr": "हे {target} सोबत {app} चॅट उघडते. तिथे कोणी पैसे, OTP किंवा 'टास्क फी' मागितल्यास सावध राहा.",
    },
    "URL_APP_INSTALL": {
        "en": "Opens an app install page for '{package}'. Only install apps you were already looking for.",
        "hi": "यह '{package}' ऐप इंस्टॉल करने का पेज खोलता है। वही ऐप इंस्टॉल करें जिसे आप पहले से ढूंढ रहे थे।",
        "mr": "हे '{package}' ॲप इन्स्टॉल करण्याचे पेज उघडते. तुम्ही आधीच शोधत असलेलीच ॲप्स इन्स्टॉल करा.",
    },
    # ---------------------------------------------------------------- WiFi
    "WIFI_INFO": {
        "en": "Joins the Wi-Fi network '{ssid}' ({security}).",
        "hi": "Wi-Fi नेटवर्क '{ssid}' ({security}) से जोड़ता है।",
        "mr": "Wi-Fi नेटवर्क '{ssid}' ({security}) शी जोडते.",
    },
    "WIFI_OPEN": {
        "en": "Joins an OPEN Wi-Fi network '{ssid}' with no password. Anyone nearby can see your traffic, so don't use UPI or banking on it.",
        "hi": "यह बिना पासवर्ड वाले खुले Wi-Fi '{ssid}' से जोड़ता है। आसपास कोई भी आपका डेटा देख सकता है, इसलिए इस पर UPI या बैंकिंग न करें।",
        "mr": "हे पासवर्ड नसलेल्या खुल्या Wi-Fi '{ssid}' शी जोडते. जवळपासचे कोणीही तुमचा डेटा पाहू शकतात, म्हणून त्यावर UPI किंवा बँकिंग करू नका.",
    },
    "WIFI_WEP": {
        "en": "This network uses WEP, an old security that is easily broken. Treat it like open Wi-Fi.",
        "hi": "यह नेटवर्क WEP इस्तेमाल करता है, जो पुरानी और आसानी से टूटने वाली सुरक्षा है। इसे खुले Wi-Fi जैसा ही मानें।",
        "mr": "हे नेटवर्क WEP वापरते, जी जुनी आणि सहज तोडता येणारी सुरक्षा आहे. याला खुल्या Wi-Fi सारखेच समजा.",
    },
    "WIFI_LOOKALIKE": {
        "en": "'{ssid}' imitates a public network like '{real}'. Real public Wi-Fi is chosen from your Wi-Fi settings and never needs a QR. Fake hotspots steal OTPs and passwords.",
        "hi": "'{ssid}' '{real}' जैसे सार्वजनिक नेटवर्क की नकल करता है। असली सार्वजनिक Wi-Fi सेटिंग्स से चुना जाता है, उसके लिए QR की ज़रूरत नहीं होती। नकली हॉटस्पॉट OTP और पासवर्ड चुराते हैं।",
        "mr": "'{ssid}' हे '{real}' सारख्या सार्वजनिक नेटवर्कची नक्कल करते. खरे सार्वजनिक Wi-Fi सेटिंग्समधून निवडले जाते, त्यासाठी QR लागत नाही. बनावट हॉटस्पॉट OTP आणि पासवर्ड चोरतात.",
    },
    "WIFI_HIDDEN": {
        "en": "This adds a HIDDEN network. You can't see it in your list to check that it is real.",
        "hi": "यह एक छिपा हुआ नेटवर्क जोड़ता है। आप इसे अपनी सूची में देखकर जांच नहीं सकते कि यह असली है।",
        "mr": "हे एक लपलेले नेटवर्क जोडते. ते खरे आहे का हे तुम्ही यादीत पाहून तपासू शकत नाही.",
    },
    # ---------------------------------------------------------------- Phone / SMS / misc
    "TEL_USSD": {
        "en": "'{number}' is a phone CODE, not a number. Codes like *401# or *21* forward your calls, including bank OTP calls, to a scammer. Never dial it.",
        "hi": "'{number}' फ़ोन नंबर नहीं, एक कोड है। *401# या *21* जैसे कोड आपकी कॉल, बैंक OTP कॉल समेत, ठग को फ़ॉरवर्ड कर देते हैं। इसे कभी डायल न करें।",
        "mr": "'{number}' हा फोन नंबर नाही, तर कोड आहे. *401# किंवा *21* सारखे कोड तुमचे कॉल, बँकेच्या OTP कॉलसह, फसवणूक करणाऱ्याकडे वळवतात. तो कधीही डायल करू नका.",
    },
    "TEL_FOREIGN": {
        "en": "'{number}' is an international number ({country}). Calling back can cost a lot; this is a common missed-call scam.",
        "hi": "'{number}' एक अंतरराष्ट्रीय नंबर ({country}) है। वापस कॉल करना महंगा पड़ सकता है; यह एक आम मिस्ड-कॉल धोखा है।",
        "mr": "'{number}' हा आंतरराष्ट्रीय नंबर ({country}) आहे. परत कॉल करणे महाग पडू शकते; ही सामान्य मिस्ड-कॉल फसवणूक आहे.",
    },
    "TEL_SHORTCODE": {
        "en": "'{number}' is a short service code. Check what it is before calling.",
        "hi": "'{number}' एक छोटा सर्विस कोड है। कॉल करने से पहले जांच लें कि यह क्या है।",
        "mr": "'{number}' हा छोटा सेवा कोड आहे. कॉल करण्यापूर्वी तो काय आहे ते तपासा.",
    },
    "TEL_HELPLINE_1930": {
        "en": "1930 is the official National Cyber Crime Helpline.",
        "hi": "1930 राष्ट्रीय साइबर अपराध हेल्पलाइन का आधिकारिक नंबर है।",
        "mr": "1930 हा राष्ट्रीय सायबर गुन्हे हेल्पलाइनचा अधिकृत नंबर आहे.",
    },
    "TEL_1600_INFO": {
        "en": "Numbers starting with 1600 are used by banks to CALL you. They are not helplines; get helpline numbers from your bank's app or website.",
        "hi": "1600 से शुरू होने वाले नंबर बैंक आपको कॉल करने के लिए इस्तेमाल करते हैं। ये हेल्पलाइन नहीं हैं; हेल्पलाइन नंबर अपने बैंक के ऐप या वेबसाइट से लें।",
        "mr": "1600 ने सुरू होणारे नंबर बँका तुम्हाला कॉल करण्यासाठी वापरतात. ते हेल्पलाइन नाहीत; हेल्पलाइन नंबर तुमच्या बँकेच्या ॲप किंवा वेबसाइटवरून घ्या.",
    },
    "SMS_INFO": {
        "en": "Sends an SMS to {number} with the text: \"{body}\".",
        "hi": "{number} पर यह SMS भेजता है: \"{body}\"।",
        "mr": "{number} वर हा SMS पाठवते: \"{body}\".",
    },
    "SMS_SHORTCODE": {
        "en": "The SMS goes to a short code ({number}). It may subscribe you to a paid service.",
        "hi": "SMS एक छोटे कोड ({number}) पर जाता है। इससे आप किसी पेड सर्विस से जुड़ सकते हैं।",
        "mr": "SMS एका छोट्या कोडवर ({number}) जातो. यामुळे तुम्ही सशुल्क सेवेला जोडले जाऊ शकता.",
    },
    "SMS_FOREIGN": {
        "en": "The SMS goes to an international number ({number}) and may cost money.",
        "hi": "SMS एक अंतरराष्ट्रीय नंबर ({number}) पर जाता है और पैसे लग सकते हैं।",
        "mr": "SMS आंतरराष्ट्रीय नंबरवर ({number}) जातो आणि पैसे लागू शकतात.",
    },
    "TEXT_SCAM_KEYWORD": {
        "en": "The text mentions '{word}', a common scam bait.",
        "hi": "टेक्स्ट में '{word}' का ज़िक्र है, जो धोखे का आम चारा है।",
        "mr": "मजकुरात '{word}' चा उल्लेख आहे, जे फसवणुकीचे सामान्य आमिष आहे.",
    },
    "TEXT_CONTAINS": {
        "en": "The text contains a link or UPI ID: {item}. We checked it too.",
        "hi": "टेक्स्ट में एक लिंक या UPI ID है: {item}। हमने उसे भी जांचा।",
        "mr": "मजकुरात एक लिंक किंवा UPI ID आहे: {item}. आम्ही तीही तपासली.",
    },
    "VCARD_BANK_PERSONAL": {
        "en": "This saves a contact '{name}' with a personal mobile number ({number}). Banks and companies don't share helplines this way.",
        "hi": "यह '{name}' नाम का संपर्क एक निजी मोबाइल नंबर ({number}) के साथ सेव करता है। बैंक और कंपनियां हेल्पलाइन ऐसे नहीं देतीं।",
        "mr": "हे '{name}' नावाचा संपर्क वैयक्तिक मोबाइल नंबरसह ({number}) सेव्ह करते. बँका आणि कंपन्या हेल्पलाइन अशा प्रकारे देत नाहीत.",
    },
    "CRYPTO_PAYMENT": {
        "en": "Crypto payment ({coin}) to {address}. Crypto transfers can never be reversed, so confirm the address with the receiver another way.",
        "hi": "{address} पर क्रिप्टो भुगतान ({coin})। क्रिप्टो ट्रांसफर कभी वापस नहीं होते, इसलिए पते की पुष्टि प्राप्तकर्ता से किसी और तरीके से करें।",
        "mr": "{address} वर क्रिप्टो पेमेंट ({coin}). क्रिप्टो ट्रान्सफर कधीही परत होत नाहीत, म्हणून पत्ता प्राप्तकर्त्याकडून दुसऱ्या मार्गाने खात्री करा.",
    },
    "FIDO_LOGIN": {
        "en": "This is a sign-in request for another device (passkey). Only approve it if YOU are signing in on a computer in front of you right now.",
        "hi": "यह किसी दूसरे डिवाइस के लिए साइन-इन अनुरोध (पासकी) है। इसे तभी मंज़ूर करें जब आप खुद अभी अपने सामने के कंप्यूटर पर साइन-इन कर रहे हों।",
        "mr": "ही दुसऱ्या डिव्हाइससाठी साइन-इन विनंती (पासकी) आहे. तुम्ही स्वतः आत्ता समोरच्या संगणकावर साइन-इन करत असाल तरच मंजूर करा.",
    },
    "OTP_SECRET": {
        "en": "This adds a 2-factor code for '{issuer}'. The secret key is inside the QR, so never share a photo of it.",
        "hi": "यह '{issuer}' के लिए 2-फ़ैक्टर कोड जोड़ता है। गुप्त कुंजी QR में है, इसलिए इसकी फ़ोटो कभी शेयर न करें।",
        "mr": "हे '{issuer}' साठी 2-फॅक्टर कोड जोडते. गुप्त किल्ली QR मध्ये आहे, म्हणून त्याचा फोटो कधीही शेअर करू नका.",
    },
    "APP_REMOTE_ACCESS": {
        "en": "This installs or opens '{package}', a remote-control app. Scammers ask you to install it so they can see your screen and UPI PIN.",
        "hi": "यह '{package}' इंस्टॉल करता या खोलता है, जो रिमोट-कंट्रोल ऐप है। ठग इसे इंस्टॉल करवाते हैं ताकि वे आपकी स्क्रीन और UPI PIN देख सकें।",
        "mr": "हे '{package}' इन्स्टॉल करते किंवा उघडते, जे रिमोट-कंट्रोल ॲप आहे. तुमची स्क्रीन आणि UPI PIN पाहण्यासाठी फसवणूक करणारे ते इन्स्टॉल करायला सांगतात.",
    },
    "INTENT_SCHEME": {
        "en": "This directly opens an app on your phone ({package}). Only continue if you expected that app.",
        "hi": "यह सीधे आपके फ़ोन का एक ऐप ({package}) खोलता है। तभी आगे बढ़ें जब आप वही ऐप खोलना चाहते थे।",
        "mr": "हे थेट तुमच्या फोनमधील ॲप ({package}) उघडते. तेच ॲप अपेक्षित असेल तरच पुढे जा.",
    },
    "COMMUNITY_REPORTED": {
        "en": "This QR has {count} community report(s). These reports are unverified and do not prove fraud.",
        "hi": "इस QR की {count} सामुदायिक शिकायतें हैं। ये अपुष्ट हैं और धोखे का प्रमाण नहीं हैं।",
        "mr": "या QR बद्दल {count} समुदायाच्या तक्रारी आहेत. त्या अपुष्ट आहेत आणि फसवणुकीचा पुरावा नाहीत.",
    },
    # ---------------------------------------------------------------- Headlines
    "HEAD_UPI_PAY_AMOUNT": {
        "en": "You are about to PAY {amount} to “{pn}” ({vpa})",
        "hi": "आप “{pn}” ({vpa}) को {amount} का भुगतान करने वाले हैं",
        "mr": "तुम्ही “{pn}” ({vpa}) ला {amount} देणार आहात",
    },
    "HEAD_UPI_PAY": {
        "en": "You are about to PAY “{pn}” ({vpa}). You will type the amount.",
        "hi": "आप “{pn}” ({vpa}) को भुगतान करने वाले हैं। रकम आप खुद डालेंगे।",
        "mr": "तुम्ही “{pn}” ({vpa}) ला पैसे देणार आहात. रक्कम तुम्ही स्वतः टाकाल.",
    },
    "HEAD_UPI_MANDATE": {
        "en": "This sets up AUTOPAY of up to {amount} to “{pn}”",
        "hi": "यह “{pn}” के लिए {amount} तक का ऑटोपे चालू करता है",
        "mr": "हे “{pn}” साठी {amount} पर्यंतचे ऑटोपे सुरू करते",
    },
    "HEAD_UPI_OTHER": {"en": "Unusual UPI request", "hi": "असामान्य UPI अनुरोध", "mr": "असामान्य UPI विनंती"},
    "HEAD_BHARAT_QR_CARD": {
        "en": "Card payment QR (Bharat QR) for “{pn}”",
        "hi": "“{pn}” के लिए कार्ड भुगतान QR (भारत QR)",
        "mr": "“{pn}” साठी कार्ड पेमेंट QR (भारत QR)",
    },
    "HEAD_URL": {"en": "Opens the website {host}", "hi": "वेबसाइट {host} खोलता है", "mr": "वेबसाइट {host} उघडते"},
    "HEAD_DANGEROUS_SCHEME": {
        "en": "Contains hidden code, not a website",
        "hi": "इसमें वेबसाइट नहीं, छिपा कोड है",
        "mr": "यात वेबसाइट नाही, लपलेला कोड आहे",
    },
    "HEAD_WIFI": {"en": "Connects to Wi-Fi “{ssid}”", "hi": "Wi-Fi “{ssid}” से जोड़ता है", "mr": "Wi-Fi “{ssid}” शी जोडते"},
    "HEAD_TEL": {"en": "Calls {number}", "hi": "{number} पर कॉल करता है", "mr": "{number} वर कॉल करते"},
    "HEAD_SMS": {"en": "Sends an SMS to {number}", "hi": "{number} पर SMS भेजता है", "mr": "{number} वर SMS पाठवते"},
    "HEAD_EMAIL": {"en": "Writes an email to {to}", "hi": "{to} को ईमेल लिखता है", "mr": "{to} ला ईमेल लिहिते"},
    "HEAD_GEO": {"en": "Opens a map location", "hi": "नक्शे पर एक जगह खोलता है", "mr": "नकाशावर एक ठिकाण उघडते"},
    "HEAD_VCARD": {"en": "Saves a contact: {name}", "hi": "संपर्क सेव करता है: {name}", "mr": "संपर्क सेव्ह करते: {name}"},
    "HEAD_EVENT": {"en": "Adds a calendar event: {title}", "hi": "कैलेंडर इवेंट जोड़ता है: {title}", "mr": "कॅलेंडर इव्हेंट जोडते: {title}"},
    "HEAD_APP": {"en": "Opens an app: {package}", "hi": "एक ऐप खोलता है: {package}", "mr": "एक ॲप उघडते: {package}"},
    "HEAD_CHAT": {"en": "Opens a {app} chat with {target}", "hi": "{target} के साथ {app} चैट खोलता है", "mr": "{target} सोबत {app} चॅट उघडते"},
    "HEAD_CRYPTO": {"en": "Crypto payment ({coin})", "hi": "क्रिप्टो भुगतान ({coin})", "mr": "क्रिप्टो पेमेंट ({coin})"},
    "HEAD_FIDO": {"en": "Passkey sign-in request", "hi": "पासकी साइन-इन अनुरोध", "mr": "पासकी साइन-इन विनंती"},
    "HEAD_OTP": {"en": "Adds a 2-factor code for {issuer}", "hi": "{issuer} के लिए 2-फ़ैक्टर कोड जोड़ता है", "mr": "{issuer} साठी 2-फॅक्टर कोड जोडते"},
    "HEAD_TEXT": {"en": "Plain text", "hi": "साधारण टेक्स्ट", "mr": "साधा मजकूर"},
    # ---------------------------------------------------------------- Shopkeeper mode
    "SHOP_MATCH": {
        "en": "The payee address matches your saved QR ({vpa}). Review the other findings before accepting payments.",
        "hi": "प्राप्तकर्ता का पता आपके सहेजे QR से मेल खाता है ({vpa})। भुगतान से पहले बाकी जांचें देखें।",
        "mr": "प्राप्तकर्त्याचा पत्ता तुमच्या जतन केलेल्या QR शी जुळतो ({vpa}). पेमेंटपूर्वी इतर तपासण्या पहा.",
    },
    "SHOP_MISMATCH": {
        "en": "This is NOT your QR! Payments would go to {found} instead of your {expected}. Remove this sticker now and report it on 1930.",
        "hi": "यह आपका QR नहीं है! पैसे आपके {expected} की जगह {found} में जाएंगे। यह स्टिकर तुरंत हटाएं और 1930 पर शिकायत करें।",
        "mr": "हा तुमचा QR नाही! पैसे तुमच्या {expected} ऐवजी {found} मध्ये जातील. हा स्टिकर लगेच काढा आणि 1930 वर तक्रार करा.",
    },
    "SHOP_NAME_CHANGED": {
        "en": "The payee name changed from “{expected}” to “{found}”.",
        "hi": "प्राप्तकर्ता का नाम “{expected}” से बदलकर “{found}” हो गया है।",
        "mr": "प्राप्तकर्त्याचे नाव “{expected}” वरून “{found}” झाले आहे.",
    },
    "SHOP_NOT_UPI": {
        "en": "A valid UPI payment identity could not be read from this QR. Check the sticker against your saved original.",
        "hi": "इस QR से सही UPI भुगतान पहचान नहीं पढ़ी जा सकी। सहेजे गए असली QR से तुलना करें।",
        "mr": "या QR मधून वैध UPI पेमेंट ओळख वाचता आली नाही. जतन केलेल्या मूळ QR शी तुलना करा.",
    },
}


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "?"


def render(code: str, params: dict | None = None, variant: str | None = None) -> dict[str, str]:
    """Render a message in all languages. Unknown codes fall back to the code itself."""
    params = params or {}
    tmpl = M.get(f"{code}.{variant}") if variant else None
    tmpl = tmpl or M.get(code)
    if tmpl is None:
        return {lang: code for lang in LANGS}
    safe = _SafeDict({k: ("" if v is None else v) for k, v in params.items()})
    return {lang: tmpl[lang].format_map(safe) for lang in LANGS}
