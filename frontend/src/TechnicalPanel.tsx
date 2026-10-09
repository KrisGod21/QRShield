import { useState } from "react";
import type { Lang, TechnicalFinding } from "./api";
import { Icon } from "./Icon";

const copy = {
  title: ["Technical inspection", "तकनीकी जांच", "तांत्रिक तपासणी"],
  subtitle: [
    "Evidence behind this result",
    "इस परिणाम के पीछे की जांच",
    "या निकालामागील तपासणी",
  ],
  coverage: ["Observed checks", "पूरी हुई जांचें", "पूर्ण झालेल्या तपासण्या"],
  note: [
    "A passed check confirms that property only. Missing checks and fixture data are shown explicitly.",
    "सफल जांच केवल उस गुण की पुष्टि करती है। अधूरी जांच और नमूना डेटा अलग दिखाए गए हैं।",
    "पूर्ण तपासणी फक्त त्या गुणाची खात्री देते. अपूर्ण तपासण्या आणि नमुना डेटा वेगळे दाखवले आहेत.",
  ],
  all: ["All findings", "सभी जांचें", "सर्व तपासण्या"],
  attention: ["Needs attention", "ध्यान दें", "लक्ष द्या"],
  unavailable: ["Unavailable", "अनुपलब्ध", "अनुपलब्ध"],
  empty: [
    "No findings in this filter",
    "इस फिल्टर में कोई जांच नहीं",
    "या फिल्टरमध्ये तपासणी नाही",
  ],
  pass: ["Checked", "जांचा गया", "तपासले"],
  warn: ["Review", "समीक्षा करें", "पुन्हा तपासा"],
  fail: ["Flagged", "चेतावनी", "धोक्याची नोंद"],
  info: ["Observed", "देखा गया", "निरीक्षण"],
  demo: ["Demo fixture", "Demo नमूना", "Demo नमुना"],
  missing: [
    "Detailed inspection is unavailable for this result. Scan again after refreshing the app.",
    "इस परिणाम की विस्तृत जांच उपलब्ध नहीं है। ऐप रीफ्रेश करके फिर स्कैन करें।",
    "या निकालाची सविस्तर तपासणी उपलब्ध नाही. ॲप रीफ्रेश करून पुन्हा स्कॅन करा.",
  ],
} as const;

export function TechnicalPanel({
  lang,
  findings = [],
}: {
  lang: Lang;
  findings?: TechnicalFinding[];
}) {
  const [filter, setFilter] = useState<"all" | "attention" | "unavailable">(
    "all",
  );
  const index = lang === "hi" ? 1 : lang === "mr" ? 2 : 0;
  const label = (key: keyof typeof copy) => copy[key][index];
  const completed = findings.filter((f) =>
    ["pass", "warn", "fail", "info"].includes(f.status),
  ).length;
  const shown = findings.filter(
    (f) =>
      filter === "all" ||
      (filter === "attention"
        ? ["warn", "fail"].includes(f.status)
        : f.status === "unavailable"),
  );
  return (
    <section className="technical-panel" aria-label={label("title")}>
      <div className="technical-heading">
        <div>
          <span className="eyebrow">{label("subtitle")}</span>
          <h3>{label("title")}</h3>
        </div>
        <span className="technical-count">
          <b>
            {completed}/{findings.length}
          </b>
          {label("coverage")}
        </span>
      </div>
      <p className="technical-note">{label("note")}</p>
      {!findings.length && <p className="technical-note">{label("missing")}</p>}
      {findings.length > 0 && (
        <div className="technical-filters" aria-label={label("title")}>
          {(["all", "attention", "unavailable"] as const).map((key) => (
            <button
              key={key}
              className={filter === key ? "on" : ""}
              aria-pressed={filter === key}
              onClick={() => setFilter(key)}
            >
              {label(key)}
            </button>
          ))}
        </div>
      )}
      <div className="technical-findings">
        {shown.map((finding, i) => (
          <details
            className={`technical-finding audit-${finding.status}`}
            key={`${finding.id}-${finding.scope}-${i}`}
          >
            <summary>
              <Icon
                name={
                  finding.status === "pass"
                    ? "check"
                    : ["warn", "fail"].includes(finding.status)
                      ? "alert"
                      : finding.status === "unavailable"
                        ? "close"
                        : "shield"
                }
                size={16}
              />
              <span className="finding-main">
                <b>{finding.label[lang]}</b>
                <code>{finding.value}</code>
              </span>
              <span className="audit-status">{label(finding.status)}</span>
            </summary>
            <div className="finding-detail">
              <p>{finding.detail[lang]}</p>
              {finding.scope && <code>{finding.scope}</code>}
            </div>
          </details>
        ))}
        {findings.length > 0 && !shown.length && (
          <p className="technical-empty">{label("empty")}</p>
        )}
      </div>
    </section>
  );
}
