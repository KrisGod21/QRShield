import { useEffect, useRef, useState } from "react";
import {
  analyze,
  report,
  shopRegister,
  shopVerify,
  type AnalyzeResult,
  type Intent,
  type Lang,
  type ShopInfo,
  type VerifyResult,
} from "./api";
import { CameraScanner, decodeFile } from "./scanner";
import { CHECK_NAMES, t } from "./i18n";
import { c } from "./content";
import { Icon, QrMark } from "./Icon";

type Tab = "scan" | "history" | "shop";
type Source = "camera" | "image" | "text";
interface HistoryItem {
  payload: string;
  verdict: string;
  headline: Record<Lang, string>;
  ts: number;
  score: number;
  intent?: Intent;
}

const store = {
  get<T>(k: string, d: T): T {
    try {
      const v = localStorage.getItem(k);
      return v ? (JSON.parse(v) as T) : d;
    } catch {
      return d;
    }
  },
  set(k: string, v: unknown) {
    try {
      localStorage.setItem(k, JSON.stringify(v));
    } catch {
      /* private mode */
    }
  },
};

export default function Workspace({
  lang,
  tab,
  setTab,
  scanRequest,
}: {
  lang: Lang;
  tab: Tab;
  setTab: (tab: Tab) => void;
  scanRequest: number;
}) {
  const [intent, setIntent] = useState<Intent>("check");
  const [result, setResult] = useState<AnalyzeResult | null>(null);
  const [payload, setPayload] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState<HistoryItem[]>(() => {
    const items = store.get<HistoryItem[]>("qrs_history", []);
    return Array.isArray(items)
      ? items.filter(
          (h) =>
            h &&
            typeof h.payload === "string" &&
            !/^(WIFI:|otpauth:)/i.test(h.payload),
        )
      : [];
  });
  const running = useRef(false);

  useEffect(() => {
    store.set("qrs_lang", lang);
    document.documentElement.lang = lang;
  }, [lang]);
  useEffect(() => {
    store.set("qrs_history", history);
  }, [history]);
  useEffect(() => {
    setResult(null);
    setPayload("");
    setError("");
  }, [scanRequest]);

  async function run(
    text: string,
    source: Source,
    scanIntent: Intent = intent,
  ) {
    if (running.current) return;
    running.current = true;
    setIntent(scanIntent);
    setPayload(text);
    setError("");
    setResult(null);
    setLoading(true);
    document
      .getElementById("scan-desk")
      ?.scrollIntoView({
        block: "start",
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
          ? "auto"
          : "smooth",
      });
    navigator.vibrate?.(40);
    try {
      const r = await analyze(text, scanIntent, source);
      setResult(r);
      if (r.verdict === "DANGER") navigator.vibrate?.([120, 60, 120]);
      if (!/^(WIFI:|otpauth:)/i.test(text)) {
        const item = {
          payload: text,
          verdict: r.verdict,
          headline: r.headline,
          ts: Date.now(),
          score: r.score,
          intent: scanIntent,
        };
        setHistory((previous) => {
          const next = [
            item,
            ...previous.filter(
              (h) => h.payload !== text || h.intent !== scanIntent,
            ),
          ].slice(0, 50);
          store.set("qrs_history", next);
          return next;
        });
      }
    } catch {
      setError(t(lang, "netError"));
    } finally {
      running.current = false;
      setLoading(false);
    }
  }

  const reset = () => {
    setResult(null);
    setPayload("");
    setError("");
  };

  return (
    <div className="app">
      <nav className="tabs" aria-label="QR tools">
        {(["scan", "history", "shop"] as Tab[]).map((k) => (
          <button
            key={k}
            className={tab === k ? "on" : ""}
            aria-pressed={tab === k}
            onClick={() => {
              setTab(k);
              if (k === "scan") reset();
            }}
          >
            <Icon name={k} />
            {t(lang, k)}
            {k === "history" && history.length > 0 && (
              <span className="tab-count">{history.length}</span>
            )}
          </button>
        ))}
      </nav>

      <div className="desk-content">
        {tab === "scan" &&
          (loading || result || error ? (
            <ResultView
              key={result?.id || (loading ? "loading" : "error")}
              lang={lang}
              loading={loading}
              result={result}
              error={error}
              payload={payload}
              onBack={reset}
            />
          ) : (
            <ScanView
              lang={lang}
              intent={intent}
              setIntent={setIntent}
              onCode={run}
            />
          ))}
        {tab === "history" && (
          <HistoryView
            lang={lang}
            items={history}
            onOpen={(h) => {
              setTab("scan");
              run(h.payload, "text", h.intent || "check");
            }}
            onClear={() => {
              setHistory([]);
              store.set("qrs_history", []);
            }}
          />
        )}
        {tab === "shop" && <ShopView lang={lang} />}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ Scan
function ScanView({
  lang,
  intent,
  setIntent,
  onCode,
}: {
  lang: Lang;
  intent: Intent;
  setIntent: (i: Intent) => void;
  onCode: (s: string, src: Source, intent?: Intent) => void;
}) {
  return (
    <section className="scan-layout">
      <div>
        <p className="label">{t(lang, "whatDoing")}</p>
        <div className="chips">
          {(["check", "pay_shop", "receive", "pay_bill"] as Intent[]).map(
            (i) => (
              <button
                key={i}
                className={`chip ${intent === i ? "on" : ""} ${i === "receive" ? "warn" : ""}`}
                aria-pressed={intent === i}
                onClick={() => setIntent(i)}
              >
                {t(lang, i)}
              </button>
            ),
          )}
        </div>
        <QrInput lang={lang} onCode={onCode} />
      </div>
      <aside className="scan-aside">
        <span className="aside-icon">
          <Icon name="shield" size={28} />
        </span>
        <h3>{c(lang, "guardTitle")}</h3>
        <p>{c(lang, "guardBody")}</p>
        <div className="sample-box">
          <span className="small-label">{c(lang, "demoTitle")}</span>
          <button
            onClick={() =>
              onCode(
                "upi://pay?pa=qrshield.demo.kirana@ybl&pn=Ramesh%20Kirana%20Store",
                "text",
                "pay_shop",
              )
            }
          >
            <Icon name="shop" size={17} />
            {c(lang, "sampleShop")}
            <Icon name="arrow" size={16} />
          </button>
          <button
            onClick={() =>
              onCode(
                "upi://pay?pa=refund.desk2291@ybl&pn=Amazon%20Refund%20Dept&am=4999.00&tn=Scan%20to%20receive%20your%20refund",
                "text",
                "receive",
              )
            }
          >
            <Icon name="alert" size={17} />
            {c(lang, "sampleRefund")}
            <Icon name="arrow" size={16} />
          </button>
          <button
            onClick={() =>
              onCode("https://onlinesbі.test/login", "text", "check")
            }
          >
            <Icon name="link" size={17} />
            {c(lang, "sampleUrl")}
            <Icon name="arrow" size={16} />
          </button>
          <small>{c(lang, "sampleNote")}</small>
        </div>
        <div className="privacy-note">
          <Icon name="lock" size={14} />
          {c(lang, "privacy")}
        </div>
      </aside>
    </section>
  );
}

function QrInput({
  lang,
  onCode,
  compact,
}: {
  lang: Lang;
  onCode: (s: string, src: Source) => void;
  compact?: boolean;
}) {
  const video = useRef<HTMLVideoElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const scanner = useRef<CameraScanner | null>(null);
  const [active, setActive] = useState(false);
  const [msg, setMsg] = useState("");
  const [text, setText] = useState("");
  const [decoding, setDecoding] = useState(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      scanner.current?.stop();
    };
  }, []);

  async function startCam() {
    setMsg("");
    if (!video.current || active) return;
    scanner.current = new CameraScanner(video.current, (code) => {
      if (mounted.current) {
        setActive(false);
        onCode(code, "camera");
      }
    });
    try {
      setActive(true);
      await scanner.current.start();
    } catch {
      scanner.current?.stop();
      if (mounted.current) {
        setActive(false);
        setMsg(t(lang, "camError"));
      }
    }
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    scanner.current?.stop();
    setActive(false);
    setDecoding(true);
    setMsg("");
    try {
      const code = await decodeFile(f);
      if (mounted.current) {
        if (code) onCode(code, "image");
        else setMsg(t(lang, "noQr"));
      }
    } catch {
      if (mounted.current) setMsg(t(lang, "noQr"));
    } finally {
      if (mounted.current) setDecoding(false);
    }
  }

  return (
    <div className={`qrinput ${compact ? "compact" : ""}`}>
      <div className={`viewfinder ${active ? "live" : ""}`}>
        <video
          ref={video}
          muted
          playsInline
          className={active ? "" : "hidden-video"}
        />
        {!active && (
          <button
            className="camera-trigger"
            onClick={startCam}
            disabled={decoding}
          >
            <span className="viewfinder-code">
              <QrMark />
              <span className="finder-beam" />
            </span>
            <span className="camera-title">
              {decoding ? t(lang, "checking") : c(lang, "camera")}
            </span>
            <span className="camera-caption">{c(lang, "cameraBody")}</span>
            <span className="camera-prompt">
              <Icon name="scan" size={15} />
              {t(lang, "startCamera")}
            </span>
          </button>
        )}
        {active && (
          <div className="vf-frame">
            <i />
            <i />
            <i />
            <i />
            <em>{t(lang, "pointCamera")}</em>
          </div>
        )}
        {active && (
          <button
            className="btn stop-camera"
            onClick={() => {
              scanner.current?.stop();
              setActive(false);
            }}
          >
            <Icon name="close" size={15} />
            {c(lang, "stopCamera")}
          </button>
        )}
      </div>
      {msg && <p className="msg">{msg}</p>}
      <div className="row">
        <button
          className="btn ghost"
          onClick={() => fileInput.current?.click()}
          disabled={decoding}
        >
          <Icon name="upload" size={18} />
          {t(lang, "upload")}
        </button>
        <input
          ref={fileInput}
          type="file"
          accept="image/*"
          onChange={onFile}
          hidden
          disabled={decoding}
          aria-label={t(lang, "upload")}
        />
      </div>
      <details className="paste">
        <summary>{t(lang, "paste")}</summary>
        <textarea
          aria-label={c(lang, "inputHint")}
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={3}
          maxLength={4096}
          placeholder="upi://pay?pa=…  |  https://…  |  WIFI:…"
        />
        <button
          className="btn primary"
          disabled={!text.trim()}
          onClick={() => {
            scanner.current?.stop();
            onCode(text.trim(), "text");
          }}
        >
          {t(lang, "analyze")}
          <Icon name="arrow" size={17} />
        </button>
      </details>
    </div>
  );
}

// ------------------------------------------------------------------ Result
function ResultView({
  lang,
  loading,
  result,
  error,
  payload,
  onBack,
}: {
  lang: Lang;
  loading: boolean;
  result: AnalyzeResult | null;
  error: string;
  payload: string;
  onBack: () => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [agree, setAgree] = useState(false);
  const [reported, setReported] = useState<number | null>(null);
  const [reporting, setReporting] = useState(false);
  const [reason, setReason] = useState("");
  const [reportError, setReportError] = useState("");
  const [reportBusy, setReportBusy] = useState(false);

  if (loading)
    return (
      <div className="loading" role="status">
        <div className="loading-symbol">
          <QrMark />
          <span className="finder-beam" />
        </div>
        <h3>{t(lang, "checking")}</h3>
        <div className="loading-progress" />
      </div>
    );
  if (error || !result)
    return (
      <div className="card danger-soft">
        <p>{error}</p>
        <button className="btn" onClick={onBack}>
          {t(lang, "scanAgain")}
        </button>
      </div>
    );

  const r = result;
  const s = r.summary;
  const isUpi = r.kind.startsWith("upi") || (r.kind === "bharat_qr" && s.vpa);
  const reasons = r.signals.filter(
    (x) =>
      x.code !== "UPI_PAY_INFO" &&
      x.code !== "WIFI_INFO" &&
      x.code !== "SMS_INFO" &&
      x.code !== "TEXT_CONTAINS",
  );
  const bad = reasons.filter((x) => x.weight > 0);
  const ussd = r.signals.some((x) => x.code === "TEL_USSD");
  const secret = /^(WIFI:|otpauth:)/i.test(payload);
  const canOpen =
    !ussd &&
    !s.invalid_url &&
    [
      "url",
      "app",
      "upi_pay",
      "upi_mandate",
      "tel",
      "sms",
      "email",
      "geo",
    ].includes(r.kind);

  function openIt() {
    if (!canOpen) return;
    if (r.verdict !== "SAFE" && !confirming) {
      setConfirming(true);
      return;
    }
    if (r.kind === "url")
      window.open(s.url || payload, "_blank", "noopener,noreferrer");
    else if (r.kind === "app") window.location.href = payload;
    else if (
      isUpi ||
      r.kind === "tel" ||
      r.kind === "sms" ||
      r.kind === "email" ||
      r.kind === "geo"
    )
      window.location.href = payload;
    setConfirming(false);
  }

  async function doReport() {
    if (reportBusy) return;
    setReportBusy(true);
    setReportError("");
    try {
      const res = await report(payload, reason);
      setReported(res.count);
      setReporting(false);
    } catch (e) {
      setReportError(e instanceof Error ? e.message : c(lang, "reportError"));
    } finally {
      setReportBusy(false);
    }
  }

  return (
    <section className="result" aria-live="polite">
      <div className="result-topline">
        <span className="eyebrow">{c(lang, "result")}</span>
        <span className="result-meta">{r.kind.replace(/_/g, " ")}</span>
      </div>
      <div className={`verdict v-${r.verdict}`}>
        <span className="vicon">
          <Icon
            name={
              r.verdict === "SAFE"
                ? "check"
                : r.verdict === "DANGER"
                  ? "close"
                  : "alert"
            }
            size={24}
          />
        </span>
        <div>
          <b>{t(lang, r.verdict)}</b>
          <small>
            {c(lang, "risk")} {r.score}/100 · {r.elapsed_ms} ms
            {r.demo ? ` · ${t(lang, "demo")}` : ""}
          </small>
        </div>
      </div>

      <h2 className="headline">{r.headline[lang]}</h2>
      {secret && (
        <p className="privacy-note">
          <Icon name="lock" size={15} />
          {c(lang, "secret")}
        </p>
      )}

      {isUpi && (
        <div className="paycard">
          <div className="pay-top">
            <span className="tag">{t(lang, "youPay")}</span>
            {s.amount_fmt ? (
              <span className="amt">
                {s.amount_fmt}
                {s.amount_locked && (
                  <em>
                    <Icon name="lock" size={11} /> {t(lang, "locked")}
                  </em>
                )}
              </span>
            ) : (
              <span className="amt small">{t(lang, "amountYou")}</span>
            )}
          </div>
          <div className="payee">
            <span>{t(lang, "to")}</span>
            <b>{s.pn || "—"}</b>
            <code>{s.vpa}</code>
          </div>
          {s.note && <div className="note">“{s.note}”</div>}
          <div className="ribbon">
            <Icon name="alert" size={13} /> {t(lang, "neverReceive")}
          </div>
        </div>
      )}
      {r.kind === "url" && (
        <div className="kv">
          <code className="url">
            {s.final_url && s.final_url !== s.url
              ? `${s.url} → ${s.final_url}`
              : s.url}
          </code>
          {typeof s.domain_age_days === "number" && (
            <span className="pill">🗓 {s.domain_age_days} d</span>
          )}
        </div>
      )}
      {r.kind === "wifi" && (
        <div className="kv">
          <span className="pill">{s.ssid}</span>
          <span className="pill">{s.security}</span>
        </div>
      )}
      {s.chat?.text && <div className="note">“{s.chat.text}”</div>}

      {r.reports.count > 0 && (
        <div className="reports">
          <Icon name="flag" size={14} />{" "}
          {t(lang, "reportedBy", { n: r.reports.count })}
        </div>
      )}

      <h3>{t(lang, "why")}</h3>
      <ul className="reasons">
        {bad.length === 0 && (
          <li className="sev-good">
            <Icon name="check" size={17} />
            <p>{t(lang, "noFlags")}</p>
          </li>
        )}
        {reasons.map((x, i) => (
          <li key={i} className={`sev-${x.severity}`}>
            <Icon
              name={x.weight > 0 ? "alert" : x.weight < 0 ? "check" : "shield"}
              size={17}
            />
            <p>{x.text[lang]}</p>
          </li>
        ))}
        {isUpi && (
          <li className="sev-info">
            <Icon name="shield" size={17} />
            <p>
              {r.signals.find((x) => x.code === "UPI_PAY_INFO")?.text[lang]}
            </p>
          </li>
        )}
      </ul>

      {r.checks.length > 0 && (
        <div className="checks">
          {t(lang, "checks")}:{" "}
          {r.checks.map((c) => (
            <span key={c.name} className={`chk chk-${c.status}`}>
              {CHECK_NAMES[c.name] ?? c.name} · {c.status}
            </span>
          ))}
        </div>
      )}

      {confirming ? (
        <div className="confirm">
          <label>
            <input
              type="checkbox"
              checked={agree}
              onChange={(e) => setAgree(e.target.checked)}
            />{" "}
            {t(lang, "confirmRisk")}
          </label>
          <div className="row">
            <button className="btn" onClick={() => setConfirming(false)}>
              {t(lang, "cancel")}
            </button>
            <button className="btn danger" disabled={!agree} onClick={openIt}>
              {t(lang, "continue")}
            </button>
          </div>
        </div>
      ) : (
        <div className="actions">
          <button className="btn primary" onClick={onBack}>
            <Icon name="shield" size={17} />
            {t(lang, "dontOpen")}
          </button>
          {canOpen && (
            <button className="btn ghost" onClick={openIt}>
              {t(lang, "openAnyway")}
            </button>
          )}
        </div>
      )}
      <div className="row between">
        <button
          className="link"
          onClick={() => setReporting(!reporting)}
          disabled={reported !== null || secret}
        >
          <Icon name="flag" size={15} />
          {reported !== null
            ? `${t(lang, "reported")} (${reported})`
            : t(lang, "report")}
        </button>
        <button className="link" onClick={onBack}>
          <Icon name="scan" size={15} />
          {t(lang, "scanAgain")}
        </button>
      </div>
      {reporting && (
        <form
          className="report-form"
          onSubmit={(e) => {
            e.preventDefault();
            doReport();
          }}
        >
          <label htmlFor="report-reason">{t(lang, "reasonPrompt")}</label>
          <p>{c(lang, "reportHelp")}</p>
          <textarea
            id="report-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={300}
            rows={3}
          />
          {reportError && (
            <p className="msg" role="alert">
              {reportError}
            </p>
          )}
          <div className="row">
            <button className="btn primary" disabled={reportBusy}>
              {reportBusy ? t(lang, "checking") : t(lang, "report")}
            </button>
            <button
              className="btn"
              type="button"
              onClick={() => setReporting(false)}
            >
              {t(lang, "cancel")}
            </button>
          </div>
        </form>
      )}
      {r.verdict !== "SAFE" && (
        <p className="helpline">{t(lang, "helpline")}</p>
      )}
    </section>
  );
}

// ------------------------------------------------------------------ History
function HistoryView({
  lang,
  items,
  onOpen,
  onClear,
}: {
  lang: Lang;
  items: HistoryItem[];
  onOpen: (item: HistoryItem) => void;
  onClear: () => void;
}) {
  if (!items.length) return <p className="empty">{t(lang, "emptyHistory")}</p>;
  return (
    <section>
      <ul className="history">
        {items.map((h) => (
          <li key={h.ts}>
            <button onClick={() => onOpen(h)}>
              <span className={`dot v-${h.verdict}`}>
                <Icon
                  name={h.verdict === "SAFE" ? "check" : "alert"}
                  size={16}
                />
              </span>
              <div>
                <b>{h.headline[lang]}</b>
                <small>
                  {new Date(h.ts).toLocaleString()}
                  {h.intent ? ` · ${t(lang, h.intent)}` : ""}
                </small>
              </div>
              <Icon name="arrow" size={18} />
            </button>
          </li>
        ))}
      </ul>
      <button className="link" onClick={onClear}>
        {t(lang, "clear")}
      </button>
    </section>
  );
}

// ------------------------------------------------------------------ Shopkeeper mode
function ShopView({ lang }: { lang: Lang }) {
  const [shop, setShop] = useState<ShopInfo | null>(() =>
    store.get("qrs_shop", null),
  );
  const [name, setName] = useState("");
  const [mode, setMode] = useState<"idle" | "register" | "verify">("idle");
  const [res, setRes] = useState<VerifyResult | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const working = useRef(false);

  async function onCode(code: string) {
    if (working.current) return;
    working.current = true;
    setBusy(true);
    setErr("");
    try {
      if (mode === "register") {
        const info = await shopRegister(code, name);
        setShop(info);
        store.set("qrs_shop", info);
      } else if (shop) {
        setRes(await shopVerify(code, shop));
        navigator.vibrate?.([100]);
      }
    } catch (e) {
      setErr((e as Error).message);
    }
    setMode("idle");
    setBusy(false);
    working.current = false;
  }

  if (res)
    return (
      <div className={`shopres ${res.match ? "ok" : "bad"}`} role="status">
        <div className="big">
          <Icon name={res.match ? "check" : "alert"} size={52} />
        </div>
        <span className="small-label">
          {c(lang, res.match ? "shopMatch" : "shopMismatch")}
        </span>
        <h2>{res.text[lang]}</h2>
        {res.name_text && <p>{res.name_text[lang]}</p>}
        {res.found && (
          <code>
            {res.found.pn} · {res.found.vpa}
          </code>
        )}
        <div className="comparison">
          <div>
            <span className="small-label">{c(lang, "expected")}</span>
            <code>{res.expected.vpa}</code>
          </div>
          <Icon name="arrow" />
          <div>
            <span className="small-label">{c(lang, "found")}</span>
            <code>{res.found?.vpa || "—"}</code>
          </div>
        </div>
        <button className="btn primary" onClick={() => setRes(null)}>
          {t(lang, "scanAgain")}
        </button>
      </div>
    );

  return (
    <section>
      <p className="intro">{t(lang, "shopIntro")}</p>
      <p className="privacy-note">
        <Icon name="lock" size={15} />
        {c(lang, "localShop")}
      </p>
      {shop ? (
        <div className="card">
          <small>{t(lang, "registeredAs")}</small>
          <h3>{shop.shop_name}</h3>
          <code>{shop.vpa}</code>
          {shop.shop_code && (
            <small>
              {t(lang, "shopCode")}: <b>{shop.shop_code}</b>
            </small>
          )}
        </div>
      ) : (
        <input
          className="input"
          aria-label={t(lang, "shopName")}
          placeholder={t(lang, "shopName")}
          value={name}
          maxLength={100}
          onChange={(e) => setName(e.target.value)}
        />
      )}
      {err && <p className="msg">{err}</p>}
      {busy ? (
        <div className="loading" role="status">
          <div className="spinner" />
          {t(lang, "checking")}
        </div>
      ) : mode === "idle" ? (
        <div className="stack">
          {shop && (
            <button
              className="btn primary big"
              onClick={() => setMode("verify")}
            >
              🔍 {t(lang, "verify")}
            </button>
          )}
          <button
            className={`btn ${shop ? "ghost" : "primary big"}`}
            onClick={() => setMode("register")}
          >
            {shop ? t(lang, "reset") : `📌 ${t(lang, "register")}`}
          </button>
        </div>
      ) : (
        <>
          <QrInput lang={lang} onCode={onCode} compact />
          <button className="link" onClick={() => setMode("idle")}>
            {t(lang, "cancel")}
          </button>
        </>
      )}
    </section>
  );
}
