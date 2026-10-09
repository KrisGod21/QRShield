import { useEffect, useRef, useState, type CSSProperties } from "react";
import type { Lang } from "./api";
import Workspace from "./Workspace";
import { Icon, QrMark } from "./Icon";
import { c } from "./content";
import { t } from "./i18n";

export default function App() {
  const [lang, setLang] = useState<Lang>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem("qrs_lang") || '"en"');
      return saved === "hi" || saved === "mr" ? saved : "en";
    } catch {
      return "en";
    }
  });
  const [tab, setTab] = useState<"scan" | "history" | "shop">("scan");
  const [scanRequest, setScanRequest] = useState(0);
  const desk = useRef<HTMLElement>(null);
  useEffect(() => {
    document.documentElement.lang = lang;
    try {
      localStorage.setItem("qrs_lang", JSON.stringify(lang));
    } catch {
      /* Optional storage. */
    }
  }, [lang]);
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) =>
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add("visible");
            observer.unobserve(e.target);
          }
        }),
      { threshold: 0.12 },
    );
    document
      .querySelectorAll(".reveal")
      .forEach((node) => observer.observe(node));
    return () => observer.disconnect();
  }, []);
  function go(next: "scan" | "shop" = "scan") {
    setTab(next);
    if (next === "scan") setScanRequest((value) => value + 1);
    desk.current?.scrollIntoView({
      block: "start",
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
        ? "auto"
        : "smooth",
    });
  }
  return (
    <div className="site-shell">
      <header className="site-header">
        <a className="brand" href="#" aria-label="QR Shield home">
          <span className="brand-symbol">
            <Icon name="shield" size={26} />
          </span>
          <span>
            QR <b>Shield</b>
            <span className="brand-dot">.</span>
          </span>
        </a>
        <nav className="header-nav" aria-label="Main navigation">
          <button onClick={() => go()}>{t(lang, "scan")}</button>
          <a href="#how-it-works">{c(lang, "how")}</a>
          <button onClick={() => go("shop")}>{c(lang, "merchant")}</button>
        </nav>
        <div className="header-actions">
          <div className="langs" role="group" aria-label="Language">
            {(["en", "hi", "mr"] as Lang[]).map((l) => (
              <button
                key={l}
                className={lang === l ? "on" : ""}
                aria-pressed={lang === l}
                onClick={() => setLang(l)}
              >
                {l === "en" ? "EN" : l === "hi" ? "हिं" : "मरा"}
              </button>
            ))}
          </div>
          <button className="btn header-cta" onClick={() => go()}>
            {c(lang, "scanCta")}
            <Icon name="arrow" size={16} />
          </button>
        </div>
      </header>
      <main>
        <section className="hero" aria-labelledby="hero-title">
          <div className="hero-grain" aria-hidden="true" />
          <div className="hero-copy">
            <div className="eyebrow hero-badge">
              <span className="live-dot" />
              {c(lang, "eyebrow")}
              <Icon name="arrow" size={14} />
            </div>
            <h1 id="hero-title">
              {c(lang, "heroOne")}
              <br />
              <span>{c(lang, "heroTwo")}</span>
            </h1>
            <p>{c(lang, "heroBody")}</p>
            <div className="hero-actions">
              <button className="btn primary" onClick={() => go()}>
                <Icon name="scan" />
                {c(lang, "scanCta")}
                <Icon name="arrow" size={18} />
              </button>
              <a className="text-action" href="#how-it-works">
                {c(lang, "how")}
                <span>↗</span>
              </a>
            </div>
            <div className="hero-assurance">
              <Icon name="lock" size={14} />
              {c(lang, "assurance")}
            </div>
          </div>
          <div
            className="hero-art"
            aria-hidden="true"
            onPointerMove={(e) => {
              const rect = e.currentTarget.getBoundingClientRect();
              e.currentTarget.style.setProperty(
                "--tilt-x",
                `${((e.clientX - rect.left) / rect.width - 0.5) * 9}deg`,
              );
              e.currentTarget.style.setProperty(
                "--tilt-y",
                `${-((e.clientY - rect.top) / rect.height - 0.5) * 9}deg`,
              );
            }}
            onPointerLeave={(e) => {
              e.currentTarget.style.setProperty("--tilt-x", "0deg");
              e.currentTarget.style.setProperty("--tilt-y", "0deg");
            }}
          >
            <div className="art-glow" />
            <div className="perspective-grid" />
            <div className="orbital orbital-one" />
            <div className="orbital orbital-two" />
            <div className="glass-tile tile-back">
              <Icon name="lock" size={54} />
            </div>
            <div className="qr-sculpture">
              <div className="qr-face">
                <QrMark className="hero-qr" />
                <div className="scan-beam" />
                <div className="qr-center">
                  <Icon name="shield" size={42} />
                </div>
                <span className="qr-corner tl" />
                <span className="qr-corner tr" />
                <span className="qr-corner bl" />
                <span className="qr-corner br" />
              </div>
            </div>
            <div className="glass-tile tile-front">
              <Icon name="shield" size={55} />
            </div>
            <div className="floating-label label-top">
              <span className="live-dot" />
              QR payload decoded<small>READ BEFORE YOU REACT</small>
            </div>
            <div className="floating-label label-bottom">
              <Icon name="lock" size={18} />
              <span>
                UPI · URLs · more<small>ONE EXTRA LAYER OF CLARITY</small>
              </span>
            </div>
            <span className="art-index">01 / QR INTELLIGENCE</span>
          </div>
          <div className="hero-watermark" aria-hidden="true">
            QR SHIELD
          </div>
        </section>
        <div className="signal-strip">
          {(["signalOne", "signalTwo", "signalThree"] as const).map(
            (key, i) => (
              <span key={key}>
                <Icon
                  name={i === 0 ? "scan" : i === 1 ? "shield" : "globe"}
                  size={17}
                />
                {c(lang, key)}
              </span>
            ),
          )}
        </div>
        <section
          className="workspace section-wrap"
          id="scan-desk"
          ref={desk}
          aria-labelledby="desk-title"
        >
          <div className="section-heading">
            <div>
              <span className="eyebrow">01 / {c(lang, "workspace")}</span>
              <h2 id="desk-title">{c(lang, "workspaceTitle")}</h2>
            </div>
            <p>{c(lang, "workspaceBody")}</p>
          </div>
          <Workspace
            lang={lang}
            tab={tab}
            setTab={setTab}
            scanRequest={scanRequest}
          />
        </section>
        <section className="features section-wrap reveal">
          <div className="section-heading">
            <div>
              <span className="eyebrow">02 / QR PROTECTION, WITH CONTEXT</span>
              <h2>{c(lang, "guardTitle")}</h2>
            </div>
          </div>
          <div className="feature-grid">
            {(
              [
                { icon: "scan", title: "intentTitle", body: "intentBody" },
                { icon: "globe", title: "langTitle", body: "langBody" },
                { icon: "shop", title: "shopTitle", body: "shopBody" },
              ] as const
            ).map((f, i) => (
              <article
                className="feature-card"
                key={f.title}
                style={{ "--delay": `${i * 90}ms` } as CSSProperties}
              >
                <span className="feature-number">0{i + 1}</span>
                <span className="feature-icon">
                  <Icon name={f.icon} size={30} />
                </span>
                <h3>{c(lang, f.title)}</h3>
                <p>{c(lang, f.body)}</p>
                {i === 2 && (
                  <button className="text-action" onClick={() => go("shop")}>
                    {c(lang, "merchant")}
                    <Icon name="arrow" size={17} />
                  </button>
                )}
              </article>
            ))}
          </div>
        </section>
        <section className="how-section section-wrap reveal" id="how-it-works">
          <span className="eyebrow">03 / {c(lang, "how")}</span>
          <h2>{c(lang, "stepTwo")}</h2>
          <div className="steps">
            {(
              [
                { title: "stepOne", body: "stepOneBody" },
                { title: "stepTwo", body: "stepTwoBody" },
                { title: "stepThree", body: "stepThreeBody" },
              ] as const
            ).map((s, i) => (
              <article key={s.title}>
                <span className="step-number">0{i + 1}</span>
                <h3>{c(lang, s.title)}</h3>
                <p>{c(lang, s.body)}</p>
              </article>
            ))}
          </div>
        </section>
        <section className="scope-section section-wrap reveal">
          <Icon name="shield" size={32} />
          <div>
            <h3>{c(lang, "scope")}</h3>
            <p>{c(lang, "scopeBody")}</p>
          </div>
          <button className="btn" onClick={() => go()}>
            {c(lang, "scanCta")}
            <Icon name="arrow" size={17} />
          </button>
        </section>
      </main>
      <footer className="site-footer section-wrap">
        <a className="brand" href="#">
          <Icon name="shield" size={22} />
          QR <b>Shield</b>
          <span className="brand-dot">.</span>
        </a>
        <span>{c(lang, "footer")}</span>
        <span className="footer-note">Built for the way India scans.</span>
      </footer>
    </div>
  );
}
