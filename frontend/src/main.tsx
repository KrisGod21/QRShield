import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";
import { registerSW } from "virtual:pwa-register";

registerSW({
  immediate: true,
  onRegisteredSW(_url, registration) {
    if (!registration) return;
    const checkForUpdate = () => {
      if (navigator.onLine && document.visibilityState === "visible") {
        void registration.update().catch(() => {});
      }
    };
    window.addEventListener("pageshow", checkForUpdate);
    document.addEventListener("visibilitychange", checkForUpdate);
    window.setInterval(checkForUpdate, 5 * 60 * 1000);
    checkForUpdate();
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
