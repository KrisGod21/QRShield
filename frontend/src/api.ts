export type Lang = "en" | "hi" | "mr";
export type Verdict = "SAFE" | "CAUTION" | "DANGER";
export type Intent = "check" | "pay_shop" | "receive" | "pay_bill";
export type L10n = Record<Lang, string>;

export interface SignalOut {
  code: string;
  severity: "critical" | "high" | "medium" | "low" | "info" | "good";
  weight: number;
  params: Record<string, unknown>;
  text: L10n;
}

export interface AnalyzeResult {
  id: string;
  kind: string;
  verdict: Verdict;
  score: number;
  headline: L10n;
  summary: Record<string, any>;
  signals: SignalOut[];
  checks: { name: string; status: string; ms: number }[];
  reports: { count: number };
  payload_hash: string;
  elapsed_ms: number;
  demo: boolean;
}

async function post<T>(
  path: string,
  body: unknown,
  timeoutMs = 8000,
): Promise<T> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    if (!r.ok) {
      const detail = await r.json().catch(() => ({}));
      throw new Error(detail.detail || `HTTP ${r.status}`);
    }
    return (await r.json()) as T;
  } finally {
    clearTimeout(t);
  }
}

export const analyze = (
  payload: string,
  intent: Intent,
  source: "camera" | "image" | "text",
) => post<AnalyzeResult>("/api/analyze", { payload, intent, source });

export const report = (payload: string, reason: string) =>
  post<{ count: number }>("/api/report", { payload, reason });

export interface ShopInfo {
  shop_code: string;
  vpa: string;
  pn: string;
  shop_name: string;
}
export const shopRegister = (payload: string, shop_name: string) =>
  post<ShopInfo>("/api/shop/register", { payload, shop_name });

export interface VerifyResult {
  match: boolean;
  expected: { vpa: string; pn: string };
  found: { vpa: string; pn: string } | null;
  changes: string[];
  text: L10n;
  name_text?: L10n | null;
}
export const shopVerify = (payload: string, shop: ShopInfo) =>
  post<VerifyResult>("/api/shop/verify", {
    payload,
    expected_vpa: shop.vpa,
    expected_name: shop.pn,
  });
