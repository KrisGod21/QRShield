import type { CSSProperties } from "react";

export function Icon({
  name,
  size = 20,
  className = "",
}: {
  name: string;
  size?: number;
  className?: string;
}) {
  const paths: Record<string, JSX.Element> = {
    shield: (
      <>
        <path d="m12 3 8 3v5c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6l8-3Z" />
        <path d="m8 12 3 3 5-6" />
      </>
    ),
    scan: (
      <>
        <path d="M8 3H3v5M16 3h5v5M3 16v5h5M21 16v5h-5M3 12h18" />
      </>
    ),
    arrow: (
      <>
        <path d="M5 12h14M13 6l6 6-6 6" />
      </>
    ),
    upload: (
      <>
        <path d="M12 16V3m-5 5 5-5 5 5M4 16v5h16v-5" />
      </>
    ),
    history: (
      <>
        <path d="M3 11a9 9 0 1 1 2.5 7M3 4v7h7M12 7v5l3 2" />
      </>
    ),
    shop: (
      <>
        <path d="M4 10v11h16V10M3 4h18l1 6H2l1-6ZM9 21v-7h6v7" />
      </>
    ),
    check: <path d="m5 12 4 4L19 6" />,
    close: <path d="m6 6 12 12M6 18 18 6" />,
    alert: (
      <>
        <path d="m12 3 10 18H2L12 3Z" />
        <path d="M12 9v5m0 3v.1" />
      </>
    ),
    link: (
      <>
        <path
          d="m10 13 4-4M8 16l-1 1a4 4 0 0 1-6-6l5-5a4 4 0 0 1 6 0m0 12a4 4 0 0 0 6 0l5-5a4 4 0 0 0-6-6l-1 1"
          transform="translate(1 0) scale(.9)"
        />
      </>
    ),
    lock: (
      <>
        <rect x="5" y="10" width="14" height="11" rx="3" />
        <path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" />
      </>
    ),
    flag: (
      <>
        <path d="M5 21V3m0 1c5-4 9 4 14 0v9c-5 4-9-4-14 0" />
      </>
    ),
    globe: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z" />
      </>
    ),
    spark: (
      <path d="m12 2 2.5 7.5L22 12l-7.5 2.5L12 22l-2.5-7.5L2 12l7.5-2.5L12 2Z" />
    ),
    copy: (
      <>
        <rect x="8" y="8" width="12" height="13" rx="2" />
        <path d="M16 8V3H3v13h5" />
      </>
    ),
  };
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      {paths[name] || paths.shield}
    </svg>
  );
}

export function QrMark({ className = "" }: { className?: string }) {
  const cells = [];
  for (let y = 0; y < 25; y++)
    for (let x = 0; x < 25; x++) {
      const finder = (ox: number, oy: number) => {
        const dx = x - ox,
          dy = y - oy;
        if (dx < 0 || dy < 0 || dx > 6 || dy > 6) return null;
        return (
          dx === 0 ||
          dx === 6 ||
          dy === 0 ||
          dy === 6 ||
          (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4)
        );
      };
      const f = finder(0, 0) ?? finder(18, 0) ?? finder(0, 18);
      const spacer = (x < 8 && y < 8) || (x > 16 && y < 8) || (x < 8 && y > 16);
      if (f ?? (!spacer && (x * 13 + y * 7 + x * y) % 9 < 4))
        cells.push(
          <rect
            key={`${x}-${y}`}
            x={x}
            y={y}
            width=".86"
            height=".86"
            rx=".12"
            style={{ "--cell-delay": `${(x + y) * 28}ms` } as CSSProperties}
          />,
        );
    }
  return (
    <svg
      viewBox="-2 -2 29 29"
      className={className}
      fill="currentColor"
      aria-hidden="true"
    >
      {cells}
    </svg>
  );
}
