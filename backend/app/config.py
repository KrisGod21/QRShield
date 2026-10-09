"""Settings from environment variables (and an optional .env file at the repo root)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


def _load_dotenv() -> None:
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()


def _flag(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    serverless: bool = bool(os.environ.get("VERCEL"))
    database_url: str = os.environ.get("DATABASE_URL", "").strip()
    demo_mode: bool = _flag("DEMO_MODE", "1")
    online_checks: bool = _flag("ONLINE_CHECKS", "1")
    feeds: bool = _flag("FEEDS", "1")
    gsb_api_key: str = os.environ.get("GSB_API_KEY", "").strip()
    urlhaus_auth_key: str = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    db_path: Path = Path(os.environ.get("DB_PATH", str(BACKEND / "data" / "qrshield.sqlite3")))
    time_budget: float = float(os.environ.get("TIME_BUDGET", "2.2"))
    frontend_dist: Path = Path(os.environ.get("FRONTEND_DIST", str(ROOT / "frontend" / "dist")))


settings = Settings()
