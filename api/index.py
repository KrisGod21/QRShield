"""Vercel ASGI entry point. Static frontend is served by Vercel's CDN."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
# Never write SQLite into a serverless deployment's read-only project filesystem.
# Add DATABASE_URL for persistent PostgreSQL reports/shops/cache across instances.
os.environ.setdefault("VERCEL", "1")
os.environ.setdefault("DB_PATH", ":memory:")
os.environ.setdefault("DEMO_MODE", "0")
os.environ.setdefault("FEEDS", "0")

from app.main import app  # noqa: E402, F401
