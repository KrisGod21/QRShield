"""SQLite storage: threat-intel entries, RDAP cache, community reports, shops."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS intel (
    url TEXT NOT NULL, host TEXT NOT NULL, is_root INTEGER NOT NULL,
    source TEXT NOT NULL, added REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS intel_url ON intel(url);
CREATE INDEX IF NOT EXISTS intel_host ON intel(host);
CREATE TABLE IF NOT EXISTS feeds (source TEXT PRIMARY KEY, count INTEGER, updated REAL);
CREATE TABLE IF NOT EXISTS rdap_cache (domain TEXT PRIMARY KEY, created TEXT, fetched REAL);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT NOT NULL, reason TEXT,
    created REAL NOT NULL, seeded INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS reports_hash ON reports(hash);
CREATE TABLE IF NOT EXISTS shops (
    code TEXT PRIMARY KEY, shop_name TEXT, vpa TEXT NOT NULL, pn TEXT, created REAL NOT NULL
);
"""


class DB:
    def __init__(self, path: Path | str):
        self.persistent = str(path) != ":memory:"
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.executescript(SCHEMA)
            self.conn.execute("PRAGMA journal_mode=WAL")

    def execute(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            cur = self.conn.execute(sql, args)
            rows = cur.fetchall()
            self.conn.commit()
            return rows

    def executemany(self, sql: str, rows: list[tuple]) -> None:
        with self.lock:
            self.conn.executemany(sql, rows)
            self.conn.commit()

    # ------------------------------------------------------------ reports
    def report_count(self, h: str) -> int:
        return self.execute("SELECT COUNT(*) AS n FROM reports WHERE hash=?", (h,))[0]["n"]

    def add_report(self, h: str, reason: str, seeded: bool = False) -> int:
        self.execute("INSERT INTO reports(hash, reason, created, seeded) VALUES (?,?,?,?)",
                     (h, reason, time.time(), int(seeded)))
        return self.report_count(h)

    def report_reasons(self, h: str, limit: int = 5) -> list[str]:
        rows = self.execute("SELECT reason FROM reports WHERE hash=? AND reason<>'' "
                            "ORDER BY created DESC LIMIT ?", (h, limit))
        return [r["reason"] for r in rows]

    # ------------------------------------------------------------ rdap
    def rdap_get(self, domain: str) -> tuple[bool, str | None]:
        rows = self.execute("SELECT created FROM rdap_cache WHERE domain=?", (domain,))
        return (True, rows[0]["created"]) if rows else (False, None)

    def rdap_put(self, domain: str, created: str | None) -> None:
        self.execute("INSERT INTO rdap_cache(domain, created, fetched) VALUES (?,?,?) "
                     "ON CONFLICT(domain) DO UPDATE SET created=excluded.created, fetched=excluded.fetched",
                     (domain, created, time.time()))

    # ------------------------------------------------------------ shops
    def shop_put(self, code: str, shop_name: str, vpa: str, pn: str) -> None:
        self.execute("INSERT INTO shops(code, shop_name, vpa, pn, created) VALUES (?,?,?,?,?) "
                     "ON CONFLICT(code) DO UPDATE SET shop_name=excluded.shop_name, vpa=excluded.vpa, "
                     "pn=excluded.pn, created=excluded.created",
                     (code, shop_name, vpa, pn, time.time()))

    def shop_get(self, code: str) -> sqlite3.Row | None:
        rows = self.execute("SELECT * FROM shops WHERE code=?", (code.upper(),))
        return rows[0] if rows else None


class PostgresDB(DB):
    """Shared durable storage for serverless deployments; same query interface as SQLite."""
    def __init__(self, database_url: str):
        import psycopg
        from psycopg.rows import dict_row
        self.persistent = True
        self.lock = threading.Lock()
        self.conn = psycopg.connect(database_url, row_factory=dict_row, connect_timeout=10)
        schema = SCHEMA.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY").replace("REAL", "DOUBLE PRECISION")
        with self.conn.cursor() as cursor:
            for statement in schema.split(";"):
                if statement.strip():
                    cursor.execute(statement)
        self.conn.commit()

    def execute(self, sql: str, args: tuple = ()) -> list:
        with self.lock:
            try:
                with self.conn.cursor() as cursor:
                    cursor.execute(sql.replace("?", "%s"), args)
                    rows = cursor.fetchall() if cursor.description else []
                self.conn.commit()
                return rows
            except Exception:
                self.conn.rollback()
                raise

    def executemany(self, sql: str, rows: list[tuple]) -> None:
        with self.lock:
            try:
                with self.conn.cursor() as cursor:
                    cursor.executemany(sql.replace("?", "%s"), rows)
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
