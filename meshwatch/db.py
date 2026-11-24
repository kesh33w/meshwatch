"""SQLite storage. One connection, WAL, used from the event loop (low volume:
only watched nodes are recorded)."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

-- Directory of nodes seen in adverts (for search). Flushed in batches.
CREATE TABLE IF NOT EXISTS seen_nodes (
  pubkey TEXT PRIMARY KEY, name TEXT, node_type TEXT, lat REAL, lon REAL,
  advert_ts INTEGER, last_seen REAL NOT NULL);
CREATE INDEX IF NOT EXISTS seen_nodes_name ON seen_nodes(name);

CREATE TABLE IF NOT EXISTS watched (
  pubkey TEXT PRIMARY KEY, label TEXT, added_at REAL NOT NULL,
  admin_pw TEXT, guest_pw TEXT,            -- encrypted (Fernet), never returned
  poll_enabled INTEGER NOT NULL DEFAULT 1,
  poll_interval_min INTEGER NOT NULL DEFAULT 30,
  alerts_enabled INTEGER NOT NULL DEFAULT 1,
  silent_min INTEGER,                      -- NULL = automatic default
  battery_mv INTEGER NOT NULL DEFAULT 3500,
  snr_drop_db REAL NOT NULL DEFAULT 6,
  notes TEXT NOT NULL DEFAULT '',
  radio_id TEXT);                          -- companion to use; NULL = automatic

CREATE TABLE IF NOT EXISTS node_state (
  pubkey TEXT PRIMARY KEY, last_heard REAL, last_heard_via TEXT,
  last_advert REAL, last_poll_at REAL, last_poll_ok REAL, poll_fails INTEGER NOT NULL DEFAULT 0,
  next_poll_at REAL, last_login_at REAL, login_role TEXT, last_error TEXT,
  status TEXT, status_at REAL, telemetry TEXT, telemetry_at REAL, firmware TEXT,
  poll_radio TEXT, login_radio TEXT);

-- Raw data (30 days). One row per node/observer/kind per 5-minute bucket,
-- averaged, to keep disk writes low for busy repeaters.
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY, pubkey TEXT NOT NULL, ts REAL NOT NULL,
  kind TEXT NOT NULL,           -- advert | relay
  observer TEXT NOT NULL, region TEXT, snr REAL, rssi REAL, n INTEGER NOT NULL,
  direct INTEGER NOT NULL,      -- 1 = observer heard this node's own transmission
  hops INTEGER, path TEXT);
CREATE INDEX IF NOT EXISTS observations_node_ts ON observations(pubkey, ts);

CREATE TABLE IF NOT EXISTS status_samples (
  id INTEGER PRIMARY KEY, pubkey TEXT NOT NULL, ts REAL NOT NULL,
  bat INTEGER, noise_floor INTEGER, last_rssi INTEGER, last_snr REAL, uptime INTEGER,
  airtime INTEGER, nb_sent INTEGER, nb_recv INTEGER, tx_queue_len INTEGER, raw TEXT);
CREATE INDEX IF NOT EXISTS status_node_ts ON status_samples(pubkey, ts);

CREATE TABLE IF NOT EXISTS telemetry_samples (
  id INTEGER PRIMARY KEY, pubkey TEXT NOT NULL, ts REAL NOT NULL, lpp TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS telemetry_node_ts ON telemetry_samples(pubkey, ts);

-- Hourly rollups (1 year)
CREATE TABLE IF NOT EXISTS rollups (
  pubkey TEXT NOT NULL, hour INTEGER NOT NULL, metric TEXT NOT NULL,
  n INTEGER NOT NULL, vmin REAL, vmax REAL, vsum REAL,
  PRIMARY KEY (pubkey, metric, hour));

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY, pubkey TEXT NOT NULL, rule TEXT NOT NULL,
  started REAL NOT NULL, resolved REAL, message TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS alerts_open ON alerts(pubkey, rule, resolved);

CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, pubkey TEXT, action TEXT NOT NULL,
  detail TEXT, ok INTEGER, response TEXT, client TEXT);
CREATE INDEX IF NOT EXISTS audit_node ON audit(pubkey, ts);

CREATE TABLE IF NOT EXISTS cli_history (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, command TEXT NOT NULL UNIQUE);

CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL,
  label TEXT, transports TEXT, created REAL NOT NULL, last_used REAL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, created REAL NOT NULL, expires REAL NOT NULL, client TEXT);
CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, label TEXT NOT NULL,
  created REAL NOT NULL, last_used REAL);
"""


class DB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self._migrate()

    # Columns added after the first release (CREATE TABLE IF NOT EXISTS leaves old tables alone).
    ADDED_COLUMNS = {"watched": ["radio_id TEXT"], "node_state": ["poll_radio TEXT", "login_radio TEXT"]}

    def _migrate(self) -> None:
        for table, columns in self.ADDED_COLUMNS.items():
            have = {r["name"] for r in self.q(f"PRAGMA table_info({table})")}
            for col in columns:
                if col.split()[0] not in have:
                    self.x(f"ALTER TABLE {table} ADD COLUMN {col}")

    def q(self, sql: str, args=()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, args).fetchall()

    def one(self, sql: str, args=()) -> sqlite3.Row | None:
        return self.conn.execute(sql, args).fetchone()

    def x(self, sql: str, args=()) -> sqlite3.Cursor:
        return self.conn.execute(sql, args)

    def many(self, sql: str, rows) -> None:
        with self.conn:
            self.conn.executemany(sql, rows)

    # settings ---------------------------------------------------------------
    def get_setting(self, key: str, default=None):
        row = self.one("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(row["value"]) if row else default

    def set_setting(self, key: str, value) -> None:
        self.x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (key, json.dumps(value)))

    def audit(self, action: str, pubkey: str | None = None, detail: str | None = None,
              ok: bool | None = None, response: str | None = None, client: str | None = None) -> None:
        self.x("INSERT INTO audit(ts,pubkey,action,detail,ok,response,client) VALUES(?,?,?,?,?,?,?)",
               (time.time(), pubkey, action, detail, None if ok is None else int(ok), response, client))
