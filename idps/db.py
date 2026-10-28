"""
SQLite is the message bus between every process (watchers, honeypot, API,
maintenance). Each process writes rows; the API's live stream reads new rows.
That is what makes alerts from separate processes appear live on the dashboard.
WAL mode lets many processes read and write at once.
"""
import sqlite3
import time
import threading
from . import paths

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT, ingested REAL NOT NULL,
  engine TEXT NOT NULL, agent TEXT,
  src_ip TEXT, dst_ip TEXT, dst_port INTEGER,
  signature TEXT, severity TEXT, kind TEXT,
  country TEXT, lat REAL, lon REAL,
  mitre TEXT, explain TEXT, intel TEXT,
  simulated INTEGER DEFAULT 0, sim_run INTEGER,
  count INTEGER DEFAULT 1,
  decision TEXT, decision_note TEXT,
  raw TEXT);
CREATE INDEX IF NOT EXISTS ix_ev_ing ON events(ingested);
CREATE INDEX IF NOT EXISTS ix_ev_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS ix_ev_collapse ON events(engine, signature, src_ip, ingested);

CREATE TABLE IF NOT EXISTS actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_epoch REAL NOT NULL, src_ip TEXT NOT NULL,
  action TEXT NOT NULL,
  reason TEXT, expires_epoch REAL, active INTEGER DEFAULT 0,
  event_id INTEGER, ttl_minutes REAL, by TEXT);
CREATE INDEX IF NOT EXISTS ix_ac_src ON actions(src_ip, ts_epoch);

CREATE TABLE IF NOT EXISTS agents(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, platform TEXT, hostname TEXT, version TEXT,
  key_hash TEXT NOT NULL, enrolled_at REAL, last_seen REAL, last_ip TEXT, info TEXT);

CREATE TABLE IF NOT EXISTS whitelist(
  id INTEGER PRIMARY KEY AUTOINCREMENT, cidr TEXT UNIQUE NOT NULL, note TEXT, added_at REAL, added_by TEXT);

CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS metrics(name TEXT PRIMARY KEY, value REAL, ts REAL);
CREATE TABLE IF NOT EXISTS notifications(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, channel TEXT, ok INTEGER, detail TEXT, nkey TEXT, event_id INTEGER);
CREATE INDEX IF NOT EXISTS ix_no_key ON notifications(nkey, ts);
CREATE TABLE IF NOT EXISTS sim_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, attack TEXT, mode TEXT, started REAL, ended REAL);
CREATE TABLE IF NOT EXISTS selftests(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, result TEXT);
CREATE TABLE IF NOT EXISTS sensor_stats(engine TEXT PRIMARY KEY, ts REAL, data TEXT);
"""

_ready = set()
_lock = threading.Lock()


def conn():
    path = paths.DB_PATH
    c = sqlite3.connect(path, timeout=15, isolation_level=None)
    c.row_factory = sqlite3.Row
    if path not in _ready:
        with _lock:
            if path not in _ready:
                c.execute("PRAGMA journal_mode=WAL")
                c.executescript(SCHEMA)
                _ready.add(path)
    c.execute("PRAGMA busy_timeout=15000")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


def q(sql, args=()):
    c = conn()
    try:
        return [dict(r) for r in c.execute(sql, args).fetchall()]
    finally:
        c.close()


def one(sql, args=()):
    rows = q(sql, args)
    return rows[0] if rows else None


def x(sql, args=()):
    """Execute a write. Returns lastrowid."""
    c = conn()
    try:
        cur = c.execute(sql, args)
        return cur.lastrowid
    finally:
        c.close()


def now():
    return time.time()


def iso(ts=None):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts or time.time()))


def metric_set(name, value):
    x("INSERT INTO metrics(name,value,ts) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value, ts=excluded.ts",
      (name, value, now()))


def metric_add(name, delta=1):
    x("INSERT INTO metrics(name,value,ts) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value, ts=excluded.ts",
      (name, delta, now()))


def metric(name, default=0.0):
    r = one("SELECT value FROM metrics WHERE name=?", (name,))
    return r["value"] if r else default


def metric_ts(name):
    r = one("SELECT ts FROM metrics WHERE name=?", (name,))
    return r["ts"] if r else None
