"""
Settings live in the database so the dashboard can change them live and every
process sees the change within a second. No restart, no file editing.
"""
import json
import time
from . import db, paths

DEFAULTS = {
    "mode": "shadow",                    # shadow = watch only, live = really block
    "block_ttl_minutes": 30,
    "repeat_offender_multiplier": 2,     # block time doubles for repeat offenders
    "max_block_ttl_minutes": 1440,
    "max_blocks_per_minute": 30,         # safety cap against runaway blocking
    "severity_block_threshold": "high",
    "dedupe_window_seconds": 60,
    "home_net": "192.168.56.0/24",
    "management_ip": "",
    "suricata_eve_log": "/var/log/suricata/eve.json",
    "snort_alert_log": "/var/log/snort/alert",
    "geoip_db_path": paths.GEOIP_PATH,
    "honeypot_enabled": True,
    "honeypot_ports": [2222, 8081, 2323],
    "intel_enabled": True,
    "notify_min_severity": "high",
    "notify_cooldown_seconds": 300,
    "telegram_token": "", "telegram_chat_id": "",
    "telegram_api_base": "https://api.telegram.org",
    "smtp_host": "", "smtp_port": 587, "smtp_user": "", "smtp_pass": "",
    "smtp_from": "", "smtp_to": "", "smtp_tls": True,
    "enrollment_password": "",
    "sim_token": "",
    "secret_key": "",
    "admin_pw_hash": "",
    "retention_days": 30,
}
SECRET = {"telegram_token", "smtp_pass", "admin_pw_hash", "secret_key", "sim_token", "enrollment_password"}
HIDDEN = {"admin_pw_hash", "secret_key"}

_cache, _stamp = {}, 0.0


def _load():
    global _cache, _stamp
    if time.time() - _stamp > 1.0:
        _cache = {r["key"]: json.loads(r["value"]) for r in db.q("SELECT key,value FROM settings")}
        _stamp = time.time()
    return _cache


def get(key, default=None):
    c = _load()
    if key in c:
        return c[key]
    return DEFAULTS.get(key, default)


def put(key, value):
    global _stamp
    db.x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
         (key, json.dumps(value)))
    _stamp = 0.0


def coerce(key, value):
    """Make a value coming from the dashboard match the type of the default."""
    d = DEFAULTS.get(key)
    if isinstance(d, bool):
        return value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes", "on")
    if isinstance(d, int):
        return int(float(value))
    if isinstance(d, float):
        return float(value)
    if isinstance(d, list):
        if isinstance(value, str):
            value = [v for v in value.replace(",", " ").split() if v.strip()]
        return [int(v) for v in value]
    return str(value) if value is not None else ""


def all_settings(masked=True):
    out = {}
    for k in DEFAULTS:
        if k in HIDDEN:
            continue
        v = get(k)
        out[k] = bool(v) if (masked and k in SECRET) else v
    return out
