"""
The decision engine. EVERY detection - Suricata, Snort, the host agent, the
honeypot, the simulator - comes through handle_event(), so protection,
shadow mode, dedupe and the safety caps apply the same way to all of them.

It never runs a firewall command itself except through firewall.py, and it
writes everything to the database, which is how other processes (the live
dashboard stream) find out.
"""
import ipaddress
import re
import shutil
import subprocess
import time
from . import config, db, enrich, firewall, intel, knowledge, notify

COLLAPSE_SECONDS = 10
_local_cache = (0.0, set())


def local_ips():
    """This machine's own addresses and default gateway: never block these."""
    global _local_cache
    if time.time() - _local_cache[0] < 60:
        return _local_cache[1]
    ips = {"127.0.0.1", "::1"}
    if shutil.which("ip"):
        try:
            out = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True, timeout=3).stdout
            ips.update(re.findall(r"inet6? ([0-9a-fA-F:.]+)/", out))
            out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3).stdout
            ips.update(re.findall(r"via ([0-9.]+)", out))
        except Exception:
            pass
    _local_cache = (time.time(), ips)
    return ips


def protected_reason(ip):
    """Why this IP must never be blocked, or None if it can be."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "not a valid address"
    if a.is_loopback:
        return "this machine (loopback)"
    if ip in local_ips():
        return "this machine or its gateway"
    mgmt = config.get("management_ip")
    if mgmt and ip == mgmt:
        return "your management address"
    for w in db.q("SELECT cidr, note FROM whitelist"):
        try:
            if a in ipaddress.ip_network(w["cidr"], strict=False):
                return "on your protected list (%s)" % (w["note"] or w["cidr"])
        except ValueError:
            continue
    ag = db.one("SELECT name FROM agents WHERE last_ip=? LIMIT 1", (ip,))
    if ag:
        return "a monitored machine (%s)" % ag["name"]
    return None


def _clean(evt):
    e = dict(evt)
    e.setdefault("ts", db.iso())
    e["engine"] = str(e.get("engine") or "unknown")[:20]
    e["signature"] = str(e.get("signature") or "unknown")[:200]
    e["severity"] = e.get("severity") if e.get("severity") in knowledge.SEV_RANK else "low"
    e["raw"] = str(e.get("raw") or "")[:1000]
    for k in ("src_ip", "dst_ip"):
        v = e.get(k)
        try:
            e[k] = str(ipaddress.ip_address(v)) if v else None
        except ValueError:
            e[k] = None
    try:
        e["dst_port"] = int(e["dst_port"]) if e.get("dst_port") is not None else None
    except (ValueError, TypeError):
        e["dst_port"] = None
    e["simulated"] = 1 if e.get("simulated") else 0
    return e


def _enrich(e):
    d = knowledge.describe(e)
    e["kind"], e["mitre"], e["explain"] = d["kind"], d["mitre"], d["explain"]
    if e.get("lat") is None and e.get("src_ip"):
        g = enrich.geo(e["src_ip"])
        if g:
            e["country"] = e.get("country") or g["country"]
            e["lat"], e["lon"] = g["lat"], g["lon"]
    hits = intel.lookup(e["src_ip"]) if e.get("src_ip") else []
    e["intel"] = ",".join(hits) if hits else None
    if hits and e["severity"] != "high":
        # an address on a known-bad list makes any alert one level worse
        e["severity"] = "medium" if e["severity"] == "low" else "high"


def _ttl_minutes(ip):
    base = float(config.get("block_ttl_minutes"))
    prior = db.one("SELECT COUNT(*) AS n FROM actions WHERE src_ip=? AND action='block' AND ts_epoch>?",
                   (ip, time.time() - 86400))["n"]
    mult = float(config.get("repeat_offender_multiplier"))
    return min(base * (mult ** prior), float(config.get("max_block_ttl_minutes")))


def _decide(e, mode, ttl_override):
    """Returns (decision, note, ttl_minutes)."""
    ip = e.get("src_ip")
    if not ip or knowledge.rank(e["severity"]) < knowledge.rank(config.get("severity_block_threshold")):
        return "alert_only", "", None
    why = protected_reason(ip)
    if why:
        return "skip_protected", why, None
    now = time.time()
    if db.one("SELECT 1 AS x FROM actions WHERE src_ip=? AND action='block' AND active=1 LIMIT 1", (ip,)):
        return "already_blocked", "", None
    window = int(config.get("dedupe_window_seconds"))
    if db.one("SELECT 1 AS x FROM actions WHERE src_ip=? AND action IN ('would_block','block_failed') AND ts_epoch>? LIMIT 1",
              (ip, now - window)):
        return "dedup", "", None
    if mode == "shadow":
        return "would_block", "", None
    cap = int(config.get("max_blocks_per_minute"))
    recent = db.one("SELECT COUNT(*) AS n FROM actions WHERE action='block' AND ts_epoch>?", (now - 60,))["n"]
    if recent >= cap:
        return "rate_limited", "", None
    ttl = ttl_override if ttl_override is not None else _ttl_minutes(ip)
    ok, msg = firewall.block(ip)
    if not ok:
        return "block_failed", msg, None
    return "blocked", "for %s minutes" % (("%g" % round(ttl, 1)) if ttl >= 1 else "%g" % round(ttl, 2)), ttl


def handle_event(evt, mode_override=None, ttl_override=None, notify_wait=False):
    """Store, understand, decide, act, notify. Returns what happened."""
    e = _clean(evt)
    mode = mode_override or config.get("mode")

    # Flood protection for our own database: identical alerts within a few
    # seconds become one row with a counter instead of thousands of rows.
    if not e["simulated"]:
        prev = db.one(
            "SELECT id FROM events WHERE engine=? AND signature=? AND IFNULL(src_ip,'')=? AND IFNULL(agent,'')=? "
            "AND simulated=0 AND ingested>? ORDER BY id DESC LIMIT 1",
            (e["engine"], e["signature"], e.get("src_ip") or "", e.get("agent") or "", time.time() - COLLAPSE_SECONDS))
        if prev:
            db.x("UPDATE events SET count=count+1 WHERE id=?", (prev["id"],))
            return {"event_id": prev["id"], "decision": "collapsed"}

    _enrich(e)
    decision, note, ttl = _decide(e, mode, ttl_override)
    e["decision"], e["decision_note"] = decision, note
    cols = ["ts", "ingested", "engine", "agent", "src_ip", "dst_ip", "dst_port", "signature", "severity", "kind",
            "country", "lat", "lon", "mitre", "explain", "intel", "simulated", "sim_run", "decision",
            "decision_note", "raw"]
    e["ingested"] = time.time()
    event_id = db.x("INSERT INTO events(%s) VALUES(%s)" % (",".join(cols), ",".join("?" * len(cols))),
                    [e.get(c) for c in cols])

    ip = e.get("src_ip")
    if decision == "blocked":
        db.x("INSERT INTO actions(ts_epoch,src_ip,action,reason,expires_epoch,active,event_id,ttl_minutes,by) "
             "VALUES(?,?,?,?,?,1,?,?,?)",
             (time.time(), ip, "block", e["signature"], time.time() + ttl * 60, event_id, ttl, "auto"))
    elif decision in ("would_block", "skip_protected", "block_failed", "rate_limited"):
        db.x("INSERT INTO actions(ts_epoch,src_ip,action,reason,active,event_id,by) VALUES(?,?,?,?,0,?,?)",
             (time.time(), ip or "-", decision, note or e["signature"], event_id, "auto"))

    notify.send(e, decision, note, event_id, wait=notify_wait)
    return {"event_id": event_id, "decision": decision, "note": note, "severity": e["severity"], "kind": e["kind"]}


def manual_block(ip, ttl_minutes, by="admin"):
    """Block from the dashboard. Still refuses protected addresses."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False, "That is not a valid IP address."
    why = protected_reason(ip)
    if why:
        return False, "Refused: %s." % why
    ok, msg = firewall.block(ip)
    if not ok:
        return False, msg
    db.x("INSERT INTO actions(ts_epoch,src_ip,action,reason,expires_epoch,active,ttl_minutes,by) VALUES(?,?,?,?,?,1,?,?)",
         (time.time(), ip, "block", "blocked by admin", time.time() + ttl_minutes * 60, ttl_minutes, by))
    return True, "Blocked for %g minutes." % ttl_minutes


def manual_unblock(ip, by="admin"):
    firewall.unblock(ip)
    db.x("UPDATE actions SET active=0 WHERE src_ip=? AND action='block' AND active=1", (ip,))
    db.x("INSERT INTO actions(ts_epoch,src_ip,action,reason,active,by) VALUES(?,?,?,?,0,?)",
         (time.time(), ip, "unblock", "unblocked by admin", by))
    return True


def unblock_all(by="admin"):
    ips = [a["src_ip"] for a in db.q("SELECT DISTINCT src_ip FROM actions WHERE action='block' AND active=1")]
    firewall.flush()
    db.x("UPDATE actions SET active=0 WHERE action='block' AND active=1")
    for ip in ips:
        db.x("INSERT INTO actions(ts_epoch,src_ip,action,reason,active,by) VALUES(?,?,?,?,0,?)",
             (time.time(), ip, "unblock", "panic: unblock everyone", by))
    return len(ips)
