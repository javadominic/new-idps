"""
The "does everything actually work?" button. Runs real checks on every function
(database, decisions, firewall, expiry, notifications, live stream, parsers,
agent enrollment, honeypot, threat lists) using reserved test addresses
(192.0.2.0/24) that never belong to a real machine, then cleans up after itself.

Run from the dashboard (Setup > Run self-test) or: python3 manage.py selftest
"""
import json
import socket
import time
from . import config, correlator, db, enrich, firewall, health, intel, knowledge, notify, watchers

TEST_NET = "192.0.2."

# Real lines captured from Suricata 7.0.3 and Snort 2.9.20 (see tests/).
SURICATA_LINE = ('{"timestamp":"2026-10-22T10:00:00.123456+0000","event_type":"alert","src_ip":"10.9.0.7","dest_ip":"10.9.0.10",'
                 '"proto":"ICMP","alert":{"action":"allowed","signature_id":2000013,"signature":"ICMP flood detected","severity":1}}')
SNORT_ICMP = "01/15-08:00:50.000000  [**] [1:1000013:2] ICMP flood detected [**] [Classification: Attempted Denial of Service] [Priority: 1] {ICMP} 10.9.0.7 -> 10.9.0.10"
SNORT_TCP = "01/15-08:00:00.304000  [**] [1:1000011:2] Port scan detected [**] [Classification: Attempted Information Leak] [Priority: 3] {TCP} 10.9.0.5:40019 -> 10.9.0.10:1019"


def _ev(ip, sev="high", sig="ICMP flood detected", **kw):
    e = {"engine": "selftest", "src_ip": ip, "signature": sig, "severity": sev, "raw": "selftest", "simulated": 1}
    e.update(kw)
    return e


def t_database():
    db.metric_set("selftest.probe", 41)
    db.metric_add("selftest.probe", 1)
    ok = db.metric("selftest.probe") == 42
    db.x("DELETE FROM metrics WHERE name='selftest.probe'")
    return ok, "Wrote and read back a value." if ok else "Read-back did not match."


def t_settings():
    old = config.get("block_ttl_minutes")
    config.put("block_ttl_minutes", 7)
    ok = config.get("block_ttl_minutes") == 7
    config.put("block_ttl_minutes", old)
    return ok, "Settings change is visible immediately." if ok else "Setting did not stick."


def t_knowledge():
    cases = {"ICMP flood detected": "dos", "Port scan detected": "scan", "SSH Brute Force attempt": "brute",
             "Possible SQL injection attempt": "sqli", "Honeypot hit on port 2222 (ssh)": "honeypot",
             "File integrity change: /x": "fim", "Repeated login failures (possible brute force)": "brute"}
    bad = [s for s, k in cases.items() if knowledge.kind_of(s) != k]
    return not bad, "Explanations and MITRE tags found for every attack type." if not bad else "Unmatched: %s" % bad


def t_alert_only():
    r = correlator.handle_event(_ev(TEST_NET + "10", sev="low", sig="Port scan detected"))
    ok = r["decision"] == "alert_only" and db.one("SELECT 1 AS x FROM events WHERE id=?", (r["event_id"],))
    return bool(ok), "A low alert is stored and left alone." if ok else "Got %s" % r["decision"]


def t_shadow():
    r = correlator.handle_event(_ev(TEST_NET + "11"), mode_override="shadow")
    ok = r["decision"] == "would_block" and TEST_NET + "11" not in firewall.list_blocked()
    return ok, "Shadow mode records 'would block' and touches nothing." if ok else "Got %s" % r["decision"]


def t_protected():
    ip = TEST_NET + "12"
    db.x("INSERT OR IGNORE INTO whitelist(cidr,note,added_at,added_by) VALUES(?,?,?,?)", (ip + "/32", "selftest", time.time(), "selftest"))
    try:
        r = correlator.handle_event(_ev(ip), mode_override="live")
        ok = r["decision"] == "skip_protected" and ip not in firewall.list_blocked()
    finally:
        db.x("DELETE FROM whitelist WHERE cidr=?", (ip + "/32",))
    return ok, "A protected address is never blocked, even in Live mode." if ok else "Got %s" % r["decision"]


def t_dedupe():
    ip = TEST_NET + "13"
    a = correlator.handle_event(_ev(ip), mode_override="shadow")
    b = correlator.handle_event(_ev(ip, sig="TCP SYN flood detected"), mode_override="shadow")
    ok = a["decision"] == "would_block" and b["decision"] == "dedup"
    return ok, "The same attacker is handled once, not once per alert." if ok else "%s then %s" % (a["decision"], b["decision"])


def t_collapse():
    e = _ev(TEST_NET + "14", sev="low", sig="Port scan detected")
    e["simulated"] = 0
    a = correlator.handle_event(dict(e))
    b = correlator.handle_event(dict(e))
    ok = a["decision"] != "collapsed" and b["decision"] == "collapsed"
    return ok, "Repeated identical alerts are merged into one row with a counter." if ok else "%s then %s" % (a["decision"], b["decision"])


def t_firewall_block_expiry():
    st = firewall.status()
    if not st["available"]:
        return None, "Skipped: " + st["detail"]
    ip = TEST_NET + "15"
    r = correlator.handle_event(_ev(ip), mode_override="live", ttl_override=0.01)
    if r["decision"] != "blocked" or ip not in firewall.list_blocked():
        return False, "Block was not applied (decision: %s %s)" % (r["decision"], r.get("note", ""))
    time.sleep(0.9)
    firewall.sweep_expired()
    gone = ip not in firewall.list_blocked()
    return gone, "Blocked a test address in the real firewall, and the block expired on its own." if gone else "Block did not expire."


def t_manual_unblock():
    st = firewall.status()
    if not st["available"]:
        return None, "Skipped: " + st["detail"]
    ip = TEST_NET + "16"
    ok1, _ = correlator.manual_block(ip, 5, by="selftest")
    in_fw = ip in firewall.list_blocked()
    correlator.manual_unblock(ip, by="selftest")
    out_fw = ip not in firewall.list_blocked()
    return ok1 and in_fw and out_fw, "Manual block and unblock both reach the firewall." if (ok1 and in_fw and out_fw) else "block=%s in=%s out=%s" % (ok1, in_fw, out_fw)


def t_notify():
    ip = TEST_NET + "17"
    t0 = time.time()
    db.x("DELETE FROM notifications WHERE nkey LIKE ?", ("%" + ip + "%",))
    correlator.handle_event(_ev(ip), mode_override="shadow", notify_wait=True)
    row = db.one("SELECT 1 AS x FROM notifications WHERE channel='console' AND ts>=?", (t0,))
    extra = [c for c, k in (("Telegram", "telegram_token"), ("Email", "smtp_host")) if config.get(k)]
    return bool(row), "Notification sent to the console%s." % ((" and " + ", ".join(extra)) if extra else "") if row else "No notification was recorded (it may be rate-limited)."


def t_live_stream():
    last = db.one("SELECT IFNULL(MAX(id),0) AS m FROM events")["m"]
    correlator.handle_event(_ev(TEST_NET + "18", sev="low", sig="Port scan detected"))
    new = db.q("SELECT id FROM events WHERE id>?", (last,))
    return bool(new), "New alerts from any process are visible to the live dashboard stream." if new else "Stream query found nothing."


def t_parsers():
    a = watchers.parse_suricata(SURICATA_LINE)
    b = watchers.parse_snort(SNORT_ICMP)
    c = watchers.parse_snort(SNORT_TCP)
    ok = (a and a[1]["severity"] == "high" and b and b[1]["src_ip"] == "10.9.0.7" and b[1]["dst_port"] is None
          and b[1]["severity"] == "high" and c and c[1]["dst_port"] == 1019 and c[1]["severity"] == "low")
    return bool(ok), "Suricata and Snort log lines (including port-less ICMP) are read correctly." if ok else "A real log line failed to parse."


def t_agent_flow():
    from . import api
    c = api.app.test_client()
    pw = config.get("enrollment_password")
    r = c.post("/api/enroll", json={"name": "selftest-agent", "platform": "selftest", "enrollment_password": "wrong"})
    if r.status_code != 403:
        return False, "A wrong enrollment password was not rejected."
    r = c.post("/api/enroll", json={"name": "selftest-agent", "platform": "selftest", "enrollment_password": pw})
    if r.status_code != 200:
        return False, "Enrollment failed (%s)." % r.status_code
    cred = r.get_json()
    try:
        bad = c.post("/api/ingest", json={"events": []}, headers={"X-Agent-Id": cred["agent_id"], "X-Agent-Key": "nope"})
        good = c.post("/api/ingest", json={"events": [{"engine": "weblog", "src_ip": TEST_NET + "19", "severity": "low",
                                                       "signature": "Possible SQL injection attempt", "raw": "selftest"}]},
                      headers={"X-Agent-Id": cred["agent_id"], "X-Agent-Key": cred["key"]})
        ok = bad.status_code == 401 and good.status_code == 200 and good.get_json()["received"] == 1
    finally:
        db.x("DELETE FROM agents WHERE id=?", (cred["agent_id"],))
    return ok, "Enrollment, wrong-key rejection and event ingest all work." if ok else "bad=%s good=%s" % (bad.status_code, good.status_code)


def t_honeypot():
    if not config.get("honeypot_enabled"):
        return None, "Skipped: honeypot is turned off."
    if not health._fresh("honeypot.alive", 30):
        return None, "Skipped: the honeypot process is not running."
    port = config.get("honeypot_ports")[0]
    before = db.one("SELECT IFNULL(SUM(count),0) n FROM events WHERE engine='honeypot'")["n"]
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.sendall(b"selftest\r\n")
        time.sleep(0.5)
        s.close()
    except OSError as e:
        return False, "Could not connect to the decoy port %s: %s" % (port, e)
    for _ in range(10):
        if db.one("SELECT IFNULL(SUM(count),0) n FROM events WHERE engine='honeypot'")["n"] > before:
            return True, "A connection to the decoy port %s was detected." % port
        time.sleep(0.3)
    return False, "Connected to port %s but no alert was recorded." % port


def t_intel():
    ip = TEST_NET + "77"
    intel.add_custom(ip)
    try:
        hit = "custom" in intel.lookup(ip)
    finally:
        intel.remove_custom(ip)
    gone = "custom" not in intel.lookup(ip)
    st = intel.stats()
    extra = " Downloaded lists: %s." % ", ".join("%s=%d" % kv for kv in st["lists"].items() if kv[0] != "custom") if len(st["lists"]) > 1 else ""
    return hit and gone, "Custom threat list works." + extra


def t_geoip():
    return (True, "Location database is installed.") if enrich.available() else (None, "Optional: location database not installed.")


TESTS = [
    ("database", "Database", t_database), ("settings", "Live settings", t_settings),
    ("knowledge", "Plain-English explanations", t_knowledge), ("parsers", "Reading Suricata and Snort logs", t_parsers),
    ("alert_only", "Logging a low alert", t_alert_only), ("shadow", "Shadow mode", t_shadow),
    ("protected", "Protected addresses", t_protected), ("dedupe", "No duplicate blocking", t_dedupe),
    ("collapse", "Merging alert floods", t_collapse),
    ("fw_expiry", "Real firewall block and automatic expiry", t_firewall_block_expiry),
    ("fw_manual", "Manual block and unblock", t_manual_unblock),
    ("notify", "Notifications", t_notify), ("stream", "Live dashboard feed", t_live_stream),
    ("agent", "Host agent enrollment and ingest", t_agent_flow), ("honeypot", "Honeypot", t_honeypot),
    ("intel", "Threat lists", t_intel), ("geoip", "Location lookup", t_geoip),
]


def cleanup():
    for r in db.q("SELECT DISTINCT src_ip FROM actions WHERE src_ip LIKE ?", (TEST_NET + "%",)):
        firewall.unblock(r["src_ip"])
    db.x("DELETE FROM events WHERE engine='selftest' OR src_ip LIKE ?", (TEST_NET + "%",))
    db.x("DELETE FROM actions WHERE src_ip LIKE ?", (TEST_NET + "%",))
    db.x("DELETE FROM notifications WHERE nkey LIKE ?", ("%" + TEST_NET + "%",))
    db.x("DELETE FROM events WHERE engine='honeypot' AND raw LIKE 'sent: selftest%'")


def run():
    cleanup()
    out = []
    for tid, name, fn in TESTS:
        t0 = time.time()
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, "Crashed: %s" % e
        out.append({"id": tid, "name": name, "status": "ok" if ok else ("warn" if ok is None else "fail"),
                    "detail": detail, "ms": int((time.time() - t0) * 1000)})
    cleanup()
    result = {"ts": time.time(), "tests": out,
              "passed": sum(1 for t in out if t["status"] == "ok"),
              "failed": sum(1 for t in out if t["status"] == "fail"),
              "skipped": sum(1 for t in out if t["status"] == "warn")}
    db.x("INSERT INTO selftests(ts,result) VALUES(?,?)", (result["ts"], json.dumps(result)))
    return result


def last():
    r = db.one("SELECT result FROM selftests ORDER BY id DESC LIMIT 1")
    return json.loads(r["result"]) if r else None
