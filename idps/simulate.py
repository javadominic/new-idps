"""
Two ways to demonstrate the system.

1. SAFE DEMO (this file, run_scenario): injects clearly labelled fake attacks
   through the REAL pipeline (understand -> decide -> block -> notify ->
   dashboard). No packets are sent anywhere. Source addresses come from the
   reserved documentation ranges (198.51.100.0/24 and 203.0.113.0/24), which
   never belong to a real machine, so even in Live mode nothing real is blocked.

2. REAL LAB TEST (simulator/lab_attacks.py + report()): attacks your own lab
   machines for real, and report() builds the expected-vs-detected table per
   engine, with detection time, for your project report.
"""
import random
import time
from . import config, correlator, db, intel

DEMO_NETS = ["198.51.100", "203.0.113"]
PLACES = [("RU", 55.75, 37.62), ("CN", 39.90, 116.40), ("BR", -23.55, -46.63), ("US", 39.04, -77.49),
          ("NL", 52.37, 4.90), ("VN", 21.03, 105.85), ("DE", 50.11, 8.68), ("NG", 6.52, 3.38)]

SCENARIOS = {
    "port_scan": dict(label="Port scan", engine="suricata", sig="Port scan detected", sev="low", port=22,
                      story="Someone probes many ports. Low severity: logged, not blocked."),
    "ssh_brute": dict(label="SSH password guessing", engine="snort", sig="SSH Brute Force attempt", sev="medium", port=22,
                      story="Rapid login attempts. Medium severity: logged and watched."),
    "icmp_flood": dict(label="Ping flood", engine="suricata", sig="ICMP flood detected", sev="high", port=None,
                       story="A flood of pings. High severity: this is blocked in Live mode."),
    "syn_flood": dict(label="SYN flood", engine="snort", sig="TCP SYN flood detected", sev="high", port=80,
                      story="A flood of connection attempts. High severity: blocked in Live mode."),
    "sqli": dict(label="Website SQL injection", engine="weblog", agent="demo-web-server",
                 sig="Possible SQL injection attempt", sev="high", port=80,
                 story="A hostile web request seen by a host agent. High severity: blocked in Live mode.",
                 raw='GET /?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200'),
    "xss": dict(label="Website script injection", engine="weblog", agent="demo-web-server",
                sig="Possible XSS attempt", sev="high", port=80, story="Hidden script code in a web request.",
                raw='GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200'),
    "honeypot": dict(label="Decoy touched", engine="honeypot", sig="Honeypot hit on port 2222 (ssh)", sev="high", port=2222,
                     story="Someone touched a decoy no real user needs. Almost always an attacker.",
                     raw="sent: SSH-2.0-libssh_0.9.6"),
    "fim": dict(label="Website file changed", engine="fim", agent="demo-web-server", src=None,
                sig="File integrity change: /var/www/html/index.php", sev="medium", port=None,
                story="A watched file changed. No attacker address, so nothing to block: you are alerted."),
    "intel": dict(label="Known bad address", engine="suricata", sig="Port scan detected", sev="low", port=22,
                  story="A low alert from an address on a threat list is raised a level and blocked.", intel=True),
    "protected": dict(label="Attack from a protected address", engine="suricata", sig="ICMP flood detected", sev="high",
                      port=None, story="Same flood, but from your own machine: protected, never blocked.", own=True),
}


def _demo_ip():
    return "%s.%d" % (random.choice(DEMO_NETS), random.randint(2, 250))


def run_scenario(name):
    s = SCENARIOS[name]
    ip = None
    if "src" not in s:
        ip = "127.0.0.1" if s.get("own") else _demo_ip()
    cc, lat, lon = random.choice(PLACES)
    added_intel = None
    if s.get("intel"):
        intel.add_custom(ip)
        added_intel = ip
    evt = {"engine": s["engine"], "agent": s.get("agent"), "src_ip": ip, "dst_ip": None, "dst_port": s["port"],
           "signature": s["sig"], "severity": s["sev"], "simulated": 1,
           "raw": s.get("raw", "simulated event (no real traffic)"),
           "country": None if s.get("own") else cc, "lat": None if s.get("own") else lat,
           "lon": None if s.get("own") else lon}
    res = correlator.handle_event(evt, notify_wait=False)
    if added_intel:
        intel.remove_custom(added_intel)
    ev = db.one("SELECT * FROM events WHERE id=?", (res["event_id"],)) or {}
    return {"scenario": name, "label": s["label"], "story": s["story"], "ip": ip,
            "decision": res["decision"], "note": res.get("note", ""), "severity": ev.get("severity", s["sev"]),
            "event_id": res["event_id"], "mode": config.get("mode")}


# ---- real lab test report -------------------------------------------------

EXPECTED = {
    "port_scan":  ("Port scan detected", ["suricata", "snort"]),
    "ssh_brute":  ("SSH Brute Force attempt", ["suricata", "snort"]),
    "icmp_flood": ("ICMP flood detected", ["suricata", "snort"]),
    "syn_flood":  ("TCP SYN flood detected", ["suricata", "snort"]),
    "sqli":       ("SQL injection", ["weblog"]),
    "xss":        ("XSS", ["weblog"]),
    "traversal":  ("path traversal", ["weblog"]),
    "web_brute":  ("login failures", ["weblog"]),
    "honeypot":   ("Honeypot hit", ["honeypot"]),
}
LABELS = {"port_scan": "Port scan", "ssh_brute": "SSH password guessing", "icmp_flood": "Ping flood",
          "syn_flood": "SYN flood", "sqli": "SQL injection", "xss": "Script injection (XSS)",
          "traversal": "Path traversal", "web_brute": "Web login brute force", "honeypot": "Honeypot touch"}


def mark(attack, phase, run_id=None):
    """Called by simulator/lab_attacks.py so timing uses the manager's clock."""
    if phase == "start":
        return db.x("INSERT INTO sim_runs(attack,mode,started) VALUES(?,?,?)", (attack, "lab", time.time()))
    db.x("UPDATE sim_runs SET ended=? WHERE id=?", (time.time(), run_id))
    return run_id


def report(limit=40):
    rows = []
    runs = db.q("SELECT * FROM sim_runs WHERE mode='lab' AND ended IS NOT NULL ORDER BY id DESC LIMIT ?", (limit,))
    seen = set()
    for r in runs:                      # newest run of each attack type only
        if r["attack"] in seen or r["attack"] not in EXPECTED:
            continue
        seen.add(r["attack"])
        kw, engines = EXPECTED[r["attack"]]
        res = {}
        for eng in engines:
            e = db.one("SELECT ingested, decision, severity FROM events WHERE engine=? AND signature LIKE ? "
                       "AND ingested>=? AND ingested<=? ORDER BY ingested LIMIT 1",
                       (eng, "%" + kw + "%", r["started"] - 1, r["ended"] + 20))
            res[eng] = {"detected": bool(e), "latency": round(e["ingested"] - r["started"], 2) if e else None,
                        "severity": e["severity"] if e else None, "decision": e["decision"] if e else None}
        rows.append({"attack": r["attack"], "label": LABELS.get(r["attack"], r["attack"]), "started": r["started"],
                     "engines": res, "passed": all(v["detected"] for v in res.values())})
    order = list(EXPECTED)
    rows.sort(key=lambda x: order.index(x["attack"]))
    total = sum(len(v["engines"]) for v in rows)
    hit = sum(1 for v in rows for e in v["engines"].values() if e["detected"])
    return {"rows": rows, "detected": hit, "expected": total}
