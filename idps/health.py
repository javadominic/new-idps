"""
The setup checklist and health page. Every item says what is wrong in plain
words and how to fix it, so an empty dashboard is never a mystery.
Silent failure is the worst failure of an IDS: a sensor that stopped reading
looks exactly like a quiet network. So we check that logs are still growing.
"""
import json
import os
import shutil
import subprocess
import time
from . import config, db, enrich, firewall, honeypot, intel


def _pids(name):
    """Processes running a given program. Matches by program name, because some
    (Suricata) rename their main thread, so the short process name is not reliable."""
    out = []
    try:
        for d in os.listdir("/proc"):
            if not d.isdigit():
                continue
            try:
                with open("/proc/%s/cmdline" % d, "rb") as f:
                    argv0 = f.read().split(b"\0")[0].decode("utf-8", "replace")
                with open("/proc/%s/comm" % d) as f:
                    comm = f.read().strip().lower()
            except OSError:
                continue
            if os.path.basename(argv0) == name or comm in (name, name + "-main"):
                out.append(int(d))
    except OSError:
        pass
    return out


def _cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            return f.read().replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        return ""


def _fresh(metric, seconds=30):
    t = db.metric_ts(metric)
    return t is not None and time.time() - t < seconds


def _item(id, group, title, status, detail, fix=""):
    return {"id": id, "group": group, "title": title, "status": status, "detail": detail, "fix": fix}


def _sensor(engine, binary, logkey, svc, marker):
    out = []
    path = config.get(logkey)
    pids = _pids(binary)
    title = "%s network sensor" % engine.capitalize()
    if not shutil.which(binary):
        out.append(_item(engine, "Sensors", title, "warn", "%s is not installed." % engine.capitalize(),
                         "Run the installer again, or: sudo apt install %s" % binary))
        return out
    if not pids:
        out.append(_item(engine, "Sensors", title, "fail", "%s is installed but not running, so no network attacks are being seen." % engine.capitalize(),
                         "sudo systemctl start %s" % svc))
        return out
    detail, status, fix = "Running.", "ok", ""
    if not os.path.exists(path):
        status, detail, fix = "fail", "Running, but its alert log %s does not exist yet." % path, "Check the sensor's log folder in Settings."
    elif engine == "suricata":
        age = time.time() - os.path.getmtime(path)
        if age > 120:
            status, detail = "fail", "Running, but its log has not changed for %d minutes. It may be blind." % (age // 60)
            fix = "sudo systemctl restart %s  (also check the network interface name)" % svc
        else:
            st = db.one("SELECT data FROM sensor_stats WHERE engine='suricata'")
            if st:
                d = json.loads(st["data"])
                if d.get("packets", 0) > 1000 and d.get("drops", 0) / max(d["packets"], 1) > 0.05:
                    status = "warn"
                    detail = "Dropping %.0f%% of packets, so some attacks will be missed." % (100.0 * d["drops"] / d["packets"])
                    fix = "Give the VM more CPU, or check the network adapter settings."
                else:
                    detail = "Running and reading packets (%s seen, %s dropped)." % (d.get("packets", 0), d.get("drops", 0))
    if status == "ok" and marker and not any(marker in _cmdline(p) for p in pids):
        status, detail = "warn", "Running, but not with the project's rules, so it will not detect the lab attacks."
        fix = "Stop the default service and start: sudo systemctl start %s" % svc
    if status == "ok" and not _fresh("watcher.%s.alive" % engine, 30):
        status, detail = "fail", "The sensor is fine but the dashboard's reader for it is not running, so alerts will not appear."
        fix = "Restart the dashboard service: sudo systemctl restart idps"
    out.append(_item(engine, "Sensors", title, status, detail, fix))
    return out


def checks():
    items = []
    items.append(_item("password", "Basics", "Dashboard login", "ok" if config.get("admin_pw_hash") else "fail",
                       "Password is set." if config.get("admin_pw_hash") else "No password set.",
                       "python3 manage.py set-password"))
    items += _sensor("suricata", "suricata", "suricata_eve_log", "idps-suricata", "suricata_custom")
    items += _sensor("snort", "snort", "snort_alert_log", "idps-snort", "snort_idps")

    fw = firewall.status()
    items.append(_item("firewall", "Protection", "Firewall (blocking)", "ok" if fw["available"] else "fail",
                       ("Ready. %d address(es) currently blocked." % fw["blocked"]) if fw["available"] else
                       "Blocking will not work: " + fw["detail"],
                       "Run the dashboard service as root, and install iptables: sudo apt install iptables"))
    mode = config.get("mode")
    items.append(_item("mode", "Protection", "Mode", "info",
                       "Shadow mode: watching only, nothing is blocked. Safe for testing." if mode == "shadow" else
                       "Live mode: attackers are really blocked.",
                       "Switch on the Overview page when you trust the alerts." if mode == "shadow" else ""))
    wl = db.one("SELECT COUNT(*) AS n FROM whitelist")["n"]
    items.append(_item("whitelist", "Protection", "Protected addresses", "ok" if (wl or config.get("management_ip")) else "warn",
                       "%d address(es) can never be blocked (plus this machine and its gateway)." % wl if (wl or config.get("management_ip"))
                       else "You have not protected your own address yet. If it ever looked like an attacker you could lock yourself out.",
                       "Settings > Protected addresses > Add my address"))
    items.append(_item("maintenance", "Protection", "Automatic cleanup", "ok" if _fresh("maintenance.alive", 30) else "fail",
                       "Expired blocks are removed automatically." if _fresh("maintenance.alive", 30) else
                       "The cleanup job is not running, so blocks will never expire.", "sudo systemctl restart idps"))

    n_agents = db.one("SELECT COUNT(*) AS n FROM agents")["n"]
    online = db.one("SELECT COUNT(*) AS n FROM agents WHERE last_seen>?", (time.time() - 90,))["n"]
    items.append(_item("agents", "Website and hosts", "Host agents",
                       "ok" if online else ("warn" if n_agents else "info"),
                       "%d of %d agent(s) online." % (online, n_agents) if n_agents else
                       "No website or computer is being watched yet. This is optional.",
                       "Agents page > Add agent" if not online else ""))
    hp_ok = _fresh("honeypot.alive", 30)
    items.append(_item("honeypot", "Detection extras", "Decoy services (honeypot)",
                       "ok" if hp_ok else ("info" if not config.get("honeypot_enabled") else "warn"),
                       "Listening on %d decoy port(s)." % db.metric("honeypot.ports") if hp_ok else
                       ("Turned off in Settings." if not config.get("honeypot_enabled") else "The decoy service is not running."),
                       "sudo systemctl restart idps" if config.get("honeypot_enabled") and not hp_ok else ""))
    ist = intel.stats()
    total = sum(ist["lists"].values())
    items.append(_item("intel", "Detection extras", "Threat lists", "ok" if total else "info",
                       "%d known-bad addresses loaded." % total if total else
                       "Not downloaded yet (needs internet). Optional.", "Settings > Threat lists > Update now"))
    items.append(_item("geoip", "Detection extras", "Location lookup", "ok" if enrich.available() else "info",
                       "Locations are shown for public addresses." if enrich.available() else
                       "Not installed. Alerts work fine, they just will not show a country or map point.",
                       "bash deploy/get-geoip.sh"))
    chans = [c for c, k in (("Telegram", "telegram_token"), ("Email", "smtp_host")) if config.get(k)]
    items.append(_item("notify", "Detection extras", "Phone and email alerts", "ok" if chans else "info",
                       ("Sending to: " + ", ".join(chans)) if chans else "Not set up. You will only see alerts on the dashboard.",
                       "Settings > Notifications"))
    return items


def overall(items=None):
    items = items or checks()
    if any(i["status"] == "fail" for i in items):
        return "red"
    if any(i["status"] == "warn" for i in items):
        return "amber"
    return "green"


def flow(window=3600):
    """Counts for each stage of the pipeline band on the Overview page."""
    since = time.time() - window
    ev = db.one("SELECT COUNT(*) AS rows, IFNULL(SUM(count),0) AS raw FROM events WHERE ingested>?", (since,))
    dec = {r["decision"]: r["n"] for r in db.q("SELECT decision, COUNT(*) AS n FROM events WHERE ingested>? GROUP BY decision", (since,))}
    src = {r["engine"]: r["n"] for r in db.q("SELECT engine, COUNT(*) AS n FROM events WHERE ingested>? GROUP BY engine", (since,))}
    notif = db.one("SELECT COUNT(*) AS n FROM notifications WHERE channel='console' AND ts>?", (since,))["n"]
    online_agents = db.one("SELECT COUNT(*) AS n FROM agents WHERE last_seen>?", (time.time() - 90,))["n"]
    return {
        "capture": {"alerts_seen": int(ev["raw"]), "sources": src,
                    "suricata": _fresh("watcher.suricata.alive", 30), "snort": _fresh("watcher.snort.alive", 30),
                    "agents": online_agents, "honeypot": _fresh("honeypot.alive", 30)},
        "understand": {"events": ev["rows"]},
        "decide": {"alert_only": dec.get("alert_only", 0),
                   "would_block": dec.get("would_block", 0), "blocked": dec.get("blocked", 0),
                   "protected": dec.get("skip_protected", 0),
                   "other": sum(v for k, v in dec.items() if k not in ("alert_only", "would_block", "blocked", "skip_protected"))},
        "act": {"active_blocks": db.one("SELECT COUNT(*) AS n FROM actions WHERE action='block' AND active=1")["n"]},
        "notify": {"sent": notif},
    }
