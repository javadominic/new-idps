"""
The dashboard's backend. Everything except /api/enroll, /api/ingest, the agent
download routes and /api/sim/mark requires the admin login.

Live updates: /api/stream reads NEW ROWS FROM THE DATABASE, so an alert written
by any other process (Suricata watcher, Snort watcher, honeypot) reaches the
browser within a second. (My first version used an in-process queue, which
only worked for alerts that arrived through this same process.)
"""
import hashlib
import ipaddress
import json
import os
import secrets
import threading
import time
import uuid
from functools import wraps

from flask import Flask, Response, abort, jsonify, redirect, request, send_from_directory, session

from . import (VERSION, agent_install, auth, config, correlator, db, enrich, firewall, health, intel, knowledge,
               notify, paths, report, selftest, simulate)

app = Flask(__name__, static_folder=None)
app.config.update(MAX_CONTENT_LENGTH=2 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=12 * 3600)
auth.ensure_secrets()
app.secret_key = config.get("secret_key")

AGENT_PATHS = ("/api/enroll", "/api/ingest", "/api/sim/mark")
_login_fail = {}      # ip -> (count, first_time)
_enroll_fail = {}


@app.before_request
def _csrf():
    if request.method in ("POST", "PUT", "DELETE") and request.path.startswith("/api/") and request.path not in AGENT_PATHS:
        if request.headers.get("X-IDPS") != "1":
            return jsonify(error="missing X-IDPS header"), 400


@app.after_request
def _headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
    return r


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if session.get("u") != "admin":
            if request.path.startswith("/api/"):
                return jsonify(error="login required"), 401
            return redirect("/login")
        return f(*a, **k)
    return w


def _blocked_by_rate(store, key, limit=8, window=600):
    c, t = store.get(key, (0, time.time()))
    if time.time() - t > window:
        c, t = 0, time.time()
    return c >= limit


def _bump(store, key):
    c, t = store.get(key, (0, time.time()))
    if time.time() - t > 600:
        c, t = 0, time.time()
    store[key] = (c + 1, t)


# ------------------------------------------------------------ presentation

def present(e):
    d = dict(e)
    d["title"] = knowledge.title(e.get("kind"))
    d["advice"] = knowledge.advice(e.get("kind"))
    d["mitre_name"] = knowledge.mitre_name(e.get("kind"))
    d["sev_word"] = knowledge.SEV_WORD.get(e.get("severity"), "")
    d["decision_text"] = knowledge.decision_text(e.get("decision"), e.get("decision_note"))
    d["intel"] = e["intel"].split(",") if e.get("intel") else []
    return d


def _valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# -------------------------------------------------------------------- pages

@app.get("/")
@login_required
def index():
    return send_from_directory(paths.WEB_DIR, "index.html")


@app.get("/login")
def login_page():
    return send_from_directory(paths.WEB_DIR, "login.html")


@app.get("/assets/<path:p>")
def assets(p):
    return send_from_directory(os.path.join(paths.WEB_DIR, "assets"), p)


@app.get("/report")
@login_required
def report_page():
    return report.render(max(1, min(int(request.args.get("days", 7)), 90)))


@app.get("/api/export/events.csv")
@login_required
def export_csv():
    days = max(1, min(int(request.args.get("days", 7)), 90))
    return Response(report.csv_export(days), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=idps-events.csv"})


# --------------------------------------------------------------------- auth

@app.post("/api/login")
def login():
    ip = request.remote_addr
    if _blocked_by_rate(_login_fail, ip, 5, 300):
        return jsonify(error="Too many wrong passwords. Wait 5 minutes."), 429
    pw = (request.get_json(silent=True) or {}).get("password", "")
    if not auth.check_password(pw):
        _bump(_login_fail, ip)
        return jsonify(error="Wrong password."), 401
    _login_fail.pop(ip, None)
    session.permanent = True
    session["u"] = "admin"
    return jsonify(ok=True)


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
@login_required
def me():
    ip = request.remote_addr
    return jsonify(ip=ip, protected=bool(correlator.protected_reason(ip)), mode=config.get("mode"), version=VERSION,
                   first_run=db.one("SELECT COUNT(*) n FROM events")["n"] == 0)


@app.post("/api/password")
@login_required
def change_password():
    d = request.get_json(silent=True) or {}
    if not auth.check_password(d.get("current", "")):
        return jsonify(error="Current password is wrong."), 400
    try:
        auth.set_password(d.get("new", ""))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    return jsonify(ok=True)


# ----------------------------------------------------------------- overview

def _active_blocks():
    return {r["src_ip"] for r in db.q("SELECT src_ip FROM actions WHERE action='block' AND active=1")}


@app.get("/api/overview")
@login_required
def overview():
    now = time.time()
    since = now - 86400
    sev = {r["severity"]: r["n"] for r in db.q("SELECT severity, SUM(count) n FROM events WHERE ingested>? GROUP BY severity", (since,))}
    start = int(now // 60) * 60 - 59 * 60
    series = [{"t": start + 60 * i, "low": 0, "medium": 0, "high": 0} for i in range(60)]
    for r in db.q("SELECT CAST((ingested-?)/60 AS INTEGER) b, severity s, SUM(count) n FROM events WHERE ingested>=? GROUP BY b, s", (start, start)):
        if 0 <= r["b"] < 60:
            series[r["b"]][r["s"]] = r["n"]
    blocked = _active_blocks()
    top = db.q("SELECT src_ip ip, MAX(country) country, SUM(count) n, MAX(ingested) last, "
               "MAX(CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) r "
               "FROM events WHERE ingested>? AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY n DESC LIMIT 6", (since,))
    for t in top:
        t["blocked"] = t["ip"] in blocked
        t["sev"] = {3: "high", 2: "medium", 1: "low"}[t["r"]]
    kinds = db.q("SELECT kind, SUM(count) n FROM events WHERE ingested>? GROUP BY kind ORDER BY n DESC LIMIT 6", (since,))
    for k in kinds:
        k["title"] = knowledge.title(k["kind"])
        k["mitre"] = knowledge.INFO.get(k["kind"], {}).get("mitre", "")
    points = db.q("SELECT ROUND(lat,1) lat, ROUND(lon,1) lon, MAX(country) c, SUM(count) n, "
                  "MAX(CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) r "
                  "FROM events WHERE lat IS NOT NULL AND ingested>? GROUP BY ROUND(lat,1), ROUND(lon,1)", (since,))
    h = health.checks()
    level = health.overall(h)
    fails = [i for i in h if i["status"] == "fail"]
    recent_high = db.one("SELECT IFNULL(SUM(count),0) n FROM events WHERE severity='high' AND ingested>? AND simulated=0", (now - 900,))["n"]
    hour = db.one("SELECT IFNULL(SUM(count),0) n FROM events WHERE ingested>? AND simulated=0", (now - 3600,))["n"]
    total_real = db.one("SELECT COUNT(*) n FROM events WHERE simulated=0")["n"]
    mode = config.get("mode")
    if fails:
        status, text = "red", "Setup needs attention: %s" % fails[0]["detail"]
    elif recent_high:
        status = "amber"
        text = "%d serious attack%s in the last 15 minutes. %s" % (
            recent_high, "" if recent_high == 1 else "s",
            "Shadow mode is on, so nothing was blocked, but the attackers would have been." if mode == "shadow" else
            "Attackers were blocked automatically.")
    elif not total_real:
        status, text = "green", "Watching. No alerts yet, which is normal for a new setup."
    elif hour:
        status, text = "green", "All quiet. %d low-priority alert%s in the last hour. Nothing needs your attention." % (hour, "" if hour == 1 else "s")
    else:
        status, text = "green", "All quiet. No alerts in the last hour."
    return jsonify(
        status=status, headline=text, mode=mode,
        counts=dict(alerts=sum(sev.values()), high=sev.get("high", 0),
                    blocked=len(blocked),
                    would_block=db.one("SELECT COUNT(*) n FROM actions WHERE action='would_block' AND ts_epoch>?", (since,))["n"],
                    agents_online=db.one("SELECT COUNT(*) n FROM agents WHERE last_seen>?", (now - 90,))["n"]),
        severity=sev, series=series, top=top, kinds=kinds, map=points, flow=health.flow(),
        health=dict(level=level, fails=len(fails), warns=sum(1 for i in h if i["status"] == "warn")))


# ------------------------------------------------------------------- alerts

@app.get("/api/alerts")
@login_required
def alerts():
    where, args = ["1=1"], []
    for key, col in (("severity", "severity"), ("engine", "engine"), ("kind", "kind")):
        v = request.args.get(key)
        if v:
            where.append("%s=?" % col)
            args.append(v)
    q = request.args.get("q", "").strip()
    if q:
        where.append("(src_ip LIKE ? OR signature LIKE ? OR agent LIKE ? OR explain LIKE ?)")
        args += ["%" + q + "%"] * 4
    if request.args.get("sim") == "0":
        where.append("simulated=0")
    before = request.args.get("before")
    if before:
        where.append("id<?")
        args.append(int(before))
    limit = max(1, min(int(request.args.get("limit", 100)), 500))
    rows = db.q("SELECT * FROM events WHERE %s ORDER BY id DESC LIMIT ?" % " AND ".join(where), args + [limit])
    return jsonify([present(r) for r in rows])


@app.get("/api/ip/<ip>")
@login_required
def ip_detail(ip):
    if not _valid_ip(ip):
        abort(400)
    ev = db.q("SELECT * FROM events WHERE src_ip=? ORDER BY id DESC LIMIT 200", (ip,))
    ac = db.q("SELECT * FROM actions WHERE src_ip=? ORDER BY id DESC LIMIT 50", (ip,))
    agg = db.one("SELECT COUNT(*) rows, IFNULL(SUM(count),0) n, MIN(ingested) first, MAX(ingested) last, MAX(country) country, "
                 "MAX(CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) r FROM events WHERE src_ip=?", (ip,))
    return jsonify(
        ip=ip, total=agg["n"], first=agg["first"], last=agg["last"], country=agg["country"],
        worst={3: "high", 2: "medium", 1: "low", None: None}[agg["r"]],
        blocked=ip in _active_blocks(), protected=correlator.protected_reason(ip), intel=intel.lookup(ip),
        events=[present(e) for e in ev], actions=ac)


# ------------------------------------------------------------------- blocks

@app.get("/api/blocks")
@login_required
def blocks():
    active = db.q("SELECT * FROM actions WHERE action='block' AND active=1 ORDER BY ts_epoch DESC")
    for a in active:
        g = db.one("SELECT MAX(country) c FROM events WHERE src_ip=?", (a["src_ip"],))
        a["country"] = g["c"] if g else None
    recent = db.q("SELECT * FROM actions WHERE action IN ('would_block','skip_protected','unblock','block_failed','rate_limited') "
                  "ORDER BY id DESC LIMIT 40")
    return jsonify(active=active, recent=recent, firewall=firewall.status())


@app.post("/api/block")
@login_required
def block():
    d = request.get_json(silent=True) or {}
    ok, msg = correlator.manual_block(str(d.get("ip", "")).strip(), float(d.get("minutes", config.get("block_ttl_minutes"))))
    return jsonify(ok=ok, message=msg), (200 if ok else 400)


@app.post("/api/unblock")
@login_required
def unblock():
    ip = str((request.get_json(silent=True) or {}).get("ip", "")).strip()
    if not _valid_ip(ip):
        return jsonify(error="bad ip"), 400
    correlator.manual_unblock(ip)
    return jsonify(ok=True)


@app.post("/api/unblock_all")
@login_required
def unblock_all():
    return jsonify(ok=True, unblocked=correlator.unblock_all())


# ---------------------------------------------------------------- whitelist

@app.get("/api/whitelist")
@login_required
def whitelist():
    return jsonify(items=db.q("SELECT * FROM whitelist ORDER BY id"),
                   automatic=sorted(correlator.local_ips()) + ([config.get("management_ip")] if config.get("management_ip") else []))


@app.post("/api/whitelist")
@login_required
def whitelist_add():
    d = request.get_json(silent=True) or {}
    raw = str(d.get("cidr", "")).strip()
    try:
        net = str(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        return jsonify(error="That is not a valid address or range (example: 192.168.56.10 or 192.168.56.0/24)."), 400
    db.x("INSERT OR IGNORE INTO whitelist(cidr,note,added_at,added_by) VALUES(?,?,?,?)",
         (net, str(d.get("note", ""))[:80], time.time(), "admin"))
    return jsonify(ok=True)


@app.post("/api/whitelist/mine")
@login_required
def whitelist_mine():
    db.x("INSERT OR IGNORE INTO whitelist(cidr,note,added_at,added_by) VALUES(?,?,?,?)",
         (request.remote_addr, "my computer (added from the dashboard)", time.time(), "admin"))
    return jsonify(ok=True, ip=request.remote_addr)


@app.delete("/api/whitelist/<int:i>")
@login_required
def whitelist_del(i):
    db.x("DELETE FROM whitelist WHERE id=?", (i,))
    return jsonify(ok=True)


# ----------------------------------------------------------------- settings

SEV_KEYS = ("severity_block_threshold", "notify_min_severity")


@app.get("/api/settings")
@login_required
def get_settings():
    return jsonify(settings=config.all_settings(masked=True), intel=intel.stats(),
                   notifications=db.q("SELECT * FROM notifications WHERE channel!='console' ORDER BY id DESC LIMIT 8"))


@app.post("/api/settings")
@login_required
def set_settings():
    d = request.get_json(silent=True) or {}
    errors, warnings, changed = [], [], []
    for k, v in d.items():
        if k not in config.DEFAULTS or k in config.HIDDEN:
            continue
        try:
            if k in config.SECRET:
                if v in ("", None):
                    continue                      # blank means "leave it as it is"
                if v == "__clear__":
                    v = ""
            else:
                v = config.coerce(k, v)
            if k == "mode" and v not in ("shadow", "live"):
                raise ValueError("Mode must be shadow or live.")
            if k in SEV_KEYS and v not in knowledge.SEV_RANK:
                raise ValueError("Severity must be low, medium or high.")
            if k == "home_net":
                ipaddress.ip_network(v, strict=False)
            if k == "management_ip" and v:
                ipaddress.ip_address(v)
            if k == "honeypot_ports" and any(not 1 <= p <= 65535 for p in v):
                raise ValueError("Ports must be between 1 and 65535.")
            if isinstance(config.DEFAULTS[k], (int, float)) and not isinstance(config.DEFAULTS[k], bool) and float(v) < 0:
                raise ValueError("%s cannot be negative." % k)
        except (ValueError, TypeError) as e:
            errors.append("%s: %s" % (k, e))
            continue
        config.put(k, v)
        changed.append(k)
    if d.get("mode") == "live" and not db.one("SELECT 1 x FROM whitelist LIMIT 1") and not config.get("management_ip"):
        warnings.append("You are now in Live mode but have not protected your own address. Add it under Settings > Protected addresses.")
    return jsonify(ok=not errors, errors=errors, warnings=warnings, changed=changed), (200 if not errors else 400)


@app.post("/api/enrollment/regenerate")
@login_required
def regen_enrollment():
    v = secrets.token_urlsafe(9)
    config.put("enrollment_password", v)
    return jsonify(ok=True)


@app.post("/api/notify/test")
@login_required
def notify_test():
    ok, detail = notify.test_channel((request.get_json(silent=True) or {}).get("channel", ""))
    return jsonify(ok=ok, detail=detail)


@app.post("/api/intel/update")
@login_required
def intel_update():
    threading.Thread(target=intel.update, kwargs={"force": True}, daemon=True).start()
    return jsonify(ok=True, message="Downloading in the background. Check again in a minute.")


@app.post("/api/intel/custom")
@login_required
def intel_custom():
    ip = str((request.get_json(silent=True) or {}).get("ip", "")).strip()
    if not _valid_ip(ip):
        return jsonify(error="Not a valid IP address."), 400
    intel.add_custom(ip)
    return jsonify(ok=True)


# ------------------------------------------------------------------- health

@app.get("/api/health")
@login_required
def health_api():
    items = health.checks()
    return jsonify(items=items, level=health.overall(items), flow=health.flow(), selftest=selftest.last())


@app.post("/api/selftest")
@login_required
def selftest_run():
    return jsonify(selftest.run())


@app.get("/api/rules")
@login_required
def rules():
    out = []
    for name, target in (("suricata_custom.rules", "/opt/idps/rules/suricata_custom.rules"),
                         ("snort_local.rules", "/etc/snort/rules/local.rules")):
        with open(os.path.join(paths.RULES_DIR, name)) as f:
            out.append({"name": name, "target": target, "content": f.read()})
    return jsonify(out)


# ------------------------------------------------------------------- agents

def _manager_url():
    h = request.args.get("host", "").strip().rstrip("/")
    if h and agent_install.valid_manager(h):
        return h
    return request.host_url.rstrip("/")


@app.get("/api/agents")
@login_required
def agents_list():
    rows = db.q("SELECT id,name,platform,hostname,version,enrolled_at,last_seen,last_ip,info FROM agents ORDER BY enrolled_at DESC")
    for r in rows:
        r["online"] = bool(r["last_seen"] and time.time() - r["last_seen"] < 90)
        r["info"] = json.loads(r["info"]) if r["info"] else {}
    return jsonify(agents=rows, enrollment_ready=bool(config.get("enrollment_password")))


@app.delete("/api/agents/<aid>")
@login_required
def agents_del(aid):
    db.x("DELETE FROM agents WHERE id=?", (aid,))
    return jsonify(ok=True)


@app.get("/api/agent_install")
@login_required
def agent_install_info():
    m = _manager_url()
    return jsonify(manager=m, commands=agent_install.commands(m, config.get("enrollment_password")),
                   localhost=("localhost" in m or "127.0.0.1" in m))


def _token_ok():
    return auth.same(request.args.get("token"), config.get("enrollment_password"))


@app.get("/agent/agent.py")
def dl_agent():
    if not _token_ok():
        abort(403)
    return send_from_directory(paths.AGENT_DIR, "agent.py", mimetype="text/x-python")


@app.get("/agent/install.sh")
def dl_sh():
    if not _token_ok():
        abort(403)
    return Response(agent_install.render("sh", request.host_url.rstrip("/"), request.args["token"]), mimetype="text/plain")


@app.get("/agent/install.ps1")
def dl_ps1():
    if not _token_ok():
        abort(403)
    return Response(agent_install.render("ps1", request.host_url.rstrip("/"), request.args["token"]), mimetype="text/plain")


@app.post("/api/enroll")
def enroll():
    ip = request.remote_addr
    if _blocked_by_rate(_enroll_fail, ip, 10, 600):
        return jsonify(error="too many attempts"), 429
    d = request.get_json(silent=True) or {}
    name = str(d.get("name", "")).strip()[:60]
    if not name or not auth.same(d.get("enrollment_password"), config.get("enrollment_password")):
        _bump(_enroll_fail, ip)
        return jsonify(error="invalid enrollment password"), 403
    aid, key = uuid.uuid4().hex[:12], secrets.token_hex(32)
    db.x("INSERT INTO agents(id,name,platform,hostname,key_hash,enrolled_at,last_seen,last_ip) VALUES(?,?,?,?,?,?,?,?)",
         (aid, name, str(d.get("platform", ""))[:30], name, hashlib.sha256(key.encode()).hexdigest(), time.time(), time.time(), ip))
    return jsonify(agent_id=aid, key=key)


def _agent_auth():
    aid, key = request.headers.get("X-Agent-Id", ""), request.headers.get("X-Agent-Key", "")
    row = db.one("SELECT * FROM agents WHERE id=?", (aid,)) if aid else None
    if row and auth.same(row["key_hash"], hashlib.sha256(key.encode()).hexdigest()):
        return row
    return None


@app.post("/api/ingest")
def ingest():
    agent = _agent_auth()
    if not agent:
        return jsonify(error="unauthorized"), 401
    d = request.get_json(silent=True) or {}
    info = d.get("info") or {}
    db.x("UPDATE agents SET last_seen=?, last_ip=?, hostname=?, version=?, platform=?, info=? WHERE id=?",
         (time.time(), request.remote_addr, str(info.get("hostname", agent["hostname"]))[:60],
          str(info.get("version", ""))[:20], str(info.get("platform", agent["platform"]))[:30],
          json.dumps(info)[:4000], agent["id"]))
    n = 0
    for e in (d.get("events") or [])[:500]:
        if not isinstance(e, dict):
            continue
        correlator.handle_event({
            "engine": e.get("engine") if e.get("engine") in ("weblog", "fim") else "weblog",
            "agent": agent["name"], "src_ip": e.get("src_ip"), "dst_port": e.get("dst_port"),
            "signature": e.get("signature"), "severity": e.get("severity"), "raw": e.get("raw"), "ts": e.get("ts")})
        n += 1
    return jsonify(status="ok", received=n)


# ---------------------------------------------------------------- simulator

@app.get("/api/sim/scenarios")
@login_required
def sim_scenarios():
    return jsonify([{"id": k, "label": v["label"], "story": v["story"]} for k, v in simulate.SCENARIOS.items()])


@app.post("/api/sim/run")
@login_required
def sim_run():
    name = (request.get_json(silent=True) or {}).get("scenario")
    if name not in simulate.SCENARIOS:
        return jsonify(error="unknown scenario"), 400
    return jsonify(simulate.run_scenario(name))


@app.get("/api/sim/info")
@login_required
def sim_info():
    m = _manager_url()
    return jsonify(token=config.get("sim_token"), manager=m,
                   command="python3 lab_attacks.py --manager %s --token %s --target <IP-OF-YOUR-LAB-SERVER>" % (m, config.get("sim_token")))


@app.post("/api/sim/mark")
def sim_mark():
    if not auth.same(request.headers.get("X-Sim-Token"), config.get("sim_token")):
        return jsonify(error="bad token"), 403
    d = request.get_json(silent=True) or {}
    if d.get("phase") == "start":
        return jsonify(run_id=simulate.mark(str(d.get("attack"))[:30], "start"))
    simulate.mark(None, "end", int(d.get("run_id", 0)))
    return jsonify(ok=True)


@app.get("/api/sim/report")
@login_required
def sim_report():
    return jsonify(simulate.report())


# ------------------------------------------------------------- live stream

def _sse(name, data):
    return "event: %s\ndata: %s\n\n" % (name, json.dumps(data))


@app.get("/api/stream")
@login_required
def stream():
    last_ev = db.one("SELECT IFNULL(MAX(id),0) m FROM events")["m"]
    last_ac = db.one("SELECT IFNULL(MAX(id),0) m FROM actions")["m"]

    def gen():
        nonlocal last_ev, last_ac
        yield "retry: 3000\n\n" + _sse("hello", {"t": time.time()})
        tick = 0
        while True:
            for e in db.q("SELECT * FROM events WHERE id>? ORDER BY id LIMIT 200", (last_ev,)):
                last_ev = e["id"]
                yield _sse("event", present(e))
            for a in db.q("SELECT * FROM actions WHERE id>? ORDER BY id LIMIT 200", (last_ac,)):
                last_ac = a["id"]
                yield _sse("action", a)
            tick += 1
            if tick % 5 == 0:
                yield _sse("tick", {"t": time.time(), "flow": health.flow()})
            time.sleep(1)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def main():
    app.run(host=os.environ.get("IDPS_BIND", "0.0.0.0"), port=int(os.environ.get("IDPS_PORT", "5000")),
            threaded=True, debug=False)


if __name__ == "__main__":
    main()
