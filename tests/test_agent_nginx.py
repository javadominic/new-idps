"""
Real-world agent test (needs root, nginx, curl). It:
  1. starts the manager and real nginx (writing /var/log/nginx/access.log)
  2. installs the agent with the REAL installer script from the dashboard
  3. sends real attacks and harmless requests with curl
  4. checks what the manager recorded (including false positives)
  5. tests file monitoring, offline spooling, revocation, and the IIS log format
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="idps-ag-")
PORT = 5081
BASE = "http://127.0.0.1:%d" % PORT
AG = os.path.join(TMP, "agent")
env = dict(os.environ, IDPS_DATA=os.path.join(TMP, "data"), IDPS_LOGS=os.path.join(TMP, "logs"), IDPS_PORT=str(PORT),
           IDPS_BIND="127.0.0.1", PYTHONPATH=ROOT)
results = []
procs = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, ("- " + str(detail)) if detail else ""), flush=True)


def run(*a, **k):
    return subprocess.run(list(a), cwd=ROOT, env=env, capture_output=True, text=True, **k)


def wait_for(fn, t=10, step=0.4):
    end = time.time() + t
    while time.time() < end:
        try:
            v = fn()
        except Exception:
            v = None
        if v:
            return v
        time.sleep(step)
    return None


def start_api():
    p = subprocess.Popen([sys.executable, "-m", "idps.api"], cwd=ROOT, env=env, stdout=open(os.path.join(TMP, "api.log"), "a"), stderr=subprocess.STDOUT)
    wait_for(lambda: requests.get(BASE + "/login", timeout=1).ok, 10)
    return p


def sigs(engine=None):
    s = requests.Session()
    s.post(BASE + "/api/login", json={"password": "agent-test-pw1"}, headers={"X-IDPS": "1"})
    rows = s.get(BASE + "/api/alerts?limit=300").json()
    return [r for r in rows if not engine or r["engine"] == engine]


def curl(path, *extra):
    subprocess.run(["curl", "-s", "-o", "/dev/null", "http://127.0.0.1:8099" + path] + list(extra), capture_output=True)


def main():
    os.makedirs(os.path.join(TMP, "www"))
    open(os.path.join(TMP, "www", "index.html"), "w").write("<h1>hello</h1>")
    webroot = "/var/www/html"
    os.makedirs(webroot, exist_ok=True)
    open(os.path.join(webroot, "index.html"), "w").write("<h1>site</h1>")
    conf = os.path.join(TMP, "nginx.conf")
    open(conf, "w").write("""pid %s/nginx.pid; error_log /var/log/nginx/error.log; events{}
http{ access_log /var/log/nginx/access.log; server{ listen 8099; root %s;
  location = /login { return 401; } location / { try_files $uri $uri/ =404; } } }""" % (TMP, webroot))
    os.makedirs("/var/log/nginx", exist_ok=True)
    open("/var/log/nginx/access.log", "w").close()
    subprocess.run(["nginx", "-c", conf], check=True)

    run(sys.executable, "manage.py", "set-password", "agent-test-pw1")
    api = start_api()
    try:
        pw = run(sys.executable, "manage.py", "show-enrollment").stdout.strip()
        # ---- install with the real generated script, exactly as pasted by a user
        script = requests.get(BASE + "/agent/install.sh", params={"token": pw}).text
        check("Installer script is served with the right token", script.startswith("#!/bin/sh") and BASE in script)
        check("Installer is refused with a wrong token", requests.get(BASE + "/agent/install.sh", params={"token": "nope"}).status_code == 403)
        check("Agent file is refused with a wrong token", requests.get(BASE + "/agent/agent.py", params={"token": "nope"}).status_code == 403)
        r = subprocess.run(["sh"], input=script, env=dict(env, IDPS_AGENT_DIR=AG, IDPS_AGENT_NAME="web-test-01"), capture_output=True, text=True, timeout=60)
        print("    installer:", " | ".join(l.strip() for l in r.stdout.splitlines()[:7]))
        check("Real installer script ran and enrolled the agent", r.returncode == 0 and "enrolled as web-test-01" in r.stdout, r.stderr[-200:])
        cfg = json.load(open(os.path.join(AG, "config.json")))
        check("Installer auto-detected nginx log and web folder", "/var/log/nginx/access.log" in cfg["web_logs"] and any("/var/www/html" in p for p in cfg["fim_paths"]), cfg["web_logs"])
        check("Config file is private (mode 600)", oct(os.stat(os.path.join(AG, "config.json")).st_mode)[-3:] == "600")
        # speed the file monitor up for the test, then start the agent (no systemd here, like the script's fallback)
        cfg["fim_interval"] = 2
        json.dump(cfg, open(os.path.join(AG, "config.json"), "w"))
        agent = subprocess.Popen([sys.executable, os.path.join(AG, "agent.py"), "--config", os.path.join(AG, "config.json")],
                                 stdout=open(os.path.join(TMP, "agent.log"), "w"), stderr=subprocess.STDOUT)
        procs.append(agent)
        s = requests.Session()
        s.post(BASE + "/api/login", json={"password": "agent-test-pw1"}, headers={"X-IDPS": "1"})
        ag = wait_for(lambda: [a for a in s.get(BASE + "/api/agents").json()["agents"] if a["online"]], 10)
        check("Agent shows as online on the dashboard", bool(ag), ag[0]["name"] if ag else "")
        time.sleep(2.5)       # let the agent take its file baseline

        # ---- real traffic: attacks AND harmless requests
        attacks = {
            "sqli": "/?id=1%27%20OR%20%271%27=%271", "union": "/?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
            "xss": "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "trav": "/..%2f..%2f..%2fetc%2fpasswd",
            "env": "/.env", "dbl": "/?id=1%2527%2520OR%25201=1"}
        for i, p in enumerate(attacks.values()):      # a different source address per payload (the agent merges repeats)
            curl(p, "--interface", "127.0.0.%d" % (20 + i))
        curl("/", "-A", "sqlmap/1.7")
        for _ in range(7):
            curl("/login", "-X", "POST")
        benign = ["/", "/index.html", "/search?q=it's+fine", "/blog/2024-01-01--summary", "/union-station", "/?q=select+a+color",
                  "/products?id=5&sort=asc", "/about-us", "/css/site.css?v=3", "/?name=Bob+O'Brien"]
        for p in benign:
            curl(p)
        time.sleep(4)
        found = {e["signature"] for e in sigs("weblog")}
        for sig in ("Possible SQL injection attempt", "Possible XSS attempt", "Possible path traversal attempt", "Probe for sensitive file",
                    "Known hacking tool in User-Agent", "Repeated login failures (possible brute force)"):
            check("Real nginx traffic detected: " + sig, sig in found)
        raws = " ".join(e["raw"] for e in sigs("weblog"))
        check("Double-encoded SQL injection (%2527) is caught", "%2527" in raws)
        check("UNION SELECT attack is caught", "UNION" in raws)
        fp = [e for e in sigs("weblog") if any(b in e["raw"] for b in ("union-station", "it's+fine", "2024-01-01--summary", "select+a+color", "O'Brien", "sort=asc"))]
        check("No false alarms on 7 harmless requests (apostrophes, 'union', 'select', '--')", not fp, [e["raw"][:60] for e in fp])

        # ---- file integrity
        open(os.path.join(webroot, "index.html"), "w").write("<h1>defaced</h1>")
        open(os.path.join(webroot, "shell.php"), "w").write("<?php system($_GET['c']); ?>")
        got = wait_for(lambda: {e["signature"] for e in sigs("fim")}, 8)
        sg = " ".join(got or [])
        check("Modified web file is reported", "modified" in sg and "index.html" in sg)
        check("New script file in the web folder is reported as urgent", any(e["severity"] == "high" and "shell.php" in e["signature"] for e in sigs("fim")))
        os.remove(os.path.join(webroot, "shell.php"))
        open(os.path.join(webroot, "index.html"), "w").write("<h1>site</h1>")

        # ---- manager down: events are spooled, then delivered
        api.send_signal(signal.SIGTERM)
        api.wait(10)
        before = len(sigs.__call__("weblog")) if False else None
        curl("/?id=1%27%20OR%20%272%27=%272")     # attack while manager is offline
        time.sleep(3)
        spool = os.path.join(AG, "spool.jsonl")
        check("While the manager is down, events wait in the local spool", os.path.exists(spool) and os.path.getsize(spool) > 0)
        api = start_api()
        flushed = wait_for(lambda: not os.path.exists(spool), 15)
        s = requests.Session()
        s.post(BASE + "/api/login", json={"password": "agent-test-pw1"}, headers={"X-IDPS": "1"})
        check("When the manager returns, the spool is delivered and emptied", bool(flushed))
        check("The attack made during the outage reached the dashboard", any("%272%27" in e["raw"] for e in sigs("weblog")))

        # ---- revocation
        aid = s.get(BASE + "/api/agents").json()["agents"][0]["id"]
        s.delete(BASE + "/api/agents/" + aid, headers={"X-IDPS": "1"})
        cred = json.load(open(os.path.join(AG, "agent.key.json")))
        r = requests.post(BASE + "/api/ingest", json={"events": []}, headers={"X-Agent-Id": cred["agent_id"], "X-Agent-Key": cred["key"]})
        check("A removed agent can no longer send events", r.status_code == 401)
        r = requests.post(BASE + "/api/enroll", json={"name": "x", "enrollment_password": "wrong"})
        check("Enrolling with a wrong password is refused", r.status_code == 403)
        r = requests.post(BASE + "/api/ingest", json={"events": [{"engine": "suricata", "src_ip": "9.9.9.9", "signature": "forged", "severity": "high"}]},
                          headers={"X-Agent-Id": "nope", "X-Agent-Key": "nope"})
        check("Forged event without a key is refused", r.status_code == 401)

        # ---- IIS (Windows) log format, via --once
        iis = os.path.join(TMP, "iis"); os.makedirs(iis)
        open(os.path.join(iis, "u_ex261022.log"), "w").write(
            "#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n"
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status\n"
            "2026-10-22 10:00:00 10.0.0.2 GET /default.aspx id=1'+OR+'1'='1 80 - 10.9.9.9 Mozilla/5.0 200\n"
            "2026-10-22 10:00:01 10.0.0.2 GET /about.aspx - 80 - 10.9.9.8 Mozilla/5.0 200\n")
        icfg = os.path.join(TMP, "iis.json")
        cred2 = requests.post(BASE + "/api/enroll", json={"name": "iis-test", "enrollment_password": pw, "platform": "Windows"}).json()
        os.makedirs(os.path.join(TMP, "iisagent")); shutil.copy(os.path.join(ROOT, "host_agent", "agent.py"), os.path.join(TMP, "iisagent", "agent.py"))
        json.dump(cred2, open(os.path.join(TMP, "iisagent", "agent.key.json"), "w"))
        json.dump({"manager_url": BASE, "enrollment_password": pw, "agent_name": "iis-test", "web_logs": [os.path.join(iis, "*.log")], "fim_paths": []}, open(icfg, "w"))
        r = subprocess.run([sys.executable, os.path.join(TMP, "iisagent", "agent.py"), "--config", icfg, "--once", "--from-start"], capture_output=True, text=True, timeout=30)
        s.post(BASE + "/api/login", json={"password": "agent-test-pw1"}, headers={"X-IDPS": "1"})
        iis_ev = [e for e in sigs("weblog") if e["src_ip"] == "10.9.9.9"]
        check("IIS (Windows) log format is parsed and the attack caught", bool(iis_ev) and iis_ev[0]["agent"] == "iis-test", r.stdout[-120:])
        check("Harmless IIS request produced no alert", not [e for e in sigs("weblog") if e["src_ip"] == "10.9.9.8"])
    finally:
        for p in procs:
            p.terminate()
        api.terminate()
        subprocess.run(["nginx", "-c", conf, "-s", "stop"], capture_output=True)
        shutil.rmtree(webroot + "/shell.php", ignore_errors=True)
        time.sleep(0.5)
        shutil.rmtree(TMP, ignore_errors=True)
    print("\n%d/%d checks passed" % (sum(results), len(results)))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
