"""
End-to-end test: starts the REAL system (run.py -> API, watchers, honeypot,
maintenance as separate processes), logs in over HTTP, opens the live stream
like a browser would, then makes other processes produce alerts and checks
they arrive live. Needs: requests. Uses real iptables if available.

    python3 tests/test_integration.py
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="idps-it-")
PORT = 5077
HP = 22222
BASE = "http://127.0.0.1:%d" % PORT
PASS = "integration-pass-1"
env = dict(os.environ, IDPS_DATA=os.path.join(TMP, "data"), IDPS_LOGS=os.path.join(TMP, "logs"), IDPS_PORT=str(PORT),
           IDPS_BIND="127.0.0.1", PYTHONPATH=ROOT)
os.makedirs(os.path.join(TMP, "live"))
EVE, ALERT = os.path.join(TMP, "live", "eve.json"), os.path.join(TMP, "live", "alert")
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, ("- " + detail) if detail else ""), flush=True)


def py(*args):
    return subprocess.run([sys.executable] + list(args), cwd=ROOT, env=env, capture_output=True, text=True)


def wait_for(fn, timeout=12, step=0.3):
    t = time.time()
    while time.time() - t < timeout:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return None


def main():
    # prepare settings before anything starts
    py("manage.py", "set-password", PASS)
    py("manage.py", "set", "suricata_eve_log", EVE)
    py("manage.py", "set", "snort_alert_log", ALERT)
    py("manage.py", "set", "honeypot_ports", str(HP))
    py("manage.py", "set", "notify_cooldown_seconds", "1")
    open(EVE, "w").close()
    open(ALERT, "w").close()

    sup = subprocess.Popen([sys.executable, "run.py"], cwd=ROOT, env=env, stdout=open(os.path.join(TMP, "run.out"), "w"),
                           stderr=subprocess.STDOUT)
    try:
        s = requests.Session()
        up = wait_for(lambda: requests.get(BASE + "/login", timeout=2).status_code == 200 if _up() else False, 20)
        check("API starts and serves the login page", bool(up))
        if not up:
            print(open(os.path.join(TMP, "run.out")).read()[-1500:])
            return

        # ---- security basics
        check("Dashboard data is refused without login", requests.get(BASE + "/api/overview").status_code == 401)
        check("Dashboard page redirects to login", requests.get(BASE + "/", allow_redirects=False).status_code == 302)
        r = requests.post(BASE + "/api/login", json={"password": "wrong"}, headers={"X-IDPS": "1"})
        check("Wrong password is rejected", r.status_code == 401)
        r = s.post(BASE + "/api/login", json={"password": PASS}, headers={"X-IDPS": "1"})
        check("Correct password logs in", r.status_code == 200)
        H = {"X-IDPS": "1"}
        check("Changing settings without the CSRF header is refused", s.post(BASE + "/api/settings", json={"mode": "live"}).status_code == 400)

        # ---- open the live stream like a browser
        got = []
        stop = threading.Event()

        def listen():
            try:
                with s.get(BASE + "/api/stream", stream=True, timeout=60) as resp:
                    name = None
                    for raw in resp.iter_lines(decode_unicode=True):
                        if stop.is_set():
                            break
                        if raw.startswith("event:"):
                            name = raw[6:].strip()
                        elif raw.startswith("data:") and name:
                            got.append((name, json.loads(raw[5:])))
            except Exception:
                pass
        threading.Thread(target=listen, daemon=True).start()
        wait_for(lambda: any(n == "hello" for n, _ in got), 8)
        check("Live stream connects", any(n == "hello" for n, _ in got))

        # ---- alerts produced by OTHER processes must reach the stream (the v1 bug)
        eve = ('{"timestamp":"2026-10-22T10:00:00.123456+0000","event_type":"alert","src_ip":"10.9.0.5","dest_ip":"10.9.0.10",'
               '"dest_port":22,"proto":"TCP","alert":{"signature":"Port scan detected","severity":3}}\n')
        with open(EVE, "a") as f:
            f.write(eve)
        snort = "10/22-10:00:01.000000  [**] [1:1000013:2] ICMP flood detected [**] [Classification: Attempted Denial of Service] [Priority: 1] {ICMP} 10.9.0.7 -> 10.9.0.10\n"
        with open(ALERT, "a") as f:
            f.write(snort)
        sock = socket.create_connection(("127.0.0.1", HP), timeout=3) if wait_for(lambda: _port_open(HP), 10) else None
        if sock:
            sock.sendall(b"SSH-2.0-test\r\n")
            time.sleep(0.4)
            sock.close()

        def seen(engine):
            return any(n == "event" and d["engine"] == engine for n, d in got)
        check("Suricata alert from the watcher process reaches the live stream", bool(wait_for(lambda: seen("suricata"), 8)))
        check("Snort alert (ICMP, no port) from the watcher process reaches the live stream", bool(wait_for(lambda: seen("snort"), 8)))
        check("Honeypot touch from the honeypot process reaches the live stream", bool(wait_for(lambda: seen("honeypot"), 8)))
        ev = next((d for n, d in got if n == "event" and d["engine"] == "snort"), {})
        check("Alert arrives with plain-English text and MITRE tag", ev.get("title") == "Traffic flood" and ev.get("mitre") == "T1498"
              and "10.9.0.7" in (ev.get("explain") or ""), "%s / %s" % (ev.get("title"), ev.get("mitre")))
        check("Shadow mode (default) decided 'would block' for the flood", ev.get("decision") == "would_block")

        # ---- history survives a page refresh (v1 bug: feed was empty after reload)
        al = s.get(BASE + "/api/alerts").json()
        check("Alert history is available after a refresh", len(al) >= 3, "%d rows" % len(al))
        ov = s.get(BASE + "/api/overview").json()
        check("Overview reports status, counts and pipeline flow", ov["status"] in ("green", "amber", "red") and ov["counts"]["alerts"] >= 3
              and "capture" in ov["flow"], ov["headline"][:70])
        ip = s.get(BASE + "/api/ip/10.9.0.7").json()
        check("Per-address timeline works", ip["total"] >= 1 and ip["events"][0]["src_ip"] == "10.9.0.7")

        # ---- live mode: another process really blocks, via the real firewall
        fw_ok = subprocess.run(["iptables", "-S"], capture_output=True).returncode == 0 if shutil.which("iptables") else False
        if fw_ok:
            r = s.post(BASE + "/api/settings", json={"mode": "live", "block_ttl_minutes": 5}, headers=H)
            check("Switching to Live mode via the dashboard API", r.status_code == 200, "; ".join(r.json().get("warnings", []))[:60])
            bad = ('{"timestamp":"2026-10-22T10:01:00.000000+0000","event_type":"alert","src_ip":"203.0.113.77","dest_ip":"10.9.0.10",'
                   '"alert":{"signature":"TCP SYN flood detected","severity":1}}\n')
            with open(EVE, "a") as f:
                f.write(bad)
            blocked = wait_for(lambda: "203.0.113.77" in s.get(BASE + "/api/blocks", headers=H).json()["active"].__repr__(), 8)
            check("Attacker is blocked by the watcher process and shows in /api/blocks", bool(blocked))
            ipt = subprocess.run(["iptables", "-S", "IDPS_BLOCK"], capture_output=True, text=True).stdout
            check("The block really exists in the kernel firewall", "203.0.113.77" in ipt)
            check("The block action reached the live stream", bool(wait_for(lambda: any(n == "action" and d.get("action") == "block" for n, d in got), 6)))
            s.post(BASE + "/api/unblock", json={"ip": "203.0.113.77"}, headers=H)
            ipt = subprocess.run(["iptables", "-S", "IDPS_BLOCK"], capture_output=True, text=True).stdout
            check("Unblock from the dashboard removes it from the firewall", "203.0.113.77" not in ipt)
            s.post(BASE + "/api/settings", json={"mode": "shadow"}, headers=H)
        else:
            print("  [SKIP] live-mode firewall checks: iptables not usable here")

        # ---- health page reflects reality
        h = s.get(BASE + "/api/health").json()
        by = {i["id"]: i for i in h["items"]}
        check("Health: watcher/honeypot/cleanup processes are reported alive",
              by["maintenance"]["status"] == "ok" and by["honeypot"]["status"] == "ok", by["honeypot"]["detail"])

        # ---- run self-test through the API while everything is running
        st = s.post(BASE + "/api/selftest", headers=H).json()
        bad = [t["name"] for t in st["tests"] if t["status"] == "fail"]
        check("Self-test through the running system: no failures", not bad, "%d passed, %d skipped %s" % (st["passed"], st["skipped"], bad))
        sim = s.post(BASE + "/api/sim/run", json={"scenario": "sqli"}, headers=H).json()
        check("Safe simulator injects a labelled demo attack", sim.get("decision") in ("would_block", "blocked", "dedup") and sim["ip"].startswith(("198.51.100.", "203.0.113.")))
        rep = s.get(BASE + "/report")
        check("Printable report renders", rep.status_code == 200 and "Security summary" in rep.text)
        check("CSV export works", s.get(BASE + "/api/export/events.csv").text.startswith("time,source"))
        stop.set()
    finally:
        sup.send_signal(signal.SIGTERM)
        try:
            sup.wait(15)
        except subprocess.TimeoutExpired:
            sup.kill()
        left = subprocess.run(["pgrep", "-f", "idps\\.(api|watchers|honeypot|maintenance)"], capture_output=True, text=True).stdout.split()
        check("Stopping the supervisor stops every child process", not left, str(left))
        subprocess.run(["iptables", "-F", "IDPS_BLOCK"], capture_output=True)
        shutil.rmtree(TMP, ignore_errors=True)
    print("\n%d/%d checks passed" % (sum(results), len(results)))
    return 0 if all(results) else 1


def _up():
    try:
        requests.get(BASE + "/login", timeout=1)
        return True
    except requests.RequestException:
        return False


def _port_open(p):
    try:
        socket.create_connection(("127.0.0.1", p), timeout=1).close()
        return True
    except OSError:
        return False


if __name__ == "__main__":
    sys.exit(main())
