#!/usr/bin/env python3
"""
One command starts everything:   sudo python3 run.py

Starts the dashboard/API, the Suricata and Snort readers, the honeypot and the
cleanup job as separate processes, and restarts any that crash. On the very
first run it creates your login and prints it ONCE.
"""
import argparse
import os
import re
import signal
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
from idps import auth, config, db, paths  # noqa: E402

COMPONENTS = {
    "api": ["-m", "idps.api"],
    "watch-suricata": ["-m", "idps.watchers", "suricata"],
    "watch-snort": ["-m", "idps.watchers", "snort"],
    "honeypot": ["-m", "idps.honeypot"],
    "maintenance": ["-m", "idps.maintenance"],
}


def detect_network():
    """Best-effort: the machine's main address and its network (used to pre-fill settings)."""
    try:
        out = subprocess.run(["ip", "-o", "-4", "route", "show", "default"], capture_output=True, text=True, timeout=3).stdout
        dev = re.search(r"dev (\S+)", out).group(1)
        addr = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", dev], capture_output=True, text=True, timeout=3).stdout
        import ipaddress
        iface = ipaddress.ip_interface(re.search(r"inet (\S+)", addr).group(1))
        return dev, str(iface.ip), str(iface.network)
    except Exception:
        return None, None, None


def first_run(quiet=False):
    created = auth.ensure_secrets()
    ssh = os.environ.get("SSH_CONNECTION", "").split()
    if ssh and not config.get("management_ip"):
        # the computer you are logged in from must never be blocked
        config.put("management_ip", ssh[0])
        db.x("INSERT OR IGNORE INTO whitelist(cidr,note,added_at,added_by) VALUES(?,?,?,?)",
             (ssh[0], "your SSH session (added at install)", time.time(), "installer"))
    if "admin_password" in created:
        dev, ip, net = detect_network()
        if net and config.get("home_net") == config.DEFAULTS["home_net"]:
            config.put("home_net", net)
        port = os.environ.get("IDPS_PORT", "5000")
        if not quiet:
            print("\n" + "=" * 62)
            print("  IDPS is ready. Open the dashboard:  http://%s:%s" % (ip or "<this-machine-ip>", port))
            print("  Login password (shown only once):   %s" % created["admin_password"])
            print("  Agent enrollment password:          %s" % created["enrollment_password"])
            print("  Forgot it later?  python3 manage.py set-password")
            print("=" * 62 + "\n", flush=True)
    return created


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="comma list of components to run")
    ap.add_argument("--init-only", action="store_true")
    a = ap.parse_args()
    first_run()
    if a.init_only:
        return
    names = [n for n in COMPONENTS if not a.only or n in a.only.split(",")]
    procs, backoff, started = {}, {}, {}

    def start(n):
        log = open(os.path.join(paths.LOG_DIR, n + ".log"), "a")
        env = dict(os.environ, PYTHONUNBUFFERED="1")
        procs[n] = subprocess.Popen([sys.executable] + COMPONENTS[n], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, env=env)
        started[n] = time.time()

    def stop(*_):
        for p in procs.values():
            if p.poll() is None:
                p.terminate()
        for p in procs.values():
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    for n in names:
        start(n)
        print("started %-15s (log: logs/%s.log)" % (n, n), flush=True)
    while True:
        for n in names:
            if procs[n].poll() is not None:
                # healthy for a minute = reset the back-off
                if time.time() - started[n] > 60:
                    backoff[n] = 1
                wait = backoff.get(n, 1)
                print("%s exited (code %s); restarting in %ds" % (n, procs[n].returncode, wait), flush=True)
                time.sleep(wait)
                backoff[n] = min(wait * 2, 30)
                start(n)
        time.sleep(1)


if __name__ == "__main__":
    main()
