#!/usr/bin/env python3
"""
IDPS host agent - the same single file runs on Linux, macOS and Windows.
Needs only Python 3.8+. No pip install, no compiler.

What it does
  * Enrolls once with the manager using the shared enrollment password and
    receives its own key (same idea as Wazuh's agent enrollment). Every later
    message carries that key. The manager stores only a hash of it.
  * Watches web server access logs (nginx, Apache, IIS) for SQL injection,
    script injection, folder escape, secret-file probes, hacking-tool
    user-agents and repeated login failures.
  * Watches files and folders for changes (file integrity monitoring), and
    flags brand-new script files appearing in a watched web folder.
  * Sends a heartbeat so the dashboard shows it online.
  * If the manager is unreachable, events wait in a local spool file and are
    sent when it comes back. Nothing is lost.

Normal use: the installer script writes config.json and starts this as a service.
Manual use:  python3 agent.py --config config.json
Testing:     python3 agent.py --once --from-start
"""
import argparse
import glob
import hashlib
import json
import os
import platform
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import unquote

VERSION = "2.0.0"
HERE = os.path.dirname(os.path.abspath(__file__))

DEFAULTS = {
    "manager_url": "http://127.0.0.1:5000",
    "enrollment_password": "",
    "agent_name": socket.gethostname(),
    "web_logs": [],          # file paths or patterns, e.g. /var/log/nginx/access.log
    "fim_paths": [],         # files or folders to watch for changes
    "fim_interval": 30,
    "poll": 1.0,
    "brute_count": 5,
    "brute_window": 30,
}

# ---------------------------------------------------------------- detection

SQLI = [r"union(\s|\+|/\*.*?\*/)+(all\s+)?select", r"\b(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"'\s*(or|and)\s*'", r"'\s*(or|and)\s+\d", r"(;|'|\")\s*--", r"\bsleep\s*\(\s*\d+\s*\)",
        r"benchmark\s*\(", r"information_schema", r"\bdrop\s+table\b", r"xp_cmdshell", r"load_file\s*\(",
        r"into\s+(out|dump)file", r"waitfor\s+delay"]
XSS = [r"<\s*script", r"javascript\s*:", r"\bon(error|load|mouseover|focus|click)\s*=",
       r"<\s*(img|svg|iframe|body)[^>]*\son\w+\s*="]
TRAVERSAL = [r"\.\./", r"\.\.\\"]
PROBE = [r"/\.env\b", r"/\.git(/|$)", r"/phpmyadmin", r"/etc/passwd", r"/boot\.ini", r"/wp-config", r"/\.aws/",
         r"/server-status"]
SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wpscan|acunetix|nessus|zgrab|havij|hydra", re.I)
LOGIN_PATH = re.compile(r"/(wp-login\.php|xmlrpc\.php|login|signin|admin|user/login)\b", re.I)
SCRIPT_EXT = {".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl", ".py", ".sh", ".exe", ".dll", ".war"}

SQLI_RE = [re.compile(p, re.I) for p in SQLI]
XSS_RE = [re.compile(p, re.I) for p in XSS]
TRAV_RE = [re.compile(p, re.I) for p in TRAVERSAL]
PROBE_RE = [re.compile(p, re.I) for p in PROBE]

# nginx / Apache "common" and "combined" formats
ACCESS_RE = re.compile(
    r'^(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[\d.]+)?"\s+(?P<status>\d{3})'
    r'(?:\s+\S+)?(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?')

_brute = {}      # ip -> [timestamps]
_recent = {}     # (ip, signature) -> last time we reported it


def decode(path):
    """Attack traffic arrives URL-encoded (%27, %20 ...), sometimes twice. Decode before matching."""
    return unquote(unquote(path)).replace("+", " ")


def classify(ip, method, path, status, ua, raw, cfg):
    """Return a list of event dicts for one web log line (usually empty)."""
    out, d = [], decode(path)

    def add(sig, sev):
        k = (ip, sig)
        if time.time() - _recent.get(k, 0) < 5:
            return
        _recent[k] = time.time()
        out.append({"engine": "weblog", "src_ip": ip, "dst_port": None, "signature": sig, "severity": sev,
                    "raw": raw[:500], "ts": time.strftime("%Y-%m-%dT%H:%M:%S")})

    if any(r.search(d) for r in SQLI_RE):
        add("Possible SQL injection attempt", "high")
    elif any(r.search(d) for r in XSS_RE):
        add("Possible XSS attempt", "high")
    elif any(r.search(d) for r in TRAV_RE):
        add("Possible path traversal attempt", "high")
    elif any(r.search(d) for r in PROBE_RE):
        add("Probe for sensitive file", "medium")
    if ua and SCANNER_UA.search(ua):
        add("Known hacking tool in User-Agent", "medium")

    failed = status in ("401", "403")
    login_post = method == "POST" and LOGIN_PATH.search(d)
    if failed or login_post:
        hits = _brute.setdefault(ip, [])
        hits.append(time.time())
        hits[:] = [t for t in hits if time.time() - t < cfg["brute_window"]]
        need = cfg["brute_count"] if failed else cfg["brute_count"] * 2
        if len(hits) >= need:
            add("Repeated login failures (possible brute force)", "medium")
    if len(_brute) > 5000:
        _brute.clear()
    if len(_recent) > 5000:
        _recent.clear()
    return out


class LogTail:
    """Follows one log (or a glob such as an IIS folder, always the newest file)."""

    def __init__(self, pattern, from_start=False):
        self.pattern, self.from_start = pattern, from_start
        self.path = self.f = None
        self.inode = None
        self.fields = None            # IIS column names

    def _newest(self):
        files = glob.glob(self.pattern)
        return max(files, key=os.path.getmtime) if files else None

    def _open(self, p):
        try:
            self.f = open(p, "r", errors="replace")
            self.inode = os.stat(p).st_ino
        except OSError:
            self.f = None
            return
        self.path = p
        self.fields = None
        # IIS logs describe their columns on a "#Fields:" line near the top
        head = self.f.read(4096)
        for ln in head.splitlines():
            if ln.startswith("#Fields:"):
                self.fields = ln[8:].split()
        if self.from_start:
            self.f.seek(0)
        else:
            self.f.seek(0, os.SEEK_END)
        self.from_start = True        # a rotated/new file is always read from its beginning

    def lines(self):
        p = self._newest()
        if p is None:
            return []
        try:
            if self.f is None or p != self.path or os.stat(p).st_ino != self.inode or os.stat(p).st_size < self.f.tell():
                if self.f:
                    self.f.close()
                self._open(p)
            if self.f is None:
                return []
        except OSError:
            return []
        out = []
        while True:
            pos = self.f.tell()
            line = self.f.readline()
            if not line:
                break
            if not line.endswith("\n"):
                self.f.seek(pos)
                break
            out.append(line.rstrip("\r\n"))
        return out


def analyze(line, tail, cfg):
    if not line.strip():
        return []
    if line.startswith("#"):
        if line.startswith("#Fields:"):
            tail.fields = line[8:].split()
        return []
    if tail.fields:                                   # IIS W3C format
        v = line.split(" ")
        if len(v) < len(tail.fields):
            return []
        r = dict(zip(tail.fields, v))
        q = r.get("cs-uri-query", "-")
        path = r.get("cs-uri-stem", "/") + ("" if q in ("-", "") else "?" + q)
        return classify(r.get("c-ip", ""), r.get("cs-method", ""), path, r.get("sc-status", ""),
                        r.get("cs(User-Agent)", "").replace("+", " "), line, cfg)
    m = ACCESS_RE.match(line)
    if not m:
        return []
    return classify(m.group("ip"), m.group("method"), m.group("path"), m.group("status"), m.group("ua") or "", line, cfg)


# --------------------------------------------------------------------- FIM

class Fim:
    MAX_FILES = 5000

    def __init__(self, paths, baseline_file):
        self.paths, self.file = paths, baseline_file
        try:
            with open(baseline_file) as f:
                self.base = json.load(f)
            self.fresh = False
        except (OSError, ValueError):
            self.base, self.fresh = {}, True

    def _walk(self):
        found = {}
        for p in self.paths:
            if os.path.isfile(p):
                found[p] = ("file",)
            elif os.path.isdir(p):
                n = 0
                for root, _, files in os.walk(p):
                    for fn in files:
                        found[os.path.join(root, fn)] = ("dir", p)
                        n += 1
                        if n >= self.MAX_FILES:
                            break
        return found

    @staticmethod
    def _sig(path):
        try:
            st = os.stat(path)
            if st.st_size > 25 * 1024 * 1024:
                return "big:%d:%d" % (st.st_size, int(st.st_mtime))
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    def scan(self):
        events, cur = [], {}
        found = self._walk()
        for path, meta in found.items():
            s = self._sig(path)
            if s:
                cur[path] = s

        def ev(sig, sev):
            return {"engine": "fim", "src_ip": None, "signature": sig, "severity": sev,
                    "raw": "file integrity monitor", "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}

        if not self.fresh:
            for path, s in cur.items():
                if path not in self.base:
                    if found[path][0] == "dir" and os.path.splitext(path)[1].lower() in SCRIPT_EXT:
                        events.append(ev("New script file in watched folder: %s" % path, "high"))
                    else:
                        events.append(ev("File integrity change: new file %s" % path, "medium"))
                elif self.base[path] != s:
                    events.append(ev("File integrity change: modified %s" % path, "medium"))
            for path in self.base:
                if path not in cur:
                    events.append(ev("File integrity change: deleted %s" % path, "medium"))
        self.base, self.fresh = cur, False
        try:
            with open(self.file, "w") as f:
                json.dump(cur, f)
        except OSError:
            pass
        return events


# ------------------------------------------------------------------ network

class Manager:
    def __init__(self, cfg):
        self.cfg, self.base = cfg, cfg["manager_url"].rstrip("/")
        self.creds = None
        self.keyfile = os.path.join(HERE, "agent.key.json")
        self.spool = os.path.join(HERE, "spool.jsonl")

    def post(self, path, payload, headers=None):
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, data=json.dumps(payload).encode(), headers=h)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}
        except Exception as e:
            return 0, {"error": str(e)}

    def enroll(self, retries=None):
        if os.path.exists(self.keyfile):
            with open(self.keyfile) as f:
                self.creds = json.load(f)
            return True
        n = 0
        while True:
            code, body = self.post("/api/enroll", {"name": self.cfg["agent_name"], "platform": platform.system(),
                                                   "enrollment_password": self.cfg["enrollment_password"]})
            if code == 200:
                self.creds = body
                with open(self.keyfile, "w") as f:
                    json.dump(body, f)
                try:
                    os.chmod(self.keyfile, 0o600)
                except OSError:
                    pass
                print("[agent] enrolled as %s (%s)" % (self.cfg["agent_name"], body["agent_id"]), flush=True)
                return True
            if code == 403:
                print("[agent] enrollment refused: the enrollment password is wrong.", flush=True)
                return False
            n += 1
            print("[agent] cannot reach the manager at %s (%s). Retrying..." % (self.base, body.get("error", code)), flush=True)
            if retries is not None and n >= retries:
                return False
            time.sleep(min(5 * n, 30))

    def send(self, events, info):
        hdr = {"X-Agent-Id": self.creds["agent_id"], "X-Agent-Key": self.creds["key"]}
        code, body = self.post("/api/ingest", {"events": events, "info": info}, hdr)
        return code

    def _spool_add(self, events):
        try:
            lines = []
            if os.path.exists(self.spool):
                with open(self.spool) as f:
                    lines = f.read().splitlines()
            lines += [json.dumps(e) for e in events]
            with open(self.spool, "w") as f:
                f.write("\n".join(lines[-5000:]) + "\n")
        except OSError:
            pass

    def _spool_take(self):
        try:
            with open(self.spool) as f:
                evs = [json.loads(l) for l in f.read().splitlines() if l.strip()]
            os.remove(self.spool)
            return evs
        except (OSError, ValueError):
            return []

    def deliver(self, events, info):
        """Send queued + new events. On failure keep them in the spool."""
        queued = self._spool_take()
        allev = queued + events
        code = 0
        for i in range(0, max(len(allev), 1), 200):
            chunk = allev[i:i + 200]
            code = self.send(chunk, info)
            if code != 200:
                self._spool_add(allev[i:])
                return code
        return code


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--enroll-only", action="store_true")
    ap.add_argument("--once", action="store_true", help="process what is there, then exit (testing)")
    ap.add_argument("--from-start", action="store_true", help="read existing log content too (testing)")
    a = ap.parse_args(argv)

    cfg = dict(DEFAULTS)
    try:
        with open(a.config) as f:
            cfg.update(json.load(f))
    except (OSError, ValueError) as e:
        print("[agent] cannot read %s: %s" % (a.config, e))
        return 2

    mgr = Manager(cfg)
    if not mgr.enroll(retries=3 if a.enroll_only else None):
        return 1
    if a.enroll_only:
        return 0

    tails = [LogTail(p, from_start=a.from_start) for p in cfg["web_logs"]]
    fim = Fim(cfg["fim_paths"], os.path.join(HERE, "fim_baseline.json")) if cfg["fim_paths"] else None
    print("[agent] %s v%s on %s | watching %d log(s), %d file path(s) | manager %s" % (
        cfg["agent_name"], VERSION, platform.system(), len(tails), len(cfg["fim_paths"]), mgr.base), flush=True)

    last_beat = last_fim = 0.0
    batch = []
    while True:
        for t in tails:
            for line in t.lines():
                batch += analyze(line, t, cfg)
        if fim and time.time() - last_fim >= cfg["fim_interval"]:
            batch += fim.scan()
            last_fim = time.time()
        if batch or time.time() - last_beat > 15 or a.once:
            info = {"hostname": socket.gethostname(), "platform": platform.system(), "version": VERSION,
                    "logs": [{"pattern": t.pattern, "file": t.path, "ok": bool(t.f)} for t in tails],
                    "fim_files": len(fim.base) if fim else 0}
            code = mgr.deliver(batch, info)
            if code == 401:
                print("[agent] the manager does not recognise this agent (revoked?). Will keep retrying.", flush=True)
            elif code != 200 and batch:
                print("[agent] manager unreachable; %d event(s) kept in the spool" % len(batch), flush=True)
            elif batch:
                print("[agent] sent %d event(s)" % len(batch), flush=True)
            batch, last_beat = [], time.time()
        if a.once:
            return 0
        time.sleep(cfg["poll"])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
