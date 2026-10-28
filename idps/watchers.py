"""
Reads the alert logs that Suricata and Snort write and hands every alert to the
correlator. One process per engine:

    python -m idps.watchers suricata
    python -m idps.watchers snort

Options (used by tests and the demo): --file PATH, --from-start, --once.

The parsers were checked against output from real Suricata 7 and Snort 2.9.
Suricata also writes "stats" records; we keep the latest so the health page can
warn when the sensor is dropping packets (an IDS that drops packets is blind).
"""
import argparse
import json
import os
import re
import sys
import time
from . import config, correlator, db

SURICATA_SEV = {1: "high", 2: "medium", 3: "low"}

# Snort fast alert, e.g.
#  10/22-10:00:01.123456  [**] [1:1000011:2] Port scan detected [**] [Classification: ...] [Priority: 3] {TCP} 10.0.0.5:5123 -> 10.0.0.1:22
#  ICMP alerts have no ports: {ICMP} 10.0.0.5 -> 10.0.0.1
SNORT_RE = re.compile(
    r"\[\*\*\]\s*\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*(?P<msg>.*?)\s*\[\*\*\]"
    r"(?:\s*\[Classification:[^\]]*\])?(?:\s*\[Priority:\s*(?P<prio>\d+)\])?"
    r"\s*\{(?P<proto>[A-Za-z0-9]+)\}\s*(?P<src>[0-9.]+?)(?::(?P<sport>\d+))?\s*->\s*(?P<dst>[0-9.]+?)(?::(?P<dport>\d+))?\s*$")


def parse_suricata(line):
    """Returns ('alert', event) | ('stats', dict) | None."""
    try:
        j = json.loads(line)
    except ValueError:
        return None
    t = j.get("event_type")
    if t == "alert":
        a = j.get("alert", {})
        return "alert", {
            "ts": (j.get("timestamp") or db.iso())[:26], "engine": "suricata",
            "src_ip": j.get("src_ip"), "dst_ip": j.get("dest_ip"), "dst_port": j.get("dest_port"),
            "signature": a.get("signature", "unknown"),
            "severity": SURICATA_SEV.get(a.get("severity"), "low"),
            "raw": line.strip()}
    if t == "stats":
        cap = (j.get("stats") or {}).get("capture", {})
        return "stats", {"packets": cap.get("kernel_packets", 0), "drops": cap.get("kernel_drops", 0)}
    return None


def snort_severity(prio, msg):
    if prio in (1, 2, 3):
        return {1: "high", 2: "medium", 3: "low"}[prio]
    m = msg.lower()
    return "high" if "flood" in m else "medium" if "brute" in m else "low"


def parse_snort(line):
    m = SNORT_RE.search(line.strip())
    if not m:
        return None
    prio = int(m.group("prio")) if m.group("prio") else 0
    return "alert", {
        "ts": db.iso(), "engine": "snort", "src_ip": m.group("src"), "dst_ip": m.group("dst"),
        "dst_port": int(m.group("dport")) if m.group("dport") else None,
        "signature": m.group("msg").strip(), "severity": snort_severity(prio, m.group("msg")),
        "raw": line.strip()}


class Tailer:
    """tail -f that survives log rotation and files that do not exist yet."""

    def __init__(self, path, from_start=False):
        self.path, self.from_start = path, from_start
        self.f, self.inode, self.pos = None, None, 0

    def _open(self):
        try:
            st = os.stat(self.path)
        except OSError:
            self.f = None
            return
        self.f = open(self.path, "r", errors="replace")
        self.inode = st.st_ino
        if not self.from_start:
            self.f.seek(0, os.SEEK_END)
        self.from_start = True       # after a rotation, read the new file from its start

    def lines(self):
        if self.f is None:
            self._open()
            if self.f is None:
                return []
        try:
            st = os.stat(self.path)
            if st.st_ino != self.inode or st.st_size < self.f.tell():
                self.f.close()
                self.f = None
                self._open()
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
            if not line.endswith("\n"):     # half-written line: wait for the rest
                self.f.seek(pos)
                break
            out.append(line)
        return out


def run(engine, path=None, from_start=False, once=False):
    parse = parse_suricata if engine == "suricata" else parse_snort
    key = "suricata_eve_log" if engine == "suricata" else "snort_alert_log"
    path = path or config.get(key)
    tail = Tailer(path, from_start=from_start)
    print("[watch-%s] watching %s" % (engine, path), flush=True)
    last_beat, n_lines, n_alerts = 0.0, 0, 0
    while True:
        for line in tail.lines():
            n_lines += 1
            r = parse(line)
            if not r:
                continue
            kind, data = r
            if kind == "alert":
                n_alerts += 1
                try:
                    correlator.handle_event(data)
                except Exception as e:           # never let one bad line stop the sensor feed
                    print("[watch-%s] error handling alert: %s" % (engine, e), flush=True)
            elif kind == "stats":
                db.x("INSERT INTO sensor_stats(engine,ts,data) VALUES(?,?,?) ON CONFLICT(engine) DO UPDATE SET ts=excluded.ts, data=excluded.data",
                     (engine, time.time(), json.dumps(data)))
        if once:
            return n_alerts
        if time.time() - last_beat > 5:
            db.metric_set("watcher.%s.alive" % engine, time.time())
            db.metric_set("watcher.%s.lines" % engine, n_lines)
            db.metric_set("watcher.%s.alerts" % engine, n_alerts)
            last_beat = time.time()
        time.sleep(0.5)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("engine", choices=["suricata", "snort"])
    ap.add_argument("--file")
    ap.add_argument("--from-start", action="store_true")
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args(argv)
    run(a.engine, a.file, a.from_start, a.once)


if __name__ == "__main__":
    main()
