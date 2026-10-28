"""
Free threat-intelligence blocklists (no account, no key).
  firehol_level1  - FireHOL's aggregated list of attack sources
  feodo           - abuse.ch Feodo Tracker botnet servers
  custom          - your own list (data/intel/custom.txt), may include lab IPs

Private/lab addresses are never matched against the public lists (FireHOL's
list includes bogon ranges that would wrongly flag every lab machine). Only the
custom list can match private addresses, which is how you demo the feature in
an isolated lab.
"""
import bisect
import ipaddress
import os
import time
import urllib.request
from . import paths, db, config, enrich

SOURCES = {
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
}
MAX_AGE = 24 * 3600
_lists = {}          # name -> (starts, ends)
_loaded_at = 0.0


def _path(name):
    return os.path.join(paths.INTEL_DIR, name + ".txt")


def _parse(text):
    ranges = []
    for line in text.splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if not line:
            continue
        try:
            if "/" in line:
                n = ipaddress.ip_network(line, strict=False)
                if n.version == 4:
                    ranges.append((int(n.network_address), int(n.broadcast_address)))
            else:
                a = ipaddress.ip_address(line)
                if a.version == 4:
                    ranges.append((int(a), int(a)))
        except ValueError:
            continue
    ranges.sort()
    return [r[0] for r in ranges], [r[1] for r in ranges]


def load(force=False):
    global _lists, _loaded_at
    if not force and _lists and time.time() - _loaded_at < 60:
        return
    new = {}
    for name in list(SOURCES) + ["custom"]:
        p = _path(name)
        if os.path.exists(p):
            with open(p, errors="ignore") as f:
                new[name] = _parse(f.read())
    _lists, _loaded_at = new, time.time()


def lookup(ip):
    """Names of every list that contains this IPv4 address."""
    if not config.get("intel_enabled") and not os.path.exists(_path("custom")):
        return []
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if a.version != 4:
        return []
    load()
    n, public, hits = int(a), enrich.is_public(ip), []
    for name, (starts, ends) in _lists.items():
        if name != "custom" and (not public or not config.get("intel_enabled")):
            continue
        i = bisect.bisect_right(starts, n) - 1
        # check a few neighbours in case of overlapping ranges
        for j in range(max(0, i - 3), i + 1):
            if j >= 0 and starts[j] <= n <= ends[j]:
                hits.append(name)
                break
    return hits


def add_custom(ip):
    ipaddress.ip_address(ip)  # validates
    p = _path("custom")
    existing = open(p).read().split() if os.path.exists(p) else []
    if ip not in existing:
        with open(p, "a") as f:
            f.write(ip + "\n")
    load(force=True)


def remove_custom(ip):
    p = _path("custom")
    if not os.path.exists(p):
        return
    keep = [l for l in open(p).read().split() if l != ip]
    with open(p, "w") as f:
        f.write("\n".join(keep) + ("\n" if keep else ""))
    load(force=True)


def update(force=False):
    """Download the free lists. Safe to call often; skips fresh files."""
    result = {}
    for name, url in SOURCES.items():
        p = _path(name)
        if not force and os.path.exists(p) and time.time() - os.path.getmtime(p) < MAX_AGE:
            result[name] = "fresh"
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "idps-lab/2.0"})
            with urllib.request.urlopen(req, timeout=25) as r:
                data = r.read().decode("utf-8", "ignore")
            starts, _ = _parse(data)
            if not starts:
                raise ValueError("list was empty")
            tmp = p + ".tmp"
            with open(tmp, "w") as f:
                f.write(data)
            os.replace(tmp, p)
            result[name] = "updated (%d entries)" % len(starts)
        except Exception as e:
            result[name] = "failed: %s" % e
    db.metric_set("intel.last_update", time.time())
    load(force=True)
    return result


def stats():
    load()
    return {"lists": {k: len(v[0]) for k, v in _lists.items()},
            "last_update": db.metric_ts("intel.last_update")}
