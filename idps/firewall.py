"""
The only module that touches the firewall.

Design:
  * All blocks live in their own chain, IDPS_BLOCK, jumped to from INPUT and
    FORWARD. INPUT protects this machine; FORWARD protects machines behind it
    when it runs as a gateway. "Unblock everyone" is a single chain flush and
    never disturbs your other firewall rules.
  * Blocks are stored in the database too, so they are re-applied after a
    reboot (iptables rules are lost on reboot) and expire on schedule.
  * Every call is safe to repeat: blocking an already-blocked IP does nothing.
"""
import ipaddress
import os
import shutil
import subprocess
import time
from . import db

CHAIN = "IDPS_BLOCK"


def _bin(v6=False):
    env = os.environ.get("IDPS_IP6TABLES" if v6 else "IDPS_IPTABLES")
    return env or shutil.which("ip6tables" if v6 else "iptables")


def _run(args, v6=False):
    b = _bin(v6)
    if not b:
        return 127, "iptables is not installed"
    cmd = [b, "-w", "5"] + list(args)
    if os.geteuid() != 0:
        if shutil.which("sudo"):
            cmd = ["sudo", "-n"] + cmd
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except Exception as e:
        return 1, str(e)
    return r.returncode, (r.stdout + r.stderr).strip()


def _ver(ip):
    try:
        return ipaddress.ip_address(ip).version == 6
    except ValueError:
        return None


def status():
    """What the dashboard health page shows."""
    if not _bin():
        return {"available": False, "detail": "iptables is not installed", "blocked": 0}
    rc, out = _run(["-S"])
    if rc != 0:
        return {"available": False, "detail": "no permission to change the firewall (run as root): %s" % out[:120],
                "blocked": 0}
    return {"available": True, "detail": "ok", "blocked": len(list_blocked())}


def ensure_chain(v6=False):
    rc, out = _run(["-N", CHAIN], v6)
    if rc != 0 and "exist" not in out.lower():
        return False, out
    for parent in ("INPUT", "FORWARD"):
        if _run(["-C", parent, "-j", CHAIN], v6)[0] != 0:
            rc, out = _run(["-I", parent, "1", "-j", CHAIN], v6)
            if rc != 0:
                return False, out
    return True, "ok"


def block(ip):
    v6 = _ver(ip)
    if v6 is None:
        return False, "not a valid IP address"
    ok, msg = ensure_chain(v6)
    if not ok:
        return False, msg
    if _run(["-C", CHAIN, "-s", ip, "-j", "DROP"], v6)[0] == 0:
        return True, "already in firewall"
    rc, out = _run(["-A", CHAIN, "-s", ip, "-j", "DROP"], v6)
    return (rc == 0), ("ok" if rc == 0 else out)


def unblock(ip):
    v6 = _ver(ip)
    if v6 is None:
        return False, "not a valid IP address"
    removed = 0
    while _run(["-C", CHAIN, "-s", ip, "-j", "DROP"], v6)[0] == 0 and removed < 20:
        if _run(["-D", CHAIN, "-s", ip, "-j", "DROP"], v6)[0] != 0:
            break
        removed += 1
    return True, "removed" if removed else "was not in firewall"


def list_blocked():
    rc, out = _run(["-S", CHAIN])
    ips = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "-A" and "-s" in parts and "DROP" in parts:
                ips.append(parts[parts.index("-s") + 1].split("/")[0])
    return ips


def flush():
    """Remove every IDPS block at once (the panic button)."""
    _run(["-F", CHAIN])
    if _bin(True):
        _run(["-F", CHAIN], True)
    return True


def restore_from_db():
    """Re-apply unexpired blocks after a reboot or restart."""
    n = 0
    for a in db.q("SELECT src_ip FROM actions WHERE action='block' AND active=1 AND expires_epoch>?", (time.time(),)):
        ok, _ = block(a["src_ip"])
        n += 1 if ok else 0
    return n


def sweep_expired():
    """Remove blocks whose time is up. Called every few seconds by maintenance."""
    expired = db.q("SELECT id, src_ip FROM actions WHERE action='block' AND active=1 AND expires_epoch<=?",
                   (time.time(),))
    for a in expired:
        unblock(a["src_ip"])
        db.x("UPDATE actions SET active=0 WHERE id=?", (a["id"],))
        db.x("INSERT INTO actions(ts_epoch,src_ip,action,reason,active,by) VALUES(?,?,?,?,0,?)",
             (time.time(), a["src_ip"], "unblock", "block time ended", "ttl"))
    return len(expired)
