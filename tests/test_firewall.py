"""Real firewall behaviour (needs root + iptables): block, no double-block, protection, expiry,
repeat-offender, reboot restore, panic button, per-minute cap, and injection safety."""
import os, sys, tempfile, time
os.environ["IDPS_DATA"] = tempfile.mkdtemp(); os.environ["IDPS_LOGS"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idps import config, correlator, db, firewall
if not firewall.status()["available"]:
    print("SKIP: firewall not available:", firewall.status()["detail"]); sys.exit(0)
ok = []
def check(n, c, d=""): ok.append(bool(c)); print("  [%s] %s %s" % ("PASS" if c else "FAIL", n, d))
def ev(ip, sig="ICMP flood detected", sev="high", **k):
    return correlator.handle_event(dict(engine="suricata", src_ip=ip, signature=sig, severity=sev, raw="t", **k), notify_wait=True)
rules = firewall.list_blocked
config.put("mode", "live"); config.put("block_ttl_minutes", 0.05); config.put("notify_cooldown_seconds", 0)
r = ev("203.0.113.50"); check("Live mode blocks an attacker in the real firewall", r["decision"] == "blocked" and "203.0.113.50" in rules(), r.get("note"))
check("Block is hooked into INPUT and FORWARD (protects machines behind a gateway too)",
      firewall._run(["-C", "INPUT", "-j", "IDPS_BLOCK"])[0] == 0 and firewall._run(["-C", "FORWARD", "-j", "IDPS_BLOCK"])[0] == 0)
r = ev("203.0.113.50", sig="TCP SYN flood detected"); check("Same attacker again is not blocked twice", r["decision"] == "already_blocked" and rules().count("203.0.113.50") == 1)
db.x("INSERT INTO whitelist(cidr,note,added_at) VALUES('10.9.0.0/24','lab',?)", (time.time(),))
for ip in ("127.0.0.1", "10.9.0.99"):
    r = ev(ip); check("Protected address %s is never blocked" % ip, r["decision"] == "skip_protected" and ip not in rules())
time.sleep(3.3); n = firewall.sweep_expired(); check("Block expires on its own", n == 1 and "203.0.113.50" not in rules())
config.put("block_ttl_minutes", 30); ev("203.0.113.60"); t1 = db.one("SELECT ttl_minutes t FROM actions WHERE src_ip='203.0.113.60' AND action='block'")["t"]
correlator.manual_unblock("203.0.113.60"); db.x("UPDATE actions SET ts_epoch=ts_epoch-100 WHERE src_ip='203.0.113.60'")
ev("203.0.113.60", sig="Port scan detected"); t2 = db.q("SELECT ttl_minutes t FROM actions WHERE src_ip='203.0.113.60' AND action='block' ORDER BY id")[-1]["t"]
check("Repeat offender is blocked for twice as long", t2 == t1 * 2, "%g then %g min" % (t1, t2))
firewall.flush(); check("After a reboot the kernel rules are gone", "203.0.113.60" not in rules())
firewall.restore_from_db(); check("...and are restored from the database", "203.0.113.60" in rules())
n = correlator.unblock_all(); check("Panic button removes every block at once", rules() == [] and n >= 1)
db.x("DELETE FROM actions"); config.put("max_blocks_per_minute", 3)
res = [ev("198.51.100.%d" % i)["decision"] for i in range(1, 7)]
check("Safety cap stops runaway automatic blocking", res.count("blocked") == 3 and res.count("rate_limited") == 3, str(res)); correlator.unblock_all()
r = ev("1.2.3.4; iptables -F"); row = db.one("SELECT src_ip FROM events ORDER BY id DESC LIMIT 1")
check("A hostile 'address' cannot inject firewall commands", row["src_ip"] is None and r["decision"] == "alert_only")
check("Public address and protected-address manual block is refused", correlator.manual_block("127.0.0.1", 5)[0] is False)
firewall.flush(); print("%d/%d firewall checks passed" % (sum(ok), len(ok))); sys.exit(0 if all(ok) else 1)
