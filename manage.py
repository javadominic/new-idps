#!/usr/bin/env python3
"""Admin commands.  python3 manage.py <command>

  set-password [new]     change the dashboard password (prompts if omitted)
  selftest               run the self-test and print every result
  doctor                 print the setup checklist
  unblock-all            remove every block now
  whitelist list|add <ip-or-cidr> [note]
  intel-update           download the free threat lists now
  report [days]          write a printable HTML report to stdout
  set <key> <value>      change any setting (e.g. set mode live)
  show-enrollment        print the agent enrollment password
"""
import getpass
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from idps import auth, config, correlator, db, health, intel, report, selftest  # noqa: E402


def main(a):
    if not a:
        print(__doc__)
        return 1
    c = a[0]
    if c == "set-password":
        pw = a[1] if len(a) > 1 else getpass.getpass("New password (8+ characters): ")
        auth.ensure_secrets()
        auth.set_password(pw)
        print("Password changed.")
    elif c == "selftest":
        r = selftest.run()
        for t in r["tests"]:
            print("  [%-4s] %-44s %s" % ({"ok": "PASS", "fail": "FAIL", "warn": "SKIP"}[t["status"]], t["name"], t["detail"]))
        print("\n%d passed, %d failed, %d skipped" % (r["passed"], r["failed"], r["skipped"]))
        return 1 if r["failed"] else 0
    elif c == "doctor":
        items = health.checks()
        for i in items:
            print("  [%-4s] %-28s %s" % (i["status"].upper(), i["title"], i["detail"]))
            if i["fix"] and i["status"] in ("fail", "warn"):
                print("         fix: " + i["fix"])
        return 1 if any(i["status"] == "fail" for i in items) else 0
    elif c == "unblock-all":
        print("Unblocked %d address(es)." % correlator.unblock_all())
    elif c == "whitelist":
        if len(a) > 1 and a[1] == "add":
            import ipaddress
            net = str(ipaddress.ip_network(a[2], strict=False))
            db.x("INSERT OR IGNORE INTO whitelist(cidr,note,added_at,added_by) VALUES(?,?,?,?)", (net, " ".join(a[3:]), time.time(), "cli"))
            print("Protected:", net)
        else:
            for w in db.q("SELECT cidr,note FROM whitelist"):
                print(w["cidr"], "-", w["note"] or "")
    elif c == "intel-update":
        print(json.dumps(intel.update(force=True), indent=2))
    elif c == "report":
        sys.stdout.write(report.render(int(a[1]) if len(a) > 1 else 7))
    elif c == "set":
        v = a[2]
        config.put(a[1], config.coerce(a[1], v) if a[1] in config.DEFAULTS else v)
        print("ok")
    elif c == "show-enrollment":
        print(config.get("enrollment_password"))
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
