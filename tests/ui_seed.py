import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idps import correlator, simulate, db
for s in ("port_scan", "ssh_brute", "icmp_flood", "sqli"): simulate.run_scenario(s)
correlator.handle_event({"engine":"weblog","agent":"<img src=x onerror=window.__xss=1>","src_ip":"10.1.1.1","severity":"high",
  "signature":"Possible SQL injection attempt <img src=x onerror=window.__xss=1>","raw":"<script>window.__xss=1</script> GET /?a=<svg onload=window.__xss=1>"})
print("seeded", db.one("SELECT COUNT(*) n FROM events")["n"])
