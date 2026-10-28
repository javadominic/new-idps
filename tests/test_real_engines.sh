#!/usr/bin/env bash
# Replays a capture (4 attacks + 2 harmless sessions) through REAL Suricata and REAL Snort,
# then reads their real output with the project's own parsers.
# Needs: suricata, snort, the project's Snort config (installer creates /etc/snort/snort_idps.conf).
set -u; cd "$(dirname "$0")/.."
T=$(mktemp -d); export IDPS_DATA=$T/data IDPS_LOGS=$T/logs
[ -f /etc/snort/snort_idps.conf ] || { cp rules/snort_local.rules /etc/snort/rules/local.rules; sed -E 's|^(include \$RULE_PATH/.*\.rules)|#\1|; s|^#+\s*(include \$RULE_PATH/local\.rules)|\1|' /etc/snort/snort.conf > /etc/snort/snort_idps.conf; }
mkdir -p $T/sur $T/snl
suricata -c /etc/suricata/suricata.yaml -S rules/suricata_custom.rules --set vars.address-groups.HOME_NET="[10.9.0.0/24]" --set stream.checksum-validation=no -r tests/samples/attacks.pcap -l $T/sur -k none >/dev/null 2>&1
snort -c /etc/snort/snort_idps.conf -S HOME_NET=10.9.0.0/24 -r tests/samples/attacks.pcap -A fast -l $T/snl -k none -q >/dev/null 2>&1
python3 -m idps.watchers suricata --file $T/sur/eve.json --from-start --once >/dev/null
python3 -m idps.watchers snort --file $T/snl/alert --from-start --once >/dev/null
python3 - << 'PY'
from idps import db
got = {(r["engine"], r["src_ip"], r["signature"]) for r in db.q("SELECT engine,src_ip,signature FROM events")}
want = {(e, ip, s) for e in ("suricata", "snort") for ip, s in [("10.9.0.5", "Port scan detected"), ("10.9.0.6", "SSH Brute Force attempt"),
        ("10.9.0.7", "ICMP flood detected"), ("10.9.0.8", "Port scan detected"), ("10.9.0.8", "TCP SYN flood detected")]}
for g in sorted(want - got): print("  MISSING:", g)
for g in sorted(got - want): print("  UNEXPECTED (false alarm):", g)
ok = got == want
print("  [%s] real Suricata and real Snort each raised exactly the 5 expected alerts, none on the 2 harmless sessions" % ("PASS" if ok else "FAIL"))
raise SystemExit(0 if ok else 1)
PY
RC=$?; rm -rf $T; exit $RC
