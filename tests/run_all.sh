#!/usr/bin/env bash
# Runs every automated test. Run from the project folder as root:  sudo bash tests/run_all.sh
# Needs: python3 requests scapy (pip), suricata, snort, nginx, iptables. UI test also needs node + jsdom.
cd "$(dirname "$0")/.."; export PYTHONPATH=$PWD; FAIL=0
run() { echo; echo "=== $1"; shift; "$@" 2>&1 | grep -v '^\[notify\]' | grep -vE '^started '; [ "${PIPESTATUS[0]}" -eq 0 ] || FAIL=1; }
run "Attack/harmless URL detection"        python3 tests/test_detection.py
run "Notifications (mock Telegram + SMTP)" python3 tests/test_notify.py
run "Firewall behaviour (real iptables)"   python3 tests/test_firewall.py
run "Real Suricata + real Snort on a capture" bash tests/test_real_engines.sh
run "Whole system as separate processes"   python3 tests/test_integration.py
run "Agent + real nginx + real installer"  python3 tests/test_agent_nginx.py
echo; [ $FAIL -eq 0 ] && echo "ALL TEST GROUPS PASSED" || echo "SOME TESTS FAILED"; exit $FAIL
