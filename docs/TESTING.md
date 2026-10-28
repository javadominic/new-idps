# What was tested, and what was not

All automated tests are in `tests/` and run with `sudo bash tests/run_all.sh`. They ran on Ubuntu 24.04 with **real Suricata 7.0.3, real Snort 2.9.20, real nginx 1.24 and a real kernel firewall**.

## Verified against the real thing

| Area | How |
|---|---|
| Suricata and Snort rules | A capture with 4 attacks and 2 harmless sessions (a normal long SSH login, a few web requests) is replayed through both engines: each raises exactly the 5 expected alerts, none on the harmless sessions. |
| Live capture | Both engines sniffed live traffic while `lab_attacks.py` ran real attacks: **9 of 9** expected detections, 0.5 to 2.4 seconds after the attack started. |
| Log parsing | The parsers read real Suricata JSON and real Snort lines, including ICMP lines that have no port numbers. |
| Firewall | 13 checks against real iptables: block, no double block, protected addresses refused, expiry, doubling for repeat offenders, restore after a reboot, panic button, per-minute cap, command-injection attempt. |
| Whole system | Real supervisor, API, watchers, honeypot and cleanup as separate processes: login, CSRF, alerts from other processes appear on the live stream, live-mode block reaches the kernel firewall, self-test, report, CSV (26 checks). |
| Dashboard | The real page loaded in a DOM engine (jsdom) against the live API, every page clicked, no script errors, hostile text in log lines stays inert (24 checks). |
| Host agent | Real nginx, the real generated installer script, real attacks and harmless requests: all attack types caught, no false alarms, file changes and new script files caught, spooling while the manager is down, key revocation, forged events refused, IIS (Windows) log format. |
| Detection quality | 27 attack strings and 6 probes caught, 25 harmless URLs (apostrophes, the word "union", "--" in dates ...) ignored. |
| Installer | Run for real (packages already installed): both sensor config tests pass, services files generated, installed copy passes its own self-test. |
| Notifications | Telegram and email requests checked against local mock servers. |

## Not verified here: please test on your VM

- **systemd services**: the unit files are generated and syntax-checked by the installer, but the sandbox had no systemd, so starting them was not exercised.
- **Suricata on a real network card** (`--af-packet=<iface>`): the sandbox only offered loopback via libpcap. This is the standard Suricata mode, but check the health page after installing.
- **PowerShell installer and Windows scheduled task, macOS launchd daemon**: written carefully but never executed (no Windows or macOS here). The agent itself is plain Python and its IIS parsing was tested.
- **Real Telegram and SMTP servers**: only mocks were available.
- **Location database and attack map**: the download URL was confirmed reachable, and the map code runs, but lab traffic uses private addresses, which have no location. Pins appear for public addresses only.
- **Threat-list matching in a lab**: lab addresses are private and are deliberately never matched against the public lists. Use *Settings > Threat lists > add an address* to demonstrate it.
- **Scale**: tested with small lab traffic, not a busy network.

## Known limits

IPv4 only for Snort parsing. The dashboard server is Flask's built-in server (fine for a lab). Suricata alerts only for traffic that reaches the monitored interface. A flood from many different spoofed sources is limited by the safety cap rather than blocked one by one.

## Running the dashboard (UI) test

```bash
cd /tmp && npm install jsdom && cd -                      # once
export IDPS_DATA=/tmp/ui IDPS_LOGS=/tmp/uil IDPS_PORT=5079 IDPS_BIND=127.0.0.1
python3 manage.py set-password 'ui-test-pass1' && python3 tests/ui_seed.py
python3 -m idps.api & python3 -m idps.honeypot & python3 -m idps.maintenance & sleep 3
BASE=http://127.0.0.1:5079 PASS=ui-test-pass1 NODE_PATH=/tmp/node_modules JSDOM_PATH=/tmp/node_modules/jsdom node tests/ui_smoke.js
```
