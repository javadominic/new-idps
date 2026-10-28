# IDPS: network and website intrusion detection and prevention

Free and open source tools only (Suricata, Snort, iptables, Python, SQLite). Watches your network and your websites, explains every alert in plain English, and can block attackers automatically, with safeguards so it never locks you out.

**Start here: [SETUP.md](SETUP.md)**: one command installs it, the dashboard walks you through the rest.

## How it works

```
 Suricata (network)    Snort (network)    Host agents (web logs, files)    Decoy ports
        |                     |                       |                        |
        v                     v                       v                        v
   Capture and parse: each source writes alerts; every alert is cleaned and checked
        \                     |                       |                       /
         +--------------------+-----------+-----------+----------------------+
                                          v
        UNDERSTAND   plain-English sentence, MITRE ATT&CK tag, country, threat-list match
                                          v
        DECIDE       one engine for every source: protected list, Shadow or Live mode,
                     already blocked?, same attacker a moment ago?, safety cap per minute
                                          v
        ACT          iptables chain IDPS_BLOCK (INPUT + FORWARD), timed block, doubles for
                     repeat offenders, restored after reboot, removed automatically
                                          v
        NOTIFY       dashboard (live), Telegram, email (cooldown + global cap)
                                          v
              SQLite database (the message bus) -> live dashboard stream
```

Every detection from every source goes through the same decision engine, so Shadow mode, the protected list and the safety limits apply identically to a Snort alert, a SQL injection seen in a web log, or a honeypot touch.

## What is in it

| Feature | Where |
|---|---|
| Dashboard with login, live feed, pipeline view, charts, attack map, per-address timeline | `web/`, `idps/api.py` |
| One-command installer, generated services, one-line agent installers | `deploy/`, `idps/agent_install.py` |
| Suricata and Snort detections (scan, SSH guessing, ping flood, SYN flood), identical on both | `rules/` |
| Host agent for Linux, macOS, Windows: web attacks, brute force, file integrity, web-shell alert, offline spool | `host_agent/agent.py` |
| Honeypot decoy ports (fake SSH, admin page, telnet) | `idps/honeypot.py` |
| Free threat lists (FireHOL, abuse.ch) plus your own | `idps/intel.py` |
| Shadow mode, protected addresses, timed and escalating blocks, panic button | `idps/correlator.py`, `idps/firewall.py` |
| Telegram and email alerts | `idps/notify.py` |
| Safe demo attacks, real lab attack script, expected-vs-detected report, self-test button | `idps/simulate.py`, `simulator/`, `idps/selftest.py` |
| Printable weekly report and CSV export | `idps/report.py` |
| Health page: detects a blind sensor, dropped packets, dead readers | `idps/health.py` |

## Folders

```
run.py            starts everything (the service runs this)
manage.py         set-password, selftest, doctor, unblock-all, whitelist, report ...
idps/             the application      web/        the dashboard
rules/            Suricata + Snort rules   host_agent/   the agent    simulator/   real lab attacks
deploy/           installer, uninstaller   tests/        automated tests    docs/   testing + viva notes
```

## Security notes

Login with a random generated password, brute-force lockout, CSRF header on every change, strict content-security policy, all log text escaped before display (tested with hostile input), agent keys stored hashed, a hostile source address cannot reach a firewall command (every address is validated), blocking refuses loopback, this machine, its gateway, every monitored machine and your protected list. The dashboard speaks plain HTTP: use it on a trusted lab network, or put it behind HTTPS before exposing it.

## Credits and licences

GeoLite2 data (optional download) © MaxMind, CC BY-SA 4.0, mirror by wp-statistics. Fonts IBM Plex (SIL Open Font License). World outline from Natural Earth via `world-atlas` (public domain). Threat lists: FireHOL blocklist-ipsets and abuse.ch Feodo Tracker, used under their published terms. Suricata (GPLv2) and Snort 2 (GPLv2) are installed from your distribution's packages.
