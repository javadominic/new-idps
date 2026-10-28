# Agent deployment (Linux, macOS, Windows)

Easiest: dashboard > **Websites and computers > Add a machine**, paste the one command shown for the system. It already contains the manager address and enrollment password. This page explains what that command does and how to do it by hand.

## How enrollment works (same idea as Wazuh)

1. The manager holds a shared **enrollment password** (Settings shows how to change it; changing it does not disconnect agents already joined).
2. The agent presents it once and receives its **own unique key**. The manager keeps only a hash of that key.
3. Every message after that carries the key. Remove an agent on the dashboard and its key stops working immediately.
4. If the manager is unreachable, events wait in a local spool file and are delivered later.

## What the one-line installer does

| System | Steps |
|---|---|
| Linux | downloads `agent.py` to `/opt/idps-agent`, detects nginx/Apache logs and web folders, writes a private `config.json`, enrolls, installs a **systemd** service `idps-agent` |
| macOS | same, installs a **launchd** daemon `com.idps.agent` |
| Windows | `C:\ProgramData\IDPSAgent`, detects IIS/nginx/Apache/XAMPP logs, enrolls, creates a **scheduled task** "IDPS Agent" running as SYSTEM at startup |

The agent uses only the Python standard library: nothing to `pip install`.

## By hand (any system with Python 3)

```bash
mkdir idps-agent && cd idps-agent
# copy host_agent/agent.py here, then create config.json:
cat > config.json <<'JSON'
{"manager_url": "http://192.168.56.10:5000",
 "enrollment_password": "<from dashboard Settings or: manage.py show-enrollment>",
 "agent_name": "web-server-01",
 "web_logs": ["/var/log/nginx/access.log"],
 "fim_paths": ["/var/www/html", "/etc/nginx/nginx.conf"]}
JSON
python3 agent.py --config config.json --enroll-only   # prints: enrolled as web-server-01
python3 agent.py --config config.json                 # runs
```

IIS example: `"web_logs": ["C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log"]` (the newest file is followed automatically).

## What it detects

SQL injection (including URL-encoded and double-encoded), script injection (XSS), folder escape (`../`), probes for `.env` / `.git` / `phpmyadmin`, hacking-tool user-agents (sqlmap, nikto...), repeated login failures, changed or deleted watched files, and **new script files** (`.php .jsp .aspx ...`) appearing in a watched web folder (possible web shell, rated urgent).

## Service commands

```bash
sudo systemctl status idps-agent      # Linux
journalctl -u idps-agent -f
sudo launchctl list | grep idps       # macOS
schtasks /Query /TN "IDPS Agent"      # Windows
```
