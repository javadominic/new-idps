# Setup guide (copy and paste)

You need one Linux VM for the **manager** (Ubuntu 22.04 or 24.04, 2 GB RAM, 2 CPUs). A second VM to attack from, and a web server VM, are optional.

```
 [Attacker VM] ----+                        +---- [Web server VM, optional]
                   |   host-only network    |      nginx/Apache/IIS + agent
                   +------ 192.168.56.0/24 -+
                            |
                   [Manager VM]  Suricata + Snort + firewall + dashboard
```
VirtualBox: give every VM a **Host-only adapter**, and on the manager set that adapter's *Promiscuous Mode* to **Allow All**.

## 1. Install (one command)

Copy `idps-project.zip` to the manager VM, then:

```bash
sudo apt-get update && sudo apt-get install -y unzip
unzip idps-project.zip && cd idps-project
sudo bash deploy/install.sh
```

It detects the network interface and subnet itself and prints them. If it picks the wrong one:

```bash
sudo bash deploy/install.sh --iface enp0s8 --home-net 192.168.56.0/24
```

At the end it prints **the dashboard address and the login password (shown only once)**. Copy them.
Optional location database for the attack map (26 MB, free): add `--geoip`, or later `sudo bash /opt/idps/deploy/get-geoip.sh`.

## 2. Open the dashboard

Browser on your own computer: `http://<manager-ip>:5000` and sign in.

1. **Setup and health** shows a checklist. Everything should be green. Any red or amber line tells you in plain words what is wrong and gives a command to copy.
2. Press **Run self-test**. Every function (database, decisions, real firewall block and expiry, notifications, live feed, honeypot, agent enrollment, parsers) is tested and shows PASS or FAIL.

## 3. See the whole workflow with no real attacker

**Simulator and tests > Safe demo attacks.** Click *Ping flood*, then open **Overview**: a dot travels along the pipeline (Capture, Understand, Decide, Act, Notify), the alert appears in plain English, and the explanation drawer shows the MITRE ATT&CK technique, what the system did and what you should do.

The system starts in **Shadow mode**: it explains and records what it *would* block, and blocks nothing. This is the safe default.

## 4. Real attacks on your lab (for your report)

Copy `simulator/lab_attacks.py` to the attacker VM (it needs only Python 3). The exact command, with your token filled in, is shown on **Simulator and tests**:

```bash
sudo python3 lab_attacks.py --manager http://192.168.56.10:5000 --token <TOKEN> --target 192.168.56.10
```

It refuses any address that is not private, asks you to type YES, and runs a scan, SSH guessing, ping flood, SYN flood and a decoy touch (about 90 seconds). Then press **Refresh results**: you get the expected-versus-detected table with detection time for Suricata and Snort. For the website attacks add `--web http://<web-server-ip>` (needs an agent there, step 5).

## 5. Watch a website or computer (agent)

**Websites and computers > Add a machine** gives one command per system. Paste it on the machine:

| System | Where to paste |
|---|---|
| Linux, macOS | a terminal (needs Python 3 and sudo) |
| Windows | PowerShell **as Administrator** (needs Python 3: `winget install Python.Python.3.12`) |

The command downloads the agent, finds nginx/Apache/IIS logs by itself, enrolls and starts it as a service. The machine shows up on the page within seconds. Test it from any machine:

```bash
curl "http://<web-server-ip>/?id=1%27%20OR%20%271%27=%271"
```

## 6. Go Live (really block attackers)

1. **Settings > Protected addresses > Add my address** (so you can never lock yourself out).
2. On **Overview**, switch **Shadow to Live** and confirm.
3. Run the flood again. **Blocked** now lists the attacker with a countdown. Repeat offenders are blocked twice as long each time. **Unblock everyone now** is the panic button.

Check on the manager: `sudo iptables -S IDPS_BLOCK`

## 7. Phone alerts (free)

**Telegram:** in Telegram talk to **@BotFather**, send `/newbot`, copy the token. Send your new bot any message, open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy the number after `"chat":{"id":`. Paste both in **Settings > Notifications**, press **Test Telegram**.
**Email:** fill the SMTP fields (Gmail: `smtp.gmail.com`, port 587, an app password), press **Test email**.

## Troubleshooting

| You see | Do this |
|---|---|
| Setup page: "Suricata is installed but not running" | `sudo systemctl status idps-suricata`, then `journalctl -u idps-suricata -n 30`. Most often the wrong interface: reinstall with `--iface`. |
| Dashboard empty during a real attack | The sensor sees only traffic that reaches the manager VM. Attack the manager's own IP, or set VirtualBox promiscuous mode to *Allow All*. |
| Suricata drops packets (health warning) | Give the VM 2+ CPUs. |
| Forgot the password | `sudo /opt/idps/venv/bin/python /opt/idps/manage.py set-password` |
| An agent says "enrollment refused" | Wrong password: copy the command again from the Agents page. |
| Locked yourself out of the VM | From the console: `sudo /opt/idps/venv/bin/python /opt/idps/manage.py unblock-all` |

Useful commands: `manage.py doctor` (checklist), `manage.py selftest`, `manage.py report 7 > report.html`, `manage.py whitelist add 192.168.56.10`.
Uninstall: `sudo bash /opt/idps/deploy/uninstall.sh /opt/idps --purge`.
