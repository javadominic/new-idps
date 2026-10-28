# Viva notes

**IDS vs IPS?** IDS watches a copy and alerts. IPS sits in the path or controls the firewall and blocks. This project is both: Shadow mode is IDS behaviour, Live mode adds prevention.

**Why Shadow mode first?** A wrong rule that blocks real users is an outage. Shadow logs "would have blocked", so you measure false positives before enabling blocking. The report's false-positive section can use this data.

**Walk through a flood.** Packets reach the interface, Suricata and Snort count 50 pings in 5 seconds and write one alert. The reader parses it, the decision engine checks it is not a protected address, not already blocked, within the per-minute cap, then (Live mode) adds an iptables DROP in the `IDPS_BLOCK` chain, records it with an expiry, notifies you, and the dashboard shows it. After the time is up the maintenance job removes the rule.

**Why a whitelist?** Automated blocking can block you. Protected addresses are never blocked; the machine itself, its gateway and every monitored machine are protected automatically; there is a per-minute cap and a panic button.

**Snort vs Suricata, from your results?** Use the report on Simulator and tests: same four attacks, same rules, detection time per engine. Suricata is multi-threaded and writes structured JSON (stats such as dropped packets); Snort 2 is single-threaded and writes plain text, and buffers output. Both detected 9 of 9 here.

**What did the bug fixes teach?** (1) A rule that counts packets instead of connections flags a normal SSH login: count SYNs. (2) A rule firing per packet floods the log: alert once per window. (3) ICMP alerts have no ports, so a parser that expects ports silently drops the most serious alert. (4) Silent failure is the worst failure of an IDS, hence the health page that notices a sensor that stopped reading.

**How does the agent enroll?** Shared enrollment password once, unique key afterwards, stored hashed on the manager; removing the agent revokes the key. Same model as Wazuh.

**Why MITRE ATT&CK?** It gives each alert a standard name: scan T1046, brute force T1110, network DoS T1498, exploit public-facing application T1190.

**Limits to admit.** No encrypted-traffic inspection (only metadata), IPv4 only, lab-scale performance, plain HTTP dashboard, signature-based (no machine learning). Say why: the research shows ML detectors trained on benchmark datasets often fail in production.

**Why only your own lab?** Scanning, flooding or attacking machines you do not own is illegal. `lab_attacks.py` refuses public addresses and asks for confirmation.
