"""Builds a capture with 4 attacks and 2 harmless sessions for testing real Snort/Suricata."""
import sys
from scapy.all import Ether, IP, TCP, ICMP, wrpcap

HOME = "10.9.0.10"
def eth(p): return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / p
pk, t = [], 1_800_000_000.0

def add(p, ts):
    p = eth(p); p.time = ts; pk.append(p)

# 1. port scan from .5: 60 different ports in 1 second
for i in range(60):
    add(IP(src="10.9.0.5", dst=HOME) / TCP(sport=40000 + i, dport=1000 + i, flags="S"), t + i * 0.016)
t += 20
# 2. SSH password guessing from .6: 8 new connections to port 22 over 8 seconds
for i in range(8):
    add(IP(src="10.9.0.6", dst=HOME) / TCP(sport=50000 + i, dport=22, flags="S"), t + i)
t += 30
# 3. ICMP flood from .7: 120 pings in 3 seconds
for i in range(120):
    add(IP(src="10.9.0.7", dst=HOME) / ICMP(type=8, id=1, seq=i), t + i * 0.025)
t += 20
# 4. SYN flood from .8: 400 SYNs to port 80 in 2 seconds
for i in range(400):
    add(IP(src="10.9.0.8", dst=HOME) / TCP(sport=10000 + i, dport=80, flags="S"), t + i * 0.005)
t += 20
# 5. HARMLESS: one normal long SSH session from .20 (1 SYN, then 80 data packets over 60s)
add(IP(src="10.9.0.20", dst=HOME) / TCP(sport=60000, dport=22, flags="S", seq=1), t)
add(IP(src=HOME, dst="10.9.0.20") / TCP(sport=22, dport=60000, flags="SA", seq=100, ack=2), t + .01)
add(IP(src="10.9.0.20", dst=HOME) / TCP(sport=60000, dport=22, flags="A", seq=2, ack=101), t + .02)
for i in range(80):
    add(IP(src="10.9.0.20", dst=HOME) / TCP(sport=60000, dport=22, flags="PA", seq=2 + i * 10, ack=101) / ("x" * 10), t + 1 + i * 0.7)
# 6. HARMLESS: a few web requests from .30 (5 SYNs in 10 seconds)
t += 70
for i in range(5):
    add(IP(src="10.9.0.30", dst=HOME) / TCP(sport=61000 + i, dport=80, flags="S"), t + i * 2)

wrpcap(sys.argv[1], pk)
print("wrote", len(pk), "packets")
