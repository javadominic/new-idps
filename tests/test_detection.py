"""Fast check of the agent's web-attack detection: many real attack strings, many harmless URLs."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "host_agent"))
import agent

CFG = {"brute_count": 5, "brute_window": 30}
ATTACKS = [
    "/?id=1' OR '1'='1", "/?id=1%27%20OR%20%271%27=%271", "/?id=1 OR 1=1", "/?id=1+or+1%3D1", "/?u=admin'--", "/?u=admin%27--%20",
    "/?id=1 UNION SELECT NULL,NULL", "/?id=1+UNION+ALL+SELECT+user,pass+FROM+users", "/?id=1/**/UNION/**/SELECT/**/1", "/?q=1;DROP TABLE users",
    "/?id=1 AND SLEEP(5)", "/?id=1;WAITFOR DELAY '0:0:5'", "/?id=(SELECT 1 FROM information_schema.tables)", "/?f=load_file('/etc/passwd')",
    "/?id=1%2527%2520OR%25201=1", "/?id=1' AND 1=1 --",
    "/?q=<script>alert(1)</script>", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "/?q=<img src=x onerror=alert(1)>", "/?q=javascript:alert(1)",
    "/?q=<svg onload=alert(1)>", "/?q=%253Cscript%253E",
    "/../../../etc/passwd", "/..%2f..%2f..%2fetc%2fpasswd", "/%2e%2e/%2e%2e/etc/passwd", "/?file=../../../../etc/shadow", "/?f=..\\..\\windows\\win.ini",
]
PROBES = ["/.env", "/.git/config", "/phpmyadmin/index.php", "/server-status", "/.aws/credentials", "/wp-config.php.bak"]
BENIGN = ["/", "/index.html", "/search?q=it's+fine", "/search?q=O'Brien", "/blog/2024-01-01--summary", "/union-station", "/?q=select+a+color",
          "/products?id=5&sort=asc", "/about-us", "/css/site.css?v=3", "/?name=Bob+O'Brien", "/?q=how+to+order+online", "/contact?subject=sales+and+support",
          "/api/users/42", "/?page=2&per_page=50", "/images/photo.jpg", "/docs/drop-in-replacement", "/?q=rock+and+roll", "/news/2026/10/22/election-results",
          "/?redirect=/dashboard", "/?q=1+1", "/files/readme.txt", "/?lang=en-US", "/search?q=select+union", "/?q=a--b"]
bad = 0
def kinds(path, method="GET", status="200", ua=""):
    agent._recent.clear(); agent._brute.clear()
    return [e["signature"] for e in agent.classify("203.0.113.9", method, path, status, ua, path, CFG)]
for p in ATTACKS:
    if not kinds(p): print("MISSED attack:", p); bad += 1
for p in PROBES:
    if not kinds(p): print("MISSED probe:", p); bad += 1
for p in BENIGN:
    k = kinds(p)
    if k: print("FALSE ALARM:", p, k); bad += 1
for ua in ("sqlmap/1.7", "Nikto/2.1.6", "Mozilla/5.00 (Nikto)", "masscan/1.3"):
    if not kinds("/", ua=ua): print("MISSED tool UA:", ua); bad += 1
for ua in ("Mozilla/5.0 (Windows NT 10.0) Chrome/120", "curl/8.4.0", "Googlebot/2.1"):
    if kinds("/", ua=ua): print("FALSE ALARM UA:", ua); bad += 1
print("%d attacks + %d probes caught, %d harmless URLs ignored, %d problems" % (len(ATTACKS), len(PROBES), len(BENIGN), bad))
sys.exit(1 if bad else 0)
