"""Telegram and email delivery against local mock servers (no internet, no real accounts)."""
import json, os, socket, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
os.environ["IDPS_DATA"] = tempfile.mkdtemp(); os.environ["IDPS_LOGS"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idps import config, correlator, db, notify
got = {"tg": [], "mail": []}

class TG(BaseHTTPRequestHandler):
    def do_POST(self):
        got["tg"].append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b'{"ok":true}')
    def log_message(self, *a): pass
tg = HTTPServer(("127.0.0.1", 0), TG); threading.Thread(target=tg.serve_forever, daemon=True).start()

def smtp():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1); smtp.port = s.getsockname()[1]
    def serve():
        c, _ = s.accept(); f = c.makefile("rwb"); c.sendall(b"220 mock\r\n"); data = False; body = []
        while True:
            line = f.readline()
            if not line: break
            t = line.decode().strip()
            if data:
                if t == ".": data = False; c.sendall(b"250 queued\r\n"); continue
                body.append(t); continue
            u = t.upper()
            if u.startswith("EHLO") or u.startswith("HELO"): c.sendall(b"250 mock\r\n")
            elif u.startswith("DATA"): data = True; c.sendall(b"354 go\r\n")
            elif u.startswith("QUIT"): c.sendall(b"221 bye\r\n"); break
            else: c.sendall(b"250 ok\r\n")
        got["mail"].append("\n".join(body))
    threading.Thread(target=serve, daemon=True).start()
smtp()
config.put("telegram_token", "123:ABC"); config.put("telegram_chat_id", "42"); config.put("telegram_api_base", "http://127.0.0.1:%d" % tg.server_port)
config.put("smtp_host", "127.0.0.1"); config.put("smtp_port", smtp.port); config.put("smtp_tls", False); config.put("smtp_to", "me@example.com"); config.put("smtp_from", "idps@example.com")
ok = []
def check(n, c): ok.append(bool(c)); print("  [%s] %s" % ("PASS" if c else "FAIL", n))
r = correlator.handle_event({"engine": "suricata", "src_ip": "203.0.113.5", "severity": "high", "signature": "ICMP flood detected", "raw": "x"}, mode_override="shadow", notify_wait=True)
time.sleep(0.5)
check("Telegram request goes to /bot<token>/sendMessage", got["tg"] and got["tg"][0][0] == "/bot123:ABC/sendMessage")
check("Telegram message has the chat id and plain-English text", got["tg"] and got["tg"][0][1]["chat_id"] == "42" and "flood" in got["tg"][0][1]["text"].lower() and "What to do" in got["tg"][0][1]["text"])
check("Email is delivered with subject and body", got["mail"] and "Subject: IDPS: Traffic flood" in got["mail"][0] and "203.0.113.5" in got["mail"][0])
n = db.one("SELECT COUNT(*) n FROM notifications WHERE ok=1 AND channel IN ('telegram','email')")["n"]
check("Both deliveries are logged as successful", n == 2)
n0 = len(got["tg"]); correlator.handle_event({"engine": "suricata", "src_ip": "203.0.113.5", "severity": "high", "signature": "TCP SYN flood detected", "raw": "y"}, mode_override="shadow", notify_wait=True)
check("A second alert from the same attacker inside the quiet time sends nothing", len(got["tg"]) == n0)
config.put("telegram_api_base", "http://127.0.0.1:9"); ok2, d = notify.send_telegram("x")
check("A dead Telegram server is reported as a failure, not a crash", ok2 is False)
print("%d/%d notification checks passed" % (sum(ok), len(ok))); sys.exit(0 if all(ok) else 1)
