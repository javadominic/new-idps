"""
Decoy services. Nothing real lives on these ports, so ANY connection is an
attacker or scanner: a detection with almost no false positives.

    2222 -> pretends to be SSH      8081 -> pretends to be an admin web page
    2323 -> pretends to be telnet   (ports are editable in Settings)

It never executes anything and never replies with real data.
"""
import socket
import threading
import time
from . import config, correlator, db

BANNERS = {
    "ssh": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    "telnet": b"\xff\xfd\x18login: ",
    "http": (b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
             b"<html><title>Admin login</title><body><form>Username <input> Password <input type=password></form></body></html>"),
    "generic": b"",
}


def service_for(port):
    return {2222: "ssh", 22: "ssh", 2323: "telnet", 23: "telnet", 8081: "http", 8080: "http", 80: "http"}.get(port, "generic")


def _handle(sock, addr, port):
    svc = service_for(port)
    try:
        sock.settimeout(3)
        if svc in ("ssh", "telnet"):
            sock.sendall(BANNERS[svc])
        try:
            data = sock.recv(256)
        except socket.timeout:
            data = b""
        if svc == "http":
            sock.sendall(BANNERS["http"])
    except OSError:
        data = b""
    finally:
        try:
            sock.close()
        except OSError:
            pass
    first = data[:80].decode("latin-1", "replace").replace("\r", " ").replace("\n", " ").strip()
    correlator.handle_event({
        "engine": "honeypot", "src_ip": addr[0], "dst_port": port, "severity": "high",
        "signature": "Honeypot hit on port %d (%s)" % (port, svc),
        "raw": ("sent: " + first) if first else "connected and sent nothing"})


def _serve(port, stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except OSError as e:
        print("[honeypot] cannot listen on %d: %s" % (port, e), flush=True)
        return False
    s.listen(32)
    s.settimeout(1)
    print("[honeypot] listening on %d (%s)" % (port, service_for(port)), flush=True)
    while not stop.is_set():
        try:
            c, a = s.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_handle, args=(c, a, port), daemon=True).start()
    s.close()
    return True


def main():
    stop = threading.Event()
    started = set()
    while True:
        if config.get("honeypot_enabled"):
            for p in config.get("honeypot_ports"):
                if p not in started:
                    started.add(p)
                    threading.Thread(target=_serve, args=(p, stop), daemon=True).start()
        db.metric_set("honeypot.alive", time.time())
        db.metric_set("honeypot.ports", len(started))
        time.sleep(5)


if __name__ == "__main__":
    main()
