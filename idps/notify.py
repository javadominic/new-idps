"""
Tells a human. Console always; Telegram and email if configured (both free).
A cooldown stops the same attacker from sending you a message every second.
Sending runs in a background thread so a slow mail server never slows detection.
"""
import json
import smtplib
import threading
import urllib.request
from email.message import EmailMessage
from . import config, db, knowledge


def _text(evt, decision, note):
    sev = knowledge.SEV_WORD.get(evt.get("severity"), "Alert")
    lines = ["[%s] %s" % (sev, knowledge.title(evt.get("kind"))),
             evt.get("explain") or evt.get("signature") or ""]
    lines.append("What we did: " + knowledge.decision_text(decision, note))
    if evt.get("kind"):
        lines.append("What to do: " + knowledge.advice(evt["kind"]))
    if evt.get("src_ip"):
        loc = evt.get("country") or ""
        lines.append("Source: %s %s" % (evt["src_ip"], ("(" + loc + ")") if loc else ""))
    return "\n".join(l for l in lines if l)


def _log(channel, ok, detail, nkey, event_id):
    db.x("INSERT INTO notifications(ts,channel,ok,detail,nkey,event_id) VALUES(?,?,?,?,?,?)",
         (db.now(), channel, 1 if ok else 0, str(detail)[:300], nkey, event_id))


def send_telegram(text):
    token, chat = config.get("telegram_token"), config.get("telegram_chat_id")
    if not token or not chat:
        return None, "not configured"
    url = "%s/bot%s/sendMessage" % (config.get("telegram_api_base").rstrip("/"), token)
    req = urllib.request.Request(url, data=json.dumps({"chat_id": chat, "text": text[:3900]}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = json.loads(r.read().decode() or "{}")
        return bool(body.get("ok", True)), "sent"
    except Exception as e:
        return False, str(e)


def send_email(subject, text):
    host, to = config.get("smtp_host"), config.get("smtp_to")
    if not host or not to:
        return None, "not configured"
    msg = EmailMessage()
    msg["Subject"], msg["To"] = subject, to
    msg["From"] = config.get("smtp_from") or config.get("smtp_user") or "idps@localhost"
    msg.set_content(text)
    port = int(config.get("smtp_port"))
    try:
        if port == 465:
            s = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            s = smtplib.SMTP(host, port, timeout=15)
            if config.get("smtp_tls"):
                s.starttls()
        if config.get("smtp_user"):
            s.login(config.get("smtp_user"), config.get("smtp_pass"))
        s.send_message(msg)
        s.quit()
        return True, "sent"
    except Exception as e:
        return False, str(e)


def _deliver(evt, decision, note, nkey, event_id):
    text = _text(evt, decision, note)
    print("[notify] " + text.replace("\n", " | "), flush=True)
    _log("console", True, "printed", nkey, event_id)
    ok, detail = send_telegram(text)
    if ok is not None:
        _log("telegram", ok, detail, nkey, event_id)
    ok, detail = send_email("IDPS: " + knowledge.title(evt.get("kind")), text)
    if ok is not None:
        _log("email", ok, detail, nkey, event_id)


def send(evt, decision, note="", event_id=None, wait=False):
    """Notify about an event if it is serious enough and not a repeat."""
    if knowledge.rank(evt.get("severity")) < knowledge.rank(config.get("notify_min_severity")):
        return False
    nkey = "%s:%s" % (evt.get("kind"), evt.get("src_ip") or evt.get("agent"))
    cutoff = db.now() - int(config.get("notify_cooldown_seconds"))
    if db.one("SELECT 1 AS x FROM notifications WHERE nkey=? AND ts>? LIMIT 1", (nkey, cutoff)):
        return False
    # global cap so a spoofed flood from many addresses cannot spam your phone
    if db.one("SELECT COUNT(*) AS n FROM notifications WHERE channel='console' AND ts>?", (db.now() - 60,))["n"] >= 10:
        return False
    if wait:
        _deliver(evt, decision, note, nkey, event_id)
    else:
        threading.Thread(target=_deliver, args=(evt, decision, note, nkey, event_id), daemon=True).start()
    return True


def test_channel(channel):
    msg = "IDPS test message. If you can read this, notifications work."
    if channel == "telegram":
        ok, detail = send_telegram(msg)
    elif channel == "email":
        ok, detail = send_email("IDPS test message", msg)
    else:
        return False, "unknown channel"
    if ok is None:
        return False, "Fill in the settings first, then save."
    _log(channel, ok, "test: " + detail, "test", None)
    return ok, detail
