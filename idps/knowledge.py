"""
Turns a raw detection ("ICMP flood detected") into something a non-technical
person can act on: what happened, why it matters, what to do, and the
MITRE ATT&CK technique it maps to. Pure lookup, no network access.
"""
import re

SEV_RANK = {"low": 1, "medium": 2, "high": 3}
SEV_WORD = {"low": "Heads-up", "medium": "Suspicious", "high": "Urgent"}


def rank(sev):
    return SEV_RANK.get(sev, 1)


# Order matters: the first pattern that matches wins.
KINDS = [
    (r"honeypot", "honeypot"),
    (r"blocklist|threat.?intel|known bad", "intel"),
    (r"new (script|executable)|web ?shell", "webshell"),
    (r"file integrity", "fim"),
    (r"sql ?inj", "sqli"),
    (r"xss|script injection", "xss"),
    (r"path traversal|directory traversal", "traversal"),
    (r"hacking tool|scanner tool", "scanner_ua"),
    (r"sensitive file|probe", "probe"),
    (r"login fail|brute", "brute"),
    (r"flood|\bdos\b", "dos"),
    (r"scan", "scan"),
]

INFO = {
    "scan": dict(
        title="Port scan", mitre="T1046", mitre_name="Network Service Discovery",
        what="{src} tried many network ports on your system within seconds, like rattling every door handle to find one that opens.",
        advice="Often the first step of an attack. If this was not you or a scanner you trust, keep it blocked."),
    "brute": dict(
        title="Password guessing", mitre="T1110", mitre_name="Brute Force",
        what="{src} made many quick login attempts, which looks like a program guessing passwords.",
        advice="Use long passwords or key-only login on SSH and admin pages, and keep this address blocked."),
    "dos": dict(
        title="Traffic flood", mitre="T1498", mitre_name="Network Denial of Service",
        what="{src} is sending a huge number of packets to overwhelm your server.",
        advice="Blocking the address stops this one source. A flood from many sources needs filtering at your provider."),
    "sqli": dict(
        title="SQL injection attempt", mitre="T1190", mitre_name="Exploit Public-Facing Application",
        what="{src} sent a web request built to trick your database into leaking or changing data.",
        advice="Check that the site uses parameterised queries. The block stops this visitor, not the weakness."),
    "xss": dict(
        title="Script injection attempt", mitre="T1190", mitre_name="Exploit Public-Facing Application",
        what="{src} sent a web request carrying hidden script code, aiming to run it in other visitors' browsers.",
        advice="Make sure the site escapes user input before showing it on a page."),
    "traversal": dict(
        title="Folder escape attempt", mitre="T1190", mitre_name="Exploit Public-Facing Application",
        what="{src} tried to climb out of the website's folder to read system files such as passwords.",
        advice="Keep the web server up to date and never build file paths from user input."),
    "probe": dict(
        title="Probe for secret files", mitre="T1595", mitre_name="Active Scanning",
        what="{src} asked your website for files that should never be public, such as .env or .git.",
        advice="Confirm those files are not reachable from the internet."),
    "scanner_ua": dict(
        title="Hacking tool detected", mitre="T1595", mitre_name="Active Scanning",
        what="{src} visited your website using a tool made for finding security holes.",
        advice="Unless you are testing your own site, keep this address blocked."),
    "fim": dict(
        title="Watched file changed", mitre="T1565", mitre_name="Data Manipulation",
        what="A file you asked us to watch has changed on {agent}. {detail}",
        advice="If you did not make this change, restore the file from backup and check who logged in."),
    "webshell": dict(
        title="New script in website folder", mitre="T1505", mitre_name="Server Software Component: Web Shell",
        what="A new script file appeared in a watched website folder on {agent}. {detail}",
        advice="Attackers upload scripts like this to control a site. Inspect it now and remove it if it is not yours."),
    "honeypot": dict(
        title="Decoy service touched", mitre="T1595", mitre_name="Active Scanning",
        what="{src} connected to a decoy service that no real user ever needs. {detail}",
        advice="Almost certainly an attacker or scanner. Keep it blocked."),
    "intel": dict(
        title="Known bad address", mitre="T1595", mitre_name="Active Scanning",
        what="{src} appears on a public list of malicious addresses.",
        advice="Traffic from listed addresses is rarely friendly. Keep it blocked."),
    "generic": dict(
        title="Suspicious activity", mitre="", mitre_name="",
        what="{src} triggered a detection rule.",
        advice="Review the details and block the address if you do not recognise it."),
}


def kind_of(signature):
    s = (signature or "").lower()
    for pat, kind in KINDS:
        if re.search(pat, s):
            return kind
    return "generic"


class _Safe(dict):
    def __missing__(self, key):
        return "?"


def describe(evt):
    """Return kind, title, mitre id/name and a one-sentence explanation."""
    kind = kind_of(evt.get("signature"))
    info = INFO[kind]
    detail = evt.get("detail") or ""
    if kind in ("fim", "webshell"):
        detail = evt.get("signature", "")
    elif kind == "honeypot":
        detail = ""
    text = info["what"].format_map(_Safe(
        src=evt.get("src_ip") or "Someone",
        agent=evt.get("agent") or "a monitored machine",
        detail=detail)).strip()
    return {"kind": kind, "title": info["title"], "mitre": info["mitre"],
            "mitre_name": info["mitre_name"], "explain": text}


def advice(kind):
    return INFO.get(kind, INFO["generic"])["advice"]


def title(kind):
    return INFO.get(kind, INFO["generic"])["title"]


def mitre_name(kind):
    return INFO.get(kind, INFO["generic"])["mitre_name"]


def decision_text(decision, note=""):
    return {
        "alert_only": "Logged. No action needed.",
        "would_block": "Shadow mode: this address would have been blocked.",
        "blocked": ("Blocked %s." % note) if note else "Blocked.",
        "skip_protected": "Not blocked because this address is on your protected list.",
        "already_blocked": "Already blocked.",
        "dedup": "Already handled a moment ago.",
        "rate_limited": "Paused: the safety limit on automatic blocks was reached.",
        "block_failed": "Could not block: %s" % (note or "unknown error"),
    }.get(decision, decision or "")
