"""Password hashing and first-run secrets. Nothing here is a default password."""
import hashlib
import hmac
import os
import secrets
from . import config


def hash_password(pw, iterations=200_000):
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return "pbkdf2$%d$%s$%s" % (iterations, salt.hex(), h.hex())


def verify(pw, stored):
    try:
        _, it, salt, h = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(calc.hex(), h)
    except Exception:
        return False


def set_password(pw):
    if len(pw) < 8:
        raise ValueError("Password must be at least 8 characters.")
    config.put("admin_pw_hash", hash_password(pw))


def check_password(pw):
    stored = config.get("admin_pw_hash")
    return bool(stored) and verify(pw, stored)


def ensure_secrets():
    """Create anything missing. Returns what was newly created (so run.py can show it once)."""
    created = {}
    if not config.get("secret_key"):
        config.put("secret_key", secrets.token_hex(32))
    if not config.get("enrollment_password"):
        v = secrets.token_urlsafe(9)
        config.put("enrollment_password", v)
        created["enrollment_password"] = v
    if not config.get("sim_token"):
        config.put("sim_token", secrets.token_urlsafe(12))
    if not config.get("admin_pw_hash"):
        pw = secrets.token_urlsafe(9)
        set_password(pw)
        created["admin_password"] = pw
    return created


def same(a, b):
    return bool(a) and bool(b) and hmac.compare_digest(str(a), str(b))
