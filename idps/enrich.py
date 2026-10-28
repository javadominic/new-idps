"""
Adds location (free GeoLite2 database) to an IP. Returns None when the database
is not installed or the IP is private - a lab uses private addresses, so most
lab traffic has no location, and the dashboard says so instead of guessing.
"""
import ipaddress
import os
from . import config

_reader = None
_reader_path = None


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved)


def _open():
    global _reader, _reader_path
    path = config.get("geoip_db_path")
    if _reader is not None and _reader_path == path:
        return _reader
    if not path or not os.path.exists(path):
        return None
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(path)
        _reader_path = path
    except Exception:
        _reader = None
    return _reader


def available():
    return _open() is not None


def geo(ip):
    if not ip or not is_public(ip):
        return None
    r = _open()
    if r is None:
        return None
    try:
        c = r.city(ip)
        return {"country": c.country.iso_code, "lat": c.location.latitude,
                "lon": c.location.longitude, "city": c.city.name}
    except Exception:
        return None
