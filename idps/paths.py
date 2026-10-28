"""Filesystem locations. Everything the app writes lives under data/ and logs/."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("IDPS_DATA", os.path.join(ROOT, "data"))
LOG_DIR = os.environ.get("IDPS_LOGS", os.path.join(ROOT, "logs"))
WEB_DIR = os.path.join(ROOT, "web")
RULES_DIR = os.path.join(ROOT, "rules")
AGENT_DIR = os.path.join(ROOT, "host_agent")
INTEL_DIR = os.path.join(DATA_DIR, "intel")
DB_PATH = os.environ.get("IDPS_DB", os.path.join(DATA_DIR, "idps.db"))
GEOIP_PATH = os.path.join(DATA_DIR, "GeoLite2-City.mmdb")

for _d in (DATA_DIR, LOG_DIR, INTEL_DIR):
    os.makedirs(_d, exist_ok=True)
