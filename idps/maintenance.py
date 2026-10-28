"""
Housekeeping that must happen on its own, with nobody remembering a cron job:
  * every 5 seconds  remove blocks whose time is up
  * at start         re-apply unexpired blocks (they vanish from the kernel on reboot)
  * every day        refresh the free threat lists and delete old events
"""
import threading
import time
from . import config, db, firewall, intel


def _intel_job():
    try:
        if config.get("intel_enabled"):
            print("[maintenance] threat lists:", intel.update(), flush=True)
    except Exception as e:
        print("[maintenance] threat list update failed:", e, flush=True)


def _purge():
    cutoff = time.time() - int(config.get("retention_days")) * 86400
    db.x("DELETE FROM events WHERE ingested<?", (cutoff,))
    db.x("DELETE FROM actions WHERE ts_epoch<? AND active=0", (cutoff,))
    db.x("DELETE FROM notifications WHERE ts<?", (cutoff,))


def main():
    n = firewall.restore_from_db()
    print("[maintenance] restored %d active block(s) into the firewall" % n, flush=True)
    last_intel, last_purge = 0.0, 0.0
    while True:
        try:
            firewall.sweep_expired()
            if time.time() - last_intel > 6 * 3600:
                last_intel = time.time()
                threading.Thread(target=_intel_job, daemon=True).start()
            if time.time() - last_purge > 86400:
                last_purge = time.time()
                _purge()
            db.metric_set("maintenance.alive", time.time())
        except Exception as e:
            print("[maintenance] error:", e, flush=True)
        time.sleep(5)


if __name__ == "__main__":
    main()
