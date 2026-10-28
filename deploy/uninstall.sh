#!/usr/bin/env bash
# Removes the IDPS services and firewall chain. Your data is kept unless you add --purge.
set -u
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo bash deploy/uninstall.sh"; exit 1; }
DIR="${1:-/opt/idps}"
for s in idps idps-suricata idps-snort; do systemctl disable --now "$s" >/dev/null 2>&1; rm -f "/etc/systemd/system/$s.service"; done
systemctl daemon-reload 2>/dev/null
for p in INPUT FORWARD; do while iptables -C "$p" -j IDPS_BLOCK 2>/dev/null; do iptables -D "$p" -j IDPS_BLOCK; done; done
iptables -F IDPS_BLOCK 2>/dev/null; iptables -X IDPS_BLOCK 2>/dev/null
[ -f /etc/snort/rules/local.rules.idps-backup ] && mv /etc/snort/rules/local.rules.idps-backup /etc/snort/rules/local.rules
rm -f /etc/snort/snort_idps.conf
if [ "${2:-}" = "--purge" ]; then rm -rf "$DIR"; echo "Removed $DIR"; else echo "Kept $DIR (data and logs). Delete it yourself, or run again with --purge."; fi
echo "IDPS removed."
