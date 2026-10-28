#!/usr/bin/env bash
# One-command installer for the IDPS manager (Ubuntu / Debian).
#
#   sudo bash deploy/install.sh
#
# Options (all optional - it detects sensible values itself):
#   --iface eth0            network interface the sensors watch
#   --home-net 10.0.0.0/24  the network you are protecting
#   --dir /opt/idps         where to install
#   --port 5000             dashboard port
#   --geoip                 also download the free location database (about 26 MB)
#   --no-sensors            do not install Suricata/Snort (dashboard, agents, honeypot only)
#   --skip-apt              do not install packages (already installed)
#   --no-systemd            do not create services (write the unit files and stop)
set -euo pipefail

IFACE="" HOME_NET="" DIR="/opt/idps" PORT="5000" GEOIP=0 SENSORS=1 APT=1 SYSTEMD=1
while [ $# -gt 0 ]; do
  case "$1" in
    --iface) IFACE="$2"; shift 2;; --home-net) HOME_NET="$2"; shift 2;; --dir) DIR="$2"; shift 2;;
    --port) PORT="$2"; shift 2;; --geoip) GEOIP=1; shift;; --no-sensors) SENSORS=0; shift;;
    --skip-apt) APT=0; shift;; --no-systemd) SYSTEMD=0; shift;;
    -h|--help) sed -n '2,16p' "$0"; exit 0;; *) echo "Unknown option: $1"; exit 1;;
  esac
done

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33m!! %s\033[0m\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "Please run as root:  sudo bash deploy/install.sh"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"

# ---------------------------------------------------------------- detect network
if [ -z "$IFACE" ]; then
  IFACE="$(ip -o -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
fi
[ -n "$IFACE" ] || { echo "Could not detect a network interface. Re-run with  --iface <name>  (see: ip address)"; exit 1; }
if [ -z "$HOME_NET" ]; then
  CIDR="$(ip -o -4 addr show dev "$IFACE" 2>/dev/null | awk '{print $4; exit}')"
  HOME_NET="$(python3 -c "import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)" "${CIDR:-192.168.56.1/24}")"
fi
MYIP="$(ip -o -4 addr show dev "$IFACE" 2>/dev/null | awk '{print $4; exit}' | cut -d/ -f1)"
say "Using interface '$IFACE' and protecting network $HOME_NET  (change with --iface / --home-net)"

# ---------------------------------------------------------------- packages
if [ "$APT" -eq 1 ]; then
  command -v apt-get >/dev/null || { echo "This installer needs apt (Ubuntu/Debian). Use --skip-apt and install the packages yourself."; exit 1; }
  say "Installing packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  PKGS="python3 python3-venv python3-pip iptables ethtool curl iproute2 procps"
  if [ "$SENSORS" -eq 1 ]; then
    {
      echo "snort snort/interface string $IFACE"
      echo "snort snort/address_range string $HOME_NET"
      echo "snort snort/startup string manual"
      echo "snort snort/reload_in_vm string false"
      echo "snort snort/options string -Z"
      echo "snort snort/disable_promiscuous boolean false"
      echo "snort snort/send_stats boolean false"
    } | debconf-set-selections
    PKGS="$PKGS suricata snort"
  fi
  apt-get install -y -qq $PKGS
  # the packages start their own default services; ours replace them
  for s in suricata snort; do systemctl disable --now "$s" >/dev/null 2>&1 || true; done
fi

# ---------------------------------------------------------------- copy the app
say "Installing the app into $DIR"
mkdir -p "$DIR"
tar -C "$SRC" --exclude=./data --exclude=./logs --exclude=./venv --exclude=./.git --exclude=./tests/__pycache__ -cf - . | tar -C "$DIR" -xf -
mkdir -p "$DIR/data" "$DIR/logs" /var/log/suricata /var/log/snort
python3 -m venv "$DIR/venv"
"$DIR/venv/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || true
"$DIR/venv/bin/pip" install -q -r "$DIR/requirements.txt"
chmod 700 "$DIR/data"

# ---------------------------------------------------------------- sensors
if [ "$SENSORS" -eq 1 ] && command -v suricata >/dev/null; then
  say "Configuring Suricata (uses only the project's rules; your system config is not edited)"
  ethtool -K "$IFACE" rx off tx off gro off lro off >/dev/null 2>&1 || true
  suricata -T -c /etc/suricata/suricata.yaml -S "$DIR/rules/suricata_custom.rules" \
    --set "vars.address-groups.HOME_NET=[$HOME_NET]" --set stream.checksum-validation=no -l /tmp >/dev/null 2>&1 \
    && echo "   Suricata configuration test: OK" || warn "Suricata configuration test failed. Run the command in idps-suricata.service by hand to see why."
fi
if [ "$SENSORS" -eq 1 ] && command -v snort >/dev/null && [ -f /etc/snort/snort.conf ]; then
  say "Configuring Snort (loads only the project's rules)"
  [ -f /etc/snort/rules/local.rules.idps-backup ] || cp /etc/snort/rules/local.rules /etc/snort/rules/local.rules.idps-backup 2>/dev/null || true
  cp "$DIR/rules/snort_local.rules" /etc/snort/rules/local.rules
  # same as the stock config, but with every rules file switched off except local.rules
  sed -E 's|^(include \$RULE_PATH/.*\.rules)|#\1|; s|^#+\s*(include \$RULE_PATH/local\.rules)|\1|' /etc/snort/snort.conf > /etc/snort/snort_idps.conf
  snort -T -c /etc/snort/snort_idps.conf -S "HOME_NET=$HOME_NET" -k none >/dev/null 2>&1 \
    && echo "   Snort configuration test: OK" || warn "Snort configuration test failed. Run:  snort -T -c /etc/snort/snort_idps.conf"
fi

# ---------------------------------------------------------------- app settings + first run
say "First-time setup"
export IDPS_PORT="$PORT"
"$DIR/venv/bin/python" "$DIR/manage.py" set home_net "$HOME_NET" >/dev/null
INIT="$(cd "$DIR" && "$DIR/venv/bin/python" run.py --init-only 2>&1 || true)"
[ "$GEOIP" -eq 1 ] && { say "Downloading the location database"; bash "$DIR/deploy/get-geoip.sh" "$DIR/data/GeoLite2-City.mmdb" || warn "Location database download failed (optional)."; }

# ---------------------------------------------------------------- services
UNITS="$DIR/deploy/generated"; mkdir -p "$UNITS"
cat > "$UNITS/idps.service" <<EOF
[Unit]
Description=IDPS dashboard, readers, decoys and cleanup
After=network-online.target
Wants=network-online.target
[Service]
WorkingDirectory=$DIR
Environment=IDPS_PORT=$PORT
ExecStart=$DIR/venv/bin/python $DIR/run.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
cat > "$UNITS/idps-suricata.service" <<EOF
[Unit]
Description=Suricata network sensor (IDPS rules)
After=network-online.target
[Service]
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -S $DIR/rules/suricata_custom.rules --set "vars.address-groups.HOME_NET=[$HOME_NET]" --set stream.checksum-validation=no --af-packet=$IFACE -l /var/log/suricata
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
cat > "$UNITS/idps-snort.service" <<EOF
[Unit]
Description=Snort network sensor (IDPS rules)
After=network-online.target
[Service]
ExecStart=/usr/sbin/snort -c /etc/snort/snort_idps.conf -i $IFACE -A fast -l /var/log/snort -S HOME_NET=$HOME_NET -k none -q
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
if [ "$SYSTEMD" -eq 1 ] && [ -d /run/systemd/system ]; then
  say "Starting services"
  cp "$UNITS/idps.service" /etc/systemd/system/
  [ "$SENSORS" -eq 1 ] && command -v suricata >/dev/null && cp "$UNITS/idps-suricata.service" /etc/systemd/system/
  [ "$SENSORS" -eq 1 ] && command -v snort >/dev/null && cp "$UNITS/idps-snort.service" /etc/systemd/system/
  systemctl daemon-reload
  for s in idps idps-suricata idps-snort; do
    [ -f "/etc/systemd/system/$s.service" ] && { systemctl enable --now "$s" >/dev/null 2>&1 && echo "   started $s" || warn "$s failed to start: journalctl -u $s -n 30"; }
  done
else
  warn "Services were not started (no systemd, or --no-systemd). Unit files are in $UNITS . To run by hand:  cd $DIR && sudo $DIR/venv/bin/python run.py"
fi

# ---------------------------------------------------------------- done
echo
echo "$INIT" | sed -n '/====/,/====/p'
cat <<EOF

Next steps
  1. Open the dashboard:   http://${MYIP:-<this-machine-ip>}:$PORT   (log in with the password above)
  2. Go to "Setup and health" and press "Run self-test".
  3. Go to "Simulator and tests" and try a safe demo attack.
  4. Add a website or computer on the "Websites and computers" page (one pasted command).
Lost the password later?  sudo $DIR/venv/bin/python $DIR/manage.py set-password
EOF
