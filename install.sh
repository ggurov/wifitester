#!/usr/bin/env bash
# Install wifitester on a Raspberry Pi: code to /opt, config to /etc,
# datastore to /var/lib, systemd unit enabled.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

SRC="$(cd "$(dirname "$0")" && pwd)"
DST=/opt/wifitester
ETC=/etc/wifitester
VAR=/var/lib/wifitester

install -d "$DST" "$ETC" "$VAR"
install -d -m 700 "$ETC/psk"

rm -rf "$DST/wifitester"
cp -a "$SRC/wifitester" "$DST/"
install -m 644 "$SRC/wifitester.service" /etc/systemd/system/wifitester.service
install -m 644 "$SRC/wifitester-web.service" /etc/systemd/system/wifitester-web.service

if [ ! -f "$ETC/config.toml" ]; then
    install -m 600 "$SRC/config.example.toml" "$ETC/config.toml"
    echo "config template installed at $ETC/config.toml -- edit it:"
    echo "  - set psk_file for each AP (put secrets in $ETC/psk/<ssid>, chmod 600)"
else
    echo "keeping existing $ETC/config.toml"
fi

install -m 755 "$SRC/wifitester-cli" /usr/local/bin/wifitester

systemctl daemon-reload
cat <<'EOF'

Done. Next steps:
  1. edit /etc/wifitester/config.toml (add per-AP psk_file secrets)
  2. wifitester validate
  3. sudo systemctl enable --now wifitester wifitester-web
  4. journalctl -u wifitester -f
  5. live status:  http://<this-pi-ip>:8787   (status page, polls every 2s)
     reports:      sudo wifitester -d /var/lib/wifitester report
     graphs:       sudo wifitester -d /var/lib/wifitester dashboard
                   -> /var/lib/wifitester/dashboard.html
EOF
