#!/bin/sh
set -eu
ROOT=/mnt/usb/n300vpn
[ -d "$ROOT" ] || { echo "USB not mounted at /mnt/usb"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
mkdir -p "$ROOT/bin" "$ROOT/certs" "$ROOT/nodes" "$ROOT/cache" "$ROOT/state" "$ROOT/private"
chmod 700 "$ROOT/private" "$ROOT/state"
chmod 755 "$ROOT/bin" "$ROOT/runtime" "$ROOT/www" "$ROOT/www/cgi-bin"
chmod 755 "$ROOT/bin/n300vless" "$ROOT/bin/curl" "$ROOT/bin/wget-ssl" 2>/dev/null || true
chmod 755 "$ROOT/www/cgi-bin/n300vpn"
sync
echo "Installed to $ROOT. VPN remains OFF; open http://192.168.2.1:8080/cgi-bin/n300vpn"
