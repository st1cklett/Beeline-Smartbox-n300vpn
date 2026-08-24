#!/bin/sh

set -u

ROOT=/mnt/usb/n300vpn
CONTROL=$ROOT/bin/n300vpn-control.sh
WEB=$ROOT/bin/n300vpn-web.sh
STATE=$ROOT/state
LOG=$STATE/boot.log

check_files() {
    [ -x "$CONTROL" ] && [ -x "$WEB" ] && [ -s "$STATE/selected.tsv" ]
}

case "${1:-start}" in
    check)
        check_files || { echo "boot_check=missing_usb_files"; exit 1; }
        desired=off
        [ -s "$STATE/autostart.mode" ] && desired=$(cat "$STATE/autostart.mode" 2>/dev/null)
        active=none
        [ -s "$STATE/active.id" ] && active=$(cat "$STATE/active.id" 2>/dev/null)
        echo "boot_check=ok desired=$desired active=$active"
        ;;
    start)
        check_files || exit 1
        mkdir -p "$STATE"
        "$WEB" start >>"$LOG" 2>&1 || true
        desired=off
        [ -s "$STATE/autostart.mode" ] && desired=$(cat "$STATE/autostart.mode" 2>/dev/null)
        active=none
        [ -s "$STATE/active.id" ] && active=$(cat "$STATE/active.id" 2>/dev/null)
        if [ "$desired" = on ] && "$CONTROL" enable "$active" >>"$LOG" 2>&1; then
            echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') boot_vpn=enabled active=$active" >>"$LOG"
        else
            "$CONTROL" disable >>"$LOG" 2>&1 || true
            echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') boot_vpn=direct" >>"$LOG"
        fi
        ;;
    *)
        echo "usage: n300vpn-boot.sh start|check"
        exit 64
        ;;
esac
