#!/bin/sh

set -u

ROOT=/mnt/usb/n300vpn
STATE=$ROOT/state
CONTROL=$ROOT/bin/n300vpn-control.sh
failures=0
health_ticks=0
update_ticks=0

while [ -s "$STATE/mode" ] && [ "$(cat "$STATE/mode")" = on ]; do
    sleep 10
    if [ ! -s "$STATE/n300vless.pid" ] || ! kill -0 "$(cat "$STATE/n300vless.pid")" 2>/dev/null; then
        echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') engine_dead"
        "$CONTROL" failover || true
        failures=0
        continue
    fi
    if ! iptables -t nat -S PREROUTING 2>/dev/null | grep -q -- '-j N300VPNP'; then
        echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') routes_missing"
        "$CONTROL" failover || true
        failures=0
        continue
    fi
    "$CONTROL" refresh-paths >/dev/null 2>&1 || true
    health_ticks=$((health_ticks + 1))
    update_ticks=$((update_ticks + 1))
    if [ "$health_ticks" -ge 6 ]; then
        health_ticks=0
        active=$(cat "$STATE/active.id" 2>/dev/null)
        if "$CONTROL" probe "$active" >/dev/null 2>&1; then
            failures=0
        else
            failures=$((failures + 1))
            echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') probe_failure=$failures active=$active"
        fi
        if [ "$failures" -ge 2 ]; then
            "$CONTROL" failover || true
            failures=0
        fi
    fi
    if [ "$update_ticks" -ge 2160 ]; then
        update_ticks=0
        "$CONTROL" refresh >/dev/null 2>&1 || true
    fi
done

rm -f "$STATE/watchdog.pid"
