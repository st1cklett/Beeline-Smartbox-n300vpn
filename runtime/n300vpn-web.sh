#!/bin/sh

set -u

ROOT=/mnt/usb/n300vpn
STATE=$ROOT/state
PIDFILE=$STATE/uhttpd.pid
LOG=$STATE/uhttpd.log

running() {
    [ -s "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

case "${1:-status}" in
    start)
        running && { echo "web_ui=already_running"; exit 0; }
        mkdir -p "$STATE"
        if [ ! -s "$STATE/web.token" ]; then
            dd if=/dev/urandom bs=16 count=1 2>/dev/null | md5sum | awk '{print $1}' >"$STATE/web.token"
            chmod 600 "$STATE/web.token"
        fi
        /usr/sbin/uhttpd -f -D -R -p 192.168.2.1:8080 -h "$ROOT/www" -x /cgi-bin -n 2 -N 8 -t 60 -T 20 -k 10 >"$LOG" 2>&1 </dev/null &
        echo "$!" >"$PIDFILE"
        sleep 1
        running || { rm -f "$PIDFILE"; echo "web_ui=start_failed"; exit 1; }
        echo "web_ui=started url=http://192.168.2.1:8080/"
        ;;
    stop)
        if running; then kill "$(cat "$PIDFILE")" 2>/dev/null || true; sleep 1; fi
        rm -f "$PIDFILE"
        echo "web_ui=stopped"
        ;;
    status)
        if running; then echo "web_ui=running url=http://192.168.2.1:8080/"; else echo "web_ui=stopped"; fi
        ;;
    *)
        echo "usage: n300vpn-web.sh start|stop|status"
        exit 64
        ;;
esac
