#!/bin/sh

set -u

ROOT=/mnt/usb/n300vpn
BIN=$ROOT/bin/n300vless
STATE=$ROOT/state
NODES=$ROOT/nodes
PIDFILE=$STATE/n300vless.pid
WATCHDOG_PID=$STATE/watchdog.pid
ACTIVE=$STATE/active.id
MODE=$STATE/mode
AUTOSTART=$STATE/autostart.mode
PATHS=$STATE/paths.conf
YOUTUBE_RESULTS=$STATE/youtube-results.tsv
YOUTUBE_BEST=$STATE/youtube-best.id
YOUTUBE_PROGRESS=$STATE/youtube-progress
YOUTUBE_LAST=$STATE/youtube-last.out
SCAN_PROGRESS=$STATE/scan-progress
PENDING=$STATE/activation.pending
ROLLBACK_PID=$STATE/activation-rollback.pid
LOG=$STATE/service.log
LOCK=/tmp/n300vpn-control.lock
UPDATE_LOCK=/tmp/n300vpn-update.lock
YOUTUBE_LOCK=/tmp/n300vpn-youtube.lock
YOUTUBE_LIMIT=20
YOUTUBE_CANDIDATES=$STATE/.youtube-candidates.$$
SUBSCRIPTION_URL=$ROOT/private/subscription.url
LEGACY_SUBSCRIPTION_URL=$ROOT/private/crunch.url
SUBSCRIPTION_CACHE=$ROOT/cache/crunch-subscription.json

mkdir -p "$STATE"

ensure_paths() {
    [ -s "$PATHS" ] && return 0
    temporary=/tmp/n300vpn-paths-default.$$
    {
        # Safe first start: the user explicitly selects which paths use VPN.
        echo lan1=0
        echo lan2=0
        echo lan3=0
        echo lan4=0
        echo wifi=0
    } >"$temporary" || return 1
    mv "$temporary" "$PATHS"
}

path_enabled() {
    ensure_paths || return 1
    grep -q "^$1=1$" "$PATHS" 2>/dev/null
}

path_port() {
    case "$1" in
        lan1) echo 0 ;;
        lan2) echo 1 ;;
        lan3) echo 2 ;;
        lan4) echo 3 ;;
        *) return 1 ;;
    esac
}

path_macs() {
    path=$1
    if [ "$path" = wifi ]; then
        iwinfo wlan0 assoclist 2>/dev/null | awk '
            $1 ~ /^([0-9A-Fa-f][0-9A-Fa-f]:){5}[0-9A-Fa-f][0-9A-Fa-f]$/ { print tolower($1) }
        '
        return
    fi
    port=$(path_port "$path") || return 1
    awk -v marker="mbr("$port" )" '
        index($0, marker) && $0 ~ /FWD DYN/ {
            for (field=1; field<=NF; field++) {
                value=tolower($field)
                if (value ~ /^([0-9a-f][0-9a-f]:){5}[0-9a-f][0-9a-f]$/) print value
            }
        }
    ' /proc/rtl865x/l2 2>/dev/null
}

all_paths_enabled() {
    for path in lan1 lan2 lan3 lan4 wifi; do
        path_enabled "$path" || return 1
    done
}

valid_id() {
    case "$1" in
        vless-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
        *) return 1 ;;
    esac
    awk -F '\t' -v wanted="$1" '$2 == wanted { found=1 } END { exit found ? 0 : 1 }' "$STATE/selected.tsv" 2>/dev/null
}

engine_pids() {
    for process_path in /proc/[0-9]*; do
        [ -r "$process_path/cmdline" ] || continue
        process_command=$(tr '\000' ' ' <"$process_path/cmdline" 2>/dev/null)
        case "$process_command" in
            "$BIN --serve "*) echo "${process_path##*/}" ;;
        esac
    done
}

engine_running() {
    engine_pids | grep -q '^[0-9][0-9]*$'
}

watchdog_running() {
    [ -s "$WATCHDOG_PID" ] || return 1
    pid=$(cat "$WATCHDOG_PID" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

routes_present() {
    iptables -t nat -S PREROUTING 2>/dev/null | grep -q -- '-j N300VPNP'
}

routes_remove() {
    while iptables -t nat -D PREROUTING -i br-lan -p tcp -j N300VPNP 2>/dev/null; do :; done
    while iptables -t nat -D PREROUTING -i br-lan -p tcp -j N300VPN 2>/dev/null; do :; done
    while iptables -t filter -D FORWARD -i br-lan -p udp --dport 443 -j N300VPNQP 2>/dev/null; do :; done
    while iptables -t filter -D FORWARD -i br-lan -p udp --dport 443 -j N300VPNQ 2>/dev/null; do :; done
    iptables -t nat -F N300VPNP 2>/dev/null || true
    iptables -t nat -X N300VPNP 2>/dev/null || true
    iptables -t nat -F N300VPN 2>/dev/null || true
    iptables -t nat -X N300VPN 2>/dev/null || true
    iptables -t filter -F N300VPNQP 2>/dev/null || true
    iptables -t filter -X N300VPNQP 2>/dev/null || true
    iptables -t filter -F N300VPNQ 2>/dev/null || true
    iptables -t filter -X N300VPNQ 2>/dev/null || true
}

policy_refresh() {
    routes_present || return 0
    iptables -t nat -F N300VPNP || return 1
    iptables -t filter -F N300VPNQP || return 1
    if all_paths_enabled; then
        iptables -t nat -A N300VPNP -j N300VPN || return 1
        iptables -t filter -A N300VPNQP -j N300VPNQ || return 1
        return 0
    fi
    macs=" "
    for path in lan1 lan2 lan3 lan4 wifi; do
        path_enabled "$path" || continue
        for mac in $(path_macs "$path"); do
            echo "$mac" | grep -Eq '^([0-9a-f][0-9a-f]:){5}[0-9a-f][0-9a-f]$' || continue
            case "$macs" in *" $mac "*) continue ;; esac
            macs="$macs$mac "
            iptables -t nat -A N300VPNP -m mac --mac-source "$mac" -j N300VPN || return 1
            iptables -t filter -A N300VPNQP -m mac --mac-source "$mac" -j N300VPNQ || return 1
        done
    done
}

routes_add() {
    routes_remove
    iptables -t nat -N N300VPN || return 1
    for network in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
        iptables -t nat -A N300VPN -d "$network" -j RETURN || return 1
    done
    # The compact engine is intentionally a web VPN. Redirecting every TCP
    # service creates a burst of TLS/Reality handshakes that can stall the
    # single-core RTL8197D. HTTP(S) covers browsers and YouTube while leaving
    # SSH, DNS and local services on their normal paths.
    iptables -t nat -A N300VPN -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 12345 || return 1
    iptables -t nat -N N300VPNP || return 1
    iptables -t nat -I PREROUTING 1 -i br-lan -p tcp -j N300VPNP || return 1
    iptables -t filter -N N300VPNQ || return 1
    iptables -t filter -A N300VPNQ -j REJECT || return 1
    iptables -t filter -N N300VPNQP || return 1
    iptables -t filter -I FORWARD 1 -i br-lan -p udp --dport 443 -j N300VPNQP || return 1
    policy_refresh || return 1
}

path_status() {
    ensure_paths || return 1
    port_data=$(cat /proc/rtl865x/port_status 2>/dev/null)
    l2_data=$(cat /proc/rtl865x/l2 2>/dev/null)
    for path in lan1 lan2 lan3 lan4; do
        port=$(path_port "$path")
        selected=off
        path_enabled "$path" && selected=on
        details=$(echo "$port_data" | awk -v wanted="$port" '
            function emit() {
                if (!active) return
                if (link == "") link="unknown"
                print link "|" speed "|" duplex
                finished=1
            }
            $1 == ("Port" wanted) && $2 == "Force" { active=1; next }
            active && /^Port/ { emit(); exit }
            active && /^$/ { emit(); exit }
            active && /LinkDown/ { link="down" }
            active && /LinkUp/ { link="up" }
            active && /Duplex Enabled/ { duplex="full" }
            active && /Duplex Disabled/ { duplex="half" }
            active && match($0, /Speed [0-9]+M/) { speed=substr($0, RSTART+6, RLENGTH-6) }
            END { if (active && !finished) emit() }
        ')
        [ -n "$details" ] || details='unknown||'
        devices=$(echo "$l2_data" | awk -v marker="mbr("$port" )" 'index($0, marker) && $0 ~ /FWD DYN/ { count++ } END { print count+0 }')
        echo "path_$path=$selected|$details|$devices"
    done
    selected=off
    path_enabled wifi && selected=on
    wifi_link=down
    if ifconfig wlan0 2>/dev/null | grep -q 'UP '; then wifi_link=up; fi
    stations=$(iwinfo wlan0 assoclist 2>/dev/null | awk '$1 ~ /^([0-9A-Fa-f][0-9A-Fa-f]:){5}[0-9A-Fa-f][0-9A-Fa-f]$/ { count++ } END { print count+0 }')
    echo "path_wifi=$selected|$wifi_link|2.4GHz||$stations"
}

set_paths() {
    requested=${1:-}
    case "$requested" in *[!a-z0-9,]*) return 2 ;; esac
    for item in $(echo "$requested" | tr ',' ' '); do
        case "$item" in lan1|lan2|lan3|lan4|wifi) ;; *) return 2 ;; esac
    done
    ensure_paths || return 1
    old=/tmp/n300vpn-paths-old.$$
    new=/tmp/n300vpn-paths-new.$$
    cp "$PATHS" "$old" || return 1
    : >"$new" || return 1
    for path in lan1 lan2 lan3 lan4 wifi; do
        value=0
        case ",$requested," in *",$path,"*) value=1 ;; esac
        echo "$path=$value" >>"$new" || return 1
    done
    mv "$new" "$PATHS" || return 1
    if routes_present && ! policy_refresh; then
        mv "$old" "$PATHS"
        policy_refresh || routes_remove
        return 1
    fi
    rm -f "$old" "$new"
    sync
}

stop_engine() {
    engine_processes=$(engine_pids)
    if [ -n "$engine_processes" ]; then
        for process in $engine_processes; do
            kill "$process" 2>/dev/null || true
        done
        sleep 1
    fi
    for process in $(engine_pids); do
        kill -9 "$process" 2>/dev/null || true
    done
    rm -f "$PIDFILE"
}

probe_node() {
    id=$1
    valid_id "$id" || return 2
    "$BIN" --probe-config "$NODES/$id.conf"
}

probe_youtube_node() {
    id=$1
    valid_id "$id" || return 2
    "$BIN" --probe-youtube-config "$NODES/$id.conf"
}

start_engine() {
    id=$1
    valid_id "$id" || return 2
    stop_engine
    "$BIN" --serve "$NODES/$id.conf" >>"$LOG" 2>&1 </dev/null &
    pid=$!
    echo "$pid" >"$PIDFILE"
    sleep 1
    if ! kill -0 "$pid" 2>/dev/null; then
        rm -f "$PIDFILE"
        return 1
    fi
}

local_tunnel_probe() {
    # Test the already running daemon through its SOCKS listener before any
    # LAN packet can be redirected to it. The bundled 2014 curl/PolarSSL does
    # not trust Google's current chain, so -k is limited to this public 204
    # transport canary; protocol authentication was already checked by
    # probe_node above. The browser independently checks YouTube afterwards.
    [ -x "$ROOT/bin/curl" ] || return 1
    "$ROOT/bin/curl" --socks5-hostname 127.0.0.1:10808 \
        -k -fsS --connect-timeout 5 -m 12 -o /dev/null \
        https://connectivitycheck.gstatic.com/generate_204 || return 1
}

cancel_activation_rollback() {
    if [ -s "$ROLLBACK_PID" ]; then
        rollback_pid=$(cat "$ROLLBACK_PID" 2>/dev/null)
        [ -n "$rollback_pid" ] && kill "$rollback_pid" 2>/dev/null || true
    fi
    rm -f "$ROLLBACK_PID" "$PENDING"
}

arm_activation_rollback() {
    id=$1
    cancel_activation_rollback
    echo "$id" >"$PENDING" || return 1
    (
        sleep 25
        [ -s "$PENDING" ] || exit 0
        pending_id=$(cat "$PENDING" 2>/dev/null)
        [ "$pending_id" = "$id" ] || exit 0
        "$0" rollback-pending "$id" >>"$LOG" 2>&1
    ) &
    echo "$!" >"$ROLLBACK_PID"
}

start_watchdog() {
    watchdog_running && return 0
    "$ROOT/bin/n300vpn-watchdog.sh" >>"$STATE/watchdog.log" 2>&1 </dev/null &
    echo "$!" >"$WATCHDOG_PID"
}

stop_watchdog() {
    if watchdog_running; then kill "$(cat "$WATCHDOG_PID")" 2>/dev/null || true; fi
    rm -f "$WATCHDOG_PID"
}

pid_lock_active() {
    lock_directory=$1
    [ -s "$lock_directory/pid" ] || return 1
    lock_pid=$(cat "$lock_directory/pid" 2>/dev/null)
    [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null
}

acquire_named_lock() {
    lock_directory=$1
    if ! mkdir "$lock_directory" 2>/dev/null; then
        pid_lock_active "$lock_directory" && return 1
        rm -f "$lock_directory/pid"
        rmdir "$lock_directory" 2>/dev/null || return 1
        mkdir "$lock_directory" 2>/dev/null || return 1
    fi
    echo "$$" >"$lock_directory/pid"
}

release_named_lock() {
    lock_directory=$1
    rm -f "$lock_directory/pid"
    rmdir "$lock_directory" 2>/dev/null || true
}

background_check_active() {
    pid_lock_active "$UPDATE_LOCK" || pid_lock_active "$YOUTUBE_LOCK"
}

status() {
    active=none
    [ -s "$ACTIVE" ] && active=$(cat "$ACTIVE")
    mode=off
    [ -s "$MODE" ] && mode=$(cat "$MODE")
    [ "$mode" = off ] && active=none
    engine=stopped
    engine_running && engine=running
    routes=off
    routes_present && routes=on
    watchdog=stopped
    watchdog_running && watchdog=running
    updating=no
    pid_lock_active "$UPDATE_LOCK" && updating=yes
    ranking=no
    pid_lock_active "$YOUTUBE_LOCK" && ranking=yes
    selected=0
    [ -s "$STATE/selected.tsv" ] && selected=$(wc -l < "$STATE/selected.tsv")
    echo "mode=$mode"
    echo "active=$active"
    echo "engine=$engine"
    echo "routes=$routes"
    echo "watchdog=$watchdog"
    echo "updating=$updating"
    echo "ranking=$ranking"
    echo "selected=$selected"
    autostart=off
    [ -s "$AUTOSTART" ] && autostart=$(cat "$AUTOSTART" 2>/dev/null)
    [ "$autostart" = on ] || autostart=off
    echo "autostart=$autostart"
    pending=none
    [ -s "$PENDING" ] && pending=$(cat "$PENDING" 2>/dev/null)
    echo "pending=$pending"
    youtube_best=none
    youtube_best_score=0
    if [ -s "$YOUTUBE_BEST" ]; then
        youtube_best=$(cat "$YOUTUBE_BEST" 2>/dev/null)
        youtube_best_score=$(awk -F '\t' -v wanted="$youtube_best" '$2 == wanted && NF >= 4 { print $1; exit }' "$YOUTUBE_RESULTS" 2>/dev/null)
        [ -n "$youtube_best_score" ] || youtube_best_score=0
    fi
    echo "youtube_best=$youtube_best"
    echo "youtube_best_score=$youtube_best_score"
    # Compatibility for a page that was already open before the metric update.
    echo "youtube_best_latency=$youtube_best_score"
    if [ "$ranking" = yes ] && [ -s "$YOUTUBE_PROGRESS" ]; then
        cat "$YOUTUBE_PROGRESS"
    else
        last_youtube_source=$(sed -n 's/.*source=\([^ ]*\).*/\1/p' "$YOUTUBE_LAST" 2>/dev/null | head -n 1)
        case "$last_youtube_source" in crunch|repository) ;; *) last_youtube_source=none ;; esac
        echo "youtube_testing=none"
        echo "youtube_done=0"
        echo "youtube_total=0"
        echo "youtube_source=$last_youtube_source"
    fi
    if [ "$updating" = yes ] && [ -s "$SCAN_PROGRESS" ]; then
        cat "$SCAN_PROGRESS"
    else
        echo "scan_phase=none"
        echo "scan_testing=none"
        echo "scan_done=0"
        echo "scan_total=0"
    fi
    path_status
}

rank_youtube_nodes() {
    youtube_source=$1
    YOUTUBE_WINNER_ID=
    YOUTUBE_WINNER_SCORE=2147483647
    YOUTUBE_WINNER_ENDPOINT=2147483647
    completed=0
    awk -F '\t' -v source="$youtube_source" 'BEGIN { OFS="\t" } {
        node_source=$9
        if (node_source == "") node_source=(index($3, "Crunch-VPN-") == 1 ? "crunch" : "repository")
        is_crunch=node_source == "crunch"
        if (source == "crunch" && !is_crunch) next
        if (source == "repository" && is_crunch) next
        priority=2
        if ($8 == "reality") priority=0
        else if ($8 == "tls") priority=1
        print priority, $0
    }' "$STATE/selected.tsv" 2>/dev/null | sort -n -k1,1 -k2,2n | head -n "$YOUTUBE_LIMIT" | cut -f2- >"$YOUTUBE_CANDIDATES"
    total=$(wc -l <"$YOUTUBE_CANDIDATES" 2>/dev/null)
    [ -n "$total" ] || total=0
    results_new=$STATE/.youtube-results.$$
    progress_new=$STATE/.youtube-progress.$$
    : >"$results_new" || return 1
    while IFS="$(printf '\t')" read -r listed_latency id rest; do
        [ -n "$id" ] || continue
        {
            echo "youtube_testing=$id"
            echo "youtube_done=$completed"
            echo "youtube_total=$total"
            echo "youtube_source=$youtube_source"
        } >"$progress_new"
        mv "$progress_new" "$YOUTUBE_PROGRESS"
        output=$(probe_youtube_node "$id" 2>&1) || {
            echo "youtube_failed=$id"
            completed=$((completed + 1))
            continue
        }
        page_ms=$(echo "$output" | sed -n 's/.*page_ms=\([0-9][0-9]*\).*/\1/p' | head -n 1)
        media_ms=$(echo "$output" | sed -n 's/.*media_ms=\([0-9][0-9]*\).*/\1/p' | head -n 1)
        [ -n "$page_ms" ] && [ -n "$media_ms" ] || {
            echo "youtube_failed=$id"
            completed=$((completed + 1))
            continue
        }
        score_ms=$page_ms
        [ "$media_ms" -le "$score_ms" ] || score_ms=$media_ms
        echo "youtube_ok=$id page_ms=$page_ms media_ms=$media_ms score_ms=$score_ms endpoint_ms=$listed_latency"
        printf '%s\t%s\t%s\t%s\t%s\n' "$score_ms" "$id" "$page_ms" "$media_ms" "$listed_latency" >>"$results_new"
        completed=$((completed + 1))
        if [ "$score_ms" -lt "$YOUTUBE_WINNER_SCORE" ] || {
            [ "$score_ms" -eq "$YOUTUBE_WINNER_SCORE" ] && [ "$listed_latency" -lt "$YOUTUBE_WINNER_ENDPOINT" ]
        }; then
            YOUTUBE_WINNER_SCORE=$score_ms
            YOUTUBE_WINNER_ENDPOINT=$listed_latency
            YOUTUBE_WINNER_ID=$id
        fi
    done <"$YOUTUBE_CANDIDATES"
    rm -f "$YOUTUBE_CANDIDATES"
    rm -f "$YOUTUBE_PROGRESS" "$progress_new"
    if [ -z "$YOUTUBE_WINNER_ID" ]; then
        rm -f "$results_new"
        echo "youtube_best_failed=no_working_nodes"
        return 1
    fi
    mv "$results_new" "$YOUTUBE_RESULTS"
    echo "$YOUTUBE_WINNER_ID" >"$YOUTUBE_BEST"
}

acquire_lock() {
    acquire_named_lock "$LOCK"
}

release_lock() {
    release_named_lock "$LOCK"
}

rank_youtube_worker() {
    youtube_source=$1
    if ! acquire_named_lock "$YOUTUBE_LOCK"; then
        echo "youtube check is already running"
        return 3
    fi
    trap 'rm -f "$YOUTUBE_PROGRESS" "$YOUTUBE_CANDIDATES"; release_named_lock "$YOUTUBE_LOCK"' EXIT INT TERM
    if rank_youtube_nodes "$youtube_source"; then
        echo "youtube_best=$YOUTUBE_WINNER_ID score_ms=$YOUTUBE_WINNER_SCORE endpoint_ms=$YOUTUBE_WINNER_ENDPOINT source=$youtube_source" >"$YOUTUBE_LAST.new"
        mv "$YOUTUBE_LAST.new" "$YOUTUBE_LAST"
        echo "youtube_best=$YOUTUBE_WINNER_ID score_ms=$YOUTUBE_WINNER_SCORE endpoint_ms=$YOUTUBE_WINNER_ENDPOINT source=$youtube_source vpn_enabled=0"
        return 0
    fi
    echo "youtube_best_failed=no_working_nodes source=$youtube_source" >"$YOUTUBE_LAST.new"
    mv "$YOUTUBE_LAST.new" "$YOUTUBE_LAST"
    return 25
}

action=${1:-status}
case "$action" in
    status)
        status
        exit 0
        ;;
    probe)
        if background_check_active; then
            echo "server checks are still running"
            exit 30
        fi
        probe_node "${2:-}"
        exit $?
        ;;
    youtube)
        if background_check_active; then
            echo "server checks are still running"
            exit 30
        fi
        probe_youtube_node "${2:-}"
        exit $?
        ;;
    refresh)
        if pid_lock_active "$UPDATE_LOCK"; then
            echo "subscription update is already running"
            exit 3
        fi
        if pid_lock_active "$YOUTUBE_LOCK"; then
            echo "youtube check is still running"
            exit 30
        fi
        "$ROOT/bin/update-subscriptions.sh" >"$STATE/update-background.log" 2>&1 </dev/null &
        echo "update_started=1"
        exit 0
        ;;
    rank-youtube)
        youtube_source=${2:-}
        case "$youtube_source" in crunch|repository) ;; *) echo "unknown subscription source"; exit 21 ;; esac
        if pid_lock_active "$UPDATE_LOCK"; then
            echo "subscription update is still running"
            exit 30
        fi
        if pid_lock_active "$YOUTUBE_LOCK"; then
            echo "youtube check is already running"
            exit 3
        fi
        if [ ! -s "$STATE/selected.tsv" ]; then
            echo "no reachable servers to check"
            exit 25
        fi
        echo "running source=$youtube_source" >"$YOUTUBE_LAST"
        "$0" rank-youtube-worker "$youtube_source" >"$STATE/youtube-background.log" 2>&1 </dev/null &
        echo "youtube_rank_started=1 limit=$YOUTUBE_LIMIT source=$youtube_source"
        exit 0
        ;;
    rank-youtube-worker)
        youtube_source=${2:-}
        case "$youtube_source" in crunch|repository) ;; *) exit 21 ;; esac
        rank_youtube_worker "$youtube_source"
        exit $?
        ;;
esac

case "$action" in
    enable|best-youtube|start-local|remove-subscription|confirm)
        if background_check_active; then
            echo "server checks are still running"
            exit 30
        fi
        ;;
esac

if ! acquire_lock; then
    echo "control operation already running"
    exit 20
fi
trap 'release_lock' EXIT INT TERM

case "$action" in
    remove-subscription)
        current_mode=off
        [ -s "$MODE" ] && current_mode=$(cat "$MODE" 2>/dev/null)
        if [ "$current_mode" != off ]; then
            echo "disable VPN before removing subscription"
            exit 31
        fi
        rm -f "$SUBSCRIPTION_URL" "$LEGACY_SUBSCRIPTION_URL"
        rm -f "$SUBSCRIPTION_CACHE" "$SUBSCRIPTION_CACHE.last-good"
        rm -f "$YOUTUBE_RESULTS" "$YOUTUBE_BEST" "$YOUTUBE_PROGRESS" "$YOUTUBE_LAST"
        "$ROOT/bin/update-subscriptions.sh" >"$STATE/update-background.log" 2>&1 </dev/null &
        echo "subscription_removed=1 update_started=1"
        ;;
    enable)
        id=${2:-}
        valid_id "$id" || exit 21
        routes_remove
        stop_engine
        if ! probe_node "$id"; then
            echo "selected node failed its real probe"
            echo off >"$MODE"
            echo off >"$AUTOSTART"
            exit 22
        fi
        if ! start_engine "$id"; then
            echo "VPN engine failed to start"
            echo off >"$MODE"
            echo off >"$AUTOSTART"
            exit 23
        fi
        if ! local_tunnel_probe; then
            stop_engine
            echo off >"$MODE"
            echo off >"$AUTOSTART"
            echo "VPN started but its local HTTPS test failed; direct internet was kept"
            exit 28
        fi
        if ! routes_add; then
            routes_remove
            stop_engine
            echo off >"$MODE"
            echo off >"$AUTOSTART"
            echo "routing activation failed; direct internet restored"
            exit 24
        fi
        echo "$id" >"$ACTIVE"
        echo pending >"$MODE"
        echo off >"$AUTOSTART"
        if ! arm_activation_rollback "$id"; then
            routes_remove
            stop_engine
            echo off >"$MODE"
            echo "safety rollback could not be armed; direct internet restored"
            exit 29
        fi
        echo "vpn_pending=$id rollback_seconds=25"
        ;;
    confirm)
        [ -s "$PENDING" ] || { echo "no pending VPN activation"; exit 29; }
        pending_id=$(cat "$PENDING" 2>/dev/null)
        engine_running && routes_present || {
            routes_remove
            stop_engine
            cancel_activation_rollback
            echo off >"$MODE"
            echo "VPN confirmation failed; direct internet restored"
            exit 29
        }
        cancel_activation_rollback
        echo "$pending_id" >"$ACTIVE"
        echo on >"$MODE"
        # Reboot restoration stays deliberately disabled until a later,
        # explicitly supervised reboot test succeeds.
        echo off >"$AUTOSTART"
        start_watchdog
        echo "vpn_confirmed=$pending_id autostart=off"
        ;;
    rollback-pending)
        expected=${2:-}
        [ -s "$PENDING" ] || exit 0
        pending_id=$(cat "$PENDING" 2>/dev/null)
        [ -z "$expected" ] || [ "$expected" = "$pending_id" ] || exit 0
        routes_remove
        stop_engine
        stop_watchdog
        rm -f "$PENDING" "$ROLLBACK_PID"
        echo off >"$MODE"
        echo off >"$AUTOSTART"
        echo "activation_timeout=$pending_id direct_internet_restored=1"
        ;;
    best-youtube)
        youtube_source=${2:-repository}
        case "$youtube_source" in crunch|repository) ;; *) echo "unknown subscription source"; exit 21 ;; esac
        rank_youtube_nodes "$youtube_source" || exit 25
        best_id=$YOUTUBE_WINNER_ID
        best_score=$YOUTUBE_WINNER_SCORE
        routes_remove
        stop_engine
        if ! start_engine "$best_id"; then
            echo off >"$MODE"
            echo off >"$AUTOSTART"
            echo "youtube_best_engine_failed=$best_id; direct internet restored"
            exit 23
        fi
        if ! local_tunnel_probe; then
            stop_engine
            echo off >"$MODE"
            echo off >"$AUTOSTART"
            echo "youtube_best_local_test_failed=$best_id; direct internet preserved"
            exit 28
        fi
        if ! routes_add; then
            routes_remove
            stop_engine
            echo off >"$MODE"
            echo off >"$AUTOSTART"
            echo "youtube_best_routes_failed=$best_id; direct internet restored"
            exit 24
        fi
        echo "$best_id" >"$ACTIVE"
        echo pending >"$MODE"
        echo off >"$AUTOSTART"
        if ! arm_activation_rollback "$best_id"; then
            routes_remove
            stop_engine
            echo off >"$MODE"
            echo "safety rollback could not be armed; direct internet restored"
            exit 29
        fi
        echo "youtube_best=$best_id score_ms=$best_score vpn_pending=1 rollback_seconds=25"
        ;;
    disable)
        cancel_activation_rollback
        routes_remove
        stop_engine
        stop_watchdog
        echo off >"$MODE"
        echo off >"$AUTOSTART"
        echo "vpn_disabled=1"
        ;;
    set-paths)
        if ! set_paths "${2:-}"; then
            echo "path policy rejected; previous safe policy restored"
            exit 26
        fi
        echo "paths_updated=1"
        path_status
        ;;
    refresh-paths)
        if ! policy_refresh; then
            routes_remove
            stop_engine
            stop_watchdog
            echo off >"$MODE"
            echo off >"$AUTOSTART"
            echo "path refresh failed; direct internet restored"
            exit 27
        fi
        echo "paths_refreshed=1"
        ;;
    start-local)
        id=${2:-}
        valid_id "$id" || exit 21
        routes_remove
        probe_node "$id" || exit 22
        start_engine "$id" || exit 23
        echo "$id" >"$ACTIVE"
        echo local >"$MODE"
        echo "local_proxy_started=$id"
        ;;
    stop-local)
        routes_remove
        stop_engine
        echo off >"$MODE"
        echo "local_proxy_stopped=1"
        ;;
    failover)
        old=none
        [ -s "$ACTIVE" ] && old=$(cat "$ACTIVE")
        routes_remove
        stop_engine
        replacement=
        while IFS="$(printf '\t')" read -r latency id rest; do
            [ "$id" = "$old" ] && continue
            if probe_node "$id" >/dev/null 2>&1 && start_engine "$id" && \
               local_tunnel_probe >/dev/null 2>&1 && routes_add; then
                replacement=$id
                break
            fi
            routes_remove
            stop_engine
        done <"$STATE/selected.tsv"
        if [ -n "$replacement" ]; then
            echo "$replacement" >"$ACTIVE"
            echo on >"$MODE"
            echo on >"$AUTOSTART"
            echo "failover=$replacement"
        else
            routes_remove
            stop_engine
            echo off >"$MODE"
            echo off >"$AUTOSTART"
            echo "failopen=direct"
        fi
        ;;
    *)
        echo "usage: n300vpn-control.sh status|probe ID|youtube ID|refresh|enable ID|confirm|best-youtube [crunch|repository]|rank-youtube SOURCE|remove-subscription|disable|set-paths LIST|refresh-paths|start-local ID|stop-local|failover"
        exit 64
        ;;
esac
