#!/bin/sh

set -u

ROOT=/mnt/usb/n300vpn
INPUT=${1:-$ROOT/cache/BLACK_VLESS_RUS.txt}
WORK=/tmp/n300vpn-rank.$$
RESULT=$WORK/reachable.tsv
SELECTED_NEW=$ROOT/state/selected.new.tsv
PROGRESS=$ROOT/state/scan-progress
LOG=$ROOT/state/rank.log
MAX_CANDIDATES=256

cleanup() {
    rm -f "$PROGRESS.$$.new"
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

write_progress() {
    phase=$1
    testing=$2
    done_count=$3
    total_count=$4
    {
        echo "scan_phase=$phase"
        echo "scan_testing=$testing"
        echo "scan_done=$done_count"
        echo "scan_total=$total_count"
    } >"$PROGRESS.$$.new" || return 1
    mv "$PROGRESS.$$.new" "$PROGRESS"
}

mkdir -p "$WORK/nodes" "$ROOT/state" "$ROOT/nodes"
if ! "$ROOT/bin/parse-subscription.lua" "$INPUT" "$WORK/nodes" "$WORK/nodes.tsv" "$MAX_CANDIDATES" "$WORK/import.stats" >>"$LOG" 2>&1; then
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') parser_failed" >>"$LOG"
    exit 10
fi

total=$(wc -l <"$WORK/nodes.tsv" 2>/dev/null)
[ -n "$total" ] || total=0
completed=0
: >"$RESULT"
write_progress endpoints none 0 "$total"

while IFS="$(printf '\t')" read -r id label protocol server port transport security source; do
    [ -n "$id" ] || continue
    write_progress endpoints "$id" "$completed" "$total"
    config=$WORK/nodes/$id.conf
    output=$($ROOT/bin/n300vless --probe-endpoint-config "$config" 2>&1) || true
    latency=$(echo "$output" | sed -n 's/.*latency_ms=\([0-9][0-9]*\).*/\1/p' | head -n 1)
    if [ -n "$latency" ]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$latency" "$id" "$label" "$protocol" "$server" "$port" "$transport" "$security" "$source" >>"$RESULT"
    fi
    completed=$((completed + 1))
done <"$WORK/nodes.tsv"

reachable=$(wc -l <"$RESULT" 2>/dev/null)
[ -n "$reachable" ] || reachable=0
cp "$WORK/import.stats" "$WORK/import.final.stats" || exit 12
{
    echo "scanned=$total"
    echo "reachable=$reachable"
} >>"$WORK/import.final.stats"

if [ ! -s "$RESULT" ]; then
    mv "$WORK/import.final.stats" "$ROOT/state/import.stats"
    write_progress failed none "$completed" "$total"
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') scanned=$total reachable=0" >>"$LOG"
    exit 11
fi

write_progress publishing none "$completed" "$total"
sort -n -k1,1 "$RESULT" >"$SELECTED_NEW" || exit 12
while IFS="$(printf '\t')" read -r latency id label protocol server port transport security source; do
    cp "$WORK/nodes/$id.conf" "$ROOT/nodes/$id.conf.new" || exit 12
    chmod 600 "$ROOT/nodes/$id.conf.new"
    mv "$ROOT/nodes/$id.conf.new" "$ROOT/nodes/$id.conf"
done <"$SELECTED_NEW"

mv "$SELECTED_NEW" "$ROOT/state/selected.tsv"
mv "$WORK/import.final.stats" "$ROOT/state/import.stats"
write_progress complete none "$completed" "$total"
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') scanned=$total reachable=$reachable" >>"$LOG"
echo "scan_complete=1 scanned=$total reachable=$reachable"
