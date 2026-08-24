#!/bin/sh

set -u

ROOT=/mnt/usb/n300vpn
CURL=$ROOT/bin/curl
CA=$ROOT/certs/cacert.pem
LEGACY_CA=$ROOT/certs/aaa-certificate-services.pem
STATE=$ROOT/state
CACHE=$ROOT/cache
LOCK=/tmp/n300vpn-update.lock
NAME=BLACK_VLESS_RUS.txt
EXTRA_NAME='BLACK_SS+All_RUS.txt'
CRUNCH_NAME='crunch-subscription.json'
CRUNCH_URL_FILE=$ROOT/private/subscription.url
TEMP_BASE=/tmp/n300vpn-subscription.$$
TEMP=$TEMP_BASE
LOG=$STATE/update.log

finish() {
    rm -f "$TEMP_BASE" "$TEMP_BASE.extra" "$TEMP_BASE.crunch" "$TEMP_BASE.crunch.vless" "$TEMP_BASE.merged"
    rm -f "$LOCK/pid"
    rmdir "$LOCK" 2>/dev/null || true
}

lock_active() {
    [ -s "$LOCK/pid" ] || return 1
    lock_pid=$(cat "$LOCK/pid" 2>/dev/null)
    [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null
}

if ! mkdir "$LOCK" 2>/dev/null; then
    if lock_active; then
        echo "subscription update is already running"
        exit 3
    fi
    rm -f "$LOCK/pid"
    rmdir "$LOCK" 2>/dev/null || true
    mkdir "$LOCK" 2>/dev/null || exit 3
fi
echo "$$" >"$LOCK/pid"
trap finish EXIT INT TERM

mkdir -p "$STATE" "$CACHE"
if [ "$(date +%Y)" -lt 2025 ]; then
    ntpd -n -q -p time.cloudflare.com -p time.google.com -p 0.openwrt.pool.ntp.org >>"$LOG" 2>&1 || true
fi
if [ "$(date +%Y)" -lt 2025 ]; then
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') clock_invalid" >>"$LOG"
    exit 4
fi

validate() {
    [ -s "$TEMP" ] || return 1
    [ "$(wc -c < "$TEMP")" -ge 256 ] || return 1
    [ "$(wc -c < "$TEMP")" -le 4194304 ] || return 1
    grep -q "$VALID_PATTERN" "$TEMP" || return 1
    grep -q '^# Date/Time:' "$TEMP" || return 1
}

fetch() {
    source_name=$1
    certificate=$2
    address=$3
    rm -f "$TEMP"
    if "$CURL" --cacert "$certificate" -A 'n300vpn/1.0' -fsSL --max-redirs 2 \
        --connect-timeout 5 -m 25 --max-filesize 4194304 -o "$TEMP" "$address" && validate; then
        SOURCE=$source_name
        return 0
    fi
    return 1
}

validate_crunch() {
    [ -s "$TEMP_BASE.crunch" ] || return 1
    [ "$(wc -c < "$TEMP_BASE.crunch")" -ge 256 ] || return 1
    [ "$(wc -c < "$TEMP_BASE.crunch")" -le 4194304 ] || return 1
    jsonfilter -i "$TEMP_BASE.crunch" -e '@[*].outbounds[0].protocol' 2>/dev/null | grep -q '^vless$'
}

fetch_crunch() {
    crunch_url=$1
    rm -f "$TEMP_BASE.crunch"
    case "$crunch_url" in https://crunch-crunch.com/sub/*) ;; *) return 1 ;; esac
    crunch_ip=$($ROOT/bin/n300vless --resolve-a crunch-crunch.com "$CA" 2>>"$LOG" | sed -n 's/^resolved_ip=//p' | head -n 1)
    [ -n "$crunch_ip" ] || return 1
    $ROOT/bin/n300vless --fetch-crunch "$CRUNCH_URL_FILE" "$crunch_ip" "$TEMP_BASE.crunch" "$CA" 2>>"$LOG" && \
        validate_crunch
}

SOURCE=
VALID_PATTERN='^vless://'
fetch github-raw "$CA" "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/$NAME" || \
fetch gitlab "$LEGACY_CA" "https://gitlab.com/igareck/vpn-configs-for-russia/-/raw/main/$NAME" || \
fetch codeberg "$CA" "https://codeberg.org/igareck/vpn-configs-for-russia/raw/branch/main/$NAME" || \
fetch gitea "$CA" "https://gitea.com/igareck/vpn-configs-for-russia/raw/branch/main/$NAME" || \
fetch bitbucket "$CA" "https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/$NAME" || \
fetch github-web "$CA" "https://github.com/igareck/vpn-configs-for-russia/raw/refs/heads/main/$NAME" || true

if [ -n "$SOURCE" ]; then
    cp "$TEMP" "$CACHE/$NAME.new" || exit 5
    chmod 600 "$CACHE/$NAME.new"
    mv "$CACHE/$NAME.new" "$CACHE/$NAME"
    cp "$CACHE/$NAME" "$CACHE/$NAME.last-good.new" || exit 5
    mv "$CACHE/$NAME.last-good.new" "$CACHE/$NAME.last-good"
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') source=$SOURCE bytes=$(wc -c < "$CACHE/$NAME")" >>"$LOG"
elif [ -s "$CACHE/$NAME.last-good" ]; then
    cp "$CACHE/$NAME.last-good" "$CACHE/$NAME"
    SOURCE=last-good
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') source=last-good" >>"$LOG"
else
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') update_failed_no_cache" >>"$LOG"
    exit 6
fi

RANK_INPUT=$CACHE/$NAME
if [ -s "$CRUNCH_URL_FILE" ]; then
    CRUNCH_URL=$(sed -n '1p' "$CRUNCH_URL_FILE" 2>/dev/null)
    case "$CRUNCH_URL" in
        https://crunch-crunch.com/sub/*)
            if fetch_crunch "$CRUNCH_URL"; then
                cp "$TEMP_BASE.crunch" "$CACHE/$CRUNCH_NAME.new" || exit 7
                chmod 600 "$CACHE/$CRUNCH_NAME.new"
                mv "$CACHE/$CRUNCH_NAME.new" "$CACHE/$CRUNCH_NAME"
                cp "$CACHE/$CRUNCH_NAME" "$CACHE/$CRUNCH_NAME.last-good.new" || exit 7
                mv "$CACHE/$CRUNCH_NAME.last-good.new" "$CACHE/$CRUNCH_NAME.last-good"
                echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') crunch_source=online bytes=$(wc -c < "$CACHE/$CRUNCH_NAME")" >>"$LOG"
            elif [ -s "$CACHE/$CRUNCH_NAME.last-good" ]; then
                cp "$CACHE/$CRUNCH_NAME.last-good" "$CACHE/$CRUNCH_NAME"
                echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') crunch_source=last-good" >>"$LOG"
            fi
            ;;
    esac
fi

if [ -s "$CRUNCH_URL_FILE" ] && [ -s "$CACHE/$CRUNCH_NAME" ] && \
   "$ROOT/bin/parse-crunch-json.sh" "$CACHE/$CRUNCH_NAME" "$TEMP_BASE.crunch.vless" >>"$LOG" 2>&1 && \
   [ -s "$TEMP_BASE.crunch.vless" ]; then
    {
        cat "$TEMP_BASE.crunch.vless"
        cat "$CACHE/$NAME"
    } >"$TEMP_BASE.merged" || exit 7
    RANK_INPUT=$TEMP_BASE.merged
fi

"$ROOT/bin/rank-nodes.sh" "$RANK_INPUT"
rm -f "$STATE/youtube-results.tsv" "$STATE/youtube-best.id" "$STATE/youtube-progress"

# The additional feed is cached for the next protocol modules. A failure here
# must not invalidate a working VLESS update.
EXTRA_TEMP="$TEMP_BASE.extra"
TEMP="$EXTRA_TEMP"
SOURCE=
VALID_PATTERN='^trojan://'
fetch github-raw "$CA" "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/$EXTRA_NAME" || \
fetch gitlab "$LEGACY_CA" "https://gitlab.com/igareck/vpn-configs-for-russia/-/raw/main/$EXTRA_NAME" || \
fetch codeberg "$CA" "https://codeberg.org/igareck/vpn-configs-for-russia/raw/branch/main/$EXTRA_NAME" || \
fetch gitea "$CA" "https://gitea.com/igareck/vpn-configs-for-russia/raw/branch/main/$EXTRA_NAME" || \
fetch bitbucket "$CA" "https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/$EXTRA_NAME" || \
fetch github-web "$CA" "https://github.com/igareck/vpn-configs-for-russia/raw/refs/heads/main/$EXTRA_NAME" || true
if [ -n "$SOURCE" ]; then
    cp "$EXTRA_TEMP" "$CACHE/$EXTRA_NAME.new" && chmod 600 "$CACHE/$EXTRA_NAME.new" && mv "$CACHE/$EXTRA_NAME.new" "$CACHE/$EXTRA_NAME"
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') extra_source=$SOURCE bytes=$(wc -c < "$CACHE/$EXTRA_NAME")" >>"$LOG"
fi
