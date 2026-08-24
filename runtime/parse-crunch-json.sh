#!/bin/sh

set -u

INPUT=${1:?JSON subscription path is required}
OUTPUT=${2:?VLESS output path is required}
WORK=/tmp/n300vpn-crunch.$$
OBJECTS=$WORK.objects
OBJECT=$WORK.object

cleanup() {
    rm -f "$OBJECTS" "$OBJECT"
}
trap cleanup EXIT INT TERM

jsonfilter -i "$INPUT" -e '@[*]' >"$OBJECTS" 2>/dev/null || exit 2
: >"$OUTPUT" || exit 2
index=0
total=0
compatible=0

while IFS= read -r json_object; do
    total=$((total + 1))
    printf '%s\n' "$json_object" >"$OBJECT" || exit 2
    protocol=$(jsonfilter -i "$OBJECT" -e '@.outbounds[0].protocol' 2>/dev/null)
    network=$(jsonfilter -i "$OBJECT" -e '@.outbounds[0].streamSettings.network' 2>/dev/null)
    security=$(jsonfilter -i "$OBJECT" -e '@.outbounds[0].streamSettings.security' 2>/dev/null)
    [ "$protocol" = vless ] || continue
    [ "$network" = tcp ] || continue
    [ "$security" = reality ] || continue

    server=$(jsonfilter -i "$OBJECT" -e '@.outbounds[0].settings.vnext[0].address' 2>/dev/null)
    port=$(jsonfilter -i "$OBJECT" -e '@.outbounds[0].settings.vnext[0].port' 2>/dev/null)
    uuid=$(jsonfilter -i "$OBJECT" -e '@.outbounds[0].settings.vnext[0].users[0].id' 2>/dev/null)
    encryption=$(jsonfilter -i "$OBJECT" -e '@.outbounds[0].settings.vnext[0].users[0].encryption' 2>/dev/null)
    flow=$(jsonfilter -i "$OBJECT" -e '@.outbounds[0].settings.vnext[0].users[0].flow' 2>/dev/null)
    sni=$(jsonfilter -i "$OBJECT" -e '@.outbounds[0].streamSettings.realitySettings.serverName' 2>/dev/null)
    public_key=$(jsonfilter -i "$OBJECT" -e '@.outbounds[0].streamSettings.realitySettings.publicKey' 2>/dev/null)
    short_id=$(jsonfilter -i "$OBJECT" -e '@.outbounds[0].streamSettings.realitySettings.shortId' 2>/dev/null)
    label=$(jsonfilter -i "$OBJECT" -e '@.remarks' 2>/dev/null)

    echo "$server" | grep -Eq '^[A-Za-z0-9._-]{1,255}$' || continue
    echo "$port" | grep -Eq '^[0-9]{1,5}$' || continue
    [ "$port" -ge 1 ] 2>/dev/null && [ "$port" -le 65535 ] 2>/dev/null || continue
    echo "$uuid" | grep -Eqi '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || continue
    [ "$encryption" = none ] || continue
    [ "$flow" = xtls-rprx-vision ] || continue
    echo "$sni" | grep -Eq '^[A-Za-z0-9._-]{1,255}$' || continue
    echo "$public_key" | grep -Eq '^[A-Za-z0-9_-]{40,44}$' || continue
    echo "$short_id" | grep -Eqi '^([0-9a-f][0-9a-f]){0,8}$' || continue

    index=$((index + 1))
    [ -n "$label" ] || label=$(printf 'Сервер подписки %02d' "$index")
    label=$(printf '%s' "$label" | tr '\t\r\n' '   ' | sed 's/%/%25/g; s/+/%2B/g')
    printf 'vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=%s&pbk=%s&sid=%s&n300source=crunch#%s\n' \
        "$uuid" "$server" "$port" "$sni" "$public_key" "$short_id" "$label" >>"$OUTPUT"
    compatible=$((compatible + 1))
done <"$OBJECTS"

echo "crunch_total=$total crunch_compatible=$compatible"
[ "$compatible" -gt 0 ]
