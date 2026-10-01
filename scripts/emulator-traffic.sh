#!/usr/bin/env bash
#
# Drives real network traffic through Heimdall's VPN on a rooted emulator and prints what
# Heimdall recorded for it. Meant for checking core:vpn changes against live traffic without
# retyping the same adb commands every time.
#
# Usage:
#   scripts/emulator-traffic.sh run [--install] [GROUP...]   start VPN, send traffic, report, stop VPN
#   scripts/emulator-traffic.sh install                      install app/build/outputs/apk/debug/app-debug.apk
#   scripts/emulator-traffic.sh vpn-start | vpn-stop
#   scripts/emulator-traffic.sh traffic [GROUP...]           send traffic (VPN must be running)
#   scripts/emulator-traffic.sh report                       pull the database, summarise the latest session
#
# Traffic groups (default: all of them, in this order):
#   dns    plain DNS queries over UDP/53 to 8.8.8.8, which also fill Heimdall's DNS cache
#   http   plaintext HTTP/1.1 requests over TCP/80, including a pipelined HEAD + GET and a
#          request with a TCP half-close
#   raw    non-HTTP bytes over TCP, and an NTP query over UDP/123
#   tls    TLS ClientHellos with chosen SNI/ALPN, replayed from the emulator's shell (see below)
#   apps   launches real apps (Play Store, YouTube) for full TLS handshakes, HTTP/2 and QUIC
#
# The "tls" group: the emulator has no TLS client in its shell, so each ClientHello is generated
# on this machine with `openssl s_client`, pushed, and sent with netcat to the real server. Only
# the ClientHello is real; the handshake is never completed. With MitM on, Heimdall answers with
# its forged ServerHello (the "bytes back"), then sees the client give up mid-handshake and
# learns passthrough for (shell, host) for the rest of the VPN session. Cases:
#   tracker       SNI of a listed tracker host, ALPN h2,http/1.1       -> tracker label from the SNI
#   early-alert   ClientHello followed at once by a close_notify alert   -> no reply, clean close
#   no-alpn       SNI, no ALPN extension
#   no-sni        no server_name extension
#   tls12         TLS 1.2-only ClientHello (no supported_versions)
#   dns-mismatch  sent to an address whose DNS-cache name differs from the SNI -> SNI replaces it
#
# Environment:
#   ANDROID_SERIAL          device to use. Default: the only running emulator.
#   HEIMDALL_ALLOW_DEVICE=1 allow a serial that is not an emulator (the script starts and stops
#                           the VPN and force-stops apps, so this is off by default).
#   HEIMDALL_APPS           space-separated packages for the "apps" group.
#   HEIMDALL_APP_WAIT       seconds to let each app generate traffic (default 25).
#   HEIMDALL_HOLD_OPEN      seconds the shell-driven TCP clients keep their sending side open
#                           after writing (default 4). 0 turns every request of the "http"
#                           and "raw" groups into a half-close.
#
# Requirements: adb, openssl, nc, sqlite3 and python3 on this machine; a rooted emulator (`su`)
# with Heimdall installed and VPN consent already granted once through the UI.

set -u

PKG="de.tomcory.heimdall"
SERVICE="$PKG/.service.HeimdallVpnService"
ACTIVITY="$PKG/.ui.main.MainActivity"
VPN_ACTION_EXTRA="de.tomcory.heimdall.net.vpn.ACTION_START"
DEVICE_TMP="/data/local/tmp/heimdall-traffic"
ALL_GROUPS="dns http raw tls apps"

TRACKER_HOST="googleads.g.doubleclick.net"
HTTP_HOSTS="example.com connectivitycheck.gstatic.com"
TLS_HOST="www.wikipedia.org"
# served from the same addresses and certificate as $TLS_HOST
EARLY_ALERT_HOST="en.wikipedia.org"
MISMATCH_DNS_HOST="example.org"
APPS="${HEIMDALL_APPS:-com.android.vending com.google.android.youtube}"
APP_WAIT="${HEIMDALL_APP_WAIT:-25}"
# Seconds the shell-driven TCP clients keep their sending side open after writing, the way an
# ordinary client does while it waits for the response. The "http" group additionally sends one
# request that closes its sending side at once (a TCP half-close, docs/vpn-mitm-audit.md PKT-30).
HOLD_OPEN="${HEIMDALL_HOLD_OPEN:-4}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APK="$REPO_ROOT/app/build/outputs/apk/debug/app-debug.apk"

if ! command -v adb >/dev/null 2>&1 && [ -x "$HOME/Library/Android/sdk/platform-tools/adb" ]; then
    PATH="$PATH:$HOME/Library/Android/sdk/platform-tools"
fi

say()  { printf '\n== %s\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

need() {
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 || die "'$tool' not found on this machine"
    done
}

pick_device() {
    if [ -z "${ANDROID_SERIAL:-}" ]; then
        local emulators
        emulators="$(adb devices | awk '$2 == "device" && $1 ~ /^emulator-/ { print $1 }')"
        [ -n "$emulators" ] || die "no running emulator found; start one or set ANDROID_SERIAL"
        [ "$(printf '%s\n' "$emulators" | wc -l | tr -d ' ')" = "1" ] \
            || die "several emulators are running; set ANDROID_SERIAL to one of: $(echo $emulators)"
        ANDROID_SERIAL="$emulators"
    fi
    export ANDROID_SERIAL
    case "$ANDROID_SERIAL" in
        emulator-*) ;;
        *) [ "${HEIMDALL_ALLOW_DEVICE:-0}" = "1" ] \
               || die "$ANDROID_SERIAL is not an emulator; set HEIMDALL_ALLOW_DEVICE=1 to use it anyway" ;;
    esac
    [ "$(adb get-state 2>/dev/null)" = "device" ] || die "$ANDROID_SERIAL is not online"
    adb shell 'su -c id' 2>/dev/null | grep -q 'uid=0' || die "$ANDROID_SERIAL is not rooted (su failed)"
    info "device: $ANDROID_SERIAL ($(adb emu avd name 2>/dev/null | head -1 | tr -d '\r'), API $(adb shell getprop ro.build.version.sdk | tr -d '\r'))"
}

root() { adb shell "su -c '$*'"; }

vpn_is_up() { adb shell ip addr show tun0 2>/dev/null | grep -q 'UP'; }

# --- commands -----------------------------------------------------------------------------------

cmd_install() {
    [ -f "$APK" ] || die "$APK not found; run ./gradlew assembleDebug first"
    say "Installing $(basename "$APK")"
    adb install -r "$APK" | tail -1
}

cmd_vpn_start() {
    say "Starting the VPN"
    adb shell pm path "$PKG" >/dev/null 2>&1 || die "$PKG is not installed"
    adb shell appops get "$PKG" ACTIVATE_VPN | grep -q 'allow' \
        || die "VPN consent has not been granted; start the VPN once from Heimdall's UI"
    if vpn_is_up; then
        info "already running"
        return
    fi
    local since
    since="$(adb shell "date +'%m-%d %H:%M:%S.000'" | tr -d '\r')"
    # the service needs the app process (Hilt) to be up before it is started
    adb shell am start -n "$ACTIVITY" >/dev/null 2>&1
    sleep 4
    root "am start-foreground-service -n $SERVICE" >/dev/null
    local waited=0
    until vpn_is_up; do
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 25 ] || die "tun0 did not come up within 25s; check 'adb logcat -s HeimdallVpnService'"
    done
    # the tracker list and traffic handlers are initialised after the interface is established
    sleep 3
    info "tun0 is up; $(adb logcat -d -T "$since" -s HeimdallVpnService 2>/dev/null | grep -o 'MitM mode: [a-z]*' | tail -1)"
    adb shell input keyevent KEYCODE_HOME
}

cmd_vpn_stop() {
    say "Stopping the VPN"
    if ! vpn_is_up; then
        info "not running"
        return
    fi
    root "am start-foreground-service -n $SERVICE --ei $VPN_ACTION_EXTRA 1" >/dev/null
    local waited=0
    while vpn_is_up; do
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 15 ] || { info "tun0 is still up after 15s"; return; }
    done
    info "stopped"
}

resolve() {
    python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$1" 2>/dev/null
}

# Sends a DNS A query for $1 to 8.8.8.8 over UDP from the emulator's shell.
dns_query() {
    local host="$1" qname="" label
    local IFS='.'
    for label in $host; do
        qname="$qname$(printf '\\x%02x' "${#label}")$label"
    done
    unset IFS
    # header: id 0x4844, recursion desired, one question; question: name, type A, class IN
    adb shell "printf '\\x48\\x44\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00${qname}\\x00\\x00\\x01\\x00\\x01' | timeout 5 nc -u -w 3 -q 2 8.8.8.8 53 | wc -c" \
        | tr -d '\r' | { read -r bytes; info "A $host -> ${bytes:-0} byte answer"; }
}

group_dns() {
    say "dns: plain DNS over UDP/53"
    local host
    for host in $HTTP_HOSTS $TLS_HOST $MISMATCH_DNS_HOST $TRACKER_HOST; do
        dns_query "$host"
    done
}

group_http() {
    say "http: plaintext HTTP over TCP/80"
    local host
    for host in $HTTP_HOSTS; do
        adb shell "{ printf 'GET / HTTP/1.1\\r\\nHost: $host\\r\\nUser-Agent: heimdall-traffic\\r\\nConnection: close\\r\\n\\r\\n'; sleep $HOLD_OPEN; } | timeout 12 nc -w 5 -q 3 $host 80 | head -1" \
            | tr -d '\r' | { read -r status; info "GET http://$host/ -> ${status:-no response}"; }
    done
    # A HEAD and a GET pipelined on one connection. The HEAD response states a Content-Length
    # but has no body (docs/vpn-mitm-audit.md PKT-33), so both responses must be recorded.
    host="${HTTP_HOSTS##* }"
    adb shell "{ printf 'HEAD /head HTTP/1.1\\r\\nHost: $host\\r\\nUser-Agent: heimdall-traffic\\r\\n\\r\\nGET /after-head HTTP/1.1\\r\\nHost: $host\\r\\nUser-Agent: heimdall-traffic\\r\\nConnection: close\\r\\n\\r\\n'; sleep $HOLD_OPEN; } | timeout 12 nc -w 5 -q 3 $host 80 | grep -c '^HTTP/1.1 '" \
        | tr -d '\r' | { read -r count; info "HEAD http://$host/head + GET /after-head on one connection -> ${count:-0} responses"; }
    # the client sends FIN right after the request and only then reads the response
    host="${HTTP_HOSTS##* }"
    adb shell "printf 'GET /half-close HTTP/1.1\\r\\nHost: $host\\r\\nUser-Agent: heimdall-traffic\\r\\nConnection: close\\r\\n\\r\\n' | timeout 12 nc -w 5 -q 8 $host 80 | head -1" \
        | tr -d '\r' | { read -r status; info "GET http://$host/half-close with half-close -> ${status:-no response}"; }
}

group_raw() {
    say "raw: non-HTTP TCP and non-DNS UDP"
    adb shell "{ printf '\\x00\\x01\\x02\\xff\\xde\\xad\\xbe\\xef heimdall-traffic raw'; sleep $HOLD_OPEN; } | timeout 12 nc -w 5 -q 3 example.com 80 >/dev/null 2>&1"
    info "8 binary bytes + text to example.com:80"
    # NTP client request: LI 0, version 3, mode 3, then 47 zero bytes
    adb shell "{ printf '\\x1b'; head -c 47 /dev/zero; } | timeout 6 nc -u -w 3 -q 2 time.google.com 123 | wc -c" \
        | tr -d '\r' | { read -r bytes; info "NTP query to time.google.com:123 -> ${bytes:-0} byte answer"; }
}

# Captures the ClientHello that `openssl s_client $2...` produces into file $1.
make_client_hello() {
    local out="$1"; shift
    local port=$((47000 + RANDOM % 2000))
    nc -l 127.0.0.1 "$port" > "$out" 2>/dev/null &
    local listener=$!
    sleep 0.5
    (sleep 2 | openssl s_client -connect "127.0.0.1:$port" "$@" >/dev/null 2>&1) &
    local client=$!
    sleep 1.5
    kill "$client" "$listener" 2>/dev/null
    wait "$client" "$listener" 2>/dev/null
    [ -s "$out" ] || return 1
    # keep only the first TLS record: openssl may append a close_notify alert when it exits,
    # depending on timing. The early-alert case adds one deliberately instead.
    local high low
    high="$(od -An -tu1 -j3 -N1 "$out" | tr -d ' ')"
    low="$(od -An -tu1 -j4 -N1 "$out" | tr -d ' ')"
    [ -n "$high" ] && [ -n "$low" ] || return 1
    head -c $((5 + high * 256 + low)) "$out" > "$out.record" && mv "$out.record" "$out"
}

# $1 case name, $2 address to send to, remaining: openssl s_client options
tls_case() {
    local name="$1" address="$2"; shift 2
    local file="$WORK/$name.bin"
    if ! make_client_hello "$file" "$@"; then
        info "$name: could not generate a ClientHello, skipped"
        return
    fi
    if [ "$name" = "early-alert" ]; then
        # a close_notify alert right behind the ClientHello (docs/vpn-mitm-audit.md PKT-31)
        printf '\x15\x03\x03\x00\x02\x01\x00' >> "$file"
    fi
    adb push "$file" "$DEVICE_TMP/$name.bin" >/dev/null 2>&1
    adb shell "{ cat $DEVICE_TMP/$name.bin; sleep $HOLD_OPEN; } | timeout 12 nc -w 5 $address 443 | wc -c" \
        | tr -d '\r' | { read -r bytes; info "$name: $(wc -c < "$file" | tr -d ' ') byte ClientHello to $address:443 -> ${bytes:-0} bytes back"; }
}

group_tls() {
    say "tls: replayed ClientHellos (handshake is not completed)"
    need openssl nc python3
    adb shell "mkdir -p $DEVICE_TMP"
    local tracker_ip tls_ip mismatch_ip
    tracker_ip="$(resolve "$TRACKER_HOST")"
    tls_ip="$(resolve "$TLS_HOST")"
    mismatch_ip="$(resolve "$MISMATCH_DNS_HOST")"
    [ -n "$tracker_ip" ] && [ -n "$tls_ip" ] && [ -n "$mismatch_ip" ] || die "could not resolve the test hosts on this machine"

    tls_case tracker      "$tracker_ip"  -servername "$TRACKER_HOST" -alpn h2,http/1.1
    # its own host name, so no passthrough has been learned for it and the MitM path is taken
    tls_case early-alert  "$tls_ip"      -servername "$EARLY_ALERT_HOST" -alpn http/1.1
    tls_case no-alpn      "$tls_ip"      -servername "$TLS_HOST"
    tls_case no-sni       "$tls_ip"      -noservername
    tls_case tls12        "$tls_ip"      -servername "$TLS_HOST" -tls1_2 -alpn http/1.1
    # the address is in Heimdall's DNS cache as $MISMATCH_DNS_HOST only if the dns group ran
    # first and returned this same address
    tls_case dns-mismatch "$mismatch_ip" -servername "sni-differs.$MISMATCH_DNS_HOST" -alpn h2

    adb shell "rm -rf $DEVICE_TMP"
}

group_apps() {
    say "apps: real apps (full TLS handshakes, HTTP/2, QUIC)"
    local app
    for app in $APPS; do
        if ! adb shell pm path "$app" >/dev/null 2>&1; then
            info "$app is not installed, skipped"
            continue
        fi
        adb shell am force-stop "$app"
        adb shell monkey -p "$app" 1 >/dev/null 2>&1
        info "launched $app, waiting ${APP_WAIT}s"
        sleep $((APP_WAIT / 2))
        # a second screen makes the app fetch more than its start page
        case "$app" in
            com.android.vending)
                adb shell "am start -a android.intent.action.VIEW -d 'market://search?q=weather' -p $app" >/dev/null 2>&1 ;;
            com.google.android.youtube)
                adb shell "am start -a android.intent.action.VIEW -d 'https://www.youtube.com/results?search_query=heimdall' -p $app" >/dev/null 2>&1 ;;
        esac
        sleep $((APP_WAIT - APP_WAIT / 2))
        adb shell am force-stop "$app"
    done
    adb shell input keyevent KEYCODE_HOME
}

cmd_traffic() {
    vpn_is_up || die "the VPN is not running; use 'vpn-start' or 'run'"
    local groups="${*:-$ALL_GROUPS}" group
    for group in $groups; do
        case "$group" in
            dns|http|raw|tls|apps) "group_$group" ;;
            *) die "unknown traffic group '$group' (known: $ALL_GROUPS)" ;;
        esac
    done
    # database writes are asynchronous
    sleep 3
}

cmd_report() {
    need sqlite3
    say "Report"
    local remote="/sdcard/heimdall-traffic-db"
    root "rm -rf $remote; mkdir -p $remote && cp /data/data/$PKG/databases/heimdall* $remote/" \
        || die "could not copy the database"
    adb pull "$remote/." "$WORK/db" >/dev/null 2>&1 || die "could not pull the database"
    adb shell rm -rf "$remote"
    local db="$WORK/db/heimdall"
    [ -f "$db" ] || die "database not found after pull"

    local session
    session="$(sqlite3 "$db" 'select max(id) from Session')"
    info "database: $db (schema v$(sqlite3 "$db" 'pragma user_version'), session $session)"

    say "Connections by transport and security"
    sqlite3 -header -column "$db" "
        select protocol, coalesce(securityProtocol, '(none)') security, count(*) n,
               sum(remoteHost is not null and remoteHost != '') with_host,
               sum(sni is not null) with_sni, sum(alpn is not null) with_alpn,
               sum(echOffered) ech, sum(isTracker) trackers, sum(blocked) blocked
        from Connection where sessionId = $session group by 1, 2 order by 1, 2;"

    say "TLS and QUIC connections"
    sqlite3 -header -column "$db" "
        select initiatorPkg app, securityProtocol sec, remotePort port,
               coalesce(remoteHost, '-') host, coalesce(sni, '-') sni, coalesce(alpn, '-') alpn,
               echOffered ech, isTracker trk, blocked blk, count(*) n
        from Connection where sessionId = $session and securityProtocol in ('TLS', 'QUIC')
        group by 1, 2, 3, 4, 5, 6, 7, 8, 9 order by 2, 1, 4;"

    say "Other connections"
    sqlite3 -header -column "$db" "
        select initiatorPkg app, protocol, coalesce(securityProtocol, '(none)') sec, remoteIp,
               remotePort port, coalesce(remoteHost, '-') host, bytesOut, bytesIn
        from Connection where sessionId = $session and (securityProtocol is null or securityProtocol = 'PLAIN')
        order by id;"

    say "Decrypted or plaintext HTTP requests"
    sqlite3 -header -column "$db" "
        select r.method, coalesce(nullif(r.remoteHost, ''), '-') host, substr(r.remotePath, 1, 50) path,
               (select statusCode from Response where requestId = r.id limit 1) status, c.securityProtocol via
        from Request r join Connection c on c.id = r.connectionId
        where c.sessionId = $session order by r.id limit 30;"

    say "Checks"
    local mismatches crashes
    mismatches="$(sqlite3 "$db" "select count(*) from Connection where sessionId = $session
        and sni is not null and echOffered = 0 and remoteHost is not lower(sni)")"
    info "connections whose hostname differs from their SNI (ECH not offered): $mismatches (expected 0)"
    crashes="$(adb logcat -d 2>/dev/null | grep -c "FATAL EXCEPTION.*\|Process: $PKG")"
    info "Heimdall crash lines in logcat: $crashes (expected 0)"
    info "Heimdall process: $(adb shell pidof "$PKG" | tr -d '\r' | sed 's/^$/not running/')"
}

# --- main ---------------------------------------------------------------------------------------

[ $# -ge 1 ] || { sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
command="$1"; shift

need adb
WORK="$(mktemp -d "${TMPDIR:-/tmp}/heimdall-traffic.XXXXXX")"
say "Heimdall emulator traffic test"
pick_device

case "$command" in
    install)   cmd_install ;;
    vpn-start) cmd_vpn_start ;;
    vpn-stop)  cmd_vpn_stop ;;
    traffic)   cmd_traffic "$@" ;;
    report)    cmd_report ;;
    run)
        if [ "${1:-}" = "--install" ]; then
            shift
            cmd_install
        fi
        cmd_vpn_start
        cmd_traffic "$@"
        cmd_report
        cmd_vpn_stop
        ;;
    *) die "unknown command '$command' (install, vpn-start, vpn-stop, traffic, report, run)" ;;
esac
