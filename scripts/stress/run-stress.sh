#!/usr/bin/env bash
#
# Stress-tests Heimdall's VPN on a rooted emulator with real traffic and reports what broke.
#
# Usage:
#   scripts/stress/run-stress.sh [--baseline] [TEST[,TEST...]]
#
# Builds StressClient.java into a dex file, pushes it to the emulator and runs it from the adb
# shell (app_process), so its traffic passes through the VPN like an app's. Plain HTTP, TCP and
# UDP tests go to stress_server.py, which this script starts on this machine (the emulator
# reaches it as 10.0.2.2). TLS tests go to public HTTPS servers.
#
#   --baseline   run with the VPN stopped. Use it to tell a failing test from a failing VPN:
#                whatever fails here is the test's or the network's fault.
#
# Tests (default: all): download upload keepalive parallel churn slowserver slowclient
#   slowupload idle serverabort clientabort unreachable duplex udp tls tlsbulk tlsclose tlsparallel
# Not in the default set: bigbody (a 300 MB download, which takes a while and a lot of memory)
#
# Around the run it records Heimdall's open file descriptors, threads and memory, and afterwards
# summarises warnings and errors from logcat. Requirements: as for emulator-traffic.sh, plus a
# JDK (javac) and the Android SDK build tools (d8).

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TRAFFIC="$HERE/../emulator-traffic.sh"
PKG="de.tomcory.heimdall"
BASE_PORT="${HEIMDALL_STRESS_PORT:-18080}"
DEVICE_DEX="/data/local/tmp/heimdall-stress.dex"
ALL_TESTS="download,upload,keepalive,parallel,churn,slowserver,slowclient,slowupload,idle,serverabort,clientabort,unreachable,duplex,udp,tls,tlsbulk,tlsclose,tlsparallel"
SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"

if ! command -v adb >/dev/null 2>&1; then PATH="$PATH:$SDK/platform-tools"; fi

say()  { printf '\n== %s\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

baseline=0
if [ "${1:-}" = "--baseline" ]; then baseline=1; shift; fi
tests="${1:-$ALL_TESTS}"

if [ -z "${ANDROID_SERIAL:-}" ]; then
    ANDROID_SERIAL="$(adb devices | awk '$2 == "device" && $1 ~ /^emulator-/ { print $1 }' | head -1)"
    [ -n "$ANDROID_SERIAL" ] || die "no running emulator found"
fi
export ANDROID_SERIAL
case "$ANDROID_SERIAL" in emulator-*) ;; *) die "$ANDROID_SERIAL is not an emulator" ;; esac

WORK="$(mktemp -d "${TMPDIR:-/tmp}/heimdall-stress.XXXXXX")"

build_client() {
    say "Building the stress client"
    local d8
    d8="$(ls "$SDK"/build-tools/*/d8 2>/dev/null | sort | tail -1)"
    [ -x "$d8" ] || die "d8 not found under $SDK/build-tools"
    javac --release 8 -Xlint:-options -d "$WORK/classes" "$HERE/StressClient.java" || die "javac failed"
    "$d8" --min-api 26 --output "$WORK" "$WORK"/classes/*.class || die "d8 failed"
    adb push "$WORK/classes.dex" "$DEVICE_DEX" >/dev/null || die "could not push the dex file"
    info "pushed $(wc -c < "$WORK/classes.dex" | tr -d ' ') bytes to $DEVICE_DEX"
}

server_pid=""
start_server() {
    if nc -z 127.0.0.1 "$BASE_PORT" 2>/dev/null; then
        info "stress servers already listening on port $BASE_PORT"
        return
    fi
    python3 "$HERE/stress_server.py" "$BASE_PORT" > "$WORK/server.log" 2>&1 &
    server_pid=$!
    sleep 1
    nc -z 127.0.0.1 "$BASE_PORT" 2>/dev/null || die "stress servers did not start (see $WORK/server.log)"
    info "stress servers started (pid $server_pid)"
}

cleanup() {
    [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null
}
trap cleanup EXIT

# Prints "fds threads pss_kb" of the Heimdall process.
metrics() {
    local pid
    pid="$(adb shell pidof "$PKG" | tr -d '\r')"
    if [ -z "$pid" ]; then echo "- - -"; return; fi
    local fds threads pss
    fds="$(adb shell "su -c 'ls /proc/$pid/fd | wc -l'" | tr -d '\r')"
    threads="$(adb shell "su -c 'grep Threads /proc/$pid/status'" | awk '{print $2}' | tr -d '\r')"
    pss="$(adb shell dumpsys meminfo "$pid" | awk '/TOTAL PSS:/ {print $3; exit} /^ *TOTAL / {print $2; exit}' | tr -d '\r')"
    echo "$fds $threads $pss"
}

say "Heimdall VPN stress test (${tests})"
info "device: $ANDROID_SERIAL"
build_client
start_server

if [ "$baseline" = "1" ]; then
    "$TRAFFIC" vpn-stop | tail -1
    say "Running WITHOUT the VPN (baseline)"
else
    "$TRAFFIC" vpn-start | tail -1
    # without this check a VPN that failed to start gives a clean run that tested nothing
    adb shell ip addr show tun0 2>/dev/null | grep -q 'inet ' \
        || die "the VPN is not up; after a cold boot start it once from Heimdall's UI"
    adb logcat -c
    before="$(metrics)"
    say "Running through the VPN"
fi

adb shell "CLASSPATH=$DEVICE_DEX app_process / StressClient 10.0.2.2 $BASE_PORT $tests" 2>&1 | tr -d '\r' | tee "$WORK/client.log"

say "Summary"
info "checks passed: $(grep -c '^RESULT .* PASS' "$WORK/client.log")   failed: $(grep -c '^RESULT .* FAIL' "$WORK/client.log")"
grep '^RESULT .* FAIL' "$WORK/client.log" | sed 's/^RESULT /   FAIL /'

if [ "$baseline" = "0" ]; then
    # let closing connections settle before measuring what is left behind
    sleep 20
    after="$(metrics)"
    say "Heimdall process: file descriptors, threads, memory (PSS kB)"
    info "before: $before"
    info "after:  $after"
    crashes="$(adb logcat -d | grep -c 'FATAL EXCEPTION')"
    info "FATAL EXCEPTION lines in logcat: $crashes"

    say "Heimdall warnings and errors in logcat (grouped, most frequent first)"
    pid="$(adb shell pidof "$PKG" | tr -d '\r')"
    adb logcat -d | grep -E " +$pid +[0-9]+ [WE] " \
        | sed -E 's/^[0-9-]+ [0-9:.]+ +[0-9]+ +[0-9]+ ([WE]) /\1 /' \
        | sed -E 's/(tcp|udp|tls|http|quic|plain|raw|dns)[0-9]+/\1N/g; s/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?/ADDR/g; s/[0-9]+ bytes/N bytes/g; s/\b[0-9a-f]{16,}\b/HEX/g; s/[0-9]{3,}/N/g' \
        | cut -c1-200 | sort | uniq -c | sort -rn | head -40
    adb logcat -d > "$WORK/logcat.txt"
    info "full logcat: $WORK/logcat.txt   client output: $WORK/client.log"
fi
