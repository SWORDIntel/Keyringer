#!/bin/bash
# kr_fuzz_serve.sh — supervisor helper for the vr-fuzz keyringer target.
#   kr_fuzz_serve.sh start [port]   build if needed, start, write pid file
#   kr_fuzz_serve.sh stop           kill a running server
# The vr-fuzz supervisor (kind: external) calls this as restart_cmd.
set -e
cd "$(dirname "$0")/.."
PID_FILE="${KR_FUZZ_PID_FILE:-/tmp/keyringer-vrf.pid}"
PORT="${KR_FUZZ_PORT:-12871}"

case "${1:-start}" in
start)
    [ -x test/kr_fuzz_server ] || gcc -Wall -O2 -std=c11 \
        -o test/kr_fuzz_server test/kr_fuzz_server.c kr_core.c
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        exit 0                       # already up; vr-fuzz just needs it alive
    fi
    setsid nohup ./test/kr_fuzz_server "$PORT" >> /tmp/kr_fuzz_server.log \
        2>&1 < /dev/null &
    echo $! > "$PID_FILE"
    sleep 0.3
    ;;
stop)
    [ -f "$PID_FILE" ] && kill "$(cat "$PID_FILE")" 2>/dev/null || true
    rm -f "$PID_FILE"
    ;;
esac
