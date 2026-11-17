#!/bin/sh
# hunt_test.sh — purple-team harness: fire a controlled stash->exec and a
# keepalive run, and assert the bpftrace detector catches both signatures.
# Needs root (bpftrace). Skips cleanly when the environment can't run it.
set -e
cd "$(dirname "$0")/.."

SUDO=""
[ "$(id -u)" = 0 ] || SUDO=sudo
if ! command -v bpftrace >/dev/null 2>&1; then
    echo "SKIP: hunt-test needs bpftrace (not installed)"; exit 0
fi
if [ -n "$SUDO" ] && ! $SUDO -n true 2>/dev/null; then
    echo "SKIP: hunt-test needs root (bpftrace)"; exit 0
fi

LOG=$(mktemp /tmp/krhunt.XXXXXX.log)
BT="$SUDO timeout 30 bpftrace detections/kr_hunt.bt"
$BT > "$LOG" 2>&1 &
BTJOB=$!
sleep 10                     # let the probes attach (LLVM bootstrap)

# --- fire the offensive side (twice: attach latency tolerance) ---
./keyringer kfile test/hello purple >/dev/null 2>&1 || true
sleep 4
./keyringer kfile test/hello purple >/dev/null 2>&1 || true
./keyringer-dyn keepalive --interval 1 --times 2 >/dev/null 2>&1 || true
sleep 8
kill "$BTJOB" 2>/dev/null || true
wait "$BTJOB" 2>/dev/null || true

# --- assert the defensive side saw it ---
rc=0
# find the pid that did READ then REVOKE (the loader), correlate add_key + exec mapping
pid=$(grep -m1 'cmd=3 REVOKE' "$LOG" | sed 's/.*pid=\([0-9]*\).*/\1/')
reads=$(grep "pid=$pid " "$LOG" | grep -c 'cmd=11 READ' || true)
revokes=$(grep "pid=$pid " "$LOG" | grep -c 'cmd=3 REVOKE' || true)
addkeys=$(grep "pid=$pid" "$LOG" | grep -c "add_key " || true)
execmap=$(grep "pid=$pid " "$LOG" | grep -cE 'mmap\+X|mprot\+X' || true)
if [ "${reads:-0}" -ge 1 ] && [ "${revokes:-0}" -ge 1 ] \
   && [ "${addkeys:-0}" -ge 1 ] && [ "${execmap:-0}" -ge 1 ]; then
    echo "ok: stash->exec correlated on pid $pid (add_key=$addkeys READ=$reads REVOKE=$revokes exec-mapping=$execmap)"
else
    echo "FAIL: stash->exec pattern not correlated (pid=$pid add_key=$addkeys READ=$reads REVOKE=$revokes exec-mapping=$execmap)"
    rc=1
fi

gp=$(grep -c 'cmd=22 GET_PERSISTENT' "$LOG" || true)
se=$(grep -c 'cmd=10 SEARCH' "$LOG" || true)
if [ "${gp:-0}" -ge 1 ] && [ "${se:-0}" -ge 1 ]; then
    echo "ok: keepalive signature seen (GET_PERSISTENT=$gp SEARCH=$se)"
else
    echo "FAIL: keepalive signature not seen (GET_PERSISTENT=$gp SEARCH=$se)"
    rc=1
fi

if [ "$rc" = 0 ]; then echo "=== hunt-test passed ==="; else
    echo "--- raw detector output (first 40 lines):"; head -40 "$LOG"; fi
rm -f "$LOG"
exit "$rc"
