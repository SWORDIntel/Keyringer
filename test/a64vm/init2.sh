#!/bin/sh
# /init2 — the real keyringer test battery on the real arm64 kernel.

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "VMTEST ok   - $1"; }
bad()  { FAIL=$((FAIL+1)); echo "VMTEST FAIL - $1"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (rc=$2 want=$3)"; fi; }
contains(){ case "$2" in *"$1"*) ok "$3";; *) bad "$3 (missing: $1)";; esac; }

echo "===A64VM-BEGIN==="
echo "VMTEST kernel: $(uname -r) $(uname -m)"
sysctl -w debug.exception-trace=1; echo "exception-trace=$(cat /proc/sys/debug/exception-trace 2>/dev/null)"
sysctl -w kernel.print-fatal-signals=1 >/dev/null 2>&1

/keyringer selftest > /tmp/st.log 2>&1
check "selftest (crypto, wire-v2, VMA probe)" "$?" 0
contains "selftest: ok" "$(cat /tmp/st.log)" "selftest ok line"

/keyringer preflight > /tmp/pf.log 2>&1
check "preflight (9 checks)" "$?" 0
tail -3 /tmp/pf.log

# deferred stash + exec across processes (shared session keyring)
cat /payload | /keyringer stash - > /tmp/serials.log 2>&1
check "stash - (user keys, chunked)" "$?" 0
/keyringer list > /tmp/list.log 2>&1
contains "_keyringer" "$(cat /tmp/list.log)" "list shows stashed keys in /proc/keys"
out=$(/keyringer exec myspoof 2>/tmp/exec.err)
check "exec (userland exec, no execve)" "$?" 0
contains "keyringer ok" "$out" "payload output correct"
if [ "$FAIL" != "0" ] && [ -s /tmp/exec.err ]; then
    echo "--- exec stderr:"; cat /tmp/exec.err
    echo "--- /proc/keys:"; cat /proc/keys
    echo "--- dmesg tail:"; dmesg 2>/dev/null | tail -40
fi

# stdin delivery one-shot (stash+exec in-process: the path that segfaulted)
out=$(cat /payload | /keyringer kstdin 2>/tmp/kstdin.err)
rc=$?
check "kstdin stash+exec" "$rc" 0
contains "keyringer ok" "$out" "kstdin payload output correct"
if [ "$rc" != "0" ]; then
    echo "--- kstdin stderr:"; cat /tmp/kstdin.err 2>/dev/null
    echo "--- dmesg tail after kstdin:"; dmesg 2>/dev/null | tail -40
fi

# encrypted roundtrip + wrong-key rejection
KEY=$(/keyringer keygen)
case "$KEY" in
  [0-9a-f]*) ok "keygen (64 hex)";;
  *) bad "keygen output: $KEY";;
esac
cat /payload | /keyringer stash --key "$KEY" - > /dev/null 2>&1
check "stash --key (KR1 envelope)" "$?" 0
out=$(/keyringer exec --key "$KEY" myspoof2 2>/dev/null)
check "exec --key roundtrip" "$?" 0
contains "keyringer ok" "$out" "decrypted payload output correct"
/keyringer exec --key 0000000000000000000000000000000000000000000000000000000000000000 myspoof3 >/dev/null 2>&1
if [ "$?" -eq 0 ]; then bad "wrong-key exec must fail"; else ok "wrong-key exec rejected"; fi

# big_key type (root in initramfs; 100000-byte chunks)
out=$(/keyringer kfile --type big_key /payload 2>/tmp/big.err)
rc=$?
if [ "$rc" != "0" ] && grep -q "No such device" /tmp/big.err 2>/dev/null; then
    ok "big_key SKIP (alpine virt kernel lacks CONFIG_BIG_KEYS; x86 suite covers it)"
elif [ "$rc" = "0" ]; then
    contains "keyringer ok" "$out" "big_key payload output correct"
else
    bad "kfile --type big_key stash+exec (rc=$rc)"
    cat /tmp/big.err 2>/dev/null
fi

# --scrub: stash then consume with invalidation; no live keys may remain
/keyringer stash - </payload >/dev/null 2>&1
out=$(/keyringer exec --scrub vmscrub 2>/dev/null)
rc=$?
check "exec --scrub roundtrip" "$rc" 0
contains "keyringer ok" "$out" "scrub payload output correct"
if awk '$9 ~ /^_keyringer/ && $2 !~ /[Ri]/' /proc/keys | grep -q .; then
    bad "scrub left live keys"
else
    ok "scrub left no live keys in /proc/keys"
fi

# wire v3 + portability: the userspace crypto fallback must agree with the
# kernel AF_ALG path on the real arm64 kernel too
KR_CRYPTO=userspace /keyringer selftest >/dev/null 2>&1
check "selftest under userspace crypto (RFC KATs + fallback impl)" "$?" 0
K3=$(/keyringer keygen)
cat /payload | KR_CRYPTO=userspace /keyringer stash --key "$K3" - >/dev/null 2>&1
out=$(/keyringer exec --key "$K3" vmspace 2>/dev/null)
check "userspace-sealed stash opens under AF_ALG loader" "$?" 0
contains "keyringer ok" "$out" "cross-crypto payload output correct"

echo "===A64VM-SUMMARY==="
echo "VMTEST pass=$PASS fail=$FAIL"
echo "===A64VM-END==="

echo "--- final dmesg tail:"; dmesg 2>/dev/null | tail -6
sync
poweroff -f
sleep 5
echo o > /proc/sysrq-trigger
while :; do sleep 1; done
