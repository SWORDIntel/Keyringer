#!/bin/sh
# /init2 — the real keyringer test battery on the real Debian arm64 kernel.
# Same battery as the Alpine lane (test/a64vm/init2.sh), plus the two
# Debian-lane headline checks: the audit subsystem and a big_key roundtrip
# attempted FOR REAL (with honest evidence when the kernel cannot offer it).

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "VMTEST ok   - $1"; }
bad()  { FAIL=$((FAIL+1)); echo "VMTEST FAIL - $1"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (rc=$2 want=$3)"; fi; }
contains(){ case "$2" in *"$1"*) ok "$3";; *) bad "$3 (missing: $1)";; esac; }

echo "===A64DEB-BEGIN==="
echo "VMTEST kernel: $(uname -r) $(uname -m)"
sysctl -w debug.exception-trace=1; echo "exception-trace=$(cat /proc/sys/debug/exception-trace 2>/dev/null)"
sysctl -w kernel.print-fatal-signals=1 >/dev/null 2>&1

# ---- AUDIT CHECK (the reason this lane exists: Debian builds it in) ----
# Two honest empirical notes about this kernel generation (6.12, also this
# dev box's 7.x PVE kernel):
#  * a default boot (no audit= param) records "state=initialized
#    audit_enabled=0" — the subsystem initializes DISABLED, so this lane
#    boots with audit=1 on the cmdline;
#  * /proc/sys/kernel/audit_enabled is NOT registered — the audit sysctls
#    are absent from the default table and userspace drives the subsystem
#    over the audit netlink. The kernel's boot-time init record in dmesg is
#    the state channel; the battery asserts on it.
aud=$(cat /proc/sys/kernel/audit_enabled 2>/dev/null)
echo "VMTEST /proc/sys/kernel/audit_enabled=${aud:-<absent on this kernel>}"
echo "VMTEST Debian config: $(grep -E '^CONFIG_AUDIT(=y|SYSCALL=y)' /kernel-config 2>/dev/null | tr '\n' ' ')"
contains "audit=1" "$(cat /proc/cmdline 2>/dev/null)" "kernel cmdline carries audit=1"
dmesg 2>/dev/null | grep -E "audit: (initializing netlink subsys|type=2000)" | head -2 | sed 's/^/   /'
if dmesg 2>/dev/null | grep -q "audit: initializing netlink subsys (enabled)"; then
    ok "audit subsystem initialized ENABLED (CONFIG_AUDIT=y, cmdline audit=1)"
else
    bad "audit subsystem not enabled (see dmesg lines above)"
fi
if dmesg 2>/dev/null | grep -q "state=initialized audit_enabled=1 res=1"; then
    ok "audit boot record: type=2000 state=initialized audit_enabled=1"
else
    bad "no type=2000 audit_enabled=1 init record in dmesg"
fi
if [ -n "$aud" ]; then
    check "audit_enabled sysctl (present on this kernel) reads 1" "$aud" 1
fi

# ---- AF_ALG evidence: the overlaid modules really registered ----
# Base algorithms are registered at module-load time and persist; template
# instances (rfc7530(...)) are created per-tfm and torn down when the last
# user closes its socket — so the rfc7530 count is printed as evidence but
# the authoritative bind proof is the selftest's RFC 8439 KAT below, which
# runs through the real kernel AF_ALG ("aead","rfc7530(chacha20,poly1305)")
# and would fail if the modules had not registered.
echo "VMTEST /proc/crypto rfc7530 instances right after selftest: $(grep -c '^name *: rfc7530' /proc/crypto 2>/dev/null || echo 0)"
contains "sha256" "$(cat /proc/crypto 2>/dev/null)" "sha256 registered in /proc/crypto"
contains "chacha20" "$(cat /proc/crypto 2>/dev/null)" "chacha20 registered in /proc/crypto (chacha_generic/chacha_neon)"
contains "poly1305" "$(cat /proc/crypto 2>/dev/null)" "poly1305 registered in /proc/crypto (poly1305_generic/poly1305_neon)"

/keyringer selftest > /tmp/st.log 2>&1
check "selftest (crypto, wire-v2, VMA probe)" "$?" 0
contains "selftest: ok" "$(cat /tmp/st.log)" "selftest ok line"

/keyringer preflight > /tmp/pf.log 2>&1
check "preflight (9 checks)" "$?" 0
# the explicit AF_ALG bind evidence line
contains "afalg" "$(cat /tmp/pf.log)" "preflight afalg bind line present"
contains "rfc7539" "$(cat /tmp/pf.log)" "preflight AF_ALG aead bind (rfc7539) reported"
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

# big_key type — the Alpine lane documents a SKIP; here it is TRIED for real
# first (modprobe in /init, roundtrip below). Debian's 6.12 arm64 kernel
# cannot offer it: v6.12 BIG_KEYS depends on CRYPTO_LIB_CHACHA20POLY1305=y
# and Debian builds that as a module (=m), so the symbol is not even offered
# in the config and no big_key.ko exists to load. ENODEV is the kernel
# telling the truth; we record it and move on (x86 suite covers big_key).
/keyringer stash --type big_key --desc bkdv - </payload >/dev/null 2>/tmp/big.err
brc=$?
if [ "$brc" = 0 ]; then
    ok "big_key stash accepted (kernel registers the big_key type)"
    out=$(/keyringer exec --raw --desc bkdv bkdv 2>/dev/null)
    check "big_key roundtrip (exec lookup found the chunk without --type)" "$?" 0
    contains "raw ok" "$out" "big_key payload output correct"
elif grep -q "No such device" /tmp/big.err 2>/dev/null; then
    ok "big_key SKIP (Debian $(uname -r) registers no big_key type:"
    echo "        v6.12 BIG_KEYS needs CRYPTO_LIB_CHACHA20POLY1305=y, Debian builds it =m;"
    echo "        $(grep -c CONFIG_BIG_KEYS /kernel-config 2>/dev/null) CONFIG_BIG_KEYS line(s) in /kernel-config;"
    echo "        no big_key.ko in the linux-image deb; covered by the x86 suite)"
    sed 's/^/        /' /tmp/big.err
else
    bad "kfile --type big_key stash+exec (rc=$brc)"
    sed 's/^/        /' /tmp/big.err
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

echo "===A64DEB-SUMMARY==="
echo "VMTEST pass=$PASS fail=$FAIL"
echo "===A64DEB-END==="

echo "--- final dmesg tail:"; dmesg 2>/dev/null | tail -6
sync
poweroff -f
sleep 5
echo o > /proc/sysrq-trigger
while :; do sleep 1; done
