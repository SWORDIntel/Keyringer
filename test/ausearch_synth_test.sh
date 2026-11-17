#!/usr/bin/env bash
# ausearch_synth_test.sh — exercise ausearch-hunt.sh's correlation logic
# WITHOUT kernel audit: a fake `ausearch` in PATH emits synthetic
# keyring_stash events (text format) covering the suspicious pattern
# (add_key + READ + REVOKE, no execve) and a benign pattern (same keyring
# churn + execve). The hunt script must flag only the suspicious PID.
set -e
cd "$(dirname "$0")/.."

command -v awk >/dev/null 2>&1 || { echo "SKIP: hunt synth needs awk"; exit 0; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
STASH_PID=$((10000 + RANDOM % 20000))
BENIGN_PID=$((STASH_PID + 1))

cat > "$TMP/ausearch" <<EOF
#!/bin/bash
# synthetic keyring_stash events, ausearch --format text style — fields
# arranged so pid is field 6, which is what the hunt script's awk keys on
cat <<'RECORDS'
----
type=SYSCALL msg=audit(1699000001.1) node=host success=yes syscall=add_key pid=$STASH_PID comm="keyringer" key="keyring_stash" a1="user" a2="_keyringer.000"
----
type=SYSCALL msg=audit(1699000002.1) node=host success=yes syscall=keyctl pid=$STASH_PID comm="keyringer" key="keyring_stash" a0=11 cmd=READ
----
type=SYSCALL msg=audit(1699000003.1) node=host success=yes syscall=keyctl pid=$STASH_PID comm="keyringer" key="keyring_stash" a0=3 cmd=REVOKE
----
type=SYSCALL msg=audit(1699000004.1) node=host success=yes syscall=add_key pid=$BENIGN_PID comm="ssh-agent" key="keyring_stash" a1="user"
----
type=SYSCALL msg=audit(1699000005.1) node=host success=yes syscall=keyctl pid=$BENIGN_PID comm="ssh-agent" key="keyring_stash" a0=11 cmd=READ
----
type=SYSCALL msg=audit(1699000006.1) node=host success=yes syscall=keyctl pid=$BENIGN_PID comm="ssh-agent" key="keyring_stash" a0=3 cmd=REVOKE
----
type=SYSCALL msg=audit(1699000007.1) node=host success=yes syscall=execve pid=$BENIGN_PID comm="ssh-agent" key="keyring_stash"
----
RECORDS
EOF
chmod +x "$TMP/ausearch"

out=$(PATH="$TMP:$PATH" bash detections/ausearch-hunt.sh today)
echo "$out"
echo "$out" | grep -q "SUSPICIOUS pid=$STASH_PID" \
    || { echo "FAIL: suspicious PID $STASH_PID not flagged"; exit 1; }
echo "$out" | grep -q "SUSPICIOUS pid=$BENIGN_PID" \
    && { echo "FAIL: benign PID $BENIGN_PID was flagged"; exit 1; }
echo "ok: ausearch-hunt.sh correlates add_key+READ+REVOKE-without-execve "
echo "    (suspicious pid=$STASH_PID flagged; benign execve pid=$BENIGN_PID clean)"
