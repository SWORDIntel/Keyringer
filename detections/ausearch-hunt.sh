#!/usr/bin/env bash
# ausearch-hunt.sh — post-hoc auditd hunt for the keyring-stash -> userland-exec
# signature. Requires auditd with auditd-keyringer.rules loaded (key
# 'keyring_stash'); auditd is NOT installed on the Keyringer test box, so this
# ships for operators on hosts that do run auditd.
#
# Usage:  sudo detections/ausearch-hunt.sh [since]
#         sudo detections/ausearch-hunt.sh today
#
# For each PID that performed add_key + keyctl(READ) + keyctl(REVOKE), it
# checks whether the same PID also execve'd within the window; stash loaders
# never do. Output: one suspicious PID per line with comm, user, and counts.

set -euo pipefail
SINCE=${1:-today}
raw=$(ausearch -k keyring_stash --format text -ts "$SINCE" 2>/dev/null || true)
[ -n "$raw" ] || { echo "no keyring_stash audit events ($SINCE)"; exit 0; }

awk '
    /add_key/  { add[$6]++ }        # text format fields vary by distro
    /keyctl.*READ/   { read[$6]++ }
    /keyctl.*REVOKE/ { rev[$6]++  }
    /execve/   { exe[$6]++ }
    END {
        for (pid in add) {
            if ((pid in read) && (pid in rev) && !(pid in exe)) {
                clean = pid; sub(/^pid=/, "", clean)
                printf "SUSPICIOUS pid=%s add_key=%d read=%d revoke=%d execve=0\n",
                       clean, add[pid], read[pid], rev[pid]
            }
        }
    }
' <<<"$raw"
echo "hint: for each PID above pull context: ausearch -k keyring_stash -sc add_key | grep -A2 pid=<pid>"
