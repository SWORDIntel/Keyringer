import json, re, sys
d = json.load(sys.stdin)
names = [e["name"] for e in d]
expect = {"seccomp", "selinux", "apparmor", "wx", "keyring", "keyring-quota",
          "libcurl", "vma", "clone", "afalg"}
assert expect <= set(names), "missing checks: %s" % (expect - set(names))
assert all(e["status"] in ("PASS", "FAIL", "INFO") for e in d), "bad status"
assert len(names) == len(set(names)), "duplicate check names"
q = [e for e in d if e["name"] == "keyring-quota"][0]
assert re.search(r"used/max keys=\d+/\d+, used/max bytes=\d+/\d+, "
                 r"remaining=~\d+ bytes \(live /proc/key-users measurement",
                 q["detail"]), \
    "keyring-quota detail is not a live measurement: %s" % q["detail"]
print("ok: preflight --json (%d checks, keyring-quota live-measured)" % len(d))
