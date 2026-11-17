import json, sys
d = json.load(sys.stdin)
assert isinstance(d, list), "not a list"
assert all(set(e) >= {"serial", "type", "desc", "revoked"} for e in d), "missing fields"
print("ok: list --json (%d entries, fields complete)" % len(d))
