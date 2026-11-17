#!/usr/bin/env python3
"""Smoke the vr-fuzz TCP target: all input classes answered with the
8-byte KRf status, connection reused, server survives hostile input."""
import os
import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 12911
s = socket.create_connection(("127.0.0.1", port), timeout=3)
hello = open("test/hello", "rb").read()
cases = [hello,
         b"KRH3" + os.urandom(200),
         b"KRH1" + os.urandom(100),
         b"KR1" + os.urandom(50),
         b"\x7fELF" + os.urandom(300),
         os.urandom(100)]
for d in cases:
    s.sendall(d)
    r = s.recv(8)
    assert r[:3] == b"KRf" and len(r) == 8, r
    if d is hello:
        assert r[3:4] == b"A", r      # the real payload must validate
print("ok: vr-fuzz target responds to all input classes (%d probes)"
      % len(cases))
