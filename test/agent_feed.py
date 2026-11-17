#!/usr/bin/env python3
"""
test/agent_feed.py — KAG1 control-frame feeder for `keyringer agent`.

Writes two frames (the ELF hello payload, then the raw shellcode) plus
the zero-length terminator frame to stdout, in the wire v2.2 agent
frame format:

    u32 LE magic 0x3147414B ("KAG1" little-endian)
    u32 LE len, len payload bytes
    u16 LE name_len, name bytes
    (len == 0 ends the stream cleanly)
"""
import struct
import sys

MAGIC = 0x3147414B


def frame(payload: bytes, name: bytes) -> bytes:
    assert len(name) <= 0xFFFF
    return (struct.pack("<II", MAGIC, len(payload)) + payload +
            struct.pack("<H", len(name)) + name)


def main() -> int:
    base = __file__.rsplit("/", 1)[0]
    with open(f"{base}/hello", "rb") as f:
        hello = f.read()
    with open(f"{base}/shellcode.bin", "rb") as f:
        shellcode = f.read()
    sys.stdout.buffer.write(
        frame(hello, b"hello-agent") +
        frame(shellcode, b"sc-agent") +
        struct.pack("<II", MAGIC, 0)   # terminator: len == 0
    )
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
