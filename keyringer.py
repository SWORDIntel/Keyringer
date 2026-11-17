#!/usr/bin/env python3
"""
keyringer.py — Linux x86-64 kernel-keyring fileless-exec loader (stdlib port).

Python twin of the C `keyringer` tool in this directory, wire-compatible at
the keyring level (wire protocol v4 by default since core 4.0 — v3/v2.2
via KR_WIRE; KR_VERSION below): same key
descriptions (<prefix>.%03u), same 30000-byte "user" chunking (100000-byte
"big_key" chunks with --type big_key), same keyring choices and SysV
process-start stack layout.  Stdlib only (ctypes/os/sys/platform/socket/
struct/secrets/errno/hmac/hashlib/time, plus io/contextlib/tempfile inside
the selftest); no subprocess, no third-party imports, no exec-family
syscall and no memfd anywhere:

  stash   split the payload into <=30000-byte "user" (or <=100000-byte
          "big_key") wire chunks and add_key() them onto the session (or
          persistent) keyring
  load    request_key each chunk until the first ENOKEY, keyctl(READ) it and
          REVOKE it immediately, then reassemble; per chunk index the
          "user" type is tried first, then "big_key"
  exec    map the ELF by hand (PT_LOAD segments per p_flags, PT_INTERP
          interpreter when present), build a fresh SysV process-start stack
          (argc/argv/envp/auxv) and switch to it with a hand-written
          trampoline stub; the payload's exit() ends this process, which is
          the design.  (Unlike the C tool, the original argv memory of the
          Python interpreter is not wiped — only prctl(PR_SET_NAME) spoofing
          is applied, since CPython owns those strings.)
  call    map the ELF, apply basic RELA relocations and call a symbol on the
          normal stack instead of switching stacks

New in wire protocol v2.2:
  --selfcontained  stash-side: after the payload chunks are stored, the
          payload's PT_INTERP path is parsed (program headers of the
          validated payload), the interpreter file is read and stashed
          under <prefix>.ldso.<idx %03d> with wire = KRH1 header
          (flags=0) || raw interpreter bytes — ALWAYS plaintext,
          regardless of --key.  exec-side (--selfcontained): when the
          payload needs an interpreter, it is reassembled from the .ldso.
          chunks (same request_key-until-ENOKEY, user-then-persistent
          ring logic), the KRH1 digest is verified, and the interpreter
          is mapped from those bytes instead of reading the disk path.
          Without the flag: unchanged disk behavior.
  --type big_key   stash with key type "big_key" and 100000-byte wire
          chunks; exec lookup per chunk index tries "user" then "big_key".
  --from s1,s2,... exec: read chunk i straight from the i-th serial via
          KEYCTL_READ probe+read (no request_key); revocation stays
          best-effort (EPERM/EACCES nonfatal); the usual KRH1 digest
          verification applies.
  --share stash: KEYCTL_SETPERM (op 5) every stored serial to 0x3f3f0000,
          then print "share: <s1>,<s2>,..." on stdout.
  --keyfd N  read the key from fd N until EOF; accepts raw 32 bytes or
          64 hex chars (trimmed); precedence --key > --keyfd >
          KEYRINGER_KEY.
  keygen  32 bytes from secrets/os.urandom, printed as hex on stdout.
  preflight  light python mirror of the C tool's environment report:
          seccomp lines, SELinux + AppArmor attributes, a W^X self-test
          (mmap RW, write a `ret`, mprotect PROT_EXEC, call it),
          kernel.keys limits and AF_ALG bind checks; exit 0 unless W^X
          is denied.
  VMA naming parity: prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, len,
          name) labels image regions "[anon:libc:heap]", the 8 MB stack
          "[anon:libc:tls]" and scratch mappings "[anon:libc:buf]"
          (best-effort; all errors swallowed).

NOT mirrored from the C tool (implemented there only — the twin refuses
these cleanly with a one-line "see keyringer (C) tool" error): the agent
and keepalive modes, --clone, khttp and its --proxy/--header/--insecure
options, and the ARCH=aarch64 build.  The python twin is x86_64-only and
refuses to start on any other machine (arm64 is the C tool's lane).

Envelope encryption (--key HEX / KEYRINGER_KEY): b"KR1" || 12-byte nonce ||
ciphertext || 16-byte Poly1305 tag, ChaCha20-Poly1305 per RFC 8439, AAD =
b"KR1" || nonce, whole payload encrypted before chunking.  The kernel's
AF_ALG "rfc7539(chacha20,poly1305)" transform is used when available and
verified against a known vector, with a pure-Python RFC 8439 implementation
as the deterministic fallback.

Wire protocol v3 (KRH3 header, default): every stash prepends a 56-byte header
  b"KRH1" || u32le flags || sha256(plaintext) to the wire payload BEFORE
  chunking; flags bit0 marks a KR1-encrypted body, all other bits zero.
  The digest always covers the PLAINTEXT (pre-encryption):
    encrypted stash = header || KR1-envelope(plaintext)
    plaintext stash = header || plaintext
  At load time the header is stripped, the body decrypted when bit0 is
  set, and sha256(plaintext) verified against the header digest — a
  MISMATCH IS FATAL (clean stderr error, exit 1, no jump, no call).
  Unknown flag bits are fatal.  Headerless pre-v2 stashes keep loading
  exactly as before; a KR1 body without a KRH1 header prints
  "no integrity digest (pre-v2 stash)".  .ldso. interpreter stashes are
  always plaintext (flags=0).  The header adds 40 bytes per stash to
  the keyring quota; the live per-UID pool is measured (quota_snapshot(),
  printed by preflight) and every stash is planned upfront against it
  (refuse-before-store; auto big_key when maxkeys would bind).  On this
  kernel a big_key charges desc+21 bytes, NOT its payload (measured),
  but never bank on byte relief across kernels.

Hardening parity with the C tool: prctl(PR_SET_DUMPABLE, 0) right after
  the PR_SET_NAME spoof; MADV_DONTDUMP on every scratch mapping and
  MADV_DONTDUMP|MADV_WIPEONFORK on the mapped image regions and the 8 MB
  stack (madvise errors are nonfatal); PR_SET_VMA labels as above;
  every bytearray the loader owns (per-chunk key buffers, the
  reassembled wire buffer, the decrypted buffer, loader-side payload
  copies) is zeroized before the jump/call.
"""

import contextlib
import ctypes
import errno
import hashlib
import hmac
import io
import os
import platform
import re
import secrets
import socket
import struct
import sys
import time

# ---------------------------------------------------------------------------
# wire-format constants (must match keyringer.c / keyringer.h) — protocol v2.2
# ---------------------------------------------------------------------------
KR_VERSION = "4.0"                # wire-protocol/tooling version marker

# ---- wire v3 (KRH3) --------------------------------------------------------
KRH3_MAGIC = b"KRH3"
KRH3_VERSION = 3
KR3_HDR_LEN = 56                   # 4+1+1+2+32+8+8 bytes
KRH3_FLAG_ENC = 0x01
KR2_MAGIC = b"KR2"
KR3_INFO = b"keyringer-v3"         # HKDF info
# ---- wire v4 (KRH4) — the DEFAULT writer since core 4.0 --------------------
# Same 56-byte header layout as v3 (magic "KRH4", version byte 4, flags bit0
# = per-chunk-sealed body), but the encrypted body is sealed PER CHUNK:
# the plaintext is split into pt-chunks of KR4_PT_CHUNK bytes and chunk i is
# its own nonce(12)||ct||tag(16) envelope (+28 B per piece) under
# subkey_i = HKDF-SHA256(key, salt = stash-id(8) || u32le(i),
#                        info = "keyringer-v4")
# with AAD = header(56) || u32le(i) || u32le(total) || u32le(ptlen_i).
# pt-chunk arithmetic: a piece is ptlen + 28 wire bytes; 29900 keeps every
# piece inside a 30000-byte "user" key even beside a 56-byte header share
# (30000 - 64 = 29936 >= 29900). The C tool STREAMS this wire on exec
# (chunk-by-chunk decrypt into the mapped image, no full plaintext
# buffer); the python twin assembles normally (it need not stream).
KRH4_MAGIC = b"KRH4"
KRH4_VERSION = 4
KR4_HDR_LEN = 56
KRH4_FLAG_ENC = 0x01
KR4_INFO = b"keyringer-v4"         # HKDF info
KR4_PT_CHUNK = 29900               # plaintext bytes per sealed piece
KR4_PIECE_OH = 12 + 16             # nonce + tag per piece
KEY_TYPE_USER = b"user"           # classic type, single payload cap 32767
KEY_TYPE_BIG_KEY = b"big_key"     # large-payload type (v2.2)
KEY_TYPES = (KEY_TYPE_USER, KEY_TYPE_BIG_KEY)   # exec lookup order per index
CHUNK_USER_MAX = 30000            # wire bytes per "user" key (hard cap 32767)
CHUNK_BIGKEY_MAX = 100000         # wire bytes per "big_key" key (v2.2)
CHUNK_MAX = CHUNK_USER_MAX        # legacy alias: default chunk size
LDSO_TAG = ".ldso"                # --selfcontained: <prefix>.ldso.<%03d>
KEY_PERM_SHARE = 0x3F3F0000       # stash --share: KEYCTL_SETPERM value
IDX_MAX = 999                     # description index is zero-padded %03u
DEFAULT_PREFIX = "_keyringer"
DEFAULT_SPOOF = "kworker/u8:2"
INTERP_GAP = 0x1000000            # interp base = main_base + span + gap
STACK_SIZE = 8 * 1024 * 1024
ENV_DESC = "KEYRINGER_DESC"
ENV_KEY = "KEYRINGER_KEY"

# commands/flags that exist only in the keyringer (C) tool; the twin
# refuses them with a clean one-line error (see module docstring)
C_ONLY_CMDS = ("agent", "keepalive", "khttp")
C_ONLY_FLAGS = ("--clone", "--proxy", "--header", "--insecure")

# keyring syscalls / commands (x86-64)
SYS_PRCTL = 157
SYS_ADD_KEY = 248
SYS_REQUEST_KEY = 249
SYS_KEYCTL = 250
KEY_SPEC_SESSION_KEYRING = -3
KEYCTL_GET_KEYRING_ID = 0
KEYCTL_REVOKE = 3
KEYCTL_SET_TIMEOUT = 15
KEYCTL_INVALIDATE = 21

# --scrub (CLI layer sets this from parsed flags): destroy each chunk with
# KEYCTL_INVALIDATE after its read instead of revoking it
SCRUB = False
KEYCTL_SETPERM = 5
KEYCTL_DESCRIBE = 6
KEYCTL_UNLINK = 9
KEYCTL_SEARCH = 10
KEYCTL_READ = 11
# this kernel's uapi defines GET_PERSISTENT as 22 (matches
# /usr/include/linux/keyctl.h here; historical kernels used 17)
KEYCTL_GET_PERSISTENT = 22
KEY_SPEC_USER_KEYRING = -4

PR_SET_NAME = 15
PR_SET_DUMPABLE = 4
# PR_SET_VMA / PR_SET_VMA_ANON_NAME: label anonymous mappings (v2.2 parity);
# the C agent reports this kernel EINVALs a naive probe, so per prctl(2)
# every failure is swallowed and execution continues
PR_SET_VMA = 0x53564D41
PR_SET_VMA_ANON_NAME = 0
VMA_NAME_IMAGE = b"[anon:libc:heap]"   # payload/interpreter image regions
VMA_NAME_STACK = b"[anon:libc:tls]"    # the 8 MB process-start stack
VMA_NAME_BUF = b"[anon:libc:buf]"      # scratch (trampoline, phdr copy)

# mm
PROT_NONE = 0
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20
MAP_STACK = 0x20000
MAP_FIXED_NOREPLACE = 0x100000    # not exposed by the mmap module; pass raw

# madvise hardening advice (best-effort, errors nonfatal)
MADV_DONTDUMP = 16
MADV_WIPEONFORK = 18

# ELF
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 62
PN_XNUM = 0xFFFF
PT_LOAD = 1
PT_INTERP = 3
PF_X = 1
PF_W = 2
PF_R = 4
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_DYNSYM = 11
SHF_ALLOC = 2
SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00
SHN_ABS = 0xFFF1
R_X86_64_NONE = 0
R_X86_64_64 = 1
R_X86_64_GLOB_DAT = 6
R_X86_64_JUMP_SLOT = 7
R_X86_64_RELATIVE = 8

# auxv
AT_NULL = 0
AT_PHDR = 3
AT_PHENT = 4
AT_PHNUM = 5
AT_PAGESZ = 6
AT_BASE = 7
AT_ENTRY = 9
AT_UID = 11
AT_EUID = 12
AT_GID = 13
AT_EGID = 14
AT_PLATFORM = 15
AT_HWCAP = 16
AT_SECURE = 23
AT_RANDOM = 25
AT_EXECFN = 31
AT_SYSINFO_EHDR = 33

# AF_ALG (kernel crypto API socket interface)
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
ALG_OP_ENCRYPT = 1
ALG_OP_DECRYPT = 2
AF_ALG_NAME = ("aead", "rfc7539(chacha20,poly1305)")

# envelope
ENV_MAGIC = b"KR1"                # b"KR1" || nonce12 || ct || tag16
NONCE_LEN = 12
TAG_LEN = 16
ENV_OVERHEAD = 3 + NONCE_LEN + TAG_LEN

# RFC 8439 section 2.8.2 AEAD test vector
RFC_KEY = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
RFC_NONCE = bytes.fromhex("070000004041424344454647")
RFC_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
RFC_PT = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
          b"only one tip for the future, sunscreen would be it.")
RFC_CT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116")
RFC_TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

_M64 = (1 << 64) - 1

try:
    _PAGESZ = os.sysconf("SC_PAGESIZE")
except (ValueError, OSError):
    _PAGESZ = 4096
if _PAGESZ <= 0:
    _PAGESZ = 4096


def _page_down(x):
    return x & ~(_PAGESZ - 1)


def _page_up(x):
    return (x + _PAGESZ - 1) & ~(_PAGESZ - 1)


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------

def die(msg):
    sys.stderr.write("keyringer: %s\n" % msg)
    sys.stderr.flush()
    sys.exit(1)


def _read_file(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as ex:
        die("open %s: %s" % (path, ex.strerror))


def _read_stdin():
    return sys.stdin.buffer.read()


# ---------------------------------------------------------------------------
# raw syscall plumbing
# ---------------------------------------------------------------------------

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long
_libc.syscall.argtypes = [ctypes.c_long] * 6
_libc.mmap.restype = ctypes.c_void_p
_libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                       ctypes.c_int, ctypes.c_int, ctypes.c_long]
_libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
_libc.mprotect.restype = ctypes.c_int
_libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
_libc.madvise.restype = ctypes.c_int
_libc.prctl.restype = ctypes.c_int
_libc.prctl.argtypes = [ctypes.c_int, ctypes.c_void_p,
                        ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]


def _sc(nr, *args):
    """raw syscall(2) with up to 5 arguments (bytes/None/ctypes/int)."""
    vals = []
    for a in list(args)[:5] + [0] * max(0, 5 - len(args)):
        if a is None:
            a = 0
        elif hasattr(a, "_b_base_"):      # any ctypes data object
            a = ctypes.cast(a, ctypes.c_void_p).value or 0
        elif isinstance(a, (bytes, bytearray)):
            a = ctypes.cast(ctypes.c_char_p(bytes(a)),
                            ctypes.c_void_p).value or 0
        else:
            a = int(a)
        vals.append(a)
    return _libc.syscall(nr, *vals)


def _errno_str():
    return os.strerror(ctypes.get_errno())


def _add_key(desc, payload, keyring, key_type=KEY_TYPE_USER):
    return _sc(SYS_ADD_KEY, key_type, desc, payload, len(payload), keyring)


def _request_key(desc, keyring, key_type=KEY_TYPE_USER):
    return _sc(SYS_REQUEST_KEY, key_type, desc, None, keyring)


def _keyctl(cmd, *args):
    return _sc(SYS_KEYCTL, cmd, *args)


class _MmapError(Exception):
    pass


def _mmap(addr, length, prot, flags, fd=-1, offset=0):
    r = _libc.mmap(addr, length, prot, flags, fd, offset)
    if r is None or r == (1 << 64) - 1:
        raise _MmapError(_errno_str())
    return r


def _munmap(addr, length):
    _libc.munmap(addr, length)


def _mprotect_checked(addr, length, prot, what, idx):
    if _libc.mprotect(addr, length, prot) == -1:
        die("%s: mprotect PT_LOAD %d -> %d failed: %s"
            % (what, idx, prot, _errno_str()))


def _madvise(addr, length, *advice):
    """best-effort madvise(2) hardening; errors are nonfatal by design."""
    for adv in advice:
        _libc.madvise(addr, length, adv)


def _no_dumpable():
    """prctl(PR_SET_DUMPABLE, 0): no core dumps, no ptrace of the loader."""
    if _libc.prctl(PR_SET_DUMPABLE, None, 0, 0, 0) == -1:
        sys.stderr.write(
            "keyringer: warning: prctl(PR_SET_DUMPABLE, 0) failed: %s\n"
            % _errno_str())


def _vma_name(addr, length, name):
    """prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, len, name): label an
    anonymous mapping so it shows up in /proc/<pid>/smaps (v2.2 parity with
    the C tool's "[anon:libc:*]" names).  Best-effort by design: kernels
    without CONFIG_ANON_VMA_NAME (or with a paranoid LSM) return EINVAL/
    EPERM — per prctl(2) the error is swallowed and execution continues."""
    try:
        _sc(SYS_PRCTL, PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, length, name)
    except Exception:
        pass


def _wr64(addr, val):
    ctypes.memmove(addr, struct.pack("<Q", val & _M64), 8)


def _raw_envp():
    """byte-exact environment of this process, straight from libc environ."""
    try:
        env = ctypes.POINTER(ctypes.c_char_p).in_dll(_libc, "environ")
    except ValueError:
        return []
    out = []
    for i in range(1000000):
        e = env[i]
        if not e:
            break
        out.append(e)
    return out


def _auxv_get(aux_type):
    """one auxv entry of this process, read from /proc/self/auxv."""
    try:
        with open("/proc/self/auxv", "rb") as fh:
            data = fh.read()
    except OSError:
        return 0
    for off in range(0, len(data) - 15, 16):
        at, val = struct.unpack_from("<QQ", data, off)
        if at == AT_NULL:
            break
        if at == aux_type:
            return val
    return 0


# ---------------------------------------------------------------------------
# ChaCha20-Poly1305, RFC 8439 — pure-Python reference implementation
# ---------------------------------------------------------------------------

_MASK32 = 0xFFFFFFFF
_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_POLY_PRIME = (1 << 130) - 5
_POLY_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & _MASK32
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK32
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _MASK32
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK32
    s[b] = _rotl32(s[b] ^ s[c], 7)


def _chacha_block(key32, counter, nonce12):
    kw = struct.unpack("<8I", key32)
    nw = struct.unpack("<3I", nonce12)
    state = list(_SIGMA) + list(kw) + [counter & _MASK32] + list(nw)
    w = list(state)
    for _ in range(10):
        _quarter(w, 0, 4, 8, 12)
        _quarter(w, 1, 5, 9, 13)
        _quarter(w, 2, 6, 10, 14)
        _quarter(w, 3, 7, 11, 15)
        _quarter(w, 0, 5, 10, 15)
        _quarter(w, 1, 6, 11, 12)
        _quarter(w, 2, 7, 8, 13)
        _quarter(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + state[i]) & _MASK32
                                 for i in range(16)])


def _chacha20(key, counter, nonce, data):
    out = bytearray(len(data))
    for i in range(0, len(data), 64):
        ks = _chacha_block(key, counter + i // 64, nonce)
        chunk = data[i:i + 64]
        out[i:i + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def _poly1305(msg, key):
    r = int.from_bytes(key[:16], "little") & _POLY_CLAMP
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        blk = msg[i:i + 16]
        n = int.from_bytes(blk, "little") + (1 << (8 * len(blk)))
        acc = ((acc + n) * r) % _POLY_PRIME
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(n):
    return b"\x00" * (-n % 16)


def _aead_py(key, nonce, aad, plaintext):
    """RFC 8439 AEAD seal: returns ciphertext || 16-byte tag."""
    poly_key = _chacha_block(key, 0, nonce)[:32]
    ct = _chacha20(key, 1, nonce, plaintext)
    mac_data = (aad + _pad16(len(aad)) + ct + _pad16(len(ct)) +
                struct.pack("<QQ", len(aad), len(ct)))
    return ct + _poly1305(mac_data, poly_key)


def _aead_open_py(key, nonce, aad, blob):
    """RFC 8439 AEAD open: returns plaintext or None on tag mismatch."""
    if len(blob) < TAG_LEN:
        return None
    ct, tag = blob[:-TAG_LEN], blob[-TAG_LEN:]
    poly_key = _chacha_block(key, 0, nonce)[:32]
    mac_data = (aad + _pad16(len(aad)) + ct + _pad16(len(ct)) +
                struct.pack("<QQ", len(aad), len(ct)))
    if not hmac.compare_digest(_poly1305(mac_data, poly_key), tag):
        return None
    return _chacha20(key, 1, nonce, ct)


# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 via kernel AF_ALG (verified against the RFC vector)
# ---------------------------------------------------------------------------

class _AuthError(Exception):
    pass


def _af_alg_aead(key, nonce, aad, payload, decrypt):
    """kernel AEAD.  payload = plaintext (seal) or ct||tag (open).

    algif_aead input layout is AAD || data with ALG_SET_AEAD_ASSOCLEN giving
    the AAD length; output is ct||tag (seal) or pt (open).
    """
    alg = socket.socket(getattr(socket, "AF_ALG", 38), socket.SOCK_SEQPACKET)
    try:
        alg.bind(AF_ALG_NAME)
        alg.setsockopt(SOL_ALG, ALG_SET_KEY, key)
        opfd, _ = alg.accept()
        with opfd:
            op = ALG_OP_DECRYPT if decrypt else ALG_OP_ENCRYPT
            cmsgs = [
                (SOL_ALG, ALG_SET_IV,
                 struct.pack("<I", len(nonce)) + nonce),
                (SOL_ALG, ALG_SET_OP, struct.pack("<I", op)),
                (SOL_ALG, ALG_SET_AEAD_ASSOCLEN,
                 struct.pack("<I", len(aad))),
            ]
            opfd.sendmsg([aad + payload], cmsgs)
            out_len = len(payload) - TAG_LEN if decrypt \
                else len(payload) + TAG_LEN
            # algif_aead answers with exactly one SOCK_SEQPACKET message.
            # Some kernels prefix the result with the associated data
            # (AAD || result); others return just the result — one recv with
            # the larger bound covers both.
            try:
                out = opfd.recv(len(aad) + out_len)
            except OSError as ex:
                if ex.errno == errno.EBADMSG:
                    raise _AuthError("Poly1305 tag mismatch")
                raise
            if len(out) == len(aad) + out_len and aad:
                out = out[len(aad):]
            if len(out) != out_len:
                raise OSError("AF_ALG short result (%d/%d bytes)"
                              % (len(out), out_len))
            return out
    finally:
        alg.close()


_AEAD_IMPL = None


def aead_impl():
    """decide once: kernel AF_ALG if it exists AND reproduces the RFC vector.
    KR_CRYPTO=userspace forces the pure-Python implementation."""
    global _AEAD_IMPL
    if _AEAD_IMPL is None:
        if os.environ.get("KR_CRYPTO", "") == "userspace":
            _AEAD_IMPL = "python"
            return _AEAD_IMPL
        try:
            ref = _aead_py(RFC_KEY, RFC_NONCE, RFC_AAD, RFC_PT)
            got = _af_alg_aead(RFC_KEY, RFC_NONCE, RFC_AAD, RFC_PT, False)
            _AEAD_IMPL = "af_alg" if got == ref else "python"
        except (OSError, _AuthError):
            _AEAD_IMPL = "python"
    return _AEAD_IMPL


def _aead_seal(key, nonce, aad, plaintext):
    if aead_impl() == "af_alg":
        try:
            return _af_alg_aead(key, nonce, aad, plaintext, False)
        except OSError:
            pass                      # kernel said no mid-flight; fall back
    return _aead_py(key, nonce, aad, plaintext)


def _aead_open(key, nonce, aad, blob):
    if aead_impl() == "af_alg":
        try:
            return _af_alg_aead(key, nonce, aad, blob, True)
        except _AuthError:
            return None
        except OSError:
            pass
    return _aead_open_py(key, nonce, aad, blob)


# ---------------------------------------------------------------------------
# KR1 envelope:  b"KR1" || nonce(12) || ciphertext || tag(16)
# ---------------------------------------------------------------------------

def _parse_key(hexstr):
    try:
        key = bytes.fromhex(hexstr.strip())
    except ValueError:
        die("--key: invalid hex key %r" % hexstr)
    if len(key) != 32:
        die("--key: need a 64-hex-char (32-byte) ChaCha20 key, got %d byte(s)"
            % len(key))
    return key


def envelope_seal(key, plaintext, nonce=None, verify=True):
    if nonce is None:
        nonce = secrets.token_bytes(NONCE_LEN)
    aad = ENV_MAGIC + nonce                       # 15 bytes of AAD
    blob = ENV_MAGIC + nonce + _aead_seal(key, nonce, aad, plaintext)
    if verify and envelope_open(key, blob) != plaintext:
        die("envelope: seal/open verification failed; nothing stored")
    return blob


def envelope_open(key, blob):
    if len(blob) < ENV_OVERHEAD or blob[:3] != ENV_MAGIC:
        die("envelope: not a KR1 envelope — was the stash created "
            "with --key/KEYRINGER_KEY?")
    nonce = blob[3:15]
    pt = _aead_open(key, nonce, blob[:15], blob[15:])
    if pt is None:
        die("envelope: ChaCha20-Poly1305 authentication failed "
            "(wrong key or corrupted stash)")
    return pt


# ---------------------------------------------------------------------------
# KRH1 wire header (protocol v2.2), prepended to every stash BEFORE chunking:
#     b"KRH1" || u32le flags || sha256(plaintext)     (40 bytes total)
# flags bit0 = body is a KR1 envelope, all other bits reserved (zero).
# The digest ALWAYS covers the plaintext (pre-encryption); .ldso.
# interpreter stashes are ALWAYS plaintext (flags=0), regardless of --key.
# Legacy headerless stashes keep loading unchanged.
# ---------------------------------------------------------------------------

KRH_MAGIC = b"KRH1"
KRH_HDR_LEN = 4 + 4 + 32            # 40
KRH_FLAG_ENVELOPE = 1 << 0
KRH_FLAGS_KNOWN = KRH_FLAG_ENVELOPE


def _hkdf_sha256(ikm, salt, info, length=32):
    """HKDF-SHA256 (RFC 5869) on the stdlib."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def _kr3_wrap(plaintext, key):
    """v3 wire: KRH3 header || body.  Header = KRH3 || ver(1)=3 ||
    flags(1) || reserved(2) || sha256(pt) || stash-id(8) || u64le len.
    Encrypted body: KR2 || nonce || ct||tag, sealed with
    key' = HKDF-SHA256(key, salt=stash-id, info="keyringer-v3") and
    AAD = the whole header || "KR2" || nonce (71 bytes) — the version,
    digest, length and stash-id are all authenticated."""
    stash_id = os.urandom(8)
    flags = KRH3_FLAG_ENC if key is not None else 0
    hdr = (KRH3_MAGIC + bytes([KRH3_VERSION, flags, 0, 0]) +
           hashlib.sha256(plaintext).digest() + stash_id +
           struct.pack("<Q", len(plaintext)))
    if key is None:
        return hdr + plaintext
    subkey = _hkdf_sha256(key, stash_id, KR3_INFO)
    nonce = os.urandom(12)
    aad = hdr + KR2_MAGIC + nonce
    ct = _aead_seal(subkey, nonce, aad, plaintext)
    return hdr + KR2_MAGIC + nonce + ct


def _kr3_unwrap(wire, key):
    """open a v3 wire payload (zeroizes wire in place, like _load_unwrap)."""
    if len(wire) < KR3_HDR_LEN:
        die("load: truncated KRH3 header (%d bytes)" % len(wire))
    if wire[4] != KRH3_VERSION:
        die("load: KRH3 header version %d unsupported (want %d) — refusing"
            % (wire[4], KRH3_VERSION))
    flags = wire[5]
    if flags & ~KRH3_FLAG_ENC:
        die("load: KRH3 header: reserved flag bits set (0x%02x) — refusing"
            % flags)
    want = bytes(wire[8:40])
    stash_id = bytes(wire[40:48])
    (wantlen,) = struct.unpack_from("<Q", wire, 48)
    if flags & KRH3_FLAG_ENC:
        if key is None:
            die("load: stash is KR2-encrypted; supply --key/KEYRINGER_KEY")
        if wire[KR3_HDR_LEN:KR3_HDR_LEN + 3] != KR2_MAGIC:
            die("load: KRH3 encrypted body is not a KR2 envelope")
        subkey = _hkdf_sha256(key, stash_id, KR3_INFO)
        nonce = bytes(wire[KR3_HDR_LEN + 3:KR3_HDR_LEN + 15])
        aad = bytes(wire[:KR3_HDR_LEN + 15])
        blob = bytes(wire[KR3_HDR_LEN + 15:])
        pt = _aead_open(subkey, nonce, aad, blob)
        if pt is None:
            die("load: KR2 authentication failed (wrong key or corrupted "
                "stash)")
        pt = bytearray(pt)
    else:
        if key is not None:
            die("load: stash body is not encrypted but --key was given")
        pt = bytearray(wire[KR3_HDR_LEN:])
    wire[:] = b"\x00" * len(wire)
    if wantlen != len(pt):
        pt[:] = b"\x00" * len(pt)
        die("load: KRH3 length field says %d but body carries %d bytes — "
            "truncated or spliced stash, refusing" % (wantlen, len(pt)))
    if not hmac.compare_digest(hashlib.sha256(pt).digest(), want):
        pt[:] = b"\x00" * len(pt)
        die("load: KRH3 digest mismatch — stash corrupted; refusing to "
            "execute")
    return pt


def _kr4_wrap(plaintext, key):
    """v4 wire (EXPERIMENTAL): KRH4 header || per-chunk-sealed body.
    Header layout = v3 (magic "KRH4", version 4, flags bit0 = sealed).
    Encrypted body: total = ceil(len/29900) pieces, piece i =
    nonce(12) || ct || tag(16) sealed with subkey_i = HKDF-SHA256(key,
    salt = stash-id(8) || u32le(i), info="keyringer-v4") and AAD =
    header(56) || u32le(i) || u32le(total) || u32le(ptlen_i). Plain body:
    header || raw plaintext (identical to v3). Byte-compatible with
    kr_core.c build_v4_wire()."""
    stash_id = os.urandom(8)
    flags = KRH4_FLAG_ENC if key is not None else 0
    hdr = (KRH4_MAGIC + bytes([KRH4_VERSION, flags, 0, 0]) +
           hashlib.sha256(plaintext).digest() + stash_id +
           struct.pack("<Q", len(plaintext)))
    if key is None:
        return hdr + plaintext
    total = (len(plaintext) + KR4_PT_CHUNK - 1) // KR4_PT_CHUNK
    body = bytearray()
    for i in range(total):
        chunk = plaintext[i * KR4_PT_CHUNK:(i + 1) * KR4_PT_CHUNK]
        subkey = _hkdf_sha256(key, stash_id + struct.pack("<I", i), KR4_INFO)
        nonce = os.urandom(12)
        aad = (hdr + struct.pack("<III", i, total, len(chunk)))
        body += nonce + _aead_seal(subkey, nonce, aad, chunk)
    return hdr + bytes(body)


def _kr4_unwrap(wire, key):
    """open a v4 wire payload (zeroizes wire in place, like _load_unwrap).
    Assembles the full plaintext (the python twin need not stream — the
    per-chunk AEAD and the whole-stash digest are verified exactly like
    the C reader)."""
    if len(wire) < KR4_HDR_LEN:
        die("load: truncated KRH4 header (%d bytes)" % len(wire))
    if wire[4] != KRH4_VERSION:
        die("load: KRH4 header version %d unsupported (want %d) — refusing"
            % (wire[4], KRH4_VERSION))
    flags = wire[5]
    if flags & ~KRH4_FLAG_ENC:
        die("load: KRH4 header: reserved flag bits set (0x%02x) — refusing"
            % flags)
    if wire[6] or wire[7]:
        die("load: KRH4 header: reserved bytes not zero — refusing")
    want = bytes(wire[8:40])
    stash_id = bytes(wire[40:48])
    (wantlen,) = struct.unpack_from("<Q", wire, 48)
    if wantlen == 0:
        die("load: KRH4 stash carries an empty body")
    if flags & KRH4_FLAG_ENC:
        if key is None:
            die("load: stash is per-chunk KR4-sealed; supply "
                "--key/KEYRINGER_KEY")
        # solve wirelen == 56 + 28*T + ptlen with (T-1)*PT < ptlen <= T*PT
        total = None
        for t in range(1, (len(wire) // KR4_PT_CHUNK) + 3):
            lo = (KR4_HDR_LEN + t * KR4_PIECE_OH + (t - 1) * KR4_PT_CHUNK
                  + 1)
            hi = KR4_HDR_LEN + t * KR4_PIECE_OH + t * KR4_PT_CHUNK
            if len(wire) < lo:
                break
            if len(wire) <= hi:
                total = t
                break
        if total is None:
            die("load: KRH4 encrypted wire length %d fits no pt-chunk "
                "equation — truncated or spliced stash, refusing"
                % len(wire))
        ptlen = len(wire) - KR4_HDR_LEN - total * KR4_PIECE_OH
        if ptlen != wantlen:
            die("load: KRH4 length field says %d but the chunk equation "
                "carries %d bytes — truncated or spliced stash, refusing"
                % (wantlen, ptlen))
        pt = bytearray()
        for i in range(total):
            off = KR4_HDR_LEN + i * (KR4_PIECE_OH + KR4_PT_CHUNK)
            chunk_len = min(KR4_PT_CHUNK, ptlen - i * KR4_PT_CHUNK)
            piece = bytes(wire[off:off + 12 + chunk_len + 16])
            subkey = _hkdf_sha256(key, stash_id + struct.pack("<I", i),
                                  KR4_INFO)
            nonce = piece[:12]
            aad = bytes(wire[:KR4_HDR_LEN]) + struct.pack(
                "<III", i, total, chunk_len)
            out = _aead_open(subkey, nonce, aad, piece[12:])
            if out is None:
                die("load: KR4 chunk %d/%d authentication failed (wrong "
                    "key or corrupted stash)" % (i, total))
            pt += out
    else:
        if key is not None:
            die("load: stash body is not encrypted but --key was given")
        pt = bytearray(wire[KR4_HDR_LEN:])
    wire[:] = b"\x00" * len(wire)
    if len(pt) != wantlen:
        pt[:] = b"\x00" * len(pt)
        die("load: KRH4 length field says %d but body carries %d bytes — "
            "truncated or spliced stash, refusing" % (wantlen, len(pt)))
    if not hmac.compare_digest(hashlib.sha256(pt).digest(), want):
        pt[:] = b"\x00" * len(pt)
        die("load: KRH4 digest mismatch — stash corrupted; refusing to "
            "execute")
    return pt


def _wire_sel():
    """stash-time wire selector from KR_WIRE: 4, 3 or 2 — mirrors the C
    wire_sel().  The final return is the DEFAULT writer for an
    unset/unknown KR_WIRE: v4, since core 4.0 (KR_WIRE=4 is an accepted
    no-op kept for pre-flip scripts)."""
    m = os.environ.get("KR_WIRE", "")
    if m == "4":
        return 4
    if m[:1] == "2":
        return 2
    if m == "3":
        return 3
    return 4


def _stash_wrap(plaintext, key, selfcontained=False):
    """build the wire payload that gets chunked.  v4 (KRH4, per-chunk
    AEAD body) by default since core 4.0; KR_WIRE=3 opts back into the
    v3 builder and KR_WIRE=2 downgrades to the v2.2 KRH1 builder
    (downgrade/interop testing).
    selfcontained=True downgrades a v4 selection to the v3 builder (v4
    ldso support pending; an EXPLICIT KR_WIRE=4 + --selfcontained is
    refused in _stash_payload).  The .ldso. interpreter stash always
    passes key=None."""
    sel = _wire_sel()
    if sel == 4 and selfcontained:
        sel = 3           # v4 ldso support pending
    if sel == 2:
        flags = KRH_FLAG_ENVELOPE if key is not None else 0
        hdr = (KRH_MAGIC + struct.pack("<I", flags) +
               hashlib.sha256(plaintext).digest())
        body = (envelope_seal(key, plaintext) if key is not None
                else plaintext)
        return hdr + body
    if sel == 4:
        return _kr4_wrap(plaintext, key)
    return _kr3_wrap(plaintext, key)


def _load_unwrap(wire, key):
    """validate the KRH1 header of a reassembled stash, decrypt when
    flagged, verify the plaintext digest (mismatch is fatal: clean stderr
    error, exit 1 — no jump, no call) and return the plaintext as a fresh
    bytearray.  `wire` is zeroized in place before return.  Headerless
    (pre-v2) stashes behave exactly as before."""
    if wire[:4] == KRH4_MAGIC:
        return _kr4_unwrap(wire, key)
    if wire[:4] == KRH3_MAGIC:
        return _kr3_unwrap(wire, key)
    if wire[:4] == KRH_MAGIC:
        if len(wire) < KRH_HDR_LEN:
            die("load: truncated KRH1 header (%d bytes)" % len(wire))
        (flags,) = struct.unpack_from("<I", wire, 4)
        if flags & ~KRH_FLAGS_KNOWN:
            die("load: unknown KRH1 header flag bits 0x%08x — refusing to "
                "execute" % flags)
        want = bytes(wire[8:KRH_HDR_LEN])
        body = wire[KRH_HDR_LEN:]
        if flags & KRH_FLAG_ENVELOPE:
            if key is None:
                die("load: stash is KR1-encrypted; supply "
                    "--key/KEYRINGER_KEY")
            pt = bytearray(envelope_open(key, body))
        else:
            pt = bytearray(body)
        body[:] = b"\x00" * len(body)             # zeroize the body copy
        wire[:] = b"\x00" * len(wire)             # zeroize the wire buffer
        if not hmac.compare_digest(hashlib.sha256(pt).digest(), want):
            pt[:] = b"\x00" * len(pt)
            die("load: KRH1 digest mismatch: sha256(plaintext) != header "
                "digest — stash corrupted; refusing to execute")
        return pt

    # legacy, pre-v2 stash without a KRH1 header: behave exactly as before
    if key is not None:
        if wire[:3] == ENV_MAGIC:
            sys.stderr.write(
                "keyringer: no integrity digest (pre-v2 stash)\n")
        pt = bytearray(envelope_open(key, wire))
    else:
        pt = bytearray(wire)
    wire[:] = b"\x00" * len(wire)                 # zeroize the wire buffer
    return pt


# ---------------------------------------------------------------------------
# phase 1: stash wire payload as "user"/"big_key" key chunks
# ---------------------------------------------------------------------------

def _desc(prefix, idx):
    return b"%s.%03d" % (prefix.encode(), idx)


def _ldso_prefix(prefix):
    return prefix + LDSO_TAG


def _chunk_max_for(key_type):
    return CHUNK_BIGKEY_MAX if key_type == KEY_TYPE_BIG_KEY else CHUNK_USER_MAX


def _stash(data, prefix, ring_serial, ring_desc, key_type=KEY_TYPE_USER,
           chunk_max=CHUNK_USER_MAX, rollback=()):
    """chunk `data` into add_key() chunks of `chunk_max` wire bytes each,
    under <prefix>.%03d with key type `key_type`.  On failure every serial
    in `rollback` plus the ones stored here are revoked (so a failed
    --selfcontained interpreter stash takes the payload chunks down with
    it).  Returns the serials stored by THIS call."""
    if not data:
        die("stash: empty input")
    nchunks = (len(data) + chunk_max - 1) // chunk_max
    if nchunks > IDX_MAX + 1:
        die("stash: %d chunks needed, max %d (chunk size %d)"
            % (nchunks, IDX_MAX + 1, chunk_max))
    serials = list(rollback)
    mine = []
    for i in range(nchunks):
        desc = _desc(prefix, i)
        chunk = data[i * chunk_max:(i + 1) * chunk_max]
        serial = _add_key(desc, chunk, ring_serial, key_type)
        if serial == -1:
            e = ctypes.get_errno()
            sys.stderr.write(
                "keyringer: stash: add_key(\"%s\", \"%s\", %d bytes) "
                "failed: %s\n"
                % (key_type.decode(), desc.decode(), len(chunk),
                   os.strerror(e)))
            for prev in serials:
                _keyctl(KEYCTL_REVOKE, prev)
            if serials:
                sys.stderr.write(
                    "keyringer: stash: revoked %d already-stored chunk "
                    "key(s)\n" % len(serials))
            if e in (errno.EDQUOT, errno.ENOMEM):
                sys.stderr.write(
                    "keyringer: kernel keyring quota exceeded (the upfront "
                    "planner normally refuses before storing anything — "
                    "the live measurement may have moved).\n"
                    "  non-root cap: /proc/sys/kernel/keys/maxbytes "
                    "(default 20000 bytes total; every user key charges "
                    "desc + payload + 5 bytes on this kernel)\n"
                    "  root cap:     /proc/sys/kernel/keys/root_maxbytes "
                    "(default 25 MiB)\n"
                    "  use a smaller payload or raise the quota "
                    "(e.g. run as root).\n")
            sys.exit(1)
        serials.append(serial)
        mine.append(serial)
        sys.stderr.write("stash: %s [%s] -> key %d (%d bytes)\n"
                         % (desc.decode(), key_type.decode(), serial,
                            len(chunk)))
    sys.stderr.write("stash: %d chunk(s), %d bytes stored on the %s keyring "
                     "(type %s)\n"
                     % (len(mine), len(data), ring_desc, key_type.decode()))
    return mine


def _share_serials(serials):
    """stash --share: KEYCTL_SETPERM (op 5) every stored serial to
    0x3f3f0000 (all permission bits for possessor+user, none for
    group/other), then print the share line on stdout.  setperm failures
    warn but never abort the share line."""
    for s in serials:
        if _keyctl(KEYCTL_SETPERM, s, KEY_PERM_SHARE) == -1:
            sys.stderr.write(
                "keyringer: warning: KEYCTL_SETPERM(key %d, 0x%08x) "
                "failed: %s\n" % (s, KEY_PERM_SHARE, _errno_str()))
    print("share: %s" % ",".join(str(s) for s in serials))


def _pt_interp_path(data):
    """PT_INTERP path bytes of a validated x86-64 ELF, or None when the
    payload is statically linked.  Used by the --selfcontained stash."""
    eh = _validate_elf(data, "payload")
    for p in eh["phdrs"]:
        if p["type"] != PT_INTERP:
            continue
        if p["off"] >= len(data) or p["off"] + p["filesz"] > len(data):
            die("stash: --selfcontained: PT_INTERP out of bounds")
        raw = data[p["off"]:p["off"] + p["filesz"]]
        if b"\x00" not in raw:
            die("stash: --selfcontained: PT_INTERP path not NUL-terminated")
        return raw.split(b"\x00", 1)[0]
    return None


def _stash_selfcontained(data, prefix, ring_serial, ring_desc, key_type,
                         rollback):
    """--selfcontained stash side: parse the (validated) payload's
    PT_INTERP, read the interpreter file and stash it under
    <prefix>.ldso.<idx %03d> with wire = KRH1 header (flags=0) || raw
    interpreter bytes — ALWAYS plaintext, regardless of --key.  Returns
    the ldso serials."""
    ipath = _pt_interp_path(data)
    if ipath is None:
        sys.stderr.write("stash: --selfcontained: payload has no PT_INTERP "
                         "(statically linked) — nothing to embed\n")
        return []
    ibytes = bytearray(_read_file(os.fsdecode(ipath)))
    sys.stderr.write("stash: --selfcontained: interpreter %s, %d bytes "
                     "(wire: KRH1 flags=0 || raw bytes, plaintext)\n"
                     % (os.fsdecode(ipath), len(ibytes)))
    wire = _stash_wrap(bytes(ibytes), None, selfcontained=True)
    ibytes[:] = b"\x00" * len(ibytes)
    return _stash(wire, _ldso_prefix(prefix), ring_serial, ring_desc,
                  key_type, _chunk_max_for(key_type), rollback=rollback)


def _apply_ttl(serials, ttl):
    """stash --ttl SECONDS: KEYCTL_SET_TIMEOUT every stored key so the
    kernel GC collects the stash even if the stasher dies first."""
    if not ttl:
        return
    n = 0
    for s in serials:
        if _keyctl(KEYCTL_SET_TIMEOUT, s, ttl) == -1:
            sys.stderr.write("keyringer: warning: SET_TIMEOUT(key %d, %ds) "
                             "failed: %s\n" % (s, ttl, _errno_str()))
        else:
            n += 1
    sys.stderr.write("stash: TTL %ds set on %d/%d key(s)\n"
                     % (ttl, n, len(serials)))


# ---------------------------------------------------------------------------
# keyring quota telemetry + upfront stash planning (kr_quota_snapshot /
# plan_stash_quota twins — same /proc sources, same charge model)
# ---------------------------------------------------------------------------

QUOTA_USER_OH = 5       # measured: desc + payload + 5 per "user" key
QUOTA_BIGKEY_OH = 21    # measured: desc + 21 per "big_key", FIXED — the
                        # payload is shmem-backed and NOT byte-charged on
                        # this kernel (a 100000-byte big_key charged 27 B
                        # as non-root here; /proc/keys shows "[file]")
QUOTA_SLACK = 16        # planning slack per key (round up, refuse early)
QUOTA_SLACK_ONCE = 64   # ring-creation / rounding slack, once per stash

# "  <uid>: <usage> <nkeys>/<qnkeys> <nikeys>/<maxkeys> <qnbytes>/<maxbytes>"
# — field semantics VERIFIED EMPIRICALLY on this kernel (7.0.14-17-pve):
# nkeys/qnbytes are the charges; qnkeys duplicates the key charge (it is
# NOT a limit); the maxkeys/maxbytes denominators track the LIVE sysctls
# (watched them flip with a sysctl write; add_key enforced it the same
# second) and win over the /proc/sys read, which stays the fallback.
_KEY_USERS_ROW = re.compile(
    r"^\s*(\d+):\s+(\d+)\s+(\d+)/(\d+)\s+(\d+)/(\d+)\s+(\d+)/(\d+)\s*$")


def quota_snapshot():
    """kr_quota_snapshot twin: live per-UID quota from the kernel.keys
    sysctls plus this uid's /proc/key-users row (euid first, uid
    fallback).  A missing row (fresh boot: no key ever created for this
    uid) degrades cleanly to used=0, measured=0.  Returns None when the
    quota LIMITS are unreadable (callers then skip planning and keep the
    mid-stash EDQUOT rollback as the backstop)."""
    euid = os.geteuid()
    kn, bn = (("root_maxkeys", "root_maxbytes") if euid == 0
              else ("maxkeys", "maxbytes"))
    kv = _read_text("/proc/sys/kernel/keys/" + kn)
    bv = _read_text("/proc/sys/kernel/keys/" + bn)
    if kv is None or bv is None:
        return None
    try:
        keys_max, bytes_max = int(kv), int(bv)
    except ValueError:
        return None
    q = {"keys_used": 0, "keys_max": keys_max, "bytes_used": 0,
         "bytes_max": bytes_max, "bytes_remaining": 0, "measured": 0}
    try:
        with open("/proc/key-users", "r") as fh:
            rows = fh.read().splitlines()
    except OSError:
        rows = []
    for ln in rows:
        m = _KEY_USERS_ROW.match(ln)
        if not m:
            continue
        uid = int(m.group(1))
        if uid != euid and uid != os.getuid():
            continue
        q["keys_used"] = int(m.group(3)) or int(m.group(4))
        q["bytes_used"] = int(m.group(7))
        if int(m.group(6)):
            q["keys_max"] = int(m.group(6))
        if int(m.group(8)):
            q["bytes_max"] = int(m.group(8))
        q["measured"] = 1
        break
    q["bytes_remaining"] = max(0, q["bytes_max"] - q["bytes_used"])
    return q


def _quota_chunkmax(key_type):
    return CHUNK_BIGKEY_MAX if key_type == KEY_TYPE_BIG_KEY else CHUNK_USER_MAX


def _quota_chunks(wirelen, chunkmax):
    return (wirelen + chunkmax - 1) // chunkmax


def _quota_charge(key_type, desclen, wirelen):
    """qnbytes a wire of `wirelen` bytes under `key_type` will charge,
    planned with the measured per-key overhead plus round-up slack per
    key: "user" keys charge desc + chunk + 5; big_key keys charge
    desc + 21 FIXED (the payload escapes the byte quota on this kernel).
    Rounds UP so a planned-OK stash cannot overflow by rounding."""
    chunkmax = _quota_chunkmax(key_type)
    oh = QUOTA_BIGKEY_OH if key_type == KEY_TYPE_BIG_KEY else QUOTA_USER_OH
    total = 0
    for i in range(_quota_chunks(wirelen, chunkmax)):
        clen = 0 if key_type == KEY_TYPE_BIG_KEY else \
            min(chunkmax, wirelen - i * chunkmax)
        total += desclen + clen + oh + QUOTA_SLACK
    return total


def _plan_quota(data, prefix, wirelen, key_type, type_explicit,
                selfcontained):
    """plan_stash_quota twin, run in _stash_payload BEFORE the first
    add_key: auto-select big_key when the \"user\" chunk count would
    exceed maxkeys (the maxkeys-relief mechanism only — never claimed as
    byte relief; skipped when --type was passed explicitly), then refuse
    cleanly — before storing ANYTHING — when the planned charge exceeds
    what remains, and warn (nonfatal) above 50% of the remaining bytes.
    Returns the effective key type.  Unmeasurable quota => the requested
    type as-is (the mid-stash EDQUOT rollback stays the backstop)."""
    q = quota_snapshot()
    if q is None:
        return key_type

    ldso_wire, have_ldso = 0, False
    if selfcontained and bytes(data[:4]) == b"\x7fELF":
        try:
            ipath = _pt_interp_path(data)
        except SystemExit:
            ipath = None   # invalid ELF: today's .ldso. path fails later
        if ipath is not None:
            try:
                hdr = KRH_HDR_LEN if _wire_sel() == 2 else KR3_HDR_LEN
                ldso_wire = hdr + os.stat(os.fsdecode(ipath)).st_size
                have_ldso = True
            except OSError:
                pass         # unreadable interpreter: ditto

    if not type_explicit and q["keys_max"]:
        nuser = _quota_chunks(wirelen, CHUNK_USER_MAX)
        nbk = _quota_chunks(wirelen, CHUNK_BIGKEY_MAX)
        if have_ldso:
            nuser += _quota_chunks(ldso_wire, CHUNK_USER_MAX)
            nbk += _quota_chunks(ldso_wire, CHUNK_BIGKEY_MAX)
        if q["keys_used"] + nuser > q["keys_max"] and \
                q["keys_used"] + nbk <= q["keys_max"]:
            key_type = KEY_TYPE_BIG_KEY
            sys.stderr.write("stash: auto big_key (chunk count would "
                             "exceed maxkeys)\n")

    pflen = len(prefix)
    needed = _quota_charge(key_type, pflen + 4, wirelen) + QUOTA_SLACK_ONCE
    total_keys = _quota_chunks(wirelen, _quota_chunkmax(key_type))
    if have_ldso:
        needed += _quota_charge(key_type, pflen + 9, ldso_wire)
        total_keys += _quota_chunks(ldso_wire, _quota_chunkmax(key_type))

    if q["bytes_max"] and needed > q["bytes_remaining"]:
        die("stash: needs ~%d bytes of keyring quota, ~%d remain "
            "(used %d/%d, live /proc/key-users measurement) — options: "
            "smaller payload; --type big_key (fewer, larger keys: "
            "100000-byte chunks; this kernel charges a big_key desc+21 "
            "and does NOT byte-charge its payload); run as root (25 MiB); "
            "or pool across UIDs with --share"
            % (needed, q["bytes_remaining"], q["bytes_used"],
               q["bytes_max"]))
    if q["bytes_max"] and needed > q["bytes_remaining"] // 2:
        sys.stderr.write("stash: warning: this stash would consume ~%d of "
                         "%d remaining quota bytes (>50%%)\n"
                         % (needed, q["bytes_remaining"]))
    if q["keys_max"] and q["keys_used"] + total_keys > q["keys_max"]:
        die("stash: needs %d keyring key(s) on top of %d/%d used "
            "(live /proc/key-users measurement) — options: --type big_key "
            "(fewer, larger keys — the maxkeys relief); smaller payload; "
            "run as root; or pool across UIDs with --share"
            % (total_keys, q["keys_used"], q["keys_max"]))
    return key_type


def _stash_payload(data, prefix, ring_serial, ring_desc, key=None,
                   selfcontained=False, key_type=KEY_TYPE_USER, share=False,
                   ttl=None, type_explicit=False):
    """stash the payload (wire v4 by default, or the KR_WIRE selection)
    and, with --selfcontained, the PT_INTERP interpreter (both wires
    auto-downgraded to v3 — v4 ldso support pending); then, with
    --share, setperm + print the share line; with --ttl, set a kernel
    expiry on every stored key.  Returns every stored serial in stored
    order."""
    if selfcontained and os.environ.get("KR_WIRE", "") == "4":
        die("stash: v4 experimental: not with --selfcontained yet")
    if selfcontained and _wire_sel() == 4:
        sys.stderr.write("stash: --selfcontained uses wire v3 "
                         "(v4 ldso support pending)\n")
    wire = _stash_wrap(data, key, selfcontained=selfcontained)
    key_type = _plan_quota(data, prefix, len(wire), key_type,
                           type_explicit, selfcontained)
    serials = _stash(wire, prefix, ring_serial, ring_desc, key_type,
                     _chunk_max_for(key_type))
    if selfcontained:
        serials += _stash_selfcontained(data, prefix, ring_serial,
                                        ring_desc, key_type,
                                        rollback=serials)
    if share:
        _share_serials(serials)
    _apply_ttl(serials, ttl)
    return serials


# ---------------------------------------------------------------------------
# phase 2: reassemble from the keyring, revoking each key right after read
# ---------------------------------------------------------------------------

def _persistent_serial(strict):
    """GET_PERSISTENT for this uid.  On this kernel dest serial 0 fails with
    EINVAL; retrying with the user keyring (@u) as dest works and still
    returns the persistent.<uid> serial (mirrors kr_core persistent_ring)."""
    serial = _keyctl(KEYCTL_GET_PERSISTENT, os.getuid(), 0)
    if serial == -1 and ctypes.get_errno() == errno.EINVAL:
        serial = _keyctl(KEYCTL_GET_PERSISTENT, os.getuid(), KEY_SPEC_USER_KEYRING)
    if serial == -1:
        if strict:
            die("persistent keyring unavailable: %s" % _errno_str())
        return None
    return serial


def _persistent_probe():
    """GET_PERSISTENT for this uid, or None if the kernel does not have it."""
    return _persistent_serial(False)


def _request_any_type(desc, ring):
    """request_key `desc` in `ring`, trying the "user" type first and then
    "big_key" (v2.2).  A live key wins immediately ("user" preferred).
    EKEYREVOKED (revoked residue pending kernel GC) is remembered but the
    remaining types are still tried — it must not mask a live stash of the
    other type; any other hard error aborts.  Returns (serial, errno)."""
    best = errno.ENOKEY
    for kt in KEY_TYPES:
        serial = _request_key(desc, ring, kt)
        if serial != -1:
            return serial, 0
        e = ctypes.get_errno()
        if e != errno.ENOKEY and e != errno.EKEYREVOKED:
            return -1, e
        if e == errno.EKEYREVOKED:
            best = e
    return -1, best


def _decide_ring(prefix):
    """Chunk 000 decides which ring holds the stash: the session keyring
    first, else the per-UID persistent ring (KEYCTL_GET_PERSISTENT serial +
    KEYCTL_SEARCH lookup).  v2.2: per index the "user" type is tried first,
    then "big_key".  The whole sequence is then read from that one ring —
    no mixing (keyringer.h).  Returns (ring, errno); ring is None when
    chunk 000 could not be found/used."""
    desc = _desc(prefix, 0)
    serial, e = _request_any_type(desc, KEY_SPEC_SESSION_KEYRING)
    if serial != -1:
        return KEY_SPEC_SESSION_KEYRING, 0
    if e not in (errno.ENOKEY, errno.EKEYREVOKED):
        return None, e
    ps = _persistent_probe()
    if ps is not None:
        best = e
        for kt in KEY_TYPES:
            serial = _keyctl(KEYCTL_SEARCH, ps, kt, desc, 0)
            if serial != -1:
                return ps, 0
            ce = ctypes.get_errno()
            if ce != errno.ENOKEY and ce != errno.EKEYREVOKED:
                return None, ce
            if ce == errno.EKEYREVOKED:
                best = ce
        e = best
    return None, e


def _revoke_from(prefix, idx):
    """best-effort revoke of every remaining chunk key from idx onward
    (v2.2: checks both "user" and "big_key" per description)."""
    for i in range(idx, IDX_MAX + 1):
        desc = _desc(prefix, i)
        found = False
        for kt in KEY_TYPES:
            serial = _request_key(desc, KEY_SPEC_SESSION_KEYRING, kt)
            if serial != -1:
                _keyctl(KEYCTL_REVOKE, serial)
                found = True
            elif ctypes.get_errno() != errno.ENOKEY:
                return
        if not found:
            break


def _revoke_sweep(prefix):
    """best-effort clean slate for the selftest: revoke + unlink every live
    or revoked-but-not-yet-GCed <prefix>.* "user"/"big_key" key on this
    session's keyring.  (The stash/exec paths keep the C tool's behavior: a
    revoked leftover makes load() die with a clear message instead.)"""
    ring = _keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0)
    if ring == -1:
        return
    n = _keyctl(KEYCTL_READ, ring, None, 0)     # keyring read = serial array
    if n <= 0:
        return
    buf = ctypes.create_string_buffer(n)
    got = _keyctl(KEYCTL_READ, ring, buf, n)
    if got <= 0:
        return
    raw = buf.raw[:got]
    want = (prefix + ".").encode()
    for i in range(len(raw) // 4):
        serial = struct.unpack_from("<I", raw, i * 4)[0]
        dsz = _keyctl(KEYCTL_DESCRIBE, serial, None, 0)
        if dsz <= 0:
            continue
        db = ctypes.create_string_buffer(dsz)
        if _keyctl(KEYCTL_DESCRIBE, serial, db, dsz) <= 0:
            continue
        fields = db.raw.split(b";", 4)
        if len(fields) < 5 or fields[0] not in (b"user", b"big_key"):
            continue
        desc = fields[4].split(b"\x00", 1)[0]
        if not desc.startswith(want):
            continue
        _keyctl(KEYCTL_REVOKE, serial)          # harmless if already dead
        _keyctl(KEYCTL_UNLINK, ring, serial)


def _read_serial_chunk(serial, label):
    """KEYCTL_READ probe + read of one key serial into a fresh bytearray,
    then an immediate best-effort revoke (EPERM/EACCES — and any other
    revoke error — only warn, never abort).  Used by _load (request_key
    path) and _load_from (--from serial path).  Returns the data; the
    caller zeroizes it."""
    size = _keyctl(KEYCTL_READ, serial, None, 0)
    if size == -1:
        e = ctypes.get_errno()
        if e == errno.EKEYREVOKED:
            die("load: key %d (\"%s\") is revoked — stale or already "
                "consumed stash" % (serial, label))
        die("load: keyctl(READ, key %d) size probe failed: %s"
            % (serial, os.strerror(e)))
    data = bytearray()
    if size > 0:
        # read straight into a bytearray we own, so it can be zeroized
        data = bytearray(size)
        view = (ctypes.c_char * size).from_buffer(data)
        got = _keyctl(KEYCTL_READ, serial, view, size)
        del view
        if got == -1:
            e = ctypes.get_errno()
            if e == errno.EKEYREVOKED:
                die("load: key %d (\"%s\") was revoked before its read "
                    "completed" % (serial, label))
            die("load: keyctl(READ, key %d) failed: %s"
                % (serial, os.strerror(e)))
        del data[got:]                   # KEYCTL_READ may report short

    # read complete — revoke immediately (best-effort, nonfatal).
    # --scrub instead destroys the key with KEYCTL_INVALIDATE while we
    # still possess it: dead immediately and swept at the next keyring GC,
    # versus an R-flag ghost that lingers.  (Order matters: after an
    # unlink we lose possession and invalidate fails EACCES.)
    if SCRUB:
        if _keyctl(KEYCTL_INVALIDATE, serial) == -1:
            sys.stderr.write(
                "keyringer: load: warning: invalidate of key %d failed: %s "
                "(nonfatal)\n" % (serial, _errno_str()))
        else:
            sys.stderr.write("load: %s -> key %d, %d bytes, invalidated\n"
                             % (label, serial, len(data)))
        return data
    if _keyctl(KEYCTL_REVOKE, serial) == -1:
        sys.stderr.write(
            "keyringer: load: warning: revoke of key %d failed: %s "
            "(nonfatal)\n" % (serial, _errno_str()))
    sys.stderr.write("load: %s -> key %d, %d bytes, revoked\n"
                     % (label, serial, len(data)))
    return data


def _request_chunk(prefix, i, ring_sel):
    """request_key chunk i in `ring_sel` across both types (v2.2: "user"
    first, then "big_key").  Returns (serial, errno); serial is -1 on miss."""
    return _request_any_type(_desc(prefix, i), ring_sel)


def _load(prefix, ring_sel=None):
    if ring_sel is None:
        ring_sel, e = _decide_ring(prefix)
        if ring_sel is None:
            if e == errno.ENOKEY:
                die("load: no %s.* keys found on the session keyring "
                    "(stash first)" % prefix)
            _revoke_from(prefix, 0)
            if e == errno.EKEYREVOKED:
                die("load: \"%s\" is revoked (leftover of a consumed stash); "
                    "no live %s.* stash found — stash again"
                    % (_desc(prefix, 0).decode(), prefix))
            die("load: request_key(\"%s\") failed: %s"
                % (_desc(prefix, 0).decode(), os.strerror(e)))

    wire = bytearray()          # reassembled wire payload (v2.2: header||body)
    nchunks = 0
    for i in range(IDX_MAX + 1):
        desc = _desc(prefix, i)
        serial, e = _request_chunk(prefix, i, ring_sel)
        if serial == -1:
            if e == errno.ENOKEY:
                break                    # first gap == chunk count
            if e == errno.EKEYREVOKED:
                break     # revoked chunk at the gap: leftover of a previous
                          # consumed stash poking out under this prefix —
                          # sequence ends here (matches kr_core.c); a
                          # truncated live stash is caught by the digest.
            _revoke_from(prefix, i + 1)
            die("load: request_key(\"%s\") failed: %s"
                % (desc.decode(), os.strerror(e)))

        data = _read_serial_chunk(serial, desc.decode())
        wire += data
        data[:] = b"\x00" * len(data)        # zeroize the chunk buffer
        nchunks += 1

    if nchunks == 0:
        die("load: no %s.* keys found on the session keyring (stash first)"
            % prefix)
    sys.stderr.write("load: %d chunk(s), %d bytes reassembled\n"
                     % (nchunks, len(wire)))
    return wire


def _load_from(serials):
    """--from s1,s2,...: read chunk i straight from the i-th serial via a
    KEYCTL_READ probe+read — NO request_key anywhere.  Revocation stays
    best-effort (EPERM/EACCES nonfatal, see _read_serial_chunk).  The
    caller KRH1-verifies the reassembled wire as usual."""
    wire = bytearray()
    for i, serial in enumerate(serials):
        data = _read_serial_chunk(serial, "--from[%d] serial %d"
                                  % (i, serial))
        wire += data
        data[:] = b"\x00" * len(data)        # zeroize the chunk buffer
    sys.stderr.write("load: %d chunk(s) via --from serials, %d bytes "
                     "reassembled\n" % (len(serials), len(wire)))
    return wire


def _load_ldso(prefix):
    """--selfcontained exec side: reassemble the interpreter from
    <prefix>.ldso.* chunks (same request_key-until-ENOKEY, user-then-
    persistent ring logic as the payload) and KRH1-verify it.  The ldso
    wire is ALWAYS plaintext (flags=0), so no key is applied here."""
    lp = _ldso_prefix(prefix)
    ibuf = _load_unwrap(_load(lp), None)
    sys.stderr.write("exec: selfcontained interpreter reassembled from %s.* "
                     "(KRH1-verified), %d bytes\n" % (lp, len(ibuf)))
    return ibuf


# ---------------------------------------------------------------------------
# phase 3: userland exec (no exec-family syscall, no memfd)
# ---------------------------------------------------------------------------

def _validate_elf(data, what):
    if len(data) < 64:
        die("%s: %d bytes: too small for an ELF header" % (what, len(data)))
    if data[:4] != b"\x7fELF":
        die("%s: missing \\x7fELF magic" % what)
    if data[4] != ELFCLASS64:
        die("%s: unsupported EI_CLASS %d (ELFCLASS64 required)"
            % (what, data[4]))
    if data[5] != ELFDATA2LSB:
        die("%s: unsupported EI_DATA %d (ELFDATA2LSB required)"
            % (what, data[5]))
    (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize,
     e_phentsize, e_phnum, e_shentsize, e_shnum,
     e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    if e_machine != EM_X86_64:
        die("%s: unsupported e_machine %d (EM_X86_64 required)"
            % (what, e_machine))
    if e_type not in (ET_EXEC, ET_DYN):
        die("%s: unsupported e_type %d (only ET_EXEC/ET_DYN)" % (what, e_type))
    if e_phentsize != 56:
        die("%s: e_phentsize %d != 56" % (what, e_phentsize))
    if e_phnum == 0 or e_phnum == PN_XNUM:
        die("%s: bad e_phnum %d" % (what, e_phnum))
    if e_phoff == 0 or e_phoff + e_phnum * 56 > len(data):
        die("%s: program header table out of bounds" % what)
    phdrs = []
    for i in range(e_phnum):
        (p_type, p_flags, p_off, p_vaddr, _paddr, p_filesz, p_memsz,
         _align) = struct.unpack_from("<IIQQQQQQ", data, e_phoff + i * 56)
        phdrs.append({"type": p_type, "flags": p_flags, "off": p_off,
                      "vaddr": p_vaddr, "filesz": p_filesz, "memsz": p_memsz})
    return {"e_type": e_type, "e_entry": e_entry, "e_phoff": e_phoff,
            "e_phnum": e_phnum, "e_phentsize": e_phentsize,
            "e_shoff": e_shoff, "e_shnum": e_shnum,
            "e_shentsize": e_shentsize, "phdrs": phdrs}


def _map_pt_loads(data, phdrs, base, what):
    for i, p in enumerate(phdrs):
        if p["type"] != PT_LOAD or p["memsz"] == 0:
            continue
        if p["memsz"] < p["filesz"]:
            die("%s: PT_LOAD %d: p_memsz < p_filesz" % (what, i))
        if p["off"] + p["filesz"] > len(data):
            die("%s: PT_LOAD %d: file range out of bounds" % (what, i))
        vstart = _page_down(base + p["vaddr"])
        vend = _page_up(base + p["vaddr"] + p["memsz"])
        try:
            got = _mmap(vstart, vend - vstart, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE)
        except _MmapError as ex:
            die("%s: mmap PT_LOAD %d at 0x%08x failed: %s"
                % (what, i, vstart, ex))
        if got != vstart:
            _munmap(got, vend - vstart)
            die("%s: mmap PT_LOAD %d: wanted 0x%08x, got 0x%08x"
                % (what, i, vstart, got))
        # image region: keep it out of core dumps and forks (best-effort),
        # and give it the C tool's PR_SET_VMA label
        _madvise(vstart, vend - vstart, MADV_DONTDUMP, MADV_WIPEONFORK)
        _vma_name(vstart, vend - vstart, VMA_NAME_IMAGE)
        ctypes.memmove(base + p["vaddr"],
                       bytes(data[p["off"]:p["off"] + p["filesz"]]),
                       p["filesz"])
        # BSS tail is already zero (anonymous pages); skip a defensive memset.
        prot = 0
        if p["flags"] & PF_R:
            prot |= PROT_READ
        if p["flags"] & PF_W:
            prot |= PROT_WRITE
        if p["flags"] & PF_X:
            prot |= PROT_EXEC
        _mprotect_checked(vstart, vend - vstart, prot, what, i)


def _load_image(data, what, mode, hint):
    """validate + map one image; mode: 'fixed' | 'probe' | 'hint'."""
    eh = _validate_elf(data, what)
    lo, hi = _M64, 0
    interp = None
    for p in eh["phdrs"]:
        if p["type"] == PT_LOAD:
            if p["memsz"] == 0:
                continue
            lo = min(lo, p["vaddr"])
            hi = max(hi, p["vaddr"] + p["memsz"])
        elif p["type"] == PT_INTERP:
            if p["off"] >= len(data) or p["off"] + p["filesz"] > len(data):
                die("%s: PT_INTERP out of bounds" % what)
            raw = data[p["off"]:p["off"] + p["filesz"]]
            if b"\x00" not in raw:
                die("%s: PT_INTERP path not NUL-terminated" % what)
            # bytes (not bytearray): os.fsdecode/open need a bytes-like
            # that is not a memoryview-ish buffer
            interp = bytes(raw.split(b"\x00", 1)[0])
    if lo > hi:
        die("%s: no non-empty PT_LOAD segments" % what)
    lo = _page_down(lo)
    hi = _page_up(hi)
    span = hi - lo

    if mode == "fixed":
        base = 0
    elif mode == "probe":
        probe = _mmap(0, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS)
        base = probe - lo
        _munmap(probe, span)
    else:
        base = _page_up(hint) - lo

    _map_pt_loads(data, eh["phdrs"], base, what)
    return {"ehdr": eh, "phdrs": eh["phdrs"], "base": base, "span": span,
            "entry": base + eh["e_entry"], "interp": interp}


def _phdr_addr_in_image(img):
    eh = img["ehdr"]
    need_off = eh["e_phoff"]
    need_end = need_off + eh["e_phnum"] * eh["e_phentsize"]
    for p in img["phdrs"]:
        if p["type"] != PT_LOAD or p["memsz"] == 0:
            continue
        if need_off >= p["off"] and need_end <= p["off"] + p["filesz"]:
            return img["base"] + p["vaddr"] + (need_off - p["off"])
    return 0


def _build_process_stack(spoof, args, at_phdr, at_phent, at_phnum, at_entry,
                         at_base):
    """fresh 8 MB stack with the SysV process-start layout; returns final rsp."""
    argv_b = [os.fsencode(spoof)] + [os.fsencode(a) for a in args]
    env_b = _raw_envp()
    stk = _mmap(0, STACK_SIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK)
    _madvise(stk, STACK_SIZE, MADV_DONTDUMP, MADV_WIPEONFORK)
    _vma_name(stk, STACK_SIZE, VMA_NAME_STACK)
    cur = stk + STACK_SIZE

    def push(b):
        nonlocal cur
        cur -= len(b)
        ctypes.memmove(cur, b, len(b))
        return cur

    astr = [push(s + b"\x00") for s in argv_b]
    estr = [push(e + b"\x00") for e in env_b]
    platform_ptr = push(b"x86_64\x00")
    random_ptr = push(secrets.token_bytes(16))
    execfn_ptr = push(os.fsencode(spoof) + b"\x00")

    slots = 1 + (len(astr) + 1) + (len(estr) + 1) + 17 * 2
    slots += slots & 1                      # even: final rsp 16-byte aligned
    cur &= ~0xF
    sp = cur - slots * 8
    if sp - stk < 4096:
        die("new stack layout overflow")

    vec = [len(astr)]
    vec += astr
    vec.append(0)
    vec += estr
    vec.append(0)
    aux = (
        (AT_PHDR, at_phdr),
        (AT_PHENT, at_phent),
        (AT_PHNUM, at_phnum),
        (AT_PAGESZ, _PAGESZ),
        (AT_ENTRY, at_entry),
        (AT_BASE, at_base),
        (AT_RANDOM, random_ptr),
        (AT_EXECFN, execfn_ptr),
        (AT_UID, os.getuid()),
        (AT_EUID, os.geteuid()),
        (AT_GID, os.getgid()),
        (AT_EGID, os.getegid()),
        (AT_SECURE, 0),
        (AT_HWCAP, _auxv_get(AT_HWCAP)),
        (AT_PLATFORM, platform_ptr),
        (AT_SYSINFO_EHDR, _auxv_get(AT_SYSINFO_EHDR)),
        (AT_NULL, 0),
    )
    for t, v in aux:
        vec.append(t)
        vec.append(v)
    ctypes.memmove(sp, struct.pack("<%dQ" % len(vec),
                                   *[v & _M64 for v in vec]), 8 * len(vec))
    return sp


def _prctl_spoof(spoof):
    name = os.fsencode(spoof)[:15]
    if _libc.prctl(PR_SET_NAME, ctypes.c_char_p(name), 0, 0, 0) == -1:
        sys.stderr.write(
            "keyringer: warning: prctl(PR_SET_NAME) failed: %s\n"
            % _errno_str())


def _trampoline(entry, sp):
    """write the stack-switch stub and jump; never returns.

    movabs rdi, entry ; xor edx,edx ; xor ebp,ebp ; movabs rsp, sp ; jmp rdi
    (rdx is read as rtld_fini by interpreters, so it is zeroed)
    """
    stub = _mmap(0, _PAGESZ, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS)
    _madvise(stub, _PAGESZ, MADV_DONTDUMP)
    _vma_name(stub, _PAGESZ, VMA_NAME_BUF)
    code = (b"\x48\xBF" + struct.pack("<Q", entry) +
            b"\x48\x31\xD2" +
            b"\x48\x31\xED" +
            b"\x48\xBC" + struct.pack("<Q", sp) +
            b"\xFF\xE7")
    ctypes.memmove(stub, code, len(code))
    ctypes.CFUNCTYPE(None)(stub)()
    die("trampoline returned (unreachable)")      # pragma: no cover


def _go(entry, at_base, at_phdr, eh, main_img, spoof, args, how):
    sp = _build_process_stack(spoof, args, at_phdr, eh["e_phentsize"],
                              eh["e_phnum"], main_img["entry"], at_base)
    sys.stderr.write('exec: jumping to entry 0x%08x (%s), base=0x%08x, '
                     'as "%s"\n' % (entry, how, at_base, spoof))
    _prctl_spoof(spoof)
    _no_dumpable()
    sys.stdout.flush()
    sys.stderr.flush()
    # every chunk key was already revoked by _load() before we got here
    _trampoline(entry, sp)


def _execute_elf(img, spoof, args, ldso_prefix=None):
    """full ELF load: PT_LOADs, optional PT_INTERP, SysV stack, trampoline.

    With ldso_prefix (--selfcontained exec), the interpreter is reassembled
    from <prefix>.ldso.* keys and KRH1-verified instead of read from the
    PT_INTERP disk path; without it, disk behavior is unchanged."""
    eh = _validate_elf(img, "payload")
    mode = "fixed" if eh["e_type"] == ET_EXEC else "probe"
    main = _load_image(img, "payload", mode, 0)

    have_interp = False
    interp = None
    ibuf = None
    if main["interp"]:
        ipath = main["interp"]
        if ldso_prefix is not None:
            ibuf = _load_ldso(ldso_prefix)
            interp = _load_image(ibuf, os.fsdecode(ipath) + " (selfcontained)",
                                 "hint",
                                 main["base"] + main["span"] + INTERP_GAP)
        else:
            try:
                with open(ipath, "rb") as fh:
                    ibuf = bytearray(fh.read())
            except OSError as ex:
                die("payload: open interpreter %s: %s"
                    % (os.fsdecode(ipath), ex.strerror))
            interp = _load_image(ibuf, os.fsdecode(ipath), "hint",
                                 main["base"] + main["span"] + INTERP_GAP)
        have_interp = True

    jump_entry = interp["entry"] if have_interp else main["entry"]
    at_base = interp["base"] if have_interp else 0

    at_phdr = _phdr_addr_in_image(main)
    if not at_phdr:
        phsz = eh["e_phnum"] * eh["e_phentsize"]
        scratch = _mmap(0, _PAGESZ, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS)
        _madvise(scratch, _PAGESZ, MADV_DONTDUMP)
        _vma_name(scratch, _PAGESZ, VMA_NAME_BUF)
        ctypes.memmove(scratch, bytes(img[eh["e_phoff"]:eh["e_phoff"] + phsz]),
                       phsz)
        at_phdr = scratch

    # every loader-side read of the payload/interp images is done — zeroize
    # them before the jump (the mapped images carry the live copy)
    img[:] = b"\x00" * len(img)
    if ibuf is not None:
        ibuf[:] = b"\x00" * len(ibuf)
    _go(jump_entry, at_base, at_phdr, eh, main, spoof, args,
        "via interpreter" if have_interp else "direct")


def _execute_raw(img, spoof, args):
    """--raw: skip ELF parsing entirely, single RWX mmap + trampoline jump."""
    if not img:
        die("raw exec: empty payload")
    length = _page_up(len(img))
    addr = _mmap(0, length, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS)
    _madvise(addr, length, MADV_DONTDUMP, MADV_WIPEONFORK)
    _vma_name(addr, length, VMA_NAME_IMAGE)
    ctypes.memmove(addr, bytes(img), len(img))
    img[:] = b"\x00" * len(img)          # zeroize the loader-side copy
    sys.stderr.write('exec: raw jump to 0x%08x, as "%s"\n' % (addr, spoof))
    sp = _build_process_stack(spoof, args, 0, 0, 0, addr, 0)
    _prctl_spoof(spoof)
    _no_dumpable()
    sys.stdout.flush()
    sys.stderr.flush()
    _trampoline(addr, sp)


# ----- --call SYM: sections, symbols, relocations --------------------------

def _sections(data, eh, what):
    if eh["e_shoff"] == 0 or eh["e_shnum"] == 0:
        return []
    if eh["e_shentsize"] != 64:
        die("%s: e_shentsize %d != 64" % (what, eh["e_shentsize"]))
    if eh["e_shoff"] + eh["e_shnum"] * 64 > len(data):
        die("%s: section header table out of bounds" % what)
    out = []
    for i in range(eh["e_shnum"]):
        (sh_name, sh_type, sh_flags, _sh_addr, sh_offset, sh_size, sh_link,
         _sh_info, _sh_addralign,
         _sh_entsize) = struct.unpack_from("<IIQQQQIIQQ", data,
                                           eh["e_shoff"] + i * 64)
        out.append({"type": sh_type, "flags": sh_flags, "off": sh_offset,
                    "size": sh_size, "link": sh_link})
    return out


def _sec_bytes(data, sec, what):
    if sec["off"] + sec["size"] > len(data):
        die("%s: section out of bounds" % what)
    return data[sec["off"]:sec["off"] + sec["size"]]


def _read_symbols(data, sec):
    if sec is None:
        return []
    raw = _sec_bytes(data, sec, "symtab")
    out = []
    for i in range(sec["size"] // 24):
        (st_name, _st_info, _st_other, st_shndx, st_value,
         _st_size) = struct.unpack_from("<IBBHQQ", raw, i * 24)
        out.append({"name_off": st_name, "shndx": st_shndx, "value": st_value})
    return out


def _apply_relocs(data, secs, base, what):
    symtab = None
    for s in secs:
        if s["type"] == SHT_SYMTAB:
            symtab = s
            break
    if symtab is None:
        for s in secs:
            if s["type"] == SHT_DYNSYM:
                symtab = s
                break
    syms = _read_symbols(data, symtab)
    for s in secs:
        # only allocated RELA sections (.rela.dyn/.rela.plt) touch memory
        if s["type"] != SHT_RELA or not (s["flags"] & SHF_ALLOC):
            continue
        raw = _sec_bytes(data, s, "rela")
        for i in range(s["size"] // 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", raw,
                                                            i * 24)
            rtype = r_info & 0xFFFFFFFF
            symidx = r_info >> 32
            if rtype == R_X86_64_NONE:
                continue
            if rtype == R_X86_64_RELATIVE:
                _wr64(base + r_offset, base + r_addend)
            elif rtype in (R_X86_64_64, R_X86_64_GLOB_DAT,
                           R_X86_64_JUMP_SLOT):
                if not syms:
                    die("%s: relocation but no symbol table" % what)
                if symidx >= len(syms):
                    die("%s: relocation symbol index %d out of range"
                        % (what, symidx))
                st = syms[symidx]
                if st["shndx"] == SHN_UNDEF:
                    die("%s: relocation against undefined symbol "
                        "(index %d) — define or statically link it"
                        % (what, symidx))
                if st["shndx"] == SHN_ABS:
                    val = st["value"] + r_addend
                elif st["shndx"] >= SHN_LORESERVE:
                    die("%s: relocation against special section index 0x%x"
                        % (what, st["shndx"]))
                else:
                    val = base + st["value"] + r_addend
                _wr64(base + r_offset, val)
            else:
                die("%s: unsupported relocation type %d "
                    "(only RELATIVE/64/GLOB_DAT/JUMP_SLOT)" % (what, rtype))


def _find_symbol(data, secs, name):
    want = name.encode() if isinstance(name, str) else name
    order = ([s for s in secs if s["type"] == SHT_SYMTAB] +
             [s for s in secs if s["type"] == SHT_DYNSYM])
    fallback = None
    for symsec in order:
        raw = _sec_bytes(data, symsec, "symtab")
        link = symsec["link"]
        stab = (_sec_bytes(data, secs[link], "strtab")
                if 0 <= link < len(secs) else b"")
        for i in range(symsec["size"] // 24):
            (st_name, _info, _other, st_shndx, st_value,
             _size) = struct.unpack_from("<IBBHQQ", raw, i * 24)
            if st_name >= len(stab):
                continue
            end = stab.find(b"\x00", st_name)
            if end < 0:
                end = len(stab)
            if stab[st_name:end] != want:
                continue
            if st_shndx != SHN_UNDEF:
                return {"value": st_value, "shndx": st_shndx}
            if fallback is None:
                fallback = st_shndx
    if fallback is not None:
        die('payload: symbol "%s" is undefined (SHN_UNDEF)' % name)
    die('payload: symbol "%s" not found in the symbol table' % name)


def _execute_call(img, sym, spoof, args):
    """--call SYM: map, apply RELA relocs, call SYM(argc, argv, envp) on the
    normal stack."""
    eh = _validate_elf(img, "payload")
    mode = "fixed" if eh["e_type"] == ET_EXEC else "probe"
    main = _load_image(img, "payload", mode, 0)
    secs = _sections(img, eh, "payload")
    if not secs:
        die("payload: no section header table — --call needs an "
            "unstripped ELF")
    base = main["base"]
    _apply_relocs(img, secs, base, "payload")
    st = _find_symbol(img, secs, sym)
    addr = st["value"] if st["shndx"] == SHN_ABS else base + st["value"]

    payload_argv = [spoof] + list(args)
    argv_arr = (ctypes.c_char_p * (len(payload_argv) + 1))(
        *[os.fsencode(a) for a in payload_argv], None)
    envb = _raw_envp()
    env_arr = (ctypes.c_char_p * (len(envb) + 1))(*envb, None)
    proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int,
                             ctypes.POINTER(ctypes.c_char_p),
                             ctypes.POINTER(ctypes.c_char_p))
    sys.stderr.write('call: %s at 0x%08x (base 0x%08x), as "%s"\n'
                     % (sym, addr, base, spoof))
    _prctl_spoof(spoof)
    _no_dumpable()
    sys.stdout.flush()
    sys.stderr.flush()
    img[:] = b"\x00" * len(img)          # zeroize the loader-side copy
    ret = proto(addr)(len(payload_argv), argv_arr, env_arr)
    sys.exit(ret & 0xFF)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

USAGE = """keyringer.py — Linux x86-64 kernel-keyring fileless exec loader (stdlib port, wire v%s)

usage:
  keyringer.py stash <file|->             store payload in kernel keyring (chunked); prints serials
  keyringer.py kfile <elf> [name] [args...]  stash from file, then revoke+load+execute
  keyringer.py kstdin [name] [args...]    stash from stdin, then revoke+load+execute
  keyringer.py exec [name] [args...]      load previously-stashed keys, revoke, execute
  keyringer.py list [--json]              list <prefix>.* keys visible to this user (parse /proc/keys)
  keyringer.py gc [--desc P]              DESTROY every visible <P>.* key via KEYCTL_INVALIDATE
  keyringer.py keygen                     print a fresh 32-byte key as 64 hex chars on stdout
  keyringer.py preflight                  environment report: seccomp, SELinux/AppArmor, W^X self-test,
                                          kernel.keys limits, AF_ALG binds (exit 0 unless W^X denied)
  keyringer.py selftest                   crypto + keyring roundtrip self test
  keyringer.py help                       show this help

flags (may appear anywhere after the subcommand):
  --desc PREFIX   key description prefix (default "_keyringer", env KEYRINGER_DESC)
  --key HEX       64-hex-char ChaCha20-Poly1305 key; KR1-envelope the stash
                  (env KEYRINGER_KEY)
  --keyfd N       read the key from fd N until EOF: raw 32 bytes or 64 hex
                  chars (trimmed); precedence --key > --keyfd > KEYRINGER_KEY
  --ttl SECONDS   stash: kernel expires every stored key after SECONDS
  --scrub         exec: destroy each chunk with KEYCTL_INVALIDATE after its
                  read instead of revoking (dead immediately, swept at the
                  next keyring GC; nothing is replayable)
  --json          machine-readable output for `list`
  --type TYPE     stash key type: "user" (default, 30000-byte wire chunks) or
                  "big_key" (100000-byte wire chunks); exec lookup per chunk
                  index tries "user" first, then "big_key", either way
  --selfcontained stash-side: also stash the payload's PT_INTERP interpreter
                  under <prefix>.ldso.<idx> (wire KRH1 flags=0, ALWAYS
                  plaintext regardless of --key).  exec-side: reassemble +
                  KRH1-verify the interpreter from those chunks and map it
                  instead of reading the disk path.  Without the flag:
                  unchanged disk behavior.
  --persistent    use the per-UID persistent keyring instead of the session ring
  --share         stash: KEYCTL_SETPERM (op 5) every stored serial to
                  0x3f3f0000, then print "share: <s1>,<s2>,..." on stdout
  --from S1,S2,…  exec: read chunk i straight from serial Si via KEYCTL_READ
                  probe+read (no request_key); revoke stays best-effort
                  (EPERM/EACCES nonfatal); KRH1 verification unchanged
  --raw           skip ELF parsing; map the payload RWX and jump to it
  --call SYM      map the ELF, apply RELATIVE/64/GLOB_DAT/JUMP_SLOT relocs,
                  then call SYM(argc, argv, envp) on the normal stack

wire protocol v2.2: every stash carries a 40-byte b"KRH1" || flags ||
  sha256(plaintext) header, prepended before chunking (digest always covers
  the plaintext).  load verifies the digest after optional KR1 decryption
  and refuses to execute on mismatch.  Pre-v2 headerless stashes still
  load; a KR1 body without a header notes "no integrity digest (pre-v2
  stash)".  .ldso. interpreter stashes are always plaintext (flags=0).
  The header adds 40 bytes of keyring quota per stash; the live per-UID
  pool is measured (quota_snapshot()) and stashes are planned upfront
  against it (refuse-before-store, auto big_key when maxkeys would bind;
  on this kernel a big_key charges desc+21 bytes, NOT its payload).

NOT mirrored from the keyringer (C) tool — implemented there only, the
  python twin refuses them cleanly: agent, keepalive, --clone, khttp and
  its --proxy/--header/--insecure options, and the aarch64 build.  This
  twin is x86_64-only and exits cleanly on any other machine.

hardening: prctl(PR_SET_DUMPABLE, 0) after the PR_SET_NAME spoof,
  MADV_DONTDUMP/WIPEONFORK on image+stack mappings and MADV_DONTDUMP on
  scratch mappings, PR_SET_VMA labels ([anon:libc:heap] image,
  [anon:libc:tls] stack, [anon:libc:buf] scratch; best-effort), and
  zeroization of all loader-side buffers before the jump/call.

default spoof name when [name] is omitted: kworker/u8:2
""" % KR_VERSION


def _usage(fh):
    fh.write(USAGE)


def _parse_tokens(tokens):
    """flags anywhere after the subcommand; positionals keep their order."""
    valued = {"--desc": "desc", "--key": "key", "--call": "call",
              "--keyfd": "keyfd", "--type": "type", "--from": "from",
              "--ttl": "ttl"}
    boolean = {"--persistent": "persistent", "--raw": "raw",
               "--selfcontained": "selfcontained", "--share": "share",
               "--scrub": "scrub", "--json": "json",
               "--keep-ring": "keep_ring"}
    pos, flags = [], {"desc": None, "key": None, "call": None,
                      "keyfd": None, "type": None, "from": None,
                      "persistent": False, "raw": False,
                      "selfcontained": False, "share": False,
                      "ttl": None, "scrub": False, "json": False,
                      "keep_ring": False}
    global SCRUB
    SCRUB = False
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in valued:
            i += 1
            if i >= len(tokens):
                die("flag %s requires a value" % t)
            flags[valued[t]] = tokens[i]
        elif t in boolean:
            flags[boolean[t]] = True
            if boolean[t] == "scrub":
                SCRUB = True
        elif t in C_ONLY_FLAGS:
            _c_only(t)
        elif t.startswith("--"):
            die("unknown flag '%s'" % t)
        else:
            pos.append(t)
        i += 1
    return pos, flags


def _c_only(what):
    """one-line clean refusal for features implemented in the keyringer (C)
    tool only (agent, keepalive, --clone, khttp --proxy/--header/--insecure,
    aarch64) — see the module docstring."""
    die("%s is implemented in the keyringer (C) tool only — see keyringer "
        "(C) tool" % what)


def _resolve_prefix(flags):
    return flags["desc"] or os.environ.get(ENV_DESC) or DEFAULT_PREFIX


def _key_from_fd(fdstr):
    """--keyfd N: read the key from fd N until EOF; accept raw 32 bytes or
    64 hex chars (trimmed)."""
    try:
        fd = int(fdstr)
    except (TypeError, ValueError):
        die("--keyfd: need an integer file descriptor, got %r" % (fdstr,))
    if fd < 0:
        die("--keyfd: bad file descriptor %d" % fd)
    parts = []
    while True:
        try:
            b = os.read(fd, 4096)
        except OSError as ex:
            die("--keyfd: read fd %d failed: %s" % (fd, ex.strerror))
        if not b:
            break
        parts.append(b)
    raw = b"".join(parts)
    if len(raw) == 32:
        return raw                          # raw 32-byte key
    return _parse_key(raw.decode("ascii", "replace").strip())


def _resolve_key(flags):
    """key precedence (v2.2): --key > --keyfd > KEYRINGER_KEY env."""
    if flags["key"]:
        if flags["keyfd"] is not None:
            sys.stderr.write("keyringer: --key overrides --keyfd\n")
        return _parse_key(flags["key"])
    if flags["keyfd"] is not None:
        return _key_from_fd(flags["keyfd"])
    hexkey = os.environ.get(ENV_KEY)
    return _parse_key(hexkey) if hexkey else None


def _resolve_key_type(flags):
    """--type user|big_key (stash side; exec lookup always tries both)."""
    v = flags["type"]
    if v is None:
        return KEY_TYPE_USER
    if v not in ("user", "big_key"):
        die("--type: unknown key type %r (user|big_key)" % v)
    return v.encode()


def _parse_from(val):
    """--from s1,s2,...: comma-separated positive key serials."""
    out = []
    for part in val.split(","):
        part = part.strip()
        if not part:
            die("--from: empty serial in %r" % val)
        try:
            s = int(part)
        except ValueError:
            die("--from: serials must be integers, got %r" % part)
        if s <= 0:
            die("--from: serials must be positive, got %d" % s)
        out.append(s)
    if not out:
        die("--from: need at least one serial")
    return out


def cmd_stash(tokens):
    pos, flags = _parse_tokens(tokens)
    if not pos:
        _usage(sys.stderr)
        return 1
    path = pos[0]
    data = _read_stdin() if path == "-" else _read_file(path)
    key = _resolve_key(flags)
    if key:
        sys.stderr.write("stash: KR1 envelope (ChaCha20-Poly1305, impl=%s)\n"
                         % aead_impl())
    if flags["persistent"]:
        ring = _persistent_serial(True)
        ring_desc = "persistent (serial %d)" % ring
    else:
        ring = KEY_SPEC_SESSION_KEYRING
        ring_desc = "session"
    ttl = None
    if flags["ttl"] is not None:
        try:
            ttl = int(flags["ttl"])
        except ValueError:
            ttl = -1
        if ttl <= 0:
            die("--ttl requires a positive number of seconds")
    # wire v4 by default (KR_WIRE=3/2 opt out), optional --selfcontained
    # .ldso. stash (auto-v3), optional --share, optional --ttl expiry
    _stash_payload(data, _resolve_prefix(flags), ring, ring_desc, key=key,
                   selfcontained=flags["selfcontained"],
                   key_type=_resolve_key_type(flags), share=flags["share"],
                   ttl=ttl, type_explicit=flags["type"] is not None)
    return 0


KEYCTL_JOIN_SESSION_KEYRING = 1


def cmd_run(cmd, tokens):
    pos, flags = _parse_tokens(tokens)
    key = _resolve_key(flags)
    prefix = _resolve_prefix(flags)
    # one-shot runs join a fresh session keyring: stash residue (even
    # revoked ghosts) dies with this process.  Skipped for --share/--from
    # (serial handoff needs keys that outlive us) and --keep-ring.
    if cmd in ("kfile", "kstdin") and not flags["share"] \
            and flags["from"] is None and not flags["keep_ring"]:
        if _keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0) >= 0:
            sys.stderr.write("stash: fresh session keyring joined — stash "
                             "residue dies with this process\n")
    if flags["from"] is not None and cmd != "exec":
        die("--from reads an existing stash by serial; it cannot be combined "
            "with %s (which stashes a fresh payload)" % cmd)
    if flags["from"] is not None and flags["selfcontained"]:
        die("--from and --selfcontained cannot be combined")

    if cmd == "kfile":
        if not pos:
            _usage(sys.stderr)
            return 1
        data = _read_file(pos[0])
        spoof = pos[1] if len(pos) > 1 else DEFAULT_SPOOF
        args = pos[2:]
    else:
        spoof = pos[0] if pos else DEFAULT_SPOOF
        args = pos[1:]
        data = _read_stdin() if cmd == "kstdin" else None

    if data is not None:
        if flags["selfcontained"] and flags["raw"]:
            sys.stderr.write("stash: --selfcontained ignored with --raw "
                             "(raw shellcode has no PT_INTERP)\n")
        if key:
            sys.stderr.write("stash: KR1 envelope (ChaCha20-Poly1305, "
                             "impl=%s)\n" % aead_impl())
        if flags["persistent"]:
            ring = _persistent_serial(True)
            ring_desc = "persistent (serial %d)" % ring
        else:
            ring = KEY_SPEC_SESSION_KEYRING
            ring_desc = "session"
        _stash_payload(data, prefix, ring, ring_desc, key=key,
                       selfcontained=(flags["selfcontained"]
                                      and not flags["raw"]),
                       key_type=_resolve_key_type(flags),
                       share=flags["share"],
                       type_explicit=flags["type"] is not None)

    if flags["from"] is not None:
        wire = _load_from(_parse_from(flags["from"]))
    else:
        wire = _load(prefix)                    # bytearray, chunks zeroized
    if flags["selfcontained"] and wire[:4] == KRH4_MAGIC:
        die("exec: v4 experimental: not with --selfcontained yet")
    img = _load_unwrap(wire, key)               # v2.2 digest + KR1 decrypt
    del wire                                    # zeroized by _load_unwrap

    if flags["raw"] and flags["call"]:
        die("--raw and --call are mutually exclusive")
    if flags["raw"]:
        _execute_raw(img, spoof, args)
    elif flags["call"]:
        if flags["selfcontained"]:
            sys.stderr.write("exec: note: --selfcontained has no effect on "
                             "--call (the call path maps no interpreter)\n")
        _execute_call(img, flags["call"], spoof, args)
    else:
        _execute_elf(img, spoof, args,
                     ldso_prefix=prefix if flags["selfcontained"] else None)


def _json_escape(s):
    out = []
    for ch in s:
        if ch in ('"', "\\"):
            out.append("\\" + ch)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def cmd_list(tokens):
    _pos, flags = _parse_tokens(tokens)
    prefix = _resolve_prefix(flags)
    json_out = flags["json"]
    try:
        with open("/proc/keys", "r") as fh:
            lines = fh.read().splitlines()
    except OSError as ex:
        sys.stderr.write("keyringer: cannot open /proc/keys: %s\n"
                         % ex.strerror)
        return 1
    found = 0
    if json_out:
        print("[", end="")
    for line in lines:
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        serial_s, kflags, _f3, _f4, _perms, _uid, _gid, ktype, rest = parts
        if ktype not in ("user", "big_key"):     # v2.2: show big_key too
            continue
        # this kernel appends ": <payload-size>" after the description
        # (": 0" once a key is revoked and its payload freed); older
        # kernels print the bare description
        desc, size = rest, None
        m = re.match(r"^(.*): (\d+)$", rest)
        if m:
            desc, size = m.group(1), m.group(2)
        if not desc.startswith(prefix + "."):
            continue
        revoked = len(kflags) > 1 and kflags[1] == "R"
        if size is None and not revoked:
            sz = _keyctl(KEYCTL_READ, int(serial_s, 16), None, 0)
            if sz != -1:
                size = "%d" % sz
        if size is None:
            size = "?"
        if json_out:
            print("%s{\"serial\":\"%s\",\"type\":\"%s\","
                  "\"desc\":\"%s\",\"revoked\":%s}"
                  % ("," if found else "", serial_s, ktype,
                     _json_escape(desc), "true" if revoked else "false"),
                  end="")
        else:
            note = " (revoked)" if revoked else ""
            print("%s  %s  [%s size=%s]%s"
                  % (serial_s, desc, kflags, size, note))
        found += 1
    if json_out:
        print("]")
    elif not found:
        print("no %s.* keys visible in /proc/keys" % prefix)
    return 0


def cmd_keygen(_tokens):
    """keygen: 32 bytes from secrets/os.urandom, hex on stdout."""
    print(secrets.token_bytes(32).hex())
    return 0


def cmd_gc(tokens):
    """gc: DESTROY every visible "<prefix>.*" key (user/big_key, live or
    dead) via KEYCTL_INVALIDATE — /proc/keys inventory like list.  Root
    can invalidate any key by serial; unprivileged callers only keys they
    still possess (orphaned-ring leftovers of consumed stashes need root)."""
    _pos, flags = _parse_tokens(tokens)
    prefix = _resolve_prefix(flags)
    want = prefix + "."
    killed = skipped = 0
    try:
        with open("/proc/keys", "r") as fh:
            lines = fh.read().splitlines()
    except OSError as ex:
        sys.stderr.write("keyringer: cannot open /proc/keys: %s\n"
                         % ex.strerror)
        return 1
    for line in lines:
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        serial_s, _flags, _f3, _f4, _perms, _uid, _gid, ktype, rest = parts
        if ktype not in ("user", "big_key"):
            continue
        desc = re.match(r"^(.*): \d+$", rest)
        desc = desc.group(1) if desc else rest
        if not desc.startswith(want):
            continue
        serial = int(serial_s, 16)          # /proc/keys serials are hex
        if _keyctl(KEYCTL_INVALIDATE, serial) == -1:
            skipped += 1
            sys.stderr.write("keyringer: gc: key %d (\"%s\") not "
                             "invalidated: %s\n"
                             % (serial, desc, _errno_str()))
        else:
            killed += 1
    sys.stderr.write("gc: destroyed %d key(s) matching %s* (%d skipped)\n"
                     % (killed, want, skipped))
    return 0


# ---------------------------------------------------------------------------
# preflight: light python mirror of the C tool's environment report
# ---------------------------------------------------------------------------

def _read_text(path):
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return None


def _af_alg_bind(algtype, algname):
    """try to bind one AF_ALG transform; returns (ok, error-string)."""
    try:
        s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET)
    except OSError as ex:
        return False, str(ex)
    try:
        s.bind((algtype, algname))
        return True, None
    except OSError as ex:
        return False, ex.strerror or str(ex)
    finally:
        s.close()


def _preflight_wx():
    """W^X self-test: mmap RW, write a single `ret` (0xC3), mprotect it
    PROT_EXEC via ctypes and call it through CFUNCTYPE.  Returns
    (allowed, why)."""
    buf = _mmap(0, _PAGESZ, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS)
    _madvise(buf, _PAGESZ, MADV_DONTDUMP)
    _vma_name(buf, _PAGESZ, VMA_NAME_BUF)
    ctypes.memmove(buf, b"\xC3", 1)
    if _libc.mprotect(buf, _PAGESZ, PROT_READ | PROT_EXEC) == -1:
        _munmap(buf, _PAGESZ)
        return False, "mprotect(RW->RX) denied: %s" % _errno_str()
    try:
        ctypes.CFUNCTYPE(None)(buf)()
    finally:
        _munmap(buf, _PAGESZ)
    return True, None


def cmd_preflight(_tokens):
    """light python mirror of the C preflight: seccomp lines, SELinux +
    AppArmor attributes, kernel.keys limits, AF_ALG binds and the W^X
    self-test.  Exit 0 unless W^X is denied."""
    print("preflight: keyringer.py wire protocol v%s (%s)"
          % (KR_VERSION, platform.machine()))

    status = _read_text("/proc/self/status") or ""
    seccomp = [ln for ln in status.splitlines() if ln.startswith("Seccomp")]
    if seccomp:
        for ln in seccomp:
            print("preflight: %s" % ln)
    else:
        print("preflight: seccomp: no Seccomp lines in /proc/self/status")

    ctx = _read_text("/proc/self/attr/current")
    print("preflight: LSM attr (/proc/self/attr/current): %s"
          % (ctx if ctx else "unavailable"))
    sel = _read_text("/sys/fs/selinux/enforce")
    if sel is None:
        print("preflight: selinux: not present "
              "(/sys/fs/selinux/enforce missing)")
    else:
        print("preflight: selinux: present, enforce=%s" % sel)
    print("preflight: apparmor: %s"
          % ("present" if os.path.isdir("/sys/kernel/security/apparmor")
             else "not present"))

    for name in ("maxkeys", "maxbytes", "root_maxkeys", "root_maxbytes",
                 "persistent_keyring_expiry"):
        v = _read_text("/proc/sys/kernel/keys/" + name)
        print("preflight: kernel.keys.%s = %s"
              % (name, v if v is not None else "unavailable"))

    # live per-UID measurement (kr_quota_snapshot twin) — same detail
    # string as the C preflight's keyring-quota check
    q = quota_snapshot()
    if q is None:
        print("preflight: keyring-quota: unavailable "
              "(/proc/sys/kernel/keys unreadable — quota limits unknown)")
    else:
        print("preflight: keyring-quota: used/max keys=%d/%d, used/max "
              "bytes=%d/%d, remaining=~%d bytes (live /proc/key-users "
              "measurement%s)"
              % (q["keys_used"], q["keys_max"], q["bytes_used"],
                 q["bytes_max"], q["bytes_remaining"],
                 "" if q["measured"] else
                 "; no row for this uid yet — nothing used"))

    for algtype, algname in (("aead", "rfc7539(chacha20,poly1305)"),
                             ("hash", "sha256"),
                             ("skcipher", "chacha20")):
        ok, why = _af_alg_bind(algtype, algname)
        print("preflight: AF_ALG bind %s/%s: %s"
              % (algtype, algname, "ok" if ok else "failed (%s)" % why))
    impl = aead_impl()
    print("preflight: AEAD impl: %s" % (
        "kernel AF_ALG rfc7539(chacha20,poly1305) (RFC-vector-verified)"
        if impl == "af_alg" else
        "pure-python RFC 8439 fallback (AF_ALG unavailable or mismatched)"))

    allowed, why = _preflight_wx()
    if allowed:
        print("preflight: W^X self-test: allowed (RW->RX mprotect + `ret` "
              "call through CFUNCTYPE succeeded)")
        return 0
    print("preflight: W^X self-test: DENIED (%s)" % why)
    return 1


def _tiny_elf(interp_path, pad=1200):
    """selftest-only helper: minimal ET_EXEC x86-64 ELF with one R+X
    PT_LOAD covering the whole image and one PT_INTERP naming
    `interp_path` (the stash does not validate interpreter content)."""
    ehsize, phentsize, phnum = 64, 56, 2
    interp_off = ehsize + phnum * phentsize              # 176
    interp = interp_path + b"\x00"
    base = 0x400000
    total = interp_off + len(interp) + pad
    eh = struct.pack("<16sHHIQQQIHHHHHH",
                     b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
                     ET_EXEC, EM_X86_64, 1, base + interp_off, ehsize, 0, 0,
                     ehsize, phentsize, phnum, 64, 0, 0)
    phdrs = (
        struct.pack("<IIQQQQQQ", PT_LOAD, PF_R | PF_X, 0, base, 0,
                    total, total, 0x1000) +
        struct.pack("<IIQQQQQQ", PT_INTERP, PF_R, interp_off,
                    base + interp_off, 0, len(interp), len(interp), 1))
    return eh + phdrs + interp + b"\x90" * pad


def _stash_retry(fn, *prefixes):
    """selftest helper: sweep revoked-key residue (it can transiently hold
    keyring quota until the kernel GC runs) and retry the stash a few
    times before giving up."""
    for attempt in range(5):
        for p in prefixes:
            _revoke_sweep(p)
        try:
            return fn()
        except SystemExit:
            if attempt == 4:
                raise
            sys.stderr.write(
                "selftest: stash hit keyring quota (revoked-key residue); "
                "waiting for kernel key GC, retry %d/4\n" % (attempt + 1))
            time.sleep(3)


def cmd_selftest(tokens):
    _pos, flags = _parse_tokens(tokens)
    prefix = _resolve_prefix(flags)
    failures = []

    impl = aead_impl()
    print("[*] keyringer.py wire protocol v%s" % KR_VERSION)
    print("[*] envelope cipher: %s" % (
        "kernel AF_ALG \"rfc7539(chacha20,poly1305)\"" if impl == "af_alg"
        else "pure-python RFC 8439 (AF_ALG unavailable or mismatched)"))

    # (a) RFC 8439 section 2.8.2 AEAD test vector, seal + open
    try:
        blob = _aead_seal(RFC_KEY, RFC_NONCE, RFC_AAD, RFC_PT)
        if blob != RFC_CT + RFC_TAG:
            raise RuntimeError("ciphertext+tag mismatch")
        pt = _aead_open(RFC_KEY, RFC_NONCE, RFC_AAD, blob)
        if pt != RFC_PT:
            raise RuntimeError("decrypted plaintext mismatch")
        print("PASS: RFC 8439 2.8.2 AEAD vector (encrypt+decrypt, impl=%s)"
              % impl)
    except (Exception, SystemExit) as ex:
        failures.append("vector")
        print("FAIL: RFC 8439 2.8.2 AEAD vector: %s" % ex)

    # (b) stash -> load-revoke -> byte-identical roundtrip of random bytes,
    #     over the v2 wire format (KRH1 header + plaintext)
    try:
        data = secrets.token_bytes(7000)
        wire = _stash_wrap(data, None)
        # revoked-key residue can transiently hold keyring quota (EDQUOT)
        # until the kernel GC runs — sweep, wait, retry
        for attempt in range(5):
            _revoke_sweep(prefix)
            try:
                _stash(wire, prefix, KEY_SPEC_SESSION_KEYRING, "session")
                break
            except SystemExit as ex:
                if attempt == 4:
                    raise RuntimeError("stash failed after %d GC-wait "
                                       "retries: %s" % (attempt + 1, ex))
                sys.stderr.write(
                    "selftest: stash hit keyring quota (revoked-key "
                    "residue); waiting for kernel key GC, retry %d/4\n"
                    % (attempt + 1))
                time.sleep(3)
        got = _load_unwrap(_load(prefix), None)
        if got != data:
            raise RuntimeError("reassembled image differs from stash "
                               "(%d vs %d bytes)" % (len(got), len(data)))
        first = _desc(prefix, 0)
        s = _request_key(first, KEY_SPEC_SESSION_KEYRING)
        if s == -1:
            e = ctypes.get_errno()
            if e == errno.ENOKEY:
                state, ok = "gone (ENOKEY)", True
            elif e == errno.EKEYREVOKED:
                state, ok = "revoked (pending kernel GC unlink)", True
            else:
                state, ok = "not found (errno %d)" % e, False
        else:
            sz = _keyctl(KEYCTL_READ, s, None, 0)
            if sz == -1 and ctypes.get_errno() == errno.EKEYREVOKED:
                state = "revoked (pending kernel GC unlink)"
                ok = True
            else:
                state = "still live/readable"
                ok = False
            _keyctl(KEYCTL_REVOKE, s)
        if not ok:
            raise RuntimeError("chunk key 000 %s after load" % state)
        print("PASS: stash->load-revoke roundtrip (7000 random bytes, "
              "v2.2 wire %d bytes, 1 chunk, chunk key 000 %s)"
              % (len(wire), state))
    except (Exception, SystemExit) as ex:
        failures.append("roundtrip")
        print("FAIL: stash->load-revoke roundtrip: %s" % ex)

    # (c) KR1 envelope interop: fixed key+nonce, deterministic hex, roundtrip
    try:
        env = envelope_seal(RFC_KEY, RFC_PT, nonce=RFC_NONCE)
        print("envelope hex (%d bytes): %s" % (len(env), env.hex()))
        pt = envelope_open(RFC_KEY, env)
        if pt != RFC_PT:
            raise RuntimeError("envelope roundtrip plaintext mismatch")
        note = ""
        if impl == "af_alg":
            py = _aead_py(RFC_KEY, RFC_NONCE, ENV_MAGIC + RFC_NONCE, RFC_PT)
            ka = _af_alg_aead(RFC_KEY, RFC_NONCE, ENV_MAGIC + RFC_NONCE,
                              RFC_PT, False)
            if ka != py:
                raise RuntimeError("AF_ALG and pure-python disagree")
            note = " + AF_ALG/python interop"
        print("PASS: KR1 envelope roundtrip%s" % note)
    except (Exception, SystemExit) as ex:
        failures.append("envelope")
        print("FAIL: KR1 envelope roundtrip: %s" % ex)

    # (d) wire v3 (KR_WIRE=3 opt-in since the core 4.0 flip) digest-header
    #     roundtrip: encrypted + plaintext + header layout + HKDF/AAD
    #     binding, plus the KR_WIRE=2 v2.2 downgrade
    try:
        payload = secrets.token_bytes(2500)
        checks = []
        os.environ["KR_WIRE"] = "3"     # v3 is the opt-in lane since 4.0
        try:
            wire = _stash_wrap(payload, RFC_KEY)        # encrypted body
            sid = bytes(wire[40:48])
            checks += [
                wire[:4] == KRH3_MAGIC,
                wire[4] == KRH3_VERSION,
                wire[5] == KRH3_FLAG_ENC,
                struct.unpack_from("<Q", wire, 48)[0] == len(payload),
                len(wire) == KR3_HDR_LEN + len(payload) + ENV_OVERHEAD,
            ]
            pt = _load_unwrap(bytearray(wire), RFC_KEY)
            checks += [pt == payload, isinstance(pt, bytearray)]
            # wrong key must fail closed
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    _load_unwrap(bytearray(_stash_wrap(payload, RFC_KEY)),
                                 bytes(32))
                checks.append(False)
            except SystemExit:
                checks.append(True)
            wire2 = _stash_wrap(payload, None)          # plaintext body
            checks += [
                wire2[:4] == KRH3_MAGIC,
                wire2[5] == 0,
                len(wire2) == KR3_HDR_LEN + len(payload),
                bytes(wire2[40:48]) != sid,         # per-stash random id
            ]
            checks.append(_load_unwrap(bytearray(wire2), None) == payload)
            # HKDF binding: flipping any header byte must break the KR2 tag
            wiret = bytearray(wire)
            wiret[8] ^= 0xFF                            # digest byte
            pt3 = None
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    pt3 = _load_unwrap(wiret, RFC_KEY)
                checks.append(False)
            except SystemExit:
                checks.append(True)
            # KR_WIRE=2 downgrade: the v2.2 builder still roundtrips
            os.environ["KR_WIRE"] = "2"
            try:
                wirev2 = _stash_wrap(payload, RFC_KEY)
            finally:
                os.environ["KR_WIRE"] = "3"
        finally:
            del os.environ["KR_WIRE"]
        checks += [
            wirev2[:4] == KRH_MAGIC,
            len(wirev2) == KRH_HDR_LEN + len(payload) + ENV_OVERHEAD,
            _load_unwrap(bytearray(wirev2), RFC_KEY) == payload,
        ]
        if not all(checks):
            raise RuntimeError("wrap/unwrap checks failed: %r" % checks)
        print("PASS: wire v3 KRH3 roundtrip under KR_WIRE=3 (encrypted + "
              "plaintext, AAD-bound header, HKDF subkey, wrong-key refusal, "
              "header-tamper refusal, KR_WIRE=2 v2.2 downgrade roundtrip)")
    except (Exception, SystemExit) as ex:
        failures.append("krh3")
        print("FAIL: wire v3 digest-header roundtrip: %s" % ex)

    # (e) deliberate digest corruption must fail cleanly: exit 1, clean
    #     stderr error, and (in the tool) no jump and no call — run on the
    #     DEFAULT (v4 since core 4.0) plaintext body
    try:
        wire = bytearray(_stash_wrap(payload, None))    # plaintext body:
        wire[KR4_HDR_LEN] ^= 0xFF                       # body byte flip must
        # trip the digest check (an encrypted flip would trip the chunk tag)
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                _load_unwrap(wire, None)
        except SystemExit as ex:
            if ex.code != 1:
                raise RuntimeError("exit code %r, want 1" % (ex.code,))
        else:
            raise RuntimeError("corrupted digest was accepted")
        if "digest mismatch" not in err.getvalue():
            raise RuntimeError("no digest-mismatch error on stderr: %r"
                               % err.getvalue())
        print("PASS: corrupted KRH4 (default wire) digest is fatal "
              "(exit 1, clean stderr)")
    except (Exception, SystemExit) as ex:
        failures.append("krh4-corrupt")
        print("FAIL: corrupted KRH4 digest handling: %s" % ex)

    # (f) v2.2 --selfcontained wire roundtrip WITHOUT executing: stash a
    #     small ELF payload whose PT_INTERP names a ~2 KB fake "interpreter"
    #     file (stash does not validate interpreter content) plus the
    #     interpreter itself under <prefix>.ldso.* (wire KRH1 flags=0,
    #     ALWAYS plaintext); then load + KRH1-verify both wires
    #     byte-identically and revoke everything.
    try:
        import tempfile
        blob = secrets.token_bytes(2048)
        fd, ipath = tempfile.mkstemp(prefix="keyringer-selftest-ldso-")
        try:
            os.write(fd, blob)
        finally:
            os.close(fd)
        try:
            payload = _tiny_elf(ipath.encode(), pad=1200)
            got = _pt_interp_path(payload)
            if got != ipath.encode():
                raise RuntimeError("PT_INTERP parse: %r != %r"
                                   % (got, ipath))
            _stash_retry(lambda: _stash_payload(
                payload, prefix, KEY_SPEC_SESSION_KEYRING, "session",
                None, selfcontained=True), prefix, _ldso_prefix(prefix))
            pwire = _load(prefix)
            lwire = _load(_ldso_prefix(prefix))
            if bytes(pwire[:4]) != KRH3_MAGIC or \
                    bytes(lwire[:4]) != KRH3_MAGIC:
                raise RuntimeError("--selfcontained did not auto-downgrade "
                                   "to wire v3 (payload %r, ldso %r)"
                                   % (bytes(pwire[:4]), bytes(lwire[:4])))
            pt = _load_unwrap(pwire, None)
            ldso = _load_unwrap(lwire, None)
            if pt != payload or ldso != blob:
                raise RuntimeError("roundtrip mismatch (payload %d/%d, "
                                   "ldso %d/%d bytes)"
                                   % (len(pt), len(payload),
                                      len(ldso), len(blob)))
            print("PASS: --selfcontained .ldso. wire roundtrip without "
                  "executing (payload %d B + interpreter %d B, ldso wire "
                  "%d B; both wires AUTO-v3, digest-verified, plaintext "
                  "flags=0)"
                  % (len(payload), len(blob), KR3_HDR_LEN + len(blob)))
        finally:
            os.unlink(ipath)
    except (Exception, SystemExit) as ex:
        failures.append("selfcontained")
        print("FAIL: --selfcontained .ldso. roundtrip: %s" % ex)

    # (g) v2.2 --type big_key: stash/load roundtrip of ~8 KB with
    #     100000-byte wire chunks; the load-side lookup must find the
    #     chunk via "big_key" after "user" misses (big_key is
    #     quota-heavier, so the test stays small)
    try:
        data = secrets.token_bytes(8000)
        wire = _stash_wrap(data, None)
        _stash_retry(lambda: _stash(wire, prefix, KEY_SPEC_SESSION_KEYRING,
                                    "session", KEY_TYPE_BIG_KEY,
                                    CHUNK_BIGKEY_MAX), prefix)
        got = _load_unwrap(_load(prefix), None)
        if got != data:
            raise RuntimeError("big_key roundtrip mismatch (%d vs %d "
                               "bytes)" % (len(got), len(data)))
        print("PASS: --type big_key stash/load roundtrip (8000 random "
              "bytes, %d-byte chunks, user-then-big_key lookup)"
              % CHUNK_BIGKEY_MAX)
    except (Exception, SystemExit) as ex:
        failures.append("big_key")
        print("FAIL: --type big_key roundtrip: %s" % ex)

    # (h) v2.2 stash --share + exec --from: stash, KEYCTL_SETPERM every
    #     serial to 0x3f3f0000, parse the "share: ..." stdout line, then
    #     reassemble via KEYCTL_READ straight from those serials (no
    #     request_key) and KRH1-verify as usual
    try:
        data = secrets.token_bytes(1500)
        wire = _stash_wrap(data, None)
        serials = _stash_retry(lambda: _stash(wire, prefix,
                                              KEY_SPEC_SESSION_KEYRING,
                                              "session"), prefix)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            _share_serials(serials)
        line = out.getvalue().strip()
        if not line.startswith("share: "):
            raise RuntimeError("no share line on stdout: %r" % line)
        parsed = [int(x) for x in line[len("share: "):].split(",")]
        if parsed != serials:
            raise RuntimeError("share line serials %r != stored %r"
                               % (parsed, serials))
        dsz = _keyctl(KEYCTL_DESCRIBE, serials[0], None, 0)
        db = ctypes.create_string_buffer(dsz)
        _keyctl(KEYCTL_DESCRIBE, serials[0], db, dsz)
        perm = db.raw.split(b";", 4)[3]
        if perm != b"3f3f0000":
            raise RuntimeError("key perm %r != 3f3f0000" % perm)
        got = _load_unwrap(_load_from(parsed), None)
        if got != data:
            raise RuntimeError("--from roundtrip mismatch (%d vs %d "
                               "bytes)" % (len(got), len(data)))
        print("PASS: stash --share (perm 0x3f3f0000, share line parsed) "
              "+ exec --from serial roundtrip (%d bytes, KRH1-verified)"
              % len(data))
    except (Exception, SystemExit) as ex:
        failures.append("from_share")
        print("FAIL: --share/--from roundtrip: %s" % ex)

    # (i) wire v4 (KRH4, the DEFAULT since core 4.0): per-chunk AEAD
    #     wrap/unwrap — multi-chunk encrypted roundtrip + header layout +
    #     length equation, wrong-key refusal, header-tamper refusal (the
    #     AAD binds the whole header per chunk), plaintext v4 body, the
    #     KR_WIRE=3 v3 downgrade and the KR_WIRE=2 v2.2 downgrade. The
    #     first two checks PROVE the flip: the DEFAULT wrap is KRH4.
    try:
        payload = secrets.token_bytes(70000)      # 3 pt-chunks of 29900
        total = (len(payload) + KR4_PT_CHUNK - 1) // KR4_PT_CHUNK
        checks = []
        # THE FLIP: a default (no KR_WIRE) encrypted wrap must be KRH4
        wire = _stash_wrap(payload, RFC_KEY)
        checks += [
            wire[:4] == KRH4_MAGIC,
            wire[4] == KRH4_VERSION,
            wire[5] == KRH4_FLAG_ENC,
            len(wire) == KR4_HDR_LEN + total * KR4_PIECE_OH + len(payload),
            _load_unwrap(bytearray(wire), RFC_KEY) == payload,
        ]
        # ... and KR_WIRE=3 must downgrade the writer back to KRH3
        os.environ["KR_WIRE"] = "3"
        try:
            wire3 = _stash_wrap(payload, RFC_KEY)
        finally:
            del os.environ["KR_WIRE"]
        checks += [
            wire3[:4] == KRH3_MAGIC,
            len(wire3) == KR3_HDR_LEN + len(payload) + ENV_OVERHEAD,
            _load_unwrap(bytearray(wire3), RFC_KEY) == payload,
        ]
        os.environ["KR_WIRE"] = "4"     # explicit 4: accepted no-op
        try:
            wire = _stash_wrap(payload, RFC_KEY)
        finally:
            del os.environ["KR_WIRE"]
        checks += [
            wire[:4] == KRH4_MAGIC,
            wire[4] == KRH4_VERSION,
            wire[5] == KRH4_FLAG_ENC,
            len(wire) == KR4_HDR_LEN + total * KR4_PIECE_OH + len(payload),
            struct.unpack_from("<Q", wire, 48)[0] == len(payload),
            _load_unwrap(bytearray(wire), RFC_KEY) == payload,
        ]
        # wrong key must fail closed (chunk 0 AEAD tag)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                _load_unwrap(bytearray(wire), bytes(32))
            checks.append(False)
        except SystemExit:
            checks.append(True)
        # header tamper: flipping any header byte must break the chunk AAD
        wiret = bytearray(wire)
        wiret[8] ^= 0xFF                                # digest byte
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                _load_unwrap(wiret, RFC_KEY)
            checks.append(False)
        except SystemExit:
            checks.append(True)
        # truncated body must be refused (no pt-chunk equation fits)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                _load_unwrap(bytearray(wire[:-40]), RFC_KEY)
            checks.append(False)
        except SystemExit:
            checks.append(True)
        # plaintext v4 body roundtrip (default, no KR_WIRE needed)
        wirep = _stash_wrap(payload, None)
        checks += [
            wirep[:4] == KRH4_MAGIC,
            wirep[5] == 0,
            len(wirep) == KR4_HDR_LEN + len(payload),
            _load_unwrap(bytearray(wirep), None) == payload,
        ]
        # KR_WIRE=2 downgrade builder still roundtrips (v4 does not
        # displace it; readers dispatch on magic, writers on KR_WIRE)
        os.environ["KR_WIRE"] = "2"
        try:
            wirev2 = _stash_wrap(payload, RFC_KEY)
        finally:
            del os.environ["KR_WIRE"]
        checks += [
            wirev2[:4] == KRH_MAGIC,
            _load_unwrap(bytearray(wirev2), RFC_KEY) == payload,
        ]
        if not all(checks):
            raise RuntimeError("v4 wrap/unwrap checks failed: %r" % checks)
        print("PASS: wire v4 KRH4 per-chunk AEAD roundtrip, DEFAULT writer "
              "proven KRH4 (3-chunk encrypted + plaintext, AAD-bound "
              "header, wrong-key + header-tamper + truncation refusal, "
              "KR_WIRE=3 v3 + KR_WIRE=2 v2.2 downgrades still readable)")
    except (Exception, SystemExit) as ex:
        failures.append("krh4")
        print("FAIL: wire v4 roundtrip: %s" % ex)

    _revoke_sweep(prefix)                    # best-effort clean slate
    _revoke_sweep(_ldso_prefix(prefix))
    return 1 if failures else 0


def main(argv):
    # x86_64-only twin (documented): arm64 is the keyringer (C) tool's
    # ARCH=aarch64 lane — refuse cleanly on any other machine
    machine = platform.machine()
    if sys.platform[:5] != "linux" or machine != "x86_64":
        sys.stderr.write("keyringer: this tool needs linux-x86_64 "
                         "(got %s-%s); arm64 is the keyringer (C) tool's "
                         "ARCH=aarch64 lane\n" % (sys.platform, machine))
        return 1
    if len(argv) < 2:
        _usage(sys.stderr)
        return 1
    cmd = argv[1]
    if cmd in ("help", "-h", "--help"):
        _usage(sys.stdout)
        return 0
    if cmd in C_ONLY_CMDS:
        _c_only("'%s'" % cmd)
    if cmd == "list":
        return cmd_list(argv[2:])
    if cmd == "gc":
        return cmd_gc(argv[2:])
    if cmd == "selftest":
        return cmd_selftest(argv[2:])
    if cmd == "preflight":
        return cmd_preflight(argv[2:])
    if cmd == "keygen":
        return cmd_keygen(argv[2:])
    if cmd == "stash":
        return cmd_stash(argv[2:])
    if cmd in ("kfile", "kstdin", "exec"):
        cmd_run(cmd, argv[2:])
    sys.stderr.write("keyringer: unknown command '%s'\n\n" % cmd)
    _usage(sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
