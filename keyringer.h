/*
 * keyringer.h — public API for libkeyringer and the keyringer CLI.
 *
 * Linux x86-64/AArch64 kernel-keyring fileless exec loader.
 *
 * Research/education reproduction of the publicly documented
 * "kernel keyring fileless exec" technique:
 *   https://matheuzsecurity.github.io/hacking/linux-kernel-keyring-fileless-exec/
 *   (reference implementation: MatheuZSecurity/Dntry)
 *
 * The payload is never written to disk and never exec'd through the
 * kernel: stashed as "user" (or "big_key") keys on a kernel keyring,
 * reassembled with keyctl(READ) (revoking every key as it is read),
 * then mapped and run in-process.
 *
 * SYSCALL POLICY (grep allowlist): execve/execveat/memfd_create/fork
 * are BANNED everywhere in this codebase — zero occurrences. clone()
 * (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|SIGCHLD) is EXPLICITLY
 * ALLOWED as the documented concurrency primitive (wire v2.2): it
 * drives the --clone flag and the `agent` subcommand, which run an
 * already-staged payload in a short-lived child on a fresh per-child
 * stack; no exec-family syscall is ever issued by the child (the
 * payload's own exit_group is the only terminal event) so the
 * process-start telemetry that execve fires never happens.
 *
 * Library rules: functions below NEVER call exit()/abort() and NEVER
 * write to stdout/stderr. They return 0 on success and -1 on error with
 * a diagnostic in the caller-provided err[] buffer. Progress/verbose
 * output goes through the optional log hook (kr_set_log()).
 *
 * wire protocol v2.2 (must match keyringer.py)
 * ---------------------------------------
 * v2.2 header:    40 bytes prepended to the wire payload at stash time,
 *                 before chunking and before the encrypt decision:
 *                   bytes 0..3   magic "KRH1"
 *                   bytes 4..7   u32 LE flags — bit 0 = body is a KR1
 *                                envelope (encrypted stash); all other
 *                                bits are reserved and must be zero
 *                                (readers reject the stash otherwise)
 *                   bytes 8..39  SHA-256 of the PLAINTEXT payload
 *                                (pre-encryption; the digest always
 *                                covers plaintext in both stash modes)
 *                 encrypted stash: header(40) || KR1-envelope(plaintext)
 *                 plaintext stash: header(40) || plaintext
 *                 Quota overhead is +40 bytes per stash (payload quota
 *                 is checked against header + body).
 * Digest check:   on load the reassembled wire is hashed (SHA-256 via
 *                 kernel AF_ALG "hash"/"sha256") after the optional
 *                 decryption and compared against the header digest;
 *                 a mismatch is FATAL — clean error, no jump, no call,
 *                 no partial execution (chunk keys are already revoked
 *                 by then).
 * Legacy:         a reassembled stash WITHOUT the KRH1 header (pre-v2)
 *                 is loaded exactly as before: plaintext executed
 *                 verbatim, or decrypted when it starts with the "KR1"
 *                 magic and a key is given. No digest is verified; a
 *                 note ("no integrity digest (pre-v2 stash)") is logged
 *                 through the kr_set_log() hook.
 * Key names:      "<prefix>.<idx>" with idx printed "%03d" starting 000.
 *                 prefix defaults to "_keyringer", override with
 *                 --desc PREFIX or env KEYRINGER_DESC.
 *                 Interpreter chunks (wire v2.2 --selfcontained) use
 *                 "<prefix>.ldso.<idx>" with the same %03d numbering,
 *                 stashed AFTER the payload chunks.
 * Key types:      default "user"; --type big_key stores "big_key" keys
 *                 instead with 100000-byte wire chunks (vs 30000 for
 *                 "user"). On exec, the chunk lookup tries "user"
 *                 first, then "big_key", PER chunk index — mixed-type
 *                 stashes are tolerated. big_key payloads may spill to
 *                 swap-backed shmem on this and other kernels (capacity
 *                 tradeoff vs "user"); on this kernel a big_key charges
 *                 desc+21 bytes of quota, its payload is NOT byte-
 *                 charged (measured; see the quota block below), and
 *                 kr_stash AUTO-SELECTS big_key when the "user" chunk
 *                 count would exceed maxkeys (the maxkeys relief).
 * Chunk size:     30000 wire bytes (header + body) per "user" key (the
 *                 "user" type caps a single payload at 32767 bytes);
 *                 100000 wire bytes per "big_key" key.
 * Max chunks:     1000 (idx 000..999).
 * Plaintext wire  header (40B) || payload bytes verbatim, split into
 *                 chunks in order.
 * Encrypted wire  header (40B) || envelope, envelope = "KR1" magic (3B)
 *                 + 12B random nonce + ciphertext || 16B Poly1305 tag.
 *                 ChaCha20-Poly1305 per RFC 8439; 32B key from --key
 *                 HEX / --keyfd FD / env KEYRINGER_KEY (precedence:
 *                 --key > --keyfd > env — --key/env leak via ps and
 *                 /proc/<pid>/environ, --keyfd reads an inherited fd
 *                 instead, accepting raw 32 bytes or 64 hex chars); AAD
 *                 = the first 15 bytes of the envelope (magic + nonce).
 *                 The whole payload is encrypted BEFORE chunking;
 *                 decryption happens after reassembly. Envelope overhead
 *                 is 31 bytes.
 * Interpreter     --selfcontained additionally stashes the payload
 * (v2.2):         ELF's PT_INTERP interpreter alongside the payload:
 *                 KRH1 header (flags=0) + raw interpreter file bytes,
 *                 ALWAYS PLAINTEXT regardless of --key (the interpreter
 *                 is a public artifact — no signature value; the digest
 *                 is still verified on load). Chunks are named
 *                 "<prefix>.ldso.<idx>" and stored after the payload
 *                 chunks. Exec with --selfcontained reassembles the
 *                 interpreter from those keys (same ring fallback and
 *                 ENOKEY-terminates loop as payloads), verifies its
 *                 digest and maps it from memory; without the flag the
 *                 interpreter comes from disk exactly as before.
 * Lookup on exec: request_key(2) in the session keyring first; if chunk
 *                 000 is ENOKEY there, the whole sequence is retried in
 *                 the per-UID persistent keyring (keyctl
 *                 KEYCTL_GET_PERSISTENT + KEYCTL_SEARCH). Whichever ring
 *                 holds chunk 000 is used for the full sequence (first
 *                 full sequence wins; no mixing). The first ENOKEY gap
 *                 terminates the sequence. --from S1,S2,... instead
 *                 reads chunk i directly from the i-th listed serial
 *                 (KEYCTL_READ size probe + read; no request_key) and
 *                 revokes best-effort — EPERM/EACCES on revoke is
 *                 nonfatal (shared keys from other UIDs).
 * Persistent:     stash --persistent stores via
 *                 keyctl(KEYCTL_GET_PERSISTENT, getuid(), 0) (dest
 *                 serial 0 => returns the persistent.<uid> serial
 *                 directly) and add_key(2)s into that serial. Persistent
 *                 rings expire after
 *                 /proc/sys/kernel/keys/persistent_keyring_expiry
 *                 (259200s here) without access; every GET_PERSISTENT
 *                 refreshes the clock (that refresh is what the
 *                 keepalive subcommand performs).
 * Sharing (v2.2): stash --share runs KEYCTL_SETPERM(0x3f3f0000 —
 *                 possessor+user: all; the same value keyrings use by
 *                 default, as seen in /proc/keys) on every stored serial
 *                 (payload AND interpreter chunks) and prints
 *                 "share: <s1>,<s2>,..." on stdout, parseable by
 *                 exec --from.
 * stash verify:   with --key, seal() is roundtrip-verified by open()
 *                 BEFORE any chunk is stored; on mismatch nothing is
 *                 stored and the error is reported.
 * Concurrency     --clone (kfile/kstdin/khttp/exec) and the `agent`
 * (v2.2):         subcommand stage the image (dumpable 0, DONTDUMP, VMA
 *                 naming, digest, revoke) and then clone() the process
 *                 (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|SIGCHLD)
 *                 into a child that runs the payload on a FRESH
 *                 per-child mmap'd stack. MADV_WIPEONFORK does not fire
 *                 on CLONE_VM (shared mappings are not copied, so wipes
 *                 are irrelevant); the payload stack is per-child
 *                 anyway. One-shot --clone: the parent waitpid()s and
 *                 exits with the payload's exit status — no execve
 *                 ever, process-start telemetry never fires, the
 *                 child's exit_group is the only terminal event.
 *                 agent mode reads KAG1 control frames
 *                 (u32 LE magic 0x3147414B, u32 LE len, len payload
 *                 bytes, u16 LE name_len, name bytes; len==0 ends
 *                 cleanly) from the ctl fd (default 0) and runs one
 *                 stash+clone-exec per frame, printing
 *                 "agent: ran <name> pid=<pid> exit=<code>" per frame.
 *                 Payloads inherit the process fds — frameworks wanting
 *                 clean payload stdin should pass a dedicated ctl fd via
 *                 --ctlfd and use real stdin for payloads.
 * VMA names:      anonymous regions are named via
 *                 prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...):
 *                 image "[anon:libc:heap]", stack "[anon:libc:tls]",
 *                 scratch "[anon:libc:buf]". Nonfatal where the kernel
 *                 lacks CONFIG_ANON_VMA_NAME.
 */
#ifndef KEYRINGER_H
#define KEYRINGER_H

#include <stdint.h>
#include <stddef.h>
#include <stddef.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KR_ERRSZ 256

/* wire protocol constants (must match keyringer.py) */
#define KR_CHUNK_MAX     30000UL           /* wire bytes per "user" key */
#define KR_CHUNK_BIGKEY  100000UL          /* wire bytes per big_key    */
#define KR_IDX_MAX       999UL             /* idx printed %03d          */
#define KR_DEFAULT_DESC  "_keyringer"      /* default name prefix       */
#define KR_MAGIC         "KR1"             /* envelope magic            */
#define KR_NONCE_LEN     12                /* ChaCha20-Poly1305 nonce   */
#define KR_TAG_LEN       16                /* Poly1305 tag              */
#define KR_AAD_LEN       15                /* magic + nonce             */
#define KR_ENV_OVERHEAD  31                /* 3 + 12 + 16               */
#define KR_KEY_HEX_LEN   64                /* 32 bytes as hex           */
#define KR_WIRE_MAGIC    "KRH1"            /* v2 header magic           */
#define KR_HDR_LEN       40UL              /* v2 header: 4+4+32 bytes   */
#define KR_HDR_FLAG_ENC  0x01u             /* flags bit 0: KR1 envelope */
/* ---- wire v3 ---- */
#define KR_WIRE3_MAGIC   "KRH3"            /* v3 header magic           */
#define KR_WIRE3_VERSION 3u                 /* header version byte       */
#define KR_HDR3_LEN      56UL              /* 4+1+1+2+32+8+8 bytes      */
#define KR_HDR3_FLAG_ENC 0x01u             /* flags bit 0: KR2 envelope */
#define KR_ENV2_MAGIC    "KR2"             /* v3 envelope magic         */
#define KR_STASH_ID_LEN  8                 /* random per-stash id       */
#define KR3_INFO         "keyringer-v3"    /* HKDF info string          */
#define KR_TYPE_USER     "user"            /* default key type          */
#define KR_TYPE_BIGKEY   "big_key"         /* --type big_key            */
#define KR_LDSO_SUFFIX   ".ldso"           /* interpreter chunk names   */
#define KR_MAX_IMG_SPAN  (1024UL << 20)    /* 1 GiB mapped-image cap    */
#define KR_SHARE_PERM    0x3f3f0000UL      /* stash --share SETPERM     */
#define KR_AGENT_MAGIC   0x3147414Bu       /* "KAG1" little-endian      */
/* ---- wire v4 (KRH4) — the DEFAULT writer since core 4.0 ---- */
/*
 * v4 = v3's 56-byte header layout with magic "KRH4"/version 4, plus the
 * two defining properties: (1) the ENCRYPTED body is sealed PER CHUNK —
 * the plaintext is split into pt-chunks of KR_V4_PT_CHUNK bytes and each
 * piece is its own ChaCha20-Poly1305 envelope (nonce||ct||tag, +28 B per
 * piece) under a per-chunk HKDF subkey; (2) the C exec path STREAMS —
 * chunk-by-chunk decryption straight into the mapped image, so a full
 * plaintext buffer never exists outside the mapped PT_LOADs. See the
 * Wire protocol section of README.md for the full spec. Writers pick it
 * by default; KR_WIRE=3 opts back to v3, KR_WIRE=2 to v2.2 (KR_WIRE=4
 * is an accepted no-op kept for pre-flip scripts).
 *
 * pt-chunk arithmetic: one sealed piece is 12 (nonce) + ptlen + 16 (tag)
 * = ptlen + 28 wire bytes.  With ptlen = 29900 a piece is 29928 bytes —
 * it fits a 30000-byte "user" key even next to a 56-byte header share
 * (30000 - 64 = 29936 >= 29900), so a piece can never force a key chunk
 * split that a v3 body of the same size would not already have.
 */
#define KR_WIRE4_MAGIC   "KRH4"            /* v4 header magic           */
#define KR_WIRE4_VERSION 4u                /* header version byte       */
#define KR_HDR4_LEN      56UL              /* same layout as v3         */
#define KR_HDR4_FLAG_ENC 0x01u             /* flags bit 0: sealed body  */
#define KR4_INFO         "keyringer-v4"    /* HKDF info string          */
#define KR_V4_PT_CHUNK   29900             /* plaintext bytes per piece */
#define KR_V4_PIECE_OH   28                /* nonce 12 + tag 16         */
#define KR_V4_AAD_LEN    (KR_HDR4_LEN + 12) /* hdr||i||total||ptlen_i   */
/* ---- keyring quota telemetry (live /proc measurement) ---- */
/*
 * What the kernel actually charges to the per-UID qnbytes pool, measured
 * on this box (kernel 7.0.14-17-pve, 2026-10, via controlled add_key +
 * /proc/key-users deltas):
 *
 *   "user" key    strlen(desc) + payload + 5          (payload IS charged)
 *   "big_key"     strlen(desc) + 21, FIXED            (payload NOT charged:
 *                a 100000-byte big_key charged 27 B as non-root here; the
 *                payload lives in shmem — /proc/keys shows "[file]")
 *   keyring       strlen(desc) + 5
 *
 * So big_key's levers are (1) fewer, larger keys (maxkeys relief) and
 * (2) >30000-byte payloads per key (the "user" per-key cap bypass) — and,
 * on kernels that charge like this one, the payload escapes the byte
 * quota entirely; the byte-quota MULTIPLIER remains root or pooling
 * across UIDs (--share/--from). Never rely on byte relief from big_key
 * across kernels: the planner measures the live quota but plans with the
 * constants below, rounded UP with slack so a "planned OK" stash cannot
 * overflow by rounding (better to refuse early than EDQUOT mid-stash;
 * the mid-stash EDQUOT rollback stays as the backstop for model drift).
 */
#define KR_QUOTA_USER_OH     5UL  /* measured: desc + payload + 5 per "user" key */
#define KR_QUOTA_BIGKEY_OH  21UL  /* measured: desc + 21 per "big_key", payload
                                     is NOT byte-charged on this kernel        */
#define KR_QUOTA_SLACK      16UL  /* planning slack per key (round up)          */
#define KR_QUOTA_SLACK_ONCE 64UL  /* planning slack: ring creation / rounding   */

/*
 * Live quota snapshot, kr_quota_snapshot(): keys_used/bytes_used come
 * from the euid's row in /proc/key-users, whose format was verified
 * empirically on this kernel (7.0.14-17-pve):
 *   "uid: usage nkeys/qnkeys nikeys/maxkeys qnbytes/maxbytes"
 * — nkeys/qnbytes are the charges, the maxkeys/maxbytes denominators
 * track the LIVE kernel.keys sysctls (verified by flipping maxkeys and
 * watching both the row and add_key enforcement follow within a second)
 * and win over the /proc/sys read, which stays the fallback (and is the
 * only source when euid == 0: root_maxkeys/root_maxbytes). A missing
 * uid row (fresh boot: no key ever created for this uid) degrades
 * cleanly to used=0 with measured=0.
 */
typedef struct {
    unsigned long keys_used, keys_max;
    unsigned long bytes_used, bytes_max, bytes_remaining;
    int measured;   /* 1 = live /proc/key-users row found for this uid;
                       0 = row absent, used counters defaulted to 0      */
} kr_quota;

typedef struct {
    const char *desc_prefix;  /* NULL => "_keyringer"                        */
    const char *key_hex;      /* 64 hex chars => encrypted stash, NULL => plaintext */
    int persistent;           /* stash into per-UID persistent ring           */
    int raw;                  /* payload is raw shellcode, not ELF            */
    const char *call_symbol;  /* relocate and call this symbol instead of jumping entry */
    /* ---- wire v2.2 ---- */
    int selfcontained;        /* stash: embed PT_INTERP; exec: take interp from keys */
    int clone_child;          /* exec: stage then run the payload in a clone() child */
    const char *key_type;     /* stash key type: NULL => "user"; "big_key" => 100000B chunks */
    const char *from_serials; /* exec: comma-separated serials, chunk i read from i-th */
    int share;                /* stash: KEYCTL_SETPERM(KR_SHARE_PERM) on stored keys */
    long ttl;                 /* stash: KEYCTL_SET_TIMEOUT every stored key after N
                                 seconds (0 => live until revoked/consumed)          */
    int scrub;                /* exec: unlink+invalidate each chunk after its read
                                 instead of revoking — no /proc/keys ghost remains   */
    long *serials_out;        /* stash: optional array receiving stored serials      */
    size_t serials_out_cap;   /* capacity of serials_out                             */
    size_t *serials_out_n;    /* optional: receives the number of stored serials     */
    long *child_pid_out;      /* exec --clone: optional, receives the child pid      */
    /* ---- wire v4 (experimental) ---- */
    int stream;               /* exec: stream wire-v4 encrypted stashes (per-chunk
                                 AEAD decrypt straight into the mapped image — no
                                 full plaintext buffer ever exists).  v4 IMPLIES
                                 streaming: the library streams every KRH4
                                 encrypted stash on the exec paths regardless of
                                 this flag (no CLI flag exists); the field lets a
                                 library consumer state the intent explicitly and
                                 is reported as "requested" instead of
                                 "automatic" in the streaming log line.          */
} kr_opts;

/*
 * Stash buf[0..len) into the keyring (chunked, optionally sealed into a
 * KR1 envelope first — in which case the seal is roundtrip-verified
 * before anything is stored). With o->selfcontained, the ELF's PT_INTERP
 * interpreter is stashed after the payload chunks. Returns 0 / -1+err.
 */
int kr_stash(const void *buf, size_t len, const kr_opts *o, char err[KR_ERRSZ]);

/*
 * gc — destroy (KEYCTL_INVALIDATE) every visible "prefix.*" keyring key
 * (user/big_key types, /proc/keys inventory): live stashes, stale chunks
 * and the revoked ghosts of consumed stashes. Root can invalidate any key
 * by serial; unprivileged callers only their own keys. Returns 0 (counts
 * reported via the log) / -1+err on failure.
 */
int kr_gc(const char *prefix, char err[KR_ERRSZ]);

/*
 * Fuzz entry: push an untrusted reassembled buffer through wire_open
 * (parse-only; never executes).  Returns 0/-1; wire is copied internally.
 */
int kr_wire_fuzz_entry(const uint8_t *wire, size_t wirelen,
                       const char *keyhex, char err[KR_ERRSZ]);

/*
 * ELF-loader fuzz entry: run an untrusted image through the phase-3
 * parsers (validate / interp / map / --call relocations) without ever
 * executing it.  See kr_core.c for the mode table.
 */
int kr_elf_fuzz_entry(const uint8_t *img, size_t len, int mode,
                      char err[KR_ERRSZ]);

/*
 * Reassemble the stashed payload from the keyring; every key is revoked
 * immediately after its read completes (o->scrub: unlinked and
 * invalidated instead, leaving no /proc/keys residue). Decrypts when o->key_hex is set.
 * Honors o->from_serials (direct serial list) when set. *out is a
 * malloc'd image the caller frees. Returns 0 / -1+err.
 *
 * wire v4 (experimental): for an ENCRYPTED KRH4 stash *out is the WIRE
 * itself (ciphertext, header-validated) — kr_exec_image streams it with
 * per-chunk AEAD decryption directly into the mapped image, so no full
 * plaintext buffer is ever built. kr_call_symbol refuses such a handoff
 * cleanly. Plaintext (flags=0) v4 bodies decrypt like v3.
 */
int kr_load_revoke(const kr_opts *o, void **out, size_t *outlen, char err[KR_ERRSZ]);

/*
 * Map img and jump to its entry point (or to a single RWX region when
 * o->raw). argv[0] is used as the spoofed process name and as the new
 * image's argv[0]; envp is the new environment. With o->clone_child the
 * payload runs in a clone() child instead: this RETURNS the payload's
 * exit status (or 128+signal) on success. Without it this NEVER RETURNS
 * on success. On failure returns -1 with err (the caller must flush
 * stdio before calling).
 */
int kr_exec_image(const void *img, size_t len, const kr_opts *o, int argc, char **argv, char **envp, char err[KR_ERRSZ]);

/*
 * Load + relocate a self-contained (-nostdlib, no undefined symbols)
 * shared object and call its exported function
 * `int sym(int argc, char **argv, char **envp)` on the normal stack.
 * Only R_X86_64_RELATIVE / R_X86_64_64 / R_X86_64_GLOB_DAT relocations
 * against locally defined symbols are applied; anything else (or an
 * undefined symbol) is a clean error — dynamic-linker relocation is
 * deliberately not attempted. x86-64 only (AArch64 builds return a
 * clean error). Returns 0 with *retval set / -1+err.
 */
int kr_call_symbol(const void *elf, size_t len, const kr_opts *o, int argc, char **argv, char **envp, long *retval, char err[KR_ERRSZ]);

/*
 * Crypto + integrity self-test: RFC 8439 §2.8.2 AEAD vector through the
 * AF_ALG path, a SHA-256 (AF_ALG) known-answer over the same plaintext,
 * a random seal/open roundtrip with tamper rejection, a full wire-v2
 * stash-format roundtrip (header + envelope) with digest verification,
 * a deliberate bit-flip that must FAIL verification, and a PR_SET_VMA
 * naming probe (nonfatal; result logged and cached for kr_vma_probe).
 * Returns 0 / -1+err.
 */
int kr_selftest(char err[KR_ERRSZ]);

/* library version string */
const char *kr_version(void);

/*
 * Optional progress hook (never writes anywhere itself). Set to NULL
 * (the default) for a fully silent library. Receives fmt + va_list and
 * is invoked for every verbose diagnostic the CLI prints to stderr.
 */
void kr_set_log(void (*fn)(const char *fmt, va_list ap));

/*
 * Let the library know the original process argv so kr_exec_image can
 * wipe the argv area (process-name spoofing phase). Optional; without
 * it no argv wiping happens.
 */
void kr_set_process_argv(int argc, char **argv);

/*
 * Fetch a URL into a malloc'd buffer (caller frees) via
 * dlopen("libcurl.so.4") at runtime — no link-time libcurl dependency.
 * TLS peer verification stays at libcurl's defaults (enabled) unless
 * insecure != 0 (CURLOPT_SSL_VERIFYPEER/HOST 0). proxy (may be NULL)
 * sets CURLOPT_PROXY; each extra_headers[i] string (NULL-terminated
 * array, may be NULL) is appended via curl_slist + CURLOPT_HTTPHEADER.
 * Returns 0 / -1+err.
 */
int kr_http_get_ex(const char *url, const char *proxy,
                   const char *const *extra_headers, int insecure,
                   void **out, size_t *outlen, char err[KR_ERRSZ]);

/* kr_http_get(url, ...) == kr_http_get_ex(url, NULL, NULL, 0, ...) */
int kr_http_get(const char *url, void **out, size_t *outlen, char err[KR_ERRSZ]);

/* ---- wire v2.2 additions ---- */

/*
 * Generate a fresh 32-byte key from getrandom(2)/urandom and encode it
 * as 64 lowercase hex chars + NUL into hexout. Returns 0 / -1+err.
 */
int kr_keygen(char hexout[KR_KEY_HEX_LEN + 1], char err[KR_ERRSZ]);

/*
 * One keepalive beat against the per-UID persistent keyring: performs
 * KEYCTL_GET_PERSISTENT (which refreshes the ring's expiry clock) and
 * then KEYCTL_SEARCHes the "<prefix>.000" chunk in that ring. Returns
 * the chunk serial (> 0) when present, 0 when the ring is alive but the
 * chunk is absent, -1+err when the ring itself is unavailable.
 */
long kr_keepalive_beat(const kr_opts *o, char err[KR_ERRSZ]);

/*
 * PR_SET_VMA (ANON_VMA_NAME) support probe: names one scratch page and
 * checks /proc/self/maps for the name. Returns 1 when naming works,
 * 0 when not (errno logged through the hook on first failure). The
 * result is probed once and cached.
 */
int kr_vma_probe(void);

/*
 * AF_ALG availability probe: binds ("hash"/"sha256") and
 * ("aead"/"rfc7539(chacha20,poly1305)") sockets. Returns 0 / -1+err
 * naming the algorithm that failed.
 */
int kr_alg_probe(char err[KR_ERRSZ]);

/*
 * clone(CLONE_VM) smoke test: spawns a child that _exit(0)s, waitpid()s
 * it and reports. Returns 0 / -1+err.
 */
int kr_clone_smoke(char err[KR_ERRSZ]);

/*
 * Live keyring-quota telemetry for the calling uid (see kr_quota above):
 * parses the kernel.keys sysctls plus this uid's /proc/key-users row.
 * Returns 0 with *q filled (measured=0 when the uid has no row yet —
 * fresh boot, used counters are genuinely 0) / -1+err only when the
 * quota LIMITS cannot be read (then callers must skip quota planning and
 * keep the mid-stash EDQUOT rollback as the backstop).
 */
int kr_quota_snapshot(kr_quota *q, char err[KR_ERRSZ]);

#ifdef __cplusplus
}
#endif

#endif /* KEYRINGER_H */
