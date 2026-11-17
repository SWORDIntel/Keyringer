/*
 * kr_fuzz_server.c — TCP target adapter so vr-fuzz (ASIC-SOC) can fuzz the
 * Keyringer ELF-loader and wire-open parsers through its persistent_tcp
 * driver, with coverage observed externally by the eBPF sensor (the target
 * is not instrumented).
 *
 * Protocol (matched to PersistentTcpDriver: raw send, idle-detect read,
 * short fixed-length response):
 *   request  = raw fuzz bytes, one input per write, up to 1 MiB
 *   response = exactly 8 bytes: "KRf" + 'A'|'R' + 4-digit ascii rc + '\n'
 *              ('A' accepted, 'R' rejected; digits = entry return code)
 *
 * Input routing (this is the tuning): if the input starts with a wire
 * magic ("KRH3"/"KRH1"/"KR1") it goes to the wire-open parser, otherwise
 * to the ELF phase-3 parsers with mode = input length & 3 — the payload
 * reaches the parser byte-for-byte unmodified (vr-fuzz sends raw corpus
 * bytes), and the mode still varies deterministically across the corpus
 * so all four parser modes get exercised from one seed set.
 *
 * Isolation: one forked child per connection — a hard crash kills only the
 * connection (vr-fuzz sees PeerClose and records it) while the listener
 * survives for the next generation.
 *
 * Usage: kr_fuzz_server [port]     (default 12871)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/wait.h>

int kr_elf_fuzz_entry(const uint8_t *img, size_t len, int mode, char *err);
int kr_wire_fuzz_entry(const uint8_t *wire, size_t wirelen,
                       const char *keyhex, char *err);

static void respond(int fd, char kind, int rc)
{
    char out[8];
    int v = rc < 0 ? -rc : rc;

    memcpy(out, "KRf", 3);
    out[3] = kind;
    out[4] = (char)('0' + (v / 100) % 10);
    out[5] = (char)('0' + (v / 10) % 10);
    out[6] = (char)('0' + v % 10);
    out[7] = '\n';
    (void)send(fd, out, 8, MSG_NOSIGNAL);
}

static void serve_connection(int fd)
{
    uint8_t buf[1024 * 1024];
    char err[256];

    for (;;) {
        /* one input per write from vr-fuzz; a short read window is fine */
        ssize_t n = recv(fd, buf, sizeof buf, 0);

        if (n <= 0)
            return;                       /* peer closed: done */
        if (n >= 4 && (memcmp(buf, "KRH3", 4) == 0 ||
                       memcmp(buf, "KRH1", 4) == 0 ||
                       memcmp(buf, "KR1", 3) == 0)) {
            int rc = kr_wire_fuzz_entry(buf, (size_t)n, NULL, err);
            respond(fd, rc == 0 ? 'A' : 'R', rc);
        } else {
            int mode = (int)(n & 3);
            int rc = kr_elf_fuzz_entry(buf, (size_t)n, mode, err);
            respond(fd, rc == 0 ? 'A' : 'R', rc);
        }
    }
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 12871;

    signal(SIGPIPE, SIG_IGN);
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;

    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((uint16_t)port);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(ls, 16) != 0) {
        perror("listen");
        return 1;
    }
    fprintf(stderr, "kr_fuzz_server: listening on 127.0.0.1:%d\n", port);

    for (;;) {
        int fd = accept(ls, NULL, NULL);

        if (fd < 0)
            continue;
        pid_t pid = fork();

        if (pid == 0) {
            close(ls);
            int nd = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nd, sizeof nd);
            serve_connection(fd);
            close(fd);
            _exit(0);
        }
        close(fd);
        /* reap finished children so the listener never blocks */
        while (waitpid(-1, NULL, WNOHANG) > 0)
            ;
    }
}
