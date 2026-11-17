/*
 * test/hello_a64.c — freestanding AArch64 test payload for keyringer.
 *
 * Prints "keyringer ok\n" via raw svc syscalls from _start; no libc, no
 * interpreter. Built -nostdlib -static with a high text base so it can
 * never collide with the (also statically linked) loader image.
 * arm64 syscall numbers: write = 64, exit = 93.
 */

static inline long sys3(long n, long a, long b, long c)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;

    __asm__ volatile ("svc #0"
                      : "+r"(x0)
                      : "r"(x8), "r"(x1), "r"(x2)
                      : "memory");
    return x0;
}

__attribute__((noreturn)) void _start(void)
{
    static const char msg[] = "keyringer ok\n";

    sys3(64, 1, (long)msg, (long)(sizeof(msg) - 1));  /* write(1, msg, 13) */
    sys3(93, 0, 0, 0);                                /* exit(0)           */
    __builtin_unreachable();
}
