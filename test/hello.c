/*
 * test/hello.c — freestanding x86-64 test payload for keyringer.
 *
 * Prints "keyringer ok\n" via raw syscalls from _start; no libc, no
 * interpreter. Built -nostdlib -static and kept < 10 KB so it fits in
 * the 20000-byte non-root kernel keyring quota.
 */

static inline long sys3(long n, long a, long b, long c)
{
    long ret;

    __asm__ volatile ("syscall"
                      : "=a"(ret)
                      : "a"(n), "D"(a), "S"(b), "d"(c)
                      : "rcx", "r11", "memory");
    return ret;
}

__attribute__((noreturn)) void _start(void)
{
    static const char msg[] = "keyringer ok\n";

    sys3(1, 1, (long)msg, (long)(sizeof(msg) - 1));  /* write(1, msg, 13) */
    sys3(60, 0, 0, 0);                               /* exit(0)           */
    __builtin_unreachable();
}
