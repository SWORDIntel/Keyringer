/*
 * test/lib.c — freestanding shared object for the keyringer --call path.
 *
 * Built -nostdlib -shared -fPIC: no libc, no undefined symbols, so the
 * loader's own RELATIVE/64/GLOB_DAT relocator can resolve it (documented
 * in usage(): --call is only for self-contained -nostdlib .so files).
 *
 * Exports kratest(argc, argv, envp), which writes "call ok <argv[1]>\n"
 * via a raw write(2) syscall (inline asm — NO libc) and returns 42.
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

__attribute__((visibility("default")))
int kratest(int argc, char **argv, char **envp)
{
    (void)argc;
    (void)envp;

    static const char pre[] = "call ok ";
    static const char nl[] = "\n";

    sys3(1, 1, (long)pre, (long)(sizeof(pre) - 1));

    const char *arg = (argv && argv[1]) ? argv[1] : "";
    long n = 0;

    while (arg[n])
        n++;
    if (n)
        sys3(1, 1, (long)arg, n);
    sys3(1, 1, (long)nl, (long)(sizeof(nl) - 1));
    return 42;
}
