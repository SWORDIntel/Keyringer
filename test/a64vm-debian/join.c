/* join.c — join a named session keyring, then exec the real test script.
 * PID 1 in the VM has no session keyring; without a shared one, every
 * command child gets its own transient ring and stash->exec dies with it.
 * (Identical twin of the Alpine lane's join.c: __NR_keyctl is 219 on arm64
 * for every arm64 kernel, Debian's included.) */
#include <unistd.h>
#include <sys/syscall.h>
int main(int argc, char **argv)
{
	long rc = syscall(219 /* __NR_keyctl aarch64 */, 1 /* KEYCTL_JOIN_SESSION_KEYRING */,
	                  "krvm", 0);
	if (rc < 0) return 1;
	execv("/bin/sh", (char *[]){"/bin/sh", argv[1], 0});
	return 2;
}
