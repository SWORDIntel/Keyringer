/*
 * test/shellcode7.S — raw shellcode payload for the keyringer --clone
 * path (wire v2.2). Same as shellcode.S but exits 7, which proves the
 * clone-child's exit status propagates: `kfile --clone --raw` must
 * return 7.
 */
    .text
    .globl _start
_start:
    leaq msg(%rip), %rsi        /* write(1, msg, 7) */
    movl $1, %edi
    movl $7, %edx
    movl $1, %eax
    syscall
    movl $7, %edi               /* exit(7) */
    movl $60, %eax
    syscall
msg:
    .ascii "clone7\n"
