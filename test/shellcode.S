/*
 * test/shellcode.S — raw shellcode payload for the keyringer --raw path.
 *
 * The Makefile assembles this into test/shellcode.bin (raw machine code
 * via objcopy -O binary -j .text; a few dozen bytes, position-
 * independent). The loader copies it into one RWX region and jumps to
 * the region start with a fresh SysV stack; this stub ignores
 * argc/argv: write(1, "raw ok\n", 7) then exit(0).
 */
    .text
    .globl _start
_start:
    leaq msg(%rip), %rsi        /* write(1, msg, 7) */
    movl $1, %edi
    movl $7, %edx
    movl $1, %eax
    syscall
    xorl %edi, %edi             /* exit(0) */
    movl $60, %eax
    syscall
msg:
    .ascii "raw ok\n"
