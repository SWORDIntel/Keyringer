/*
 * fuzz_elf.c — deterministic structured fuzzer for the phase-3 ELF
 * parsers (validate / PT_INTERP / PT_LOAD mapping / --call symtab +
 * relocations).  Seeds are the suite's real payload (test/hello) plus a
 * synthetic shared object with a section table, then heavy structure-
 * aware mutations: header-field chaos (e_phoff/e_phnum/e_shoff/...),
 * extreme p_offset/p_vaddr/p_memsz values including 64-bit wrap-inducing
 * ones, and out-of-range section descriptors.  Any crash is a bug: the
 * loader must reject hostile stashes cleanly.  Part of `make test`
 * (section 32); KR_FUZZ_ITERS overrides the iteration count.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <elf.h>

#include "../keyringer.h"

static uint64_t rng_state = 0xd1b54a32d192ed03ULL;

static uint64_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

/* a synthetic ET_DYN shared object: phdrs + section table + SYMTAB +
 * STRTAB + one SHT_RELA, so modes 2 and 3 get deep coverage */
static size_t build_fake_so(uint8_t *buf, size_t cap)
{
    memset(buf, 0, cap);
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    memcpy(eh->e_ident, "\177ELF\2\1\1", 8);
    eh->e_type = ET_DYN;
    eh->e_machine = EM_X86_64;
    eh->e_version = 1;
    eh->e_entry = 0x1000;
    eh->e_phentsize = sizeof(Elf64_Phdr);
    eh->e_phnum = 2;
    eh->e_phoff = sizeof(Elf64_Ehdr);
    eh->e_shentsize = sizeof(Elf64_Shdr);
    eh->e_shnum = 4;
    eh->e_shoff = 0x400;

    Elf64_Phdr *ph = (Elf64_Phdr *)(buf + eh->e_phoff);
    ph[0].p_type = PT_LOAD;
    ph[0].p_flags = PF_R | PF_X;
    ph[0].p_offset = 0x200;
    ph[0].p_vaddr = 0x1000;
    ph[0].p_filesz = 0x100;
    ph[0].p_memsz = 0x100;
    ph[1].p_type = PT_LOAD;
    ph[1].p_flags = PF_R | PF_W;
    ph[1].p_offset = 0x300;
    ph[1].p_vaddr = 0x2000;
    ph[1].p_filesz = 0x20;
    ph[1].p_memsz = 0x100;
    memset(buf + 0x200, 0xc3, 0x100);            /* ret sled "code" */

    Elf64_Shdr *sh = (Elf64_Shdr *)(buf + eh->e_shoff);
    sh[0].sh_type = SHT_NULL;
    sh[1].sh_type = SHT_SYMTAB;
    sh[1].sh_offset = 0x500;
    sh[1].sh_size = 3 * sizeof(Elf64_Sym);
    sh[1].sh_link = 2;
    sh[2].sh_type = SHT_STRTAB;
    sh[2].sh_offset = 0x600;
    sh[2].sh_size = 32;
    strcpy((char *)buf + 0x600, "kratest");
    sh[3].sh_type = SHT_RELA;
    sh[3].sh_offset = 0x700;
    sh[3].sh_size = 2 * sizeof(Elf64_Rela);
    Elf64_Sym *syms = (Elf64_Sym *)(buf + 0x500);
    syms[1].st_name = 1;
    syms[1].st_info = (1 << 4) | STT_FUNC;       /* global func, defined */
    syms[1].st_shndx = 1;
    syms[1].st_value = 0x1000;
    Elf64_Rela *rela = (Elf64_Rela *)(buf + 0x700);
    rela[0].r_offset = 0x2000;
    rela[0].r_info = (uint64_t)1 << 32 | 8u;     /* R_X86_64_RELATIVE */
    rela[0].r_addend = 0x1000;
    rela[1].r_offset = 0x2008;
    rela[1].r_info = (uint64_t)1 << 32 | 6u;     /* R_X86_64_GLOB_DAT */
    return 0x800;
}

static void mutate(uint8_t *buf, size_t *len, size_t cap)
{
    switch (rnd() % 7) {
    case 0:                                          /* random bit flips */
        for (int i = 0; i < 8; i++)
            buf[rnd() % *len] ^= (uint8_t)(1u << (rnd() % 8));
        break;
    case 1:                                          /* ehdr field chaos */
        switch (rnd() % 6) {
        case 0: ((Elf64_Ehdr *)buf)->e_phoff = rnd() & 0xffff; break;
        case 1: ((Elf64_Ehdr *)buf)->e_phnum = (uint16_t)rnd(); break;
        case 2: ((Elf64_Ehdr *)buf)->e_phentsize = (uint16_t)rnd(); break;
        case 3: ((Elf64_Ehdr *)buf)->e_shoff = rnd() & 0xffffffffULL; break;
        case 4: ((Elf64_Ehdr *)buf)->e_shnum = (uint16_t)rnd(); break;
        default: ((Elf64_Ehdr *)buf)->e_shentsize = (uint16_t)rnd(); break;
        }
        break;
    case 2: {                                        /* phdr value chaos */
        if (*len < sizeof(Elf64_Ehdr) + 4 * sizeof(Elf64_Phdr))
            break;
        Elf64_Phdr *ph = (Elf64_Phdr *)(buf +
            ((Elf64_Ehdr *)buf)->e_phoff % (*len - 4 * sizeof(Elf64_Phdr)));
        Elf64_Phdr *p = &ph[rnd() % 4];
        switch (rnd() % 4) {
        case 0: p->p_offset = rnd() & 0xffffffffULL; break;
        case 1: p->p_vaddr = rnd() & 0xfffffffffffff000ULL; break;
        case 2: p->p_memsz = rnd() & 0xffffffffULL; break;
        default: p->p_filesz = rnd() & 0xffffffffULL; break;
        }
        break;
    }
    case 3:                                          /* truncate */
        *len = 8 + rnd() % (*len - 8);
        break;
    case 4:                                          /* ident chaos */
        buf[rnd() % 16] = (uint8_t)rnd();
        break;
    case 5: {                                        /* shdr value chaos */
        if (*len < 0x400 + 4 * sizeof(Elf64_Shdr))
            break;
        Elf64_Shdr *sh = (Elf64_Shdr *)(buf + 0x400);
        Elf64_Shdr *s = &sh[rnd() % 4];
        switch (rnd() % 3) {
        case 0: s->sh_offset = rnd() & 0xffffffffULL; break;
        case 1: s->sh_size = rnd() & 0xffffffffULL; break;
        default: s->sh_link = (uint32_t)rnd(); break;
        }
        break;
    }
    default: {                                       /* splice body bytes */
        size_t a = KR_HDR3_LEN + rnd() % (*len - KR_HDR3_LEN - 32);
        memcpy(buf + a, buf + a + 16, 16);
        break;
    }
    }
    if (*len > cap)
        *len = cap;
}

int main(void)
{
    char err[KR_ERRSZ];
    uint8_t seed_hello[16384], seed_so[4096];
    size_t n_hello = 0, n_so;
    long iters = 100000;
    const char *env = getenv("KR_FUZZ_ITERS");

    if (env && *env)
        iters = strtol(env, NULL, 10);

    FILE *f = fopen("test/hello", "rb");

    if (f) {
        n_hello = fread(seed_hello, 1, sizeof seed_hello, f);
        fclose(f);
    }
    if (n_hello == 0) {
        printf("fuzz-elf: no test/hello seed; synthetic-only run\n");
        n_hello = build_fake_so(seed_hello, sizeof seed_hello);
    }
    n_so = build_fake_so(seed_so, sizeof seed_so);

    /* sanity: the untouched seeds must validate (mode 0) */
    if (kr_elf_fuzz_entry(seed_hello, n_hello, 0, err) != 0) {
        printf("fuzz-elf: FAIL sanity: seed hello rejected: %s\n", err);
        return 1;
    }

    uint8_t buf[sizeof seed_hello];
    int accepted = 0, rejected = 0, unsupported = 0;
    clock_t budget = 20 * CLOCKS_PER_SEC;   /* hard wall-clock bound */
    const char *secs = getenv("KR_FUZZ_SECS");

    if (secs && *secs)
        budget = strtol(secs, NULL, 10) * CLOCKS_PER_SEC;
    clock_t t0 = clock();

    for (long it = 0; it < iters; it++) {
        /* weight toward the pure-parse modes: mapping modes cost 2-4
         * syscalls each and dominate the wall clock otherwise */
        uint64_t msel = rnd();
        int mode = (msel % 10 < 8) ? (int)(msel & 1) : 2 + (int)(msel & 1);

        if ((it & 1023) == 0 && clock() - t0 > budget) {
            iters = it;                      /* budget hit: report actual */
            printf("fuzz-elf: wall-clock budget reached at iteration %ld\n",
                   it);
            break;
        }
        const uint8_t *seed = (rnd() & 1) ? seed_hello : seed_so;
        size_t len = seed == seed_hello ? n_hello : n_so;

        memcpy(buf, seed, len);
        mutate(buf, &len, sizeof buf);
        int rc = kr_elf_fuzz_entry(buf, len, mode, err);
        if (rc == 0)
            accepted++;
        else if (rc == -2)
            unsupported++;
        else
            rejected++;
    }
    printf("fuzz-elf: %ld mutations survived (accepted=%d rejected=%d "
           "unsupported=%d)\n", iters, accepted, rejected, unsupported);
    return 0;
}
