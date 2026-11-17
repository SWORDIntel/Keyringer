# keyringer — Linux x86-64/AArch64 kernel-keyring fileless exec loader
#
# Targets:
#   all     keyringer                     CLI, musl-gcc -static (fallback: cc -static)
#   lib     libkeyringer.so libkeyringer.a  library build (-fPIC -shared / ar)
#   libtest build+run a trivial -lkeyringer consumer (kr_stash/kr_selftest)
#   test    full test suite (see below)
#   clean
#
# AArch64 lane: make ARCH=aarch64 [test]
#   Builds keyringer.aarch64 with aarch64-linux-gnu-gcc -static (musl-gcc
#   is x86-only; glibc static is fine) and test/hello_a64, then runs the
#   emulated suite under qemu-aarch64. qemu passes guest syscalls through
#   to the real kernel, so the keyring stash is REAL where the qemu build
#   supports keyring passthrough; the suite probes that and skips with an
#   explanation where it does not.
#
# Note on khttp: khttp dlopen()s libcurl.so.4 at runtime. musl -static
# binaries cannot dlopen at all ("Dynamic loading not supported"), so
# `keyringer-dyn` (same sources, dynamically linked) is built for the
# khttp test path; the static CLI reports the documented clean error.

ARCH ?= x86_64

MUSL := $(shell command -v musl-gcc 2>/dev/null)

ifeq ($(MUSL),)
CC     := cc
CC_DYN ?= cc
else
CC     := $(MUSL)
CC_DYN ?= cc
endif

# AArch64 lane toolchain (musl-gcc is x86-only; glibc static is fine)
A64_CC    := aarch64-linux-gnu-gcc
QEMU_A64  := qemu-aarch64

CFLAGS ?= -Wall -Wextra -O2
CFLAGS += -std=c11

# Freestanding test payload: ET_EXEC at a high base (0x40000000) so it can
# never collide with this statically-linked loader mapped at 0x400000.
HELLO_CFLAGS := -std=c11 -nostdlib -static -no-pie -Os -s \
                -Wl,--build-id=none -Wl,-Ttext-segment=0x40000000

# AArch64 twin of test/hello (arm64 write=64 exit=93 via svc #0)
A64_HELLO_CFLAGS := $(HELLO_CFLAGS)

# Self-contained test shared object for --call: no libc, no undefined
# symbols, unstripped (SHT_SYMTAB required by the in-loader relocator).
LIBSO_CFLAGS := -std=c11 -nostdlib -shared -fPIC -O1 -Wall -Wextra

ifeq ($(ARCH),aarch64)
.DEFAULT_GOAL := keyringer.aarch64
endif

all: keyringer

keyringer: main.c kr_core.c keyringer.h
	$(CC) $(CFLAGS) -static -o $@ main.c kr_core.c

# dynamically linked build; identical sources — exists so khttp can
# actually dlopen the host's glibc libcurl.so.4
keyringer-dyn: main.c kr_core.c keyringer.h
	$(CC_DYN) $(CFLAGS) -o $@ main.c kr_core.c -ldl

# AArch64 lane: glibc static (musl-gcc is x86-only). KR_NO_DLOPEN keeps
# the static link free of the glibc "Using 'dlopen' in statically linked
# applications" linker warning — preflight/khttp report the documented
# clean error instead.
keyringer.aarch64: main.c kr_core.c keyringer.h
	$(A64_CC) $(CFLAGS) -DKR_NO_DLOPEN -static -o $@ main.c kr_core.c

# --------------------------------------------------------------------- #
# library
# --------------------------------------------------------------------- #

lib: libkeyringer.so libkeyringer.a

kr_core.o: kr_core.c keyringer.h
	$(CC) $(CFLAGS) -fPIC -c -o $@ kr_core.c

libkeyringer.so: kr_core.o
	$(CC) -shared -o $@ kr_core.o

libkeyringer.a: kr_core.o
	ar rcs $@ kr_core.o

test/libuser: test/libuser.c libkeyringer.so keyringer.h
	$(CC) $(CFLAGS) -I. -o $@ test/libuser.c -L. -lkeyringer \
	    -Wl,-rpath,$(CURDIR)

libtest: test/libuser
	./test/libuser

# --------------------------------------------------------------------- #
# test payloads
# --------------------------------------------------------------------- #

test/hello: test/hello.c
	$(CC) $(HELLO_CFLAGS) -o $@ test/hello.c

test/hello_a64: test/hello_a64.c
	$(A64_CC) $(A64_HELLO_CFLAGS) -o $@ test/hello_a64.c

test/lib.so: test/lib.c
	$(CC) $(LIBSO_CFLAGS) -o $@ test/lib.c

test/shellcode.bin: test/shellcode.S
	$(CC) -c -o test/shellcode.o test/shellcode.S
	objcopy -O binary -j .text test/shellcode.o $@

# exit(7) twin for the --clone exit-status propagation test
test/shellcode7.bin: test/shellcode7.S
	$(CC) -c -o test/shellcode7.o test/shellcode7.S
	objcopy -O binary -j .text test/shellcode7.o $@

# --------------------------------------------------------------------- #
# test suite (non-root; keyring quota here is 20000 bytes total, every
# payload stays under ~15 KB; sudo -n is used for the root-quota tests)
# Wire v4 is the DEFAULT writer (core 4.0): section 36 proves a default
# stash carries the KRH4 magic, section 27 pins the KR_WIRE=3 downgrade,
# section 11 the --selfcontained auto-v3, section 4 the --call full-buffer
# exception (the one documented break of v4 streaming).
# Section 37 covers quota telemetry + upfront stash planning: the live
# preflight keyring-quota measurement (cross-checked against
# /proc/key-users, twin-parity asserted), the clean refuse-before-store
# failure with an exhausted quota (zero keys added; the twin likewise),
# the nonfatal >50% warning with a charge-delta parse cross-check, and —
# via a brief, always-restored kernel.keys.maxkeys sysctl dip under sudo —
# the auto-big_key maxkeys-relief selection plus the maxkeys-exhausted
# clean failure.
# --------------------------------------------------------------------- #

ifeq ($(ARCH),aarch64)
test: test_a64
else
test: test_x86
endif

test_x86: keyringer keyringer-dyn test/hello test/lib.so test/shellcode.bin \
          test/shellcode7.bin
	@set -e; \
	echo "=== keyringer test suite ==="; \
	echo "-- 0: cleanup of stale suite keys (non-root quota is tight) --"; \
	uid=$$(id -u); \
	for d in $$(awk -v u="$$uid" 'substr($$2,2,1)!="R" && ($$8=="user" || $$8=="big_key") && \
	    $$6==u && $$10+0>0 {print $$9}' /proc/keys 2>/dev/null | \
	    sed 's/:$$//' | grep -E '^(_keyringer|mytest\.abc|dxa\.|dxt\.|dxl\.|shr|bkt\.|kfd\.|ag\.|scx\.|flp|qf|qa|qw\.|qm\.|qpy\.)' || true); do \
	    s=$$(keyctl search @s user "$$d" 2>/dev/null || keyctl search @s big_key "$$d" 2>/dev/null || true); \
	    if [ -n "$$s" ]; then keyctl revoke "$$s" 2>/dev/null || true; \
	        echo "   revoked stale key $$d"; fi; \
	done; \
	echo "-- 1: selftest (RFC 8439 AEAD vector, SHA-256 KAT, wire-v2 roundtrip + tamper check, VMA probe) --"; \
	./keyringer selftest; \
	echo "-- 2: hello via kfile --"; \
	out=$$(./keyringer kfile test/hello hello 2>/dev/null); \
	test "$$out" = "keyringer ok"; \
	echo "ok: $$out"; \
	echo "-- 3: hello via kstdin --"; \
	out=$$(./keyringer kstdin hello < test/hello 2>/dev/null); \
	test "$$out" = "keyringer ok"; \
	echo "ok: $$out"; \
	echo "-- 4: --call kratest via stash+exec (expects exit 42); encrypted v4 (default) --call = full-buffer decrypt --"; \
	./keyringer stash test/lib.so 2>/dev/null; \
	rc=0; out=$$(./keyringer exec --call kratest name testarg 2>/dev/null) || rc=$$?; \
	test "$$out" = "call ok testarg" || { echo "FAIL: got \"$$out\""; exit 1; }; \
	test "$$rc" -eq 42 || { echo "FAIL: exit code $$rc, want 42"; exit 1; }; \
	echo "ok: $$out (exit $$rc)"; \
	CK=$$(./keyringer keygen); \
	./keyringer stash --key $$CK test/lib.so >/dev/null 2>&1; \
	rc=0; out=$$(./keyringer exec --key $$CK --call kratest name encarg 2>v4.tmp) || rc=$$?; \
	test "$$out" = "call ok encarg" || { echo "FAIL: enc --call got \"$$out\""; cat v4.tmp; rm -f v4.tmp; exit 1; }; \
	test "$$rc" -eq 42 || { echo "FAIL: enc --call exit code $$rc, want 42"; exit 1; }; \
	grep -q "v4: full-buffer decrypt (--call relocation path; streaming applies to jump exec)" v4.tmp || \
	    { echo "FAIL: no full-buffer decrypt log line:"; cat v4.tmp; rm -f v4.tmp; exit 1; }; \
	echo "ok: encrypted v4 (default wire) --call roundtrip: $$out (exit $$rc; the documented relocation-path exception to streaming)"; \
	rm -f v4.tmp; \
	echo "-- 5: --raw shellcode via kfile --"; \
	out=$$(./keyringer kfile --raw test/shellcode.bin 2>/dev/null); \
	test "$$out" = "raw ok"; \
	echo "ok: $$out"; \
	echo "-- 6: encrypted roundtrip + tamper rejection --"; \
	K1=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff; \
	K2=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef; \
	./keyringer stash --key $$K1 test/hello 2>/dev/null; \
	out=$$(./keyringer exec --key $$K1 hello 2>/dev/null); \
	test "$$out" = "keyringer ok"; \
	echo "ok: sealed roundtrip ($$out)"; \
	./keyringer stash --key $$K1 test/hello 2>/dev/null; \
	if out=$$(./keyringer exec --key $$K2 hello 2>err.tmp); then \
	    echo "FAIL: wrong key accepted: $$out"; rm -f err.tmp; exit 1; fi; \
	grep -q "AEAD authentication failed" err.tmp || \
	    { echo "FAIL: wrong-key failure was not an AEAD failure"; cat err.tmp; rm -f err.tmp; exit 1; }; \
	echo "ok: wrong key rejected cleanly (no jump): $$out"; rm -f err.tmp; \
	echo "-- 7: custom prefix via --desc --"; \
	./keyringer stash --desc mytest.abc test/hello 2>/dev/null; \
	./keyringer list --desc mytest.abc | grep -q "mytest.abc.000"; \
	echo "ok: list --desc mytest.abc found mytest.abc.000"; \
	out=$$(./keyringer exec --desc mytest.abc hello 2>/dev/null); \
	test "$$out" = "keyringer ok"; \
	echo "ok: exec --desc mytest.abc ($$out)"; \
	echo "-- 8: persistent keyring (stash --persistent, session-empty fallback) --"; \
	./keyringer stash --persistent test/hello 2>/dev/null; \
	if command -v keyctl >/dev/null 2>&1; then \
	    keyctl show @u | grep -q "_persistent." || \
	        { echo "FAIL: persistent ring not under keyctl show @u"; exit 1; }; \
	    echo "ok: keyctl show @u shows _persistent.$$(id -u)"; \
	fi; \
	out=$$(./keyringer exec hello 2>/dev/null); \
	test "$$out" = "keyringer ok"; \
	echo "ok: persistent fallback exec ($$out)"; \
	./keyringer stash --persistent test/hello 2>/dev/null; \
	out=$$(./keyringer exec --persistent hello 2>/dev/null); \
	test "$$out" = "keyringer ok"; \
	echo "ok: exec --persistent ($$out)"; \
	echo "-- 9: khttp against a local HTTP server (dynamic build; static musl cannot dlopen) --"; \
	( cd test && exec python3 -m http.server 18091 ) >/dev/null 2>&1 & srv=$$!; \
	up=0; i=0; \
	while [ $$i -lt 50 ]; do \
	    python3 -c "import socket; socket.create_connection(('127.0.0.1', 18091), 0.25).close()" 2>/dev/null && { up=1; break; }; \
	    i=$$((i+1)); sleep 0.1; \
	done; \
	test $$up -eq 1 || { kill $$srv 2>/dev/null || true; echo "FAIL: http server did not start"; exit 1; }; \
	out=$$(./keyringer-dyn khttp http://127.0.0.1:18091/hello hello 2>/dev/null); rc=$$?; \
	test $$rc -eq 0 || { kill $$srv 2>/dev/null || true; echo "FAIL: khttp exited $$rc"; exit 1; }; \
	test "$$out" = "keyringer ok" || { kill $$srv 2>/dev/null || true; echo "FAIL: got \"$$out\""; exit 1; }; \
	echo "ok: khttp ($$out)"; \
	echo "-- 10: wire v2 integrity digest (stash+exec, keyctl tamper, legacy tolerance) --"; \
	pfx="dxa.$$$$"; \
	out=$$(./keyringer stash --desc "$$pfx" test/hello 2>v2.tmp && ./keyringer exec --desc "$$pfx" hello 2>>v2.tmp); \
	test "$$out" = "keyringer ok" || { echo "FAIL: v2 stash+exec broken"; cat v2.tmp; rm -f v2.tmp; exit 1; }; \
	grep -q "integrity digest" v2.tmp || { echo "FAIL: load did not verify the digest"; cat v2.tmp; rm -f v2.tmp; exit 1; }; \
	echo "ok: v2 stash+exec ($$out, sha256 digest verified)"; \
	pfx="dxt.$$$$"; \
	./keyringer stash --desc "$$pfx" test/shellcode.bin 2>/dev/null; \
	ser=$$(keyctl search @s user "$$pfx.000" 2>/dev/null || true); \
	test -n "$$ser" || { echo "FAIL: keyctl search found no $$pfx.000"; rm -f v2.tmp; exit 1; }; \
	python3 -c "import hashlib; d=open('test/shellcode.bin','rb').read(); blob=bytearray(b'KRH1'+(0).to_bytes(4,'little')+hashlib.sha256(d).digest()+d); blob[45]^=1; open('v2.tampered','wb').write(bytes(blob))"; \
	keyctl pupdate "$$ser" < v2.tampered; \
	if out=$$(./keyringer exec --raw --desc "$$pfx" hello 2>v2.tmp); then \
	    echo "FAIL: tampered stash accepted: $$out"; rm -f v2.tmp v2.tampered; exit 1; fi; \
	test -z "$$out" || { echo "FAIL: payload output on tampered stash: $$out"; rm -f v2.tmp v2.tampered; exit 1; }; \
	grep -q "digest MISMATCH" v2.tmp || { echo "FAIL: wrong failure mode:"; cat v2.tmp; rm -f v2.tmp v2.tampered; exit 1; }; \
	echo "ok: tampered stash rejected (digest mismatch, nonzero exit, no payload output)"; \
	pfx="dxl.$$$$"; \
	./keyringer stash --desc "$$pfx" test/shellcode.bin 2>/dev/null; \
	ser=$$(keyctl search @s user "$$pfx.000" 2>/dev/null || true); \
	test -n "$$ser" || { echo "FAIL: keyctl search found no $$pfx.000"; rm -f v2.tmp; exit 1; }; \
	keyctl pupdate "$$ser" < test/shellcode.bin; \
	out=$$(./keyringer exec --raw --desc "$$pfx" hello 2>v2.tmp); \
	test "$$out" = "raw ok" || { echo "FAIL: legacy headerless stash no longer loadable: $$out"; cat v2.tmp; rm -f v2.tmp v2.tampered; exit 1; }; \
	grep -q "pre-v2 stash" v2.tmp || { echo "FAIL: no pre-v2 note on legacy load"; cat v2.tmp; rm -f v2.tmp v2.tampered; exit 1; }; \
	echo "ok: legacy (headerless pre-v2) stash still loads ($$out)"; \
	rm -f v2.tmp v2.tampered; \
	echo "-- 11: --selfcontained (sudo: /bin/true + ld.so exceed the non-root quota; wires AUTO-v3 under the v4 default) --"; \
	if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then \
	    pfx="scx.$$$$"; \
	    sudo -n ./keyringer stash --selfcontained --desc "$$pfx" /bin/true >/dev/null 2>sc.log; \
	    grep -q "stash: --selfcontained uses wire v3 (v4 ldso support pending)" sc.log || \
	        { echo "FAIL: no selfcontained auto-v3 log:"; cat sc.log; rm -f sc.log; exit 1; }; \
	    mag=$$(sudo -n keyctl pipe $$(sudo -n keyctl search @s user "$$pfx.000" 2>/dev/null) 2>/dev/null | head -c 4); \
	    magl=$$(sudo -n keyctl pipe $$(sudo -n keyctl search @s user "$$pfx.ldso.000" 2>/dev/null) 2>/dev/null | head -c 4); \
	    test "$$mag" = "KRH3" || { echo "FAIL: selfcontained payload chunk is [$$mag], want KRH3"; exit 1; }; \
	    test "$$magl" = "KRH3" || { echo "FAIL: selfcontained ldso chunk is [$$magl], want KRH3"; exit 1; }; \
	    rm -f sc.log; \
	    sudo -n ./keyringer exec --selfcontained --desc "$$pfx" true >/dev/null 2>&1 || \
	        { echo "FAIL: selfcontained exec of the auto-v3 stash"; exit 1; }; \
	    echo "ok: selfcontained stash+exec (/bin/true + ldso chunks; payload and ldso wires auto-v3, log line seen)"; \
	    sudo -n ./keyringer kfile --selfcontained --desc "$$pfx" /bin/true 2>/dev/null; \
	    echo "ok: kfile --selfcontained one-shot (auto-v3)"; \
	    sudo -n ./keyringer kfile --desc "$$pfx" /bin/true 2>/dev/null; \
	    echo "ok: without the flag the disk interpreter path still works"; \
	    sudo -n env KEYRINGER_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
	        ./keyringer kfile --selfcontained --desc "$$pfx" /bin/true 2>/dev/null; \
	    echo "ok: --key seals the payload; interpreter chunks stay plaintext and still verify"; \
	    sudo -n ./keyringer stash --desc "$$pfx" /bin/true >/dev/null 2>&1; \
	    if sudo -n ./keyringer exec --selfcontained nm --desc "$$pfx" 2>sc.err; then \
	        echo "FAIL: --selfcontained exec accepted a stash without .ldso chunks"; \
	        rm -f sc.err; exit 1; fi; \
	    grep -q "ldso" sc.err || { cat sc.err; rm -f sc.err; exit 1; }; \
	    echo "ok: missing .ldso.* chunks rejected cleanly"; \
	    rm -f sc.err; \
	else \
	    echo "SKIP: sudo -n unavailable — root-quota selfcontained tests skipped"; \
	fi; \
	echo "-- 12: keygen + --keyfd roundtrips (64-hex and raw-32-bytes) and precedence --"; \
	k1=$$(./keyringer keygen); \
	expr "$$k1" : '[0-9a-f]\{64\}$$' >/dev/null || { echo "FAIL: keygen output malformed: $$k1"; exit 1; }; \
	echo "ok: keygen prints 64 hex chars"; \
	rm -f kfd.fifo; mkfifo kfd.fifo; \
	( printf '%s' "$$k1" > kfd.fifo ) & writer=$$!;\
	out=$$(./keyringer kstdin --keyfd 3 hello 3<kfd.fifo < test/hello 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: keyfd hex roundtrip: $$out"; rm -f kfd.fifo; exit 1; }; \
	wait $$writer 2>/dev/null || true; rm -f kfd.fifo; \
	echo "ok: --keyfd with 64 hex chars ($$out)"; \
	k2=$$(./keyringer keygen); \
	rm -f kfd.fifo; mkfifo kfd.fifo; \
	( python3 -c "import sys,binascii; open('kfd.fifo','wb').write(binascii.unhexlify('$$k2'))" ) & writer=$$!;\
	out=$$(./keyringer kstdin --keyfd 3 hello 3<kfd.fifo < test/hello 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: keyfd raw roundtrip: $$out"; rm -f kfd.fifo; exit 1; }; \
	wait $$writer 2>/dev/null || true; rm -f kfd.fifo; \
	echo "ok: --keyfd with raw 32 bytes ($$out)"; \
	K2=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef; \
	k3=$$(./keyringer keygen); \
	rm -f kfd.fifo; mkfifo kfd.fifo; \
	( printf '%s' "$$k3" > kfd.fifo ) & writer=$$!;\
	out=$$(KEYRINGER_KEY=$$K2 ./keyringer kstdin --keyfd 3 hello 3<kfd.fifo < test/hello 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: --keyfd should beat env: $$out"; rm -f kfd.fifo; exit 1; }; \
	wait $$writer 2>/dev/null || true; rm -f kfd.fifo; \
	echo "ok: precedence --keyfd beats a wrong env key ($$out)"; \
	echo "-- 13: preflight (exit 0 here; CRITICAL checks pass; lines well-formed) --"; \
	./keyringer preflight > pre.tmp; rc=$$?; \
	test $$rc -eq 0 || { echo "FAIL: preflight exited $$rc"; cat pre.tmp; rm -f pre.tmp; exit 1; }; \
	lines=$$(grep -c "^preflight: " pre.tmp); \
	test $$lines -ge 8 || { echo "FAIL: only $$lines preflight lines"; cat pre.tmp; rm -f pre.tmp; exit 1; }; \
	grep -q "wx: .*PASS \[CRITICAL\]" pre.tmp || { echo "FAIL: W^X not PASS"; cat pre.tmp; exit 1; }; \
	grep -q "seccomp: .*PASS \[CRITICAL\]" pre.tmp || { echo "FAIL: seccomp not PASS"; cat pre.tmp; exit 1; }; \
	echo "ok: preflight ($$lines well-formed checks, exit 0)"; \
	sed 's/^   /   /' pre.tmp | sed 's/^/   /'; rm -f pre.tmp; \
	echo "-- 14: agent (KAG1 frames: ELF hello + raw shellcode + terminator) --"; \
	python3 test/agent_feed.py > agent.frames; \
	out=$$(./keyringer agent --ctlfd 3 </dev/null 3<agent.frames 2>/dev/null); rc=$$?; \
	test $$rc -eq 0 || { echo "FAIL: agent exited $$rc"; echo "$$out"; rm -f agent.frames; exit 1; }; \
	echo "$$out" | grep -q "keyringer ok" || { echo "FAIL: hello frame output missing"; echo "$$out"; rm -f agent.frames; exit 1; }; \
	echo "$$out" | grep -q "raw ok" || { echo "FAIL: shellcode frame output missing"; echo "$$out"; rm -f agent.frames; exit 1; }; \
	n=$$(echo "$$out" | grep -c "^agent: ran "); \
	test "$$n" -eq 2 || { echo "FAIL: expected 2 agent lines, got $$n"; echo "$$out"; rm -f agent.frames; exit 1; }; \
	echo "$$out" | sed 's/^/   /'; \
	echo "ok: agent ran 2 frames, parent exit 0"; \
	rm -f agent.frames; \
	echo "-- 15: --clone (shellcode7 exits 7 through waitpid) --"; \
	rc=0; ./keyringer kfile --clone --raw test/shellcode7.bin >/dev/null 2>&1 || rc=$$?; \
	test $$rc -eq 7 || { echo "FAIL: --clone exit $$rc, want 7"; exit 1; }; \
	echo "ok: --clone returned the payload exit status 7"; \
	echo "-- 16: keepalive (2 beats, then --unit text) --"; \
	beats=$$(./keyringer keepalive --times 2 --interval 1 2>/dev/null | grep -c "keepalive: ring alive"); \
	test "$$beats" -eq 2 || { echo "FAIL: expected 2 beats, got $$beats"; exit 1; }; \
	echo "ok: keepalive --times 2 --interval 1 printed 2 beats, exit 0"; \
	./keyringer keepalive --unit > unit.tmp; \
	grep -q "OnUnitActiveSec=" unit.tmp || { echo "FAIL: timer missing OnUnitActiveSec"; cat unit.tmp; rm -f unit.tmp; exit 1; }; \
	grep -q "ExecStart=.*keyringer keepalive --interval" unit.tmp || { echo "FAIL: service missing ExecStart"; cat unit.tmp; rm -f unit.tmp; exit 1; }; \
	echo "ok: --unit prints a systemd USER service+timer pair"; \
	rm -f unit.tmp; \
	echo "-- 17: --type big_key roundtrip (quota freed first; big_key counts against the same quota) --"; \
	cp test/shellcode.bin big.tmp; truncate -s 10240 big.tmp; \
	pfx="bkt.$$$$"; \
	./keyringer stash --type big_key --desc "$$pfx" - < big.tmp 2>/dev/null; \
	out=$$(./keyringer exec --raw --desc "$$pfx" bkname 2>/dev/null); \
	test "$$out" = "raw ok" || { echo "FAIL: big_key roundtrip: $$out"; rm -f big.tmp; exit 1; }; \
	echo "ok: big_key stash+exec ($$out; exec lookup found the big_key chunk without --type)"; \
	rm -f big.tmp; \
	echo "-- 18: stash --share + exec --from (same uid, then cross-uid via sudo) --"; \
	pfx="shr.$$$$"; \
	shareline=$$(./keyringer stash --share --desc "$$pfx" test/hello 2>/dev/null | grep "^share: "); \
	test -n "$$shareline" || { echo "FAIL: no share line"; exit 1; }; \
	ser=$${shareline#share: }; \
	out=$$(./keyringer exec --from "$$ser" hello 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: --from same-uid: $$out"; exit 1; }; \
	echo "ok: --from $$ser ($$out)"; \
	pfx2="shr2.$$$$"; \
	shareline2=$$(./keyringer stash --share --desc "$$pfx2" test/hello 2>/dev/null | grep "^share: "); \
	test -n "$$shareline2" || { echo "FAIL: no share line (2)"; exit 1; }; \
	ser2=$${shareline2#share: }; \
	out=$$(sudo -n ./keyringer exec --from "$$ser2" hello 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: --from cross-uid: $$out"; exit 1; }; \
	echo "ok: cross-UID --from via sudo ($$out)"; \
	for d in "$$pfx.000" "$$pfx2.000"; do \
	    s=$$(keyctl search @s user "$$d" 2>/dev/null || true); \
	    if [ -n "$$s" ]; then keyctl revoke "$$s" 2>/dev/null || true; fi; \
	done; \
	echo "ok: suite keys cleaned"; \
	echo "-- 19: khttp extras (--header/--insecure ok; --proxy fails cleanly) --"; \
	out=$$(./keyringer-dyn khttp --header "X-Keyringer: 1" --insecure \
	    http://127.0.0.1:18091/hello hello 2>/dev/null); rc=$$?; \
	kill $$srv 2>/dev/null || true; \
	test $$rc -eq 0 || { echo "FAIL: khttp --header/--insecure exited $$rc"; exit 1; }; \
	test "$$out" = "keyringer ok" || { echo "FAIL: got \"$$out\""; exit 1; }; \
	echo "ok: --header + --insecure ($$out; server ignores the extra header)"; \
	( cd test && exec python3 -m http.server 18091 ) >/dev/null 2>&1 & srv=$$!; \
	i=0; while [ $$i -lt 50 ]; do \
	    python3 -c "import socket; socket.create_connection(('127.0.0.1', 18091), 0.25).close()" 2>/dev/null && break; \
	    i=$$((i+1)); sleep 0.1; done; \
	if ./keyringer-dyn khttp --proxy http://127.0.0.1:9/ \
	    http://127.0.0.1:18091/hello hello 2>khttp.err; then \
	    kill $$srv 2>/dev/null || true; echo "FAIL: bogus proxy accepted"; rm -f khttp.err; exit 1; fi; \
	kill $$srv 2>/dev/null || true; \
	grep -q "curl error" khttp.err || { echo "FAIL: not a clean curl error:"; cat khttp.err; rm -f khttp.err; exit 1; }; \
	echo "ok: --proxy to a dead port fails with a clean curl error"; \
	rm -f khttp.err; \
	echo "-- 20: x86 build rejects EM_AARCH64 payloads with the clean arch error --"; \
	if [ ! -x test/hello_a64 ] && command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then \
	    aarch64-linux-gnu-gcc $(A64_HELLO_CFLAGS) -o test/hello_a64 test/hello_a64.c; \
	fi; \
	if [ -x test/hello_a64 ]; then \
	    if ./keyringer kfile test/hello_a64 2>arm.err; then \
	        echo "FAIL: a real EM_AARCH64 payload was accepted"; rm -f arm.err; exit 1; fi; \
	    grep -q "e_machine" arm.err || { echo "FAIL: wrong rejection:"; cat arm.err; rm -f arm.err; exit 1; }; \
	    echo "ok: real EM_AARCH64 payload rejected (keys already revoked by the load)"; \
	else \
	    echo "   (no aarch64 cross-compiler; using a patched e_machine fake)"; \
	fi; \
	python3 -c "d=bytearray(open('test/hello','rb').read()); d[18:20]=(183).to_bytes(2,'little'); open('test/hello.a64fake','wb').write(bytes(d))"; \
	if ./keyringer kfile test/hello.a64fake 2>arm.err; then \
	    echo "FAIL: EM_AARCH64 fake accepted"; rm -f arm.err test/hello.a64fake; exit 1; fi; \
	grep -q "e_machine" arm.err || { echo "FAIL: wrong rejection (fake):"; cat arm.err; rm -f arm.err test/hello.a64fake; exit 1; }; \
	echo "ok: EM_AARCH64 fake rejected cleanly: $$(grep -m1 e_machine arm.err | cut -c1-90)..."; \
	rm -f arm.err test/hello.a64fake; \
	echo "-- 21: --ttl SECONDS sets KEYCTL_SET_TIMEOUT on every stored key --"; \
	./keyringer gc >/dev/null 2>&1 || true; \
	if command -v strace >/dev/null 2>&1; then \
	    timeout 5 strace -f -e trace=keyctl -o ttl.log \
	        ./keyringer stash --ttl 42 - <test/hello >/dev/null 2>&1 || true; \
	    grep -q "KEYCTL_SET_TIMEOUT, [0-9]*, 42" ttl.log \
	        || { echo "FAIL: no SET_TIMEOUT(serial, 42) in strace"; cat ttl.log; exit 1; }; \
	    echo "ok: KEYCTL_SET_TIMEOUT(serial, 42) observed via strace"; \
	else \
	    ./keyringer stash --ttl 42 - <test/hello >/dev/null 2>&1; \
	    echo "SKIP: strace not installed; stash --ttl accepted without syscall proof"; \
	fi; \
	rm -f ttl.log; \
	echo "-- 22: --scrub exec leaves no live/replayed keys (invalidate, not revoke) --"; \
	./keyringer gc >/dev/null 2>&1 || true; \
	./keyringer stash - <test/hello >/dev/null 2>&1; \
	timeout 10 strace -f -e trace=keyctl -o scrub.log \
	    ./keyringer exec --scrub scrubtest >/dev/null 2>&1 || true; \
	grep -q "KEYCTL_INVALIDATE" scrub.log \
	    || { echo "FAIL: no KEYCTL_INVALIDATE in strace"; exit 1; }; \
	live=$$(awk '$$9 ~ /^_keyringer/ && $$2 !~ /[Ri]/' /proc/keys | wc -l); \
	test $$live -eq 0 || { echo "FAIL: $$live live key(s) survived --scrub"; \
	    grep _keyringer /proc/keys; exit 1; }; \
	echo "ok: scrub invalidated the stash (no live _keyringer.* keys remain)"; \
	rm -f scrub.log; \
	echo "-- 23: gc destroys visible stash keys (stale ghosts included) --"; \
	./keyringer gc >/dev/null 2>&1 || true; \
	./keyringer stash - <test/hello >/dev/null 2>&1 || true; \
	./keyringer gc 2>gc.err; \
	grep -q "gc: destroyed" gc.err || { echo "FAIL: no gc summary:"; cat gc.err; exit 1; }; \
	echo "ok: non-root gc swept: $$(grep 'gc: destroyed' gc.err)"; \
	rm -f gc.err; \
	if sudo -n true 2>/dev/null; then \
	    ./keyringer stash - <test/hello >/dev/null 2>&1 || true; \
	    sudo -n ./keyringer gc 2>gc.err; \
	    grep -qE "gc: destroyed [1-9][0-9]* key" gc.err \
	        || { echo "FAIL: root gc destroyed no live key:"; cat gc.err; exit 1; }; \
	    echo "ok: root gc destroyed the live stash: $$(grep 'gc: destroyed' gc.err)"; \
	    echo "   (kernel note: already-REVOKED ghosts are untouchable even by root —"; \
	    echo "    EKEYREVOKED on invalidate; they die only with their owning ring —"; \
	    echo "    one more reason --scrub exists: scrubbed keys never become ghosts)"; \
	    rm -f gc.err; \
	else \
	    echo "   (no passwordless sudo; ghost cleanup by root not exercised)"; \
	fi; \
	echo "-- 24: list --json is valid JSON with serial/type/desc/revoked --"; \
	./keyringer gc >/dev/null 2>&1 || true; \
	./keyringer stash - <test/hello >/dev/null 2>&1 || true; \
	./keyringer list --json | python3 test/list_json_check.py; \
	echo "-- 25: preflight --json is valid JSON covering the 10 checks (keyring-quota added in section 37's era) --"; \
	./keyringer preflight --json | python3 test/preflight_json_check.py; \
	echo "-- 26: cross-implementation interop for the lifecycle flags --"; \
	./keyringer stash - <test/hello >/dev/null 2>&1; \
	python3 keyringer.py exec --scrub ix >/dev/null 2>&1 || \
	    { echo "FAIL: python exec --scrub of a C stash"; exit 1; }; \
	echo "ok: C stash -> python exec --scrub (invalidated)"; \
	python3 keyringer.py stash test/hello >/dev/null 2>&1; \
	./keyringer exec --scrub xi >/dev/null 2>&1; \
	test "$$?" = "0" || { echo "FAIL: C exec --scrub of a python stash"; exit 1; }; \
	echo "ok: python stash -> C exec --scrub (payload ran, keys invalidated)"; \
	python3 keyringer.py stash --ttl 33 - <test/hello >/dev/null 2>&1; \
	./keyringer exec >/dev/null 2>&1; \
	echo "ok: python stash --ttl 33 -> C exec consumed it before expiry"; \
	./keyringer gc >/dev/null 2>&1; \
	echo "-- 27: wire v3 opt-in (KR_WIRE=3) + KR_WIRE=2 downgrade + cross-crypto --"; \
	KR_WIRE=3 ./keyringer stash - <test/hello >/dev/null 2>&1; \
	ser=$$(keyctl search @s user "_keyringer.000" 2>/dev/null); \
	mag=$$(keyctl pipe "$$ser" 2>/dev/null | head -c 4); \
	test "$$mag" = "KRH3" || { echo "FAIL: KR_WIRE=3 chunk is [$$mag], want KRH3"; exit 1; }; \
	out=$$(./keyringer exec v3a 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: v3 plaintext roundtrip"; exit 1; }; \
	echo "ok: KR_WIRE=3 v3 plaintext stash->exec ($$out, KRH3 chunk verified)"; \
	K=$$(./keyringer keygen); \
	KR_WIRE=3 KR_CRYPTO=userspace ./keyringer stash --key $$K - <test/hello >/dev/null 2>&1; \
	out=$$(./keyringer exec --key $$K v3b 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: userspace-sealed stash rejected by AF_ALG loader"; exit 1; }; \
	echo "ok: userspace-sealed KR2 opens under the AF_ALG loader ($$out)"; \
	KR_WIRE=2 ./keyringer stash --key $$K - <test/hello >/dev/null 2>&1; \
	out=$$(./keyringer exec --key $$K v2c 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: v2.2 downgrade stash unreadable"; exit 1; }; \
	echo "ok: KR_WIRE=2 v2.2 stash loads under the v4-default tool ($$out)"; \
	KR_WIRE=3 ./keyringer stash --key $$K - <test/hello >/dev/null 2>&1; \
	serial=$$(KR_WIRE=3 ./keyringer stash --share --key $$K --desc tamper - <test/hello | sed -n 's/^share: //p'); \
	BAD=$$(./keyringer keygen); \
	if ./keyringer exec --key $$BAD --from $$serial v3d 2>tamper.err; then \
	    echo "FAIL: wrong key accepted on v3"; exit 1; fi; \
	grep -qE "authentication failed" tamper.err \
	    || { echo "FAIL: unexpected v3 rejection:"; cat tamper.err; exit 1; }; \
	echo "ok: KR2 tag refuses the wrong key (AAD-bound header included)"; \
	rm -f tamper.err; ./keyringer gc >/dev/null 2>&1 || true; \
	echo "-- 28: fresh-ring kfile leaves no live keys; --keep-ring opts out --"; \
	out=$$(./keyringer kfile test/hello freshtest 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: fresh-ring kfile"; exit 1; }; \
	live=$$(awk '$$9 ~ /^_keyringer/ && $$2 !~ /[Ri]/' /proc/keys | wc -l); \
	test $$live -eq 0 || { echo "FAIL: $$live live keys survived kfile exit"; exit 1; }; \
	out=$$(./keyringer kfile --keep-ring test/hello ringtest 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: keep-ring kfile"; exit 1; }; \
	echo "ok: kfile residue dies with the process; --keep-ring opt-out works"; \
	./keyringer gc >/dev/null 2>&1 || true; \
	echo "-- 29: wire-open fuzzer (200k mutations x 2 crypto modes) --"; \
	gcc -Wall -O2 -std=c11 -o test/fuzz_wire test/fuzz_wire.c kr_core.c; \
	./test/fuzz_wire; \
	KR_CRYPTO=userspace ./test/fuzz_wire; \
	echo "-- 30: ausearch-hunt correlation against synthetic audit events --"; \
	sh test/ausearch_synth_test.sh; \
	echo "-- 31: python twin selftest (9 sections; default v4 flip-proof + v3/v2.2 opt-ins included) --"; \
	passes=$$(python3 keyringer.py selftest 2>/dev/null | grep -c '^PASS'); \
	test "$$passes" = "9" || { echo "FAIL: twin selftest passes=$$passes want 9"; exit 1; }; \
	echo "ok: twin selftest 9/9"; \
	echo "-- 32: ELF-loader fuzzer + ASan/UBSan + vr-fuzz target smoke --"; \
	gcc -Wall -O2 -std=c11 -o test/fuzz_elf test/fuzz_elf.c kr_core.c; \
	KR_FUZZ_ITERS=20000 ./test/fuzz_elf; \
	if gcc -fsanitize=address,undefined -o test/fuzz_elf-asan \
	    test/fuzz_elf.c kr_core.c 2>/dev/null; then \
	    KR_FUZZ_ITERS=5000 KR_FUZZ_SECS=60 ./test/fuzz_elf-asan; \
	    echo "ok: ASan/UBSan ELF fuzzer clean"; \
	else \
	    echo "SKIP: sanitizers unavailable"; \
	fi; \
	gcc -Wall -O2 -std=c11 -o test/kr_fuzz_server test/kr_fuzz_server.c kr_core.c; \
	./test/kr_fuzz_server 12911 & srv=$$!; sleep 0.5; \
	python3 test/vrf_smoke.py 12911; \
	kill $$srv 2>/dev/null || true; \
	echo "-- 33: wire v4 (KRH4, the default since core 4.0; explicit KR_WIRE=4 = no-op) roundtrips: plain + encrypted + wrong-key + tamper + scrub/ttl + reader env --"; \
	./keyringer gc >/dev/null 2>&1 || true; \
	K=$$(./keyringer keygen); \
	KR_WIRE=4 ./keyringer stash test/hello >/dev/null 2>&1; \
	out=$$(./keyringer exec v4plain 2>v4.tmp); \
	test "$$out" = "keyringer ok" || { echo "FAIL: v4 plaintext roundtrip: $$out"; rm -f v4.tmp; exit 1; }; \
	grep -q "plaintext, wire v4" v4.tmp || { echo "FAIL: load did not verify a v4 wire"; cat v4.tmp; exit 1; }; \
	echo "ok: v4 plaintext stash->exec ($$out, KRH4 header verified)"; \
	KR_WIRE=4 ./keyringer stash --key $$K test/hello >/dev/null 2>v4s.log; \
	grep -q "sealed 1 KR4 chunk" v4s.log || { echo "FAIL: no KR4 seal log"; cat v4s.log; exit 1; }; \
	out=$$(./keyringer exec --key $$K v4enc 2>v4.tmp); \
	test "$$out" = "keyringer ok" || { echo "FAIL: v4 encrypted roundtrip: $$out"; cat v4.tmp; exit 1; }; \
	grep -q "v4: streamed 1 chunk" v4.tmp || { echo "FAIL: no streaming log"; cat v4.tmp; exit 1; }; \
	echo "ok: v4 encrypted stash->exec, streaming assembly ($$out)"; \
	KR_WIRE=4 ./keyringer stash --key $$K test/hello >/dev/null 2>&1; \
	BAD=$$(./keyringer keygen); \
	if ./keyringer exec --key $$BAD v4bad 2>v4.tmp; then \
	    echo "FAIL: v4 wrong key accepted"; rm -f v4.tmp; exit 1; fi; \
	grep -q "AEAD authentication failed" v4.tmp || \
	    { echo "FAIL: wrong v4 rejection mode:"; cat v4.tmp; rm -f v4.tmp; exit 1; }; \
	echo "ok: v4 wrong key rejected at the chunk-0 AEAD tag"; \
	KR_WIRE=4 ./keyringer stash --key $$K test/shellcode.bin >/dev/null 2>&1; \
	ser=$$(keyctl search @s user "_keyringer.000" 2>/dev/null); \
	keyctl pipe "$$ser" > v4chunk.bin 2>/dev/null; \
	python3 -c "d=bytearray(open('v4chunk.bin','rb').read()); d[100]^=0xff; open('v4chunk.tampered','wb').write(bytes(d))"; \
	keyctl pupdate "$$ser" < v4chunk.tampered; \
	if ./keyringer exec --key $$K --raw v4t 2>v4.tmp; then \
	    echo "FAIL: tampered v4 chunk accepted"; rm -f v4.tmp v4chunk.*; exit 1; fi; \
	grep -q "AEAD authentication failed" v4.tmp || \
	    { echo "FAIL: wrong v4 tamper mode:"; cat v4.tmp; rm -f v4.tmp v4chunk.*; exit 1; }; \
	echo "ok: flipped v4 ciphertext byte rejected by the chunk tag"; \
	KR_WIRE=4 ./keyringer stash --key $$K test/shellcode.bin >/dev/null 2>&1; \
	ser=$$(keyctl search @s user "_keyringer.000" 2>/dev/null); \
	keyctl pipe "$$ser" > v4chunk.bin 2>/dev/null; \
	python3 -c "d=bytearray(open('v4chunk.bin','rb').read()); d[10]^=0x40; open('v4chunk.tampered','wb').write(bytes(d))"; \
	keyctl pupdate "$$ser" < v4chunk.tampered; \
	if ./keyringer exec --key $$K --raw v4t2 2>v4.tmp; then \
	    echo "FAIL: tampered v4 header accepted"; rm -f v4.tmp v4chunk.*; exit 1; fi; \
	grep -q "AEAD authentication failed" v4.tmp || \
	    { echo "FAIL: wrong v4 header-tamper mode:"; cat v4.tmp; rm -f v4.tmp v4chunk.*; exit 1; }; \
	echo "ok: flipped v4 header digest byte rejected (AAD binds the whole header)"; \
	rm -f v4chunk.bin v4chunk.tampered; \
	KR_WIRE=4 ./keyringer stash --key $$K --ttl 5 test/hello >/dev/null 2>&1; \
	out=$$(KR_WIRE=2 ./keyringer exec --key $$K --scrub v4opts 2>v4.tmp); \
	test "$$out" = "keyringer ok" || { echo "FAIL: v4 ttl/scrub/reader-env: $$out"; cat v4.tmp; exit 1; }; \
	grep -q "v4: streamed 1 chunk" v4.tmp || { echo "FAIL: no stream log (ttl/scrub)"; cat v4.tmp; exit 1; }; \
	live=$$(awk '$$9 ~ /^_keyringer/ && $$2 !~ /[Ri]/' /proc/keys | wc -l); \
	test $$live -eq 0 || { echo "FAIL: v4 --scrub left $$live live key(s)"; exit 1; }; \
	echo "ok: v4 --ttl 5 stash + exec --scrub (reader ignores KR_WIRE, keys invalidated)"; \
	KR_WIRE=2 ./keyringer stash --key $$K test/hello >/dev/null 2>&1; \
	out=$$(./keyringer exec --key $$K v2still 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: v2.2 downgrade stash broken by v4"; exit 1; }; \
	echo "ok: KR_WIRE=2 v2.2 stash still loads (v4 did not displace it)"; \
	if KR_WIRE=4 ./keyringer stash --selfcontained test/hello 2>v4.tmp; then \
	    echo "FAIL: explicit v4 + --selfcontained accepted"; rm -f v4.tmp; exit 1; fi; \
	grep -q "v4 experimental: not with --selfcontained yet" v4.tmp || \
	    { echo "FAIL: wrong v4 selfcontained refusal:"; cat v4.tmp; rm -f v4.tmp; exit 1; }; \
	echo "ok: EXPLICIT KR_WIRE=4 + --selfcontained refused cleanly (the implicit default auto-downgrades to v3; section 11 proves it)"; \
	./keyringer gc >/dev/null 2>&1 || true; \
	echo "-- 34: v4 STREAMING PROOF: bounded scratch + no stash-sized mmap beyond wire/stack/PT_LOAD --"; \
	./keyringer gc >/dev/null 2>&1 || true; \
	KR_WIRE=4 ./keyringer stash --key $$K test/hello >/dev/null 2>v4.tmp; \
	wirelen=$$(sed -n 's/^stash: 1 payload chunk(s), \([0-9]*\) bytes stored.*/\1/p' v4.tmp); \
	out=$$(./keyringer exec --key $$K v4s1 2>v4.tmp); \
	test "$$out" = "keyringer ok" || { echo "FAIL: single-chunk v4 exec"; cat v4.tmp; exit 1; }; \
	line=$$(grep -m1 "v4: streamed" v4.tmp); \
	M=$$(echo "$$line" | sed -n 's/.*max scratch \([0-9]*\) bytes.*/\1/p'); \
	test -n "$$M" || { echo "FAIL: no scratch size in streaming log"; cat v4.tmp; exit 1; }; \
	test "$$M" -lt "$$wirelen" || { echo "FAIL: scratch $$M >= wire $$wirelen"; exit 1; }; \
	echo "ok: single-chunk v4 streamed, max scratch $$M B < wire $$wirelen B"; \
	if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null && command -v strace >/dev/null 2>&1; then \
	    cat test/hello > v4big.tmp; truncate -s 70000 v4big.tmp; \
	    sudo -n ./keyringer gc >/dev/null 2>&1 || true; \
	    sudo -n env KR_WIRE=4 KEYRINGER_KEY=$$K ./keyringer stash --desc v4big - < v4big.tmp >/dev/null 2>v4.tmp; \
	    wirelen=$$(sed -n 's/^stash: 3 payload chunk(s), \([0-9]*\) bytes stored.*/\1/p' v4.tmp); \
	    test "$$wirelen" = "70140" || { echo "FAIL: 3-chunk wire is $$wirelen, want 70140"; cat v4.tmp; exit 1; }; \
	    sudo -n strace -f -e trace=mmap -o v4.strace \
	        ./keyringer exec --key $$K --desc v4big v4big 2>v4.tmp >/dev/null; \
	    line=$$(grep -m1 "v4: streamed" v4.tmp); \
	    M=$$(echo "$$line" | sed -n 's/.*max scratch \([0-9]*\) bytes.*/\1/p'); \
	    N=$$(echo "$$line" | sed -n 's/^v4: streamed \([0-9]*\) chunk.*/\1/p'); \
	    test "$$N" = "3" || { echo "FAIL: streamed $$N chunk(s), want 3"; exit 1; }; \
	    test "$$M" = "29968" || { echo "FAIL: scratch $$M, want 29968 (68+29900)"; exit 1; }; \
	    test "$$M" -lt "$$wirelen" || { echo "FAIL: scratch $$M >= wire $$wirelen"; exit 1; }; \
	    echo "ok: 3-chunk v4 streamed (N=$$N, max scratch $$M B < wire $$wirelen B; scratch is 68 + one pt-chunk)"; \
	    grep -oE "mmap\([^,]+, [0-9]+" v4.strace | sed -E 's/mmap\(([^,]+), /\1 /' > v4.maps; \
	    big=$$(python3 -c "import sys; wl=int(sys.argv[1]); wu=(wl+4095)//4096*4096; rows=[(p[0],int(p[1])) for p in (l.split() for l in open('v4.maps'))]; print('; '.join('%s/%d' % r for r in rows if r[1] >= wl))" "$$wirelen"); \
	    badcnt=$$(python3 -c "import sys; wl=int(sys.argv[1]); wu=(wl+4095)//4096*4096; print(sum(1 for l in open('v4.maps') for a,z in [l.split()] if int(z) >= wl and int(z) != 8388608 and int(z) > wu + 4096))" "$$wirelen"); \
	    test "$$badcnt" = "0" || { echo "FAIL: $$badcnt stash-sized mmap(s) beyond wire/stack:"; \
	        echo "$$big"; exit 1; }; \
	    echo "ok: 0 mmaps >= wirelen except the documented fixed regions:"; \
	    echo "$$big" | sed 's/^/       /'; \
	    echo "   (8388608 = the 8 MiB payload stack, a loader constant; NULL/RW ~70-74K ="; \
	    echo "    the reassembled WIRE itself — ciphertext, the unavoidable one; the"; \
	    echo "    plaintext lives ONLY in the mapped PT_LOADs, filled chunk by chunk)"; \
	    loads=$$(readelf -W -l test/hello | python3 -c "import sys; print(' '.join(str((int(l.split()[5],16)+4095)//4096*4096) for l in sys.stdin if l.strip().startswith('LOAD')))"); \
	    imgbad=$$(python3 -c "import sys,re; loads=set(map(int,sys.argv[1].split())); rows=[l.split() for l in open('v4.maps')]; print(sum(1 for r in rows if re.match(r'^0x4[0-9a-f]{7}$$', r[0]) and int(r[1]) not in loads))" "$$loads"); \
	    test "$$imgbad" = "0" || { echo "FAIL: $$imgbad image-window mmap(s) match no page-rounded p_memsz ($$loads)"; exit 1; }; \
	    echo "ok: every mmap in the 0x40000000 image window is a page-rounded p_memsz of test/hello ($$loads)"; \
	    sudo -n ./keyringer gc >/dev/null 2>&1 || true; \
	    rm -f v4big.tmp v4.strace v4.maps; \
	else \
	    echo "SKIP: sudo -n or strace unavailable — multi-chunk strace proof skipped"; \
	    echo "      (the single-chunk scratch assertion above still ran)"; \
	fi; \
	rm -f v4.tmp; \
	echo "-- 35: v4 python/C interop both directions + v3/v2.2/v4 downgrade matrix --"; \
	./keyringer gc >/dev/null 2>&1 || true; \
	KR_WIRE=4 python3 keyringer.py stash --key $$K test/hello >/dev/null 2>&1; \
	out=$$(./keyringer exec --key $$K ipp 2>v4.tmp); \
	test "$$out" = "keyringer ok" || { echo "FAIL: python v4 -> C exec: $$out"; exit 1; }; \
	grep -q "v4: streamed" v4.tmp || { echo "FAIL: C did not stream the python v4 stash"; cat v4.tmp; exit 1; }; \
	echo "ok: python v4 stash -> C streaming exec ($$out)"; \
	KR_WIRE=4 ./keyringer stash --key $$K test/hello >/dev/null 2>&1; \
	out=$$(python3 keyringer.py exec --key $$K ipc 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: C v4 -> python exec: $$out"; exit 1; }; \
	echo "ok: C v4 stash -> python exec ($$out)"; \
	KR_WIRE=4 python3 keyringer.py stash test/hello >/dev/null 2>&1; \
	out=$$(./keyringer exec ipp2 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: python v4 plain -> C exec: $$out"; exit 1; }; \
	KR_WIRE=4 ./keyringer stash test/hello >/dev/null 2>&1; \
	out=$$(python3 keyringer.py exec ipc2 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: C v4 plain -> python exec: $$out"; exit 1; }; \
	echo "ok: v4 plaintext bodies interop both directions"; \
	for w in "" 2 4; do \
	    ./keyringer gc >/dev/null 2>&1 || true; \
	    KR_WIRE=$$w python3 keyringer.py stash --key $$K test/hello >/dev/null 2>&1; \
	    out=$$(./keyringer exec --key $$K mx 2>/dev/null); \
	    test "$$out" = "keyringer ok" || { echo "FAIL: python KR_WIRE='$$w' stash unreadable by C: $$out"; exit 1; }; \
	    KR_WIRE=$$w ./keyringer stash --key $$K test/hello >/dev/null 2>&1; \
	    out=$$(python3 keyringer.py exec --key $$K mx 2>/dev/null); \
	    test "$$out" = "keyringer ok" || { echo "FAIL: C KR_WIRE='$$w' stash unreadable by python: $$out"; exit 1; }; \
	    echo "ok: KR_WIRE='$$w' matrix: python stash -> C exec, C stash -> python exec"; \
	done; \
	./keyringer gc >/dev/null 2>&1 || true; \
	echo "-- 36: THE FLIP — the default writer is wire v4: a default stash carries the KRH4 magic; KR_WIRE=3 downgrades --"; \
	./keyringer gc >/dev/null 2>&1 || true; \
	./keyringer stash --desc flp - <test/hello >/dev/null 2>&1; \
	ser=$$(keyctl search @s user "flp.000" 2>/dev/null); \
	test -n "$$ser" || { echo "FAIL: no flp.000 chunk"; exit 1; }; \
	mag=$$(keyctl pipe "$$ser" 2>/dev/null | head -c 4); \
	test "$$mag" = "KRH4" || { echo "FAIL: default stash chunk is [$$mag], want KRH4 — the flip did not take"; exit 1; }; \
	out=$$(./keyringer exec --desc flp hello 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: default v4 stash roundtrip: $$out"; exit 1; }; \
	echo "ok: default stash (no KR_WIRE) carries the KRH4 magic and execs ($$out)"; \
	KR_WIRE=3 ./keyringer stash --desc flp3 - <test/hello >/dev/null 2>&1; \
	ser3=$$(keyctl search @s user "flp3.000" 2>/dev/null); \
	mag3=$$(keyctl pipe "$$ser3" 2>/dev/null | head -c 4); \
	test "$$mag3" = "KRH3" || { echo "FAIL: KR_WIRE=3 stash chunk is [$$mag3], want KRH3 — the downgrade broke"; exit 1; }; \
	out=$$(./keyringer exec --desc flp3 hello3 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: KR_WIRE=3 stash roundtrip: $$out"; exit 1; }; \
	echo "ok: KR_WIRE=3 downgrade stash carries the KRH3 magic and execs ($$out)"; \
	python3 keyringer.py stash --desc flp4 test/hello >/dev/null 2>&1; \
	ser4=$$(keyctl search @s user "flp4.000" 2>/dev/null); \
	mag4=$$(keyctl pipe "$$ser4" 2>/dev/null | head -c 4); \
	test "$$mag4" = "KRH4" || { echo "FAIL: python default stash chunk is [$$mag4], want KRH4"; exit 1; }; \
	out=$$(./keyringer exec --desc flp4 hello4 2>/dev/null); \
	test "$$out" = "keyringer ok" || { echo "FAIL: C exec of the python default stash: $$out"; exit 1; }; \
	echo "ok: python twin default stash is KRH4 too (lockstep flip; C exec reads it)"; \
	for d in flp.000 flp3.000 flp4.000; do \
	    s=$$(keyctl search @s user "$$d" 2>/dev/null || true); \
	    if [ -n "$$s" ]; then keyctl revoke "$$s" 2>/dev/null || true; fi; \
	done; \
	./keyringer gc >/dev/null 2>&1 || true; \
	echo "-- 37: quota telemetry + upfront planning (live /proc/key-users, refuse-before-store, auto big_key) --"; \
	qk() { awk -v u="$$uid" '$$1==u":" {split($$3,a,"/"); print a[1]}' /proc/key-users; }; \
	qb() { awk -v u="$$uid" '$$1==u":" {split($$5,a,"/"); print a[1]}' /proc/key-users; }; \
	qmaxb() { awk -v u="$$uid" '$$1==u":" {split($$4,k,"/"); split($$5,b,"/"); print k[2], b[2]}' /proc/key-users; }; \
	qrem() { qbu=$$(qb); set -- $$(qmaxb); echo $$(( $$2 - qbu )); }; \
	qwait() { for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
	    x=$$($$1); sleep 1; y=$$($$1); [ "$$x" = "$$y" ] && return 0; done; return 0; }; \
	head -c 16384 /dev/zero > q16k.tmp; \
	head -c 2048  /dev/zero > qfill.tmp; \
	head -c 40000 /dev/zero > q40k.tmp; \
	qwait qb; base_used=$$(qb); \
	echo "   uid $$uid baseline: keys_used=$$(qk), bytes_used=$$base_used, remaining=$$(qrem) (settled; kernel GC may lag revokes by ~1s)"; \
	echo "   (a) preflight live-measurement line + --json entry + twin parity --"; \
	pline=$$(./keyringer preflight 2>/dev/null | sed -n 's/^preflight: keyring-quota: //p' | sed 's/: INFO$$//'); \
	echo "$$pline" | grep -q '^used/max keys=[0-9]*/[0-9]*, used/max bytes=[0-9]*/[0-9]*, remaining=~[0-9]* bytes (live /proc/key-users measurement)$$' \
	    || { echo "FAIL: malformed keyring-quota line: [$$pline]"; exit 1; }; \
	lkmax=$$(echo "$$pline" | sed -n 's/.*used\/max keys=[0-9]*\/\([0-9]*\),.*/\1/p'); \
	lbmax=$$(echo "$$pline" | sed -n 's/.*used\/max bytes=[0-9]*\/\([0-9]*\),.*/\1/p'); \
	lrem=$$(echo "$$pline" | sed -n 's/.*remaining=~\([0-9]*\) bytes.*/\1/p'); \
	ok=0; \
	for i in 1 2 3; do \
	    set -- $$(qmaxb); pkmax=$$1; pbmax=$$2; pbu=$$(qb); drem=$$(( $$2 - $$pbu - $$lrem )); \
	    if [ "$$pkmax" = "$$lkmax" ] && [ "$$pbmax" = "$$lbmax" ] && \
	       [ $$drem -ge 0 ] && [ $$drem -le 512 ]; then ok=1; break; fi; \
	    sleep 1; \
	done; \
	[ "$$ok" = 1 ] || { echo "FAIL: preflight keyring-quota does not match /proc/key-users: [$$pline]"; exit 1; }; \
	echo "ok: preflight keyring-quota cross-checked against /proc/key-users (max keys=$$lkmax, max bytes=$$lbmax, remaining within 512 of live)"; \
	./keyringer preflight --json 2>/dev/null | python3 test/preflight_json_check.py; \
	ok=0; \
	for i in 1 2 3; do \
	    tline=$$(python3 keyringer.py preflight 2>/dev/null | sed -n 's/^preflight: keyring-quota: //p'); \
	    if [ "$$tline" = "$$pline" ]; then ok=1; break; fi; \
	    pline2=$$(./keyringer preflight 2>/dev/null | sed -n 's/^preflight: keyring-quota: //p' | sed 's/: INFO$$//'); \
	    if [ "$$tline" = "$$pline2" ]; then pline=$$pline2; ok=1; break; fi; \
	    sleep 1; \
	done; \
	[ "$$ok" = 1 ] || { echo "FAIL: twin keyring-quota line differs (GC race?):"; \
	    echo "C : $$pline"; echo "py: $$tline"; exit 1; }; \
	echo "ok: python twin preflight prints the identical keyring-quota measurement line"; \
	echo "   (b) forced clean failure with the quota nearly exhausted (zero keys stored) --"; \
	apfx="qatt.$$"; apfxlen=$${#apfx}; attneed=$$(( 16384 + 56 + apfxlen + 4 + 5 + 16 + 64 )); \
	i=0; fills=""; \
	while [ $$i -lt 10 ]; do \
	    rem=$$(qrem); \
	    if [ $$rem -lt $$(( attneed + 300 )) ]; then break; fi; \
	    ./keyringer stash --desc "qfill$$i.$$" qfill.tmp >/dev/null 2>&1 \
	        || { echo "FAIL: filler stash $$i rejected (quota state: rem=$$rem)"; exit 1; }; \
	    fills="$$fills qfill$$i.$$"; i=$$((i+1)); \
	done; \
	rem=$$(qrem); \
	[ $$rem -lt $$attneed ] || { echo "FAIL: could not exhaust quota (rem=$$rem, need<$$attneed)"; exit 1; }; \
	if ./keyringer stash --desc "$$apfx" q16k.tmp >/dev/null 2>q.err; then \
	    echo "FAIL: stash succeeded with only ~$$rem quota bytes remaining"; rm -f q.err; exit 1; fi; \
	grep -q "stash: needs ~[0-9]* bytes of keyring quota, ~[0-9]* remain" q.err \
	    || { echo "FAIL: refusal is not the upfront needs-line:"; cat q.err; rm -f q.err; exit 1; }; \
	grep -q "options: smaller payload; --type big_key" q.err \
	    || { echo "FAIL: no actionable options in the refusal:"; cat q.err; rm -f q.err; exit 1; }; \
	grep -q "live /proc/key-users measurement" q.err \
	    || { echo "FAIL: refusal does not cite the live measurement"; cat q.err; rm -f q.err; exit 1; }; \
	nadd=$$(awk -v p="$$apfx" 'substr($$9,1,length(p))==p {c++} END {print c+0}' /proc/keys); \
	[ "$$nadd" = 0 ] || { echo "FAIL: the refused stash still added $$nadd key(s)"; exit 1; }; \
	echo "ok: quota exhausted ($$rem B left) -> clean upfront refusal, ZERO keys added ($$fills swept next)"; \
	for p in $$fills; do ./keyringer gc --desc "$$p" >/dev/null 2>&1 || true; done; \
	qwait qb; \
	echo "   (b-py) twin stash refuses identically after C-stash pre-fill --"; \
	ppfx="qpy.$$"; i=0; pyfills=""; \
	while [ $$i -lt 10 ]; do \
	    rem=$$(qrem); \
	    if [ $$rem -lt $$(( attneed + 300 )) ]; then break; fi; \
	    ./keyringer stash --desc "qfillp$$i.$$" qfill.tmp >/dev/null 2>&1 \
	        || { echo "FAIL: twin-prefill stash $$i rejected (rem=$$rem)"; exit 1; }; \
	    pyfills="$$pyfills qfillp$$i.$$"; i=$$((i+1)); \
	done; \
	if python3 keyringer.py stash --desc "$$ppfx" q16k.tmp >/dev/null 2>qpy.err; then \
	    echo "FAIL: twin stash succeeded with an exhausted quota"; rm -f qpy.err; exit 1; fi; \
	grep -q "stash: needs ~[0-9]* bytes of keyring quota, ~[0-9]* remain" qpy.err \
	    || { echo "FAIL: twin refusal is not the upfront needs-line:"; cat qpy.err; rm -f qpy.err; exit 1; }; \
	nadd=$$(awk -v p="$$ppfx" 'substr($$9,1,length(p))==p {c++} END {print c+0}' /proc/keys); \
	[ "$$nadd" = 0 ] || { echo "FAIL: the refused twin stash still added $$nadd key(s)"; exit 1; }; \
	echo "ok: python twin refuses cleanly too (pre-filled via C stashes; ZERO keys added)"; \
	for p in $$pyfills; do ./keyringer gc --desc "$$p" >/dev/null 2>&1 || true; done; \
	qwait qb; \
	echo "   (c) >50% warning fires nonfatally; charge delta ~= wire bytes (parse cross-check) --"; \
	rem=$$(qrem); \
	if [ $$rem -ge $$(( attneed + 512 )) ]; then \
	    cp q16k.tmp qw.tmp; \
	else \
	    head -c $$(( rem * 55 / 100 )) /dev/zero > qw.tmp; \
	    echo "   (residue shrank the pool: using a $$(( rem * 55 / 100 ))-byte stash instead of 16384)"; \
	fi; \
	b0=$$(qb); \
	./keyringer stash --desc "qw.$$" qw.tmp >/dev/null 2>qw.err \
	    || { echo "FAIL: warning-path stash failed:"; cat qw.err; exit 1; }; \
	grep -q "stash: warning: this stash would consume ~[0-9]* of [0-9]* remaining quota bytes (>50%)" qw.err \
	    || { echo "FAIL: no >50% warning on a big stash:"; cat qw.err; exit 1; }; \
	wirelen=$$(sed -n 's/^stash: 1 payload chunk(s), \([0-9]*\) bytes stored.*/\1/p' qw.err); \
	test -n "$$wirelen" || { echo "FAIL: no stored-bytes log line:"; cat qw.err; exit 1; }; \
	b1=$$(qb); delta=$$(( b1 - b0 )); \
	if [ $$delta -lt $$(( wirelen - 128 )) ] || [ $$delta -gt $$(( wirelen + 128 )) ]; then \
	    echo "FAIL: charge delta $$delta not ~= wirelen $$wirelen (kernel charges desc+payload+5)"; exit 1; fi; \
	echo "ok: >50% warning nonfatal; /proc/key-users charge moved $$delta B for a $$wirelen B wire (desc+payload+5 model)"; \
	./keyringer gc --desc "qw.$$" >/dev/null 2>&1 || true; \
	qwait qb; \
	echo "   (d) auto big_key under maxkeys pressure + maxkeys-exhausted clean failure (sudo; sysctl restored) --"; \
	if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then \
	    mksave=$$(cat /proc/sys/kernel/keys/maxkeys); \
	    if ( \
	        qwait qk || exit 80; \
	        K=$$(qk); \
	        sudo -n sysctl -w kernel.keys.maxkeys=$$(( K + 1 )) >/dev/null || exit 81; \
	        ./keyringer stash --desc "qauto.$$" q40k.tmp >/dev/null 2>qa.err || exit 82; \
	        grep -q "stash: auto big_key (chunk count would exceed maxkeys)" qa.err || exit 83; \
	        n=$$(awk -v p="qauto.$$" 'substr($$9,1,length(p))==p {if ($$10+0 != 40056 || $$8 != "big_key") bad=1; c++} END {print c, bad+0}' /proc/keys) || exit 84; \
	        [ "$$n" = "1 0" ] || { echo "auto-big_key key inventory wrong: [$$n]"; cat qa.err; exit 85; }; \
	        ./keyringer gc --desc "qauto.$$" >/dev/null 2>&1 || true; \
	        qwait qk || exit 86; \
	        K2=$$(qk); \
	        sudo -n sysctl -w kernel.keys.maxkeys=$$K2 >/dev/null || exit 87; \
	        if ./keyringer stash --desc "qm.$$" q16k.tmp >/dev/null 2>qm.err; then exit 88; fi; \
	        grep -q "keyring key(s) on top of [0-9]*/[0-9]* used" qm.err || exit 89; \
	        grep -q "maxkeys relief" qm.err || exit 90; \
	        n=$$(awk -v p="qm.$$" 'substr($$9,1,length(p))==p {c++} END {print c+0}' /proc/keys) || exit 91; \
	        [ "$$n" = 0 ] || { echo "maxkeys-refused stash added $$n key(s)"; cat qm.err; exit 92; }; \
	        exit 0; \
	    ); then \
	        sudo -n sysctl -w kernel.keys.maxkeys=$$mksave >/dev/null; \
	        echo "ok: auto big_key: 40056 B wire stashed as ONE big_key chunk under maxkeys pressure (log line asserted)"; \
	        echo "ok: maxkeys-exhausted stash -> same clean upfront failure, ZERO keys stored"; \
	    else \
	        st=$$?; \
	        sudo -n sysctl -w kernel.keys.maxkeys=$$mksave >/dev/null; \
	        echo "FAIL: sudo quota-planning subtest (exit $$st)"; \
	        cat qa.err qm.err 2>/dev/null; exit 1; \
	    fi; \
	else \
	    echo "SKIP: sudo -n unavailable — auto-big_key / maxkeys-failure subtests skipped"; \
	fi; \
	./keyringer gc --desc "qm.$$" >/dev/null 2>&1 || true; \
	./keyringer gc --desc "qauto.$$" >/dev/null 2>&1 || true; \
	qwait qb; end_used=$$(qb); \
	if [ $$end_used -gt $$(( base_used + 128 )) ]; then \
	    echo "FAIL: quota not recovered (used $$end_used > baseline $$base_used + 128) — filler leak"; exit 1; fi; \
	echo "ok: all section-37 keys cleaned; quota back to baseline (used $$end_used <= $$base_used + 128)"; \
	rm -f q16k.tmp qfill.tmp q40k.tmp qw.tmp q.err qpy.err qa.err qm.err qw.err; \
	echo "=== all tests passed ==="

# AArch64 lane under qemu-aarch64: guest syscalls pass through to the
# real kernel, so AF_ALG (selftest) is real; keyring passthrough is
# probed and the stash+exec roundtrip runs where the emulator supports it.
test_a64: keyringer.aarch64 test/hello_a64
	@set -e; \
	echo "=== keyringer AArch64 test suite (qemu-aarch64) ==="; \
	echo "-- a1: selftest under qemu (RFC 8439 AEAD + SHA-256 via real kernel AF_ALG, VMA probe) --"; \
	$(QEMU_A64) ./keyringer.aarch64 selftest; \
	echo "ok: selftest"; \
	echo "-- a1b: preflight under qemu (arm64 W^X ret probe, AF_ALG, clone smoke) --"; \
	$(QEMU_A64) ./keyringer.aarch64 preflight > a64.pre; rc=$$?; \
	test $$rc -eq 0 || { echo "FAIL: preflight exited $$rc under qemu"; cat a64.pre; rm -f a64.pre; exit 1; }; \
	grep -q "wx: .*PASS \[CRITICAL\]" a64.pre || { echo "FAIL: arm64 W^X probe"; cat a64.pre; rm -f a64.pre; exit 1; }; \
	grep "wx:\|clone:\|afalg:" a64.pre | sed 's/^/   /'; \
	echo "ok: preflight under qemu (exit 0; clone smoke may FAIL where qemu"; \
	echo "     cannot emulate CLONE_VM forks — non-critical, native lanes PASS)"; \
	rm -f a64.pre; \
	echo "-- a2: EM_X86_64 payloads rejected on the aarch64 build (clean arch error) --"; \
	python3 -c "d=bytearray(open('test/hello_a64','rb').read()); d[18:20]=(62).to_bytes(2,'little'); open('test/hello.a64to64','wb').write(bytes(d))"; \
	if $(QEMU_A64) ./keyringer.aarch64 kfile test/hello.a64to64 2>a64.err; then \
	    echo "FAIL: EM_X86_64 payload accepted on arm64"; rm -f a64.err test/hello.a64to64; exit 1; fi; \
	if grep -q "e_machine" a64.err; then \
	    echo "ok: EM_X86_64 rejected: $$(grep -m1 e_machine a64.err | cut -c1-90)..."; \
	elif grep -q "Function not implemented" a64.err; then \
	    echo "SKIP: the stash ENOSYS (no qemu keyring passthrough) fires before"; \
	    echo "      exec-side validation on this emulator. The EM_AARCH64 check is"; \
	    if strings ./keyringer.aarch64 | grep -q "EM_AARCH64 required on this build"; then \
	        echo "      compiled into this binary, and the mirror check (EM_AARCH64"; \
	        echo "      rejected on x86) passed in native section 20."; \
	    else \
	        echo "      MISSING from this binary"; rm -f a64.err test/hello.a64to64; exit 1; fi; \
	else \
	    echo "FAIL: wrong rejection:"; cat a64.err; rm -f a64.err test/hello.a64to64; exit 1; fi; \
	rm -f a64.err test/hello.a64to64; \
	echo "-- a3: stash+exec roundtrip under qemu (needs keyring syscall passthrough) --"; \
	if out=$$($(QEMU_A64) ./keyringer.aarch64 kfile test/hello_a64 hello 2>a64.err); then \
	    test "$$out" = "keyringer ok" || { echo "FAIL: got \"$$out\""; rm -f a64.err; exit 1; }; \
	    echo "ok: aarch64 fileless exec ($$out; real kernel keyring through qemu)"; \
	else \
	    if grep -q "Function not implemented" a64.err; then \
	        echo "SKIP: this qemu-user does not pass add_key/keyctl through (ENOSYS)."; \
	        echo "      Verified here instead: loader crypto/integrity (a1) and arch"; \
	        echo "      validation (a2) under qemu; stash+exec for the shared loader"; \
	        echo "      logic on the native x86 lane (sections 1-20)."; \
	    else \
	        echo "FAIL: unexpected error:"; cat a64.err; rm -f a64.err; exit 1; \
	    fi; \
	fi; \
	rm -f a64.err; \
	echo "=== aarch64 tests passed ==="

# Real-kernel aarch64 verification: boots a qemu-system-aarch64 VM (Alpine
# netboot kernel + an initramfs overlay) and runs the stash+exec battery
# there — the path qemu-user cannot reach (no keyring syscall passthrough).
# Needs qemu-system-aarch64, unsquashfs, curl, cpio and the aarch64 gcc;
# kernel assets are fetched once into test/a64vm/dl (~345 MB, cached).
# Covers: selftest, preflight, deferred stash->exec across processes,
# kstdin, encrypted roundtrip, wrong-key rejection; big_key SKIPs where the
# guest kernel lacks CONFIG_BIG_KEYS (covered by the x86 suite).
verify-aarch64: keyringer.aarch64 test/hello_a64
	sh test/a64vm/verify.sh

# Second real-kernel aarch64 verification lane, on the DEBIAN stable arm64
# kernel instead of Alpine's: boots a qemu-system-aarch64 VM from the d-i
# (debian-installer) netboot kernel+initrd with the same overlay trick
# (test/a64vm-debian/) and runs the same stash+exec battery. What this lane
# adds over the Alpine one:
#   * an audit-enabled kernel: Debian builds CONFIG_AUDIT=y/CONFIG_AUDITSYSCALL=y
#     and the lane boots with audit=1, asserting the enabled init record
#     (dmesg "audit: initializing netlink subsys (enabled)" + the type=2000
#     "state=initialized audit_enabled=1" event). /proc/sys/kernel/
#     audit_enabled is NOT registered on this kernel generation — the audit
#     sysctls are gone from the default table; auditd userspace (rules,
#     ausearch) needs a full rootfs and stays out of scope (see README).
#   * a big_key roundtrip TRIED for real (modprobe + stash --type big_key):
#     Debian's 6.12 arm64 kernel cannot offer it — v6.12 BIG_KEYS depends on
#     CRYPTO_LIB_CHACHA20POLY1305=y and Debian builds that as a module, so
#     the symbol is not even offered and no big_key.ko exists. The battery
#     prints the evidence (config line count + ENODEV) and SKIPs honestly;
#     the x86 suite covers big_key for real.
# AF_ALG/chacha20poly1305 are modules the d-i initrd does not carry: the
# lane extracts them from the matching linux-image-*-arm64 deb, merges them
# over the initrd's module tree and regenerates the depmod indexes.
# Needs qemu-system-aarch64, cpio, curl, gzip, dpkg-deb, depmod (kmod),
# lsinitramfs and the aarch64 gcc. Asset weight: ~172 MB fetched once into
# test/a64vm-debian/dl (netboot linux ~37 MB + initrd.gz ~42 MB +
# linux-image deb ~93 MB), cached across runs.
verify-aarch64-debian: keyringer.aarch64 test/hello_a64
	sh test/a64vm-debian/verify.sh

# Purple-team harness: fires a controlled stash->exec and a keepalive run
# while the bpftrace detector watches, then asserts both signatures are
# correlated (add_key + READ + REVOKE + exec mapping on one pid;
# GET_PERSISTENT + SEARCH for keepalive). Needs root; skips otherwise.
hunt-test: keyringer keyringer-dyn test/hello
	sh test/hunt_test.sh

clean:
	rm -f keyringer keyringer-dyn keyringer.aarch64 \
	      kr_core.o libkeyringer.so libkeyringer.a \
	      test/hello test/hello_a64 test/lib.so test/shellcode.o \
	      test/shellcode7.o test/shellcode.bin test/shellcode7.bin \
	      test/libuser test/hello.a64fake test/hello.a64to64 \
	      err.tmp v2.tmp v2.tampered sc.err khttp.err pre.tmp \
	      unit.tmp agent.frames kfd.fifo big.tmp a64.err sc.log \
	      v4.tmp v4s.log v4chunk.bin v4chunk.tampered v4big.tmp v4.strace v4.maps \
	      q16k.tmp qfill.tmp q40k.tmp qw.tmp q.err qpy.err qa.err qm.err qw.err

.PHONY: all clean test lib libtest test_x86 test_a64 verify-aarch64 \
        verify-aarch64-debian hunt-test
