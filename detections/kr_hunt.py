#!/usr/bin/env python3
"""
kr_hunt.py — BCC live detector for the kernel-keyring stash -> userland-exec
pattern (Keyringer / Dntry-style fileless loaders).

Technique: a loader stashes its payload as add_key("user", "<prefix>.%03u")
chunks on a user keyring, then keyctl(KEYCTL_READ) + keyctl(KEYCTL_REVOKE)
each chunk, maps memory with PROT_EXEC (no execve, no memfd ever fires for
this class) and spoofs its name with prctl(PR_SET_NAME).

Signature per pid, inside a --window (default 2 s) time window:
    >= 1 add_key("user", desc, plen)
    + keyctl(KEYCTL_READ=11) and keyctl(KEYCTL_REVOKE=3) on a serial that
      this pid's add_key returned
    + an mmap()/mprotect() with PROT_EXEC
    (prctl(PR_SET_NAME=15) is recorded as supporting evidence)

ALERT prints timestamp, pid, comm, stash description(s), serial(s) and
"KEYRING-STASH->USERLAND-EXEC".

A second, standalone signature: >= 5 request_key("user", desc) for the
SAME description inside the window is dead-drop beacon polling (kr-kit
exhibit 09-chan-keyring; between commands a beacon emits nothing else).
That emits "BEACON-POLL pid=... desc=... count=..." on its own — polling
alone is suspicious even with zero add_key — and, if a stash->exec alert
fires for the same pid, appends a "beacon-poll evidence" line to it.

usage:
    sudo python3 kr_hunt.py [-v] [--window 2]

Requires root and the `bcc` python package.  If BCC cannot attach in this
environment (missing kernel headers, seccomp/container lockdown,
perf_event_paranoid), fall back to the bpftrace one:
    sudo bpftrace detections/kr_hunt.bt

Kernel caveat (observed on pve 7.0.14): some kernels silently never deliver
events from the syscalls:sys_enter_add_key tracepoint while other syscall
tracepoints (keyctl) work fine — on such hosts this tool's correlation
cannot fire (no add_key events arrive). kr_hunt.bt works there: its
add_key probe is a kprobe on __x64_sys_add_key.  Verified live on the
same host, syscalls:sys_enter_request_key has the identical defect
(6/6 poll syscalls seen on kprobe:__x64_sys_request_key, 0/6 on the
tracepoint), so the request_key probe here is a kprobe too.
"""

import argparse
import ctypes
import datetime
import os
import sys
import time

# ---------------------------------------------------------------------------
# constants (mirror keyringer's toolchain)
# ---------------------------------------------------------------------------
KEYCTL_READ = 11               # keyctl cmd: read a key payload
KEYCTL_REVOKE = 3              # keyctl cmd: kill a key
PROT_EXEC = 0x4
PR_SET_NAME = 15

# event kinds emitted by the BPF program
EV_ADD_KEY = 1                 # sys_enter_add_key, type == "user"
EV_ADDKEY_RET = 2              # sys_exit_add_key, ret > 0 (serial)
EV_KEYCTL = 3                  # sys_enter_keyctl, cmd in (READ, REVOKE)
EV_MMAP = 4                    # sys_enter_mmap, prot & PROT_EXEC
EV_MPROTECT = 5                # sys_enter_mprotect, prot & PROT_EXEC
EV_PRCTL = 6                   # sys_enter_prctl, option == PR_SET_NAME
EV_REQKEY = 7                  # kprobe request_key, type == "user"

# beacon-poll threshold: request_key("user", desc) hits on ONE description
# inside the correlation window before BEACON-POLL fires (kr-kit exhibit
# 09 polls every 200 ms, so a live beacon crosses this in ~1 s)
BEACON_POLL_MIN = 5

KIND_NAMES = {
    EV_ADD_KEY: "add_key",
    EV_ADDKEY_RET: "add_key=ret",
    EV_KEYCTL: "keyctl",
    EV_MMAP: "mmap",
    EV_MPROTECT: "mprotect",
    EV_PRCTL: "prctl",
    EV_REQKEY: "request_key",
}

BPF_SRC = r"""
#include <uapi/linux/ptrace.h>

#define EV_ADD_KEY     1
#define EV_ADDKEY_RET  2
#define EV_KEYCTL      3
#define EV_MMAP        4
#define EV_MPROTECT    5
#define EV_PRCTL       6
#define EV_REQKEY      7

struct event_t {
    u64  ts_ns;      /* bpf_ktime_get_ns() */
    u64  aux;        /* plen / mmap-mprotect length */
    s64  serial;     /* key serial (add_key ret / keyctl arg2) */
    u32  pid;        /* tgid */
    u32  cmd;        /* keyctl cmd / prot / prctl option */
    u32  kind;       /* EV_* */
    char comm[16];
    char desc[64];   /* key description / prctl name */
};

BPF_PERF_OUTPUT(events);

/* raw syscall-tracepoint argument frame (x86-64): common header, then
 * __syscall_nr, then the six syscall arguments.  Declared by hand so the
 * program does not depend on per-kernel tracepoint field naming. */
struct sc_enter {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __syscall_nr;
    long           args[6];
};

struct sc_exit {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __syscall_nr;
    long           ret;
};

static __always_inline void fill(struct event_t *e, u32 kind) {
    u64 id = bpf_get_current_pid_tgid();
    e->pid   = id >> 32;
    e->ts_ns = bpf_ktime_get_ns();
    e->kind  = kind;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
}

/*
 * add_key enters/exits via KPROBE on the syscall stub, NOT the syscall
 * tracepoint: some kernels (observed on pve 7.0.14) silently never deliver
 * sys_enter_add_key tracepoint events while other syscall tracepoints
 * (keyctl etc.) work fine.  Syscall args on x86-64 live in
 * di/si/dx/r10/r8/r9 — plen is the 4th arg, hence regs->r10.
 */
int on_enter_add_key(struct pt_regs *ctx) {
    /* the stub's only argument is a pointer to the saved user regs:
     * arg0 (type) = regs->di, arg1 (desc) = regs->si, arg3 (plen) =
     * regs->r10 — deref the kernel-side pointer first */
    u64 up = (u64)ctx->di;
    struct pt_regs *uregs = (struct pt_regs *)up;
    u64 type_ptr = 0, desc_ptr = 0, plen = 0;
    char type[8] = {};

    bpf_probe_read_kernel(&type_ptr, sizeof(type_ptr), &uregs->di);
    bpf_probe_read_kernel(&desc_ptr, sizeof(desc_ptr), &uregs->si);
    bpf_probe_read_kernel(&plen, sizeof(plen), &uregs->r10);
    bpf_probe_read_user_str(type, sizeof(type), (const void *)type_ptr);
    if (type[0] != 'u' || type[1] != 's' || type[2] != 'e' ||
        type[3] != 'r' || type[4] != '\0')
        return 0;                       /* only "user"-type keys stash */
    struct event_t e = {};
    fill(&e, EV_ADD_KEY);
    e.aux = plen;
    bpf_probe_read_user_str(e.desc, sizeof(e.desc), (const void *)desc_ptr);
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int on_exit_add_key(struct pt_regs *ctx) {
    u64 ret = (u64)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;                       /* failed add_key: no serial */
    struct event_t e = {};
    fill(&e, EV_ADDKEY_RET);
    e.serial = ret;
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

/*
 * request_key enters via the SAME kprobe-on-stub workaround as add_key:
 * this host's syscalls:sys_enter_request_key tracepoint silently never
 * delivers (verified live: 0/6 events vs 6/6 on the kprobe).  Args:
 * arg0 (type) = regs->di, arg1 (desc) = regs->si, arg3 (dest ring id) =
 * regs->r10.  Only "user"-type requests are kept, matching add_key: the
 * keyring-C2 grammar (Keyringer, kr-kit exhibit 09) is user-type, and it
 * keeps dns_resolver/cifs.spnego id-resolution chatter out.
 */
int on_enter_request_key(struct pt_regs *ctx) {
    u64 up = (u64)ctx->di;
    struct pt_regs *uregs = (struct pt_regs *)up;
    u64 type_ptr = 0, desc_ptr = 0, ringid = 0;
    char type[8] = {};

    bpf_probe_read_kernel(&type_ptr, sizeof(type_ptr), &uregs->di);
    bpf_probe_read_kernel(&desc_ptr, sizeof(desc_ptr), &uregs->si);
    bpf_probe_read_kernel(&ringid, sizeof(ringid), &uregs->r10);
    bpf_probe_read_user_str(type, sizeof(type), (const void *)type_ptr);
    if (type[0] != 'u' || type[1] != 's' || type[2] != 'e' ||
        type[3] != 'r' || type[4] != '\0')
        return 0;                       /* only "user"-type beacons poll */
    struct event_t e = {};
    fill(&e, EV_REQKEY);
    e.serial = ringid;                  /* dest keyring id (KEY_SPEC_*) */
    bpf_probe_read_user_str(e.desc, sizeof(e.desc), (const void *)desc_ptr);
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int on_enter_keyctl(struct sc_enter *args) {
    u32 cmd = args->args[0];
    if (cmd != 11 && cmd != 3)          /* KEYCTL_READ / KEYCTL_REVOKE */
        return 0;
    struct event_t e = {};
    fill(&e, EV_KEYCTL);
    e.cmd    = cmd;
    e.serial = args->args[1];           /* key serial */
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

int on_enter_mmap(struct sc_enter *args) {
    u32 prot = args->args[2];
    if (!(prot & 0x4))                  /* PROT_EXEC */
        return 0;
    struct event_t e = {};
    fill(&e, EV_MMAP);
    e.cmd = prot;
    e.aux = args->args[1];              /* length */
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

int on_enter_mprotect(struct sc_enter *args) {
    u32 prot = args->args[2];
    if (!(prot & 0x4))                  /* PROT_EXEC */
        return 0;
    struct event_t e = {};
    fill(&e, EV_MPROTECT);
    e.cmd = prot;
    e.aux = args->args[1];              /* length */
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

int on_enter_prctl(struct sc_enter *args) {
    if (args->args[0] != 15)            /* PR_SET_NAME */
        return 0;
    struct event_t e = {};
    fill(&e, EV_PRCTL);
    e.cmd = 15;
    bpf_probe_read_user_str(e.desc, sizeof(e.desc),
                            (const void *)args->args[1]);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""


class Event(ctypes.Structure):
    """userspace mirror of the BPF struct event_t (native alignment)."""
    _fields_ = [
        ("ts_ns", ctypes.c_uint64),
        ("aux", ctypes.c_uint64),
        ("serial", ctypes.c_int64),
        ("pid", ctypes.c_uint32),
        ("cmd", ctypes.c_uint32),
        ("kind", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("desc", ctypes.c_char * 64),
    ]


def _cstr(raw):
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


class PidState(object):
    """correlation state for one pid (stash -> consume -> exec chain)."""

    __slots__ = ("start_ns", "last_seen", "descs", "serials", "plen",
                 "read", "revoke", "exec", "exec_how", "prname", "comm",
                 "reqkey", "beacon")

    def __init__(self):
        self.reset(0)

    def reset(self, now_ns):
        self.start_ns = now_ns
        self.descs = set()
        self.serials = set()
        self.plen = set()
        self.read = False
        self.revoke = False
        self.exec = False
        self.exec_how = set()
        self.prname = None
        self.comm = b"?"
        self.reqkey = {}             # desc -> [ts_ns, ...] within window
        self.beacon = {}             # desc -> count, already alerted


class Hunter(object):
    def __init__(self, window_s, verbose):
        self.window_ns = int(window_s * 1e9)
        self.verbose = verbose
        self.states = {}
        self.alerts = 0

    def _state(self, pid, ts_ns):
        st = self.states.get(pid)
        if st is None:
            st = self.states[pid] = PidState()
        if st.start_ns == 0 or ts_ns - st.start_ns > self.window_ns:
            st.reset(ts_ns)             # outside the window: start over
        return st

    def _verbose(self, ev):
        if not self.verbose:
            return
        detail = ""
        if ev.kind == EV_ADD_KEY:
            detail = 'desc="%s" plen=%d' % (_cstr(ev.desc), ev.aux)
        elif ev.kind == EV_ADDKEY_RET:
            detail = "serial=%d" % ev.serial
        elif ev.kind == EV_KEYCTL:
            detail = "cmd=%s serial=%d" % (
                "KEYCTL_READ" if ev.cmd == KEYCTL_READ else "KEYCTL_REVOKE",
                ev.serial)
        elif ev.kind in (EV_MMAP, EV_MPROTECT):
            detail = "prot=0x%x len=%d" % (ev.cmd, ev.aux)
        elif ev.kind == EV_PRCTL:
            detail = 'PR_SET_NAME="%s"' % _cstr(ev.desc)
        elif ev.kind == EV_REQKEY:
            detail = 'desc="%s" ringid=%d' % (_cstr(ev.desc), ev.serial)
        print("[event] %-11s pid=%-7d comm=%-16s %s"
              % (KIND_NAMES[ev.kind], ev.pid, _cstr(ev.comm), detail),
              flush=True)

    def feed(self, ev):
        st = self._state(ev.pid, ev.ts_ns)
        st.last_seen = ev.ts_ns
        st.comm = ev.comm

        if ev.kind == EV_ADD_KEY:
            st.descs.add(_cstr(ev.desc))
            st.plen.add(ev.aux)
        elif ev.kind == EV_ADDKEY_RET:
            st.serials.add(ev.serial)
        elif ev.kind == EV_KEYCTL:
            # only count keyctl churn on a serial THIS pid's add_key returned
            if ev.serial in st.serials:
                if ev.cmd == KEYCTL_READ:
                    st.read = True
                elif ev.cmd == KEYCTL_REVOKE:
                    st.revoke = True
        elif ev.kind == EV_MMAP:
            st.exec = True
            st.exec_how.add("mmap")
        elif ev.kind == EV_MPROTECT:
            st.exec = True
            st.exec_how.add("mprotect")
        elif ev.kind == EV_PRCTL:
            st.prname = _cstr(ev.desc)
        elif ev.kind == EV_REQKEY:
            # dead-drop beacon heartbeat: same description polled over and
            # over (usually ENOKEY).  Standalone alert once per window.
            desc = _cstr(ev.desc)
            polls = st.reqkey.setdefault(desc, [])
            polls.append(ev.ts_ns)
            st.reqkey[desc] = [t for t in polls
                               if ev.ts_ns - t <= self.window_ns]
            if (len(st.reqkey[desc]) >= BEACON_POLL_MIN
                    and desc not in st.beacon):
                st.beacon[desc] = len(st.reqkey[desc])
                self.beacon_alert(ev.pid, st, desc)

        self._verbose(ev)

        if (st.descs and st.read and st.revoke and st.exec
                and ev.ts_ns - st.start_ns <= self.window_ns):
            self.alert(ev.pid, st)
            st.reset(ev.ts_ns)          # one alert per burst

    def alert(self, pid, st):
        self.alerts += 1
        now = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        spoof = ' prctl-name="%s"' % st.prname if st.prname else ""
        print("ALERT %s pid=%d comm=%s stash-descs=%s serials=%s "
              "exec=%s%s KEYRING-STASH->USERLAND-EXEC"
              % (now, pid, _cstr(st.comm),
                 ",".join(sorted(st.descs)) or "?",
                 ",".join(str(s) for s in sorted(st.serials)) or "?",
                 "+".join(sorted(st.exec_how)) or "?",
                 spoof),
              flush=True)
        # supporting evidence: this pid was also dead-drop polling
        for desc in sorted(st.beacon):
            print("      beacon-poll evidence: request_key(\"%s\") x%d "
                  "within the window" % (desc, st.beacon[desc]),
                  flush=True)

    def beacon_alert(self, pid, st, desc):
        """standalone: polling alone is suspicious even with zero add_key."""
        self.alerts += 1
        now = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        print("BEACON-POLL %s pid=%d comm=%s desc=%s count=%d window=%.1fs "
              "dead-drop request_key polling"
              % (now, pid, _cstr(st.comm), desc, st.beacon[desc],
                 self.window_ns / 1e9),
              flush=True)

    def purge(self):
        """drop state for pids that went quiet (bound memory)."""
        cutoff = time.monotonic() - max(self.window_ns / 1e9 * 4, 10.0)
        for pid in [p for p, s in self.states.items()
                    if s.last_seen < cutoff]:
            del self.states[pid]


def main():
    ap = argparse.ArgumentParser(
        description="live hunt for kernel-keyring stash -> userland-exec "
                    "loaders (Keyringer/Dntry class)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log every raw event line")
    ap.add_argument("--window", type=float, default=2.0, metavar="SEC",
                    help="correlation window in seconds (default 2)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.stderr.write("kr_hunt: must run as root "
                         "(sudo python3 detections/kr_hunt.py)\n")
        return 1
    try:
        from bcc import BPF
    except Exception as ex:
        sys.stderr.write("kr_hunt: cannot import bcc: %s\n" % ex)
        sys.stderr.write("  fall back to: sudo bpftrace "
                         "detections/kr_hunt.bt\n")
        return 1

    try:
        bpf = BPF(text=BPF_SRC)
        for spec, fn, kind in (
            ("__x64_sys_add_key", "on_enter_add_key", "kprobe"),
            ("__x64_sys_add_key", "on_exit_add_key", "kretprobe"),
            ("__x64_sys_request_key", "on_enter_request_key", "kprobe"),
            ("syscalls:sys_enter_keyctl", "on_enter_keyctl", "tracepoint"),
            ("syscalls:sys_enter_mmap", "on_enter_mmap", "tracepoint"),
            ("syscalls:sys_enter_mprotect", "on_enter_mprotect", "tracepoint"),
            ("syscalls:sys_enter_prctl", "on_enter_prctl", "tracepoint"),
        ):
            if kind == "kprobe":
                bpf.attach_kprobe(event=spec, fn_name=fn)
            elif kind == "kretprobe":
                bpf.attach_kretprobe(event=spec, fn_name=fn)
            else:
                bpf.attach_tracepoint(tp=spec, fn_name=fn)
    except Exception as ex:
        sys.stderr.write("kr_hunt: BCC attach failed: %s: %s\n"
                         % (type(ex).__name__, ex))
        sys.stderr.write(
            "  BCC cannot attach in this environment (missing kernel "
            "headers, seccomp/container lockdown, or perf_event_paranoid).\n"
            "  fall back to the bpftrace version:\n"
            "      sudo bpftrace detections/kr_hunt.bt\n")
        return 1

    hunter = Hunter(args.window, args.verbose)

    def on_event(cpu, data, size):
        ev = ctypes.cast(data, ctypes.POINTER(Event)).contents
        hunter.feed(ev)

    def on_lost(lost):
        sys.stderr.write("kr_hunt: WARNING: %d events lost\n" % lost)

    bpf["events"].open_perf_buffer(on_event, page_cnt=128,
                                   lost_cb=on_lost)

    print("kr_hunt: watching add_key/request_key/keyctl/mmap/mprotect/prctl"
          " (window %.1fs, verbose=%s) — Ctrl-C to stop"
          % (args.window, args.verbose), flush=True)
    try:
        last_purge = time.monotonic()
        while True:
            bpf.perf_buffer_poll(timeout=300)
            if time.monotonic() - last_purge > 5.0:
                hunter.purge()
                last_purge = time.monotonic()
    except KeyboardInterrupt:
        print("\nkr_hunt: exiting (%d alert(s) raised)"
              % hunter.alerts, flush=True)
        return 0
    finally:
        try:
            bpf.cleanup()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
