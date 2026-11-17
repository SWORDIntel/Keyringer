/*
 * keyringer-loader.yara — identify the Keyringer loader binary and its kin
 * (Dntry-class kernel-keyring fileless exec tools) on disk or in memory dumps,
 * plus the Python twin source of the same tool.
 *
 *   yara detections/keyringer-loader.yara <file|pid>
 *
 * Covers: CLI strings, library exports, wire-format magics (KRH1/KR1),
 * the AF_ALG algorithm name, the default spoof name, the KAG1 agent magic,
 * and — as a second rule — the Python twin source (KR_VERSION + wire/syscall
 * markers; not ELF). Any binary that is 4+ of these is almost certainly a
 * keyring-stash loader.
 */

rule Keyringer_Loader
{
    meta:
        author      = "Keyringer detections"
        description = "Kernel keyring fileless ELF loader (Keyringer / Dntry class)"
        date        = "2026-09-13"
        license     = "CC0"
        severity    = "high"

    strings:
        $cli1      = "kstdin" ascii
        $cli2      = "kfile" ascii
        $cli3      = "khttp" ascii
        $cli4      = "selftest" ascii
        $cli5      = "kworker/u8:2" ascii            // default spoof name
        $hdr       = { 4B 52 48 31 }                 // "KRH1" wire v2 header magic
        $env       = { 4B 52 31 }                    // "KR1"  envelope magic
        $desc      = "_keyringer" ascii              // default key description prefix
        $afalg     = "rfc7539(chacha20,poly1305)" ascii
        $exp1      = "kr_load_revoke" ascii
        $exp2      = "kr_stash" ascii
        $agent     = "KAG1" ascii                    // agent framed-pipe stager magic
        $strace_c  = "KEYCTL_READ" ascii             // usage/verbose artifacts

    condition:
        uint32(0) == 0x464C457F                    // ELF
        and ( 3 of ($cli*)                         // CLI artifact
              or 2 of ($exp*)                      // library build
              or ( $hdr and $desc )                // wire + prefix together
              or ( $env and $afalg )               // envelope + kernel-crypto name
              or ( $agent and $desc )              // agent magic + prefix
              or ( $strace_c and $desc ) )         // verbose artifacts + prefix
}

rule Keyringer_Python_Twin
{
    meta:
        author      = "Keyringer detections"
        description = "Keyringer python twin source (kernel-keyring stash loader)"
        date        = "2026-09-18"
        license     = "CC0"
        severity    = "medium"

    strings:
        $ver       = "KR_VERSION" ascii
        $hdr       = "KRH1" ascii                    // wire v2 header magic
        $env       = "KR1" ascii                     // envelope magic
        $desc      = "_keyringer" ascii              // default key prefix
        $afalg     = "rfc7539(chacha20,poly1305)" ascii
        $syscall   = "add_key" ascii
        $spoof     = "kworker/u8:2" ascii

    condition:
        uint32(0) != 0x464C457F                    // not an ELF — source/script
        and 3 of them
}
