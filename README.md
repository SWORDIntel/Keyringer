# Keyringer

Keyringer is a Linux research tool for examining how kernel keyrings can be used to stage and load executable data in memory. It is designed for authorized security research and controlled lab use, and includes both the loader and defensive tools for observing and detecting this behavior.

The project supports Linux on x86-64 and AArch64. Its C command-line tool and Python companion can store payload data in kernel keyrings, validate and load supported ELF files or raw test code, and clean up keys after use. The repository also includes hunt rules and utilities to help defenders identify related keyring and memory-mapping activity.

This is a specialized low-level tool, not a general-purpose application. Its behavior depends on kernel configuration, keyring permissions and quotas, and executable-memory policy. Some modes deliberately execute supplied code in the current process; use only in systems and engagements where you have explicit authorization. The included detections and test suites help examine the technique, but do not guarantee detection or compatibility on every system.

## Getting started

On a Linux development system with a C compiler and `make`:

```sh
make
make test
```

The tests exercise the local x86-64 build. AArch64 builds and virtual-machine verification require additional cross-compilers, emulators, and downloads; see the technical guide before running those targets.

## Project resources

- [CLI and technical guide](docs/CLI.md) — commands, options, architecture, formats, testing, platform limitations, and detection details.
- [`detections/`](detections/) — live and post-event detection and prevention material.
- [`test/`](test/) — test sources, fuzzing harnesses, and architecture-specific test infrastructure.

## Credits

Keyringer builds on publicly documented kernel-keyring research, including the [Linux kernel keyring fileless exec write-up](https://matheuzsecurity.github.io/hacking/linux-kernel-keyring-fileless-exec/) and the [Dntry reference implementation](https://github.com/MatheuZSecurity/Dntry).
