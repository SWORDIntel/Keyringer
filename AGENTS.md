# Contributor and agent guide

## Project scope

Keyringer is Linux x86-64/AArch64 research software for studying kernel-keyring-backed
in-memory payload loading, together with defensive detection and prevention material. Make
changes for authorized lab and defensive work. Preserve clear documentation of execution
behavior, platform constraints, and detection limitations. Start with [README.md](README.md)
and consult the [CLI and technical guide](docs/CLI.md) for command and architecture details.

## Layout

- `main.c`, `kr_core.c`, `keyringer.h`, and `keyringer.py`: loader, core/library API, and Python companion.
- `test/`: unit/integration tests, fuzz harnesses, sample payload sources, and VM verification scripts.
- `detections/`: hunt rules, detector scripts, and prevention profiles.
- `docs/CLI.md`: detailed CLI, implementation, testing, and detection reference.

## Build and test

The project targets Linux. A C compiler and `make` are required for the standard x86-64 path.
Use the Makefile as the source of truth for available targets:

```sh
make
make test
make hunt-test
make ARCH=aarch64
make ARCH=aarch64 test
```

AArch64 VM verification targets require additional cross-compilers, QEMU, and other host tools;
they may download large kernel and initramfs assets. See `docs/CLI.md` before running them. Run
focused checks for changes, then the relevant wider suite. Do not claim VM or live-kernel
coverage based only on unit tests.

## Change expectations

- Keep patches focused and preserve existing behavior unless the request calls for a change.
- Add or update tests for behavior changes; keep detection rules and documentation aligned with
  implementation.
- Validate documentation links and formatting when editing Markdown.
- Do not delete or regenerate files as cleanup without checking whether they are user data or
  cached inputs.

## Preserve local artifacts and research records

`test/a64vm/` and `test/a64vm-debian/` contain generated VM trees and large downloaded assets.
They are cached inputs for expensive real-kernel tests; do not remove or overwrite them as
incidental cleanup. `make clean` removes the build outputs listed by the Makefile, not those VM
trees. Preserve `recovery/` and `zcode_recovered_sessions/` if they exist in a local research
checkout; do not publish them without explicit authorization.
