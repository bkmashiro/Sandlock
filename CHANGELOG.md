# Changelog

## v1.5.0 — OJ Compatibility

### Added
- `--output-stats`: Output JSON resource usage to stderr after execution
  - Fields: `time_ms`, `memory_kb`, `wall_ms`, `exit_code`, `signal`
  - Uses `wait4()` with `struct rusage` for precise measurements
- `--stdin-file PATH`: Redirect stdin from a file (for OJ judge I/O)
- `--stdout-file PATH`: Redirect stdout to a file (for OJ judge I/O)
- `OJ_COMPAT.md`: Detailed analysis of Lambda vs OJ differences
- `tests/oj_compat_test.sh`: 9-test OJ compatibility test suite

### Fixed
- **seccomp**: Removed `tkill`/`tgkill` from dangerous blocklist. These are
  used by glibc for `raise()`, `abort()`, and `pthread_cancel()`. Blocking them
  broke signal handling and assertions in user programs. The child process is
  already isolated via `setsid()` + `setpgid()`.

### Changed
- Parent process now uses `wait4()` instead of `waitpid()` to collect resource
  usage data (no behavioral change unless `--output-stats` is used)

## v1.4.0 — Strict Mode

### Added
- Strict mode (`--strict`): Path-level syscall interception via seccomp notify
- `--allow PATH`: Allowlist paths for strict mode
- Configuration validation with conflict detection
- Modular source code structure (`src/` directory)

## v1.3.0 — Logging

### Added
- Log levels: `-v` (verbose), `-q` (quiet), `-vv` (debug), `-qqq` (silent)
- `--features` flag to show available kernel features

## v1.2.0 — Isolation

### Added
- `--isolate-tmp`: Private /tmp directory per invocation
- `--cleanup-tmp`: Clean /tmp after execution (Lambda optimization)
- `--workdir DIR`: Set working directory

## v1.1.0 — Landlock

### Added
- Landlock filesystem sandboxing (kernel 5.13+)
- `--landlock`, `--ro PATH`, `--rw PATH`
- `--pipe-io`: Wrap I/O in pipes
- `--max-output BYTES`: Limit output size

## v1.0.0 — Initial Release

### Added
- seccomp-bpf syscall filtering (60+ dangerous syscalls)
- Resource limits: `--cpu`, `--mem`, `--fsize`, `--nofile`, `--nproc`, `--timeout`
- `--no-network`: Block all network syscalls
- `--no-fork`: Block fork (allow threads)
- `--clean-env`: Sanitize environment variables
- No root required
