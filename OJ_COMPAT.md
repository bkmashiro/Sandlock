# Sandlock OJ Compatibility Analysis

This document analyzes the differences between sandlock's Lambda-optimized design and the requirements of an OJ (Online Judge) / Botzone evaluation backend.

## 1. /tmp Isolation: Lambda vs OJ

### Current Behavior (Lambda-oriented)

- `--isolate-tmp`: Creates `/tmp/sandlock_<pid>_<time>/` per invocation, sets `TMPDIR`
- `--cleanup-tmp`: Records initial `/tmp` entries before execution, removes anything new after execution (whitelist approach)
- `sanitize_env()` sets `HOME` to the isolated tmp directory

### OJ Differences

| Aspect | Lambda | OJ |
|--------|--------|----|
| /tmp persistence | Shared across warm invocations | Ephemeral per test case |
| Working directory | Lambda handler dir | Judge-provided workdir (e.g., `/judge/run/`) |
| File I/O | Typically via API | stdin/stdout files in workdir |
| HOME | Isolated /tmp | Irrelevant (sandboxed user) |

### Recommendations

- For OJ, prefer `--workdir /judge/run/<id>` over `--isolate-tmp`
- `--cleanup-tmp` is Lambda-specific; OJ judges typically wipe the entire workdir externally
- `--isolate-tmp` is still useful for OJ as defense-in-depth, but not required

## 2. Seccomp Rules: What's Missing for OJ

### Currently Blocked (problematic for OJ)

| Syscall | Blocked By | OJ Impact |
|---------|-----------|-----------|
| `tkill` | `--no-dangerous` | **CRITICAL**: glibc uses `tkill` internally for `raise()`, `abort()`, and `pthread_cancel()`. Blocking it breaks signal handling in user programs. |
| `tgkill` | `--no-dangerous` | **CRITICAL**: Used by glibc for `raise()` (sends signal to calling thread). Blocking breaks `assert()`, `abort()`, signal-based error reporting. |
| `inotify_init` | `--no-dangerous` | Low impact for OJ (not typically needed) |
| `symlink`/`link` | `--no-dangerous` | Low impact for OJ (competition programs don't create symlinks) |

### Currently Allowed (good for OJ)

| Syscall | Status | Notes |
|---------|--------|-------|
| `futex` | Allowed | Required for multithreaded programs, mutexes, condition variables |
| `mmap`/`mmap2` | Allowed | Required for memory allocation, shared libraries |
| `brk` | Allowed | Required for heap allocation (malloc) |
| `clone` (threads) | Allowed | `--no-fork` only blocks fork-style clone, threads pass through |
| `mremap` | Allowed | Used by `realloc()` for large allocations |
| `mprotect` | Allowed | Used by dynamic linker |

### Recommendations

- **Remove `tkill`/`tgkill` from the dangerous blocklist**: These are essential for normal program operation. Blocking them was overly cautious — the real threat (killing other processes) is already mitigated by `setsid()` + `setpgid()` isolation. Programs can only signal themselves.
- Keep the `kill(-1, *)` restriction (prevents signaling all processes).

## 3. Resource Statistics: Not Available

### Current State

- sandlock applies `RLIMIT_CPU` and `RLIMIT_AS` but never reports actual usage
- The parent calls `waitpid()` but doesn't call `getrusage()` or `wait4()`
- No machine-readable output of time/memory consumption

### OJ Requirements

OJ judges need precise resource metrics per test case:
- **CPU time** (user + system, milliseconds)
- **Wall-clock time** (for timeout detection)
- **Peak memory** (KB, for memory limit verdicts)
- **Exit code** and **signal** (for RE/TLE/MLE verdicts)

### Recommendations

- Add `--output-stats` flag that outputs JSON to stderr after execution:
  ```json
  {"time_ms": 123, "memory_kb": 4096, "exit_code": 0, "signal": 0, "wall_ms": 150}
  ```
- Use `wait4()` instead of `waitpid()` to get `struct rusage`
- Read `/proc/<pid>/status` for `VmPeak` before the child exits (or use `ru_maxrss` from `getrusage`)

## 4. I/O Redirection: Missing File Support

### Current State

- `--pipe-io`: Wraps stdin/stdout/stderr in pipes, supports `--max-output`
- No support for redirecting stdin from a file or stdout to a file
- The pipe approach adds overhead and complexity (poll loop)

### OJ Requirements

- OJ judges typically: `./solution < input.txt > output.txt 2>/dev/null`
- Need `--stdin-file` and `--stdout-file` for file-based I/O
- File redirection is simpler and more efficient than pipe-io

### Recommendations

- Add `--stdin-file PATH` and `--stdout-file PATH` flags
- Implement via `open()` + `dup2()` in the child process (before `execvp`)
- These are simpler and more OJ-appropriate than `--pipe-io`

## 5. Stack Size Limit

### Current State

- `rlimits.c` hard-codes `RLIMIT_STACK = 8MB`

### OJ Impact

- Most OJ problems are fine with 8MB stack
- Some competitive programming problems with deep recursion may need more
- Consider making this configurable via `--stack MB`

## 6. Process Count Limit

### Current State

- `--nproc N` sets `RLIMIT_NPROC` — limits per-user process count
- `--no-fork` blocks `clone()` without `CLONE_THREAD`

### OJ Recommendations

- For single-threaded problems: `--no-fork --nproc 1`
- For multi-threaded problems: `--nproc 4` (or similar small limit)
- Current behavior is correct for OJ use

## 7. Strict Mode vs Normal Mode

### Current State

- Strict mode uses seccomp-notify for path-level interception
- It conflicts with `--pipe-io` (disables it)
- It's the most secure but adds overhead

### OJ Recommendations

- **Use normal mode** for OJ: simpler, faster, sufficient security
- Strict mode is overkill for OJ where the filesystem is already controlled by the judge
- Use `--landlock` + normal mode for filesystem restrictions if needed

## Summary: Recommended OJ Configuration

```bash
# Typical OJ invocation
sandlock \
  --cpu 2 \
  --mem 256 \
  --timeout 5 \
  --fsize 64 \
  --no-network \
  --clean-env \
  --workdir /judge/run/123/ \
  --stdin-file input.txt \
  --stdout-file output.txt \
  --output-stats \
  -- ./solution
```

## Action Items

1. **[CRITICAL]** Stop blocking `tkill`/`tgkill` in default dangerous list
2. **[HIGH]** Add `--output-stats` for machine-readable resource usage
3. **[HIGH]** Add `--stdin-file` / `--stdout-file` for file-based I/O
4. **[LOW]** Consider `--stack MB` flag for configurable stack size
5. **[LOW]** Document recommended OJ configuration in README
