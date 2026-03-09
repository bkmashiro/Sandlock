# Sandlock v1.4.0 Technical Documentation

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    sandlock binary                          │
├─────────────────────────────────────────────────────────────┤
│  main.c          │ CLI parsing, signal handling, fork/exec  │
│  config.c        │ Configuration validation, conflict check │
│  strict.c        │ Seccomp notify path-level control        │
│  seccomp.c       │ seccomp-bpf syscall filtering            │
│  landlock.c      │ Landlock filesystem sandbox              │
│  rlimits.c       │ Resource limits (CPU, memory, files)     │
│  pipes.c         │ I/O pipe handling                        │
│  isolation.c     │ /tmp isolation and cleanup               │
│  globals.c       │ Global state and feature detection       │
└─────────────────────────────────────────────────────────────┘
```

## Module Details

### 1. Feature Detection (globals.c)

```c
typedef struct {
    int kernel_major, kernel_minor;
    int has_landlock;        // kernel >= 5.13
    int has_memfd_secret;    // kernel >= 5.14
    int has_seccomp_notify;  // kernel >= 5.0
} SystemFeatures;
```

Runtime detection via `uname()` to enable/disable features gracefully.

### 2. Configuration Validation (config.c)

Validates configuration at startup, detects conflicts:

| Conflict | Detection | Resolution |
|----------|-----------|------------|
| `--strict` without `--allow` | Error | Won't start |
| `--strict` + `--pipe-io` | Warning | Disable pipe-io |
| `--landlock` + `--strict` | Warning | Both work (redundant) |
| `--isolate-tmp` + `--cleanup-tmp` | Warning | Redundant |
| `--cpu` > `--timeout` | Warning | Timeout triggers first |

### 3. Seccomp Filtering (seccomp.c)

Uses libseccomp for BPF filter generation.

**Blocked syscalls (--no-dangerous, default on):**

| Category | Syscalls |
|----------|----------|
| Debug | ptrace, process_vm_readv/writev |
| Kernel | bpf, io_uring_*, userfaultfd, perf_event_open |
| Namespace | unshare, setns |
| Filesystem | mount, umount2, chroot, pivot_root, symlink*, link* |
| System | reboot, kexec_*, *_module |
| Monitoring | inotify_*, fanotify_* |
| Keys | keyctl, add_key, request_key |
| Hardware | ioperm, iopl, modify_ldt |
| Time | settimeofday, clock_settime, adjtimex |
| Signals | kill(-1, *), tkill, tgkill |

**Network blocking (--no-network):**
```c
socket, connect, bind, listen, accept, accept4,
sendto, recvfrom, sendmsg, recvmsg, socketpair
```

**Fork blocking (--no-fork):**
```c
// Blocks fork but allows threads
clone with CLONE_THREAD=0 → EPERM
```

### 4. Strict Mode (strict.c)

Path-level syscall interception using seccomp notify (kernel 5.0+).

**Architecture:**

```
Parent Process                    Child Process
     │                                 │
     │                            fork()
     │                                 │
     │                        ┌────────┴────────┐
     │                        │ Install seccomp │
     │                        │ with NEW_LISTENER│
     │                        └────────┬────────┘
     │                                 │
     │◄──────── send notify_fd ────────┤
     │                                 │
     ├─────────── "ready" ────────────►│
     │                                 │
┌────┴────┐                      ┌─────┴─────┐
│ Notify  │                      │  execvp() │
│ Handler │                      └───────────┘
│ Thread  │
└────┬────┘
     │
     │◄─────── openat("/etc/passwd") ──
     │         
     ├── is_path_allowed() ?
     │   ├─ YES: CONTINUE
     │   └─ NO:  EACCES
     │
     ├─────── response ──────────────►
```

**Always-allowed paths:**
```c
"/bin", "/sbin", "/usr/bin", "/usr/sbin",
"/lib", "/lib64", "/usr/lib", "/usr/lib64",
"/etc/ld.so", "/etc/localtime", "/etc/timezone", "/etc/passwd",
"/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/tty",
"/proc/", "/sys/"
```

**Intercepted syscalls:**
- `openat` - File access
- `open` - Legacy file access (x86_64)
- `execve` - Program execution

### 5. Landlock (landlock.c)

Filesystem sandboxing using Landlock LSM (kernel 5.13+).

**Supported operations:**
```c
LANDLOCK_ACCESS_FS_READ_FILE
LANDLOCK_ACCESS_FS_READ_DIR
LANDLOCK_ACCESS_FS_WRITE_FILE
LANDLOCK_ACCESS_FS_REMOVE_FILE
LANDLOCK_ACCESS_FS_REMOVE_DIR
LANDLOCK_ACCESS_FS_MAKE_REG
LANDLOCK_ACCESS_FS_MAKE_DIR
LANDLOCK_ACCESS_FS_EXECUTE
```

**Graceful degradation:** If Landlock unavailable, logs warning and continues.

### 6. Resource Limits (rlimits.c)

| Option | rlimit | Notes |
|--------|--------|-------|
| `--cpu N` | RLIMIT_CPU | CPU seconds |
| `--mem N` | RLIMIT_AS | Virtual memory (MB) |
| `--fsize N` | RLIMIT_FSIZE | Max file size (MB) |
| `--nofile N` | RLIMIT_NOFILE | Open file descriptors |
| `--nproc N` | RLIMIT_NPROC | Per-user, not per-sandbox |

**Always set:**
- RLIMIT_CORE = 0 (no core dumps)
- RLIMIT_STACK = 8MB

### 7. I/O Handling (pipes.c)

When `--pipe-io` enabled:
1. Create stdin/stdout/stderr pipes
2. Child redirects to pipes
3. Parent polls and forwards with optional truncation

**Output limiting (`--max-output`):** Truncates after N bytes.

### 8. Isolation (isolation.c)

**`--isolate-tmp`:**
```c
// Creates /tmp/sandlock_<pid>_<time>/
// Sets TMPDIR environment variable
// Auto-cleanup on exit via atexit()
```

**`--cleanup-tmp`:**
```c
// Records /tmp entries before execution
// Deletes only NEW entries after execution
// Whitelist approach (concurrent-safe)
```

## Execution Flow

### Normal Mode

```
main()
  ├─ detect_features()
  ├─ parse_options()
  ├─ validate_config()     ← NEW in v1.4.0
  ├─ setup_signals()
  ├─ setup_isolated_tmp()  (if --isolate-tmp)
  ├─ record_tmp_entries()  (if --cleanup-tmp)
  ├─ setup_pipes()         (if --pipe-io)
  ├─ fork()
  │   └─ Child:
  │       ├─ setsid(), setpgid()
  │       ├─ child_setup_pipes()
  │       ├─ chdir(workdir)
  │       ├─ prctl(NO_NEW_PRIVS)
  │       ├─ apply_rlimits()
  │       ├─ apply_landlock()    (if --landlock)
  │       ├─ apply_seccomp()
  │       ├─ sanitize_env()      (if --clean-env)
  │       └─ execvp()
  └─ Parent:
      ├─ parent_handle_pipes()
      ├─ waitpid()
      ├─ cleanup_isolated_tmp()
      ├─ cleanup_tmp_dir()
      └─ return exit_code
```

### Strict Mode

```
main()
  ├─ detect_features()
  ├─ parse_options()
  ├─ validate_config()
  │   └─ Check: has paths, no pipe-io conflict
  └─ run_strict_mode()     ← Different path
      ├─ socketpair()      (for fd passing)
      ├─ fork()
      │   └─ Child:
      │       ├─ apply_rlimits()
      │       ├─ apply_landlock()
      │       ├─ setup_strict_seccomp()
      │       │   └─ Returns notify_fd
      │       ├─ send notify_fd to parent
      │       ├─ wait for "ready"
      │       └─ execvp()
      └─ Parent:
          ├─ receive notify_fd
          ├─ pthread_create(notify_handler)
          ├─ signal "ready" to child
          ├─ waitpid()
          └─ cleanup
```

## Kernel Compatibility

| Feature | Min Kernel | Lambda (5.10) | Modern (6.x) |
|---------|:----------:|:-------------:|:------------:|
| seccomp-bpf | 3.5 | ✅ | ✅ |
| seccomp notify | 5.0 | ✅ | ✅ |
| Landlock | 5.13 | ❌ | ✅ |
| memfd_secret | 5.14 | ❌ | ✅ |

**Lambda limitation:** Firecracker pre-applies seccomp filters, blocking additional filter installation.

## Log Levels

```c
enum LogLevel {
    LL_SILENT = 0,  // -qqq
    LL_ERROR  = 1,  // -qq
    LL_WARN   = 2,  // -q
    LL_INFO   = 3,  // default
    LL_DEBUG  = 4,  // -v
    LL_TRACE  = 5   // -vv
};
```

## Performance

| Overhead | Time |
|----------|------|
| Startup (minimal) | ~1.5ms |
| Startup (full) | ~2.5ms |
| Strict mode notify | ~0.1ms/syscall |

## Security Considerations

### Mitigated Threats

1. **Syscall-based attacks** - seccomp-bpf blocks 60+ dangerous syscalls
2. **Network exfiltration** - Socket syscalls blocked
3. **Resource exhaustion** - rlimits enforced
4. **Privilege escalation** - NO_NEW_PRIVS always set
5. **File access (Landlock)** - Kernel-enforced path restrictions
6. **File access (Strict)** - Userspace path validation

### Known Limitations

1. `/proc` readable without mount namespace
2. `RLIMIT_NPROC` is per-user, not per-sandbox
3. Static binaries bypass LD_PRELOAD (not used)
4. Lambda: Cannot install seccomp filters

### Attack Surface

| Vector | Status | Mitigation |
|--------|--------|------------|
| Direct syscall | ✅ Blocked | seccomp-bpf |
| /proc info leak | ⚠️ Partial | --clean-env |
| Shared /tmp | ✅ Mitigated | --isolate-tmp |
| Symlink attacks | ✅ Blocked | Block symlink* |

## Environment Comparison

### Feature Availability

| Feature | Userspace | Lambda |
|---------|:---------:|:------:|
| seccomp-bpf | ✅ | ❌ Firecracker blocks |
| seccomp notify | ✅ | ❌ |
| Landlock | ✅ (5.13+) | ❌ (kernel 5.10) |
| rlimits | ✅ | ✅ |
| Python sandbox | ✅ | ✅ |
| Node.js sandbox | ✅ | ✅ |
| LD_PRELOAD | ✅ | ✅ |
| Source scanner | ✅ | ✅ |
| VPC isolation | N/A | ✅ |

### Attack Defense by Environment

| Attack | Userspace | Lambda+Py | Lambda+Node | Lambda+Preload | Lambda Only |
|--------|:---------:|:---------:|:-----------:|:--------------:|:-----------:|
| Network exfiltration | ✅ | ✅ | ✅ | ✅ | ❌ |
| Reverse shell | ✅ | ✅ | ✅ | ✅ | ❌ |
| Fork bomb | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| subprocess/exec | ✅ | ✅ | ✅ | ✅ | ❌ |
| Memory exhaustion | ✅ | ✅ | ✅ | ✅ | ✅ |
| CPU exhaustion | ✅ | ✅ | ✅ | ✅ | ✅ |
| Disk filling | ✅ | ✅ | ✅ | ✅ | ✅ |
| Infinite loop | ✅ | ✅ | ✅ | ✅ | ✅ |
| Read sensitive files | ✅ | ✅ | ✅ | ✅ | ❌ |
| Write outside /tmp | ✅ | ✅ | ✅ | ✅ | ✅ |
| ptrace/debugging | ✅ | ✅ | ✅ | ✅ | ✅ |
| Symlink attacks | ✅ | ✅ | ✅ | ⚠️ | ❌ |
| dlopen/FFI | ✅ | ✅ | ✅ | ⚠️ | ❌ |
| eval/exec (dynamic) | N/A | ✅ | ✅ | N/A | ❌ |
| Direct syscall (asm) | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| Sandbox escape | ✅ | ⚠️ | ⚠️ | N/A | N/A |
| /proc info leak | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ |

Legend: ✅ Defended | ⚠️ Partial | ❌ Not defended | N/A Not applicable

**Lambda+Preload** = LD_PRELOAD + source scanner + dynamic linking (for C/C++/Rust/Go)

### Defense Technologies

| Attack | Userspace | Lambda+Py/Node | Lambda+Preload | Lambda Only |
|--------|-----------|----------------|----------------|-------------|
| Network | seccomp | import/module block | LD_PRELOAD | ❌ use VPC |
| Fork | seccomp | import/module block | LD_PRELOAD | Lambda limit |
| Memory | rlimit | rlimit | rlimit | Lambda config |
| CPU/timeout | rlimit | rlimit | rlimit | Lambda timeout |
| Disk | rlimit | rlimit | rlimit | /tmp 512MB |
| File read | Landlock/strict | restricted open() | LD_PRELOAD | ❌ |
| File write | Landlock/strict | restricted open() | LD_PRELOAD | read-only rootfs |
| ptrace | seccomp | no ctypes/ffi | Firecracker | Firecracker |
| Symlink | seccomp | no os module | ⚠️ partial | ❌ |
| FFI/dlopen | seccomp | blocked imports | source scanner | ❌ |
| Direct syscall | seccomp | ⚠️ scanner | ⚠️ scanner | ❌ |

## Language Sandboxes

### Python Sandbox (lang/python/sandbox.py)

**Mechanism:**
- Import hook blocks dangerous modules
- Restricted builtins (no exec/eval/compile/input)
- Restricted open() only allows /tmp

**Blocked modules:**
```
socket, ssl, requests, urllib, http
subprocess, os, sys, shutil
ctypes, cffi, mmap, pickle, marshal
importlib, inspect, gc
multiprocessing, threading
```

**Allowed modules:**
```
math, json, csv, re, collections
datetime, typing, dataclasses
random, statistics, hashlib
```

**Known bypass risks:**
- `().__class__.__bases__[0].__subclasses__()` - partial mitigation
- C extensions with inline asm - use source scanner

### JavaScript Sandbox (lang/javascript/)

**sandbox.js (VM isolation):**
- Uses Node.js `vm` module
- Restricted context (no process, eval, Function)
- Module whitelist/blacklist
- Timeout protection

**wrapper.js (Runtime patching):**
- Full Node API available
- Module blocking at require level
- FS path restrictions
- For apps needing npm packages

| Feature | sandbox.js | wrapper.js |
|---------|:----------:|:----------:|
| npm packages | ❌ | ✅ |
| Full Node API | ❌ | ✅ |
| Isolation strength | Higher | Medium |

### Source Code Scanner (lang/scanner/scanner.py)

Pre-compilation check for dangerous patterns:

| Severity | Patterns | Example |
|----------|----------|---------|
| 🔴 Critical | Inline asm | `asm("syscall")` |
| 🔴 Critical | syscall instruction | `syscall`, `int 0x80` |
| 🔴 Critical | Custom entry point | `_start()` |
| 🟠 High | Syscall wrapper | `syscall(SYS_socket)` |
| 🟠 High | FFI | `ctypes`, `dlopen`, `ffi-napi` |
| 🟡 Medium | Dangerous functions | `fork`, `socket`, `eval` |

**Supported languages:** C/C++, Python, JavaScript, Rust, Go

### LD_PRELOAD Hook (lang/preload/sandbox_preload.c)

Hooks libc functions for compiled languages:

```bash
LD_PRELOAD=./sandbox_preload.so \
  SANDBOX_NO_NETWORK=1 \
  SANDBOX_NO_FORK=1 \
  SANDBOX_ALLOW_PATH=/tmp \
  ./program
```

**Hooked functions:**
- Network: `socket`, `connect`, `bind`
- Process: `fork`, `execve`, `execvp`
- Filesystem: `open`, `fopen`
- Anti-bypass: `unsetenv`, `putenv`, `setenv` (LD_PRELOAD)

**⚠️ Bypass methods (known):**
- Static linking
- Direct syscall via inline asm
- ctypes/FFI

## Full-Stack Comparison

### Defense Stack

**Full-Stack Userspace:**
```
seccomp-bpf + Landlock + rlimits + language sandbox + source scanner + clean-env
```

**Full-Stack Lambda:**
```
VPC isolation + rlimits + language sandbox + LD_PRELOAD + source scanner + clean-env
```

### Full-Stack Attack Defense

| Attack | Full-Stack Userspace | Full-Stack Lambda | Bypass Difficulty |
|--------|:--------------------:|:-----------------:|:-----------------:|
| Network exfiltration | ✅ seccomp+lang | ✅ VPC+lang+preload | 🔴 Impossible |
| Reverse shell | ✅ seccomp+lang | ✅ VPC+lang+preload | 🔴 Impossible |
| Fork/subprocess | ✅ seccomp+lang | ✅ lang+preload | 🔴 Very Hard |
| Memory/CPU/Disk | ✅ rlimit | ✅ rlimit+Lambda | 🔴 Impossible |
| Read sensitive files | ✅ Landlock+lang | ✅ lang+preload | 🔴 Very Hard |
| Write outside /tmp | ✅ Landlock | ✅ Lambda rootfs | 🔴 Impossible |
| ptrace/debugging | ✅ seccomp | ✅ Firecracker | 🔴 Impossible |
| Direct syscall (asm) | ✅ seccomp | ⚠️ scanner only | 🟡 Hard |
| dlopen/FFI | ✅ seccomp+lang | ✅ lang+scanner | 🔴 Very Hard |
| Sandbox escape | ✅ seccomp | ⚠️ lang+scanner | 🟡 Hard |
| /proc info leak | ⚠️ partial | ⚠️ partial | 🟢 Medium |
| VPC lateral movement | N/A | ✅ VPC isolation | 🔴 Impossible |
| Kernel 0-day | ⚠️ | ⚠️ | 🔴 Requires 0-day |

### Security Levels

| Configuration | Security | Use Case |
|---------------|:--------:|----------|
| Full-Stack Userspace | 🟢🟢🟢 | Maximum security, any untrusted code |
| Full-Stack Lambda | 🟢🟢 | Production student code execution |
| Lambda + Language sandbox | 🟡 | Basic protection |
| Lambda only | 🟠 | Not recommended for untrusted code |

### Remaining Attack Surface

| Environment | Remaining Risks |
|-------------|-----------------|
| Userspace | Kernel 0-day, timing side-channels |
| Lambda | Inline asm bypass, kernel 0-day, sandbox escape tricks |

## Lambda Configuration

### Recommended Setup

```yaml
functions:
  sandbox:
    runtime: python3.12
    timeout: 30
    memorySize: 256
    vpc:
      securityGroupIds:
        - sg-deny-all-egress
      subnetIds:
        - subnet-private
    role: arn:aws:iam::xxx:role/minimal-lambda-role
```

### Minimal IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
    "Resource": "arn:aws:logs:*:*:*"
  }]
}
```

### Lambda Built-in Protections

| Protection | Description |
|------------|-------------|
| ✅ Read-only rootfs | Cannot write to /var/task, /opt |
| ✅ Firecracker seccomp | Blocks ptrace, mount, reboot, etc. |
| ✅ Memory limit | 128MB-10GB per function |
| ✅ Timeout | Max 15 minutes |
| ✅ /tmp limit | 512MB ephemeral |
| ❌ Network | Full outbound by default |
| ❌ File read | Can read /etc/passwd, /proc |
| ❌ Subprocess | Can spawn processes |

## Performance Overhead

| Configuration | Python | C/Go | Notes |
|---------------|:------:|:----:|-------|
| Baseline (no sandbox) | 5ms | 0ms | - |
| Sandlock minimal | 6ms | 0ms | +1ms |
| Sandlock full | 5ms | 0ms | ~0ms |
| Sandlock strict | 6ms | 1ms | +1ms |
| Python sandbox only | 13ms | N/A | +8ms |
| Sandlock + Python sandbox | 14ms | N/A | +9ms |
| Node.js sandbox | 15ms | N/A | +10ms |
| LD_PRELOAD | 1ms | 1ms | +1ms |

## Build

```bash
# Dependencies
apt install libseccomp-dev  # Debian/Ubuntu
yum install libseccomp-devel  # RHEL/Amazon Linux

# Build
make

# Install
sudo make install
```

## File Structure

```
sandlock/
├── src/
│   ├── sandlock.h      # Common definitions
│   ├── main.c          # Entry point, CLI
│   ├── globals.c       # Global state
│   ├── config.c        # Validation
│   ├── strict.c        # Seccomp notify
│   ├── seccomp.c       # BPF filtering
│   ├── landlock.c      # FS sandbox
│   ├── rlimits.c       # Resource limits
│   ├── pipes.c         # I/O handling
│   └── isolation.c     # /tmp management
├── lang/
│   ├── python/
│   │   └── sandbox.py      # Python sandbox
│   ├── javascript/
│   │   ├── sandbox.js      # VM isolation
│   │   └── wrapper.js      # Runtime wrapper
│   ├── scanner/
│   │   └── scanner.py      # Source code scanner
│   └── preload/
│       ├── sandbox_preload.c   # LD_PRELOAD hook
│       └── Makefile
├── tests/
│   ├── framework.sh        # Test framework
│   ├── attacks/            # Attack test cases
│   │   ├── python/         # 21 tests
│   │   ├── javascript/     # 12 tests
│   │   ├── shell/          # 10 tests
│   │   └── c/              # 5 tests
│   └── results/            # Test reports
├── Makefile
├── README.md
├── README_zh.md
├── README_ja.md
├── TECHNICAL.md
└── .github/workflows/
    ├── ci.yml
    └── security-tests.yml
```

## Version History

| Version | Changes |
|---------|---------|
| 1.0.0 | Initial: seccomp, rlimits, basic options |
| 1.1.0 | Landlock, pipe-io, max-output |
| 1.2.0 | --isolate-tmp, --cleanup-tmp |
| 1.3.0 | Log levels (-v/-q) |
| 1.4.0 | Strict mode, config validation |
| 1.5.0 | Python sandbox, JavaScript sandbox, source scanner, LD_PRELOAD hook |

## Code Statistics

| Component | Lines |
|-----------|------:|
| src/*.c + src/*.h | ~1,500 |
| lang/python/sandbox.py | ~320 |
| lang/javascript/sandbox.js | ~350 |
| lang/javascript/wrapper.js | ~320 |
| lang/scanner/scanner.py | ~450 |
| lang/preload/sandbox_preload.c | ~250 |
| tests/framework.sh | ~500 |
| Attack test cases | 48 files |
| Documentation | ~1,000 |
| **Total** | **~4,700** |

---

*Last updated: 2026-03-09*
