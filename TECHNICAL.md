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
| VPC isolation | N/A | ✅ |

### Attack Defense by Environment

| Attack Category | Userspace | Lambda+Python | Lambda+Other |
|-----------------|:---------:|:-------------:|:------------:|
| **Network** |
| TCP/UDP/DNS | ✅ seccomp | ⚠️ import hook | ❌ VPC only |
| Reverse shell | ✅ seccomp | ⚠️ import hook | ❌ VPC only |
| **Process** |
| fork/clone | ✅ seccomp | ✅ import hook | ❌ undefended |
| subprocess | ✅ seccomp | ✅ import hook | ❌ undefended |
| exec | ✅ seccomp | ✅ import hook | ❌ undefended |
| **Filesystem** |
| Read sensitive files | ✅ Landlock/strict | ✅ restricted open | ❌ undefended |
| Write arbitrary | ✅ Landlock/strict | ✅ restricted open | ❌ undefended |
| Symlink/hardlink | ✅ seccomp | ✅ no os module | ❌ undefended |
| **Low-level** |
| ptrace | ✅ seccomp | ✅ no ctypes | ❌ undefended |
| Direct syscall | ✅ seccomp | ✅ no ctypes | ❌ undefended |
| mmap exploit | ✅ seccomp | ✅ no mmap | ❌ undefended |
| io_uring | ✅ seccomp | ✅ blocked | ❌ undefended |
| bpf | ✅ seccomp | ✅ blocked | ❌ undefended |
| **Resources** |
| CPU exhaustion | ✅ RLIMIT_CPU | ✅ RLIMIT_CPU | ✅ RLIMIT_CPU |
| Memory bomb | ✅ RLIMIT_AS | ✅ RLIMIT_AS | ✅ RLIMIT_AS |
| Disk filling | ✅ RLIMIT_FSIZE | ✅ RLIMIT_FSIZE | ✅ RLIMIT_FSIZE |
| Infinite loop | ✅ timeout | ✅ timeout | ✅ timeout |
| **Info leak** |
| Environment vars | ✅ clean-env | ✅ clean-env | ✅ clean-env |
| /proc | ⚠️ readable | ⚠️ readable | ⚠️ readable |

### Lambda Non-Python: Unmitigated Risks

When running non-Python code on Lambda without kernel-level sandboxing:

| Risk | Attack Vector | Impact | Mitigation |
|------|---------------|--------|------------|
| **Data Exfiltration** | `curl`, `wget`, raw sockets | Secrets leaked | VPC (no NAT) |
| **Reverse Shell** | `bash -i >& /dev/tcp/...` | Full control | VPC (no NAT) |
| **Credential Theft** | `cat /proc/self/environ` | AWS keys exposed | Minimal IAM role |
| **Lateral Movement** | Port scanning VPC | Attack other services | Security groups |
| **Cryptojacking** | Download & run miner | Resource abuse | VPC + short timeout |
| **Persistence** | Write to /tmp, /dev/shm | Survive between calls | Lambda cleans /tmp |

### Recommended Lambda Configuration

```yaml
# For untrusted code execution
functions:
  sandbox:
    runtime: python3.12
    timeout: 30
    memorySize: 256
    vpc:
      securityGroupIds:
        - sg-deny-all-egress  # No outbound traffic
      subnetIds:
        - subnet-private      # No NAT gateway
    role: arn:aws:iam::xxx:role/minimal-lambda-role
```

IAM Policy (minimal):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

### Performance Overhead

| Configuration | Python | C/Go | Notes |
|---------------|:------:|:----:|-------|
| Baseline (no sandbox) | 5ms | 0ms | - |
| Sandlock minimal | 6ms | 0ms | +1ms |
| Sandlock full | 5ms | 0ms | ~0ms |
| Sandlock strict | 6ms | 1ms | +1ms |
| Python sandbox only | 13ms | N/A | +8ms |
| Sandlock + Python sandbox | 14ms | N/A | +9ms |

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
│   ├── config.c        # Validation        [NEW]
│   ├── strict.c        # Seccomp notify    [NEW]
│   ├── seccomp.c       # BPF filtering
│   ├── landlock.c      # FS sandbox
│   ├── rlimits.c       # Resource limits
│   ├── pipes.c         # I/O handling
│   └── isolation.c     # /tmp management
├── Makefile
├── README.md
├── TECHNICAL.md                            [NEW]
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

---

*Last updated: 2026-03-09*
