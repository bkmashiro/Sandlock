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

I/O Control:
  --pipe-io          Wrap I/O in pipes
  --max-output N     Limit output size in bytes

Isolation:
  --isolate-tmp      Use private /tmp directory
  --workdir DIR      Set working directory

Other:
  -v, --verbose      Verbose output
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

## Known Limitations

- `/proc` is readable (Linux limitation without mount namespace)
- `RLIMIT_NPROC` is per-user, not per-sandbox
- Requires `libseccomp` on the system
- Linux only (uses seccomp-bpf)
- Landlock requires kernel 5.13+ (graceful fallback on older kernels)

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
