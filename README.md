# Sandlock 🔒

Lightweight userspace sandbox for Linux. No root required.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- 🔒 **seccomp-bpf** syscall filtering (60+ dangerous syscalls blocked)
- 📊 **Resource limits** - CPU, memory, file size, open files
- 🌐 **Network isolation** - Block all socket operations
- 🧵 **Thread-safe** - Blocks fork while allowing threads
- ⚡ **Low overhead** - ~1.5ms startup cost
- 🔧 **Configurable** - Enable/disable each security feature
- 🚫 **No root required** - Pure userspace implementation

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
  --cpu SEC        CPU time limit in seconds
  --mem MB         Memory limit in megabytes
  --fsize MB       Max file size in megabytes
  --nofile N       Max open file descriptors
  --nproc N        Max processes (per-user)
  --timeout SEC    Wall-clock timeout

Security Features:
  --no-network     Block all network syscalls
  --no-fork        Block fork/clone (allow threads)
  --no-dangerous   Block dangerous syscalls (default: on)
  --allow-dangerous  Disable dangerous syscall blocking
  --clean-env      Sanitize environment variables
  --no-new-privs   Set NO_NEW_PRIVS (default: on)
  --allow-privs    Allow privilege escalation

Isolation:
  --isolate-tmp    Use private /tmp directory
  --workdir DIR    Set working directory

Other:
  -v, --verbose    Verbose output
  -h, --help       Show help
  --version        Show version
```

## Examples

### Run untrusted code

```bash
# Student code submission
sandlock --no-network --no-fork --clean-env \
         --cpu 5 --mem 256 --timeout 30 \
         -- python3 student_code.py
```

### Execute with minimal permissions

```bash
# Block everything except basic execution
sandlock --no-network --no-fork --clean-env --isolate-tmp \
         -- ./binary
```

### Allow specific operations

```bash
# Only block network
sandlock --no-network -- ./server

# Only block fork
sandlock --no-fork -- ./threaded_app
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
│  │         seccomp-bpf              │  │
│  │   (syscall filtering layer)      │  │
│  │                                  │  │
│  │  • 60+ syscalls blocked          │  │
│  │  • Network optionally blocked    │  │
│  │  • Fork optionally blocked       │  │
│  └──────────────────────────────────┘  │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │           rlimits                │  │
│  │   (resource limiting layer)      │  │
│  │                                  │  │
│  │  • CPU time                      │  │
│  │  • Memory (AS)                   │  │
│  │  • File size                     │  │
│  │  • Open files                    │  │
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
| Filesystem isolation | ⚠️ | ✅ | ✅ | ✅ |
| Resource limits | ✅ | ✅ | ✅ | ❌ |
| Syscall filtering | ✅ | ✅ | ✅ | ✅ |
| Complexity | Low | High | Medium | Medium |

## Known Limitations

- `/proc` is readable (Linux limitation without mount namespace)
- `RLIMIT_NPROC` is per-user, not per-sandbox
- Requires `libseccomp` on the system
- Linux only (uses seccomp-bpf)

## Testing

```bash
# Run test suite (requires Docker)
make test

# Or run directly on Linux
./test.sh
```

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please open an issue or PR.

## Related Projects

- [firejail](https://github.com/netblue30/firejail) - SUID sandbox
- [bubblewrap](https://github.com/containers/bubblewrap) - Unprivileged sandboxing
- [nsjail](https://github.com/google/nsjail) - Process isolation with namespaces

## CI Status

[![CI](https://github.com/bkmashiro/Sandlock/actions/workflows/ci.yml/badge.svg)](https://github.com/bkmashiro/Sandlock/actions/workflows/ci.yml)
[![Security Tests](https://github.com/bkmashiro/Sandlock/actions/workflows/security-tests.yml/badge.svg)](https://github.com/bkmashiro/Sandlock/actions/workflows/security-tests.yml)
