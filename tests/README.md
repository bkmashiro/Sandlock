# Sandlock Test Framework

Comprehensive security testing and benchmarking for Sandlock.

## Quick Start

```bash
# Generate test cases (attack scripts)
./framework.sh --generate

# Run security tests
./framework.sh --run

# Run benchmarks
./framework.sh --benchmark

# Run both
./framework.sh --run --benchmark
```

## Test Categories

### Python Attacks (`attacks/python/`)

| Category | Tests | Description |
|----------|-------|-------------|
| **Network** | net_tcp, net_udp, net_http | Socket connections, HTTP requests |
| **Process** | proc_fork, proc_subprocess, proc_exec, proc_system | Process creation |
| **Filesystem** | fs_read_passwd, fs_write_etc, fs_symlink | File access |
| **Low-level** | low_ptrace, low_syscall, low_mmap | System-level attacks |
| **Resources** | res_cpu, res_memory, res_disk, res_forkbomb | Resource exhaustion |
| **Info leak** | info_env, info_proc | Information disclosure |
| **Valid** | valid_math, valid_json, valid_compute | Should succeed |

### Shell Attacks (`attacks/shell/`)

| Category | Tests | Description |
|----------|-------|-------------|
| **Network** | net_curl, net_wget, net_revshell | Network tools |
| **Process** | proc_forkbomb, proc_exec_python | Process attacks |
| **Filesystem** | fs_read_passwd, fs_write_etc, fs_symlink | File operations |
| **Valid** | valid_echo, valid_math | Should succeed |

### C Attacks (`attacks/c/`)

| Category | Tests | Description |
|----------|-------|-------------|
| **Network** | net_socket | Raw socket |
| **Process** | proc_fork | fork() |
| **Filesystem** | fs_read | fopen() |
| **Low-level** | low_ptrace | ptrace() |
| **Valid** | valid_compute | Math computation |

## Test Environments

### Userspace (Linux with seccomp)

```bash
./framework.sh --run --env userspace
```

Tests:
- Sandlock with seccomp-bpf
- Sandlock with Landlock (if available)
- Sandlock strict mode

### Lambda Simulation

```bash
./framework.sh --run --env lambda
```

Tests:
- Python sandbox only (no seccomp)
- Resource limits via rlimit

## Output

Results are saved to `tests/results/`:

```
results/
├── test_output.txt       # Test run log
├── benchmark_output.txt  # Benchmark results
└── report_YYYYMMDD.md    # Combined report
```

## Extending for Other Languages

### Adding JavaScript Tests

1. Create `attacks/javascript/` directory
2. Add test files:
   ```javascript
   // attacks/javascript/net_http.js
   const http = require('http');
   http.get('http://example.com', (res) => console.log('connected'));
   ```

3. Add runner function in `framework.sh`:
   ```bash
   run_javascript_sandbox_tests() {
       # ...
   }
   ```

4. Create `lang/javascript/sandbox.js` (TODO)

### Adding Java Tests

1. Create `attacks/java/` directory
2. Add test files:
   ```java
   // attacks/java/NetSocket.java
   import java.net.*;
   public class NetSocket {
       public static void main(String[] args) throws Exception {
           new Socket("example.com", 80);
       }
   }
   ```

3. Add runner function in `framework.sh`
4. Create `lang/java/Sandbox.java` (TODO)

## Expected Results Matrix

| Attack | Userspace | Lambda+Python | Lambda+Other |
|--------|:---------:|:-------------:|:------------:|
| net_tcp | ✅ blocked | ✅ blocked | ❌ |
| proc_fork | ✅ blocked | ✅ blocked | ❌ |
| fs_read_passwd | ⚠️ allowed* | ✅ blocked | ❌ |
| low_ptrace | ✅ blocked | ✅ blocked | ❌ |
| res_cpu | ✅ blocked | ✅ blocked | ✅ blocked |
| valid_* | ✅ works | ✅ works | ✅ works |

*Use `--landlock` or `--strict` to block filesystem access

## CI Integration

```yaml
# .github/workflows/security-tests.yml
- name: Run full test suite
  run: |
    ./tests/framework.sh --generate
    ./tests/framework.sh --run --benchmark
```
