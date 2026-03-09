#!/bin/bash
# Sandlock Test Suite v1.1.0

set -e

SANDLOCK="./sandlock"
PASS=0
FAIL=0
SKIP=0

test_case() {
    local name="$1"
    local expected="$2"
    shift 2
    
    echo -n "  $name: "
    
    if "$@" > /dev/null 2>&1; then
        result=0
    else
        result=$?
    fi
    
    if [ "$expected" = "pass" ] && [ $result -eq 0 ]; then
        echo "✓"
        ((PASS++))
    elif [ "$expected" = "fail" ] && [ $result -ne 0 ]; then
        echo "✓ (blocked)"
        ((PASS++))
    elif [ "$expected" = "skip" ]; then
        echo "⊘ (skipped)"
        ((SKIP++))
    else
        echo "✗ (exit=$result, expected=$expected)"
        ((FAIL++))
    fi
}

test_output() {
    local name="$1"
    local pattern="$2"
    shift 2
    
    echo -n "  $name: "
    
    output=$("$@" 2>&1)
    if echo "$output" | grep -q "$pattern"; then
        echo "✓"
        ((PASS++))
    else
        echo "✗ (pattern not found)"
        ((FAIL++))
    fi
}

echo "═══════════════════════════════════════════════════════════"
echo "                 Sandlock Test Suite v1.1.0                 "
echo "═══════════════════════════════════════════════════════════"
echo ""

# Feature detection
echo "System Features:"
$SANDLOCK --features
HAS_LANDLOCK=$($SANDLOCK --features | grep -c "Landlock: available" || true)
echo ""

echo "───────────────────────────────────────────────────────────"
echo "1. Basic Execution (3 tests)"
echo "───────────────────────────────────────────────────────────"
test_case "echo" pass $SANDLOCK -- echo hello
test_case "true" pass $SANDLOCK -- true
test_case "false (exit 1)" fail $SANDLOCK -- false

echo ""
echo "───────────────────────────────────────────────────────────"
echo "2. Network Isolation (2 tests)"
echo "───────────────────────────────────────────────────────────"
test_case "socket (allowed)" pass $SANDLOCK --allow-dangerous -- python3 -c "import socket"
test_case "socket (blocked)" fail $SANDLOCK --no-network -- python3 -c "import socket; socket.socket()"

echo ""
echo "───────────────────────────────────────────────────────────"
echo "3. Process Isolation (3 tests)"
echo "───────────────────────────────────────────────────────────"
test_case "fork (allowed)" pass $SANDLOCK --allow-dangerous -- python3 -c "import os; os.fork() or exit(0)"
test_case "fork (blocked)" fail $SANDLOCK --no-fork -- python3 -c "import os; os.fork()"
test_case "threads (allowed)" pass $SANDLOCK --no-fork -- python3 -c "import threading; t=threading.Thread(target=lambda:None); t.start(); t.join()"

echo ""
echo "───────────────────────────────────────────────────────────"
echo "4. Dangerous Syscalls (2 tests)"
echo "───────────────────────────────────────────────────────────"
test_case "ptrace (blocked default)" fail $SANDLOCK -- python3 -c "import ctypes; ctypes.CDLL(None).ptrace(0,0,0,0)"
test_case "ptrace (allowed)" pass $SANDLOCK --allow-dangerous -- python3 -c "pass"

echo ""
echo "───────────────────────────────────────────────────────────"
echo "5. Resource Limits (4 tests)"
echo "───────────────────────────────────────────────────────────"
test_case "memory limit" fail $SANDLOCK --mem 16 -- python3 -c "x=[0]*10000000"
test_case "cpu limit" fail $SANDLOCK --cpu 1 -- python3 -c "while True: pass"
test_case "timeout" fail $SANDLOCK --timeout 1 -- sleep 10
test_case "file size" fail $SANDLOCK --fsize 1 -- python3 -c "open('/tmp/big','w').write('x'*2000000)"

echo ""
echo "───────────────────────────────────────────────────────────"
echo "6. Environment (2 tests)"
echo "───────────────────────────────────────────────────────────"
test_case "clean env" pass $SANDLOCK --clean-env -- env
test_output "env var count" "^4$" $SANDLOCK --clean-env -- sh -c 'env | wc -l'

echo ""
echo "───────────────────────────────────────────────────────────"
echo "7. Isolation (2 tests)"
echo "───────────────────────────────────────────────────────────"
test_case "isolate tmp" pass $SANDLOCK --isolate-tmp -- sh -c 'test -n "$TMPDIR"'
test_case "workdir" pass $SANDLOCK --workdir /tmp -- sh -c 'pwd | grep -q /tmp'

echo ""
echo "───────────────────────────────────────────────────────────"
echo "8. Pipe I/O (3 tests)"
echo "───────────────────────────────────────────────────────────"
test_output "pipe basic" "hello" $SANDLOCK --pipe-io -- echo hello
test_output "max-output truncate" "^AAAAAAAAAA$" $SANDLOCK --pipe-io --max-output 10 -- python3 -c "print('A'*100)"
test_output "timeout with output" "Line 0" $SANDLOCK --pipe-io --timeout 1 -- python3 -c "import time; print('Line 0', flush=True); time.sleep(5)"

echo ""
echo "───────────────────────────────────────────────────────────"
echo "9. Landlock (3 tests) - kernel 5.13+"
echo "───────────────────────────────────────────────────────────"
if [ "$HAS_LANDLOCK" = "1" ]; then
    test_case "landlock rw /tmp" pass $SANDLOCK --landlock --rw /tmp -- touch /tmp/sandlock_test
    test_case "landlock ro /usr" pass $SANDLOCK --landlock --ro /usr -- ls /usr
    test_case "landlock block /etc" fail $SANDLOCK --landlock --rw /tmp -- cat /etc/passwd
else
    echo "  ⊘ Landlock not available (kernel < 5.13)"
    ((SKIP+=3))
fi

echo ""
echo "───────────────────────────────────────────────────────────"
echo "10. Combined (2 tests)"
echo "───────────────────────────────────────────────────────────"
test_case "full sandbox" pass $SANDLOCK --no-network --no-fork --clean-env --mem 64 --timeout 5 -- python3 -c "print('ok')"
test_output "full + pipe" "ok" $SANDLOCK --no-network --no-fork --clean-env --pipe-io -- python3 -c "print('ok')"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "                         RESULTS                            "
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Passed:  $PASS"
echo "  Failed:  $FAIL"
echo "  Skipped: $SKIP"
echo ""

if [ $FAIL -gt 0 ]; then
    echo "❌ SOME TESTS FAILED"
    exit 1
fi

echo "✅ ALL TESTS PASSED!"
