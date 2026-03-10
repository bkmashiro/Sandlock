#!/bin/bash
# OJ Compatibility Test Suite for sandlock
# Tests --output-stats, --stdin-file, --stdout-file, timeout behavior

set -e

SANDLOCK="./sandlock"
PASS=0
FAIL=0
TMPDIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

# ============================================================
# Test 1: Compile and run a simple C program
# ============================================================
echo "=== Test 1: Basic C program execution ==="

cat > "$TMPDIR/hello.c" << 'CEOF'
#include <stdio.h>
int main() {
    printf("Hello, OJ!\n");
    return 0;
}
CEOF

gcc -o "$TMPDIR/hello" "$TMPDIR/hello.c"
OUTPUT=$($SANDLOCK -q -- "$TMPDIR/hello" 2>/dev/null)
if [ "$OUTPUT" = "Hello, OJ!" ]; then
    pass "Basic C program output correct"
else
    fail "Expected 'Hello, OJ!', got '$OUTPUT'"
fi

# ============================================================
# Test 2: --output-stats produces valid JSON
# ============================================================
echo "=== Test 2: --output-stats JSON output ==="

STATS=$($SANDLOCK -q --output-stats -- "$TMPDIR/hello" 2>&1 >/dev/null)
if echo "$STATS" | grep -q '"time_ms":'; then
    pass "--output-stats contains time_ms"
else
    fail "--output-stats missing time_ms: $STATS"
fi

if echo "$STATS" | grep -q '"memory_kb":'; then
    pass "--output-stats contains memory_kb"
else
    fail "--output-stats missing memory_kb: $STATS"
fi

if echo "$STATS" | grep -q '"exit_code":0'; then
    pass "--output-stats reports exit_code 0"
else
    fail "--output-stats wrong exit_code: $STATS"
fi

if echo "$STATS" | grep -q '"signal":0'; then
    pass "--output-stats reports signal 0"
else
    fail "--output-stats wrong signal: $STATS"
fi

if echo "$STATS" | grep -q '"wall_ms":'; then
    pass "--output-stats contains wall_ms"
else
    fail "--output-stats missing wall_ms: $STATS"
fi

# ============================================================
# Test 3: --stdin-file and --stdout-file
# ============================================================
echo "=== Test 3: --stdin-file / --stdout-file ==="

cat > "$TMPDIR/echo_input.c" << 'CEOF'
#include <stdio.h>
int main() {
    int a, b;
    scanf("%d %d", &a, &b);
    printf("%d\n", a + b);
    return 0;
}
CEOF

gcc -o "$TMPDIR/echo_input" "$TMPDIR/echo_input.c"
echo "3 5" > "$TMPDIR/input.txt"

$SANDLOCK -q --stdin-file "$TMPDIR/input.txt" --stdout-file "$TMPDIR/output.txt" \
    -- "$TMPDIR/echo_input" 2>/dev/null

OUTPUT=$(cat "$TMPDIR/output.txt")
if [ "$OUTPUT" = "8" ]; then
    pass "--stdin-file/--stdout-file A+B correct"
else
    fail "Expected '8', got '$OUTPUT'"
fi

# ============================================================
# Test 4: Timeout kills the process
# ============================================================
echo "=== Test 4: Timeout enforcement ==="

cat > "$TMPDIR/infinite.c" << 'CEOF'
int main() {
    while(1) {}
    return 0;
}
CEOF

gcc -o "$TMPDIR/infinite" "$TMPDIR/infinite.c"

set +e
$SANDLOCK -q --timeout 1 -- "$TMPDIR/infinite" 2>/dev/null
EXIT_CODE=$?
set -e

if [ "$EXIT_CODE" -eq 124 ]; then
    pass "Timeout returns exit code 124"
else
    fail "Expected exit code 124, got $EXIT_CODE"
fi

# ============================================================
# Test 5: Timeout + --output-stats reports signal
# ============================================================
echo "=== Test 5: Timeout with --output-stats ==="

set +e
STATS=$($SANDLOCK -q --timeout 1 --output-stats -- "$TMPDIR/infinite" 2>&1 >/dev/null)
set -e

if echo "$STATS" | grep -q '"signal":9'; then
    pass "--output-stats reports SIGKILL (9) on timeout"
else
    fail "--output-stats wrong signal on timeout: $STATS"
fi

if echo "$STATS" | grep -q '"exit_code":124'; then
    pass "--output-stats reports exit_code 124 on timeout"
else
    fail "--output-stats wrong exit_code on timeout: $STATS"
fi

# ============================================================
# Test 6: Memory limit enforcement
# ============================================================
echo "=== Test 6: Memory limit ==="

cat > "$TMPDIR/mem_hog.c" << 'CEOF'
#include <stdlib.h>
#include <string.h>
int main() {
    // Try to allocate 512MB
    char *p = malloc(512 * 1024 * 1024);
    if (!p) return 1;
    memset(p, 'A', 512 * 1024 * 1024);
    free(p);
    return 0;
}
CEOF

gcc -o "$TMPDIR/mem_hog" "$TMPDIR/mem_hog.c"

set +e
$SANDLOCK -q --mem 64 -- "$TMPDIR/mem_hog" 2>/dev/null
EXIT_CODE=$?
set -e

if [ "$EXIT_CODE" -ne 0 ]; then
    pass "Memory limit enforced (exit $EXIT_CODE)"
else
    fail "Memory limit not enforced (exit 0)"
fi

# ============================================================
# Test 7: Non-zero exit code propagation
# ============================================================
echo "=== Test 7: Exit code propagation ==="

cat > "$TMPDIR/exit42.c" << 'CEOF'
int main() { return 42; }
CEOF

gcc -o "$TMPDIR/exit42" "$TMPDIR/exit42.c"

set +e
STATS=$($SANDLOCK -q --output-stats -- "$TMPDIR/exit42" 2>&1 >/dev/null)
EXIT_CODE=$?
set -e

if [ "$EXIT_CODE" -eq 42 ]; then
    pass "Exit code 42 propagated"
else
    fail "Expected exit code 42, got $EXIT_CODE"
fi

if echo "$STATS" | grep -q '"exit_code":42'; then
    pass "--output-stats reports exit_code 42"
else
    fail "--output-stats wrong exit_code: $STATS"
fi

# ============================================================
# Test 8: --no-network blocks sockets
# ============================================================
echo "=== Test 8: Network blocking ==="

cat > "$TMPDIR/net_test.c" << 'CEOF'
#include <sys/socket.h>
#include <stdio.h>
int main() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("BLOCKED\n");
        return 0;
    }
    printf("ALLOWED\n");
    return 1;
}
CEOF

gcc -o "$TMPDIR/net_test" "$TMPDIR/net_test.c"

OUTPUT=$($SANDLOCK -q --no-network -- "$TMPDIR/net_test" 2>/dev/null)
if [ "$OUTPUT" = "BLOCKED" ]; then
    pass "--no-network blocks socket()"
else
    fail "Expected 'BLOCKED', got '$OUTPUT'"
fi

# ============================================================
# Test 9: raise() works (tkill/tgkill not blocked)
# ============================================================
echo "=== Test 9: raise()/abort() works (tkill/tgkill allowed) ==="

cat > "$TMPDIR/raise_test.c" << 'CEOF'
#include <signal.h>
#include <stdio.h>
int main() {
    // raise() uses tkill/tgkill internally
    printf("BEFORE\n");
    fflush(stdout);
    raise(SIGUSR1);
    // Should not reach here
    printf("AFTER\n");
    return 0;
}
CEOF

gcc -o "$TMPDIR/raise_test" "$TMPDIR/raise_test.c"

set +e
OUTPUT=$($SANDLOCK -q -- "$TMPDIR/raise_test" 2>/dev/null)
EXIT_CODE=$?
set -e

if [ "$OUTPUT" = "BEFORE" ] && [ "$EXIT_CODE" -ne 0 ]; then
    pass "raise() works, process terminated by signal"
else
    fail "raise() behavior unexpected: output='$OUTPUT' exit=$EXIT_CODE"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "==============================="
echo "Results: $PASS passed, $FAIL failed"
echo "==============================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
