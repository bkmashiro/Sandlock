# LD_PRELOAD Sandbox Library

CC ?= gcc
CFLAGS = -Wall -Wextra -O2 -fPIC
LDFLAGS = -shared -ldl

TARGET = sandbox_preload.so

.PHONY: all clean test

all: $(TARGET)

$(TARGET): sandbox_preload.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

test: $(TARGET)
	@echo "=== Test: Network blocking ==="
	LD_PRELOAD=./$(TARGET) SANDBOX_NO_NETWORK=1 python3 -c "import socket; socket.socket()" 2>&1 && echo "FAIL" || echo "PASS: blocked"
	@echo ""
	@echo "=== Test: Fork blocking ==="
	LD_PRELOAD=./$(TARGET) SANDBOX_NO_FORK=1 python3 -c "import os; os.fork()" 2>&1 && echo "FAIL" || echo "PASS: blocked"
	@echo ""
	@echo "=== Test: Path restriction ==="
	LD_PRELOAD=./$(TARGET) SANDBOX_ALLOW_PATH=/tmp python3 -c "open('/etc/passwd')" 2>&1 && echo "FAIL" || echo "PASS: blocked"
	@echo ""
	@echo "=== Test: Allowed path ==="
	LD_PRELOAD=./$(TARGET) SANDBOX_ALLOW_PATH=/tmp python3 -c "open('/tmp/test', 'w').write('ok')" 2>&1 && echo "PASS: allowed" || echo "FAIL"
