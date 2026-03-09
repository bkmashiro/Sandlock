# Sandlock Makefile

CC ?= gcc
CFLAGS = -O2 -Wall -Wextra -pedantic -std=c11
LDFLAGS = -lseccomp

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

TARGET = sandlock

.PHONY: all clean install uninstall test

all: $(TARGET)

$(TARGET): sandlock.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

# Run tests (requires Docker for Linux environment)
test:
	@echo "Running tests in Docker..."
	docker run --rm \
		--security-opt seccomp=unconfined \
		-v $(PWD):/app \
		-w /app \
		gcc:latest \
		sh -c 'apt-get update -qq && apt-get install -y -qq libseccomp-dev && make clean all && ./test.sh'
