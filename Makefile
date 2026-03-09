# Sandlock Makefile

CC ?= gcc
CFLAGS = -O2 -Wall -Wextra -pedantic -std=c11
LDFLAGS = -lseccomp

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

TARGET = sandlock
SRCDIR = src
SRCS = $(SRCDIR)/main.c \
       $(SRCDIR)/globals.c \
       $(SRCDIR)/landlock.c \
       $(SRCDIR)/seccomp.c \
       $(SRCDIR)/rlimits.c \
       $(SRCDIR)/pipes.c \
       $(SRCDIR)/isolation.c

OBJS = $(SRCS:.c=.o)

.PHONY: all clean install uninstall test single

all: $(TARGET)

# Multi-file build
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/sandlock.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Single-file build (for compatibility)
single: sandlock.c
	$(CC) $(CFLAGS) -o $(TARGET) $< $(LDFLAGS)

clean:
	rm -f $(TARGET) $(OBJS)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

# Run tests
test:
	@echo "Running tests in Docker..."
	docker run --rm \
		--security-opt seccomp=unconfined \
		-v $(PWD):/app \
		-w /app \
		gcc:latest \
		sh -c 'apt-get update -qq && apt-get install -y -qq libseccomp-dev && make clean all && ./test.sh'
