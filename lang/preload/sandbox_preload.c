/*
 * sandbox_preload.c - LD_PRELOAD library for sandboxing
 * 
 * Provides basic syscall interception via libc hooking.
 * 
 * WARNING: This can be bypassed by:
 *   - Statically linked binaries
 *   - Direct syscall (e.g., via ctypes/FFI)
 *   - Clearing LD_PRELOAD
 *   - setuid binaries
 * 
 * Use as defense-in-depth, not primary protection.
 * 
 * Build:
 *   gcc -shared -fPIC -o sandbox_preload.so sandbox_preload.c -ldl
 * 
 * Usage:
 *   LD_PRELOAD=./sandbox_preload.so SANDBOX_NO_NETWORK=1 ./program
 * 
 * Environment variables:
 *   SANDBOX_NO_NETWORK=1    Block socket operations
 *   SANDBOX_NO_FORK=1       Block fork/clone
 *   SANDBOX_NO_EXEC=1       Block exec* calls
 *   SANDBOX_ALLOW_PATH=/tmp Block file access outside path
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdarg.h>

// Original function pointers
static int (*real_socket)(int, int, int) = NULL;
static int (*real_connect)(int, const struct sockaddr*, socklen_t) = NULL;
static int (*real_bind)(int, const struct sockaddr*, socklen_t) = NULL;
static pid_t (*real_fork)(void) = NULL;
static int (*real_execve)(const char*, char* const[], char* const[]) = NULL;
static int (*real_execvp)(const char*, char* const[]) = NULL;
static int (*real_open)(const char*, int, ...) = NULL;
static FILE* (*real_fopen)(const char*, const char*) = NULL;

// Configuration
static int block_network = 0;
static int block_fork = 0;
static int block_exec = 0;
static const char* allow_path = NULL;

// Initialize on load
__attribute__((constructor))
static void init(void) {
    // Load original functions
    real_socket = dlsym(RTLD_NEXT, "socket");
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_bind = dlsym(RTLD_NEXT, "bind");
    real_fork = dlsym(RTLD_NEXT, "fork");
    real_execve = dlsym(RTLD_NEXT, "execve");
    real_execvp = dlsym(RTLD_NEXT, "execvp");
    real_open = dlsym(RTLD_NEXT, "open");
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    
    // Read configuration from environment
    block_network = getenv("SANDBOX_NO_NETWORK") != NULL;
    block_fork = getenv("SANDBOX_NO_FORK") != NULL;
    block_exec = getenv("SANDBOX_NO_EXEC") != NULL;
    allow_path = getenv("SANDBOX_ALLOW_PATH");
    
    // Prevent clearing LD_PRELOAD
    // (Note: determined attacker can still bypass)
}

// ============================================================
// Network Hooks
// ============================================================

int socket(int domain, int type, int protocol) {
    if (block_network) {
        // Allow Unix sockets for local IPC
        if (domain != AF_UNIX && domain != AF_LOCAL) {
            errno = EPERM;
            return -1;
        }
    }
    return real_socket(domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (block_network) {
        // Check if it's a network socket (not Unix)
        if (addr->sa_family != AF_UNIX && addr->sa_family != AF_LOCAL) {
            errno = EPERM;
            return -1;
        }
    }
    return real_connect(sockfd, addr, addrlen);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (block_network) {
        if (addr->sa_family != AF_UNIX && addr->sa_family != AF_LOCAL) {
            errno = EPERM;
            return -1;
        }
    }
    return real_bind(sockfd, addr, addrlen);
}

// ============================================================
// Process Hooks
// ============================================================

pid_t fork(void) {
    if (block_fork) {
        errno = EPERM;
        return -1;
    }
    return real_fork();
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (block_exec) {
        errno = EPERM;
        return -1;
    }
    return real_execve(pathname, argv, envp);
}

int execvp(const char *file, char *const argv[]) {
    if (block_exec) {
        errno = EPERM;
        return -1;
    }
    return real_execvp(file, argv);
}

// ============================================================
// Filesystem Hooks
// ============================================================

static int path_allowed(const char *path) {
    if (!allow_path) return 1;  // No restriction
    
    // Always allow /tmp
    if (strncmp(path, "/tmp", 4) == 0) return 1;
    
    // Always allow common system paths (read)
    if (strncmp(path, "/lib", 4) == 0) return 1;
    if (strncmp(path, "/usr/lib", 8) == 0) return 1;
    if (strncmp(path, "/etc/ld", 7) == 0) return 1;
    if (strncmp(path, "/dev/null", 9) == 0) return 1;
    if (strncmp(path, "/dev/zero", 9) == 0) return 1;
    if (strncmp(path, "/dev/urandom", 12) == 0) return 1;
    if (strncmp(path, "/proc/self", 10) == 0) return 1;
    
    // Check allowed path
    size_t len = strlen(allow_path);
    if (strncmp(path, allow_path, len) == 0) {
        // Path starts with allowed prefix
        return 1;
    }
    
    return 0;
}

int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    
    if (!path_allowed(pathname)) {
        errno = EACCES;
        return -1;
    }
    
    return real_open(pathname, flags, mode);
}

FILE *fopen(const char *pathname, const char *mode) {
    if (!path_allowed(pathname)) {
        errno = EACCES;
        return NULL;
    }
    return real_fopen(pathname, mode);
}

// ============================================================
// Anti-Bypass (limited effectiveness)
// ============================================================

// Block unsetenv/putenv for LD_PRELOAD (weak protection)
int unsetenv(const char *name) {
    if (strcmp(name, "LD_PRELOAD") == 0) {
        errno = EPERM;
        return -1;
    }
    
    int (*real_unsetenv)(const char*) = dlsym(RTLD_NEXT, "unsetenv");
    return real_unsetenv(name);
}

int putenv(char *string) {
    if (strncmp(string, "LD_PRELOAD=", 11) == 0) {
        // Trying to clear LD_PRELOAD
        errno = EPERM;
        return -1;
    }
    
    int (*real_putenv)(char*) = dlsym(RTLD_NEXT, "putenv");
    return real_putenv(string);
}

int setenv(const char *name, const char *value, int overwrite) {
    if (strcmp(name, "LD_PRELOAD") == 0) {
        errno = EPERM;
        return -1;
    }
    
    int (*real_setenv)(const char*, const char*, int) = dlsym(RTLD_NEXT, "setenv");
    return real_setenv(name, value, overwrite);
}
