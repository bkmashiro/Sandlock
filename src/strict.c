/*
 * strict.c - Strict mode with seccomp notify for path-level control
 * 
 * Uses SECCOMP_FILTER_FLAG_NEW_LISTENER to intercept file access syscalls
 * and validate paths against an allowlist.
 */

#include "sandlock.h"
#include <stddef.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <pthread.h>
#include <sys/ioctl.h>

// Seccomp notify structures (may not be in older headers)
#ifndef SECCOMP_IOCTL_NOTIF_RECV
struct seccomp_notif {
    __u64 id;
    __u32 pid;
    __u32 flags;
    struct seccomp_data data;
};

struct seccomp_notif_resp {
    __u64 id;
    __s64 val;
    __s32 error;
    __u32 flags;
};

#define SECCOMP_IOCTL_NOTIF_RECV    _IOWR('!', 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND    _IOWR('!', 1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW('!', 2, __u64)
#endif

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

// Thread context for notify handler
typedef struct {
    int notify_fd;
    pid_t child_pid;
    volatile int *running;
} NotifyContext;

// Check if path is allowed
static int is_path_allowed(const char *path) {
    if (!path || path[0] == '\0') return 0;
    
    // Always allow certain system paths
    const char *always_allowed[] = {
        "/bin", "/sbin", "/usr/bin", "/usr/sbin",
        "/lib", "/lib64", "/usr/lib", "/usr/lib64",
        "/etc/ld.so", "/etc/localtime", "/etc/timezone", "/etc/passwd",
        "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/tty",
        "/proc/self/", "/proc/", "/sys/",
        NULL
    };
    
    for (int i = 0; always_allowed[i]; i++) {
        if (strncmp(path, always_allowed[i], strlen(always_allowed[i])) == 0) {
            return 1;
        }
    }
    
    // Check user-specified allowed paths
    for (int i = 0; i < config.strict_path_count; i++) {
        const char *allowed = config.strict_paths[i];
        size_t len = strlen(allowed);
        
        // Exact match or prefix match (for directories)
        if (strcmp(path, allowed) == 0) return 1;
        if (strncmp(path, allowed, len) == 0 && 
            (path[len] == '/' || path[len] == '\0')) {
            return 1;
        }
    }
    
    return 0;
}

// Read path from child process memory
static int read_child_path(pid_t pid, unsigned long addr, char *buf, size_t len) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/mem", pid);
    
    int fd = open(proc_path, O_RDONLY);
    if (fd < 0) return -1;
    
    if (lseek(fd, addr, SEEK_SET) < 0) {
        close(fd);
        return -1;
    }
    
    ssize_t n = read(fd, buf, len - 1);
    close(fd);
    
    if (n <= 0) return -1;
    buf[n] = '\0';
    
    // Ensure null-terminated
    char *end = memchr(buf, '\0', n);
    if (!end) buf[len - 1] = '\0';
    
    return 0;
}

// Notify handler thread
static void *notify_handler_thread(void *arg) {
    NotifyContext *ctx = (NotifyContext *)arg;
    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;
    
    // Allocate aligned structures
    req = calloc(1, sizeof(*req));
    resp = calloc(1, sizeof(*resp));
    if (!req || !resp) goto cleanup;
    
    while (*(ctx->running)) {
        memset(req, 0, sizeof(*req));
        
        if (ioctl(ctx->notify_fd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
            if (errno == EINTR) continue;
            break;  // Child exited or fd closed
        }
        
        // Default: allow (continue the syscall)
        resp->id = req->id;
        resp->error = 0;
        resp->val = 0;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        
        int syscall_nr = req->data.nr;
        char path[PATH_MAX] = {0};
        int blocked = 0;
        
        // Handle openat (most common)
        if (syscall_nr == __NR_openat) {
            unsigned long path_addr = req->data.args[1];
            
            if (read_child_path(req->pid, path_addr, path, sizeof(path)) == 0) {
                // Resolve relative paths (openat with AT_FDCWD)
                if (path[0] != '/' && (int)req->data.args[0] == AT_FDCWD) {
                    char cwd[PATH_MAX];
                    char resolved[PATH_MAX];
                    snprintf(cwd, sizeof(cwd), "/proc/%d/cwd", req->pid);
                    ssize_t len = readlink(cwd, resolved, sizeof(resolved) - 1);
                    if (len > 0) {
                        resolved[len] = '\0';
                        char full[PATH_MAX];
                        snprintf(full, sizeof(full), "%s/%s", resolved, path);
                        strncpy(path, full, sizeof(path) - 1);
                    }
                }
                
                if (!is_path_allowed(path)) {
                    LOG_DEBUG("BLOCKED: openat(%s)", path);
                    resp->error = -EACCES;
                    resp->val = -1;
                    blocked = 1;
                } else {
                    LOG_TRACE("ALLOWED: openat(%s)", path);
                }
            }
        }
        // Handle open (legacy)
        #ifdef __NR_open
        else if (syscall_nr == __NR_open) {
            unsigned long path_addr = req->data.args[0];
            
            if (read_child_path(req->pid, path_addr, path, sizeof(path)) == 0) {
                if (!is_path_allowed(path)) {
                    LOG_DEBUG("BLOCKED: open(%s)", path);
                    resp->error = -EACCES;
                    resp->val = -1;
                    blocked = 1;
                }
            }
        }
        #endif
        // Handle execve
        else if (syscall_nr == __NR_execve) {
            unsigned long path_addr = req->data.args[0];
            
            if (read_child_path(req->pid, path_addr, path, sizeof(path)) == 0) {
                if (!is_path_allowed(path)) {
                    LOG_DEBUG("BLOCKED: execve(%s)", path);
                    resp->error = -EACCES;
                    resp->val = -1;
                    blocked = 1;
                }
            }
        }
        
        // Validate notification is still valid
        if (ioctl(ctx->notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) < 0) {
            continue;  // Process died, skip response
        }
        
        // Send response
        if (ioctl(ctx->notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0) {
            if (errno == EINVAL && resp->flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE) {
                // CONTINUE not supported, try without
                LOG_TRACE("CONTINUE not supported, retrying%s", "");
                resp->flags = 0;
                if (ioctl(ctx->notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0) {
                    if (errno != ENOENT) {
                        LOG_WARN("notify send failed (retry): %s", strerror(errno));
                    }
                }
            } else if (errno != ENOENT) {
                LOG_WARN("notify send failed: %s", strerror(errno));
            }
        }
        
        (void)blocked;  // Suppress unused warning
    }
    
cleanup:
    free(req);
    free(resp);
    return NULL;
}

// Build seccomp filter for strict mode
static int setup_strict_seccomp(void) {
    // BPF filter that sends openat/open/execve to userspace notification
    // Other syscalls pass through to normal seccomp rules
    
    #if defined(__x86_64__)
    #define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
    #elif defined(__aarch64__)
    #define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64
    #else
    #error "Unsupported architecture"
    #endif
    
    struct sock_filter filter[] = {
        // Load architecture
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        // Check architecture
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SCMP_ACT_KILL),
        
        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        
        // Check for openat
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        
        #ifdef __NR_open
        // Check for open
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        #endif
        
        // Check for execve
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        
        // Allow everything else
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    
    // Install filter and get listener fd
    int fd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 
                     SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    
    return fd;
}

// Main strict mode execution
int run_strict_mode(char *argv[], int optind) {
    LOG_DEBUG("entering strict mode%s", "");
    
    // Set up seccomp with notify BEFORE fork
    // This way parent gets the listener fd
    
    // We need to fork first, then have child install filter
    // Parent receives fd via pidfd_getfd or unix socket
    // Actually, simpler: fork, child installs filter, sends fd to parent
    
    // Even simpler: use SECCOMP_FILTER_FLAG_TSYNC is not what we want
    // Let's try a different approach:
    // 1. Create socketpair
    // 2. Fork
    // 3. Child: install filter, send fd to parent, exec
    // 4. Parent: receive fd, run notify handler
    
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        LOG_ERROR("socketpair failed: %s", strerror(errno));
        return 1;
    }
    
    pid_t pid = fork();
    if (pid < 0) {
        LOG_ERROR("fork failed: %s", strerror(errno));
        return 1;
    }
    
    if (pid == 0) {
        // Child process
        close(sv[0]);
        
        setsid();
        setpgid(0, 0);
        
        if (config.workdir) {
            chdir(config.workdir);
        } else if (config.isolate_tmp && isolated_tmp[0]) {
            chdir(isolated_tmp);
        }
        
        if (config.no_new_privs) {
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        }
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        
        apply_rlimits();
        
        // Apply landlock if requested (before seccomp)
        if (config.use_landlock) {
            apply_landlock();
        }
        
        // Install strict seccomp filter
        int notify_fd = setup_strict_seccomp();
        if (notify_fd < 0) {
            LOG_ERROR("seccomp setup failed: %s", strerror(errno));
            _exit(1);
        }
        
        // Send notify_fd to parent
        struct msghdr msg = {0};
        struct cmsghdr *cmsg;
        char buf[CMSG_SPACE(sizeof(int))];
        struct iovec iov = { .iov_base = "x", .iov_len = 1 };
        
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = buf;
        msg.msg_controllen = sizeof(buf);
        
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &notify_fd, sizeof(int));
        
        if (sendmsg(sv[1], &msg, 0) < 0) {
            LOG_ERROR("sendmsg failed: %s", strerror(errno));
            _exit(1);
        }
        
        close(notify_fd);  // Child doesn't need it
        
        // Wait for parent to signal it's ready
        char ack;
        if (read(sv[1], &ack, 1) < 0) {
            LOG_ERROR("failed to receive ready signal%s", "");
            _exit(1);
        }
        close(sv[1]);
        
        if (config.clean_env) {
            sanitize_env();
        }
        
        LOG_DEBUG("executing %s", argv[optind]);
        
        execvp(argv[optind], &argv[optind]);
        perror("sandlock: exec");
        _exit(127);
    }
    
    // Parent process
    close(sv[1]);
    child_pid = pid;
    
    // Receive notify_fd from child
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))];
    char data[1];
    struct iovec iov = { .iov_base = data, .iov_len = 1 };
    
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    
    if (recvmsg(sv[0], &msg, 0) < 0) {
        LOG_ERROR("recvmsg failed: %s", strerror(errno));
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 1;
    }
    
    int notify_fd = -1;
    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
        memcpy(&notify_fd, CMSG_DATA(cmsg), sizeof(int));
    }
    
    if (notify_fd < 0) {
        LOG_ERROR("failed to receive notify fd%s", "");
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 1;
    }
    
    LOG_DEBUG("received notify_fd=%d", notify_fd);
    
    // Start notify handler thread
    volatile int running = 1;
    NotifyContext ctx = {
        .notify_fd = notify_fd,
        .child_pid = pid,
        .running = &running
    };
    
    pthread_t handler_thread;
    if (pthread_create(&handler_thread, NULL, notify_handler_thread, &ctx) != 0) {
        LOG_ERROR("pthread_create failed: %s", strerror(errno));
        close(notify_fd);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 1;
    }
    
    // Signal child that we're ready
    if (write(sv[0], "x", 1) < 0) {
        LOG_WARN("failed to send ready signal: %s", strerror(errno));
    }
    close(sv[0]);
    
    // Set timeout
    if (config.timeout_seconds > 0) {
        alarm(config.timeout_seconds);
    }
    
    // Wait for child
    int status;
    waitpid(pid, &status, 0);
    alarm(0);
    
    // Stop handler thread
    running = 0;
    close(notify_fd);
    pthread_join(handler_thread, NULL);
    
    // Cleanup
    cleanup_isolated_tmp();
    if (config.cleanup_tmp) {
        cleanup_tmp_dir();
    }
    
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGKILL && config.timeout_seconds > 0) {
            LOG_INFO("timeout%s", "");
            return 124;
        }
        LOG_INFO("killed by signal %d", sig);
        return 128 + sig;
    }
    
    return 1;
}
