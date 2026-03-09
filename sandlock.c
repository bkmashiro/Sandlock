/*
 * sandlock.c - Lightweight userspace sandbox for Linux
 * 
 * Features:
 *   - seccomp-bpf syscall filtering
 *   - Resource limits (rlimit)
 *   - Network/fork isolation
 *   - Landlock filesystem sandboxing (kernel 5.13+)
 *   - Pipe-wrapped I/O with limits
 *   - Environment sanitization
 * 
 * No root required. ~1.5ms overhead.
 * 
 * License: MIT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <signal.h>
#include <errno.h>
#include <seccomp.h>
#include <getopt.h>
#include <time.h>
#include <ftw.h>
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
#include <linux/landlock.h>
#include <sys/syscall.h>
#include <dirent.h>

#define VERSION "1.2.0"

// ============================================================
// Feature Detection
// ============================================================

typedef struct {
    int kernel_major;
    int kernel_minor;
    int has_landlock;      // kernel >= 5.13
    int has_memfd_secret;  // kernel >= 5.14
} SystemFeatures;

static SystemFeatures features = {0};

static void detect_features(void) {
    struct utsname u;
    if (uname(&u) == 0) {
        sscanf(u.release, "%d.%d", &features.kernel_major, &features.kernel_minor);
        
        // Landlock requires 5.13+
        features.has_landlock = (features.kernel_major > 5) || 
                                (features.kernel_major == 5 && features.kernel_minor >= 13);
        
        // memfd_secret requires 5.14+
        features.has_memfd_secret = (features.kernel_major > 5) || 
                                    (features.kernel_major == 5 && features.kernel_minor >= 14);
    }
}

// ============================================================
// Configuration
// ============================================================

typedef struct {
    // Resource limits
    unsigned long cpu_seconds;
    unsigned long memory_mb;
    unsigned long fsize_mb;
    unsigned long nofile;
    unsigned long nproc;
    
    // Security features
    int block_network;
    int block_fork;
    int block_dangerous;
    int clean_env;
    int no_new_privs;
    
    // Landlock
    int use_landlock;
    char *landlock_ro_paths[32];  // Read-only paths
    char *landlock_rw_paths[32];  // Read-write paths
    int landlock_ro_count;
    int landlock_rw_count;
    
    // I/O control
    int pipe_io;              // Wrap stdin/stdout in pipes
    unsigned long max_output; // Max output bytes (0 = unlimited)
    
    // Isolation
    int isolate_tmp;
    int cleanup_tmp;      // Clean /tmp after execution
    char *workdir;
    
    // Execution
    int timeout_seconds;
    int verbose;
    
} SandlockConfig;

static SandlockConfig config = {
    .cpu_seconds = 0,
    .memory_mb = 0,
    .fsize_mb = 0,
    .nofile = 0,
    .nproc = 0,
    
    .block_network = 0,
    .block_fork = 0,
    .block_dangerous = 1,
    .clean_env = 0,
    .no_new_privs = 1,
    
    .use_landlock = 0,
    .landlock_ro_count = 0,
    .landlock_rw_count = 0,
    
    .pipe_io = 0,
    .max_output = 0,
    
    .isolate_tmp = 0,
    .cleanup_tmp = 0,
    .workdir = NULL,
    
    .timeout_seconds = 0,
    .verbose = 0,
};

static char isolated_tmp[PATH_MAX] = {0};
static pid_t child_pid = 0;

// Pipe file descriptors
static int stdin_pipe[2] = {-1, -1};
static int stdout_pipe[2] = {-1, -1};
static int stderr_pipe[2] = {-1, -1};

// ============================================================
// Landlock (kernel 5.13+)
// ============================================================

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

static int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, uint32_t flags) {
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static int landlock_add_rule(int ruleset_fd, enum landlock_rule_type type, const void *attr, uint32_t flags) {
    return syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}

static int landlock_restrict_self(int ruleset_fd, uint32_t flags) {
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

static int apply_landlock(void) {
    if (!features.has_landlock) {
        if (config.verbose) {
            fprintf(stderr, "sandlock: Landlock not available (kernel %d.%d < 5.13)\n",
                    features.kernel_major, features.kernel_minor);
        }
        return 0;  // Not an error, just unavailable
    }
    
    // Check if Landlock is enabled in kernel
    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        if (config.verbose) {
            fprintf(stderr, "sandlock: Landlock disabled in kernel\n");
        }
        return 0;
    }
    
    // Define allowed filesystem operations
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = 
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_REMOVE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_REG |
            LANDLOCK_ACCESS_FS_MAKE_DIR |
            LANDLOCK_ACCESS_FS_EXECUTE
    };
    
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        if (config.verbose) {
            fprintf(stderr, "sandlock: landlock_create_ruleset failed: %s\n", strerror(errno));
        }
        return -1;
    }
    
    // Add read-write paths
    for (int i = 0; i < config.landlock_rw_count; i++) {
        int fd = open(config.landlock_rw_paths[i], O_PATH | O_CLOEXEC);
        if (fd < 0) continue;
        
        struct landlock_path_beneath_attr path_attr = {
            .allowed_access = 
                LANDLOCK_ACCESS_FS_READ_FILE |
                LANDLOCK_ACCESS_FS_READ_DIR |
                LANDLOCK_ACCESS_FS_WRITE_FILE |
                LANDLOCK_ACCESS_FS_REMOVE_FILE |
                LANDLOCK_ACCESS_FS_REMOVE_DIR |
                LANDLOCK_ACCESS_FS_MAKE_REG |
                LANDLOCK_ACCESS_FS_MAKE_DIR,
            .parent_fd = fd,
        };
        landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);
        close(fd);
    }
    
    // Add read-only paths
    for (int i = 0; i < config.landlock_ro_count; i++) {
        int fd = open(config.landlock_ro_paths[i], O_PATH | O_CLOEXEC);
        if (fd < 0) continue;
        
        struct landlock_path_beneath_attr path_attr = {
            .allowed_access = 
                LANDLOCK_ACCESS_FS_READ_FILE |
                LANDLOCK_ACCESS_FS_READ_DIR |
                LANDLOCK_ACCESS_FS_EXECUTE,
            .parent_fd = fd,
        };
        landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);
        close(fd);
    }
    
    // Apply restrictions
    if (landlock_restrict_self(ruleset_fd, 0) != 0) {
        if (config.verbose) {
            fprintf(stderr, "sandlock: landlock_restrict_self failed: %s\n", strerror(errno));
        }
        close(ruleset_fd);
        return -1;
    }
    
    close(ruleset_fd);
    
    if (config.verbose) {
        fprintf(stderr, "sandlock: Landlock enabled (ro=%d, rw=%d paths)\n",
                config.landlock_ro_count, config.landlock_rw_count);
    }
    
    return 0;
}

// ============================================================
// Resource Limits
// ============================================================

static void apply_rlimits(void) {
    struct rlimit rl;
    
    #define SET_RLIMIT(resource, value) do { \
        if ((value) > 0) { \
            rl.rlim_cur = rl.rlim_max = (value); \
            setrlimit((resource), &rl); \
        } \
    } while(0)
    
    SET_RLIMIT(RLIMIT_CPU, config.cpu_seconds);
    SET_RLIMIT(RLIMIT_AS, config.memory_mb * 1024 * 1024);
    SET_RLIMIT(RLIMIT_FSIZE, config.fsize_mb * 1024 * 1024);
    SET_RLIMIT(RLIMIT_NOFILE, config.nofile);
    SET_RLIMIT(RLIMIT_NPROC, config.nproc);
    
    rl.rlim_cur = rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);
    
    rl.rlim_cur = rl.rlim_max = 8 * 1024 * 1024;
    setrlimit(RLIMIT_STACK, &rl);
    
    #undef SET_RLIMIT
}

// ============================================================
// Seccomp
// ============================================================

static int apply_seccomp(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return -1;
    
    #define BLOCK(syscall) seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(syscall), 0)
    
    if (config.block_network) {
        BLOCK(socket); BLOCK(connect); BLOCK(bind); BLOCK(listen);
        BLOCK(accept); BLOCK(accept4); BLOCK(sendto); BLOCK(recvfrom);
        BLOCK(sendmsg); BLOCK(recvmsg); BLOCK(socketpair);
    }
    
    if (config.block_fork) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone),
            1, SCMP_A0(SCMP_CMP_MASKED_EQ, 0x10000, 0));
    }
    
    if (config.block_dangerous) {
        BLOCK(ptrace); BLOCK(process_vm_readv); BLOCK(process_vm_writev);
        BLOCK(userfaultfd); BLOCK(perf_event_open); BLOCK(bpf);
        BLOCK(io_uring_setup); BLOCK(io_uring_enter); BLOCK(io_uring_register);
        BLOCK(keyctl); BLOCK(add_key); BLOCK(request_key);
        BLOCK(unshare); BLOCK(setns);
        BLOCK(mount); BLOCK(umount2); BLOCK(chroot); BLOCK(pivot_root);
        BLOCK(symlink); BLOCK(symlinkat); BLOCK(link); BLOCK(linkat);
        BLOCK(reboot); BLOCK(kexec_load); BLOCK(kexec_file_load);
        BLOCK(init_module); BLOCK(finit_module); BLOCK(delete_module);
        BLOCK(acct); BLOCK(swapon); BLOCK(swapoff);
        BLOCK(sethostname); BLOCK(setdomainname);
        BLOCK(settimeofday); BLOCK(clock_settime); BLOCK(adjtimex);
        BLOCK(ioperm); BLOCK(iopl); BLOCK(modify_ldt);
        BLOCK(open_tree); BLOCK(move_mount); BLOCK(fsopen);
        BLOCK(fspick); BLOCK(fsconfig); BLOCK(fsmount);
        BLOCK(inotify_init); BLOCK(inotify_init1); BLOCK(inotify_add_watch);
        BLOCK(fanotify_init); BLOCK(fanotify_mark);
        BLOCK(personality); BLOCK(quotactl); BLOCK(nfsservctl);
        
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kill),
            1, SCMP_A0(SCMP_CMP_EQ, -1));
        BLOCK(tkill); BLOCK(tgkill);
    }
    
    #undef BLOCK
    
    int rc = seccomp_load(ctx);
    seccomp_release(ctx);
    return rc;
}

// ============================================================
// I/O Pipes
// ============================================================

static void setup_pipes(void) {
    pipe(stdin_pipe);
    pipe(stdout_pipe);
    pipe(stderr_pipe);
}

static void child_setup_pipes(void) {
    // Redirect stdin from pipe
    close(stdin_pipe[1]);
    dup2(stdin_pipe[0], STDIN_FILENO);
    close(stdin_pipe[0]);
    
    // Redirect stdout/stderr to pipes
    close(stdout_pipe[0]);
    dup2(stdout_pipe[1], STDOUT_FILENO);
    close(stdout_pipe[1]);
    
    close(stderr_pipe[0]);
    dup2(stderr_pipe[1], STDERR_FILENO);
    close(stderr_pipe[1]);
}

static void parent_handle_pipes(void) {
    close(stdin_pipe[0]);
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    
    // Forward stdin from parent
    // (For now, close stdin - could be enhanced to forward)
    close(stdin_pipe[1]);
    
    // Read output with limit
    unsigned long total_out = 0;
    unsigned long total_err = 0;
    char buf[4096];
    
    struct pollfd fds[2];
    fds[0].fd = stdout_pipe[0];
    fds[0].events = POLLIN;
    fds[1].fd = stderr_pipe[0];
    fds[1].events = POLLIN;
    
    while (fds[0].fd >= 0 || fds[1].fd >= 0) {
        int ret = poll(fds, 2, 100);
        if (ret <= 0) {
            // Check if child exited
            int status;
            if (waitpid(child_pid, &status, WNOHANG) > 0) break;
            continue;
        }
        
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(stdout_pipe[0], buf, sizeof(buf));
            if (n > 0) {
                if (config.max_output == 0 || total_out < config.max_output) {
                    ssize_t to_write = n;
                    if (config.max_output > 0 && total_out + n > config.max_output) {
                        to_write = config.max_output - total_out;
                    }
                    write(STDOUT_FILENO, buf, to_write);
                    total_out += n;
                }
            }
        }
        if (fds[0].revents & (POLLHUP | POLLERR)) {
            close(stdout_pipe[0]);
            fds[0].fd = -1;
        }
        
        if (fds[1].revents & POLLIN) {
            ssize_t n = read(stderr_pipe[0], buf, sizeof(buf));
            if (n > 0) {
                if (config.max_output == 0 || total_err < config.max_output) {
                    ssize_t to_write = n;
                    if (config.max_output > 0 && total_err + n > config.max_output) {
                        to_write = config.max_output - total_err;
                    }
                    write(STDERR_FILENO, buf, to_write);
                    total_err += n;
                }
            }
        }
        if (fds[1].revents & (POLLHUP | POLLERR)) {
            close(stderr_pipe[0]);
            fds[1].fd = -1;
        }
    }
    
    if (fds[0].fd >= 0) close(stdout_pipe[0]);
    if (fds[1].fd >= 0) close(stderr_pipe[0]);
}

// ============================================================
// Isolation
// ============================================================

static int rm_callback(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)typeflag; (void)ftwbuf;
    return remove(path);
}

static void cleanup_isolated_tmp(void) {
    if (isolated_tmp[0]) {
        nftw(isolated_tmp, rm_callback, 64, FTW_DEPTH | FTW_PHYS);
    }
}

// ============================================================
// /tmp Cleanup (for Lambda-like environments)
// ============================================================

#define MAX_TMP_ENTRIES 4096
static char *initial_tmp_entries[MAX_TMP_ENTRIES];
static int initial_tmp_count = 0;

static void record_tmp_entries(void) {
    DIR *dir = opendir("/tmp");
    if (!dir) return;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && initial_tmp_count < MAX_TMP_ENTRIES) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        initial_tmp_entries[initial_tmp_count++] = strdup(entry->d_name);
    }
    closedir(dir);
}

static int was_initial_entry(const char *name) {
    for (int i = 0; i < initial_tmp_count; i++) {
        if (strcmp(initial_tmp_entries[i], name) == 0)
            return 1;
    }
    return 0;
}

static void cleanup_tmp_dir(void) {
    DIR *dir = opendir("/tmp");
    if (!dir) return;
    
    struct dirent *entry;
    char path[PATH_MAX];
    
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        
        // Skip entries that existed before execution
        if (was_initial_entry(entry->d_name))
            continue;
        
        // Skip our own isolated_tmp (handled separately)
        if (isolated_tmp[0] && strstr(entry->d_name, "sandlock_"))
            continue;
        
        snprintf(path, sizeof(path), "/tmp/%s", entry->d_name);
        
        struct stat st;
        if (lstat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                // Remove directory recursively
                nftw(path, rm_callback, 64, FTW_DEPTH | FTW_PHYS);
            } else {
                unlink(path);
            }
        }
    }
    closedir(dir);
    
    // Free recorded entries
    for (int i = 0; i < initial_tmp_count; i++) {
        free(initial_tmp_entries[i]);
    }
    initial_tmp_count = 0;
}

static void setup_isolated_tmp(void) {
    snprintf(isolated_tmp, sizeof(isolated_tmp), 
             "/tmp/sandlock_%d_%ld", getpid(), time(NULL));
    if (mkdir(isolated_tmp, 0700) == 0) {
        setenv("TMPDIR", isolated_tmp, 1);
    } else {
        isolated_tmp[0] = 0;
    }
}

static void sanitize_env(void) {
    clearenv();
    setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
    setenv("HOME", isolated_tmp[0] ? isolated_tmp : "/tmp", 1);
    setenv("USER", "sandbox", 1);
    setenv("LANG", "C.UTF-8", 1);
}

// ============================================================
// Signal Handlers
// ============================================================

static void timeout_handler(int sig) {
    (void)sig;
    if (child_pid > 0) kill(-child_pid, SIGKILL);
}

static void cleanup_handler(int sig) {
    cleanup_isolated_tmp();
    _exit(128 + sig);
}

// ============================================================
// Main
// ============================================================

static void print_usage(const char *prog) {
    fprintf(stderr, 
        "sandlock v" VERSION " - Lightweight userspace sandbox\n"
        "\n"
        "Usage: %s [OPTIONS] -- COMMAND [ARGS...]\n"
        "\n"
        "Resource Limits:\n"
        "  --cpu SEC          CPU time limit\n"
        "  --mem MB           Memory limit\n"
        "  --fsize MB         Max file size\n"
        "  --nofile N         Max open files\n"
        "  --nproc N          Max processes\n"
        "  --timeout SEC      Wall-clock timeout\n"
        "\n"
        "Security:\n"
        "  --no-network       Block network syscalls\n"
        "  --no-fork          Block fork (allow threads)\n"
        "  --no-dangerous     Block dangerous syscalls (default)\n"
        "  --allow-dangerous  Allow dangerous syscalls\n"
        "  --clean-env        Sanitize environment\n"
        "\n"
        "Landlock (kernel 5.13+):\n"
        "  --landlock         Enable Landlock filesystem sandbox\n"
        "  --ro PATH          Add read-only path (repeatable)\n"
        "  --rw PATH          Add read-write path (repeatable)\n"
        "\n"
        "I/O Control:\n"
        "  --pipe-io          Wrap I/O in pipes\n"
        "  --max-output BYTES Limit output size\n"
        "\n"
        "Isolation:\n"
        "  --isolate-tmp      Private /tmp directory\n"
        "  --cleanup-tmp      Clean /tmp after execution\n"
        "  --workdir DIR      Set working directory\n"
        "\n"
        "Other:\n"
        "  -v, --verbose      Verbose output\n"
        "  --features         Show available features\n"
        "  -h, --help         Show help\n"
        "  --version          Show version\n"
        "\n",
        prog
    );
}

static void print_features(void) {
    detect_features();
    printf("Kernel: %d.%d\n", features.kernel_major, features.kernel_minor);
    printf("Landlock: %s\n", features.has_landlock ? "available" : "not available (need 5.13+)");
    printf("memfd_secret: %s\n", features.has_memfd_secret ? "available" : "not available (need 5.14+)");
}

int main(int argc, char *argv[]) {
    detect_features();
    
    static struct option long_options[] = {
        {"cpu",             required_argument, 0, 'c'},
        {"mem",             required_argument, 0, 'm'},
        {"fsize",           required_argument, 0, 'f'},
        {"nofile",          required_argument, 0, 'n'},
        {"nproc",           required_argument, 0, 'p'},
        {"timeout",         required_argument, 0, 't'},
        {"workdir",         required_argument, 0, 'w'},
        {"no-network",      no_argument, 0, 'N'},
        {"no-fork",         no_argument, 0, 'F'},
        {"no-dangerous",    no_argument, 0, 'D'},
        {"allow-dangerous", no_argument, 0, 'd'},
        {"clean-env",       no_argument, 0, 'E'},
        {"landlock",        no_argument, 0, 'L'},
        {"ro",              required_argument, 0, 'R'},
        {"rw",              required_argument, 0, 'W'},
        {"pipe-io",         no_argument, 0, 'I'},
        {"max-output",      required_argument, 0, 'O'},
        {"isolate-tmp",     no_argument, 0, 'T'},
        {"cleanup-tmp",     no_argument, 0, 'C'},
        {"verbose",         no_argument, 0, 'v'},
        {"features",        no_argument, 0, 'Z'},
        {"help",            no_argument, 0, 'h'},
        {"version",         no_argument, 0, 'V'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "+c:m:f:n:p:t:w:NFDdELR:W:IO:TvhV", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c': config.cpu_seconds = atol(optarg); break;
            case 'm': config.memory_mb = atol(optarg); break;
            case 'f': config.fsize_mb = atol(optarg); break;
            case 'n': config.nofile = atol(optarg); break;
            case 'p': config.nproc = atol(optarg); break;
            case 't': config.timeout_seconds = atoi(optarg); break;
            case 'w': config.workdir = optarg; break;
            case 'N': config.block_network = 1; break;
            case 'F': config.block_fork = 1; break;
            case 'D': config.block_dangerous = 1; break;
            case 'd': config.block_dangerous = 0; break;
            case 'E': config.clean_env = 1; break;
            case 'L': config.use_landlock = 1; break;
            case 'R':
                if (config.landlock_ro_count < 32) {
                    config.landlock_ro_paths[config.landlock_ro_count++] = optarg;
                }
                break;
            case 'W':
                if (config.landlock_rw_count < 32) {
                    config.landlock_rw_paths[config.landlock_rw_count++] = optarg;
                }
                break;
            case 'I': config.pipe_io = 1; break;
            case 'O': config.max_output = atol(optarg); break;
            case 'T': config.isolate_tmp = 1; break;
            case 'C': config.cleanup_tmp = 1; break;
            case 'v': config.verbose = 1; break;
            case 'Z': print_features(); return 0;
            case 'V': printf("sandlock v" VERSION "\n"); return 0;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }
    
    if (optind >= argc) {
        fprintf(stderr, "sandlock: no command specified\n");
        return 1;
    }
    
    signal(SIGALRM, timeout_handler);
    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);
    
    if (config.isolate_tmp) {
        setup_isolated_tmp();
        atexit(cleanup_isolated_tmp);
    }
    
    if (config.cleanup_tmp) {
        record_tmp_entries();
    }
    
    if (config.pipe_io) {
        setup_pipes();
    }
    
    if (config.timeout_seconds > 0) {
        alarm(config.timeout_seconds);
    }
    
    pid_t pid = fork();
    if (pid < 0) {
        perror("sandlock: fork");
        return 1;
    }
    
    if (pid == 0) {
        // Child
        setsid();
        setpgid(0, 0);
        
        if (config.pipe_io) {
            child_setup_pipes();
        }
        
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
        
        if (config.use_landlock) {
            if (apply_landlock() != 0 && config.verbose) {
                fprintf(stderr, "sandlock: Landlock setup failed\n");
            }
        }
        
        if (apply_seccomp() != 0) {
            fprintf(stderr, "sandlock: seccomp setup failed\n");
            _exit(1);
        }
        
        if (config.clean_env) {
            sanitize_env();
        }
        
        if (config.verbose) {
            fprintf(stderr, "sandlock: executing %s\n", argv[optind]);
        }
        
        execvp(argv[optind], &argv[optind]);
        perror("sandlock: exec");
        _exit(127);
    }
    
    // Parent
    child_pid = pid;
    
    if (config.pipe_io) {
        parent_handle_pipes();
    }
    
    int status;
    waitpid(pid, &status, 0);
    alarm(0);
    cleanup_isolated_tmp();
    
    if (config.cleanup_tmp) {
        cleanup_tmp_dir();
        if (config.verbose) {
            fprintf(stderr, "sandlock: cleaned /tmp\n");
        }
    }
    
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGKILL && config.timeout_seconds > 0) {
            fprintf(stderr, "sandlock: timeout\n");
            return 124;
        }
        fprintf(stderr, "sandlock: killed by signal %d\n", sig);
        return 128 + sig;
    }
    
    return 1;
}
