/*
 * main.c - Entry point and command-line parsing
 */

#include "sandlock.h"

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
// Help and Features
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
        "Logging:\n"
        "  -v, --verbose      Increase verbosity (can repeat: -vv)\n"
        "  -q, --quiet        Decrease verbosity (can repeat: -qqq)\n"
        "\n"
        "Other:\n"
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

// ============================================================
// Main
// ============================================================

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
        {"quiet",           no_argument, 0, 'q'},
        {"features",        no_argument, 0, 'Z'},
        {"help",            no_argument, 0, 'h'},
        {"version",         no_argument, 0, 'V'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "+c:m:f:n:p:t:w:NFDdELR:W:IO:TCvqhV", long_options, NULL)) != -1) {
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
            case 'v': log_level++; break;
            case 'q': log_level--; if (log_level < 0) log_level = 0; break;
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
        record_execution_start();
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
            if (apply_landlock() != 0) {
                LOG_WARN("Landlock setup failed%s", "");
            }
        }
        
        if (apply_seccomp() != 0) {
            LOG_ERROR("seccomp setup failed%s", "");
            _exit(1);
        }
        
        if (config.clean_env) {
            sanitize_env();
        }
        
        LOG_DEBUG("executing %s", argv[optind]);
        
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
