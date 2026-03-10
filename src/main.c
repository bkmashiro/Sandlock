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
        "Strict Mode (kernel 5.0+):\n"
        "  --strict           Enable path-level syscall filtering\n"
        "  --allow PATH       Allow access to path (repeatable, required with --strict)\n"
        "\n"
        "Logging:\n"
        "  -v, --verbose      Increase verbosity (can repeat: -vv)\n"
        "  -q, --quiet        Decrease verbosity (can repeat: -qqq)\n"
        "\n"
        "OJ / Judge:\n"
        "  --output-stats     Output JSON resource stats to stderr\n"
        "  --stdin-file PATH  Redirect stdin from file\n"
        "  --stdout-file PATH Redirect stdout to file\n"
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
    printf("seccomp notify: %s\n", features.has_seccomp_notify ? "available" : "not available (need 5.0+)");
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
        {"strict",          no_argument, 0, 'S'},
        {"allow",           required_argument, 0, 'A'},
        {"output-stats",    no_argument, 0, 'J'},
        {"stdin-file",      required_argument, 0, 'i'},
        {"stdout-file",     required_argument, 0, 'o'},
        {"verbose",         no_argument, 0, 'v'},
        {"quiet",           no_argument, 0, 'q'},
        {"features",        no_argument, 0, 'Z'},
        {"help",            no_argument, 0, 'h'},
        {"version",         no_argument, 0, 'V'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "+c:m:f:n:p:t:w:NFDdELR:W:IO:TCSA:Ji:o:vqhV", long_options, NULL)) != -1) {
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
            case 'S': config.strict_mode = 1; break;
            case 'A':
                if (config.strict_path_count < 32) {
                    config.strict_paths[config.strict_path_count++] = optarg;
                }
                break;
            case 'J': config.output_stats = 1; break;
            case 'i': config.stdin_file = optarg; break;
            case 'o': config.stdout_file = optarg; break;
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
    
    // Validate configuration
    if (validate_config() > 0) {
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
    
    // Use strict mode if requested (different execution path)
    if (config.strict_mode) {
        return run_strict_mode(argv, optind);
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

        // File-based I/O redirection (OJ mode)
        if (config.stdin_file) {
            int fd = open(config.stdin_file, O_RDONLY);
            if (fd < 0) {
                perror("sandlock: open stdin-file");
                _exit(1);
            }
            dup2(fd, STDIN_FILENO);
            close(fd);
        }
        if (config.stdout_file) {
            int fd = open(config.stdout_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("sandlock: open stdout-file");
                _exit(1);
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
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

    struct timeval wall_start, wall_end;
    gettimeofday(&wall_start, NULL);

    if (config.pipe_io) {
        parent_handle_pipes();
    }

    int status;
    struct rusage rusage;
    wait4(pid, &status, 0, &rusage);
    gettimeofday(&wall_end, NULL);
    alarm(0);
    cleanup_isolated_tmp();

    if (config.cleanup_tmp) {
        cleanup_tmp_dir();
    }

    int exit_code = 1;
    int term_signal = 0;

    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        term_signal = WTERMSIG(status);
        if (term_signal == SIGKILL && config.timeout_seconds > 0) {
            LOG_INFO("timeout%s", "");
            exit_code = 124;
        } else {
            LOG_INFO("killed by signal %d", term_signal);
            exit_code = 128 + term_signal;
        }
    }

    if (config.output_stats) {
        long time_ms = (rusage.ru_utime.tv_sec + rusage.ru_stime.tv_sec) * 1000
                     + (rusage.ru_utime.tv_usec + rusage.ru_stime.tv_usec) / 1000;
        long memory_kb = rusage.ru_maxrss;  // Already in KB on Linux
        long wall_ms = (wall_end.tv_sec - wall_start.tv_sec) * 1000
                     + (wall_end.tv_usec - wall_start.tv_usec) / 1000;
        fprintf(stderr,
            "{\"time_ms\":%ld,\"memory_kb\":%ld,\"wall_ms\":%ld,"
            "\"exit_code\":%d,\"signal\":%d}\n",
            time_ms, memory_kb, wall_ms, exit_code, term_signal);
    }

    return exit_code;
}
