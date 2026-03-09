/*
 * sandlock.h - Common definitions and configuration
 */

#ifndef SANDLOCK_H
#define SANDLOCK_H

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

#define VERSION "1.3.0"

// ============================================================
// Logging
// ============================================================

enum LogLevel {
    LL_SILENT = 0,
    LL_ERROR  = 1,
    LL_WARN   = 2,
    LL_INFO   = 3,
    LL_DEBUG  = 4,
    LL_TRACE  = 5
};

extern int log_level;

#define LOG(level, fmt, ...) do { \
    if (log_level >= level) { \
        const char *prefix = ""; \
        switch(level) { \
            case LL_ERROR: prefix = "ERROR: "; break; \
            case LL_WARN:  prefix = "WARN: "; break; \
            case LL_DEBUG: prefix = "DEBUG: "; break; \
            case LL_TRACE: prefix = "TRACE: "; break; \
            default: break; \
        } \
        fprintf(stderr, "sandlock: %s" fmt "\n", prefix, ##__VA_ARGS__); \
    } \
} while(0)

#define LOG_ERROR(fmt, ...) LOG(LL_ERROR, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  LOG(LL_WARN, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  LOG(LL_INFO, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) LOG(LL_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...) LOG(LL_TRACE, fmt, ##__VA_ARGS__)

// ============================================================
// Feature Detection
// ============================================================

typedef struct {
    int kernel_major;
    int kernel_minor;
    int has_landlock;      // kernel >= 5.13
    int has_memfd_secret;  // kernel >= 5.14
} SystemFeatures;

extern SystemFeatures features;

void detect_features(void);

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
    char *landlock_ro_paths[32];
    char *landlock_rw_paths[32];
    int landlock_ro_count;
    int landlock_rw_count;
    
    // I/O control
    int pipe_io;
    unsigned long max_output;
    
    // Isolation
    int isolate_tmp;
    int cleanup_tmp;
    char *workdir;
    
    // Execution
    int timeout_seconds;
    
} SandlockConfig;

extern SandlockConfig config;
extern char isolated_tmp[PATH_MAX];
extern pid_t child_pid;

// ============================================================
// Module Functions
// ============================================================

// landlock.c
int apply_landlock(void);

// seccomp.c
int apply_seccomp(void);

// rlimits.c
void apply_rlimits(void);

// pipes.c
extern int stdin_pipe[2];
extern int stdout_pipe[2];
extern int stderr_pipe[2];

void setup_pipes(void);
void child_setup_pipes(void);
void parent_handle_pipes(void);

// isolation.c
void setup_isolated_tmp(void);
void cleanup_isolated_tmp(void);
void sanitize_env(void);
void record_execution_start(void);
void cleanup_tmp_dir(void);

#endif // SANDLOCK_H
