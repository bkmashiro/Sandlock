/*
 * globals.c - Global variables
 */

#include "sandlock.h"

int log_level = LL_INFO;

SystemFeatures features = {0};

SandlockConfig config = {
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
};

char isolated_tmp[PATH_MAX] = {0};
pid_t child_pid = 0;

int stdin_pipe[2] = {-1, -1};
int stdout_pipe[2] = {-1, -1};
int stderr_pipe[2] = {-1, -1};

void detect_features(void) {
    struct utsname u;
    if (uname(&u) == 0) {
        sscanf(u.release, "%d.%d", &features.kernel_major, &features.kernel_minor);
        
        features.has_landlock = (features.kernel_major > 5) || 
                                (features.kernel_major == 5 && features.kernel_minor >= 13);
        
        features.has_memfd_secret = (features.kernel_major > 5) || 
                                    (features.kernel_major == 5 && features.kernel_minor >= 14);
    }
}
