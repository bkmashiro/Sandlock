/*
 * rlimits.c - Resource limits
 */

#include "sandlock.h"

void apply_rlimits(void) {
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
    
    // Always set these
    rl.rlim_cur = rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);  // No core dumps
    
    rl.rlim_cur = rl.rlim_max = 8 * 1024 * 1024;
    setrlimit(RLIMIT_STACK, &rl);  // 8MB stack
    
    #undef SET_RLIMIT
}
