/*
 * config.c - Configuration validation and conflict detection
 */

#include "sandlock.h"

int validate_config(void) {
    int errors = 0;
    
    // ========================================
    // Strict mode conflicts
    // ========================================
    
    if (config.strict_mode) {
        // Check kernel support
        if (!features.has_seccomp_notify) {
            LOG_ERROR("--strict requires kernel 5.0+ (current: %d.%d)",
                      features.kernel_major, features.kernel_minor);
            errors++;
        }
        
        // Strict mode requires allowed paths
        if (config.strict_path_count == 0) {
            LOG_ERROR("--strict requires at least one --allow PATH%s", "");
            errors++;
        }
        
        // Strict mode conflicts with pipe-io (parent must handle notify)
        if (config.pipe_io) {
            LOG_WARN("--strict with --pipe-io may cause deadlocks, disabling pipe-io%s", "");
            config.pipe_io = 0;
        }
        
        // Strict mode implies no-dangerous (we control syscalls differently)
        if (!config.block_dangerous) {
            LOG_DEBUG("--strict implies --no-dangerous%s", "");
            config.block_dangerous = 1;
        }
    }
    
    // ========================================
    // Landlock conflicts
    // ========================================
    
    if (config.use_landlock) {
        // Landlock + strict is redundant but allowed
        if (config.strict_mode) {
            LOG_WARN("--landlock with --strict is redundant%s", "");
        }
        
        // Landlock requires paths
        if (config.landlock_ro_count == 0 && config.landlock_rw_count == 0) {
            LOG_WARN("--landlock without --ro or --rw has no effect%s", "");
        }
    }
    
    // ========================================
    // /tmp isolation conflicts
    // ========================================
    
    if (config.isolate_tmp && config.cleanup_tmp) {
        LOG_WARN("--isolate-tmp with --cleanup-tmp is redundant%s", "");
    }
    
    // ========================================
    // Resource limit sanity
    // ========================================
    
    if (config.memory_mb > 0 && config.memory_mb < 8) {
        LOG_WARN("--mem %lu is very low, may cause immediate OOM", config.memory_mb);
    }
    
    if (config.cpu_seconds > 0 && config.timeout_seconds > 0 &&
        config.cpu_seconds > (unsigned long)config.timeout_seconds) {
        LOG_WARN("--cpu %lu > --timeout %d, timeout will trigger first",
                 config.cpu_seconds, config.timeout_seconds);
    }
    
    // ========================================
    // Workdir conflicts
    // ========================================
    
    if (config.workdir && config.isolate_tmp) {
        LOG_DEBUG("--workdir overrides --isolate-tmp directory%s", "");
    }
    
    return errors;
}
