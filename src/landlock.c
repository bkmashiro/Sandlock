/*
 * landlock.c - Landlock filesystem sandbox (kernel 5.13+)
 */

#include "sandlock.h"

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

int apply_landlock(void) {
    if (!features.has_landlock) {
        LOG_DEBUG("Landlock not available (kernel %d.%d < 5.13)",
                  features.kernel_major, features.kernel_minor);
        return 0;
    }
    
    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        LOG_DEBUG("Landlock disabled in kernel%s", "");
        return 0;
    }
    
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
        LOG_WARN("landlock_create_ruleset failed: %s", strerror(errno));
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
    
    if (landlock_restrict_self(ruleset_fd, 0) != 0) {
        LOG_WARN("landlock_restrict_self failed: %s", strerror(errno));
        close(ruleset_fd);
        return -1;
    }
    
    close(ruleset_fd);
    
    LOG_DEBUG("Landlock enabled (ro=%d, rw=%d paths)",
              config.landlock_ro_count, config.landlock_rw_count);
    
    return 0;
}
