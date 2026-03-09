/*
 * isolation.c - Filesystem isolation and cleanup
 */

#include "sandlock.h"

// ============================================================
// Isolated /tmp
// ============================================================

static int rm_callback(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)typeflag; (void)ftwbuf;
    return remove(path);
}

void cleanup_isolated_tmp(void) {
    if (isolated_tmp[0]) {
        nftw(isolated_tmp, rm_callback, 64, FTW_DEPTH | FTW_PHYS);
    }
}

void setup_isolated_tmp(void) {
    snprintf(isolated_tmp, sizeof(isolated_tmp), 
             "/tmp/sandlock_%d_%ld", getpid(), time(NULL));
    if (mkdir(isolated_tmp, 0700) == 0) {
        setenv("TMPDIR", isolated_tmp, 1);
    } else {
        isolated_tmp[0] = 0;
    }
}

void sanitize_env(void) {
    clearenv();
    setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
    setenv("HOME", isolated_tmp[0] ? isolated_tmp : "/tmp", 1);
    setenv("USER", "sandbox", 1);
    setenv("LANG", "C.UTF-8", 1);
}

// ============================================================
// /tmp Cleanup
// ============================================================

#define MAX_TMP_ENTRIES 4096
static char *initial_tmp_entries[MAX_TMP_ENTRIES];
static int initial_tmp_count = 0;

void record_execution_start(void) {
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

void cleanup_tmp_dir(void) {
    DIR *dir = opendir("/tmp");
    if (!dir) return;
    
    struct dirent *entry;
    char path[PATH_MAX];
    int cleaned = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        
        if (isolated_tmp[0] && strstr(entry->d_name, "sandlock_"))
            continue;
        
        if (was_initial_entry(entry->d_name))
            continue;
        
        snprintf(path, sizeof(path), "/tmp/%s", entry->d_name);
        
        struct stat st;
        if (lstat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                nftw(path, rm_callback, 64, FTW_DEPTH | FTW_PHYS);
            } else {
                unlink(path);
            }
            cleaned++;
        }
    }
    closedir(dir);
    
    // Free recorded entries
    for (int i = 0; i < initial_tmp_count; i++) {
        free(initial_tmp_entries[i]);
    }
    initial_tmp_count = 0;
    
    if (cleaned > 0) {
        LOG_DEBUG("cleaned %d items from /tmp", cleaned);
    }
}
