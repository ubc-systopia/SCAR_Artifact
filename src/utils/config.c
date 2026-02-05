#include "config.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "log.h"

static int config_init = 0;
config_t global_config;

char* find_project_root() {
    static char path[256] = "";
    if (path[0] == '\0') {
        if (getcwd(path, sizeof(path)) != NULL) {
            while (strcmp(path, "/") != 0) {
                struct stat sb;

                char filepath[256];
                snprintf(filepath, sizeof(filepath), "%s/.project", path);
                if (stat(filepath, &sb) == 0 && S_ISREG(sb.st_mode)) {
                    return path;
                }
                char* slash = strrchr(path, '/');

                if (slash == NULL) {
                    break;
                }
                *slash = '\0';
            }
        }
        log_warn("Cannot find project root, use / instead.");
        strcpy(path, "/");
    }
    return path;
}

config_t* get_config() {
    if (!config_init) {
        load_config(&global_config);
        global_config.project_root = find_project_root();
        log_info("Project root: %s", global_config.project_root);
        config_init = 1;
    }
    return &global_config;
}

void load_config(config_t* cfg) {
    cpuid_cache_info(&cfg->l1d, 0);
    cpuid_cache_info(&cfg->l1i, 1);
    cpuid_cache_info(&cfg->l2, 2);
    cpuid_cache_info(&cfg->l3, 3);
    cfg->sets_per_slice = cfg->l3.aux.info.sets / CPU_CORE_NUM;
    /* NOTE:
       Use twice the size of LLC to utilize the *uniformly distributed* hash function
       Ref: ‘Last-Level Cache Side-Channel Attacks are Practical’
         Hence, a buffer of twice the size of the LLC is large enough to construct
         the desired conflict set.
    */
    cfg->buffer_cachelines = cfg->l3.n_cacheline * 2;
    cfg->buffer_size = cfg->l3.size_b * 2;
    cfg->mmap_flag = MAP_HUGETLB;
}