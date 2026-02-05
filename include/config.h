#pragma once

#include "cache.h"

#define CPU_CORE_NUM (16)

typedef struct config_t {
    cache_info_t l1d;
    cache_info_t l1i;
    cache_info_t l2;
    cache_info_t l3;

    int sets_per_slice;

    // Candidate buffer size in byte
    int buffer_size;

    // Number of cache lines in candidate buffer
    int buffer_cachelines;

    // Flags for mmap (HUGETLB)
    int mmap_flag;

    char* project_root;
} config_t;

config_t* get_config();

char* find_project_root();

void load_config(config_t* cfg);
