#pragma once

#include <strings.h>

#include "arch.h"

#define CACHE_LINE(op, __cl_off) ((void*)((uintptr_t)target_##op + __cl_off * CACHE_LINE_SIZE))

#define FLUSH_CACHE_LINE(op, __cl_off) clflush(CACHE_LINE(op, __cl_off))

#define RELOAD_CACHE_LINE(op, __cl_off, __slot) do {                \
    sample_tsc[index][__slot] = rdtscp();                           \
    uint64_t access_time = timed_access(CACHE_LINE(op, __cl_off));  \
    reload_time[index][__slot] = access_time;                       \
} while(0)

uint64_t FR_wait(uint64_t waiting_time);