#pragma once

#include "shared_memory.h"
#include "cache/helper_thread.h"
#include "cache/cache.h"

#include <stdint.h>
#include <pthread.h>

#define NUM_PAGE_SLOTS (PAGE_SIZE / CL_SIZE)

extern const uint32_t l2_repeat, array_repeat;
extern const double bad_threshold_ratio;

typedef struct PS_attacker_thread_config_t {
    const char *test_name;
    const char *label;
    int slot;
    int pin_cpu;
    int cache_line_count;
    int profile_samples;
    uint64_t max_exec_cycles;
    int victim_runs;
    pthread_barrier_t *threads_barrier;
    uint64_t **sample_tsc;
    uint64_t **probe_time;
    uint8_t *target;
    EVSet *evset;
    evchain *chain;
    uint8_t *scope;
} PS_attacker_thread_config_t;

void PS_profile_once(EVSet *evset,
                     int slot,
                     uint64_t profile_samples,
                     uint64_t max_exec_cycles,
                     uint64_t **sample_tsc,
                     uint64_t **probe_time);

void *PS_attacker_thread(void *args);

int LLCF_multi_evset(u32 n_offset, helper_thread_ctrl *hctrl);

void dump_profiling_trace(const char *dump_prefix,
                          int dump_id,
                          uint64_t **sample_tsc,
                          uint64_t **reload_time,
                          int cl_cnt,
                          int sp_cnt);

void dump_profiling_traces(const char *dump_prefix,
                           int victim_runs,
                           uint64_t **sample_tsc,
                           uint64_t **reload_time,
                           int cl_cnt,
                           int sp_cnt,
                           int reset);


// LLCFeasible
EVSet*** build_l2_evsets_all(void);
EVCands ***build_evcands_all(EVBuildConfig *conf, EVSet ***l2evsets);
EVSet* get_sf_kth_evset(int k);
EVSet* prepare_evsets(u8* target, helper_thread_ctrl* hctrl);
