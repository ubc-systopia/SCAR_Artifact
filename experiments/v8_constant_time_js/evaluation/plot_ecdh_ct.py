#!/usr/bin/env python3
"""Plot one v8_ctjs_ecdh trace, optionally with the victim's own per-bit
timestamps drawn underneath it.

    plot_ecdh_ct.py -i <capture>/r0.out                    # trace alone
    plot_ecdh_ct.py -i <capture>/r0.out --truth            # + ground truth
    plot_ecdh_ct.py -d <capture> --run 3 --truth --bits 40 # zoom on 40 bits
    plot_ecdh_ct.py -i <capture>/r0.out --rel              # x from ladder start
    plot_ecdh_ct.py -i <capture>/r0.out --psd_index 0      # + PSD for col0
    plot_ecdh_ct.py -i <capture>/r0.out --truth \
        --psd_index 0 --interval_index 0 --burst_index 0

x is the raw rdtscp of the capture unless --rel is given, so a timestamp read
off the plot is the same number the extractor and victim_bits.txt use.

The point of --truth is alignment. A capture taken with BITS=1 carries
`victim_bits.txt`, the victim's OWN (rdtscp, bit) pair per ladder iteration,
recorded on the same clock and in the same run as the attack samples next to
it. Drawn together, a decode's two failure modes become visible directly:
whether the slot boundaries land where the bits actually are, and whether the
marker line fires inside 0-bit slots and stays quiet inside 1-bit slots.

This is a separate script from LLCT's scripts/plot/plot_general.py, which it
borrows its conventions from (bokeh, palette, one row per cache line, hits as
scatter): that one plots any trace, this one knows about this experiment's
`channels` metadata and its ground-truth file.
"""

import argparse
import math
import os
import re
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bokeh.layouts import column  # noqa: E402
from bokeh.models import ColumnDataSource, HoverTool, Span  # noqa: E402
from bokeh.plotting import figure, output_file, save  # noqa: E402
from scipy.signal import find_peaks, welch  # noqa: E402

from utils import (PS_sample_interval, cpu_freq, lat_to_hit,  # noqa: E402
                   load_trace, palette)


PP_PSD_BIN_CYCLES = 1000
BURST_GAP_CYCLES = 10000
LADDER_BITS_MAX = 256


def load_channels(directory):
    """`channels` -> ([(role, handler, off)], primitive), or (None, None).

    Same file the extractor configures itself from, so a plot cannot disagree
    with a decode about which column is the marker and which is the clock.
    """
    path = os.path.join(directory, "channels")
    if not os.path.exists(path):
        return None, None
    rows, prim = [], "fr"
    for ln in open(path):
        if ln.startswith("#") or not ln.strip():
            continue
        f = ln.split()
        rows.append((f[1], f[2], f[3]))
        prim = f[4] if len(f) > 4 else prim
    return rows, prim


def _parse_truth_blocks(path):
    """victim_bits.txt -> [{"set", "col", "rows": [(ts, bit), ...]}, ...].

    Two on-disk layouts are read into the same shape:

    * Legacy: bare `<ts>,<bit>` lines, one profiled run's block after the next
      in run order, no separators. Parsed as a single anonymous block (set and
      col None) that the caller slices positionally.
    * CSI / labelled: each run's block is introduced by a comment header
      `# set <N> col <C> key <path>`, so a capture that runs several keys per
      evset candidate is self-describing. `set` is the r<set>.out the block
      belongs to and `col` which profiled key produced it.

    Comment lines and blank lines are skipped either way, so a header (or any
    `#` note) no longer derails the parse -- the previous `.read().split()`
    tokenised `# set 326 ...` into commaless words and raised on unpack.
    """
    blocks, cur = [], None
    for raw in open(path):
        ln = raw.strip()
        if not ln:
            continue
        if ln.startswith("#"):
            m = re.match(r"#\s*set\s+(\d+)\s+col\s+(\d+)", ln)
            cur = {"set": int(m.group(1)) if m else None,
                   "col": int(m.group(2)) if m else None, "rows": []}
            blocks.append(cur)
            continue
        parts = ln.split(",")
        if len(parts) < 2:
            continue                       # tolerate a stray/garbled line
        if cur is None:
            cur = {"set": None, "col": None, "rows": []}
            blocks.append(cur)
        cur["rows"].append((int(parts[0]), int(parts[1])))
    return [b for b in blocks if b["rows"]]


def load_truth(path, run, nruns, col=None):
    """victim_bits.txt -> (timestamps, bits) for the block(s) of ONE trace.

    Labelled (CSI) captures are matched by name: r<set>.out pairs with every
    block whose header says `set <run>`, in `col` order. When a set was
    profiled with several keys back to back (one r<set>.out spanning them all),
    every column is concatenated so the overlay covers the whole trace; pass
    `col` to isolate one key. Legacy captures have no headers, so the file is
    one anonymous block sliced positionally: block length len(rows) // nruns,
    nruns counted from the trace files, exactly as score_oracle does it -- the
    TSC runs across runs so there is no restart in the timestamps to split on.
    """
    blocks = _parse_truth_blocks(path)
    if not blocks:
        raise SystemExit(f"{path} has no ground-truth bit rows")

    labelled = [b for b in blocks if b["set"] is not None]
    if labelled:
        sel = sorted((b for b in labelled if b["set"] == run),
                     key=lambda b: (b["col"] if b["col"] is not None else 0))
        if not sel:
            sets = sorted({b["set"] for b in labelled})
            raise SystemExit(f"{path} has no block for set {run}; available "
                             f"sets: {sets} -- pass --run <set> to choose one")
        if col is not None:
            sel = [b for b in sel if b["col"] == col]
            if not sel:
                avail = sorted({b["col"] for b in labelled if b["set"] == run})
                raise SystemExit(f"set {run} has no col {col}; available "
                                 f"cols: {avail}")
        rows = [r for b in sel for r in b["rows"]]
        cols = [b["col"] for b in sel]
        print(f"  truth: set {run}, "
              + (f"col {cols[0]}" if len(sel) == 1
                 else f"{len(sel)} key-columns {cols} concatenated")
              + f" ({len(rows)} bits)")
    else:
        rows = blocks[0]["rows"]
        if len(rows) % nruns:
            print(f"  warning: {len(rows)} oracle lines is not a multiple of "
                  f"{nruns} traces; run/trace pairing may be off")
        nbits = max(len(rows) // nruns, 1)
        if run >= nruns:
            raise SystemExit(f"{path} holds {nruns} run(s); asked for run {run}")
        rows = rows[run * nbits:(run + 1) * nbits]
    return (np.array([t for t, _ in rows], dtype=np.int64),
            np.array([b for _, b in rows], dtype=int))


def plot_trace(trace, labels, at, title, truth=None, nbits=None, t0=None,
               absolute=True):
    """One row per monitored cache line.

    By default x is the raw rdtscp the trace was recorded with -- the same
    convention as LLCT's scripts/plot/plot_general.py, so a timestamp read off
    this plot is the one every other tool on this capture (the extractor's
    debug output, victim_bits.txt, another plot) is talking about. Note that
    bokeh carries x as float64 on both sides of the wire, so a TSC past 2^53
    (any machine up a few weeks) quantizes to ~16 cycles -- invisible against a
    ~50k-cycle bit period, but do not read fine structure off an absolute plot.

    With `absolute=False`, x is cycles since the ladder start instead (or since
    the first hit, without ground truth), which is the readable form when what
    you care about is where a feature sits inside the ladder.
    """
    if absolute:
        t0 = 0
    p = figure(
        width=1400,
        height=460,
        toolbar_location="right",
        title=title,
        x_axis_label="CPU timestamp (absolute TSC)" if absolute else
                     ("cycles since the first ladder bit" if truth
                      else "cycles since the first hit"),
        y_axis_label="target cache line",
        tools="pan,box_zoom,wheel_zoom,reset,save",
    )

    # Bokeh's default grid runs at its own spacing, which has nothing to do
    # with the bit period: it reads as a second, wrong set of slot boundaries
    # laid over the ground truth. The only vertical rules on this plot should
    # be the real bit boundaries drawn below.
    p.xgrid.grid_line_color = None
    p.ygrid.grid_line_color = None

    cols = []
    for i in range(trace.shape[1]):
        mask = trace.apply(lambda x: lat_to_hit(x[i][1], at), axis=1)
        cols.append(trace[i][mask].tolist())

    if t0 is None:
        firsts = [c[0][0] for c in cols if c]
        t0 = min(firsts) if firsts else 0

    # Ground truth first, so the hits are drawn on top of the shading.
    lo = hi = None
    if truth is not None:
        ts, bits = truth
        T = int(np.median(np.diff(ts))) if len(ts) > 1 else 0
        edges = np.append(ts, ts[-1] + T)
        if nbits:
            edges = edges[:nbits + 1]
            bits = bits[:nbits]
        lo, hi = float(edges[0] - t0), float(edges[-1] - t0)
        # The ground truth goes in its OWN track under the channel rows, not
        # as a full-height wash behind them. Shading the plot area competes
        # with the scatter however it is coloured -- greys included -- while a
        # compact bar per slot reads as a barcode of the scalar and leaves the
        # data area white. A filled bar is a 0-bit, the value the marker line
        # fires on; an outlined one is a 1-bit.
        left = (edges[:-1] - t0).astype(float)
        right = (edges[1:] - t0).astype(float)
        # A concatenated multi-key (CSI) truth has a dead gap between one key's
        # last bit and the next key's first: its slot is orders of magnitude
        # wider than T. Draw that terminal bit at the normal width instead of
        # one bar stretched across the gap (the per-slot spans below sit on the
        # real slot starts, so they need no such fix).
        bridge = (right - left) > 3 * T if T else np.zeros(len(left), bool)
        right = np.where(bridge, left + T, right)
        idx = np.arange(len(bits))
        z = bits == 0
        quads = []
        for sel, fill, line, lab in (
                (z, "#b3b3b3", "#9a9a9a",
                 f"true 0-bit (marker fires, T~{T} cyc)"),
                (~z, "#f2f2f2", "#b3b3b3", "true 1-bit")):
            src = ColumnDataSource(dict(left=left[sel], right=right[sel],
                                        slot=idx[sel], bit=bits[sel]))
            quads.append(p.quad(left="left", right="right", bottom=-1.35,
                                top=-0.75, source=src, fill_color=fill,
                                line_color=line, line_width=1,
                                legend_label=lab))
        # Which slot a feature sits in is the question every alignment check
        # ends up asking, so the ladder iteration number is written under its
        # bar. Every slot at 246 bits is unreadable overlapping text, so the
        # labels thin out to ~50 across whatever range is on screen; the hover
        # still reports the exact slot and bit for any bar.
        stride = max(1, int(np.ceil(len(idx) / 50.0)))
        lbl = idx[::stride]
        p.text(x=(left[lbl] + right[lbl]) / 2.0, y=-1.42,
               text=[str(i) for i in lbl], text_color="#666666",
               text_font_size="7pt", text_align="center", text_baseline="top")
        p.add_tools(HoverTool(renderers=quads, point_policy="follow_mouse",
                              tooltips=[("slot", "@slot"), ("bit", "@bit"),
                                        ("start", "@left{int}")]))
        for e in np.append(left, right[-1]):
            p.add_layout(Span(location=float(e), dimension="height",
                              line_color="#666666", line_width=1,
                              line_dash="dotted"))

    for i, xy in enumerate(cols):
        x = np.array([t[0] for t in xy], dtype=float) - t0
        lab = f"col{i}"
        if labels and i < len(labels):
            role, handler, off = labels[i]
            kind = {"0": "marker(0-bit)", "1": "marker(1-bit)"}.get(role, "clock")
            lab = f"col{i} {kind} {handler}+{off}"
        print(f"  {lab}: {len(xy)} hits")
        p.scatter(x=x, y=i, color=palette[i % len(palette)], size=7,
                  legend_label=lab)

    if truth is not None and hi is not None:
        p.x_range.start, p.x_range.end = lo - 0.02 * (hi - lo), hi
    ticks = list(range(len(cols)))
    overrides = {}
    if truth is not None:
        ticks = [-1] + ticks
        overrides[-1] = "true bit"
        p.y_range.start, p.y_range.end = -2.0, len(cols) - 0.4
    p.yaxis.ticker = ticks
    if overrides:
        p.yaxis.major_label_overrides = overrides
    p.legend.location = "top_right"
    p.legend.click_policy = "hide"
    p.legend.label_text_font_size = "9pt"
    p.add_layout(p.legend[0], "right")
    p.add_tools(HoverTool(tooltips=[("cycle", "@x{int}"), ("row", "$index")]))
    return p


def contrast_report(trace, labels, at, truth):
    """Per-slot hit counts split by true bit value -- the same quantity the
    decoder thresholds, printed so a plot can be checked against a number."""
    ts, bits = truth
    T = int(np.median(np.diff(ts))) if len(ts) > 1 else 0
    edges = np.append(ts, ts[-1] + T)
    print(f"\n  per-slot hits by TRUE bit value ({len(bits)} bits, T~{T} cyc)")
    for i in range(trace.shape[1]):
        mask = trace.apply(lambda x: lat_to_hit(x[i][1], at), axis=1)
        x = np.array([t[0] for t in trace[i][mask].tolist()], dtype=np.int64)
        pos = np.searchsorted(edges, x, side="right") - 1
        pos = pos[(pos >= 0) & (pos < len(bits))]
        n = np.bincount(pos, minlength=len(bits)).astype(float)
        m0, m1 = n[bits == 0].mean(), n[bits == 1].mean()
        role = labels[i][0] if labels and i < len(labels) else "?"
        kind = {"0": "marker", "1": "marker"}.get(role, "clock ")
        print(f"    col{i} ({kind}): 0-bit {m0:6.2f}   1-bit {m1:6.2f}   "
              f"ratio {m0 / max(m1, 1e-9):5.2f}x"
              + ("   <- should be ~1x" if role == "c" else ""))


def hit_timestamps(trace, idx, at):
    """Sorted hit timestamps for one independently recorded trace column."""
    mask = trace.apply(lambda x: lat_to_hit(x[idx][1], at), axis=1)
    hits = np.asarray([x[0] for x in trace[idx][mask] if x[0] > 0],
                      dtype=np.int64)
    return np.sort(hits)


def estimate_burst_period(hits, gap_split=BURST_GAP_CYCLES):
    """Estimate the group period using only integer-friendly gap operations.

    A gap above `gap_split` begins a new burst. The median burst-start gap is
    refined with the same broad 0.55T..1.80T core used by the decoder. Missing
    groups therefore create integer multiples without shifting later groups.
    """
    if len(hits) < 8:
        return None
    gaps = np.diff(hits)
    cut = np.flatnonzero(gaps > gap_split) + 1
    starts = np.concatenate(([hits[0]], hits[cut]))
    if len(starts) < 4:
        return None
    steps = np.diff(starts)
    period = float(np.median(steps))
    core = steps[(steps > 0.55 * period) & (steps < 1.80 * period)]
    return int(round(float(np.median(core)))) if len(core) else int(round(period))


def densest_window(hits, width):
    """O(n) densest fixed-width hit window; directly portable to C."""
    left = best_left = best_right = 0
    for right in range(len(hits)):
        while hits[right] - hits[left] > width:
            left += 1
        if right - left > best_right - best_left:
            best_left, best_right = left, right
    lo = int(hits[best_left])
    return lo, lo + int(width)


def timing_window(trace, idx, at, truth=None, gap_split=BURST_GAP_CYCLES,
                  max_periods=LADDER_BITS_MAX):
    """Return (hits in ladder-sized ROI, period, bounds, source).

    Ground truth gives exact bounds when explicitly requested. Otherwise the
    period is inferred from burst gaps and the densest `max_periods * T`
    interval is selected. The eventual period count is inferred from the
    burst-center gaps, not forced to one key size. There is deliberately no
    lower bound: this elliptic.js ladder iterates over the scalar's bitLength.
    """
    hits = hit_timestamps(trace, idx, at)
    if not len(hits):
        return hits, None, None, "empty"

    if truth is not None:
        ts, _ = truth
        period = (int(np.median(np.diff(ts))) if len(ts) > 1 else
                  estimate_burst_period(hits, gap_split))
        if period is None:
            return hits, None, (int(hits[0]), int(hits[-1]) + 1), "all hits"
        bounds = (int(ts[0]), int(ts[-1]) + period)
        source = "ground-truth ladder"
    else:
        period = estimate_burst_period(hits, gap_split)
        if period is None:
            return hits, None, (int(hits[0]), int(hits[-1]) + 1), "all hits"
        bounds = densest_window(hits, max_periods * period)
        source = f"densest candidate window (at most {max_periods} periods)"

    lo, hi = bounds
    return hits[(hits >= lo) & (hits < hi)], period, bounds, source


def probes_to_signal(probes, sample_interval, bounds):
    """Bin hit timestamps into a binary, uniformly sampled event signal."""
    lo, hi = bounds
    nslots = max(1, math.ceil((hi - lo) / sample_interval))
    signal = np.zeros(nslots, dtype=int)
    probes = np.asarray(probes, dtype=np.int64)
    probes = probes[(probes >= lo) & (probes < hi)]
    if len(probes):
        slots = ((probes - lo) // sample_interval).astype(int)
        signal[slots] = 1
    return signal


def plot_trace_psd(hits, idx, sample_interval, bounds, source):
    """Welch PSD over the selected operation window, with no extra truncation."""
    signal = probes_to_signal(hits, sample_interval, bounds)
    fs = cpu_freq / sample_interval
    if len(signal) < 4 or not np.any(signal):
        print(f"  warning: col{idx} has too few hits; PSD is empty")
        frequencies = np.array([], dtype=float)
        power = np.array([], dtype=float)
    else:
        nperseg = min(4096, len(signal))
        frequencies, power = welch(signal, fs, nperseg=nperseg,
                                   noverlap=nperseg // 2)
        # scipy.signal.welch already returns the complete one-sided spectrum.
        frequencies = frequencies / 1000.0
        power = power * 1e7

    p = figure(
        width=1000,
        height=320,
        toolbar_location="right",
        title=(f"PSD of col{idx} ({sample_interval} cycles/bin; {source})"),
        x_axis_label="Frequency (kHz)",
        y_axis_label=r"PSD (\[10^{-7}\])",
        tools="pan,box_zoom,wheel_zoom,reset,save",
    )
    p.line(frequencies, power, line_width=2)
    if len(power) and np.max(power) > 0:
        peaks, _ = find_peaks(power, prominence=0.05 * np.max(power))
        p.scatter(frequencies[peaks], power[peaks], color="red", size=8)
    p.add_tools(HoverTool(tooltips=[("frequency", "@x{0.000} kHz"),
                                    ("power", "@y{0.000}")]))
    return p


def plot_interarrival(hits, idx, period, gap_split, source):
    """Plot each inter-arrival interval, classified by integer thresholds."""
    gaps = np.diff(hits)
    x = np.arange(len(gaps))
    p = figure(
        width=1200,
        height=340,
        y_axis_type="log",
        toolbar_location="right",
        title=f"Inter-arrival intervals of col{idx} ({source})",
        x_axis_label="interval index",
        y_axis_label="cycles",
        tools="pan,box_zoom,wheel_zoom,reset,save",
    )
    if len(gaps):
        p.line(x, gaps, color="#bdbdbd", line_alpha=0.6, line_width=1)
        classes = [
            (gaps <= gap_split, "#0072B2", "intra-burst"),
            ((gaps > gap_split) & (gaps < 1.5 * period),
             "#20B254", "next burst"),
            (gaps >= 1.5 * period, "#EC1557", "one or more groups skipped"),
        ]
        renderers = []
        for sel, color, label in classes:
            src = ColumnDataSource(dict(interval=x[sel], cycles=gaps[sel]))
            renderers.append(p.scatter(x="interval", y="cycles", source=src,
                                       color=color, size=6,
                                       legend_label=label))
        p.add_tools(HoverTool(renderers=renderers,
                              tooltips=[("interval", "@interval"),
                                        ("cycles", "@cycles{0,0}")]))
    p.add_layout(Span(location=gap_split, dimension="width",
                      line_color="#0072B2", line_dash="dashed"))
    p.add_layout(Span(location=period, dimension="width",
                      line_color="#20B254", line_dash="dashed"))
    p.add_layout(Span(location=1.5 * period, dimension="width",
                      line_color="#EC1557", line_dash="dotted"))
    p.legend.location = "top_right"
    p.legend.click_policy = "hide"
    return p


def burst_gap_stats(hits, period, gap_split):
    """Segment bursts and count rounded center-gap multiples of the period.

    Every operation is a compare, add, divide, or integer histogram update;
    this function is also the executable specification for a C version.
    """
    if not len(hits):
        return np.array([], dtype=np.int64), np.array([], dtype=np.int64), 0, 0.0
    cut = np.concatenate(([0], np.flatnonzero(np.diff(hits) > gap_split) + 1,
                          [len(hits)]))
    centers, sizes = [], []
    for begin, end in zip(cut[:-1], cut[1:]):
        group = hits[begin:end]
        # Sum offsets rather than absolute TSCs: safe in a uint64_t C port.
        center = int(group[0] + np.sum(group - group[0]) // len(group))
        centers.append(center)
        sizes.append(len(group))
    center_gaps = np.diff(np.asarray(centers, dtype=np.int64))
    # Positive integer round(gap / T), without floating point.
    multiples = np.maximum(1, (center_gaps + period // 2) // period)
    missed = int(np.sum(multiples - 1))
    opportunities = len(multiples) + missed
    miss_rate = missed / opportunities if opportunities else 0.0
    return multiples, np.asarray(sizes), missed, miss_rate


def plot_burst_gap_histogram(hits, idx, period, gap_split, source):
    """Histogram of integer period multiples between consecutive bursts."""
    multiples, sizes, missed, miss_rate = burst_gap_stats(
        hits, period, gap_split)
    cap = 8
    labels = [str(i) for i in range(1, cap)] + [f"{cap}+"]
    counts = [int(np.sum(multiples == i)) for i in range(1, cap)]
    counts.append(int(np.sum(multiples >= cap)))
    src = ColumnDataSource(dict(multiple=labels, count=counts))
    p = figure(
        width=900,
        height=340,
        x_range=labels,
        toolbar_location="right",
        title=(f"Burst-center gaps of col{idx}: {missed} inferred missing "
               f"groups ({miss_rate:.1%}; {source})"),
        x_axis_label="rounded burst-center gap / period",
        y_axis_label="number of gaps",
        tools="pan,box_zoom,wheel_zoom,reset,save",
    )
    p.vbar(x="multiple", top="count", source=src, width=0.8,
           color="#0072B2")
    p.add_tools(HoverTool(tooltips=[("periods", "@multiple"),
                                    ("gaps", "@count")]))
    return p, multiples, sizes, missed, miss_rate


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-i", "--trace_file", help="a single r<i>.out")
    src.add_argument("-d", "--directory", help="capture directory")
    ap.add_argument("--run", type=int, default=None,
                    help="with -d, which run to plot (default 0); with -i it "
                         "is taken from the r<i>.out name")
    ap.add_argument("--at", choices=["FR", "PS", "PP"], default=None,
                    help="attack primitive (default: from the capture's "
                         "`channels` metadata)")
    ap.add_argument("--truth", nargs="?", const=True, default=None,
                    help="overlay the victim's per-bit timestamps; bare flag "
                         "uses victim_bits.txt next to the trace, or give a path")
    ap.add_argument("--col", type=int, default=None,
                    help="for a labelled (CSI) truth file whose set was "
                         "profiled with several keys, overlay only this key-"
                         "column instead of all of them concatenated")
    ap.add_argument("--rel", dest="absolute", action="store_false",
                    help="plot cycles since the ladder start (or the first "
                         "hit) on x instead of the default raw rdtscp")
    ap.add_argument("--bits", type=int, default=None,
                    help="plot only the first N bits (a 246-bit ladder over "
                         "~12M cycles is unreadable at full width)")
    ap.add_argument("--psd_index", type=int, default=None,
                    help="also plot the PSD for this zero-based trace column")
    ap.add_argument("--psd_bin_cycles", type=int, default=None,
                    help="PSD time-bin width in cycles (default: 1000 for PP, "
                         f"{PS_sample_interval} otherwise)")
    ap.add_argument("--interval_index", type=int, default=None,
                    help="plot inter-arrival intervals for this trace column")
    ap.add_argument("--burst_index", type=int, default=None,
                    help="plot burst-center gap multiples for this column")
    ap.add_argument("--burst_gap_cycles", type=int,
                    default=BURST_GAP_CYCLES,
                    help="maximum intra-burst gap in cycles (default: "
                         f"{BURST_GAP_CYCLES})")
    ap.add_argument("-o", "--out_path", help="output .html (default: next to "
                                             "the trace)")
    args = ap.parse_args()

    if args.psd_bin_cycles is not None and args.psd_bin_cycles <= 0:
        ap.error("--psd_bin_cycles must be positive")
    if args.burst_gap_cycles <= 0:
        ap.error("--burst_gap_cycles must be positive")
    if args.trace_file:
        trace_path = Path(args.trace_file)
        directory = str(trace_path.parent)
        m = re.match(r"r(\d+)\.out$", trace_path.name)
        run = args.run if args.run is not None else (int(m.group(1)) if m else 0)
    else:
        directory = args.directory
        run = args.run or 0
        trace_path = Path(directory) / f"r{run}.out"
    if not trace_path.exists():
        raise SystemExit(f"no trace at {trace_path}")

    labels, prim = load_channels(directory)
    at = args.at or {"fr": "FR", "ps": "PS", "pp": "PP"}.get(prim or "fr", "FR")

    truth = None
    if args.truth:
        tp = (os.path.join(directory, "victim_bits.txt")
              if args.truth is True else args.truth)
        if not os.path.exists(tp):
            raise SystemExit(
                f"no ground truth at {tp} -- re-capture with BITS=1, e.g. "
                f"`BITS=1 RUNS=1 ./evaluation/run_ecdh_ct.sh -pp 0`")
        # Count the runs in the directory the TRUTH lives in, which is not
        # always the trace's: --truth takes an explicit path.
        nruns = len(list(Path(tp).parent.glob("r*.out")))
        truth = load_truth(tp, run, max(nruns, 1), args.col)

    trace = load_trace(str(trace_path))
    print(f"{trace_path}  ({at}, {trace.shape[1]} columns, {len(trace)} samples)")
    for name, idx in (("--psd_index", args.psd_index),
                      ("--interval_index", args.interval_index),
                      ("--burst_index", args.burst_index)):
        if idx is not None and not 0 <= idx < trace.shape[1]:
            ap.error(f"{name} must be between 0 and {trace.shape[1] - 1}")

    if truth is not None:
        # Both clocks are the same rdtscp, so a truth block that does not
        # overlap the trace in time is from a DIFFERENT run -- which plots as
        # an empty ladder and reports 0.00 hits per slot rather than as an
        # error. Catch it here instead.
        ts = np.array([p[0] for row in trace.values for p in row
                       if p is not None and p[0] > 0], dtype=np.int64)
        lo, hi = truth[0][0], truth[0][-1]
        if len(ts) and (ts.max() < lo or ts.min() > hi):
            raise SystemExit(
                f"ground truth and trace do not overlap in time -- truth spans "
                f"{lo}..{hi}, trace {ts.min()}..{ts.max()}. They are from "
                f"different runs; use the victim_bits.txt from this capture, "
                f"and --run to pick the block matching r<i>.out.")
    title = f"{Path(directory).name} / {trace_path.name}  [{at}]"
    p = plot_trace(trace, labels, at, title, truth, args.bits,
                   absolute=args.absolute)
    plots = [p]
    requested = {idx for idx in (args.psd_index, args.interval_index,
                                 args.burst_index) if idx is not None}
    timing = {}
    for idx in requested:
        timing[idx] = timing_window(
            trace, idx, at, truth=truth,
            gap_split=args.burst_gap_cycles,
            max_periods=LADDER_BITS_MAX)
        hits, period, bounds, source = timing[idx]
        if period is None or bounds is None:
            ap.error(f"could not estimate a burst period for column {idx}")
        print(f"  col{idx} timing ROI: {len(hits)} hits, T~{period} cycles, "
              f"{source} [{bounds[0]}..{bounds[1]})")

    if args.psd_index is not None:
        idx = args.psd_index
        hits, _, bounds, source = timing[idx]
        sample_interval = (args.psd_bin_cycles or
                           (PP_PSD_BIN_CYCLES if at == "PP" else
                            PS_sample_interval))
        plots.append(plot_trace_psd(hits, idx, sample_interval, bounds, source))
    if args.interval_index is not None:
        idx = args.interval_index
        hits, period, _, source = timing[idx]
        plots.append(plot_interarrival(hits, idx, period,
                                       args.burst_gap_cycles, source))
        gaps = np.diff(hits)
        print(f"  col{idx} intervals: {np.sum(gaps <= args.burst_gap_cycles)} "
              f"intra-burst, "
              f"{np.sum((gaps > args.burst_gap_cycles) & (gaps < 1.5 * period))} "
              f"next-burst, {np.sum(gaps >= 1.5 * period)} skipped-group")
    if args.burst_index is not None:
        idx = args.burst_index
        hits, period, _, source = timing[idx]
        bp, multiples, sizes, missed, miss_rate = plot_burst_gap_histogram(
            hits, idx, period, args.burst_gap_cycles, source)
        plots.append(bp)
        hist = ""
        if len(multiples):
            hist = " ".join(
                f"{k}T:{np.sum(multiples == k)}"
                for k in range(1, min(8, int(multiples.max()) + 1)))
            if multiples.max() >= 8:
                hist += f" 8+T:{np.sum(multiples >= 8)}"
        inferred_periods = len(multiples) + missed
        plausible = inferred_periods <= LADDER_BITS_MAX
        print(f"  col{idx} bursts: {len(sizes)}, size median "
              f"{np.median(sizes) if len(sizes) else 0:g}; gaps {hist}; "
              f"inferred missing {missed}/{inferred_periods} "
              f"({miss_rate:.1%}); inferred period span {inferred_periods} "
              f"({'within maximum' if plausible else 'ABOVE MAXIMUM'})")
    if truth is not None:
        contrast_report(trace, labels, at, truth)

    out = args.out_path or str(trace_path.with_suffix(".html"))
    output_file(filename=out, title=title)
    save(column(*plots))
    print(f"\n  -> {os.path.abspath(out)}")


if __name__ == "__main__":
    main()
