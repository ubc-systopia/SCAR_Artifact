#!/usr/bin/env python3
"""Plot one v8_ctjs_ecdh trace, optionally with the victim's own per-bit
timestamps drawn underneath it.

    plot_ecdh_ct.py -i <capture>/r0.out                    # trace alone
    plot_ecdh_ct.py -i <capture>/r0.out --truth            # + ground truth
    plot_ecdh_ct.py -d <capture> --run 3 --truth --bits 40 # zoom on 40 bits
    plot_ecdh_ct.py -i <capture>/r0.out --rel              # x from ladder start

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
import os
import re
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bokeh.layouts import column  # noqa: E402
from bokeh.models import (BoxAnnotation, ColumnDataSource, HoverTool,  # noqa: E402
                          Span)
from bokeh.plotting import figure, output_file, save  # noqa: E402

from utils import lat_to_hit, load_trace, palette  # noqa: E402


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


def load_truth(path, run, nruns):
    """victim_bits.txt -> (timestamps, bits) for ONE profiled run.

    The file holds every profiled run's block back to back, in run order, so
    trace r<i>.out pairs with the i-th block. The block length is len(rows) //
    nruns, with nruns counted from the trace files -- the same way
    extract_v8_ct_ecdh.score_oracle does it. It cannot be found from the
    timestamps: the TSC keeps counting across runs, so there is no restart to
    look for.
    """
    rows = [ln.split(",") for ln in open(path).read().split()]
    rows = [(int(a), int(b)) for a, b in rows]
    if len(rows) % nruns:
        print(f"  warning: {len(rows)} oracle lines is not a multiple of "
              f"{nruns} traces; run/trace pairing may be off")
    nbits = max(len(rows) // nruns, 1)
    if run >= nruns:
        raise SystemExit(f"{path} holds {nruns} run(s); asked for run {run}")
    blk = rows[run * nbits:(run + 1) * nbits]
    return (np.array([t for t, _ in blk], dtype=np.int64),
            np.array([b for _, b in blk], dtype=int))


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
    ap.add_argument("--rel", dest="absolute", action="store_false",
                    help="plot cycles since the ladder start (or the first "
                         "hit) on x instead of the default raw rdtscp")
    ap.add_argument("--bits", type=int, default=None,
                    help="plot only the first N bits (a 246-bit ladder over "
                         "~12M cycles is unreadable at full width)")
    ap.add_argument("-o", "--out_path", help="output .html (default: next to "
                                             "the trace)")
    args = ap.parse_args()

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
        truth = load_truth(tp, run, max(nruns, 1))

    trace = load_trace(str(trace_path))
    print(f"{trace_path}  ({at}, {trace.shape[1]} columns, {len(trace)} samples)")

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
    if truth is not None:
        contrast_report(trace, labels, at, truth)

    out = args.out_path or str(trace_path.with_suffix(".html"))
    output_file(filename=out, title=title)
    save(column(p))
    print(f"\n  -> {os.path.abspath(out)}")


if __name__ == "__main__":
    main()
