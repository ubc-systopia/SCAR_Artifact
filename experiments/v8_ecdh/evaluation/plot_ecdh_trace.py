#!/usr/bin/env python3
"""Look at raw v8_ecdh (elliptic, non-CT) Prime+Scope traces.

    # the capture-health table: per-key hit counts vs the key's popcount
    plot_ecdh_trace.py --summary ./build/output/perkey_t11

    # one trace, three channels as a raster + the common-line gap plot
    plot_ecdh_trace.py -i ./build/output/perkey_t11/v8_ecdh_key_pool_key00000_r00010/r0.out

    # same, by key/run index, x measured from the ladder start
    plot_ecdh_trace.py -d ./build/output/perkey_t11 --key 0 --run 3 --rel

A trace file is three INDEPENDENT event lists, one per attacker slot, dumped
side by side as `tsc:latency` columns and padded with `0:0` -- row i of column
j is the i-th HIT of slot j, so rows do NOT line up across columns. Column
order follows `cl_offset` in v8_ecdh_key_pool.cc: 0 = common (loop header,
one hit per ladder iteration = the clock), 1 = false (the bit==0
fall-through arm), 2 = true (the bit==1 jump target).

The capture is Prime+Scope, so any non-zero latency is a hit; the F+R
latency bands in utils.lat_to_clevel do not apply here.

--summary is the no-decode capture-health test: the TRUE line's median hit
count over a key should equal that key's number of 1-bits, and the COMMON
line should sit near the key's bit length (one hit per iteration). FALSE is
reached by sequential prefetch from the branch, so it fires nearly every
iteration and carries no usable signal -- the table prints it so you can see
that for yourself rather than take it on faith.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bokeh.layouts import column as bk_column  # noqa: E402
from bokeh.models import BoxAnnotation, HoverTool  # noqa: E402
from bokeh.plotting import figure, output_file, save  # noqa: E402

from utils import load_trace, palette  # noqa: E402

CHANNELS = ["common (0xe00)", "false (0xec0)", "true (0xfc0)"]
KEY_DIR_RE = re.compile(r"_key(\d+)_r(\d+)$")

# One ladder iteration is ~23k cycles and a whole derive ~5.8M, so a gap an
# order of magnitude above the iteration period means the probe window left
# the derive (idle, or a neighbouring derive).
SEGMENT_BREAK_CYCLES = 150000


def channel_hits(df, col):
    """Timestamps of slot `col`'s hits, in order. P+S: lat > 0 is a hit."""
    if col >= df.shape[1]:
        return np.array([], dtype=np.uint64)
    pairs = [p for p in df[col] if p is not None and p[1] > 0]
    return np.array([p[0] for p in pairs], dtype=np.uint64)


def densest_segment(ts, break_cycles=SEGMENT_BREAK_CYCLES):
    """The longest run of hits with no gap above `break_cycles`.

    This is what a decoder uses as the ladder: the common line keeps firing
    over the whole ~100M-cycle profiling window, but only one stretch of it
    is the derive we asked for.
    """
    if len(ts) < 2:
        return ts
    breaks = np.nonzero(np.diff(ts.astype(np.int64)) > break_cycles)[0]
    starts = np.concatenate(([0], breaks + 1))
    ends = np.concatenate((breaks + 1, [len(ts)]))
    best = np.argmax(ends - starts)
    return ts[starts[best]:ends[best]]


def load_key(pool_dir, key_id):
    """The pool's secret scalar for this key index, or None."""
    path = Path(pool_dir) / f"ec_key_{key_id}.json"
    if not path.exists():
        return None
    return int(json.load(open(path))["key1"], 16)


def key_dirs(capture_dir):
    """(key_id, path) for every key directory of a capture, key order."""
    out = []
    for p in sorted(Path(capture_dir).iterdir()):
        m = KEY_DIR_RE.search(p.name)
        if p.is_dir() and m:
            out.append((int(m.group(1)), p))
    return sorted(out)


ALIVE_COMMON_MIN = 200   # the clock must see ~one hit per ladder iteration
ALIVE_TRUE_TOL = 12      # `true` counts the 1-bits, +- probe noise


def summary(capture_dir, pool_dir):
    """Per-key hit counts, and how many runs are actually decodable.

    A slot is either alive for a whole run or flat (~1 hit), so the median
    over ALL runs of a key measures how often the slot was alive, not how
    good its eviction set is. Both are printed: `common`/`true` are the
    median over the runs where that slot was alive, and `alive` / `dec`
    count the runs. `dec` -- common AND true alive in the SAME run -- is the
    only column a decode can use, since it needs the clock and the marker
    together.
    """
    print(f"{'key':>4} {'bits':>5} {'ones':>5} "
          f"{'common(alive)':>16} {'false(alive)':>16} {'true(alive)':>16} "
          f"{'alive c/f/t':>13} {'dec':>5}")
    for key_id, kdir in key_dirs(capture_dir):
        runs = sorted(kdir.glob("r*.out"),
                      key=lambda p: int(p.stem[1:]))
        if not runs:
            continue
        counts = np.zeros((len(runs), 3), dtype=np.int64)
        for i, r in enumerate(runs):
            df = load_trace(r)
            for c in range(3):
                counts[i, c] = len(channel_hits(df, c))
        key = load_key(pool_dir, key_id)
        if key is None:
            med = np.median(counts, axis=0)
            print(f"{key_id:>4} {'?':>5} {'?':>5} "
                  f"{med[0]:>16.0f} {med[1]:>16.0f} {med[2]:>16.0f}")
            continue
        ones = bin(key).count("1")
        bits = key.bit_length()

        # "alive" is per slot per run: the flat runs sit at ~1 hit, the live
        # ones within noise of what the line is supposed to count, so a
        # simple floor separates them cleanly.
        alive = [counts[:, 0] >= ALIVE_COMMON_MIN,
                 counts[:, 1] >= ALIVE_COMMON_MIN // 2,
                 np.abs(counts[:, 2] - ones) <= ALIVE_TRUE_TOL]
        cells = []
        for c in range(3):
            live = counts[alive[c], c]
            if not len(live):
                cells.append("-")
                continue
            cells.append(f"{np.median(live):>4.0f} "
                         f"[{live.min():>3}-{live.max():>3}]")
        decodable = int(np.sum(alive[0] & alive[2]))
        print(f"{key_id:>4} {bits:>5} {ones:>5} "
              f"{cells[0]:>16} {cells[1]:>16} {cells[2]:>16} "
              f"{alive[0].sum():>4}/{alive[1].sum():>3}/{alive[2].sum():>3} "
              f"{decodable:>4}/{len(runs)}")
    print("\ncommon should track the key's bit length (one hit per ladder "
          "iteration) and\ntrue should equal `ones`; false is prefetch-driven "
          "and tracks neither.\n`dec` is what a decode can actually use: "
          "clock and marker alive in the same run.")


def plot(trace_path, key, rel, out_path):
    df = load_trace(trace_path)
    hits = [channel_hits(df, c) for c in range(3)]
    seg = densest_segment(hits[0])
    origin = int(seg[0]) if rel and len(seg) else 0

    title = f"{Path(trace_path).parent.name}/{Path(trace_path).name}"
    if key is not None:
        title += (f"  --  key {key.bit_length()} bits, "
                  f"{bin(key).count('1')} ones")

    raster = figure(width=1400, height=420, title=title,
                    x_axis_label="rdtscp" + (" from ladder start" if rel else ""),
                    y_range=CHANNELS, tools="xpan,xwheel_zoom,box_zoom,reset,save",
                    active_scroll="xwheel_zoom")
    for c in range(3):
        x = (hits[c].astype(np.int64) - origin)
        raster.scatter(x=x, y=[CHANNELS[c]] * len(x), size=6,
                       marker="dash", angle=np.pi / 2,
                       color=palette[c], legend_label=f"{CHANNELS[c]}"
                       f"  n={len(x)}")
    if len(seg):
        raster.add_layout(BoxAnnotation(
            left=int(seg[0]) - origin, right=int(seg[-1]) - origin,
            fill_alpha=0.07, fill_color="#0072B2"))
    raster.legend.location = "top_left"
    raster.legend.click_policy = "hide"

    gaps = figure(width=1400, height=300, x_range=raster.x_range,
                  title=f"common-line inter-arrival gap "
                        f"(densest segment: {len(seg)} hits, "
                        f"median gap "
                        f"{int(np.median(np.diff(seg.astype(np.int64)))) if len(seg) > 1 else 0} cyc)",
                  x_axis_label="rdtscp" + (" from ladder start" if rel else ""),
                  y_axis_label="cycles to previous hit",
                  y_axis_type="log", tools="xpan,xwheel_zoom,box_zoom,reset,save",
                  active_scroll="xwheel_zoom")
    if len(hits[0]) > 1:
        d = np.diff(hits[0].astype(np.int64))
        gaps.scatter(x=hits[0][1:].astype(np.int64) - origin, y=d,
                     size=5, color=palette[0])
    gaps.add_tools(HoverTool(tooltips=[("t", "@x{0,0}"), ("gap", "@y{0,0}")]))

    output_file(out_path, title=title)
    save(bk_column(raster, gaps))
    print("hits per channel: " +
          ", ".join(f"{CHANNELS[c]}={len(hits[c])}" for c in range(3)))
    if len(seg) > 1:
        print(f"densest common segment: {len(seg)} hits, span "
              f"{int(seg[-1] - seg[0]):,} cycles, median gap "
              f"{int(np.median(np.diff(seg.astype(np.int64)))):,}")
    print(f"wrote {out_path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--input", help="one r<N>.out trace file")
    ap.add_argument("-d", "--dir", help="a capture directory (the -tag= dir)")
    ap.add_argument("--key", type=int, default=None, help="key index within -d")
    ap.add_argument("--run", type=int, default=0, help="run index within the key")
    ap.add_argument("--summary", help="capture dir: print the hit-count table")
    ap.add_argument("--pool", default="experiments/v8_ecdh/ec_key_pool",
                    help="key pool directory")
    ap.add_argument("--rel", action="store_true",
                    help="x measured from the ladder start")
    ap.add_argument("-o", "--out", default=None, help="output html")
    args = ap.parse_args()

    if args.summary:
        summary(args.summary, args.pool)
        return

    key_id = args.key
    if args.input:
        trace_path = Path(args.input)
        m = KEY_DIR_RE.search(trace_path.parent.name)
        if m and key_id is None:
            key_id = int(m.group(1))
    elif args.dir and args.key is not None:
        match = [p for k, p in key_dirs(args.dir) if k == args.key]
        if not match:
            ap.error(f"no key {args.key} under {args.dir}")
        trace_path = match[0] / f"r{args.run}.out"
    else:
        ap.error("give -i <trace>, or -d <capture> --key N [--run M], "
                 "or --summary <capture>")

    out = args.out or f"ecdh_trace_key{key_id}_r{args.run}.html"
    plot(trace_path, load_key(args.pool, key_id) if key_id is not None else None,
         args.rel, out)


if __name__ == "__main__":
    main()
