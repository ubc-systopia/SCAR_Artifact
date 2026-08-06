"""Text versions of the EXPLANATION.md figures, from the shipped traces.

Same content as plot_figures.py renders with bokeh, printed as ASCII so it can
be checked without installing anything beyond numpy.

    python3 figures.py [--trace r0]
"""
import argparse

import numpy as np

import decoder as D


def enrich(path):
    """decoder.decode plus the intermediates the raster figures need.

    decoder.py is left untouched because verify.py checks its output; these are
    the same computations repeated, not different ones.
    """
    res = D.decode(path)
    ts, _ = D.load_trace(path)
    lsb_first = D.load_exponent()
    start_t, wide_gap, _, _ = D.wide_narrow(ts)
    idx, valid, _ = D.assign_indices(start_t, len(lsb_first),
                                     anchor=res["anchor"])
    res.update(wide_start=start_t, wide_gap=wide_gap,
               idx=idx, valid=valid, lsb_first=lsb_first)
    return res


def timeline(ts):
    """Figure 1: the pair pattern, with the numbers that define it."""
    lo, hi = D.signing_window(ts)
    t = ts[(ts >= lo) & (ts <= hi)]
    gaps = np.diff(t)

    inner = gaps[gaps < D.PAIR_SPLIT_CYCLES]
    outer = gaps[gaps >= D.PAIR_SPLIT_CYCLES]
    valley = ((gaps > 35_000) & (gaps < 270_000)).sum()

    start_t, wide, narrow, alternation = D.wide_narrow(t)
    period = np.median(np.diff(start_t))

    print("FIGURE 1  the signal pattern")
    print(f"  accesses in signing window : {len(t)}")
    print(f"  loop period (median)       : {period:,.0f} cycles")
    print(f"  gap between pairs (median) : {np.median(outer):,.0f} cycles")
    print(f"  wide pair gap              : {wide.mean():,.0f} +- {wide.std():,.0f}"
          f"   ({len(wide)} pairs)   <- signal")
    print(f"  narrow pair gap            : {narrow.mean():,.0f} +- {narrow.std():,.0f}"
          f"   ({len(narrow)} pairs)   <- control")
    print(f"  wide/narrow alternation    : {alternation:.3f}")
    print(f"  gaps in the empty valley   : {valley} of {len(gaps)} "
          f"({100 * valley / len(gaps):.1f}%)")
    print(f"  inner gap range            : {inner.min():,.0f} .. {inner.max():,.0f}")
    print()


def _hist_pair(gap, truth, lo=27_000, hi=34_200, bins=18, width=30):
    """Side-by-side ASCII histograms of the wide-pair gap, split by key bit."""
    h0, edges = np.histogram(gap[truth == 0], bins=bins, range=(lo, hi))
    h1, _ = np.histogram(gap[truth == 1], bins=bins, range=(lo, hi))
    scale = max(h0.max(), h1.max()) or 1
    rows = []
    for i in range(bins):
        b0 = "#" * int(round(h0[i] * width / scale))
        b1 = "#" * int(round(h1[i] * width / scale))
        rows.append(f"{edges[i]:8,.0f} | {b0:<{width + 1}}| {b1}")
    return rows


def separation(res):
    """Figure 2: why the wide-pair gap is readable as a bit."""
    gap, truth, idx = res["gap"], res["truth"], res["bit_index"]

    for label, sel in (("lowest 2048 bits", idx < 2048),
                       ("all 4094 bits", np.ones_like(idx, dtype=bool))):
        g, t = gap[sel], truth[sel]
        print(f"FIGURE 2  wide-pair gap by key bit, {label}")
        print(f"{'':10}{'bit = 0':<32}{'bit = 1'}")
        for row in _hist_pair(g, t):
            print("  " + row)
        print(f"  mean {g[t == 0].mean():,.0f} sd {g[t == 0].std():,.0f}"
              f"   /   mean {g[t == 1].mean():,.0f} sd {g[t == 1].std():,.0f}"
              f"   correlation {np.corrcoef(g, t)[0, 1]:+.3f}")
        print()


def along_trace(res, parts=10):
    """Figure 3: accuracy and correlation per tenth of the trace."""
    gap, truth = res["gap"], res["truth"]
    predicted = res["predicted"]
    n = len(gap)
    bounds = [(i * n // parts, (i + 1) * n // parts) for i in range(parts)]

    corr = [np.corrcoef(gap[a:b], truth[a:b])[0, 1] for a, b in bounds]
    acc = [(predicted[a:b] == truth[a:b]).mean() for a, b in bounds]

    print(f"FIGURE 3  accuracy along the trace ({parts} equal parts, low bits first)")
    for level in np.arange(1.0, 0.45, -0.05):
        bar = "".join(" #### " if a >= level else "      " for a in acc)
        print(f"  {level:4.2f} |{bar}")
    print("       +" + "-" * (6 * parts))
    print("        " + "".join(f"{a:5.3f} " for a in acc))
    print("  corr  " + "".join(f"{c:+5.2f} " for c in corr))
    print()


def _raster_row(times, t0, span, cols, mark="|"):
    """One row of a raster: cache accesses binned into `cols` time buckets."""
    row = [" "] * cols
    sel = times[(times >= t0) & (times < t0 + span)]
    for x in ((sel - t0) * cols // span).astype(int):
        row[min(x, cols - 1)] = mark
    return "".join(row)


def raster(path, res, n_iters=2, cols=112, first_bit=40):
    """Figure 4: time on x, accesses to the watched cache line on y, zoomed in.

    At this zoom one column is several thousand cycles, so the wide/narrow
    difference is only a column or two. The point of this figure is the coarse
    structure -- pairs, alternation, loop period. Figure 5 resolves the bit.
    """
    sig, _ = D.load_trace(path)

    period = res["period"]
    starts, idx, valid = res["wide_start"], res["idx"], res["valid"]
    anchor = np.where(valid & (idx >= first_bit))[0][0]
    t0 = starts[anchor] - 0.12 * period
    span = int(n_iters * period)
    per_col = span / cols

    # Rebuild every pair in the window, wide and narrow alike.
    win = sig[(sig >= t0) & (sig < t0 + span)]
    breaks = np.concatenate(([0], np.where(np.diff(win) >= D.PAIR_SPLIT_CYCLES)[0] + 1))
    ends = np.concatenate((breaks[1:] - 1, [len(win) - 1]))
    median_gap = np.median(res["wide_gap"].tolist() + [0])  # split, as in decoder

    print(f"FIGURE 4  raster: the bf_logic_or cache line over {n_iters} "
          f"loop iterations")
    print(f"  one column = {per_col:,.0f} cycles   "
          f"(loop period {period:,.0f} = {cols // n_iters} columns)")
    print()
    print("                 time ->")
    print("  bf_logic_or    |" + _raster_row(sig, t0, span, cols) + "|")

    ann = [" "] * cols
    wide_seen = 0
    for s, e in zip(breaks, ends):
        if e != s + 1:
            continue
        gap = win[e] - win[s]
        x = int((win[s] - t0) / per_col)
        is_wide = gap > median_gap
        if is_wide:
            k = anchor + wide_seen
            wide_seen += 1
            label = (f"WIDE bit={int(res['lsb_first'][idx[k]])}"
                     if k < len(idx) and valid[k] else "WIDE")
        else:
            label = "narrow"
        for j, ch in enumerate(label):
            if 0 <= x + j < cols:
                ann[x + j] = ch
    print("                 " + "".join(ann))
    print()


def folded(res, n_bits=20, cols=96, window=60_000):
    """Figure 5: one row per exponent bit, aligned on the wide pair.

    Each row starts at the first access of that bit's wide pair, so the second
    access lands further right exactly when the bit is 1.
    """
    starts, gaps = res["wide_start"], res["wide_gap"]
    idx, valid = res["idx"], res["valid"]
    lsb = res["lsb_first"]

    rows = np.where(valid & (idx >= 40))[0][:n_bits]
    per_col = window / cols

    print(f"FIGURE 5  the same wide pairs, stacked and aligned "
          f"(one row = one exponent bit)")
    print(f"  one column = {per_col:,.0f} cycles")
    print()
    print("   bit#  |" + " " * cols + "|  gap     true bit")
    for k in rows:
        row = [" "] * cols
        row[0] = "|"
        x = int(gaps[k] / per_col)
        if x < cols:
            row[x] = "|"
        bit = int(lsb[idx[k]])
        print(f"  {idx[k]:5d}  |{''.join(row)}|  {gaps[k]:6,.0f}   {bit}"
              f"{'   <-- wider' if bit else ''}")
    split = int(np.median(gaps) / per_col)
    ruler = [" "] * cols
    ruler[split] = "^"
    print("         |" + "".join(ruler) + "|  decision threshold (median)")
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", default="r0", help="trace name, e.g. r0")
    args = ap.parse_args()

    path = next(p for p in D.trace_paths() if p.name.startswith(args.trace))
    print(f"# figures for {path.name}\n")

    ts, _ = D.load_trace(path)
    timeline(ts)

    res = enrich(path)
    raster(path, res)
    folded(res)
    separation(res)
    along_trace(res)


if __name__ == "__main__":
    main()
