"""Two runtime figures in the `plot_violin_figure.py` style, split by the bit.

    sqm     one square-and-multiply loop iteration, end to end, measured from
            the trace: the ~611,000 cycles from one SELECT pair to the next
            (multiply + SELECT + square + narrow). This is what a total-time
            attacker sees. The bit moves it by ~1,700 cycles out of 611,000,
            so the violins sit on top of each other -- the point being that
            the leak is *not* in the runtime of the iteration.

    select  `selectBigInt` itself, timed directly in the engine rather than
            through the cache: openpgp_patch/bench.mjs's `cond,cycles` CSV,
            rdtscp around each call. Same quantity plot_dist_paper.py's
            figure 4b plots, restyled to match these figures.

Both use build_fig from plot_violin_figure (same palette, Tukey box, 0.5/99.5
percentile trim, cond = 0 / cond = 1 categories).

    python3 plot_runtime_figures.py sqm    [--trace r0]
    python3 plot_runtime_figures.py select [--csv ../../openpgp_patch/results/quickjs_selectBigInt.csv]
"""
import argparse
from pathlib import Path

import numpy as np

import decoder as D
from figures import enrich
from plot_violin_figure import build_fig

# Iteration periods longer than this are trace dropouts (a missed pair merges
# two iterations), not slow iterations; same spirit as figures.anatomy's
# 400,000-cycle cut on the between-pair gap.
MAX_PERIOD = 1_000_000

# ... and a spurious extra pair splits one iteration in two, giving roughly
# half a period. Both artefacts are trace defects, so cut them symmetrically.
MIN_PERIOD = 400_000

# bench.mjs's first samples run before the interpreter's inline caches settle;
# plot_dist.py discards the same count.
WARMUP = 200


def sqm_arrays(trace):
    """(x0, x1): full loop-iteration times from one trace, split by key bit.

    The period is SELECT-pair start to the next SELECT-pair start, so it spans
    exactly one pass of the square-and-multiply loop and is attributed to the
    bit that pass consumed.
    """
    res = enrich(D.TRACE_DIR / f"{trace}.out")
    start_t, idx, valid = res["wide_start"], res["idx"], res["valid"]
    period = np.diff(start_t).astype(float)
    ok = valid[:-1]
    period, truth = period[ok], res["lsb_first"][idx[:-1][ok]]
    keep = (period > MIN_PERIOD) & (period < MAX_PERIOD)
    period, truth = period[keep], truth[keep]
    return period[truth == 0], period[truth == 1]


def select_arrays(csv_path):
    """(x0, x1): per-call `selectBigInt` cycle counts, split by the cond bit."""
    rows = [ln for ln in Path(csv_path).read_text().splitlines()
            if ln and not ln.startswith("#")]
    data = np.array([[int(v) for v in ln.split(",")] for ln in rows[1:]],
                    dtype=float)[WARMUP:]
    cond, cyc = data[:, 0], data[:, 1]
    return cyc[cond == 0], cyc[cond == 1]


def main():
    here = Path(__file__).resolve().parent
    figs = here.parent / "results" / "figures"
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("what", choices=("sqm", "select"))
    ap.add_argument("--trace", default="r0", help="sqm: which trace")
    ap.add_argument("--csv", default=str(here.parent.parent.parent / "openpgp_patch"
                                         / "results" / "quickjs_selectBigInt.csv"),
                    help="select: bench.mjs output CSV")
    ap.add_argument("--trim", type=float, nargs="+", default=None,
                    help="one value trims that percent off each tail; two give "
                         "the low/high percentile bounds (e.g. --trim 0 99). "
                         "Default: 0 99 for select, 0.5 for sqm")
    ap.add_argument("--out", default=None, help="output path stem")
    args = ap.parse_args()
    # selectBigInt's cond=1 group has a long upper tail (99th at 11,252
    # against a 9,804 median); trimming it symmetrically at 0.5% stretches the
    # axis to 13,700 and flattens both bodies, so cut the top only.
    if args.trim is None:
        args.trim = (0.0, 99.0) if args.what == "select" else 0.5
    elif len(args.trim) == 1:
        args.trim = args.trim[0]
    else:
        args.trim = tuple(args.trim[:2])

    if args.what == "sqm":
        x0, x1 = sqm_arrays(args.trace)
        title = "iteration time<br>(cycles)"
        out = Path(args.out or figs / "fig6_runtime_sqm")
    else:
        x0, x1 = select_arrays(args.csv)
        title = "exec. time<br>(cycles)"
        out = Path(args.out or figs / "fig6_runtime_select")

    fig = build_fig(x0, x1, trim=args.trim)
    fig.update_yaxes(title_text=title)
    fig.update_layout(margin=dict(l=72, r=14, t=12, b=46))
    out.parent.mkdir(parents=True, exist_ok=True)
    for ext, kw in ((".svg", {}), (".png", {"scale": 2}), (".pdf", {})):
        fig.write_image(str(out.with_suffix(ext)), **kw)

    g = np.concatenate([x0, x1])
    t = np.concatenate([np.zeros(len(x0)), np.ones(len(x1))])
    print(f"[*] wrote {out}.svg / .png / .pdf  "
          f"(median0={np.median(x0):,.0f} cyc, median1={np.median(x1):,.0f} cyc, "
          f"delta={np.median(x1) - np.median(x0):+,.0f}, "
          f"corr={np.corrcoef(g, t)[0, 1]:+.3f}, n0={len(x0)}, n1={len(x1)})")


if __name__ == "__main__":
    main()
