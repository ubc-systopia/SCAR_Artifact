"""Companion figure to `plot_gap_figure.py`: the distribution its two instances

were drawn from -- every wide-pair (`SELECT`) gap in the trace, i.e. every
`rint(r * x mod n)` -> `bf_logic_or` interval, split by the true key bit, as
violins with a thin Tukey box (median + IQR) inside each. It is what justifies
"typical" in the schematic figure: the two instances picked there sit at each
violin's median.

The gaps are `decoder.decode`'s own `gap`/`truth` arrays -- the same
index-aligned pairs `verify.py` scores each trace's published accuracy on, not
a separate recomputation. Whole-trace they overlap heavily (r0: correlation
+0.48, 77% at the best single threshold): each trace holds index phase over a
contiguous stretch and slips elsewhere, so misindexed gaps land against the
wrong truth bit. `--low 2048` keeps the stretch r0 holds phase over, where the
same gaps separate cleanly (correlation +0.82, 99.4%).

Same subfigure style as `openpgp_patch/plot_dist_paper.py`'s figure 4b, and the
same library/font/template/panel conventions (Helvetica/Arial, plotly_white,
400 wide, ticks-outside black-bordered panels). COND_COLOR is that script's own
per-secret-bit palette, shared with `plot_gap_figure.py` so the two figures read
as a matched pair. Tails beyond the 0.5/99.5 percentiles are trimmed.

    python3 plot_violin_figure.py [--trace r0] [--out ../results/figures/fig6_violin]
"""
import argparse
import concurrent.futures as cf
from pathlib import Path

import numpy as np
import plotly.graph_objects as go

import decoder as D
from plot_gap_figure import COND_COLOR, FONT, INK, _rgba

COND_CAT = {0: "cond = 0", 1: "cond = 1"}

WIDTH, HEIGHT = 400, 120


def pool_gap_arrays(pool_dir, low=0, jobs=8):
    """(x0, x1): SELECT gaps from the one-trace-per-key pool, split by key bit.

    The single-shot dataset -- one uniformly-random trace per key, built by
    make_one_trace_pool.py and scored by evaluate_pool.py. Each trace is split
    and indexed exactly as evaluate_pool.process_key does it (wide_narrow ->
    best_anchor -> assign_indices, degenerate traces dropped at
    MIN_WIDE_PAIRS), with the wide-pair gap kept alongside the index so the
    same pairs that produce that script's accuracy produce these violins.
    """
    import evaluate_pool as EP

    key_dirs = EP.find_key_dirs(pool_dir)
    x0, x1 = [], []
    with cf.ProcessPoolExecutor(max_workers=jobs) as ex:
        for key_id in sorted(key_dirs):
            paths = EP.trace_files(key_dirs[key_id])
            if not paths:
                continue
            lsb_first, _ = D.load_exponent(key_id)
            n_bits = len(lsb_first)
            for r in ex.map(EP._process_trace, paths):
                if r["degenerate"]:
                    continue
                start_t, wide_gap = r["start_t"], r["wide_gap"]
                anchor, _ = D.best_anchor(start_t, wide_gap, n_bits, lsb_first)
                idx, valid, _ = D.assign_indices(start_t, n_bits, anchor=anchor)
                bit_index, gap = idx[valid], wide_gap[valid]
                if low:
                    sel = bit_index < low
                    bit_index, gap = bit_index[sel], gap[sel]
                truth = lsb_first[bit_index]
                x0.append(gap[truth == 0])
                x1.append(gap[truth == 1])
    return np.concatenate(x0), np.concatenate(x1)


def gap_arrays(res, low=0):
    """(x0, x1): the evaluation's own (gap, truth) pairs, split by the key bit.

    Straight off `decoder.decode` -- `res["gap"]`/`res["truth"]` are the arrays
    `verify.py` scores its published per-trace accuracy on, index-aligned by the
    decoder, so this panel and that number describe the same data. `low` keeps
    only the lowest N exponent bits (`res["bit_index"]`), the stretch each trace
    holds phase over; see verify.EXPECTED_LOW.
    """
    gap, truth = res["gap"], res["truth"]
    if low:
        sel = res["bit_index"] < low
        gap, truth = gap[sel], truth[sel]
    return gap[truth == 0], gap[truth == 1]


def _darken(hexc, f):
    h = hexc.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgb({int(r * f)},{int(g * f)},{int(b * f)})"


def build_fig(x0, x1, trim=0.5):
    """`trim` drops tail mass before the y-axis is cropped to what is left --
    raise it when one group's tail is long enough to squash both bodies into
    the bottom of the panel. A scalar trims that percent off each tail; a
    (low, high) pair gives the two percentile bounds directly, so (0, 99)
    keeps the full lower tail and cuts only the top."""
    fig = go.Figure()
    groups = [(0, x0), (1, x1)]
    p_lo, p_hi = (trim, 100 - trim) if np.isscalar(trim) else trim
    lo = min(np.percentile(a, p_lo) for _, a in groups)
    hi = max(np.percentile(a, p_hi) for _, a in groups)
    for cond, arr in groups:
        a = arr[(arr >= lo) & (arr <= hi)]
        fig.add_trace(go.Violin(
            y=a, x=[COND_CAT[cond]] * len(a), name=f"cond={cond} gap",
            showlegend=False,
            fillcolor=_rgba(COND_COLOR[cond], 0.30),
            line=dict(color=COND_COLOR[cond], width=1.2),
            width=0.85, points=False, spanmode="hard",
            box=dict(visible=True, width=0.05, fillcolor="rgba(0,0,0,0)",
                     line=dict(color=_darken(COND_COLOR[cond], 0.5), width=1.2)),
            meanline_visible=False,
            hovertemplate=f"cond={cond}<br>cyc=%{{y:.0f}}<extra></extra>"))

    margin = 0.06 * (hi - lo)
    fig.update_xaxes(showline=True, linecolor=INK, linewidth=1, mirror=True,
                     ticks="outside")
    fig.update_yaxes(title_text="rint → or gap<br>(cycles)",
                     range=[lo - margin, hi + margin], showline=True,
                     linecolor=INK, linewidth=1, mirror=True, ticks="outside",
                     showgrid=False)
    fig.update_layout(
        width=WIDTH, height=HEIGHT, template="plotly_white",
        font=dict(family=FONT, size=12, color="black"),
        margin=dict(l=60, r=14, t=12, b=46),
        showlegend=False, violinmode="group",
        plot_bgcolor="white", paper_bgcolor="white")
    return fig


def main():
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trace", default="r0",
                    help="single trace to plot; ignored when --pool is given")
    ap.add_argument("--pool", default=None,
                    help="one-trace-per-key pool (make_one_trace_pool.py --out); "
                         "plots the pooled single-shot gaps instead of one trace")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--low", type=int, default=0,
                    help="restrict to the lowest N exponent bits (0 = all, "
                         "the whole-trace set the evaluation scores)")
    ap.add_argument("--out", default=str(here.parent / "results" / "figures"
                                         / "fig6_violin"),
                    help="output path stem; .svg, .png and .pdf are written")
    args = ap.parse_args()

    if args.pool:
        x0, x1 = pool_gap_arrays(Path(args.pool), low=args.low, jobs=args.jobs)
        res = None
    else:
        res = D.decode(D.TRACE_DIR / f"{args.trace}.out")
        x0, x1 = gap_arrays(res, low=args.low)

    fig = build_fig(x0, x1)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.write_image(str(out.with_suffix(".svg")))
    fig.write_image(str(out.with_suffix(".png")), scale=2)
    fig.write_image(str(out.with_suffix(".pdf")))
    tail = ""
    if res is not None:
        acc = float((res["predicted"] == res["truth"]).mean())
        tail = f", trace accuracy={acc:.4f}"
    print(f"[*] wrote {out}.svg / .png / .pdf  (median0={np.median(x0):,.0f} cyc, "
          f"median1={np.median(x1):,.0f} cyc, n0={len(x0)}, n1={len(x1)}{tail})")


if __name__ == "__main__":
    main()
