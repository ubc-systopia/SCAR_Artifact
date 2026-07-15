#!/usr/bin/env python3
"""Analyse & plot the rdtscp timing data collected by run_eval.sh (plotly).

For every (engine, impl) CSV under ./results it:
  * splits per-call cycle counts by the secret bit `cond` (0/1),
  * trims interrupt/GC tails robustly,
  * computes a leakage / distinguishability summary
        - median and trimmed-mean difference (cond=1 - cond=0)
        - Mann-Whitney U p-value (tie-corrected normal approximation)
        - AUC = P(t_{cond=1} > t_{cond=0})   (0.5 = no leak, 1.0 = perfectly
          distinguishable from a single timing sample),
  * draws overlaid cond=0 vs cond=1 distributions with a Gaussian-KDE curve
    overlay (2x2: engines x selection functions).

Output:
  results/leakage_summary.csv      machine-readable stats
  results/distribution.html        interactive plotly figure (always; no browser needed)
  results/distribution.{svg,pdf}   static vector export, opt-in via --export
                                   (best effort; needs kaleido)

Usage:  python plot_dist.py [-d results_dir] [--trim-pct 1.0] [--trim-above CYCLES]
                            [--warmup 200] [--export svg,pdf]
"""
import argparse
import math
import os

import numpy as np
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Engine / selection-function display order and colours.
ENGINES = ["quickjs", "v8"]
SEL_FUNCS = ["ternary", "selectBigInt"]
SEL_FUNC_LABEL = {
    "ternary": "ternary (original: r = lsb ? rx : r)",
    "selectBigInt": "selectBigInt (patched constant-time)",
}
COND_COLOR = {0: "#1f77b4", 1: "#d62728"}  # blue=cond0, red=cond1
COND_HOVER_BG = {0: "#ffffff", 1: "#ffffff"}  # white hover box (black text below)

# A run is flagged as leaking only if the single-sample distinguishability is
# well clear of chance. 0.1 leaves headroom over the quantization noise that
# nudges the non-leaking control off 0.5 (heavily-discretized ~hundred-cycle
# reference returns), while the real leaks sit at AUC ~1.0.
LEAK_AUC_MARGIN = 0.1


def load_csv(path):
    """Return (cond array, cycles array) skipping the '#' header line."""
    df = pd.read_csv(path, comment="#")
    return df["cond"].to_numpy(), df["cycles"].to_numpy(dtype=float)


def trim(x, pct):
    """Drop samples above the (100-pct) percentile to remove interrupt tails."""
    if len(x) == 0:
        return x
    hi = np.percentile(x, 100.0 - pct)
    return x[x <= hi]


def _rankdata_avg(a):
    """Average ranks (1-based) with tie handling — scipy.rankdata equivalent."""
    a = np.asarray(a)
    sorter = np.argsort(a, kind="mergesort")
    inv = np.empty(len(a), dtype=np.intp)
    inv[sorter] = np.arange(len(a))
    a_sorted = a[sorter]
    obs = np.r_[True, a_sorted[1:] != a_sorted[:-1]]
    dense = obs.cumsum()[inv]
    counts = np.r_[np.flatnonzero(obs), len(a)]
    return 0.5 * (counts[dense] + counts[dense - 1] + 1)


def gaussian_kde(x, xs):
    """Evaluate a Gaussian KDE of `x` at points `xs`.

    Scott's-rule bandwidth (bw = n^(-1/5) * std, ddof=1) — identical to
    scipy.stats.gaussian_kde's default in 1-D, reimplemented in numpy because
    scipy doesn't build on this Python.
    """
    x = np.asarray(x, dtype=float)
    n = len(x)
    if n < 2:
        return np.zeros_like(xs)
    bw = n ** (-1.0 / 5.0) * np.std(x, ddof=1)
    if bw <= 0:
        return np.zeros_like(xs)
    u = (xs[:, None] - x[None, :]) / bw
    k = np.exp(-0.5 * u * u) / math.sqrt(2.0 * math.pi)
    return k.sum(axis=1) / (n * bw)


def auc_distinguish(x0, x1):
    """AUC = P(X1 > X0) via Mann-Whitney U, plus a tie-corrected normal p-value.

    AUC = 0.5 means the secret bit cannot be told from a single timing sample;
    AUC -> 1.0 (or 0.0) means perfect single-shot distinguishability.
    """
    n0, n1 = len(x0), len(x1)
    if n0 == 0 or n1 == 0:
        return float("nan"), float("nan")
    allv = np.concatenate([x0, x1])
    ranks = _rankdata_avg(allv)
    u1 = ranks[n0:].sum() - n1 * (n1 + 1) / 2.0
    auc = u1 / (n0 * n1)

    n = n0 + n1
    _, tie_counts = np.unique(allv, return_counts=True)
    tie = float(np.sum(tie_counts ** 3 - tie_counts))
    mu = n0 * n1 / 2.0
    var = (n0 * n1 / 12.0) * ((n + 1) - tie / (n * (n - 1)))
    if var <= 0:
        return auc, float("nan")
    z = (u1 - mu) / math.sqrt(var)
    p = math.erfc(abs(z) / math.sqrt(2.0))  # two-sided
    return auc, p


def analyse(path, trim_pct, warmup, trim_above=None):
    cond, cyc = load_csv(path)
    cond, cyc = cond[warmup:], cyc[warmup:]  # drop cold/JIT-warmup transient
    if trim_above is not None:  # hard cycle cap (drop interrupt/GC spikes)
        keep = cyc <= trim_above
        cond, cyc = cond[keep], cyc[keep]
    x0 = trim(cyc[cond == 0], trim_pct)
    x1 = trim(cyc[cond == 1], trim_pct)
    auc, p = auc_distinguish(x0, x1)
    return {
        "x0": x0, "x1": x1, "n0": len(x0), "n1": len(x1),
        "median0": float(np.median(x0)) if len(x0) else float("nan"),
        "median1": float(np.median(x1)) if len(x1) else float("nan"),
        "mean0": float(np.mean(x0)) if len(x0) else float("nan"),
        "mean1": float(np.mean(x1)) if len(x1) else float("nan"),
        "median_diff": (float(np.median(x1)) - float(np.median(x0)))
        if len(x0) and len(x1) else float("nan"),
        "auc": auc, "mwu_p": p,
    }


def add_panel(fig, res, show_legend, row=None, col=None,
              anno_x=0.97, anno_xanchor="right"):
    """Overlaid cond=0/cond=1 histograms + KDE for one (engine, sel_func) cell.

    With row/col it draws into a make_subplots grid cell; with row=col=None it
    draws into a standalone single-axis figure (used by --split).
    anno_x/anno_xanchor place the stats box (top-right by default; --split moves
    it top-left so it doesn't sit under the in-axes legend).
    """
    loc = {} if row is None else dict(row=row, col=col)
    x0, x1 = res["x0"], res["x1"]
    both = np.concatenate([x0, x1]) if len(x0) and len(x1) else np.array([0.0, 1.0])
    bins = np.histogram_bin_edges(both, bins=80)
    xs = np.linspace(both.min(), both.max(), 400)  # KDE eval grid
    for cond, x in ((0, x0), (1, x1)):
        if len(x) == 0:
            continue
        h, edges = np.histogram(x, bins=bins, density=True)
        centers = 0.5 * (edges[:-1] + edges[1:])
        fig.add_trace(
            go.Bar(
                x=centers, y=h,
                width=(edges[1] - edges[0]),
                marker_color=COND_COLOR[cond],
                opacity=0.55,
                name=f"cond={cond}",
                legendgroup=f"cond{cond}",
                showlegend=show_legend,
                hovertemplate=f"cond={cond}<br>cyc=%{{x:.0f}}<br>density=%{{y:.2e}}<extra></extra>",
                # light-tinted hover box with black text (default is the full
                # trace colour + white text, which the user found hard to read).
                hoverlabel=dict(
                    bgcolor=COND_HOVER_BG[cond],
                    bordercolor=COND_COLOR[cond],
                    font=dict(color="black"),
                ),
            ),
            **loc,
        )
        # Smooth Gaussian-KDE overlay (matches the original plot.py curve).
        fig.add_trace(
            go.Scatter(
                x=xs, y=gaussian_kde(x, xs),
                mode="lines",
                line=dict(color=COND_COLOR[cond], width=2),
                legendgroup=f"cond{cond}",
                showlegend=False,
                hoverinfo="skip",
            ),
            **loc,
        )
    leak = "LEAK" if abs(res["auc"] - 0.5) > LEAK_AUC_MARGIN else "balanced"
    fig.add_annotation(
        xref="x domain", yref="y domain",
        x=anno_x, y=0.97, xanchor=anno_xanchor, yanchor="top", showarrow=False,
        align=anno_xanchor, font=dict(size=11),
        text=(f"Δmedian = {res['median_diff']:+.0f} cyc<br>"
              f"AUC = {res['auc']:.3f} <b>[{leak}]</b>"),
        bgcolor="rgba(255,255,255,0.7)",
        **loc,
    )


def write_outputs(fig, rdir, basename, img_formats):
    """Write <basename>.html plus each requested static image (best effort)."""
    html = os.path.join(rdir, f"{basename}.html")
    fig.write_html(html, include_plotlyjs=True)
    print(f"[*] wrote {html}")
    # kaleido drives a headless chromium: works on x86 (leapx02, kaleido 0.2.1)
    # but its bundled chromium segfaults on the aarch64 dev box, so images are
    # exported only where possible — the HTML always works.
    for fmt in img_formats:
        out = os.path.join(rdir, f"{basename}.{fmt}")
        try:
            fig.write_image(out, format=fmt, scale=2)
            print(f"[*] wrote {out}")
        except Exception as e:  # noqa: BLE001
            print(f"[i] {fmt.upper()} export of {basename} skipped "
                  f"({type(e).__name__}). Render on an x86 host with kaleido.")


def _subset(arg, allowed, what):
    """Parse a comma-separated subset arg, validated against `allowed`."""
    sel = [s.strip() for s in arg.split(",") if s.strip()]
    bad = [s for s in sel if s not in allowed]
    if bad:
        raise SystemExit(f"unknown {what}: {', '.join(bad)} (choose from {', '.join(allowed)})")
    return sel


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("-d", "--results-dir", default=os.path.join(here, "results"))
    ap.add_argument("--trim-pct", type=float, default=1.0,
                    help="drop this %% upper tail per group (default 1.0)")
    ap.add_argument("--trim-above", type=float, default=None, metavar="CYCLES",
                    help="drop samples with rdtscp cycles above this absolute "
                         "threshold (applied before --trim-pct; default off)")
    ap.add_argument("--warmup", type=int, default=200,
                    help="discard first N samples (default 200)")
    ap.add_argument("--export", default="",
                    help="comma-separated static formats to also export besides "
                         "the always-written HTML, best-effort (default none; "
                         "needs kaleido's bundled chromium). e.g. 'svg', 'pdf', "
                         "'svg,pdf'")
    ap.add_argument("--engines", default=",".join(ENGINES),
                    help=f"comma-separated subset of {{{','.join(ENGINES)}}} to plot")
    ap.add_argument("--sel", default=",".join(SEL_FUNCS),
                    help=f"comma-separated subset of selection functions "
                         f"{{{','.join(SEL_FUNCS)}}} to plot "
                         "(e.g. --sel selectBigInt for just the patched one)")
    ap.add_argument("--split", action="store_true",
                    help="emit each (engine,sel_func) panel as its own file "
                         "distribution_<engine>_<sel_func>.* instead of one 2x2 grid")
    args = ap.parse_args()
    rdir = args.results_dir
    engines = _subset(args.engines, ENGINES, "engine")
    sel_funcs = _subset(args.sel, SEL_FUNCS, "sel_func")
    img_formats = [f.strip() for f in args.export.split(",") if f.strip()]

    # ---- analyse every selected (engine, sel_func) cell that has data ----
    rows = []
    cells = []  # (engine, sel_func, res) in display order, present files only
    for engine in engines:
        for sf in sel_funcs:
            path = os.path.join(rdir, f"{engine}_{sf}.csv")
            if not os.path.exists(path):
                print(f"[!] missing {path}, skipping")
                continue
            res = analyse(path, args.trim_pct, args.warmup, args.trim_above)
            cells.append((engine, sf, res))
            rows.append({
                "engine": engine, "sel_func": sf, "n0": res["n0"], "n1": res["n1"],
                "median0_cyc": round(res["median0"], 1),
                "median1_cyc": round(res["median1"], 1),
                "median_diff_cyc": round(res["median_diff"], 1),
                "mean_diff_cyc": round(res["mean1"] - res["mean0"], 1),
                "auc": round(res["auc"], 4), "mwu_p": res["mwu_p"],
                "leaks": abs(res["auc"] - 0.5) > LEAK_AUC_MARGIN,
            })

    # ---- summary table (always over the selected subset) ----
    summary = pd.DataFrame(rows)
    pd.set_option("display.width", 200)
    print("\n=== Timing-leakage summary (cond = secret exponent bit) ===")
    print(summary.to_string(index=False))
    out_csv = os.path.join(rdir, "leakage_summary.csv")
    summary.to_csv(out_csv, index=False)
    print(f"\n[*] wrote {out_csv}")

    if not cells:
        print("[!] no data to plot")
        return

    if args.split:
        # ---- one standalone figure per panel ----
        for engine, sf, res in cells:
            fig = go.Figure()
            # legend above the plot (like the grid figure); stats box top-right.
            add_panel(fig, res, show_legend=True)
            fig.update_layout(
                barmode="overlay", bargap=0, width=640, height=460,
                template="plotly_white",
                title=f"{engine} · {SEL_FUNC_LABEL[sf]}",
                xaxis_title="rdtscp cycles", yaxis_title="density",
                legend=dict(orientation="h", yanchor="bottom", y=1.02,
                            xanchor="right", x=1),
            )
            write_outputs(fig, rdir, f"distribution_{engine}_{sf}", img_formats)
    else:
        # ---- one combined grid over the selected subset ----
        fig = make_subplots(
            rows=len(engines), cols=len(sel_funcs),
            subplot_titles=[f"{e} · {SEL_FUNC_LABEL[s]}"
                            for e in engines for s in sel_funcs],
            horizontal_spacing=0.08, vertical_spacing=0.13,
        )
        first = True
        for engine, sf, res in cells:
            r = engines.index(engine) + 1
            c = sel_funcs.index(sf) + 1
            add_panel(fig, res, show_legend=first, row=r, col=c)
            first = False
            fig.update_xaxes(title_text="rdtscp cycles", row=r, col=c)
            fig.update_yaxes(title_text="density", row=r, col=c)
        fig.update_layout(
            barmode="overlay", bargap=0,
            width=590 * len(sel_funcs), height=380 * len(engines),
            template="plotly_white",
            title=("OpenPGP.js constant-time modExp patch — rdtscp timing of the "
                   "selection step (cond = secret exponent bit)"),
            legend=dict(orientation="h", yanchor="bottom", y=1.06, xanchor="right", x=1),
        )
        write_outputs(fig, rdir, "distribution", img_formats)


if __name__ == "__main__":
    main()
