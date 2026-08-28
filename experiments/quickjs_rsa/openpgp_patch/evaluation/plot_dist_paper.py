#!/usr/bin/env python3
"""Paper figure: the patched `selectBigInt` still leaks the secret bit.

One violin panel per engine, the two violins being the `cond` values. Each
engine keeps its own y-axis, so the ~10x cross-engine cycle gap needs no
shared / log / broken axis. The paper prints the QuickJS panel alone and
without a caption; --engines and --annotate widen that back out. Reads the
`selectBigInt` CSVs written by run_eval.sh.

    venv/bin/python plot_dist_paper.py        # -> ../results/selectbigint_timing_99.pdf
    venv/bin/python plot_dist_paper.py --export html,svg   # also emit HTML + SVG
"""
import argparse
import math
import os

import numpy as np
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots


# ---- analysis --------------------------------------------------------------
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


# ---- figure ---------------------------------------------------------------
# Per-secret-bit palette.
COND_COLOR = {0: "#1071e5", 1: "#fc9432"}    # CornflowerBlue / BurntOrange
VIOLIN_CAT = {0: "cond = 0", 1: "cond = 1"}  # x-axis categories
COND_LABEL = {0: "secret bit = 0", 1: "secret bit = 1"}

# Engines and panel titles.
PANELS = [("quickjs", "QuickJS - Interpreter"), ("v8", "V8 - JIT (TurboFan)")]
# The paper prints the QuickJS panel alone; --engines widens it back out.
PAPER_ENGINES = ["quickjs"]

# Analysis + figure constants (edit here if needed).
TRIM_PCT = 1.0       # drop this % upper tail per group
TRIM_ABOVE = None    # or an absolute cycle cap
WARMUP = 200         # discard first N samples
WIDTH, HEIGHT = 400, 250


def _rgba(hexc, a):
    h = hexc.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{a})"


def _darken(hexc, f):
    """Scale an #rrggbb colour toward black by factor f (0=black, 1=unchanged)."""
    h = hexc.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgb({int(r * f)},{int(g * f)},{int(b * f)})"


def build_violin(cells, annotate=False):
    """cells: list of (title, res); one violin panel per engine.

    Each violin carries a thin, unfilled Tukey box (median + IQR) inside it.
    """
    cells = sorted(cells, key=lambda c: c[1]["median0"])  # smaller cycles left
    rng = np.random.default_rng(0)
    fig = make_subplots(rows=1, cols=len(cells), horizontal_spacing=0.13)
    for col, (title, res) in enumerate(cells, start=1):
        groups = [(c, a) for c, a in ((0, res["x0"]), (1, res["x1"])) if len(a)]
        # Clip the thin outlier tails so the bodies aren't squashed into spikes,
        # and crop the y-axis to the kept range.
        lo = min(np.percentile(a, 0.5) for _, a in groups)
        hi = max(np.percentile(a, 99.5) for _, a in groups)
        for cond, arr in groups:
            a = arr[(arr >= lo) & (arr <= hi)]
            if len(a) > 25000:
                a = rng.choice(a, 25000, replace=False)
            fig.add_trace(go.Violin(
                y=a, x=[VIOLIN_CAT[cond]] * len(a), name=COND_LABEL[cond],
                showlegend=False,
                fillcolor=_rgba(COND_COLOR[cond], 0.30),
                line=dict(color=COND_COLOR[cond], width=1.2),
                width=0.85, points=False, spanmode="hard",
                box=dict(visible=True, width=0.05, fillcolor="rgba(0,0,0,0)",
                         line=dict(color=_darken(COND_COLOR[cond], 0.5), width=1.2)),
                meanline_visible=False,
                hovertemplate=f"{COND_LABEL[cond]}<br>cyc=%{{y:.0f}}<extra></extra>"),
                row=1, col=col)
        leak = "LEAK" if abs(res["auc"] - 0.5) > LEAK_AUC_MARGIN else "balanced"
        if annotate:
            fig.add_annotation(
                xref=f"x{'' if col == 1 else col} domain", x=0.5, yref="paper",
                y=1.0, xanchor="center", yanchor="bottom", showarrow=False,
                align="center", font=dict(size=11, color="black"),
                text=(f"<b>{title}</b><br>Δmedian {res['median_diff']:+.0f} cyc<br>"
                      f"AUC {res['auc']:.3f} <b>[{leak}]</b>"))
        margin = 0.06 * (hi - lo)
        fig.update_xaxes(row=1, col=col, showline=True, linecolor="black",
                         ticks="outside")
        fig.update_yaxes(title_text=("Execution Time (cycle)" if col == 1 else None),
                         row=1, col=col, range=[lo - margin, hi + margin],
                         showline=True, linecolor="black", ticks="outside",
                         showgrid=False)
    fig.update_layout(
        width=WIDTH, height=HEIGHT, template="plotly_white", violinmode="group",
        font=dict(family="Helvetica, Arial, sans-serif", size=12, color="black"),
        margin=dict(l=72, r=20, t=(64 if annotate else 16), b=52))
    return fig


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-d", "--data-dir",
                    default=os.path.join(here, os.pardir, "results"),
                    help="directory holding <engine>_selectBigInt.csv")
    ap.add_argument("--out-dir", default=os.path.join(here, os.pardir, "results"),
                    help="directory the figure is written to (created if absent)")
    ap.add_argument("--export", default="",
                    help="extra formats to also export besides the default PDF "
                         "(e.g. 'html', 'svg', 'html,svg'). PDF/SVG need system "
                         "chromium; HTML always works.")
    ap.add_argument("--engines", default=",".join(PAPER_ENGINES),
                    help="comma-separated engines to draw, one panel each "
                         f"(default {','.join(PAPER_ENGINES)}, as printed in the "
                         "paper; 'quickjs,v8' draws both)")
    ap.add_argument("--annotate", action="store_true",
                    help="add the per-panel Delta-median/AUC caption; off by "
                         "default because the paper's figure carries none")
    ap.add_argument("-o", "--out", default=None,
                    help="output basename inside the output dir "
                         "(default selectbigint_timing_99, the name the paper "
                         "includes)")
    args = ap.parse_args()

    titles = dict(PANELS)
    wanted = [e.strip() for e in args.engines.split(",") if e.strip()]
    unknown = [e for e in wanted if e not in titles]
    if unknown:
        raise SystemExit(f"unknown engine(s) {unknown}; choose from {list(titles)}")

    cells = []
    for engine in wanted:
        path = os.path.join(args.data_dir, f"{engine}_selectBigInt.csv")
        if not os.path.exists(path):
            raise SystemExit(f"missing {path} — run run_eval.sh first")
        cells.append((titles[engine], analyse(path, TRIM_PCT, WARMUP, TRIM_ABOVE)))

    fig = build_violin(cells, annotate=args.annotate)
    os.makedirs(args.out_dir, exist_ok=True)
    base = os.path.join(args.out_dir, args.out or "selectbigint_timing_99")
    # PDF by default; HTML/SVG opt-in via --export. Dedupe, keep order.
    formats, seen = [], set()
    for fmt in ["pdf", *(f.strip() for f in args.export.split(",") if f.strip())]:
        if fmt not in seen:
            seen.add(fmt)
            formats.append(fmt)
    for fmt in formats:
        out = f"{base}.{fmt}"
        try:
            if fmt == "html":
                fig.write_html(out, include_plotlyjs=True)
            else:
                fig.write_image(out, format=fmt, scale=2)
            print(f"[*] wrote {out}")
        except Exception as e:  # noqa: BLE001
            print(f"[i] {fmt.upper()} export skipped ({type(e).__name__}); "
                  "needs a system chromium on PATH (pacman -S chromium).")


if __name__ == "__main__":
    main()
