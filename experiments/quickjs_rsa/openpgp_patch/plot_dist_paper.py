#!/usr/bin/env python3
"""Paper figure: the patched `selectBigInt` leaks the secret bit on BOTH engines.

One violin panel per engine (V8, QuickJS), the two violins being the secret-bit
values. Each engine keeps its own y-axis, so the ~10x cross-engine cycle gap
needs no shared / log / broken axis. A per-panel caption reports Δmedian and the
single-sample distinguishability AUC. Reads the two `selectBigInt` CSVs written
by run_eval.sh; the analysis (trim, Mann-Whitney AUC) is reused from plot_dist.

    venv/bin/python plot_dist_paper.py        # -> results/selectBigInt_dist.pdf
    venv/bin/python plot_dist_paper.py --export html,svg   # also emit HTML + SVG
"""
import argparse
import os

import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from plot_dist import LEAK_AUC_MARGIN, analyse

# Per-secret-bit palette.
COND_COLOR = {0: "#1071e5", 1: "#fc9432"}    # CornflowerBlue / BurntOrange
VIOLIN_CAT = {0: "bit = 0", 1: "bit = 1"}    # x-axis categories
COND_LABEL = {0: "secret bit = 0", 1: "secret bit = 1"}

# Engines and panel titles.
PANELS = [("quickjs", "QuickJS - Interpreter"), ("v8", "V8 - JIT (TurboFan)")]

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


def build_violin(cells):
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
        fig.add_annotation(
            xref=f"x{'' if col == 1 else col} domain", x=0.5, yref="paper", y=1.0,
            xanchor="center", yanchor="bottom", showarrow=False, align="center",
            font=dict(size=11, color="black"),
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
        margin=dict(l=72, r=20, t=64, b=52))
    return fig


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-d", "--results-dir", default=os.path.join(here, "results"))
    ap.add_argument("--export", default="",
                    help="extra formats to also export besides the default PDF "
                         "(e.g. 'html', 'svg', 'html,svg'). PDF/SVG need system "
                         "chromium; HTML always works.")
    args = ap.parse_args()

    cells = []
    for engine, title in PANELS:
        path = os.path.join(args.results_dir, f"{engine}_selectBigInt.csv")
        if not os.path.exists(path):
            raise SystemExit(f"missing {path} — run run_eval.sh first")
        cells.append((title, analyse(path, TRIM_PCT, WARMUP, TRIM_ABOVE)))

    fig = build_violin(cells)
    base = os.path.join(args.results_dir, "selectBigInt_dist")
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
