"""Bokeh figures for EXPLANATION.md, generated from the shipped traces.

Writes a single standalone HTML file with five linked-panel figures:

  1. raster        the two watched cache lines against time, zoomed to a few
                   loop iterations -- the picture of the signal
  2. gap scales    every inter-access gap, showing the empty valley that
                   justifies the 100,000-cycle pair threshold
  3. per-bit gap   wide-pair gap against exponent-bit index, coloured by the
                   true key bit
  4. separation    the same gaps as two histograms, one per key bit
  5. along trace   accuracy per tenth of the trace, where it breaks down

Unlike decoder.py and figures.py this needs bokeh as well as numpy:

    pip install bokeh
    python3 plot_figures.py [--trace r0] [--out ../results/figures.html]
"""
import argparse
from pathlib import Path

import numpy as np
from bokeh.layouts import column
from bokeh.models import (ColumnDataSource, Div, HoverTool, Label, Span,
                          Whisker)
from bokeh.plotting import figure, output_file, save

import decoder as D
from figures import enrich

# Reference categorical palette, slots 1 and 2, used in fixed order.
BIT0 = "#2a78d6"   # blue
BIT1 = "#eb6834"   # orange
INK = "#0b0b0b"
MUTED = "#8a8985"
GRID = "#e8e8e4"
SURFACE = "#fcfcfb"


def style(p, ylabel=None):
    """Recessive axes and grid, per the chart anatomy rules."""
    p.background_fill_color = SURFACE
    p.border_fill_color = SURFACE
    p.outline_line_color = None
    p.xgrid.grid_line_color = None
    p.ygrid.grid_line_color = GRID
    p.ygrid.grid_line_width = 1
    p.axis.axis_line_color = GRID
    p.axis.major_tick_line_color = GRID
    p.axis.minor_tick_line_color = None
    p.axis.axis_label_text_color = MUTED
    p.axis.major_label_text_color = MUTED
    p.title.text_color = INK
    p.title.text_font_size = "13pt"
    if ylabel:
        p.yaxis.axis_label = ylabel
    return p


def fig_raster(path, res, n_iters=4, first_bit=40):
    """Figure 1: time on x, accesses to the watched cache line on y."""
    sig, _ = D.load_trace(path)

    period = res["period"]
    starts, gaps = res["wide_start"], res["wide_gap"]
    idx, valid, lsb = res["idx"], res["valid"], res["lsb_first"]

    anchor = int(np.where(valid & (idx >= first_bit))[0][0])
    t0 = starts[anchor] - 0.15 * period
    t1 = t0 + n_iters * period

    def rel(a):
        a = a[(a >= t0) & (a <= t1)]
        return (a - t0) / 1000.0        # kilocycles

    p = figure(height=200, sizing_mode="stretch_width",
               title="1. What the attacker records: the bf_logic_or cache "
                     f"line over {n_iters} loop iterations",
               x_axis_label="time (thousands of CPU cycles, relative)",
               y_range=(1.62, 2.72), tools="xpan,xwheel_zoom,reset",
               active_scroll="xwheel_zoom")
    style(p)
    p.yaxis.ticker = [2]
    p.yaxis.major_label_overrides = {2: "bf_logic_or"}
    p.ygrid.grid_line_color = None

    x = rel(sig)
    p.segment(x0=x, x1=x, y0=1.78, y1=2.22,
              line_color=BIT0, line_width=2, legend_label="bf_logic_or access")

    # Bracket each wide pair and label the bit it encodes.
    lo, hi = [], []
    for k in range(anchor, min(anchor + n_iters + 1, len(starts))):
        if not valid[k]:
            continue
        x0 = (starts[k] - t0) / 1000.0
        x1 = x0 + gaps[k] / 1000.0
        if x1 > (t1 - t0) / 1000.0:
            break
        bit = int(lsb[idx[k]])
        color = BIT1 if bit else BIT0
        p.quad(left=x0, right=x1, bottom=1.7, top=2.35,
               fill_color=color, fill_alpha=0.13, line_color=None)
        p.line([x0, x1], [2.42, 2.42], line_color=color, line_width=2)
        p.add_layout(Label(x=(x0 + x1) / 2, y=2.46, text=f"bit {bit}",
                           text_color=color, text_font_size="10pt",
                           text_align="center"))
        lo.append(x0)
        hi.append(x1)

    p.legend.background_fill_color = SURFACE
    p.legend.border_line_color = None
    p.legend.label_text_color = INK
    p.legend.orientation = "horizontal"
    p.add_layout(p.legend[0], "below")
    return p


def fig_gap_scales(path):
    """Figure 2: the two gap scales and the empty valley between them."""
    ts, _ = D.load_trace(path)
    lo, hi = D.signing_window(ts)
    gaps = np.diff(ts[(ts >= lo) & (ts <= hi)]) / 1000.0

    edges = np.linspace(0, 320, 161)
    counts, _ = np.histogram(gaps, bins=edges)
    src = ColumnDataSource(dict(left=edges[:-1], right=edges[1:],
                                top=np.maximum(counts, 0.7), count=counts))

    valley = float(((gaps > 35) & (gaps < 270)).mean())
    p = figure(height=260, sizing_mode="stretch_width", y_axis_type="log",
               title="2. Gaps between accesses are either small or large: "
                     f"only {valley:.1%} land in between",
               x_axis_label="gap to the next access (thousands of cycles)",
               tools="")
    style(p, "number of gaps (log)")
    p.quad(source=src, left="left", right="right", bottom=0.7, top="top",
           fill_color=BIT0, line_color=None, fill_alpha=0.85)
    p.add_tools(HoverTool(tooltips=[("gap", "@left{0.0}-@right{0.0}k cycles"),
                                    ("count", "@count")]))

    thr = D.PAIR_SPLIT_CYCLES / 1000.0
    p.add_layout(Span(location=thr, dimension="height", line_color=INK,
                      line_dash="dashed", line_width=2))
    p.add_layout(Label(x=thr + 4, y=0.9, text=(
        f"threshold {thr:.0f}k: left = inside a pair, right = between pairs"),
        text_color=INK, text_font_size="10pt", y_offset=-40))
    return p


def fig_per_bit(res, n_show=220):
    """Figure 3: wide-pair gap against bit index, coloured by the true bit."""
    idx, valid = res["idx"], res["valid"]
    gaps, lsb = res["wide_gap"], res["lsb_first"]

    sel = valid & (idx < n_show)
    bits = lsb[idx[sel]]
    src = ColumnDataSource(dict(x=idx[sel], y=gaps[sel] / 1000.0,
                                bit=[str(b) for b in bits],
                                color=[BIT1 if b else BIT0 for b in bits]))

    p = figure(height=300, sizing_mode="stretch_width",
               title=f"3. One dot per exponent bit: the gap alone separates "
                     f"0 from 1 (lowest {n_show} bits)",
               x_axis_label="exponent bit index (0 = least significant)",
               tools="pan,wheel_zoom,reset")
    style(p, "wide-pair gap (thousands of cycles)")
    p.scatter(source=src, x="x", y="y", size=9, fill_color="color",
              line_color=SURFACE, line_width=1, fill_alpha=0.9)
    p.add_tools(HoverTool(tooltips=[("bit index", "@x"), ("true bit", "@bit"),
                                    ("gap", "@y{0.00}k cycles")]))

    med = np.median(gaps) / 1000.0
    p.add_layout(Span(location=med, dimension="width", line_color=INK,
                      line_dash="dashed", line_width=2))
    p.add_layout(Label(x=2, y=med, text="decision threshold (median gap)",
                       text_color=INK, text_font_size="10pt", y_offset=16))
    p.x_range.end = n_show * 1.14
    for bit, color, dy in ((1, BIT1, 4), (0, BIT0, 4)):
        band = gaps[sel][bits == bit] / 1000.0
        p.add_layout(Label(x=n_show + 4, y=band.mean(), text=f"bit = {bit}",
                           text_color=color, text_font_size="11pt", y_offset=dy))
    return p


def fig_separation(res):
    """Figure 4: the same gaps as two histograms, low half vs whole exponent."""
    idx, valid = res["idx"], res["valid"]
    gaps, lsb = res["wide_gap"], res["lsb_first"]
    edges = np.linspace(26, 35, 46)

    plots = []
    for tag, title, sel in (
            ("4a", "lowest 2048 bits -- almost no overlap", valid & (idx < 2048)),
            ("4b", "all 4094 bits -- index assignment has failed in the "
                   "upper half", valid)):
        bits = lsb[idx[sel]]
        g = gaps[sel] / 1000.0
        p = figure(height=260, sizing_mode="stretch_width",
                   title=f"{tag}. Gap distribution by true key bit, {title}",
                   x_axis_label="wide-pair gap (thousands of cycles)", tools="")
        style(p, "number of bits")
        for bit, color in ((0, BIT0), (1, BIT1)):
            c, _ = np.histogram(g[bits == bit], bins=edges)
            p.quad(left=edges[:-1], right=edges[1:], bottom=0, top=c,
                   fill_color=color, fill_alpha=0.6, line_color=color,
                   line_width=1, legend_label=f"true bit = {bit}")
        p.legend.location = "top_right"
        p.legend.background_fill_color = SURFACE
        p.legend.border_line_color = GRID
        p.legend.label_text_color = INK
        r = np.corrcoef(g, bits)[0, 1]
        p.add_layout(Label(x=26.2, y=0, text=f"correlation {r:+.3f}",
                           text_color=MUTED, text_font_size="10pt",
                           y_offset=-30, y_units="screen"))
        plots.append(p)
    return plots


def fig_along_trace(res, parts=10):
    """Figure 5: accuracy per tenth of the trace."""
    gap, truth, pred = res["gap"], res["truth"], res["predicted"]
    n = len(gap)
    bounds = [(i * n // parts, (i + 1) * n // parts) for i in range(parts)]
    acc = np.array([(pred[a:b] == truth[a:b]).mean() for a, b in bounds])
    corr = np.array([np.corrcoef(gap[a:b], truth[a:b])[0, 1] for a, b in bounds])

    src = ColumnDataSource(dict(x=np.arange(1, parts + 1), acc=acc, corr=corr,
                                color=[BIT0 if a > 0.6 else MUTED for a in acc],
                                label=[f"{a:.3f}" for a in acc]))

    p = figure(height=300, sizing_mode="stretch_width",
               title="5. Accuracy along the trace: near-perfect until the bit "
                     "indexing loses sync, then chance",
               x_axis_label="part of trace (1 = lowest exponent bits)",
               y_range=(0.45, 1.03), tools="")
    style(p, "fraction of bits recovered correctly")
    p.vbar(source=src, x="x", top="acc", bottom=0.45, width=0.68,
           fill_color="color", line_color=None)
    p.text(source=src, x="x", y="acc", text="label", text_color=MUTED,
           text_font_size="9pt", text_align="center", y_offset=-8)
    p.add_tools(HoverTool(tooltips=[("part", "@x"), ("accuracy", "@acc{0.000}"),
                                    ("correlation", "@corr{+0.000}")]))
    p.add_layout(Span(location=0.5, dimension="width", line_color=INK,
                      line_dash="dashed", line_width=2))
    p.add_layout(Label(x=parts + 0.35, y=0.5, text="chance", text_color=INK,
                       text_font_size="10pt", y_offset=-14))
    p.x_range.end = parts + 1.1
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", default="r0")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    path = next(p for p in D.trace_paths() if p.name.startswith(args.trace))
    out = Path(args.out) if args.out else (
        Path(__file__).resolve().parents[1] / "results" /
        f"figures_{args.trace}.html")
    out.parent.mkdir(parents=True, exist_ok=True)

    res = enrich(path)

    header = Div(text=f"""
      <div style="font:14px/1.6 system-ui,sans-serif;color:{INK};
                  max-width:70em;padding:8px 4px 0">
        <h1 style="font-size:22px;margin:0 0 6px">Prime+Scope against
          OpenPGP.js's branchless RSA exponent selection</h1>
        <p style="color:{MUTED};margin:0">Every figure is computed from
          <code>data/traces/{path.name}</code> &mdash; one signature, one
          RSA-4096 key. Figures 1 and 3 pan and zoom.</p>
      </div>""", sizing_mode="stretch_width")

    items = [header, fig_raster(path, res), fig_gap_scales(path),
             fig_per_bit(res), *fig_separation(res), fig_along_trace(res)]

    output_file(out, title=f"SELECT leak figures ({path.name})", mode="inline")
    save(column(*items, sizing_mode="stretch_width",
                background=SURFACE))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
