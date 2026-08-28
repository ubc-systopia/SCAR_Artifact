"""Small paper figure: the SELECT gap, split by the true key bit.

One lane per value of the secret bit, and one real loop iteration per lane --
a single instance, not a distribution. Every marker is coloured by bit (same
per-bit hue as the shaded span), shaped by which libbf call it is: filled for
`bf_rint`, hollow for `bf_logic_or`, in the order the loop makes them -- one
extra leading `rint` dot for the previous iteration's `x * x mod n` (for
context), then `rint`, `rint`, `or`, `rint`, `rint` for the depicted
iteration itself. Both iterations are picked from the same trace, each one's
wide-pair gap equal to that bit's median, so the panel shows a typical
instance, not a cherry-picked one. The shaded span and the bracket both mark
the interval the attacker measures, `rint(r * x mod n)` to `or`, i.e. all of
`SELECT`; the bracket label rounds to the nearest 1,000 cycles.

The two modular multiplications either side of `SELECT` are ~278,000 cycles
each, nine times the interval that carries the bit, so they are drawn
compressed and marked as such; everything between the bracketed endpoints,
and the leading segment back to the previous iteration's last dot, is at
true scale.

Built with plotly, same library/font/template/panel conventions as
`openpgp_patch/plot_dist_paper.py` (Helvetica/Arial, plotly_white, 400 wide,
ticks-outside black-bordered panels). COND_COLOR is that script's own
per-secret-bit palette, so the two figures read as a matched pair.

    python3 plot_gap_figure.py [--trace r0] [--out ../results/figures/fig6_gap]
"""
import argparse
import math
from pathlib import Path

import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots

import decoder as D
from figures import enrich

# Per-secret-bit palette, verbatim from openpgp_patch/plot_dist_paper.py.
COND_COLOR = {0: "#1071e5", 1: "#fc9432"}
INK = "#000000"
MUTED = "#666666"
FAINT = "#bbbbbb"
ITER_COLOR = "#d62728"            # marks one loop iteration's start/end
FONT = "Helvetica, Arial, sans-serif"

WIDTH, HEIGHT = 400, 118
LANE_Y = {0: 0.60, 1: -0.10}      # bit=0 lane on top, bit=1 below
LEAD = 0.02                       # axis-fraction gap before the first dot
SLACK = 0.025                      # line overhang past the first/last dot, showing it continues
BREAK_FRAC = 0.10                 # x-fraction given to each compressed multiply
XMAX = 34_000                     # cycles at the right end of the true-scale part
LEGEND_X0 = 0.83                  # legend column sits to the right of the lanes

# Median cycles from rint(x*x % n) to the next rint(exp >>= 1n): the narrow
# pair, drawn after the second compressed stretch (and, mirrored, before the
# first dot to give the previous iteration's last access). Measured,
# analysis/figures.py.
NARROW_CYCLES = 25_564


def gap_arrays(res):
    """(x0, x1): every wide-pair (SELECT) gap in the trace, split by true bit."""
    gap, idx, valid, lsb = (res["wide_gap"], res["idx"], res["valid"],
                            res["lsb_first"])
    truth = lsb[idx[valid]]
    kept = gap[valid]
    return kept[truth == 0], kept[truth == 1]


def typical_gaps(x0, x1):
    """{0: gap, 1: gap} -- one real iteration per bit, picked as the instance

    closest to that bit's median gap. A single instance, not a distribution;
    "typical" only in the sense of not being a cherry-picked outlier.
    """
    out = {}
    for bit, arr in ((0, x0), (1, x1)):
        out[bit] = float(arr[np.argmin(np.abs(arr - np.median(arr)))])
    return out


def _rgba(hexc, a):
    h = hexc.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{a})"


def add_schematic(fig, gaps, row):
    """One real loop iteration per bit lane, bracketed on SELECT."""
    x_prev = LEAD                                # rint(x * x mod n), previous iteration
    x_end = LEGEND_X0 - 0.04                      # last dot of the lane, legend sits past it
    # The leading segment (x_prev -> x_a) is true scale like the trailing one
    # (x_sq1 -> x_lane_end), not compressed -- solved so x_lane_end lands on
    # x_end: x_lane_end - x_prev = 2*BREAK_FRAC + scale*(XMAX + 2*NARROW_CYCLES).
    scale = (x_end - x_prev - 2 * BREAK_FRAC) / (XMAX + 2 * NARROW_CYCLES)
    x_a = x_prev + scale * NARROW_CYCLES         # rint(exp >>= 1n)
    x_b = x_a + BREAK_FRAC                       # rint(r * x mod n) -- bracket opens

    def sx(cycles):
        return x_b + scale * cycles

    loc = dict(row=row, col=1)

    # ---- legend, to the right of the lanes ----------------------------------
    # A real plotly legend anchors to the whole figure (paper coordinates), not
    # a subplot, so it can't sit between bit=0 and bit=1; draw it by hand,
    # stacked vertically past the right end of the lanes, centred between them.
    legend_mid_y = (LANE_Y[0] + LANE_Y[1]) / 2
    for ly, symbol, label in ((legend_mid_y + 0.14, "circle", "bf_rint"),
                              (legend_mid_y - 0.14, "circle-open", "bf_logic_or")):
        fig.add_trace(go.Scatter(x=[LEGEND_X0], y=[ly], mode="markers",
                                 showlegend=False,
                                 marker=dict(symbol=symbol, size=8, color=INK,
                                            line=dict(width=1.4, color=INK))),
                     **loc)
        fig.add_annotation(x=LEGEND_X0 + 0.03, y=ly, text=label, showarrow=False,
                          font=dict(size=11, color=INK), xanchor="left",
                          yanchor="middle", **loc)

    # Bit-independent: the same x for both lanes.
    x_sq0, x_sq1 = sx(XMAX), sx(XMAX) + BREAK_FRAC
    x_lane_end = sx(XMAX + NARROW_CYCLES) + BREAK_FRAC

    for bit in (0, 1):
        y = LANE_Y[bit]
        gap = gaps[bit]

        # Lane line, with a little overhang past the first/last dot -- the
        # loop continues in both directions, this is just one iteration of it.
        fig.add_shape(type="line", x0=x_prev - SLACK, x1=x_lane_end + SLACK,
                     y0=y, y1=y, line=dict(color=FAINT, width=1),
                     layer="below", **loc)

        # Shade the measured interval -- the two points of interest, rint(r*x
        # mod n) to or -- in that bit's hue.
        fig.add_shape(type="rect", x0=x_b, x1=sx(gap), y0=y - 0.09, y1=y + 0.09,
                     fillcolor=_rgba(COND_COLOR[bit], 0.30), line=dict(width=0),
                     layer="below", **loc)

        # Compressed stretches: the two modular multiplications.
        for xm in ((x_a + x_b) / 2, (x_sq0 + x_sq1) / 2):
            for dx in (-0.006, 0.006):
                fig.add_shape(type="line", x0=xm + dx - 0.006, x1=xm + dx + 0.006,
                             y0=y - 0.05, y1=y + 0.05, line=dict(color=FAINT,
                                                                width=1.1), **loc)

        # The five accesses of one real loop iteration -- plus a leading dot
        # for the previous iteration's last access, for context -- in that
        # bit's colour, same per-bit hue as the shaded span.
        colour = COND_COLOR[bit]
        xs_rint = [x_prev, x_a, x_b, x_sq1, x_lane_end]
        fig.add_trace(go.Scatter(x=xs_rint, y=[y] * len(xs_rint), mode="markers",
                                 showlegend=False,
                                 marker=dict(symbol="circle", size=8,
                                            color=colour)), **loc)
        fig.add_trace(go.Scatter(x=[sx(gap)], y=[y], mode="markers",
                                 showlegend=False,
                                 marker=dict(symbol="circle-open", size=8,
                                            color=colour,
                                            line=dict(width=1.4, color=colour))),
                     **loc)

        # Bracket on the measured interval: two ticks + a connecting line.
        tick_y0, tick_y1 = y - 0.14, y - 0.22
        for xt in (x_b, sx(gap)):
            fig.add_shape(type="line", x0=xt, x1=xt, y0=tick_y0, y1=tick_y1,
                         line=dict(color=INK, width=1.2), **loc)
        fig.add_shape(type="line", x0=x_b, x1=sx(gap), y0=tick_y1, y1=tick_y1,
                     line=dict(color=INK, width=1.2), **loc)
        fig.add_annotation(x=(x_b + sx(gap)) / 2, y=tick_y1 - 0.05,
                          text=f"~{round(gap, -3):,.0f} cycles", showarrow=False,
                          font=dict(size=11, color=INK), yanchor="top", **loc)

    # Lane labels are native y-axis tick labels now (see build_fig), not
    # hand-placed annotations.

    # Iteration boundaries -- rint(exp >>= 1n) to the next one -- marked across
    # both lanes; same x for bit=0 and bit=1, so drawn once, not per lane.
    iter_y0, iter_y1 = LANE_Y[0] + 0.15, LANE_Y[1] - 0.32
    for xi, label in ((x_a, "iteration start"), (x_sq1, "iteration end")):
        fig.add_shape(type="line", x0=xi, x1=xi, y0=iter_y0, y1=iter_y1,
                     line=dict(color=ITER_COLOR, width=1.2, dash="dot"),
                     layer="below", **loc)
        fig.add_annotation(x=xi, y=iter_y0, text=label, showarrow=False,
                          font=dict(size=10, color=ITER_COLOR),
                          yanchor="bottom", **loc)

    # Time arrow, aligned to where a native x-axis line would sit -- the exact
    # bottom/left/right edges of the plot rect.
    x_range = (-0.02, 1.02)
    y_range = (-0.68, 0.90)
    axis_y = -0.62
    fig.add_shape(type="line", x0=x_range[0], x1=x_range[1], y0=axis_y,
                 y1=axis_y, line=dict(color=INK, width=1.2), **loc)
    fig.add_annotation(x=x_range[1], y=axis_y, ax=x_range[0], ay=axis_y,
                      xref="x", yref="y", axref="x", ayref="y",
                      showarrow=True, arrowhead=2, arrowsize=1,
                      arrowwidth=1.2, arrowcolor=INK, text="", **loc)
    fig.update_xaxes(range=list(x_range), row=row, col=1)
    fig.update_yaxes(range=list(y_range), row=row, col=1)


def build_fig(x0, x1, gaps):
    fig = make_subplots(rows=1, cols=1)
    add_schematic(fig, gaps, row=1)

    # The x-axis is a compressed illustrative timeline, not literal cycles, so
    # no ticks/labels there. The y-axis is just two categories -- give it real
    # ticks instead of a hand-placed annotation, native left border included
    # for free.
    fig.update_xaxes(row=1, col=1, showticklabels=False, showgrid=False,
                     zeroline=False, showline=False, ticks="")
    fig.update_yaxes(row=1, col=1, showgrid=False, zeroline=False,
                     showline=True, linecolor=INK, linewidth=1, mirror=False,
                     ticks="", tickvals=[LANE_Y[1], LANE_Y[0]],
                     ticktext=["cond = 1", "cond = 0"],
                     tickfont=dict(size=11, color=INK))

    fig.update_layout(
        width=WIDTH, height=HEIGHT, template="plotly_white",
        font=dict(family=FONT, size=12, color="black"),
        margin=dict(l=55, r=10, t=10, b=10),
        showlegend=False,
        plot_bgcolor="white", paper_bgcolor="white")
    return fig


def main():
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trace", default="r0")
    ap.add_argument("--out", default=str(here.parent / "results" / "figures"
                                         / "fig6_gap"),
                    help="output path stem; .svg and .png are both written")
    args = ap.parse_args()

    res = enrich(D.TRACE_DIR / f"{args.trace}.out")
    x0, x1 = gap_arrays(res)
    gaps = typical_gaps(x0, x1)

    fig = build_fig(x0, x1, gaps)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.write_image(str(out.with_suffix(".svg")))
    fig.write_image(str(out.with_suffix(".png")), scale=2)
    fig.write_image(str(out.with_suffix(".pdf")))
    print(f"[*] wrote {out}.svg / .png / .pdf  (bit0={gaps[0]:,.0f} cyc, "
          f"bit1={gaps[1]:,.0f} cyc, delta={gaps[1] - gaps[0]:+,.0f}, "
          f"n0={len(x0)}, n1={len(x1)})")


if __name__ == "__main__":
    main()
