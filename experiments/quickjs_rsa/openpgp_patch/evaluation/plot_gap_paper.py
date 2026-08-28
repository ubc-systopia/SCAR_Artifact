"""Paper figure: the SELECT interval, split by the secret bit.

One lane per value of the secret bit, each showing a single real loop
iteration rather than a distribution. Markers are coloured by bit and shaped
by which libbf call they are, filled for `bf_rint` and hollow for
`bf_logic_or`, in the order the loop makes them: a leading `rint` for the
previous iteration's `x * x mod n`, then `rint`, `rint`, `or`, `rint`, `rint`
for the depicted iteration. Both iterations come from the same trace and each
has the median gap for its bit, so the panel shows a typical instance rather
than a cherry-picked one. The shaded span and the bracket both mark the
interval the attacker measures, `rint(r * x mod n)` to `or`, which is all of
SELECT. The bracket label rounds to the nearest 1,000 cycles.

The modular multiplications either side of SELECT run about 278,000 cycles
each, nine times the interval that carries the bit, so they are drawn
compressed and marked with break ticks. Everything between the bracketed
endpoints, and the leading segment back to the previous iteration, is at true
scale.

Shares the library, font, template and panel conventions of
`plot_dist_paper.py`, including its per-secret-bit palette, so the two figures
read as a matched pair.

    python3 plot_gap_paper.py --traces DIR [--trace r0] [--export png,svg]
"""
import argparse
from pathlib import Path

import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots

import decoder as D
from figures import enrich

COND_COLOR = {0: "#1071e5", 1: "#fc9432"}
INK = "#000000"
RULE = "#bbbbbb"
BOUNDARY_COLOR = "#d62728"
FONT = "Helvetica, Arial, sans-serif"

WIDTH, HEIGHT = 400, 118
LANE_Y = {0: 0.60, 1: -0.10}
LANE_START_X = 0.02
LANE_OVERHANG = 0.025
COMPRESSED_MUL_WIDTH = 0.10
SELECT_AXIS_CYCLES = 34_000
LEGEND_X = 0.83

NARROW_PAIR_CYCLES = 25_564
"""Median cycles from `rint(x * x mod n)` to the next `rint(exp >>= 1n)`.

The narrow pair, drawn after the second compressed multiplication and,
mirrored, before the first marker so the lane opens on the previous
iteration's last access. Measured by figures.py.
"""


def gaps_by_bit(trace):
    """Every wide-pair (SELECT) gap in the trace, split by the true key bit."""
    gap, index, valid, lsb_first = (trace["wide_gap"], trace["idx"],
                                    trace["valid"], trace["lsb_first"])
    truth = lsb_first[index[valid]]
    kept = gap[valid]
    return kept[truth == 0], kept[truth == 1]


def median_instance_per_bit(bit0_gaps, bit1_gaps):
    """The one real gap per bit that sits closest to that bit's median.

    A single instance rather than a distribution, typical only in the sense of
    not being an outlier.
    """
    instances = {}
    for bit, gaps in ((0, bit0_gaps), (1, bit1_gaps)):
        instances[bit] = float(gaps[np.argmin(np.abs(gaps - np.median(gaps)))])
    return instances


def _rgba(hex_color, alpha):
    channels = hex_color.lstrip("#")
    red, green, blue = (int(channels[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({red},{green},{blue},{alpha})"


def _draw_marker_legend(figure, subplot):
    """Draw the marker key by hand, to the right of the lanes.

    A native plotly legend anchors to the whole figure in paper coordinates
    rather than to a subplot, so it cannot be placed between the two lanes.
    """
    middle_y = (LANE_Y[0] + LANE_Y[1]) / 2
    entries = ((middle_y + 0.14, "circle", "bf_rint"),
               (middle_y - 0.14, "circle-open", "bf_logic_or"))
    for entry_y, symbol, label in entries:
        figure.add_trace(go.Scatter(
            x=[LEGEND_X], y=[entry_y], mode="markers", showlegend=False,
            marker=dict(symbol=symbol, size=8, color=INK,
                        line=dict(width=1.4, color=INK))), **subplot)
        figure.add_annotation(
            x=LEGEND_X + 0.03, y=entry_y, text=label, showarrow=False,
            font=dict(size=11, color=INK), xanchor="left", yanchor="middle",
            **subplot)


def _draw_iteration_boundaries(figure, x_iteration_start, x_iteration_end,
                               subplot):
    """Mark one loop iteration across both lanes.

    The boundaries fall at the same x for either bit, so they are drawn once
    rather than per lane.
    """
    top_y, bottom_y = LANE_Y[0] + 0.15, LANE_Y[1] - 0.32
    for boundary_x, label in ((x_iteration_start, "iteration start"),
                              (x_iteration_end, "iteration end")):
        figure.add_shape(
            type="line", x0=boundary_x, x1=boundary_x, y0=top_y, y1=bottom_y,
            line=dict(color=BOUNDARY_COLOR, width=1.2, dash="dot"),
            layer="below", **subplot)
        figure.add_annotation(
            x=boundary_x, y=top_y, text=label, showarrow=False,
            font=dict(size=10, color=BOUNDARY_COLOR), yanchor="bottom",
            **subplot)


def _draw_time_arrow(figure, subplot, row):
    """Draw the time axis where a native x-axis line would sit."""
    x_range = (-0.02, 1.02)
    y_range = (-0.68, 0.90)
    axis_y = -0.62
    figure.add_shape(
        type="line", x0=x_range[0], x1=x_range[1], y0=axis_y, y1=axis_y,
        line=dict(color=INK, width=1.2), **subplot)
    figure.add_annotation(
        x=x_range[1], y=axis_y, ax=x_range[0], ay=axis_y, xref="x", yref="y",
        axref="x", ayref="y", showarrow=True, arrowhead=2, arrowsize=1,
        arrowwidth=1.2, arrowcolor=INK, text="", **subplot)
    figure.update_xaxes(range=list(x_range), row=row, col=1)
    figure.update_yaxes(range=list(y_range), row=row, col=1)


def draw_lanes(figure, instances, row):
    """One real loop iteration per bit lane, bracketed on SELECT.

    The leading segment is at true scale like the trailing one, so the lane
    end is solved for rather than chosen: the true-scale cycles either side of
    the two compressed multiplications must span what is left of the lane.
    """
    subplot = dict(row=row, col=1)
    x_previous_iteration = LANE_START_X
    x_lane_limit = LEGEND_X - 0.04
    true_scale_cycles = SELECT_AXIS_CYCLES + 2 * NARROW_PAIR_CYCLES
    cycles_to_x = ((x_lane_limit - x_previous_iteration
                    - 2 * COMPRESSED_MUL_WIDTH) / true_scale_cycles)

    x_iteration_start = x_previous_iteration + cycles_to_x * NARROW_PAIR_CYCLES
    x_select_start = x_iteration_start + COMPRESSED_MUL_WIDTH

    def x_at(cycles):
        return x_select_start + cycles_to_x * cycles

    x_second_mul_start = x_at(SELECT_AXIS_CYCLES)
    x_second_mul_end = x_second_mul_start + COMPRESSED_MUL_WIDTH
    x_lane_end = (x_at(SELECT_AXIS_CYCLES + NARROW_PAIR_CYCLES)
                  + COMPRESSED_MUL_WIDTH)

    _draw_marker_legend(figure, subplot)

    for bit in (0, 1):
        lane_y = LANE_Y[bit]
        gap = instances[bit]
        colour = COND_COLOR[bit]

        figure.add_shape(
            type="line", x0=x_previous_iteration - LANE_OVERHANG,
            x1=x_lane_end + LANE_OVERHANG, y0=lane_y, y1=lane_y,
            line=dict(color=RULE, width=1), layer="below", **subplot)

        figure.add_shape(
            type="rect", x0=x_select_start, x1=x_at(gap),
            y0=lane_y - 0.09, y1=lane_y + 0.09,
            fillcolor=_rgba(colour, 0.30), line=dict(width=0), layer="below",
            **subplot)

        for break_x in ((x_iteration_start + x_select_start) / 2,
                        (x_second_mul_start + x_second_mul_end) / 2):
            for offset in (-0.006, 0.006):
                figure.add_shape(
                    type="line", x0=break_x + offset - 0.006,
                    x1=break_x + offset + 0.006, y0=lane_y - 0.05,
                    y1=lane_y + 0.05, line=dict(color=RULE, width=1.1),
                    **subplot)

        rint_xs = [x_previous_iteration, x_iteration_start, x_select_start,
                   x_second_mul_end, x_lane_end]
        figure.add_trace(go.Scatter(
            x=rint_xs, y=[lane_y] * len(rint_xs), mode="markers",
            showlegend=False,
            marker=dict(symbol="circle", size=8, color=colour)), **subplot)
        figure.add_trace(go.Scatter(
            x=[x_at(gap)], y=[lane_y], mode="markers", showlegend=False,
            marker=dict(symbol="circle-open", size=8, color=colour,
                        line=dict(width=1.4, color=colour))), **subplot)

        tick_top, tick_bottom = lane_y - 0.14, lane_y - 0.22
        for tick_x in (x_select_start, x_at(gap)):
            figure.add_shape(
                type="line", x0=tick_x, x1=tick_x, y0=tick_top, y1=tick_bottom,
                line=dict(color=INK, width=1.2), **subplot)
        figure.add_shape(
            type="line", x0=x_select_start, x1=x_at(gap), y0=tick_bottom,
            y1=tick_bottom, line=dict(color=INK, width=1.2), **subplot)
        figure.add_annotation(
            x=(x_select_start + x_at(gap)) / 2, y=tick_bottom - 0.05,
            text=f"~{round(gap, -3):,.0f} cycles", showarrow=False,
            font=dict(size=11, color=INK), yanchor="top", **subplot)

    _draw_iteration_boundaries(figure, x_iteration_start, x_second_mul_end,
                               subplot)
    _draw_time_arrow(figure, subplot, row)


def build_figure(instances):
    """Assemble the single-panel figure.

    The x-axis is a compressed illustrative timeline rather than literal
    cycles, so it carries no ticks. The y-axis is two categories, given real
    tick labels so the panel's left border comes for free.
    """
    figure = make_subplots(rows=1, cols=1)
    draw_lanes(figure, instances, row=1)

    figure.update_xaxes(row=1, col=1, showticklabels=False, showgrid=False,
                        zeroline=False, showline=False, ticks="")
    figure.update_yaxes(row=1, col=1, showgrid=False, zeroline=False,
                        showline=True, linecolor=INK, linewidth=1,
                        mirror=False, ticks="",
                        tickvals=[LANE_Y[1], LANE_Y[0]],
                        ticktext=["cond = 1", "cond = 0"],
                        tickfont=dict(size=11, color=INK))
    figure.update_layout(
        width=WIDTH, height=HEIGHT, template="plotly_white",
        font=dict(family=FONT, size=12, color="black"),
        margin=dict(l=55, r=10, t=10, b=10), showlegend=False,
        plot_bgcolor="white", paper_bgcolor="white")
    return figure


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--traces", required=True,
                        help="capture directory holding r*.out[.gz], e.g. "
                             "build/output/quickjs_bigint_select_rsa/"
                             "quickjs_bigint_select_rsa_key00000_r00128")
    parser.add_argument("--trace", default="r0",
                        help="which trace in that directory (default r0)")
    parser.add_argument("--out",
                        default=str(here.parent / "results"
                                    / "selectbigint_gap"),
                        help="output path stem, without extension")
    parser.add_argument("--export", default="",
                        help="extra formats besides the default PDF, "
                             "comma-separated (e.g. 'png,svg')")
    args = parser.parse_args()

    D.TRACE_DIR = Path(args.traces)
    trace = enrich(D.trace_path(args.trace))
    bit0_gaps, bit1_gaps = gaps_by_bit(trace)
    instances = median_instance_per_bit(bit0_gaps, bit1_gaps)

    figure = build_figure(instances)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    formats, seen = [], set()
    for fmt in ["pdf", *(f.strip() for f in args.export.split(",") if f.strip())]:
        if fmt not in seen:
            seen.add(fmt)
            formats.append(fmt)
    for fmt in formats:
        path = out.with_suffix(f".{fmt}")
        figure.write_image(str(path), scale=2 if fmt == "png" else 1)
        print(f"[*] wrote {path}")

    print(f"[*] cond=0 {instances[0]:,.0f} cyc (n={len(bit0_gaps)}), "
          f"cond=1 {instances[1]:,.0f} cyc (n={len(bit1_gaps)}), "
          f"delta {instances[1] - instances[0]:+,.0f}")


if __name__ == "__main__":
    main()
