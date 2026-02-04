import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import math
import numpy as np
import pandas as pd
from bokeh.models import (
    ColorBar,
    ColumnDataSource,
    HoverTool,
    LinearAxis,
    LinearColorMapper,
    Range1d,
)
from bokeh.palettes import Turbo256
from bokeh.plotting import figure
from scipy.signal import stft
from spectrum import probes_to_signal
from scipy.signal import butter, filtfilt, welch, find_peaks

from utils import *


def plot_latency(trace, opcodes=["goto8", "sar", "mod", "mul"]):
    ts0 = min((map(lambda p: p[0], trace.iloc[0])))

    p = figure(
        width=800,
        height=300,
        toolbar_location="right",
        title="Latency of each detection",
        x_axis_label="CPU Timestamp",
        y_axis_label="Access Latency",
    )

    for i in range(trace.shape[1]):
        x = trace[i].map(lambda x: x[0]).astype(float)
        y = trace[i].map(lambda x: x[1])
        valid = x.apply(lambda x: x > 0)
        x = x[valid]
        y = y[valid]
        x -= ts0
        p.scatter(
            x=x,
            y=y,
            color=palette[i],
            size=8,
            legend_label=opcodes[i],
        )

    p.y_range = Range1d(0, 1000)
    p.title.text_font_size = "12pt"
    p.legend.label_text_font_size = "10pt"
    p.legend.glyph_height = 40
    p.legend.glyph_width = 40
    p.xaxis.axis_label_text_font_size = "12pt"
    p.xaxis.major_label_text_font_size = "12pt"
    p.yaxis.axis_label_text_font_size = "12pt"
    p.yaxis.major_label_text_font_size = "12pt"
    p.legend.click_policy = "hide"
    p.legend.location = "top_right"
    # p.add_layout(p.legend[0], "right")

    hover = HoverTool()
    hover.tooltips = [
        ("Timestamp", "@x{int}"),  # this will show integer, even if x is float
        ("CacheLevel", "@y{1}"),  # this will format as 1-decimal float
    ]
    p.add_tools(hover)
    return p


def plot_aligned_hits(
    trace: pd.DataFrame,
    title="QuickJS Trace",
    opcodes=["goto8", "sar", "mod", "aligned goto8", "aligned sar"],
    at="FR",
):
    pos = []
    all_pos = trace.apply(lambda x: False, axis=1)
    for i in range(trace.shape[1]):
        pos.append(trace.apply(lambda x: lat_to_hit(x[i][1], at), axis=1))
        all_pos |= pos[i]

    trace = trace[all_pos]

    ts0 = min((map(lambda p: p[0], trace.iloc[0])))

    hit_ts = [
        list(map(lambda t: t[0] - ts0, trace[pos[i]][i])) for i in range(trace.shape[1])
    ]

    aligned_goto8 = aligned_timestamps(hit_ts[0], hit_ts[2])
    # aligned_sar = aligned_timestamps(hit_ts[1], hit_ts[2])
    aligned_sar = aligned_timestamps(hit_ts[1], hit_ts[0])

    align_ts = [
        hit_ts[0],
        hit_ts[1],
        hit_ts[2],
        aligned_goto8,
        aligned_sar,
    ]

    p = figure(
        width=1200,
        height=600,
        toolbar_location="right",
        title=title,
        x_axis_label="CPU Timestamp",
        y_axis_label="Target CacheLine Hits",
    )

    if trace.empty:
        print("Error: Trace has 0 hits")
        return p

    op_num = trace.shape[1]
    opcodes = opcodes[: (len(align_ts))]
    yticker = list(range(len(align_ts)))

    ts0 = min((map(lambda p: p[0], trace.iloc[0])))

    for i in range(len(align_ts)):
        x = align_ts[i]
        print(f"{opcodes[i]} detects {len(x)} hits")
        p.scatter(
            x=x,
            y=yticker[i],
            color=palette[i],
            size=8,
            legend_label=opcodes[i],
        )

    p.title.text_font_size = "12pt"
    p.legend.label_text_font_size = "10pt"
    p.legend.glyph_height = 40
    p.legend.glyph_width = 40
    p.yaxis.ticker = yticker
    p.yaxis.major_label_overrides = {i: opcodes[i] for i in range(len(align_ts))}
    p.xaxis.axis_label_text_font_size = "12pt"
    p.xaxis.major_label_text_font_size = "12pt"
    p.yaxis.axis_label_text_font_size = "12pt"
    p.yaxis.major_label_text_font_size = "12pt"
    p.legend.click_policy = "hide"
    p.add_layout(p.legend[0], "right")

    hover = HoverTool()
    hover.tooltips = [
        ("Timestamp", "@x{int}"),  # this will show integer, even if x is float
        ("CacheLevel", "hit"),  # this will format as 1-decimal float
    ]
    p.add_tools(hover)

    return p


def plot_hits(
    trace: pd.DataFrame,
    title="QuickJS Trace",
    opcodes=None,
    at="FR",
):
    filtered_trace = []

    for i in range(trace.shape[1]):
        mask = trace.apply(lambda x: lat_to_hit(x[i][1], at), axis=1)
        filtered_list = trace[i][mask].tolist()
        filtered_trace.append(filtered_list)

    p = figure(
        width=800,
        height=400,
        toolbar_location="right",
        title=title,
        x_axis_label="CPU Timestamp",
        y_axis_label="Target CacheLine Hits",
    )

    if trace.empty:
        print("Error: Trace has 0 hits")
        return p

    op_num = len(filtered_trace)

    if opcodes == None:
        opcodes = ["CacheS" + str(i) for i in range(op_num)]
    else:
        opcodes = opcodes[:op_num]
    yticker = list(range(op_num))

    ts0 = 0
    mins = [col[0][0] for col in filtered_trace if col]
    if mins:
        ts0 = min(mins)

    for i in range(len(filtered_trace)):
        # xy = trace[i][pos[i]]
        xy = filtered_trace[i]
        print(f"{opcodes[i]} detects {len(xy)} hits")
        x = np.array([t[0] for t in xy]).astype(float)
        y = np.array([t[1] for t in xy])
        # x -= ts0
        p.scatter(
            x=x,
            y=yticker[i],
            color=palette[i],
            size=8,
            legend_label=opcodes[i],
        )

    p.title.text_font_size = "12pt"
    p.legend.label_text_font_size = "10pt"
    p.legend.glyph_height = 40
    p.legend.glyph_width = 40
    p.yaxis.ticker = yticker
    p.yaxis.major_label_overrides = {i: opcodes[i] for i in range(op_num)}
    p.xaxis.axis_label_text_font_size = "12pt"
    p.xaxis.major_label_text_font_size = "12pt"
    p.yaxis.axis_label_text_font_size = "12pt"
    p.yaxis.major_label_text_font_size = "12pt"
    p.legend.click_policy = "hide"
    p.legend.location = "top_right"
    p.add_layout(p.legend[0], "right")

    hover = HoverTool()
    hover.tooltips = [
        ("Timestamp", "@x{int}"),  # this will show integer, even if x is float
        ("CacheLevel", "hit"),  # this will format as 1-decimal float
    ]
    p.add_tools(hover)
    return p


def plot_trace_stft(
    trace, sample_interval, fs, at="FR", nperseg=1024, opcodes=["goto16", "shl"]
):
    pos = trace.apply(lambda x: lat_to_hit(x[0][1], at), axis=1)
    probe_hits = list(trace[pos].apply(lambda x: x[0][0], axis=1))
    signal = probes_to_signal(probe_hits, sample_interval)
    frequencies, times, Zxx = stft(signal, fs=fs, nperseg=nperseg)
    Zxx_magnitude = np.abs(Zxx)

    KHz_frequencies = frequencies / 1000
    color_mapper = LinearColorMapper(
        palette=Turbo256, low=np.min(Zxx_magnitude), high=np.max(Zxx_magnitude)
    )

    p = figure(
        title="STFT",
        x_axis_label="Time (s)",
        y_axis_label="Frequency (KHz)",
        width=800,
        height=300,
        output_backend="svg",
    )

    p.image(
        image=[Zxx_magnitude],
        x=times.min(),
        y=frequencies.min(),
        dw=times.max() - times.min(),
        dh=frequencies.max() - frequencies.min(),
        color_mapper=color_mapper,
    )

    color_bar = ColorBar(color_mapper=color_mapper, label_standoff=12, location=(0, 0))
    color_bar.major_label_text_font_size = "10pt"
    p.add_layout(color_bar, "right")

    p.legend.label_text_font_size = "12pt"
    p.legend.glyph_height = 40
    p.legend.glyph_width = 40
    p.xaxis.axis_label_text_font_size = "10pt"
    p.xaxis.major_label_text_font_size = "10pt"
    p.yaxis.axis_label_text_font_size = "10pt"
    p.yaxis.major_label_text_font_size = "10pt"

    return p


def plot_trace_interval_hist(trace, at="FR", thres=99, bins=100):
    pos = trace.apply(lambda x: lat_to_hit(x[1], at))
    probe_hits = list(trace[pos].apply(lambda x: x[0]))
    intervals = np.diff(probe_hits)

    p = figure(
        title="Time Series Interval Histogram",
        x_axis_label="Cycles",
        y_axis_label="Count",
        width=800,
        height=300,
    )

    threshold = min(np.percentile(intervals, thres), 1000000)
    bins = min(bins, int(math.sqrt(len(intervals))))
    filtered_intervals = intervals[intervals <= threshold]
    hist, edges = np.histogram(filtered_intervals, bins=bins)
    p.quad(top=hist, bottom=0, left=edges[:-1], right=edges[1:], alpha=0.7)

    sorted_intervals = np.sort(intervals)
    cdf = np.arange(1, len(intervals) + 1) / len(intervals)
    cdf_source = ColumnDataSource(data={"intervals": sorted_intervals, "cdf": cdf})
    p.extra_y_ranges = {"cdf": Range1d(start=0, end=1)}  # Normalize CDF from 0 to 1
    p.add_layout(LinearAxis(y_range_name="cdf", axis_label="CDF"), "right")

    cdf_line = p.line(
        "intervals",
        "cdf",
        source=cdf_source,
        line_width=2,
        color="red",
        y_range_name="cdf",
        legend_label="CDF",
    )

    p.x_range = Range1d(min(intervals), threshold)
    hover = HoverTool()
    hover.renderers = [cdf_line]  # Attach to CDF line
    hover.tooltips = [
        ("Interval", "@intervals{0.000} s"),  # Display interval with 3 decimal places
        ("CDF", "@cdf{0.00}"),  # Display CDF with 2 decimals
    ]
    p.add_tools(hover)
    return p


def plot_psd(signal, fs):
    frequencies_psd, psd_values = welch(
        signal,
        fs,
        nperseg=2048,
        noverlap=1024,
    )
    n_freq = len(frequencies_psd)
    p = figure(
        title="",
        x_axis_label="Frequency (KHz)",
        y_axis_label=r"PSD (\[10^{-7}\])",
        # y_axis_type="log",
        width=800,
        height=300,
        toolbar_location="right",
    )
    p.line(
        frequencies_psd[: n_freq // 2] / 1000,
        psd_values[: n_freq // 2] * (10**7),
        line_width=2,
    )
    psd_x = frequencies_psd[: n_freq // 2] / 1000
    psd_y = psd_values[: n_freq // 2] * (10**7)
    peaks, _ = find_peaks(psd_y, prominence=0.05 * np.max(psd_y))
    p.scatter(psd_x[peaks], psd_y[peaks], color="red", size=8)
    p.title.text_font_size = "16pt"
    # p.legend.label_text_font_size = "16pt"
    # p.legend.glyph_height = 40
    # p.legend.glyph_width = 40
    p.xaxis.axis_label_text_font_size = "24pt"
    p.xaxis.major_label_text_font_size = "24pt"
    p.yaxis.axis_label_text_font_size = "20pt"
    p.yaxis.major_label_text_font_size = "24pt"
    # p.toolbar_location = None
    hover = HoverTool()
    hover.tooltips = [
        ("Freq", "@x{1.1}"),  # this will show integer, even if x is float
        ("Power", "@y{1.1}"),  # this will format as 1-decimal float
    ]
    p.add_tools(hover)
    return p


def plot_trace_psd(trace, sample_interval, fs, at="PS"):
    pos = trace.apply(lambda x: lat_to_hit(x[0][1], at), axis=1)
    probe_hits = list(trace[pos].apply(lambda x: x[0][0], axis=1))
    signal = probes_to_signal(probe_hits, sample_interval)
    return plot_psd(signal, fs)
