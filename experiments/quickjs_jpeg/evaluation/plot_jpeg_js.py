import argparse
import math
from pathlib import Path

import numpy as np
import pandas as pd
from bokeh.layouts import column
from bokeh.models import LinearAxis, Range1d
from bokeh.palettes import Category20_20, Paired12
from bokeh.plotting import figure, output_file, save
from scipy.fft import idct
from plot_models import *
from scipy.signal import convolve, welch
from sklearn.cluster import KMeans
from sklearn.linear_model import LinearRegression
from sklearn.metrics import silhouette_score

from utils import *

test_name = "quickjs_jpeg"
title = "QuickJS Jpeg Decode Trace"

PP_sample_interval = 2000
sample_interval = PP_sample_interval
fs = PS_fs
sx_range_min = 0
sx_range_max = 0

idct_loop_cluster_lb = 10000
idct_loop_cluster_ub = 90000


class Cluster(object):
    begin: int
    end: int
    nodes: list[int]

    def __init__(self, node):
        self.begin = node
        self.end = node
        self.nodes = [node]

    def append(self, node):
        self.end = max(self.end, node)
        self.nodes.append(node)

    def size(self):
        return len(self.nodes)

    def length(self):
        return self.end - self.begin

    def center(self):
        return (self.begin + self.end) // 2

    def merge(self, cluster):
        if self.end < cluster.begin:
            self.nodes.extend(cluster.nodes)
            self.end = cluster.end
        elif self.begin > cluster.end:
            self.nodes = cluster.nodes + self.nodes
            self.begin = cluster.begin
        else:
            raise AssertionError("Cannot merge clusters")


def get_trace_clusters(strace, base_interval=3000):
    clusters = []
    i = 0

    # basic cluster
    while i < len(strace):
        cluster = Cluster(strace[i])
        j = i + 1
        while j < len(strace) and strace[j] < cluster.end + 1.5 * base_interval:
            cluster.append(strace[j])
            j += 1
        clusters.append(cluster)
        i = j

    # bridge 1 scale missing hits
    i = 0
    while i < len(clusters) - 1:
        cluster_i = clusters[i]
        cluster_j = clusters[i + 1]
        if (
            cluster_j.begin - cluster_i.end <= 2.5 * base_interval
            and cluster_i.size() + cluster_j.size() >= 4
        ):
            cluster_i.merge(cluster_j)
            clusters.pop(i + 1)
        else:
            i = i + 1

    return clusters


def instrument_clusters(clusters):
    x = []
    size = []
    length = []
    i = 0
    while i < len(clusters):
        c = clusters[i]
        x.append(c.center())
        size.append(c.size())
        length.append(c.length())
        if i + 1 < len(clusters):
            c1 = clusters[i + 1]
            x.append((c.end + c1.begin) // 2)
            size.append(0)
            length.append(0)
        else:
            x.append(c.end)
            size.append(0)
            length.append(0)
        i += 1
    return x, size, length


def filter_by_period(signal, period, tolerance=2):
    """
    signal: 0/1 array
    period: estimated period (e.g., 10)
    tolerance: allow slight misalignment
    """
    signal = np.array(signal)
    one_indices = np.where(signal == 1)[0]
    filtered = np.zeros_like(signal)
    print(one_indices)
    i = 0
    while i < len(signal):
        window_start = max(i - tolerance, 0)
        window_end = min(i + tolerance + 1, len(signal))
        candidates = [idx for idx in one_indices if window_start <= idx < window_end]
        if candidates:
            best = min(candidates, key=lambda x: abs(x - i))
            filtered[best] = 1
            i = best + period
        else:
            i += period

    one_indices = np.where(filtered == 1)[0]
    print(one_indices)
    return filtered


def check_image_width_separator(clusters, occ, line_width, err_range=0.1):
    if err_range <= 1:
        err_range = line_width * err_range
    opt_i = [0 for o in occ]
    prev = [0 for o in occ]
    for idx, o in enumerate(occ):
        if idx == 0:
            opt_i[idx] = 1
            prev[idx] = o
            continue
        opt = -10000
        pre = o
        for j in range(idx, 0, -1):
            po = occ[j - 1]
            if po < o - 3 * line_width:
                break
            if po >= o - line_width - err_range and po <= o - line_width + err_range:
                if opt_i[j - 1] + 1 > opt:
                    opt = opt_i[j - 1] + 1
                    pre = po
                elif opt_i[j - 1] + 1 == opt:
                    if abs(po - (o - line_width)) < abs(pre - (o - line_width)):
                        pre = po
            if (
                po >= o - 2 * line_width - err_range
                and po <= o - 2 * line_width + err_range
            ):
                if opt_i[j - 1] + 1 > opt:
                    opt = opt_i[j - 1] + 1
                    pre = po
                elif opt_i[j - 1] + 1 == opt:
                    if abs(po - (o - line_width)) < abs(pre - (o - line_width)):
                        pre = po
        opt_i[idx] = opt
        prev[idx] = pre
    return opt_i, prev


def split_idct_clusters(clusters, occ, line_width, err_range=0.1):
    opt_i, prev = check_image_width_separator(clusters, occ, line_width, err_range)
    opt = opt_i[-1]
    index = len(opt_i) - 1
    print(f"Split opt: {opt}")
    line_range = []
    for i in range(opt - 1):
        seg_end = occ[index]
        seg_begin = prev[index]
        if round((seg_end - seg_begin) / line_width) == 1:
            line_range.append((seg_begin, seg_end))
        else:
            mid = (seg_begin + seg_end) // 2
            line_range.append((mid, seg_end))
            line_range.append((seg_begin, mid))
        index = occ.index(seg_begin)

    line_range.reverse()

    block_clusters = []
    for i, ra in enumerate(line_range):
        l, r = ra
        seg = list(filter(lambda c: c.center() > l and c.center() < r, clusters))
        print(f"Line {i} Range: {ra} \t {len(seg)}")
        block_clusters.append(seg)
    return block_clusters, line_range


def patch_goto16_cluster_fractures(clusters, calibration, fracture_thres):
    i = 1

    print(f"cali: {calibration}, fracture thres: {fracture_thres}")

    def close_to(a, b, ratio=0.25):
        if a > b:
            a, b = b, a
        return (b - a) / a <= ratio

    while i < len(clusters) - 2:
        ch = clusters[i - 1]
        ci = clusters[i]
        cj = clusters[i + 1]
        ck = clusters[i + 2]
        c_gap = cj.begin - ci.end
        p_gap = ci.begin - ch.end
        n_gap = ck.begin - cj.end
        if c_gap <= fracture_thres:
            print(
                f"i,j: {(ci.center(), cj.center())} c_gap: {c_gap} p_gap: {p_gap} n_gap: {n_gap} close_to({close_to(p_gap, calibration),close_to(n_gap, calibration)})"
            )
            if close_to(p_gap, calibration) and close_to(n_gap, calibration):
                print(
                    f"new range: {idct_loop_cluster_lb}<={cj.end-ci.begin}<={idct_loop_cluster_ub}"
                )
                if (
                    cj.end - ci.begin >= idct_loop_cluster_lb
                    and cj.end - ci.begin <= idct_loop_cluster_ub
                ):
                    print(f"Merge range: {ci.begin, ci.end}")
                    ci.merge(cj)
                    print(f"Merge range: {ci.begin, ci.end}")
                    cj = clusters.pop(i + 1)
                    print(f"Merge range: {clusters[i].begin, clusters[i].end}")
                    i = i
                else:
                    i = i + 1
            if n_gap <= fracture_thres and close_to(c_gap, n_gap):
                # bloack line separator, skip
                i = i + 2
            else:
                i = i + 1
        else:
            i = i + 1


def plot_trace_clusters(trace, at="PP"):
    p = figure(
        title="Cluster",
        x_axis_label="CPU Timestamp",
        y_axis_label="",
        width=800,
        height=300,
        output_backend="svg",
    )

    pos = trace[0].apply(lambda x: lat_to_hit(x[1], at))
    goto16 = trace[0][pos].apply(lambda x: x[0]).astype(float)
    pos = trace[1].apply(lambda x: lat_to_hit(x[1], at))
    shl = trace[1][pos].apply(lambda x: x[0]).astype(float)

    global sx_range_min, sx_range_max
    # sx_range_min = min(goto16.iloc[0], shl.iloc[0])
    # sx_range_max = max(goto16.iloc[-1], shl.iloc[-1])
    # goto16 = list(goto16 - sx_range_min)
    # shl = list(shl - sx_range_min)

    goto16_clusters = get_trace_clusters(goto16)
    shl_clusters = get_trace_clusters(shl)
    print(f"#goto16 cluster {len(goto16_clusters)}")
    print(f"#shl cluster {len(shl_clusters)}")

    goto16_x, goto16_size, goto16_length = instrument_clusters(goto16_clusters)
    shl_x, shl_size, shl_length = instrument_clusters(shl_clusters)

    p.line(
        x=goto16_x,
        y=goto16_size,
        y_range_name="size",
        line_width=2,
        color=palette[0],
        legend_label="goto16",
    )
    p.line(
        x=shl_x,
        y=shl_size,
        y_range_name="size",
        line_width=2,
        color=palette[1],
        legend_label="shl",
    )

    idct_cand = list(
        filter(
            lambda t: t[1] >= idct_loop_cluster_lb and t[1] <= idct_loop_cluster_ub,
            zip(goto16_x, goto16_length),
        )
    )
    if len(idct_cand) == 0:
        return p, p

    idct_pos = [x for x, l in idct_cand]
    goto16_peaks_cluster = get_trace_clusters(idct_pos, 100000)
    idct_cluster = max(goto16_peaks_cluster, key=lambda x: x.size())

    flex_bound = 120000
    idct_begin = idct_cluster.begin - flex_bound
    idct_end = idct_cluster.end + flex_bound

    print(f"idct (begin, end): {(idct_begin, idct_end)}")
    idct_goto16_clusters = list(
        filter(
            lambda c: c.begin >= idct_begin and c.end <= idct_end,
            goto16_clusters,
        )
    )

    idct_loop_goto16_clusters = list(
        filter(
            lambda c: c.length() >= idct_loop_cluster_lb
            and c.length() <= idct_loop_cluster_ub
            and c.begin >= idct_begin
            and c.end <= idct_end,
            goto16_clusters,
        )
    )

    idct_length = [c.length() for c in idct_loop_goto16_clusters]
    rescale_min = np.percentile(idct_length, 20)
    rescale_max = np.percentile(idct_length, 90)

    gaps = [
        idct_goto16_clusters[i + 1].begin - idct_goto16_clusters[i].end
        for i in range(len(idct_goto16_clusters) - 1)
    ]

    fracture_thres = np.percentile(gaps, 20)

    patch_goto16_cluster_fractures(
        idct_goto16_clusters, np.median(gaps), fracture_thres
    )

    idct_goto16_x, idct_goto16_size, idct_goto16_length = instrument_clusters(
        idct_goto16_clusters
    )

    p.line(
        x=idct_goto16_x,
        y=idct_goto16_length,
        line_width=2,
        color=palette[4],
        legend_label="goto16",
    )

    hist, edges = np.histogram(gaps, bins="auto")

    p_hist = figure(
        title="Histogram of Differences",
        x_axis_label="Difference",
        y_axis_label="Count",
    )
    p_hist.quad(
        top=hist,
        bottom=0,
        left=edges[:-1],
        right=edges[1:],
        fill_color="skyblue",
        alpha=0.7,
    )

    sorted_gaps = np.sort(gaps)
    p_hist.extra_y_ranges["cdf"] = Range1d(-0.1, 1.1)
    cdf = np.arange(1, len(sorted_gaps) + 1) / len(sorted_gaps)
    ax_cdf = LinearAxis(y_range_name="cdf", axis_label="Cluster Size")
    p_hist.add_layout(ax_cdf, "right")
    p_hist.line(sorted_gaps, cdf, y_range_name="cdf", line_width=2, color="darkgreen")
    p_hist.scatter(
        sorted_gaps, cdf, y_range_name="cdf", size=5, color="darkgreen", alpha=0.6
    )

    print(list(map(lambda x: x.size(), goto16_peaks_cluster)))

    p.extra_y_ranges["size"] = Range1d(0, 15)
    ax1 = LinearAxis(y_range_name="size", axis_label="Cluster Size")
    p.add_layout(ax1, "right")

    sx_range = Range1d(idct_begin, idct_end)
    sy_range = Range1d(-100, idct_loop_cluster_ub)

    p.x_range = sx_range
    p.y_range = sy_range

    idct_goto16_turning_cand = list(
        map(
            lambda p: p[0],
            filter(
                lambda t: t[0] >= idct_begin
                and t[0] <= idct_end
                and t[1] >= 1
                and t[1] <= 4,
                zip(goto16_x, goto16_size),
            ),
        )
    )
    idct_shl_turning_cand = list(
        map(
            lambda p: p[0],
            filter(
                lambda t: t[0] >= idct_begin
                and t[0] <= idct_end
                and t[1] >= 1
                and t[1] <= 4,
                zip(shl_x, shl_size),
            ),
        )
    )

    goto16_sig = probes_to_signal(
        idct_goto16_turning_cand,
        sample_interval,
        (idct_begin, idct_end),
        0,
    )

    shl_sig = probes_to_signal(
        idct_shl_turning_cand,
        sample_interval,
        (idct_begin, idct_end),
        0,
    )
    tolerance = 5

    kernel = np.ones(2 * tolerance + 1)

    shl_blurred = convolve(shl_sig, kernel, mode="same")
    co_seq = (goto16_sig == 1) & (shl_blurred > 0)

    co = [idct_begin + sample_interval * i for i, v in enumerate(co_seq) if v]
    co = [idct_goto16_clusters[0].begin] + co + [idct_goto16_clusters[-1].end]
    print("\n\n\n")
    print(list(map(int, co)))
    p.scatter(co, 5, y_range_name="size", color=palette[3])
    # p.scatter(idct_goto16_turning_cand, 6, y_range_name="size", color=palette[4])
    # p.scatter(idct_shl_turning_cand, 7, y_range_name="size", color=palette[5])

    pos_dim = []
    height = 64
    width = 64
    # for h in range(2, math.ceil(math.sqrt(len(idct_loop_goto16_clusters))) + 1):
    for h in range(2, height):
        co_opt, _ = check_image_width_separator(
            idct_loop_goto16_clusters,
            co,
            (idct_end - idct_begin) / h,
            err_range=0.15,
        )
        co_cnt = max(co_opt)
        pos_dim.append((h, co_cnt / (h + 1)))

    print(pos_dim)

    block_clusters, line_range = split_idct_clusters(
        idct_loop_goto16_clusters,
        co,
        (idct_end - idct_begin) / height,
        err_range=0.15,
    )

    # seps = list(map(lambda p: p[0], line_range)) + [line_range[-1][1]]

    # p.segment(
    #     x0=seps,
    #     y0=[0] * len(seps),
    #     x1=seps,
    #     y1=[10] * len(seps),
    #     line_color=palette[3],
    #     line_width=2,
    #     y_range_name="size",
    #     legend_label="line separator",
    # )

    def rescale_line(line) -> list[int]:
        def rescale_block(c):
            b = c.length()
            if b <= rescale_min:
                cnt = 0
            elif b >= rescale_max:
                cnt = 16
            else:
                cnt = round(((b - rescale_min) / (rescale_max - rescale_min)) ** 2 * 16)
            return 16 - cnt

        return list(map(rescale_block, line))

    gray_scale = list(map(rescale_line, block_clusters))
    # print(gray_scale)
    # print(len(gray_scale))
    # print(bytes(gray_scale))
    output_fp = Path(__file__).resolve().parent.parent / Path(
        "output/jpeg-extraction.out"
    )

    line_block_cnt = np.array(list(map(len, block_clusters)))
    print(f"Line Mean: {np.mean(line_block_cnt)}, Std: {np.std(line_block_cnt)}")

    # with open(output_fp, "wb") as f:
    #     for line in gray_scale:
    #         # padding end
    #         # for c in range(width):
    #         #     if c < len(line):
    #         #         f.write(bytes([line[c]]))
    #         #     else:
    #         #         f.write(bytes([8]))

    #         # padding evenly
    #         missing = max(0, width - len(line))
    #         i = 0
    #         while i < missing // 2:
    #             f.write(bytes([8]))
    #             i += 1
    #         for b in line:
    #             f.write(bytes([b]))
    #             i += 1
    #             if i == width:
    #                 break
    #         while i < width:
    #             f.write(bytes([8]))
    #             i += 1

    # co_signal = co_seq - np.mean(co_seq)
    # freqs, psd = welch(co_signal, fs=fs, nperseg=8192)

    # dominant_freq = freqs[np.argmax(psd[1:]) + 1]
    # print("Dominant Freq: ", dominant_freq)
    # estimated_period_psd = 1 / dominant_freq if dominant_freq != 0 else None

    # p_psd = figure(
    #     title=f"PSD (Welch) — Estimated Period = {estimated_period_psd:.2f}",
    #     x_axis_label="Frequency",
    #     y_axis_label="Power",
    # )
    # p_psd.line(freqs, psd, line_width=2)

    # filtered = filter_by_period(co_seq, 510, 50)
    # print("Filtered: ", filtered)

    # co_f = [idct_begin + sample_interval * i for i, v in enumerate(filtered) if v]
    # print(co_f)
    # p.scatter(co_f, 4, y_range_name="size", color=palette[3])

    hover = HoverTool(
        tooltips=[
            ("x", "@x"),
            ("y", "@y"),
        ]
    )
    p.add_tools(hover)
    return p, p_hist


def plot_trace_convolution(trace, at="PP", window=100000, interval=10000):
    pos = trace[0].apply(lambda x: lat_to_hit(x[1], at))
    goto16 = trace[0][pos].apply(lambda x: x[0])
    pos = trace[1].apply(lambda x: lat_to_hit(x[1], at))
    shl = trace[1][pos].apply(lambda x: x[0])

    global sx_range_min, sx_range_max
    sx_range_min = min(goto16.iloc[0], shl.iloc[0])
    sx_range_max = max(goto16.iloc[-1], shl.iloc[-1])
    goto16 = list(goto16 - sx_range_min)
    shl = list(shl - sx_range_min)

    p = figure(
        title="Convolution",
        x_axis_label="CPU Timestamp",
        y_axis_label="",
        width=800,
        height=300,
        output_backend="svg",
    )

    i = 0
    j = 1
    con = []
    while i < len(goto16):
        if j == i:
            j += 1
        while (
            j < len(goto16)
            and goto16[j] - goto16[i] < window
            and goto16[j] - goto16[j - 1] < interval
        ):
            j += 1
        con.append(j - i)
        i = i + 1
    p.line(x=goto16, y=con, line_width=2, color=palette[0])

    # print(con)
    i = 0
    j = 1
    con = []
    while i < len(shl):
        while j < len(shl) and shl[j] - shl[i] < window:
            j += 1
        con.append(j - i)
        i = i + 1
    p.line(x=shl, y=con, line_width=2, color=palette[1])
    return p


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot Quickjs Jpeg Decode Trace")

    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Output file",
    )

    parser.add_argument(
        "--at",
        choices=["FR", "PS", "PP"],
        default="PP",
        help="Attack Primitive: FR or PS (default: FR)",
    )

    args = parser.parse_args()

    trace_filepath = Path(__file__).resolve().parent / Path(
        "output/" + test_name + ".out"
    )

    if args.file:
        trace_filepath = args.file
    trace = load_trace(trace_filepath)

    opcodes = ["goto16", "shl", "sar"]

    p1 = plot_hits(trace, title=title, at=args.at, opcodes=opcodes)
    p2, p_hist = plot_trace_clusters(trace, at=args.at)
    # p3 = plot_trace_stft(trace[0], fs, sample_interval, nperseg=256, at="PP", opcodes=opcodes)
    # p4 = plot_trace_interval_hist(trace[0], at="PP", thres=95, bins=200)
    # p5 = plot_trace_convolution(trace)

    sx_range = Range1d(0, sx_range_max - sx_range_min)
    # p1.x_range = sx_range
    # p2.x_range = sx_range
    p1.x_range = p2.x_range

    p = column(p1, p2, p_hist)

    figure_path = Path(__file__).resolve().parent / Path(
        "../figures/" + test_name + "_" + args.at + ".html"
    )
    figure_path.parent.mkdir(parents=True, exist_ok=True)
    output_file(filename=figure_path)
    print(figure_path)
    save(p)
