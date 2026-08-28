#!/usr/bin/env python3

import argparse
import json
import re

import numpy as np

from utils import Path, find_project_root, load_trace, trace_to_timestamp

MAX_TICK_SHIFT = 10
SEGMENT_BREAK_CYCLES = 150000
MARKER_EDGE_TOLERANCE = 30000

def densest_segment(ts, break_cycles=SEGMENT_BREAK_CYCLES):
    if len(ts) < 2:
        return ts
    breaks = np.nonzero(np.diff(ts.astype(np.int64)) > break_cycles)[0]
    starts = np.concatenate(([0], breaks + 1))
    ends = np.concatenate((breaks + 1, [len(ts)]))
    best = np.argmax(ends - starts)
    return ts[starts[best]:ends[best]]


def trace_candidates(clock, marker, key_length):
    ticks = densest_segment(clock)
    if len(ticks) < key_length:
        return []
    out = []
    span = min(len(ticks) - key_length, MAX_TICK_SHIFT)
    for shift in range(span + 1):
        t = ticks[shift:shift + key_length]
        idx = np.clip(np.searchsorted(t, marker), 1, key_length - 1)
        near = np.where(marker - t[idx - 1] <= t[idx] - marker, idx - 1, idx)
        near = near[(marker >= t[0] - MARKER_EDGE_TOLERANCE)
                    & (marker <= t[-1] + MARKER_EDGE_TOLERANCE)]
        bits = np.zeros(key_length, dtype=np.int8)
        bits[near] = 1
        out.append(bits)
    return out


MAX_MERGE_SEEDS = 8


def merge_inference(candidates, iters=6):
    best = None
    for cand_list in candidates[:MAX_MERGE_SEEDS]:
        for seed in cand_list:
            merged = seed.copy()
            for _ in range(iters):
                chosen = [max(c, key=lambda b: (b == merged).sum())
                          for c in candidates]
                merged = (np.mean(chosen, axis=0) >= 0.5).astype(np.int8)
            score = float(np.mean([(b == merged).mean() for b in chosen]))
            if best is None or score > best[0]:
                best = (score, merged)
    return best


def false_arm_tick_count(clock, false_arm, key_length):
    ticks = densest_segment(clock)
    if len(ticks) < key_length or len(false_arm) == 0:
        return None
    t = ticks[:key_length]
    inside = false_arm[(false_arm >= t[0]) & (false_arm <= t[-1])]
    if len(inside) == 0:
        return None
    idx = np.clip(np.searchsorted(t, inside, side="right") - 1,
                  0, key_length - 1)
    return len(np.unique(idx))


def infer_key(subdir, key_length):
    candidates = []
    false_ticks = []
    for filepath in sorted(Path(subdir).glob("*.out")):
        trace = load_trace(filepath)
        if trace.shape[1] < 3:
            continue
        clock = trace_to_timestamp(trace[0], "PS")
        marker = trace_to_timestamp(trace[2], "PS")
        false_arm = trace_to_timestamp(trace[1], "PS")
        cand = trace_candidates(clock, marker, key_length)
        if cand:
            candidates.append(cand)
            lit = false_arm_tick_count(clock, false_arm, key_length)
            if lit is not None:
                false_ticks.append(lit)
    if not candidates:
        return None, 0.0, 0, None
    score, bits = merge_inference(candidates)

    bits[0] = 1
    median_lit = float(np.median(false_ticks)) if false_ticks else None
    return bits, score, len(candidates), median_lit


def infer_key_pool(all_keys_dir):
    dir_path = Path(all_keys_dir)
    pattern = r"v8_ecdh_key_pool_key(\d+)"
    total_wrong = total_bits = 0
    rows = []
    for subdir in sorted(dir_path.iterdir()):
        if not subdir.is_dir():
            continue
        matches = re.search(pattern, subdir.name)
        if not matches:
            continue
        key_id = int(matches.group(1))
        keypair = json.load(open(
            find_project_root()
            + f"/experiments/v8_ecdh/ec_key_pool/ec_key_{key_id}.json"))
        secret = int(keypair["key1"], 16)
        truth = np.array([int(c) for c in bin(secret)[2:]], dtype=np.int8)

        zeros = int((truth == 0).sum())
        bits, score, n, lit = infer_key(subdir, len(truth))
        if bits is None:
            rows.append((key_id, len(truth), 0, 0.0, None, len(truth),
                         zeros, None))
            total_bits += len(truth)
            total_wrong += len(truth)
            continue
        wrong = int((bits != truth).sum())
        total_wrong += wrong
        total_bits += len(truth)
        rows.append((key_id, len(truth), n, score,
                     (bits == truth).mean(), wrong, zeros, lit))

    print(f"{'key':>4} {'bits':>5} {'traces':>7} {'consistency':>12} "
          f"{'accuracy':>9} {'wrong':>6} {'zeros':>6} {'cl1 lit':>8}")
    for key_id, length, n, score, acc, wrong, zeros, lit in rows:
        acc_s = "-" if acc is None else f"{acc * 100:.2f}%"
        lit_s = "-" if lit is None else f"{lit:.0f}"
        print(f"{key_id:>4} {length:>5} {n:>7} {score:>12.4f} "
              f"{acc_s:>9} {wrong:>6} {zeros:>6} {lit_s:>8}")
    if total_bits:
        print(f"\nTOTAL: {total_wrong} wrong / {total_bits} bits = "
              f"{(1 - total_wrong / total_bits) * 100:.3f}%")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Recover ECDH secret scalars from a v8_ecdh capture"
    )
    parser.add_argument(
        "--all_keys",
        required=True,
        help="capture directory, e.g. ./build/output/full_run",
    )
    args = parser.parse_args()

    infer_key_pool(args.all_keys)
