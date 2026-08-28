import gzip
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
TRACE_DIR = None
POOL_KEY_DIR = ROOT.parent / "rsa_key_pool"

PAIR_SPLIT_CYCLES = 100_000

def signal_slot(path):
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt") as fh:
        for line in fh:
            cols = line.split()
            if cols:
                return len(cols) - 1
    raise ValueError(f"empty trace: {path}")


def load_trace(path, slot=None):
    if slot is None:
        slot = signal_slot(path)
    opener = gzip.open if str(path).endswith(".gz") else open
    ts, lat = [], []
    with opener(path, "rt") as fh:
        for line in fh:
            cols = line.split()
            if len(cols) <= slot:
                continue
            t, _, l = cols[slot].partition(":")
            t = int(t)
            if t > 0:
                ts.append(t)
                lat.append(int(l))
    ts = np.array(ts, dtype=np.int64)
    lat = np.array(lat, dtype=np.int64)
    order = np.argsort(ts)
    return ts[order], lat[order]


def signing_window(ts, bins=40, frac=0.25):
    hist, edges = np.histogram(ts, bins=bins)
    keep = np.where(hist >= frac * hist.max())[0]
    return edges[keep[0]], edges[keep[-1] + 1]


def wide_narrow(ts):
    lo, hi = signing_window(ts)
    ts = ts[(ts >= lo) & (ts <= hi)]

    gaps = np.diff(ts)
    starts = np.concatenate(([0], np.where(gaps >= PAIR_SPLIT_CYCLES)[0] + 1))
    ends = np.concatenate((starts[1:] - 1, [len(ts) - 1]))

    exactly_two = (ends - starts) == 1
    start_t = ts[starts[exactly_two]].astype(float)
    gap = (ts[ends[exactly_two]] - ts[starts[exactly_two]]).astype(float)

    wide = gap > np.median(gap)
    alternation = float((wide[:-1] != wide[1:]).mean())
    return start_t[wide], gap[wide], gap[~wide], alternation


def loop_period(t):
    return float(np.median(np.diff(t)))


def assign_indices(t, n_bits, anchor=0):
    period = loop_period(t)
    idx = np.round((t - t[0]) / period).astype(int)
    idx += anchor - idx.min()
    valid = (idx >= 0) & (idx < n_bits)
    return idx, valid, period


def best_anchor(t, wide_gap, n_bits, truth_lsb_first, span=2):
    predicted = (wide_gap > np.median(wide_gap)).astype(int)
    scores = {}
    for cand in range(-span, span + 1):
        idx, valid, _ = assign_indices(t, n_bits, anchor=cand)
        if not valid.any():
            continue
        scores[cand] = float(
            (predicted[valid] == truth_lsb_first[idx[valid]]).mean())
    best = max(scores, key=scores.get)
    return best, scores[best]


def key_file(key_id=0):
    candidate = POOL_KEY_DIR / f"rsa_key_{key_id}.json"
    if candidate.exists():
        return candidate
    raise FileNotFoundError(f"no key file for key_id={key_id} (checked {candidate})")


def load_exponent(key_id=0):
    key = json.loads(key_file(key_id).read_text())
    d = int(key["d"], 16)
    msb_first = np.array([int(c) for c in bin(d)[2:]], dtype=np.int64)
    return msb_first[::-1], msb_first


def decode(path, key_id=0, anchor=None):
    ts, _ = load_trace(path)
    lsb_first, msb_first = load_exponent(key_id)
    n_bits = len(lsb_first)

    start_t, wide_gap, narrow_gap, alternation = wide_narrow(ts)
    if anchor is None:
        anchor, _ = best_anchor(start_t, wide_gap, n_bits, lsb_first)
    idx, valid, period = assign_indices(start_t, n_bits, anchor=anchor)

    bit_index = idx[valid]
    gap = wide_gap[valid]
    predicted = (gap > np.median(gap)).astype(int)

    return {
        "name": Path(path).name.split(".")[0],
        "key_id": key_id,
        "wide_pairs": len(start_t),
        "alternation": alternation,
        "period": period,
        "anchor": anchor,
        "bit_index": bit_index,
        "gap": gap,
        "predicted": predicted,
        "truth": lsb_first[bit_index],
        "truth_forward": msb_first[bit_index],
        "wide_mean": wide_gap.mean(), "wide_std": wide_gap.std(),
        "narrow_mean": narrow_gap.mean(), "narrow_std": narrow_gap.std(),
        "n_bits": n_bits,
    }


def correlation(gap, truth):
    if gap.std() == 0 or truth.std() == 0:
        return float("nan")
    return float(np.corrcoef(gap, truth)[0, 1])


def accuracy(predicted, truth):
    return float((predicted == truth).mean())


def _require_trace_dir():
    if TRACE_DIR is None:
        raise RuntimeError("TRACE_DIR is unset; point it at a capture directory")
    return TRACE_DIR


def trace_paths():
    return sorted(_require_trace_dir().glob("r*.out*"))


def trace_path(name):
    directory = _require_trace_dir()
    for candidate in (directory / f"{name}.out", directory / f"{name}.out.gz"):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"no trace {name}.out[.gz] in {directory}")


def decode_with_indices(path):
    result = decode(path)
    timestamps, _ = load_trace(path)
    lsb_first, _ = load_exponent()
    start_t, wide_gap, _, _ = wide_narrow(timestamps)
    idx, valid, _ = assign_indices(start_t, len(lsb_first),
                                   anchor=result["anchor"])
    result.update(wide_start=start_t, wide_gap=wide_gap, idx=idx, valid=valid,
                  lsb_first=lsb_first)
    return result
