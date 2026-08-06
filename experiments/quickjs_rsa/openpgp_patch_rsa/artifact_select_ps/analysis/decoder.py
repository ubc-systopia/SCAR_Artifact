"""Self-contained decoder for the Prime+Scope traces of SELECT-patched modExp.

Recovers exponent bits from the interval between paired accesses to the
bf_logic_or cache line. See REPORT.md sections 5.2.4 and 5.2.5.

Depends only on numpy. Trace format is one line per probe record, columns
separated by whitespace, each column "tsc:latency"; column 0 is bf_add_internal
(control) and column 1 is bf_logic_or (signal).
"""
import gzip
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
TRACE_DIR = ROOT / "data" / "traces"
KEY_FILE = ROOT / "victim" / "rsa_key_0.json"

# Splits the two gap scales. Every observed gap is either < 35,000 or
# > 270,000 cycles, so this is read off the data, not tuned.
PAIR_SPLIT_CYCLES = 100_000

# Column index of the bf_logic_or probe in the trace file.
SIGNAL_SLOT = 1
CONTROL_SLOT = 0


def load_trace(path, slot):
    """Return (timestamps, latencies) for one probe slot, sorted by timestamp."""
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
    """Bounds of the dense region where signing occurs.

    The probe loop runs for the whole cycle budget, so the tail of the trace is
    post-signing idle. Keep histogram bins holding at least `frac` of the
    busiest bin.
    """
    hist, edges = np.histogram(ts, bins=bins)
    keep = np.where(hist >= frac * hist.max())[0]
    return edges[keep[0]], edges[keep[-1] + 1]


def wide_narrow(ts):
    """Split accesses into pairs and separate the wide and narrow groups.

    Returns (wide_start_times, wide_gaps, narrow_gaps, alternation_rate).
    """
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


def assign_indices(t, n_bits):
    """Map wide-pair timestamps to exponent-bit indices.

    Fits t = index * P + c by least squares over the whole trace, three times.
    A global fit is used because any scheme that counts forward from the
    previous pair loses a bit for every missed loop iteration (REPORT 5.2.4).
    Indices claimed by more than one pair are dropped.
    """
    period = np.median(np.diff(t))
    idx = np.round((t - t[0]) / period).astype(int)
    offset = 0.0
    for _ in range(3):
        design = np.vstack([idx, np.ones_like(idx)]).T
        period, offset = np.linalg.lstsq(design, t, rcond=None)[0]
        idx = np.round((t - offset) / period).astype(int)

    valid = (idx >= 0) & (idx < n_bits)
    uniq, counts = np.unique(idx[valid], return_counts=True)
    duplicated = set(uniq[counts > 1].tolist())
    valid &= np.array([i not in duplicated for i in idx])
    return idx, valid, period


def load_exponent():
    """Return the private exponent bits, least significant first."""
    key = json.loads(KEY_FILE.read_text())
    d = int(key["d"], 16)
    bits = np.array([int(c) for c in bin(d)[2:]], dtype=np.int64)
    return bits[::-1]


def decode(path):
    """Decode one trace. Returns a dict of per-trace results."""
    ts, _ = load_trace(path, SIGNAL_SLOT)
    lsb_first = load_exponent()
    n_bits = len(lsb_first)

    start_t, wide_gap, narrow_gap, alternation = wide_narrow(ts)
    idx, valid, period = assign_indices(start_t, n_bits)

    bit_index = idx[valid]
    gap = wide_gap[valid]
    predicted = (gap > np.median(gap)).astype(int)

    return {
        "name": Path(path).name.split(".")[0],
        "wide_pairs": len(start_t),
        "alternation": alternation,
        "period": period,
        "bit_index": bit_index,
        "gap": gap,
        "predicted": predicted,
        "truth": lsb_first[bit_index],
        "truth_forward": np.array([int(c) for c in bin(
            int(json.loads(KEY_FILE.read_text())["d"], 16))[2:]],
            dtype=np.int64)[bit_index],
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


def trace_paths():
    return sorted(TRACE_DIR.glob("r*.out*"))
