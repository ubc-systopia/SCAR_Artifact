"""Score the Prime+Scope traces from quickjs_select_rsa_ps.

P+S records one (tsc, latency) event per detected eviction rather than sampling
on a fixed grid, so unlike the FR traces we get (a) more events per SELECT call
and (b) usable *timing* within a call. This scores several per-iteration
features against the true exponent:

  count  - bf_logic_or events in the iteration's cluster (the FR channel, but
           less quantized)
  span   - last minus first OR event in the cluster: a direct proxy for how
           long bf_logic_op ran, which is what SELECT's cond-dependent operand
           magnitudes should actually modulate
  lat    - mean/max probe latency within the cluster
  add    - bf_add_internal events in the same window (known non-exclusive,
           kept as a control)

P+S traces contain post-signing idle (the probe loop runs for the full cycle
budget), so the dense signing region is detected and isolated first.
"""
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "evaluation"))

from extract_openpgp_rsa import RSA_KEY  # noqa: E402
from extract_select_rsa import _cluster_count  # noqa: E402
from utils import load_trace  # noqa: E402

DEFAULT_DIR = Path(
    "/home/ddinh02/SCAR_Artifact/build/output/quickjs_select_rsa_ps/"
    "quickjs_select_rsa_ps_key00000_r00005"
)


def signing_window(ts, bins=40, frac=0.25):
    """Isolate the dense signing region: keep bins holding at least `frac` of
    the busiest bin's count, and return the (lo, hi) tsc bounds."""
    h, edges = np.histogram(ts, bins=bins)
    keep = np.where(h >= frac * h.max())[0]
    return edges[keep[0]], edges[keep[-1] + 1]


def find_threshold(ts, n_bits, lo=1_000, hi=2_000_000):
    """Largest-margin threshold giving exactly n_bits clusters, or None.
    _cluster_count is monotonically non-increasing in the threshold."""
    if _cluster_count(ts, lo) < n_bits or _cluster_count(ts, hi) > n_bits:
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        c = _cluster_count(ts, mid)
        if c == n_bits:
            return mid
        if c > n_bits:
            lo = mid + 1
        else:
            hi = mid
    return lo if _cluster_count(ts, lo) == n_bits else None


def score(sig, truth, label):
    if np.std(sig) == 0:
        print(f"    {label:8s}: degenerate")
        return None
    corr = float(np.corrcoef(sig, truth)[0, 1])
    pred = (sig > np.median(sig)).astype(int)
    acc = float((pred == truth).mean())
    pol = "direct"
    if acc < 0.5:
        acc, pol = 1.0 - acc, "inverted"
    print(f"    {label:8s}: corr={corr:+.4f}  acc={acc:.4f} ({pol})")
    return corr


def analyse(fp, truth, n_bits):
    trace = load_trace(str(fp))
    orr = np.array(trace[1].tolist(), dtype=np.int64)
    add = np.array(trace[0].tolist(), dtype=np.int64)
    orr = orr[orr[:, 0] > 0]
    add = add[add[:, 0] > 0]
    if orr.shape[0] == 0:
        return None

    orr = orr[np.argsort(orr[:, 0])]
    lo, hi = signing_window(orr[:, 0])
    m = (orr[:, 0] >= lo) & (orr[:, 0] <= hi)
    ots, olat = orr[m, 0], orr[m, 1]

    th = find_threshold(ots, n_bits)
    print(f"  {fp.name}: or_events={len(ots)} ({len(ots)/n_bits:.2f}/iter) "
          f"window={(hi-lo)/1e9:.2f}e9 thresh={th}")
    if th is None:
        near = {t: _cluster_count(ots, t) for t in (5_000, 50_000, 200_000, 500_000)}
        print(f"    no exact {n_bits}-cluster threshold; counts={near}")
        return None

    d = np.diff(ots)
    starts = np.concatenate(([0], np.where(d >= th)[0] + 1))
    ends = np.concatenate((starts[1:] - 1, [len(ots) - 1]))
    count = (ends - starts + 1).astype(float)
    span = (ots[ends] - ots[starts]).astype(float)
    lat_mean = np.array([olat[s:e + 1].mean() for s, e in zip(starts, ends)])
    lat_max = np.array([olat[s:e + 1].max() for s, e in zip(starts, ends)])

    ats = np.sort(add[:, 0])
    edges = np.concatenate((ots[starts], [ots[ends[-1]] + th]))
    add_count = np.histogram(ats, bins=edges)[0].astype(float)

    out = {}
    for name, sig in (("count", count), ("span", span), ("lat_mean", lat_mean),
                      ("lat_max", lat_max), ("add", add_count)):
        out[name] = score(sig, truth, name)
    return out


def main():
    d = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DIR
    skey = RSA_KEY.load_key(0)
    n_bits = skey.secret_key_bits
    truth = np.array([int(c) for c in skey.secret_key_bin], dtype=np.int64)
    print(f"key 0: {n_bits} bits, {truth.sum()} ones\ndir: {d}\n")

    per_feature = {}
    for fp in sorted(d.glob("*.out")):
        res = analyse(fp, truth, n_bits)
        if res:
            for k, v in res.items():
                if v is not None:
                    per_feature.setdefault(k, []).append(v)

    print("\n=== per-feature correlation across rounds ===")
    for k, v in per_feature.items():
        arr = np.array(v)
        same_sign = np.all(arr > 0) or np.all(arr < 0)
        print(f"{k:8s}: n={len(arr)} mean={arr.mean():+.4f} "
              f"std={arr.std():.4f} all-same-sign={same_sign}")


if __name__ == "__main__":
    main()
