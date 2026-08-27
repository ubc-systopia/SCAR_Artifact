"""Score the bf_logic_or *amplitude* channel against the true exponent.

Earlier work treated bf_logic_or purely as an exclusive per-SELECT clock and
threw away how many probes hit inside each cluster. That count is itself
cond-dependent: SELECT computes `a & (mask - cond)` and `b & (mask - 1n + cond)`,
so the operand magnitudes handed to bf_logic_op differ by the secret bit, which
changes the OR's limb count -> its duration -> how many probes catch it.

Per round the effect is ~0.02 correlation (well inside single-round noise), but
it was positive in all 10 usable rounds of the WAITING_TIME sweep. This script
tests whether averaging the per-cluster counts across rounds turns that into
usable per-bit accuracy.
"""
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "evaluation"))

from extract_openpgp_rsa import RSA_KEY  # noqa: E402
from extract_select_rsa import _find_exact_cluster_threshold  # noqa: E402
from utils import load_trace  # noqa: E402

DEFAULT_BASE = Path(
    "/tmp/claude-1004/-home-ddinh02-SCAR-Artifact-experiments-quickjs-rsa/"
    "d08294d6-fd40-4d08-924b-7a3b24f6dd89/scratchpad/density"
)


def cluster_amplitudes(fp, n_bits):
    """Per-iteration bf_logic_or hit count, or None if this round's marker
    trace doesn't cluster cleanly into exactly n_bits iterations."""
    trace = load_trace(str(fp))
    op = np.array(trace[1].tolist(), dtype=np.int64)
    if op.shape[0] == 0:
        return None
    or_hit = np.sort(op[:, 0][(op[:, 1] > 0) & (op[:, 1] < 300)])
    if len(or_hit) < n_bits:
        return None
    th = _find_exact_cluster_threshold(or_hit, n_bits, lo=100_000, hi=400_000)
    if th is None:
        return None
    d = np.diff(or_hit)
    starts = np.concatenate(([0], np.where(d >= th)[0] + 1))
    ends = np.concatenate((starts[1:] - 1, [len(or_hit) - 1]))
    return (ends - starts + 1).astype(float)


def score(sig, truth, label):
    """Classify bit=1 where the (round-averaged) amplitude is above its median,
    and report accuracy plus correlation."""
    if sig.std() == 0:
        print(f"{label}: degenerate signal")
        return
    corr = float(np.corrcoef(sig, truth)[0, 1])
    pred = (sig > np.median(sig)).astype(int)
    acc = float((pred == truth).mean())
    # A signal can be informative with the opposite polarity; report the
    # better orientation but say which one it is.
    if acc < 0.5:
        acc, pol = 1.0 - acc, "inverted"
    else:
        pol = "direct"
    print(f"{label}: corr={corr:+.4f}  acc={acc:.4f} ({pol})")


def main():
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_BASE
    skey = RSA_KEY.load_key(0)
    n_bits = skey.secret_key_bits
    truth = np.array([int(c) for c in skey.secret_key_bin], dtype=np.int64)
    print(f"key 0: {n_bits} bits, {truth.sum()} ones ({truth.mean():.3f})")

    sigs = []
    for dd in sorted(base.glob("wt*")):
        for fp in sorted(dd.glob("*.out")):
            amp = cluster_amplitudes(fp, n_bits)
            tag = f"{dd.name}/{fp.name}"
            if amp is None:
                print(f"{tag}: unusable (no exact {n_bits}-cluster threshold)")
                continue
            score(amp, truth, f"{tag:24s} single")
            # z-score within round: rounds differ in probe density, so raw
            # counts aren't comparable across WAITING_TIME settings.
            sigs.append((amp - amp.mean()) / amp.std())

    if len(sigs) < 2:
        print("\nnot enough usable rounds to aggregate")
        return

    print(f"\n=== aggregate over {len(sigs)} rounds ===")
    stack = np.vstack(sigs)
    for k in range(2, len(sigs) + 1):
        score(stack[:k].mean(axis=0), truth, f"mean of first {k:2d} rounds")


if __name__ == "__main__":
    main()
