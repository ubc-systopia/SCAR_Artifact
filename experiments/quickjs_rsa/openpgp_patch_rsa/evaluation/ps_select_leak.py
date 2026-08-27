"""Recover exponent bits from Prime+Scope traces of the SELECT-patched modExp.

This is the decoder that actually works, and it supersedes ps_analyze.py's
"count events per iteration" approach.  What changed is the segmentation, not
the data.

STRUCTURE (measured, see PROGRESS.md "Re-segmentation")
-------------------------------------------------------
bf_logic_or events do not form one blob per modExp iteration.  They come in
PAIRS: two events ~25-32k cycles apart, with ~278k cycles to the next pair.
Pairs alternate strictly (97.5-98.2% of the time) between two populations:

    WIDE   pair gap ~30,000 cycles, std ~1400
    NARROW pair gap ~25,600 cycles, std ~600

Two pairs per iteration, 2 x ~306k ~= the ~612k iteration period.  The WIDE
member carries 2-3x the variance of the narrow one -- that variance is the
signal.  This is what SELECT's cond-dependent operand magnitudes do: `mask-cond`
vs `mask-1n+cond` differ in limb count with the secret bit, so bf_logic_op runs
for a different duration, and the gap between its two probed accesses stretches
or shrinks accordingly.

The narrow member is the control: same code, non-varying operands, ~half the
spread, and no correlation with the key.

ORDER
-----
Square-and-multiply consumes the exponent LSB-first, so trace order maps to
bits[::-1].  Scoring in forward order is the built-in negative control and
returns ~0.51 (chance).

ALIGNMENT (the accuracy-limiting step)
--------------------------------------
~100 of 4094 iterations produce no clean pair, so the wide series is ~3990 long
and cannot be sliced positionally.  Indices come from a global least-squares fit
of t = idx*P + c.  This is anchored (errors do not accumulate) but per-point
residual jitter is ~0.25P, so individual points slip and correlation decays over
the trace -- per-chunk correlation reaches +0.96 early and falls off later.
Sequential counting and block-anchored variants were both tried and are worse
(see PROGRESS.md); a drop-aware aligner is the obvious next improvement.
"""
import sys
from pathlib import Path

import numpy as np

_EV = Path(__file__).resolve().parent
sys.path.insert(0, str(_EV))
sys.path.insert(0, str(_EV.parents[1] / "evaluation"))

from extract_openpgp_rsa import RSA_KEY  # noqa: E402
from ps_analyze import signing_window  # noqa: E402
from utils import load_trace  # noqa: E402

DEFAULT_DIR = Path(
    "/home/ddinh02/SCAR_Artifact/build/output/quickjs_select_rsa_ps/"
    "quickjs_select_rsa_ps_key00000_r00005"
)

# Between the ~32k intra-pair scale and the ~278k inter-pair scale. The gap
# histogram is empty between ~35k and ~270k, so this is not a tuned knob.
PAIR_SPLIT_CYCLES = 100_000


def wide_narrow(fp):
    """Return (wide_t, wide_gap, narrow_gap) for one round's trace."""
    trace = load_trace(str(fp))
    orr = np.array(trace[1].tolist(), dtype=np.int64)
    orr = orr[orr[:, 0] > 0]
    if orr.shape[0] == 0:
        return None
    orr = orr[np.argsort(orr[:, 0])]

    lo, hi = signing_window(orr[:, 0])
    ts = orr[(orr[:, 0] >= lo) & (orr[:, 0] <= hi), 0]

    gaps = np.diff(ts)
    starts = np.concatenate(([0], np.where(gaps >= PAIR_SPLIT_CYCLES)[0] + 1))
    ends = np.concatenate((starts[1:] - 1, [len(ts) - 1]))

    clean = (ends - starts) == 1          # exactly two events
    t0 = ts[starts[clean]].astype(float)
    gap = (ts[ends[clean]] - ts[starts[clean]]).astype(float)

    wide = gap > np.median(gap)
    alternation = float((wide[:-1] != wide[1:]).mean())
    return t0[wide], gap[wide], gap[~wide], alternation


def align(t, n_bits):
    """Global least-squares index assignment; see module docstring."""
    P = np.median(np.diff(t))
    idx = np.round((t - t[0]) / P).astype(int)
    for _ in range(3):
        A = np.vstack([idx, np.ones_like(idx)]).T
        P, c = np.linalg.lstsq(A, t, rcond=None)[0]
        idx = np.round((t - c) / P).astype(int)

    ok = (idx >= 0) & (idx < n_bits)
    uniq, cnt = np.unique(idx[ok], return_counts=True)
    dup = set(uniq[cnt > 1].tolist())
    ok &= np.array([i not in dup for i in idx])
    return idx, ok, P


def _score(sig, truth):
    corr = float(np.corrcoef(sig, truth)[0, 1])
    acc = float(((sig > np.median(sig)).astype(int) == truth).mean())
    return corr, acc


def main():
    d = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DIR
    key = RSA_KEY.load_key(0)
    n_bits = key.secret_key_bits
    bits = np.array([int(c) for c in key.secret_key_bin], dtype=np.int64)
    lsb_first = bits[::-1]
    print(f"key 0: {n_bits} bits, {bits.sum()} ones\ndir: {d}\n")

    votes = np.zeros(n_bits)
    seen = np.zeros(n_bits)

    for fp in sorted(d.glob("*.out")):
        res = wide_narrow(fp)
        if res is None:
            print(f"{fp.name}: empty")
            continue
        t, wgap, ngap, alt = res
        idx, ok, P = align(t, n_bits)
        si, sv = idx[ok], wgap[ok]
        truth = lsb_first[si]

        corr, acc = _score(sv, truth)
        fcorr, facc = _score(sv, bits[si])
        print(f"{fp.name}: wide={len(t)} alt={alt:.3f} P={P:.0f} n={len(si)}")
        print(f"   wide   gap mean={wgap.mean():7.0f} std={wgap.std():6.0f}")
        print(f"   narrow gap mean={ngap.mean():7.0f} std={ngap.std():6.0f}  (control)")
        print(f"   LSB-first : corr={corr:+.4f}  acc={acc:.4f}")
        print(f"   forward   : corr={fcorr:+.4f}  acc={facc:.4f}  (negative control)")

        chunks = np.array_split(np.arange(len(si)), 10)
        cs = [np.corrcoef(sv[c], truth[c])[0, 1] for c in chunks]
        print("   corr/chunk: " + " ".join(f"{x:+.3f}" for x in cs))

        z = (sv - sv.mean()) / sv.std()
        votes[si] += z
        seen[si] += 1
        print()

    m = seen > 0
    if m.sum():
        corr, acc = _score(votes[m] / seen[m], lsb_first[m])
        print(f"=== {int(seen.max())}-round vote: n={m.sum()} "
              f"corr={corr:+.4f} acc={acc:.4f} ===")


if __name__ == "__main__":
    main()
