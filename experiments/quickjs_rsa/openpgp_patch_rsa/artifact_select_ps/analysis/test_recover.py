"""recover.py (the pseudocode) and decoder.py (the implementation the rest of
the analysis imports) must agree bit for bit. Run: python3 test_recover.py"""
import sys
from pathlib import Path

import numpy as np

import decoder as D
import recover as R


def check(path, key_id=0):
    lsb_first, _ = D.load_exponent(key_id)
    n_bits = len(lsb_first)
    d = D.decode(path, key_id=key_id)                       # resolves anchor itself
    i, b = R.recover(R.load(path), n_bits, anchor=d["anchor"])
    assert np.array_equal(i, d["bit_index"]), f"{path}: indices differ"
    assert np.array_equal(b, d["predicted"]), f"{path}: bits differ"
    return len(i), float((b == lsb_first[i]).mean())


if __name__ == "__main__":
    paths = [Path(a) for a in sys.argv[1:]] or D.trace_paths()
    if not paths:
        sys.exit(f"no traces found in {D.TRACE_DIR}")
    for p in paths:
        n, acc = check(p)
        print(f"  {p.name:<12} {n:>5} bits  accuracy {acc:.4f}  identical to decoder.py")
    print(f"\n{len(paths)} traces: recover.py == decoder.py")
