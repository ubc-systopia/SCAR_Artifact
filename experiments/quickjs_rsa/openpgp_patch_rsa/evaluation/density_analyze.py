import sys
from pathlib import Path
import numpy as np

EV = Path("/home/ddinh02/SCAR_Artifact/experiments/quickjs_rsa/openpgp_patch_rsa/evaluation")
sys.path.insert(0, str(EV))
sys.path.insert(0, "/home/ddinh02/SCAR_Artifact/experiments/quickjs_rsa/evaluation")
from extract_openpgp_rsa import RSA_KEY
from utils import load_trace
from extract_select_rsa import _find_exact_cluster_threshold, _cluster_count

skey = RSA_KEY.load_key(0)
n_bits = skey.secret_key_bits
truth = np.array([int(c) for c in skey.secret_key_bin], dtype=np.int64)

BASE = Path("/tmp/claude-1004/-home-ddinh02-SCAR-Artifact-experiments-quickjs-rsa/"
            "d08294d6-fd40-4d08-924b-7a3b24f6dd89/scratchpad/density")

for wt in (2000, 1000, 400, 100):
    dd = BASE / f"wt{wt}"
    if not dd.exists():
        continue
    print(f"\n########## WAITING_TIME={wt} ##########")
    for fp in sorted(dd.glob("*.out")):
        trace = load_trace(str(fp))
        op = np.array(trace[1].tolist(), dtype=np.int64)
        ap = np.array(trace[0].tolist(), dtype=np.int64)
        add_tsc, add_lat = ap[:, 0], ap[:, 1]
        o = np.argsort(add_tsc)
        add_tsc = add_tsc[o]
        add_hit = ((add_lat[o] > 0) & (add_lat[o] < 460)).astype(np.int64)
        period = float(np.median(np.diff(add_tsc)))

        or_hit = np.sort(op[:, 0][(op[:, 1] > 0) & (op[:, 1] < 300)])
        th = _find_exact_cluster_threshold(or_hit, n_bits, lo=100_000, hi=400_000)
        span = add_tsc[-1] - add_tsc[0]
        iter_cyc = span / n_bits
        print(f"{fp.name}: probe_period={period:7.0f}  samples/iter={iter_cyc/period:6.1f}  "
              f"add_hits={add_hit.sum():6d}  or_hits={len(or_hit):6d}  "
              f"exact_thresh={th}")
        if th is None:
            print(f"    (cluster counts: 100k={_cluster_count(or_hit,100000)} "
                  f"400k={_cluster_count(or_hit,400000)})")
            continue
        d = np.diff(or_hit)
        starts = np.concatenate(([0], np.where(d >= th)[0] + 1))
        ends = np.concatenate((starts[1:] - 1, [len(or_hit) - 1]))
        first, last = or_hit[starts], or_hit[ends]
        chit = np.concatenate(([0], np.cumsum(add_hit)))
        cnt = np.arange(len(add_tsc) + 1)

        best = None
        for width in (1000, 2000, 5000, 10000, 20000, 50000):
            for nm, (lo, hi) in (("pre", (first - width, first)),
                                 ("post", (last, last + width))):
                i0 = np.searchsorted(add_tsc, lo, "left")
                i1 = np.searchsorted(add_tsc, hi, "right")
                h, s = chit[i1] - chit[i0], cnt[i1] - cnt[i0]
                ok = s > 0
                if ok.sum() < n_bits * 0.9:
                    continue
                r = (h[ok] / s[ok]); t = truth[ok]
                if r.std() == 0 or t.std() == 0:
                    continue
                c = float(np.corrcoef(r, t)[0, 1])
                if best is None or abs(c) > abs(best[0]):
                    best = (round(c, 4), width, nm, round(float(s.mean()), 1))
        print(f"    best narrow-window corr: {best}")
