import argparse
import concurrent.futures
import glob
import json
import os
import statistics
import sys

import numpy as np
from collections import namedtuple

import utils
from utils import find_project_root, lat_to_hit


ratio_thresh = 0.60

grid_lo, grid_hi = 0.55, 1.80
merge_max = 0.50

period_lo, period_hi = 0.40, 1.50
period_probe_traces = 120

pp_gap_split = 10000

window_margin = 8
align_offsets = 4
align_probe_traces = 40

band_lo = 0.88
band_hi = 0.99

llr_margin = 2.0
llr_folds = 3

history_taps = 2
history_ridge = 1e-2

phase_steps = {"fr": 1, "ps": 4, "pp": 4}
phase_probe_traces = 120
seed_by_contrast = False

ps_posterior = 0.99
ps_fit_rounds = 8

count_cap = 12
count_em_rounds = 60
count_prior = 0.5
mode_halfwidth = 0.05
llr_first_pass = 2.5


BuiltinLine = namedtuple("BuiltinLine", "handler off role")


def load_builtin_lines(directory):
    path = os.path.join(directory, "channels")
    if not os.path.exists(path):
        raise SystemExit(f"no `channels` metadata in {directory} -- the "
                         f"capture is incomplete; re-run run_ecdh_ct.sh")
    lines, prim = [], "fr"
    for ln in open(path):
        if ln.startswith("#") or not ln.strip():
            continue
        f = ln.split()
        lines.append(BuiltinLine(handler=f[2], off=f[3], role=f[1]))
        prim = f[4] if len(f) > 4 else prim
    return lines, prim


def load_trace(filepath, primitive):
    attack = "FR" if primitive == "fr" else "PS"
    df = utils.load_trace(filepath)
    cols = []
    for i in range(df.shape[1]):
        ts = [p[0] for p in df[i]
              if p is not None and p[0] > 0 and lat_to_hit(p[1], attack)]
        cols.append(np.array(sorted(ts), dtype=np.int64))
    return cols


def split_gap(gaps):
    lg = np.log10(np.maximum(gaps, 1))
    lo, hi = lg.min(), lg.max()
    if hi - lo < 0.3:
        return None
    c0, c1 = lo, hi
    for _ in range(30):
        mid = 0.5 * (c0 + c1)
        left, right = lg[lg <= mid], lg[lg > mid]
        if not len(left) or not len(right):
            return None
        n0, n1 = left.mean(), right.mean()
        if abs(n0 - c0) < 1e-6 and abs(n1 - c1) < 1e-6:
            break
        c0, c1 = n0, n1
    return 10 ** (0.5 * (c0 + c1))


def fit_uniform_grid(starts, T):
    idx = np.concatenate(([0.0], np.cumsum(
        np.maximum(np.rint(np.diff(starts) / T), 1.0))))
    a, b = np.polyfit(idx, starts, 1)[::-1]
    for _ in range(3):
        resid = starts - (a + b * idx)
        s = 1.4826 * float(np.median(np.abs(resid))) + 1e-9
        keep = np.abs(resid) < 3.0 * s
        if keep.sum() < 8:
            break
        a, b = np.polyfit(idx[keep], starts[keep], 1)[::-1]
    if not (grid_lo * T < b < grid_hi * T):
        return None, None
    return a + b * np.arange(int(idx[-1]) + 1), float(b)


def ladder_anchor(pooled, starts, T, nbits, tol=1):
    pos = np.floor((pooled - starts[0]) / T).astype(np.int64)
    pos = pos[(pos >= 0) & (pos < len(starts))]
    occ = np.zeros(len(starts), dtype=bool)
    occ[np.unique(pos)] = True

    best_start, best_len = 0, 0
    i, n = 0, len(occ)
    while i < n:
        if not occ[i]:
            i += 1
            continue
        j, miss, last = i, 0, i
        while j < n:
            if occ[j]:
                last, miss = j, 0
            else:
                miss += 1
                if miss > tol:
                    break
            j += 1
        if last - i + 1 > best_len:
            best_start, best_len = i, last - i + 1
        i = j + 1
    return best_start


def count_mixture_ll(K, cap=None, rounds=None):
    cap = count_cap if cap is None else cap
    rounds = count_em_rounds if rounds is None else rounds
    K = np.clip(np.rint(np.atleast_2d(K)).astype(int), 0, cap)
    col = np.array([np.bincount(K[:, i], minlength=cap + 1)
                    for i in range(K.shape[1])], dtype=float)
    w = (K.mean(axis=0) >= np.median(K)).astype(float)
    p0 = p1 = None
    pi = 0.5
    for _ in range(rounds):
        h0 = w @ col + count_prior
        h1 = (1.0 - w) @ col + count_prior
        p0, p1 = h0 / h0.sum(), h1 / h1.sum()
        pi = min(max(float(w.mean()), 0.02), 0.98)
        d = col @ (np.log(p0) - np.log(p1)) + np.log(pi / (1.0 - pi))
        w_new = 1.0 / (1.0 + np.exp(-np.clip(d, -60, 60)))
        if np.max(np.abs(w_new - w)) < 1e-6:
            break
        w = w_new
    return float(np.sum(np.logaddexp(col @ np.log(p0) + np.log(pi),
                                     col @ np.log(p1) + np.log(1.0 - pi))))


def capture_period(files, primitive, nbits, sample=None):
    thresh = pp_gap_split if primitive == "pp" else None
    est = []
    for fp in files[:sample or len(files)]:
        cols = load_trace(fp, primitive)
        nonempty = [c for c in cols if len(c)]
        if not nonempty:
            continue
        pooled = np.sort(np.concatenate(nonempty))
        if len(pooled) < 16:
            continue
        _, T = find_slots(pooled, nbits, thresh=thresh)
        span = float(pooled[-1] - pooled[0])
        if not T or span <= 0:
            continue
        if period_lo < nbits * T / span < period_hi:
            est.append(T)
    return float(np.median(est)) if est else None


def find_slots(all_hits, nbits=None, T_hint=None, thresh=None):
    if len(all_hits) < 16:
        return None, None
    gaps = np.diff(all_hits)

    if T_hint:
        cut = np.flatnonzero(gaps > merge_max * T_hint) + 1
        starts = np.concatenate(([all_hits[0]], all_hits[cut])).astype(float)
        if len(starts) < 8:
            return None, None
        grid, T = fit_uniform_grid(starts, float(T_hint))
        if grid is None or (nbits and len(grid) < nbits):
            return None, None
        return grid, T

    if thresh is None:
        thresh = split_gap(gaps)
        if thresh is None:
            return None, None

    cut = np.flatnonzero(gaps > thresh) + 1
    starts = np.concatenate(([all_hits[0]], all_hits[cut])).astype(float)
    if len(starts) < 8:
        return None, None

    step = np.diff(starts)
    period = float(np.median(step))
    core = step[(step > grid_lo * period) & (step < grid_hi * period)]
    T = float(np.median(core)) if len(core) else period
    if T <= 0:
        return None, None

    cut = np.flatnonzero(gaps > merge_max * T) + 1
    starts = np.concatenate(([all_hits[0]], all_hits[cut])).astype(float)
    step = np.diff(starts)
    if len(starts) < 8:
        return None, None

    if nbits and len(starts) < nbits:
        return None, None
    return starts, T


def decode_candidates(cols, builtin_lines, nbits, tag=None, phases=1,
                      phase=None, phase_contrast=None, T_hint=None, offset=0):
    marker = [i for i, r in enumerate(builtin_lines)
              if r.role in "01" and i < len(cols)]
    clock = [i for i, r in enumerate(builtin_lines)
             if r.role == "c" and i < len(cols)]
    if not marker:
        return [], [], [], 0
    nonempty = [c for c in cols if len(c)]
    if not nonempty:
        if tag:
            print(f"  [{tag}] no hits in any column")
        return [], [], [], 0
    pooled = np.sort(np.concatenate(nonempty))
    starts, T = find_slots(pooled, nbits, T_hint)
    if starts is None:
        if tag:
            print(f"  [{tag}] could not segment {len(pooled)} hits into bursts")
        return [], [], [], 0

    nwin = len(starts) - nbits + 1
    spans = starts[nbits - 1:] - starts[:nwin]
    if T_hint:
        seed = min(max(ladder_anchor(pooled, starts, T, nbits) + offset, 0),
                   nwin - 1)
        lo0 = max(0, seed - window_margin)
        lo1 = min(nwin, seed + window_margin + 1)
        tightest = seed - lo0
    else:
        lo0, lo1 = 0, nwin
        seed = tightest = int(np.argmin(spans))

    def grid(lo, ph):
        return np.append(starts[lo:lo + nbits], starts[lo + nbits - 1] + T) - ph

    if phase_contrast is not None:
        for k in range(phases):
            phase_contrast.append(candidate_contrast(
                decode_window(cols, marker, clock, builtin_lines,
                              grid(seed, k * T / phases))[1]))
    ph = (phase or 0.0) * T
    out = []
    for lo in range(lo0, lo1):
        out.append(decode_window(cols, marker, clock, builtin_lines,
                                 grid(lo, ph)))
    counts = [c for _, _, c in out]
    ratios = [r for _, r, _ in out]
    out = [k for k, _, _ in out]
    if tag:
        print(f"  [{tag}] {len(pooled)} hits, {len(starts)} slots for {nbits} "
              f"bits, T~{T:.0f}, {lo1 - lo0}/{nwin} windows x "
              f"{max(phases, 1)} phases, seed at +{seed}")
    return out, ratios, counts, tightest


def decode_window(cols, marker, clock, builtin_lines, edges):
    n = len(edges) - 1

    def counts(idxs):
        total = np.zeros(n, dtype=float)
        for i in idxs:
            pos = np.searchsorted(edges, cols[i], side="right") - 1
            pos = pos[(pos >= 0) & (pos < n)]
            total += np.bincount(pos, minlength=n)
        return total / len(idxs) if idxs else total

    m = counts(marker)
    c = counts(clock) if clock else np.full(n, 4.0)
    marker_value = builtin_lines[marker[0]].role
    other = "1" if marker_value == "0" else "0"

    empty = (m == 0) & (c == 0)
    labels = np.where(m / np.maximum(c, 1) >= ratio_thresh, marker_value, other)
    labels[empty] = "u"

    scale = float(np.median(c))
    score = m / (scale if scale > 0 else 1.0)
    score[empty] = np.nan
    return "".join(labels), score, m


def candidate_contrast(score):
    s = score[np.isfinite(score)]
    if len(s) < 8:
        return -np.inf
    c0, c1 = float(s.min()), float(s.max())
    if c1 - c0 < 1e-9:
        return -np.inf
    for _ in range(30):
        mid = 0.5 * (c0 + c1)
        lo, hi = s[s <= mid], s[s > mid]
        if not len(lo) or not len(hi):
            return -np.inf
        n0, n1 = float(lo.mean()), float(hi.mean())
        if abs(n0 - c0) < 1e-9 and abs(n1 - c1) < 1e-9:
            break
        c0, c1 = n0, n1
    lo, hi = s[s <= 0.5 * (c0 + c1)], s[s > 0.5 * (c0 + c1)]
    sd = np.sqrt((lo.var() * len(lo) + hi.var() * len(hi)) / len(s))
    return (c1 - c0) / max(float(sd), 1e-6)


def majority(keys):
    n = min(len(k) for k in keys)
    out = []
    for i in range(n):
        z = sum(k[i] == "0" for k in keys)
        o = sum(k[i] == "1" for k in keys)
        out.append("0" if z > o else "1" if o > z else "u")
    return "".join(out)


def zero_cluster(f, halfwidth=None):
    halfwidth = mode_halfwidth if halfwidth is None else halfwidth
    g = f[np.isfinite(f)]
    if len(g) < 8:
        return None, None
    grid = np.linspace(g.min(), g.max(), 400)
    dens = np.array([np.sum(np.abs(g - c) <= halfwidth) for c in grid])
    core = g[np.abs(g - grid[int(np.argmax(dens))]) <= halfwidth]
    return float(core.mean()), max(float(core.std()), 1e-3)


def fit_history_fir(z, f, K=None, ridge=None):
    K = history_taps if K is None else K
    ridge = history_ridge if ridge is None else ridge
    n = len(z)
    X = np.stack([np.ones(n)] +
                 [np.concatenate([np.zeros(k), z[:-k]]) for k in range(1, K + 1)], 1)
    ones = z < 0.5
    ones[:K] = False
    if ones.sum() < 4 * (K + 1):
        return None, None
    A, y = X[ones], f[ones]
    pen = np.eye(K + 1) * ridge
    pen[0, 0] = 0.0
    w = np.linalg.solve(A.T @ A + pen * len(y), A.T @ y)
    sd = max(float((y - A @ w).std()), 1e-3)
    return w, sd


def fit_matched_kernel(z, f, taps, ridge=None):
    ridge = history_ridge if ridge is None else ridge
    n = len(f)
    X = np.ones((n, taps + 1))
    for k in range(taps):
        col = np.zeros(n)
        if k < n:
            col[k:] = z[:n - k]
        X[:, k + 1] = col
    gram = X.T @ X + ridge * np.eye(taps + 1)
    coef = np.linalg.solve(gram, X.T @ f)
    return float(coef[0]), coef[1:]


def ps_noise_sd(f, c, h, z=None):
    if z is None:
        return max(float(np.std(f)) * 0.5, 1e-3)
    resid = f - (c + history_convolve(z, h))
    return max(float(np.std(resid)), 1e-3)


def history_convolve(z, h):
    out = np.zeros(len(z))
    for k, hk in enumerate(h):
        if k:
            out[k:] += hk * z[:len(z) - k]
        else:
            out += hk * z
    return out


def viterbi_matched(f, c, h, sd, posteriors=False):
    n = len(f)
    taps = len(h)
    mem = taps - 1
    nstates = 1 << mem if mem > 0 else 1

    lvl = np.zeros((nstates, 2))
    for s in range(nstates):
        past = [(s >> k) & 1 for k in range(mem)]
        base = c + sum(h[k + 1] * past[k] for k in range(mem))
        lvl[s, 0] = base
        lvl[s, 1] = base + h[0]
    emit = -0.5 * ((f[:, None, None] - lvl[None, :, :]) / sd) ** 2

    def nxt(s, b):
        return ((s << 1) | b) & (nstates - 1) if mem else 0

    neg = -1e18
    delta = np.full((n, nstates), neg)
    back = np.zeros((n, nstates), dtype=np.int64)
    delta[0, 0] = 0.0
    for i in range(n):
        if i:
            prev = delta[i - 1]
            for s in range(nstates):
                if prev[s] <= neg / 2:
                    continue
                for b in (0, 1):
                    t = nxt(s, b)
                    cand = prev[s] + emit[i - 1, s, b]
                    if cand > delta[i, t]:
                        delta[i, t] = cand
                        back[i, t] = s * 2 + b
    final = np.full(nstates, neg)
    last_choice = np.zeros(nstates, dtype=np.int64)
    for s in range(nstates):
        if delta[n - 1, s] <= neg / 2:
            continue
        for b in (0, 1):
            cand = delta[n - 1, s] + emit[n - 1, s, b]
            if cand > final[nxt(s, b)]:
                final[nxt(s, b)] = cand
                last_choice[nxt(s, b)] = s * 2 + b

    z = np.zeros(n, dtype=np.int64)
    s = int(np.argmax(final))
    s, b = last_choice[s] // 2, last_choice[s] % 2
    z[n - 1] = b
    for i in range(n - 1, 0, -1):
        prev, b = back[i, s] // 2, back[i, s] % 2
        z[i - 1] = b
        s = prev
    if not posteriors:
        return z, None

    fw = np.full((n + 1, nstates), neg)
    fw[0, 0] = 0.0
    for i in range(n):
        for s in range(nstates):
            if fw[i, s] <= neg / 2:
                continue
            for b in (0, 1):
                t = nxt(s, b)
                fw[i + 1, t] = np.logaddexp(fw[i + 1, t], fw[i, s] + emit[i, s, b])
    bw = np.full((n + 1, nstates), neg)
    bw[n, :] = 0.0
    for i in range(n - 1, -1, -1):
        for s in range(nstates):
            acc = neg
            for b in (0, 1):
                acc = np.logaddexp(acc, emit[i, s, b] + bw[i + 1, nxt(s, b)])
            bw[i, s] = acc

    post = np.zeros(n)
    for i in range(n):
        num = np.full(2, neg)
        for s in range(nstates):
            if fw[i, s] <= neg / 2:
                continue
            for b in (0, 1):
                num[b] = np.logaddexp(
                    num[b], fw[i, s] + emit[i, s, b] + bw[i + 1, nxt(s, b)])
        tot = np.logaddexp(num[0], num[1])
        post[i] = float(np.exp(num[1] - tot)) if np.isfinite(tot) else 0.5
    return z, post


def history_predict_fir(z, w):
    K = len(w) - 1
    n = len(z)
    X = np.stack([np.ones(n)] +
                 [np.concatenate([np.zeros(k), z[:-k]]) for k in range(1, K + 1)], 1)
    return X @ w


def history_llr_fir(f, z, a, sd_a, w, sd_1):
    p1 = history_predict_fir(z, w)
    return ((-0.5 * ((f - a) / sd_a) ** 2 - np.log(sd_a)) -
            (-0.5 * ((f - p1) / sd_1) ** 2 - np.log(sd_1)))


CURVE25519_N = 2 ** 252 + 27742317777372353535851937790883648493


class EC_KEY:

    def __init__(self, key_str, builtin_lines, primitive):
        if not key_str.startswith("0x"):
            key_str = "0x" + key_str
        self.secret_key = int(key_str, 16)
        self.secret_key %= CURVE25519_N
        self.secret_key_bin = bin(self.secret_key)[2:]
        self.secret_key_bits = len(self.secret_key_bin)
        self.builtin_lines = builtin_lines
        self.primitive = primitive
        self.phase = 0.0
        self.period = None
        self.offset = 0
        self.infer_keys = []
        self.candidates = []
        self.offsets = []
        self.scores = None
        self.counts = None

    @classmethod
    def load(cls, path, builtin_lines, primitive):
        raw = open(path).read().strip()
        if raw.startswith("{"):
            raw = json.loads(raw)["key1"].strip()
        return cls(raw, builtin_lines, primitive)

    def infer_file(self, filename, debug=False, phase_contrast=None):
        name = os.path.basename(filename)
        cols = load_trace(filename, self.primitive)
        cands, ratios, counts, tightest = decode_candidates(
            cols, self.builtin_lines, self.secret_key_bits,
            name if debug else None, phase_steps.get(self.primitive, 1),
            self.phase, phase_contrast, self.period, self.offset)
        if cands:
            self.candidates.append((name, cands, ratios, counts, tightest))

    def pick_phase(self, files, verbose=False):
        steps = phase_steps.get(self.primitive, 1)
        if steps <= 1:
            return
        total = np.zeros(steps)
        seen = 0
        for fp in files[:phase_probe_traces]:
            con = []
            cols = load_trace(fp, self.primitive)
            decode_candidates(cols, self.builtin_lines, self.secret_key_bits,
                              None, steps, 0.0, con, self.period)
            if len(con) == steps and np.all(np.isfinite(con)):
                total += np.array(con)
                seen += 1
        if seen:
            k = int(np.argmax(total))
            self.phase = k / steps
            if verbose or k:
                print(f"  phase: {k}/{steps} of the bit period "
                      f"(from {seen} traces)")

    def pick_alignment(self, files, verbose=False):
        steps = phase_steps.get(self.primitive, 1)
        best = None
        for off in range(align_offsets):
            for k in range(max(steps, 1)):
                K = []
                for fp in files[:align_probe_traces]:
                    cols = load_trace(fp, self.primitive)
                    cands, _, counts, tight = decode_candidates(
                        cols, self.builtin_lines, self.secret_key_bits, None,
                        1, k / max(steps, 1), None, self.period, off)
                    if cands:
                        K.append(counts[tight])
                if len(K) < 4:
                    continue
                width = min(len(c) for c in K)
                ll = count_mixture_ll(np.array([c[:width] for c in K]))
                if best is None or ll > best[0]:
                    best = (ll, off, k / max(steps, 1))
        if best:
            _, self.offset, self.phase = best
            if verbose:
                print(f"  alignment: offset {self.offset} slot(s), phase "
                      f"{self.phase:.2f} of the bit period "
                      f"(log-lik {best[0]:.0f})")

    def infer_directory(self, output_dir, debug=False):
        files = sorted(glob.glob(os.path.join(output_dir, "*.out")))
        if not files:
            raise ValueError(f"no .out traces in {output_dir}")
        if self.primitive in ("pp", "ps"):
            self.period = capture_period(files, self.primitive,
                                         self.secret_key_bits,
                                         period_probe_traces)
        if self.period:
            if debug:
                print(f"  capture bit period: {self.period:.0f} cyc")
            self.pick_alignment(files, True)
        else:
            self.pick_phase(files, debug)
        for fp in files:
            self.infer_file(fp, debug)

    def align_candidates(self, rounds=3, verbose=False):
        if not self.candidates:
            return
        chosen = []
        for _, cands, ratios, _, tight in self.candidates:
            best = tight
            if seed_by_contrast:
                con = [candidate_contrast(r) for r in ratios]
                if np.any(np.isfinite(con)):
                    best = int(np.argmax(con))
            chosen.append(min(best, len(cands) - 1))
        for _ in range(rounds):
            ref = majority([c[chosen[i]]
                            for i, (_, c, _, _, _) in enumerate(self.candidates)])
            new = [int(np.argmax([self.agreement(k, ref) for k in c]))
                   for _, c, _, _, _ in self.candidates]
            if new == chosen:
                break
            chosen = new
        self.offsets = chosen
        self.infer_keys = [(nm, c[chosen[i]])
                           for i, (nm, c, _, _, _) in enumerate(self.candidates)]
        self.scores = np.array([r[chosen[i]]
                                for i, (_, _, r, _, _) in enumerate(
                                    self.candidates)])
        self.counts = np.array([n[chosen[i]]
                                for i, (_, _, _, n, _) in enumerate(
                                    self.candidates)])
        if verbose:
            for i, (nm, c, _, _, t) in enumerate(self.candidates):
                print(f"  {nm}: {len(c)} windows, tightest +{t}, "
                      f"chose +{chosen[i]}")


    @staticmethod
    def agreement(a, b):
        co = ag = 0
        for x, y in zip(a, b):
            if x in "01" and y in "01":
                co += 1
                ag += x == y
        return ag / co if co else 0.0

    def all_traces(self):
        return list(range(len(self.infer_keys)))

    def mean_score(self, kept):
        s = np.atleast_2d(self.scores)[kept]
        with np.errstate(invalid="ignore"):
            return np.nanmean(s, axis=0)

    def vote(self, kept, lo=None, hi=None):
        lo = band_lo if lo is None else lo
        hi = band_hi if hi is None else hi
        r0 = self.mean_score(kept)
        pred = []
        known = correct = unknown = 0
        for i in range(self.secret_key_bits):
            if r0[i] >= hi:
                bit = "0"
            elif r0[i] <= lo:
                bit = "1"
            else:
                bit = "u"
            pred.append(bit)
            if bit == "u":
                unknown += 1
            else:
                known += 1
                correct += bit == self.secret_key_bin[i]
        return "".join(pred), {
            "bits": self.secret_key_bits,
            "known": known,
            "unknown": unknown,
            "wrong": known - correct,
            "known_acc": correct / known if known else None,
            "traces": len(kept),
            "band": (round(lo, 3), round(hi, 3)),
        }


    @staticmethod
    def history_labels(f, margin):
        a, sd_a = zero_cluster(f)
        if a is None:
            return None, None
        z = (f >= a - llr_first_pass * sd_a).astype(float)
        def fit(zz):
            return fit_history_fir(zz, f)

        def llr(zz, par):
            return history_llr_fir(f, zz, a, sd_a, par[0], par[1])

        par = fit(z)
        if par[0] is None:
            return None, None
        for _ in range(12):
            got = fit(z)
            if got[0] is None:
                break
            par = got
            new = (llr(z, par) > 0).astype(float)
            if np.array_equal(new, z):
                break
            z = new
            if new.sum() >= 8:
                a = float(f[new > 0.5].mean())
                sd_a = max(float(f[new > 0.5].std()), 1e-3)
        got = fit(z)
        if got[0] is not None:
            par = got
        d = llr(z, par)
        lab = ["0" if x > margin else "1" if x < -margin else "u" for x in d]
        shape, sd_1 = par
        return lab, (shape, a, sd_a, sd_1)

    def vote_history(self, kept, margin=None, folds=None):
        margin = llr_margin if margin is None else margin
        folds = llr_folds if folds is None else folds
        n = self.secret_key_bits
        f = self.mean_score(kept)
        pred, model = self.history_labels(f, margin)
        if pred is None:
            return self.vote(kept)

        eff_folds = folds if folds > 1 and len(kept) >= 4 * folds else 1
        if eff_folds > 1:
            s = np.atleast_2d(self.scores)[kept]
            for k in range(folds):
                with np.errstate(invalid="ignore"):
                    sub = np.nanmean(s[k::folds], axis=0)
                lab, _ = self.history_labels(sub, margin)
                if lab is None:
                    continue
                pred = [p if p == q and p != "u" else "u"
                        for p, q in zip(pred, lab)]

        pred = list(pred)
        pred[n - 1] = "u"
        shape, A, sd_a, sd_1 = model

        known = correct = unknown = 0
        for i in range(n):
            if pred[i] == "u":
                unknown += 1
            else:
                known += 1
                correct += pred[i] == self.secret_key_bin[i]
        return "".join(pred), {
            "bits": n,
            "known": known,
            "unknown": unknown,
            "wrong": known - correct,
            "known_acc": correct / known if known else None,
            "traces": len(kept),
            "band": None,
            "folds": eff_folds,
            "model": (tuple(round(float(v), 3) for v in np.atleast_1d(shape)),
                      round(A, 3), round(sd_a, 4), round(float(sd_1), 3)),
        }

    def matched_labels(self, f, taps, margin, kernel):
        n = len(f)
        fin = np.isfinite(f)
        if fin.sum() < 8 * taps:
            return None, None
        g = np.where(fin, f, np.nanmedian(f[fin]))

        if kernel is not None:
            c, h = kernel
        else:
            z = (g >= np.median(g)).astype(float)
            c, h = None, None
            for _ in range(ps_fit_rounds):
                c, h = fit_matched_kernel(z, g, taps)
                if not np.any(h > 0):
                    return None, None
                z_new, _ = viterbi_matched(g, c, h, ps_noise_sd(g, c, h, z))
                if np.array_equal(z_new, z):
                    break
                z = z_new

        sd = ps_noise_sd(g, c, h, None)
        z_hat, post = viterbi_matched(g, c, h, sd, posteriors=True)

        marker_value = self.builtin_lines[
            [i for i, r in enumerate(self.builtin_lines)
             if r.role in "01"][0]].role
        other = "1" if marker_value == "0" else "0"

        pred = []
        for i in range(n):
            p = post[i] if i < len(post) else 0.5
            conf = max(p, 1.0 - p)
            if conf < margin:
                pred.append("u")
            else:
                pred.append(marker_value if z_hat[i] else other)
        return pred, (c, h, sd)

    def vote_matched(self, kept, taps=None, margin=None, kernel=None, folds=None):
        taps = history_taps + 1 if taps is None else taps
        margin = ps_posterior if margin is None else margin
        folds = llr_folds if folds is None else folds
        n = self.secret_key_bits
        f = self.mean_score(kept)
        pred, model = self.matched_labels(f, taps, margin, kernel)
        if pred is None:
            return self.vote(kept)

        eff_folds = folds if folds > 1 and len(kept) >= 4 * folds else 1
        if eff_folds > 1:
            s = np.atleast_2d(self.scores)[kept]
            for k in range(folds):
                with np.errstate(invalid="ignore"):
                    sub = np.nanmean(s[k::folds], axis=0)
                lab, _ = self.matched_labels(sub, taps, margin, kernel)
                if lab is None:
                    continue
                pred = [p if p == q and p != "u" else "u"
                        for p, q in zip(pred, lab)]

        pred = list(pred)
        pred[n - 1] = "u"
        c, h, sd = model

        known = correct = unknown = 0
        for i in range(n):
            if pred[i] == "u":
                unknown += 1
            else:
                known += 1
                correct += pred[i] == self.secret_key_bin[i]
        return "".join(pred), {
            "bits": n,
            "known": known,
            "unknown": unknown,
            "wrong": known - correct,
            "known_acc": correct / known if known else None,
            "traces": len(kept),
            "band": None,
            "folds": eff_folds,
            "model": (tuple(round(float(v), 3) for v in np.atleast_1d(h)),
                      round(float(c), 3), round(float(sd), 4),
                      "profiled" if kernel is not None else "blind"),
        }

    def per_trace_accuracy(self, kept):
        return [self.agreement(self.infer_keys[i][1], self.secret_key_bin)
                for i in kept]


def print_key_comparison(true_bits, pred, width=60):
    color = sys.stdout.isatty()
    red, dim, rst = ("\033[31;1m", "\033[2m", "\033[0m") if color else ("", "", "")
    legend = ("[red=wrong, dim=unknown]" if color else
              "[marked '^'=wrong, '.'=unknown]")
    print(f"\nreal vs inferred scalar (MSB-first) {legend}")
    for lo in range(0, len(true_bits), width):
        t_row = true_bits[lo:lo + width]
        p_row = pred[lo:lo + width]
        infer = "".join(
            f"{dim}{p}{rst}" if p == "u" else
            f"{red}{p}{rst}" if p != t else p
            for t, p in zip(t_row, p_row))
        diff = "".join(
            "." if p == "u" else "^" if p != t else " "
            for t, p in zip(t_row, p_row))
        print(f"  [{lo:>4}] real : {t_row}")
        print(f"  [{lo:>4}] infer: {infer}")
        print(f"          {diff}")


def channel_counts(path):
    marker = clock = 0
    with open(path) as fp:
        for line in fp:
            for i, cell in enumerate(line.rstrip("\n").split("\t")[:2]):
                ts, _, lat = cell.partition(":")
                if lat and ts.isdigit() and ts != "0":
                    if i == 0:
                        marker += 1
                    else:
                        clock += 1
    return marker, clock


def capture_health(directory, marker_lo=250, marker_hi=650,
                   clock_lo=300, clock_hi=1300):
    files = sorted(glob.glob(os.path.join(directory, "r*.out")))
    if not files:
        return f"{directory}: no traces", False
    counts = [channel_counts(f) for f in files]
    marker = statistics.median(c[0] for c in counts)
    clock = statistics.median(c[1] for c in counts)
    why = []
    if not marker_lo <= marker <= marker_hi:
        why.append(f"marker {marker:.0f} outside [{marker_lo},{marker_hi}]")
    if not clock_lo <= clock <= clock_hi:
        why.append(f"clock {clock:.0f} outside [{clock_lo},{clock_hi}]")
    verdict = "ok" if not why else "BAD: " + ", ".join(why)
    return f"marker {marker:.0f} clock {clock:.0f} n {len(files)} -> {verdict}", not why


def decode_one_key(args):
    directory, key_path = args
    builtin_lines, primitive = load_builtin_lines(directory)
    skey = EC_KEY.load(key_path, builtin_lines, primitive)
    skey.infer_directory(directory)
    skey.align_candidates()
    if not skey.infer_keys:
        return None
    kept = skey.all_traces()
    if primitive == "ps":
        pred, st = skey.vote_matched(kept)
    else:
        pred, st = skey.vote_history(kept, llr_margin, llr_folds)
    nbits = st["known"] + st["unknown"]
    return {"known": st["known"], "unknown": st["unknown"], "wrong": st["wrong"],
            "traces": st["traces"], "known_acc": st["known_acc"],
            "coverage": 100.0 * st["known"] / nbits,
            "fallback": "model" not in st and "counts_model" not in st}


def infer_key_pool(output_dir, tag, runs, keys, jobs):
    pool = os.path.join(find_project_root(), "experiments", "v8_ecdh",
                        "ec_key_pool")
    todo = []
    for k in range(keys):
        d = os.path.join(output_dir, f"pp_{tag}_k{k}_r{runs:05d}")
        if os.path.isdir(d):
            todo.append((k, d, os.path.join(pool, f"ec_key_{k}.json")))
    if not todo:
        print(f"no captures under {output_dir} for tag {tag}")
        return 1

    results = {}
    with concurrent.futures.ProcessPoolExecutor(jobs) as ex:
        futs = {ex.submit(decode_one_key, (d, kp)): k for k, d, kp in todo}
        for f in concurrent.futures.as_completed(futs):
            results[futs[f]] = f.result()

    print(f"{'key':>4} {'known':>6} {'coverage':>9} {'wrong':>6} {'known-acc':>10}")
    good = []
    for k, _, _ in todo:
        r = results.get(k)
        if r is None:
            print(f"{k:>4} {'-':>6} {'-':>9} {'-':>6} {'no traces':>10}")
            continue
        acc = "none" if r["known_acc"] is None else f"{r['known_acc']:.5f}"
        flag = "  [band fallback]" if r["fallback"] else ""
        print(f"{k:>4} {r['known']:>6} {r['coverage']:>8.2f}% {r['wrong']:>6} "
              f"{acc:>10}{flag}")
        if r["known_acc"] is not None:
            good.append(r)

    if not good:
        print("\nno key decoded")
        return 1
    acc = sorted(r["known_acc"] for r in good)
    cov = sorted(r["coverage"] for r in good)
    rec = sorted(r["coverage"] * r["known_acc"] for r in good)
    def triple(v, scale=1.0):
        return (f"{scale * v[0]:.1f} / {scale * statistics.median(v):.1f} / "
                f"{scale * v[-1]:.1f}")
    print(f"\n{len(good)}/{len(todo)} keys decoded")
    print(f"  bits predicted             {triple(cov)} %")
    print(f"  bits of the key recovered  {triple(rec)} %")
    print(f"  accuracy on predicted bits {triple(acc, 100)} %")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract an ECDH private scalar from v8_ctjs_ecdh traces")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-d", "--directory", help="capture directory of *.out traces")
    src.add_argument("-f", "--file", help="single .out trace")
    src.add_argument("--all_keys", help="output directory holding one capture per pool key")
    src.add_argument("--health", help="capture directory to accept or reject")
    parser.add_argument("--key", help="key file the capture used: ec_key_<i>.json pool entry or raw-hex scalar")
    parser.add_argument("--tag", default="paper", help="capture tag used by e2e.sh")
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--keys", type=int, default=100)
    parser.add_argument("--jobs", type=int, default=10)
    parser.add_argument("--debug", action="store_true", help="per-trace diagnostics")
    args = parser.parse_args()

    if args.health:
        line, ok = capture_health(args.health)
        print(line)
        raise SystemExit(0 if ok else 1)

    if args.all_keys:
        raise SystemExit(infer_key_pool(args.all_keys, args.tag, args.runs,
                                        args.keys, args.jobs))

    if not args.key:
        raise SystemExit("--key is required with -d/-f")

    directory = args.directory or os.path.dirname(args.file)
    builtin_lines, primitive = load_builtin_lines(directory)
    print(f"capture {directory}")
    print(f"  primitive {primitive}, channels: " + ", ".join(
        f"col{i} role '{r.role}' {r.handler}+{r.off}"
        for i, r in enumerate(builtin_lines)))

    skey = EC_KEY.load(args.key, builtin_lines, primitive)
    print(f"  secret scalar: {skey.secret_key_bits} bits (MSB-first)")

    if args.file:
        skey.infer_file(args.file, args.debug)
    else:
        skey.infer_directory(directory, args.debug)

    skey.align_candidates(verbose=args.debug)
    if not skey.infer_keys:
        print("No traces decoded; run with --debug to see why.")
        raise SystemExit(1)

    kept = skey.all_traces()
    print(f"\ndecoded {len(kept)} traces")

    matched = primitive == "ps"

    if matched:
        pred, st = skey.vote_matched(kept)
    else:
        pred, st = skey.vote_history(kept, llr_margin, llr_folds)

    if "counts_model" in st:
        e = st["counts_model"]
        nm = ["P(k|0,prev 0)", "P(k|0,prev 1)", "P(k|1,prev 0)", "P(k|1,prev 1)"]
        head = ("VOTE: count sequence model, k=0..5\n        "
                + "\n        ".join(f"{a}={list(b)}" for a, b in zip(nm, e)))
    elif "model" not in st:
        why = ("no 0-cluster to anchor the history model"
               if not matched else "too few resolved slots to fit a kernel")
        head = (f"VOTE: {why} (constant scalar or thin capture) -- "
                f"fixed band {st['band']}")
    elif matched:
        h, c, sd, how = st["model"]
        head = (f"VOTE: matched filter ({how}) h={list(h)} c={c} sd={sd}, "
                f"posterior >= {ps_posterior}")
    else:
        shape, a, sd_a, sd_1 = st["model"]
        eff = st.get("folds", llr_folds)
        head = (f"VOTE: history model FIR w={list(shape)} "
                f"A={a}+-{sd_a} sd_1={sd_1}, llr margin {llr_margin}, "
                f"{eff} fold(s)"
                + (f" (asked for {llr_folds}; needs {4 * llr_folds} traces, "
                   f"have {st['traces']})" if eff != llr_folds else ""))

    pa = np.array(skey.per_trace_accuracy(kept))
    nbits = st["known"] + st["unknown"]
    acc = "  None " if st["known_acc"] is None else f"{st['known_acc']:.5f}"
    print(f"\n{head}")
    print(f"  known {st['known']:>4} ({100 * st['known'] / nbits:5.2f}%) | "
          f"unknown {st['unknown']:>4} ({100 * st['unknown'] / nbits:5.2f}%) | "
          f"wrong {st['wrong']:>3} | known-acc {acc} | {st['traces']} traces")
    print(f"  per-kept-trace acc (co-decided bits): mean {pa.mean():.5f} "
          f"min {pa.min():.5f} max {pa.max():.5f}")
    if st["wrong"] == 0 and st["unknown"] == 0:
        print("FULL KEY RECOVERED (0 wrong, 0 unknown).")
    elif st["wrong"] == 0:
        print(f"0 wrong ({st['unknown']} unknown bits left for key-recovery).")

    print_key_comparison(skey.secret_key_bin, pred)
