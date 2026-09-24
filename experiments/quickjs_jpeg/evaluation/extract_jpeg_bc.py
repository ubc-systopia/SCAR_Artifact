"""
Inference for the single-process bytecode (I1/DA) attack (quickjs_jpeg_bc).

Trace channels (see quickjs_jpeg_bc.c):
  slot0 entry     - quantizeAndInverse's dequant loop + row-loop header. Fires
                    only inside this function, so it is a clean per-block marker.
  slot1 row_btf   - a cache line inside the row-pass butterfly; complex rows.
  slot2 col_btf   - a cache line inside the column-pass butterfly; complex cols.
  slot3 row_mark  - js_typed_array_constructor (the C routine behind
                    `new Uint8Array(...)`). buildComponentData allocates 8 output
                    lines at the head of every block-ROW and quantizeAndInverse
                    allocates none, so a tight burst of these marks the start of
                    each image row.

The image size is NOT an input. Both dimensions are recovered from the trace;
the true size is used elsewhere only as ground truth to score the result.

Why the row marker matters
--------------------------
Block value and block segmentation (channels 0-2) recover a 1-D stream of block
complexities. Reshaping that stream to an image needs the number of blocks in
every row. If one block is missed or an extra split is made, a single assumed
width shears every row after it (the "drift"). The row_mark channel gives the
row boundaries from hardware, so each row is cut and resized on its own and a
local miscount can no longer propagate down the image.

Pipeline
--------
1. IDCT window   = dense `entry` band.
2. Row bounds    = start of each row_mark burst (>=MIN_BURST marks within WB cyc).
3. Block bounds  = `entry` gaps (> ENTRY_GAP) inside the window.
4. Block value   = row_btf + col_btf hits per block (complexity == darkness).
5. Per row       = the blocks between two row bounds, resampled to width W.
6. Stack rows, percentile-normalize, render. No cross-row drift.

Resolution note: one IDCT iteration (~1200-2500 cyc) is below Prime+Probe's
~3000 cyc resolution, so per-block hit counts stay coarse; recovery shows image
edges rather than exact intensities. The row marker removes the geometric drift,
not that intensity coarseness.

Usage:
  extract_jpeg_bc.py -f build/output/quickjs_jpeg_bc_r00001/r0.out -o out.jpg
"""
import argparse
from pathlib import Path
import numpy as np
from PIL import Image

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from utils import load_trace  # noqa: E402
from extract_jpeg_js import _hits, _resample, _resize2d  # noqa: E402

CORE_BINS = 600
BURST_MASS = 0.92
ENTRY_GAP = 10_000    # cyc gap between per-block entry groups
MIN_ENTRY = 64
# row_mark clustering is auto-tuned over these candidates (see _best_rows); the
# right (WB, MIN) is the one that makes every image row hold the same number of
# blocks, so no single value is baked in.
WB_CAND = (2_000, 3_000, 4_000, 6_000, 8_000, 12_000)
MIN_CAND = (3, 4, 5, 6, 8)


def _idct_window(entry):
    lo, hi = entry.min(), entry.max()
    if hi <= lo:
        return lo, hi
    edges = np.linspace(lo, hi, CORE_BINS + 1)
    h, _ = np.histogram(entry, bins=edges)
    total = h.sum()
    peak = int(np.argmax(h))
    l = r = peak
    acc = h[peak]
    while acc < BURST_MASS * total and (l > 0 or r < len(h) - 1):
        left = h[l - 1] if l > 0 else -1
        right = h[r + 1] if r < len(h) - 1 else -1
        if right >= left:
            r += 1
            acc += h[r]
        else:
            l -= 1
            acc += h[l]
    return edges[l], edges[r + 1]


def _burst_starts(rmw, wb, min_burst):
    """Start time of each row_mark burst: a run of >=min_burst marks whose
    neighbours are within wb cycles. Isolated marks are line-sharing noise."""
    if len(rmw) == 0:
        return np.array([])
    cuts = np.where(np.diff(rmw) > wb)[0]
    bounds = np.concatenate([[0], cuts + 1, [len(rmw)]])
    sizes = np.diff(bounds)
    starts = rmw[bounds[:-1]]
    return starts[sizes >= min_burst]


def _best_rows(rmw, btime):
    """Auto-tune the burst clustering. Sweep (wb, min_burst) and keep the row
    segmentation whose rows are the most uniform in block count -- geometrically,
    every image row has the same width, so the true segmentation minimises the
    spread of per-row block counts (with a small term for even row spacing).
    Returns (row_start_times, per_row_block_counts) or (None, None)."""
    nblk = len(btime)
    best = None
    for wb in WB_CAND:
        for mb in MIN_CAND:
            starts = _burst_starts(rmw, wb, mb)
            R = len(starts)
            if R < 4 or R > nblk // 2:
                continue
            ridx = np.clip(np.searchsorted(starts, btime, "right") - 1, 0, R - 1)
            counts = np.array([int((ridx == r).sum()) for r in range(R)])
            counts = counts[counts > 0]
            if len(counts) < 4 or np.median(counts) < 4:
                continue
            wcv = counts.std() / (counts.mean() + 1e-9)     # width uniformity
            gg = np.diff(starts)
            scv = gg.std() / (gg.mean() + 1e-9)             # spacing evenness
            score = wcv + 0.5 * scv
            if best is None or score < best[0]:
                best = (score, starts, counts)
    if best is None:
        return None, None
    return best[1], best[2]


def block_map(filepath, at="PP", verbose=True):
    """Recover the per-block value map of one bytecode trace. Returns
    (grid, W, H); the shape is measured from the trace, not supplied."""
    df = load_trace(filepath)
    if df.shape[1] < 4:
        print(f"expected 4 channels, got {df.shape[1]} "
              f"(rebuild quickjs_jpeg_bc with the row_mark slot)")
        return None, 0, 0
    entry = _hits(df, 0, at)
    row = _hits(df, 1, at)
    col = _hits(df, 2, at)
    rmark = _hits(df, 3, at)
    if len(entry) < MIN_ENTRY:
        print(f"too few entry hits ({len(entry)})")
        return None, 0, 0
    t0 = entry[0]
    entry -= t0
    row -= t0
    col -= t0
    rmark -= t0

    a, b = _idct_window(entry)
    ew = entry[(entry >= a) & (entry <= b)]
    rw = row[(row >= a) & (row <= b)]
    cw = col[(col >= a) & (col <= b)]
    rmw = rmark[(rmark >= a) & (rmark <= b)]

    bcuts = np.where(np.diff(ew) > ENTRY_GAP)[0]
    bbounds = np.concatenate([[ew[0]], (ew[bcuts] + ew[bcuts + 1]) / 2, [ew[-1]]])
    btime = (bbounds[:-1] + bbounds[1:]) / 2.0
    vr = np.diff(np.searchsorted(rw, bbounds)).astype(np.float64)
    vc = np.diff(np.searchsorted(cw, bbounds)).astype(np.float64)
    values = vr + vc
    nblocks = len(values)

    rstarts, _ = _best_rows(rmw, btime)
    if rstarts is not None and len(rstarts) >= 2:
        row_idx = np.searchsorted(rstarts, btime, side="right") - 1
        row_idx = np.clip(row_idx, 0, len(rstarts) - 1)
        rows = [values[row_idx == r] for r in range(len(rstarts))]
        rows = [rw_ for rw_ in rows if len(rw_) > 0]
        counts = np.array([len(r) for r in rows])
        w = int(round(np.median(counts)))
        h = len(rows)
        grid = np.vstack([_resample(r, w) for r in rows])
        if verbose:
            print(f"IDCT window dur={b-a:.3e} blocks={nblocks} "
                  f"recovered {w}x{h} (WxH) row-block min/med/max="
                  f"{counts.min()}/{int(np.median(counts))}/{counts.max()}")
    else:
        w = max(1, int(round(np.sqrt(nblocks))))
        h = int(np.ceil(nblocks / w))
        v = np.full(w * h, float(np.median(values)))
        v[:nblocks] = values
        grid = v.reshape(h, w)
        if verbose:
            print(f"IDCT window dur={b-a:.3e} blocks={nblocks} "
                  f"(no row marker) recovered {w}x{h}")
    return grid, w, h


def extract_p_from_file(filepath, at="PP", image_path=None, scale=6,
                        invert=True, verbose=True):
    """Recover one or more bytecode traces of the SAME image into one picture.

    `filepath` may be a single path or a list. Per-capture SNR is low, so
    several captures are combined by averaging their z-scored block maps; a map
    whose recovered shape differs is resampled onto the first one's grid.
    """
    paths = [filepath] if isinstance(filepath, (str, Path)) else list(filepath)
    maps, W, H = [], 0, 0
    for p in paths:
        g, w, h = block_map(p, at, verbose)
        if g is None:
            continue
        if not maps:
            W, H = w, h
        elif (w, h) != (W, H):
            if verbose:
                print(f"{p}: {w}x{h} resampled to {W}x{H} for averaging")
            g = _resize2d(g, W, H)
        maps.append((g - g.mean()) / (g.std() + 1e-9))
    if not maps:
        return 0, 0, np.zeros((1, 1), np.uint8)
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

    out = Path(image_path) if image_path else Path("jpeg-bc-extraction.jpg")
    out.parent.mkdir(parents=True, exist_ok=True)
    rec = Image.fromarray(img, mode="L")
    if scale != 1:
        rec = rec.resize((W * scale, H * scale), Image.NEAREST)
    rec.save(out)
    if verbose:
        print(f"recovered ({rec.width}x{rec.height}) -> {out}")
    return H, W, img


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="quickjs jpeg-js bytecode trace -> image")
    ap.add_argument("-f", "--file", required=True, action="append",
                    help="attacker trace r0.out; repeat to average captures")
    ap.add_argument("-o", "--image", default=None)
    ap.add_argument("--att", choices=["FR", "PS", "PP"], default="PP")
    ap.add_argument("--scale", type=int, default=6)
    ap.add_argument("--no-invert", action="store_true")
    a = ap.parse_args()
    extract_p_from_file(a.file, at=a.att, image_path=a.image,
                        scale=a.scale, invert=not a.no_invert)
