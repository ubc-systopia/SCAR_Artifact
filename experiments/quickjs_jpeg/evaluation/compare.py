"""
Compare a recovered jpeg-js IDCT image against the original and against the
theoretical best this side channel can reveal.

The attack recovers, per 8x8 block, how many row/column IDCT iterations took the
COMPLEX (non-flat) path -- a block "activity/edge" map, not pixel intensities.
So there are two useful references:

  original    : the grayscale original downscaled to one pixel per 8x8 block.
                This is what the paper reports cosine similarity against.
  theo_best   : the exact per-block complexity map (number of rows + columns
                with non-zero AC energy), computed from the original by an 8x8
                DCT. This is the CEILING of what this channel can reveal -- a
                perfect, noiseless attack would reproduce exactly this map, and
                its cosine to the grayscale original is the best score the
                channel's metric can reach.

Cosine similarity is computed the paper's way (mean-subtracted, sign chosen to
favor the recovery, since the map may be inverted). Outputs a side-by-side PNG:
[ original | theoretical best | recovered ].

Usage:
  python3 compare.py --orig emacs_gs.jpg --recovered recovered.jpg \
      --width 64 --height 64 --out compare.png [--ac-thresh 8]
"""
import argparse
from pathlib import Path
import numpy as np
from PIL import Image


def dct_matrix(n=8):
    k = np.arange(n)
    M = np.cos(np.pi / (2 * n) * np.outer(k, 2 * k + 1)) * np.sqrt(2 / n)
    M[0] /= np.sqrt(2)
    return M


def complexity_map(gray, w, h, ac_thresh):
    """Per-block (nz AC rows + nz AC cols) from the decoded pixels' 8x8 DCT.
    The decoded pixels' DCT approximates the dequantized coefficients that
    quantizeAndInverse branches on, so a near-zero AC value == the simple path."""
    D = dct_matrix(8)
    cm = np.zeros((h, w))
    for by in range(h):
        for bx in range(w):
            blk = gray[by * 8:by * 8 + 8, bx * 8:bx * 8 + 8].astype(float)
            C = D @ blk @ D.T
            nz_rows = sum(np.any(np.abs(C[r, 1:]) > ac_thresh) for r in range(8))
            nz_cols = sum(np.any(np.abs(C[1:, c]) > ac_thresh) for c in range(8))
            cm[by, bx] = nz_rows + nz_cols
    return cm


def cos_centered(a, b):
    """Pearson / mean-subtracted cosine: pure structural agreement."""
    a = a.ravel().astype(float); b = b.ravel().astype(float)
    a = a - a.mean(); b = b - b.mean()
    d = (np.linalg.norm(a) * np.linalg.norm(b)) + 1e-9
    c = float(np.dot(a, b) / d)
    return max(c, -c)

def cos_raw(a, b):
    """Uncentered cosine on pixel values in [0,1] (both maps oriented so that
    bright == same feature). Dominated by shared brightness, so a rough match
    scores high -- this is the lenient convention that yields ~0.8 numbers."""
    a = a.ravel().astype(float); b = b.ravel().astype(float)
    d = (np.linalg.norm(a) * np.linalg.norm(b)) + 1e-9
    return float(np.dot(a, b) / d)


def norm01(x):
    x = x.astype(float)
    lo, hi = np.percentile(x, [2, 98])
    if hi <= lo:
        hi = lo + 1
    return np.clip((x - lo) / (hi - lo), 0, 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--orig", required=True, help="original grayscale JPEG")
    ap.add_argument("--recovered", required=True, help="recovered image")
    ap.add_argument("--width", type=int, required=True, help="blocks wide (px/8)")
    ap.add_argument("--height", type=int, required=True, help="blocks tall (px/8)")
    ap.add_argument("--ac-thresh", type=float, default=8.0,
                    help="AC magnitude above which a row/col counts as complex")
    ap.add_argument("--out", default=None, help="side-by-side PNG path")
    a = ap.parse_args()

    W, H = a.width, a.height
    gray_full = np.array(Image.open(a.orig).convert("L"))
    # references
    orig_ds = np.array(Image.open(a.orig).convert("L").resize((W, H), Image.BOX),
                       dtype=float)
    theo = complexity_map(gray_full, W, H, a.ac_thresh)
    rec = np.array(Image.open(a.recovered).convert("L").resize((W, H), Image.BOX),
                   dtype=float)

    # A darker recovered pixel means more complex, so it correlates with the
    # complexity map and anti-correlates with a bright uniform background; the
    # signed/abs cosine handles either convention.
    # orient recovered & theo so bright == edge/ink, matching orig (1-gray = ink)
    orig_ink = 1 - norm01(orig_ds)
    theo_n = norm01(theo)
    rec_n = norm01(rec)
    # pick orientation of rec that best matches orig_ink (raw)
    if cos_raw(1 - rec_n, orig_ink) > cos_raw(rec_n, orig_ink):
        rec_n = 1 - rec_n
    print(f"image: {W}x{H} blocks   AC threshold: {a.ac_thresh}")
    print("RAW cosine (uncentered, the lenient ~0.8-style metric):")
    print(f"  recovered   vs original grayscale : {cos_raw(rec_n, orig_ink):.3f}")
    print(f"  theoretical vs original grayscale : {cos_raw(theo_n, orig_ink):.3f}   <- channel ceiling")
    print(f"  recovered   vs theoretical best   : {cos_raw(rec_n, theo_n):.3f}")
    print("CENTERED cosine (Pearson, pure structure -- strict):")
    rec_vs_orig = cos_centered(rec, orig_ds)
    theo_vs_orig = cos_centered(theo, orig_ds)
    rec_vs_theo = cos_centered(rec, theo)
    print(f"  recovered   vs original grayscale : {rec_vs_orig:.3f}")
    print(f"  theoretical vs original grayscale : {theo_vs_orig:.3f}   <- channel ceiling")
    print(f"  recovered   vs theoretical best   : {rec_vs_theo:.3f}")

    if a.out:
        # panels: original (dark=ink), theoretical best (dark=complex), recovered
        panels = [
            ("original", 1 - norm01(orig_ds)),        # ink dark on white
            ("theoretical best", 1 - norm01(theo)),    # edges/complex dark on white
            ("recovered", norm01(rec)),                # already complex-dark
        ]
        scale = max(4, 384 // max(W, H))
        imgs = []
        for _, p in panels:
            im = Image.fromarray((p * 255).astype(np.uint8), mode="L").resize(
                (W * scale, H * scale), Image.NEAREST)
            imgs.append(im)
        gap = 8
        total_w = sum(im.width for im in imgs) + gap * (len(imgs) - 1)
        canvas = Image.new("L", (total_w, imgs[0].height), 255)
        x = 0
        for im in imgs:
            canvas.paste(im, (x, 0)); x += im.width + gap
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        canvas.save(a.out)
        print(f"side-by-side [original | theoretical best | recovered] -> {a.out}")


if __name__ == "__main__":
    main()
