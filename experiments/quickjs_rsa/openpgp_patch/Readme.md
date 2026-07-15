# OpenPGP.js constant-time `modExp` patch evaluation

OpenPGP.js version: `v5.11.2`

QuickJS version: `3b45d15`

## Description

The parent case study shows that OpenPGP.js's modular exponentiation leaks the
secret exponent bit because the selection `r = lsb ? rx : r` branches on a
secret. In response, the OpenPGP.js team proposed an *algorithmically
constant-time* replacement (`ct-modexp.patch`):

```js
r = selectBigInt(lsb, rx, r, nBitLength);
// selectBigInt(cond, a, b, maxBitLength):
//   const mask = _1n << maxBitLength;
//   return (a & (mask - cond)) | (b & (mask - _1n + cond));
```

This experiment measures whether that branchless `selectBigInt` is actually
constant-time *once executed by a real JS engine*. It times a single selection
per measurement with `rdtscp`, split by the secret bit `cond`, and reports the
single-sample distinguishability (AUC) on both V8 and QuickJS.

**Result:** the patched `selectBigInt` still leaks the secret bit on both
engines — the arbitrary-precision `BigInt` arithmetic underneath the masking is
not itself constant-time, so the source-level "constant-time" property does not
survive lowering to the engine's BigInt routines.

## Evaluation

```bash
./run_eval.sh                  # all js/*.mjs, qjs + d8

# all options:
./run_eval.sh -n 200000 -b 4095 -s 1 -c 10
#   -n samples   timed measurements per run (default 200000)
#   -b bits      operand bit-length (default 4095, ~RSA-4096 limb)
#   -s seed      PRNG seed; same operands/cond trace across engines (default 1)
#   -c cpu       taskset CPU to pin to (default 10)
```

CSVs saved in `results/<engine>_<impl>.csv`.

### Plot / Analyse

```bash
python3 plot_dist.py            # -> results/leakage_summary.csv, distribution.html
python3 plot_dist_paper.py      # -> results/selectBigInt_dist.pdf
```
