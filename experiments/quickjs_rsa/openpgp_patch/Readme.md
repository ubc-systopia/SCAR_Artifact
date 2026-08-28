# OpenPGP.js constant-time `modExp` patch

Reproduces the disclosure and patch analysis in **paper §4.2**.

QuickJS version: `3b45d15`

OpenPGP.js version: `v5.11.2`

## Description

The parent case study shows that OpenPGP.js's modular exponentiation leaks the
secret exponent bit because the selection `r = lsb ? rx : r` branches on a
secret. In response, the OpenPGP.js team proposed an *algorithmically
constant-time* replacement (`ct-modexp.patch`, included here as
`ct-modexp.zip`):

```js
function selectBigInt(cond, a, b, maxBitLength) {
    const _1n = 1n;
    const mask = _1n << maxBitLength;
    return (a & (mask - cond)) | (b & (mask - _1n + cond));
}

r = selectBigInt(lsb, rx, r, nBitLength);
```

The replacement is branchless at the source and bytecode levels, but QuickJS
takes a fast path in `BigInt` addition and subtraction when one operand is
zero. For `cond = 0n` two fast paths are taken and for `cond = 1n` neither is,
so the two values of the secret bit still differ in execution time.

## Part 1: the timing distributions

Times a single selection per measurement with `rdtscp`, split by the secret bit,
and reports the single-sample distinguishability on both QuickJS and V8.

```bash
cd experiments/quickjs_rsa/openpgp_patch
./evaluation/run_eval.sh
```

It times every selector in `js/impl/` on both QuickJS and V8 and writes
`results/<engine>_<impl>.csv`. To analyse them and draw the paper's figure:

```bash
python3 evaluation/plot_violin.py
```

That writes `results/selectbigint_timing_99.pdf`.

## Part 2: key recovery against the patched `modExp`

A Prime+Scope attack monitoring a single cache line shared by the handlers used
inside the selector and by `modExp`, reading the secret bit from the interval
between hits.


```bash
cd SCAR_Artifact
NUM_KEYS=100 VICTIM_RUNS=128 \
  experiments/quickjs_rsa/openpgp_patch/evaluation/run_bigint_select_rsa_pool.sh
```


```bash
python3 experiments/quickjs_rsa/openpgp_patch/evaluation/evaluate_pool.py \
    --pool build/output/quickjs_bigint_select_rsa --runs 128
```

```bash
python3 experiments/quickjs_rsa/openpgp_patch/evaluation/plot_gap.py \
    --traces build/output/quickjs_bigint_select_rsa/<key directory>
```
