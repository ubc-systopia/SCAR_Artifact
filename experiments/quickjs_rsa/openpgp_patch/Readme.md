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

## Layout

```text
evaluation/     the run scripts, the decoder, and the analysis they call
js/impl/        the selection implementations run_eval.sh times
js/             the victim scripts and the measurement harnesses
data/           five shipped Prime+Scope traces and the ground-truth key
results/        collected CSVs, the paper figure, reference decoder output
```

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
python3 evaluation/plot_dist_paper.py
```

## Part 2: key recovery against the patched `modExp`

A Prime+Scope attack monitoring a single cache line shared by the handlers used
inside the selector and by `modExp`, reading the secret bit from the interval
between hits. No cache-set identification is performed.

One key:

```bash
cd SCAR_Artifact
experiments/quickjs_rsa/openpgp_patch/evaluation/run_bigint_select_rsa.sh
```

```bash
NUM_KEYS=100 VICTIM_RUNS=128 \
  experiments/quickjs_rsa/openpgp_patch/evaluation/run_bigint_select_rsa_pool.sh
```

Traces land in `build/output/quickjs_bigint_select_rsa/`. Decode a capture with:

```bash
python3 experiments/quickjs_rsa/openpgp_patch/evaluation/reproduce.py \
    --traces build/output/quickjs_bigint_select_rsa/<key directory>
```

### Checking the decode without capturing

Five Prime+Scope traces of one signature each ship in `data/traces/`, so the
decoder can be checked without the measurement hardware. Needs only numpy and
takes about ten seconds:

```bash
cd experiments/quickjs_rsa/openpgp_patch
./evaluation/run_offline_verify.sh
```

`reproduce.py` prints the result tables and `verify.py` asserts 42 values
against `results/expected_output.txt`, exiting non-zero on any mismatch. It
checks the exact numbers obtained from the shipped traces, so it will not pass
on newly captured ones.

## Analysis tooling

The remaining scripts in `evaluation/` support the analysis behind §4.2 rather
than the reproduction above: `run_intel_pt.sh` with `compare_intel_pt*.py`
compares the instruction traces of the two `cond` values, and
`run_opcode_timing.sh` with `analyze_opcode_timing.py` attributes the time
difference to individual QuickJS opcodes.
