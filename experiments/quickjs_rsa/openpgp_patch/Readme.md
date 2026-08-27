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
r = selectBigInt(lsb, rx, r, nBitLength);
// selectBigInt(cond, a, b, maxBitLength):
//   const mask = _1n << maxBitLength;
//   return (a & (mask - cond)) | (b & (mask - _1n + cond));
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
./run_eval.sh                  # all js/*.mjs, qjs + d8

# all options:
./run_eval.sh -n 200000 -b 4095 -s 1 -c 10
#   -n samples   timed measurements per run (default 200000)
#   -b bits      operand bit-length (default 4095, ~RSA-4096 limb)
#   -s seed      PRNG seed; same operands/cond trace across engines (default 1)
#   -c cpu       taskset CPU to pin to (default 10)
```

CSVs are written to `results/<engine>_<impl>.csv`. To analyse and plot:

```bash
python3 plot_dist.py            # -> results/leakage_summary.csv, distribution.html
python3 plot_dist_paper.py      # -> results/selectBigInt_dist.pdf
```

## Part 2: key recovery against the patched `modExp`

A Prime+Scope attack monitoring a single cache line shared by the handlers used
inside the selector and by `modExp`, reading the secret bit from the interval
between hits. No cache-set identification is performed.

One key:

```bash
cd SCAR_Artifact
experiments/quickjs_rsa/openpgp_patch/run_select_rsa_ps.sh
```

The full 100-key pool behind the paper's numbers (100 keys x 128 signatures):

```bash
NUM_KEYS=100 VICTIM_RUNS=128 \
  experiments/quickjs_rsa/openpgp_patch/run_select_rsa_ps_pool.sh
```

The pool run is long. It is resumable: a key whose output directory already
holds the requested number of traces is skipped, and a key that fails or times
out is recorded in the log and left behind rather than aborting the pool, so
re-running the script picks up whatever is missing. Per-key status is written to
the log the script names on exit.

Decode a capture:

```bash
python experiments/quickjs_rsa/openpgp_patch/evaluation/extract_select_rsa.py \
    -d build/output/quickjs_select_rsa_ps/<key directory>
```

`run_select_rsa_eval.sh` runs the capture and the decode together for a single
key.

### Verifying the decode without capturing

`artifact_select_ps/` is a self-contained copy of this attack with traces
already included, so the analysis can be checked without the measurement
hardware. It needs `numpy` only and takes about ten seconds:

```bash
cd experiments/quickjs_rsa/openpgp_patch/artifact_select_ps
./run.sh
```

## Analysis tooling

The remaining scripts support the analysis behind §4.2 rather than the
reproduction above: `run_intel_pt.sh` with `compare_intel_pt*.py` compares the
instruction traces of the two `cond` values, and `run_opcode_timing.sh` with
`analyze_opcode_timing.py` attributes the time difference to individual QuickJS
opcodes.
