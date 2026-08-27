# OpenPGP.js constant-time patch: key recovery under Prime+Scope

Reproduces the attack result in **paper §4.2**, disclosure and patch analysis:
a Prime+Scope attack on 100 random 4096-bit keys recovers from 3% to 98.2% of
the exponent bits, with a median of 95.7%.

QuickJS version: `3b45d15`

OpenPGP.js version: `v5.11.2`, with the maintainers' proposed constant-time
`modExp` patch applied.

## Description

The patch replaces the secret-dependent ternary in `modExp` with the branchless
`selectBigInt`. That removes the bytecode branch, but QuickJS takes a fast path
in `BigInt` addition and subtraction when one operand is zero, so the two values
of the secret bit still differ in execution time. The attack monitors a single
cache line shared by the handlers used inside the selector and by `modExp`, and
reads the secret bit from the interval between hits. No cache-set identification
is performed.

## Evaluation

One key:

```bash
cd SCAR_Artifact
experiments/quickjs_rsa/openpgp_patch_rsa/run_select_rsa_ps.sh
```

The full 100-key pool behind the paper's numbers (100 keys x 128 signatures):

```bash
NUM_KEYS=100 VICTIM_RUNS=128 \
  experiments/quickjs_rsa/openpgp_patch_rsa/run_select_rsa_ps_pool.sh
```

The pool run is long. It is resumable: a key whose output directory already
holds the requested number of traces is skipped, and a key that fails or times
out is recorded in the log and left behind rather than aborting the pool, so
re-running the script picks up whatever is missing. Per-key status is written to
the log the script names on exit.

Decode a capture:

```bash
python experiments/quickjs_rsa/openpgp_patch_rsa/evaluation/extract_select_rsa.py \
    -d build/output/quickjs_select_rsa_ps/<key directory>
```

`run_select_rsa_eval.sh` runs the capture and the decode together for a single
key.

## Verifying without capturing

`artifact_select_ps/` is a self-contained copy of this attack with traces
already included, for checking the analysis without running the victim:

```bash
cd experiments/quickjs_rsa/openpgp_patch_rsa/artifact_select_ps
./run.sh
```

It needs `numpy` only.
