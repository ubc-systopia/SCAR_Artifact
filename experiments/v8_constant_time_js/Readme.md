# Case Study 6: V8 — constant-time-js

V8 version: `v13.9-lkgr`

## Description

Constant-time-js's branchless selectors still leak the secret condition bit,
because V8's bytecode handlers dispatch on a value's runtime representation
rather than its value. The end-to-end target is Elliptic's Curve25519 ladder
with its secret-dependent branch replaced by two `select_ints` merges.

Two lines are monitored with Prime+Probe: `BitwiseAndHandler+0x080` (the
HeapNumber `-0` slow path, touched only on a 0 bit) and `NegateHandler+0x000`
(once per `select_ints`, which marks off ladder iterations).

## Evaluation

Capture 100 traces for each of the first 100 pool keys, re-launching a key
until its capture is healthy:

```bash
cd SCAR_Artifact
RUNS=100 TAG=paper experiments/v8_constant_time_js/evaluation/run_pp_batch.sh 0 99
```

Decode them and print the per-key statistics:

```bash
python experiments/v8_constant_time_js/evaluation/decode_pp_batch.py \
    --tag pp_paper -- --llr-folds 2 --llr-margin 2
```

`--llr-folds`/`--llr-margin` trade coverage against accuracy. Measured over
100 keys: folds 3 / margin 2 (the decoder's default) gives a median of 86.9%
accuracy over 62.5% of bits, folds 2 / margin 2 gives 84.6% over 74.4%, and
folds 1 / margin 2 gives 80.6% over 90.3%. The paper reports folds 2 /
margin 2.

A single capture is enough for the numbers above. To trade coverage for
accuracy instead, capture the same keys two or three times under different
tags and keep only the bits the captures agree on:

```bash
python experiments/v8_constant_time_js/evaluation/combine_pp_captures.py \
    --tags pp_paper,pp_paper2,pp_paper3 --rule agree --min-votes 3
```

That reaches a median of 98.5% accuracy over 20.9% of bits.

### Capture health

Whether the two eviction sets are usable is decided per launch, not per key,
and roughly a third of launches build a set that shares a cache set with a hot
line. Those captures decode at chance while looking healthy, so
`run_pp_batch.sh` runs `capture_health.py` on every launch and repeats a key
whose channels are out of band. The attacker's own in-flight ceiling only
watches the clock channel and misses an over-broad marker evset.

Do not run two captures at once -- they ruin each other. `run_pp_batch.sh`
takes a lock to prevent it.

More traces per key does not help. Measured on one key with four healthy
launches at each count: 100 traces gives a median of 84.4% accuracy, 400 gives
85.7%, and 1000 gives 72.5% and is far more erratic. Launch-to-launch variation
dominates the trace count at every level.
