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
python experiments/v8_constant_time_js/evaluation/decode_pp_batch.py --tag pp_paper
```


A single capture is enough for the numbers above. To trade coverage for
accuracy instead, capture the same keys two or three times under different
tags and keep only the bits the captures agree on:

```bash
python experiments/v8_constant_time_js/evaluation/combine_pp_captures.py \
    --tags pp_paper,pp_paper2,pp_paper3 --rule agree --min-votes 3
```

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

### Looking at a capture

```bash
# the health verdict a batch run uses, for one capture directory
python experiments/v8_constant_time_js/evaluation/capture_health.py \
    build/experiments/v8_constant_time_js/output/pp_paper_k0_r00100
# both channels of one capture as a raster, with the ladder segmentation
python experiments/v8_constant_time_js/evaluation/plot_ecdh_ct.py -d \
    build/experiments/v8_constant_time_js/output/pp_paper_k0_r00100
```

`evaluation/DECODING.md` documents how the decoder turns those two channels
into bits, and which of its stages earn their place.
