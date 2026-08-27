# Case Study 6: V8 — constant-time-js

Reproduces the results in **paper §4.5** (V8 — constant-time-js).

V8 version: `v13.9-lkgr`

## Description

Constant-time-js's branchless selectors still leak the secret condition bit,
because V8's bytecode handlers dispatch on a value's runtime representation
rather than its value. The target is Elliptic's Curve25519 ladder with its
secret-dependent branch replaced by two `select_ints` merges.

Two cache lines are monitored with Prime+Probe: one in the `BitwiseAnd` handler
that is touched only when the secret bit is 0, and one in the `Negate` handler
that is touched once per selector call and so marks off ladder iterations.

## Evaluation

Capture 100 traces for each of the first 100 pool keys, repeating a key until
its capture is healthy:

```bash
cd SCAR_Artifact
RUNS=100 TAG=paper experiments/v8_constant_time_js/evaluation/run_pp_batch.sh 0 99
```

Decode them and print the per-key statistics:

```bash
python experiments/v8_constant_time_js/evaluation/decode_pp_batch.py --tag pp_paper
```

This is the paper's configuration: it is the decoder's default. The three
quantities the paper reports, as minimum / median / maximum over the keys:

| quantity | expected |
| --- | --- |
| bits predicted | 11.9 / 62.4 / 99.2 % |
| bits of the key recovered | 10.7 / 49.4 / 91.7 % |
| accuracy on predicted bits | 44.6 / 86.8 / 96.4 % |

`--llr-folds` and `--llr-margin`, passed after a bare `--`, trade coverage
against accuracy if you want to explore the operating point.

### Requirements for a valid capture

* **Do not run two captures at once** — they ruin each other. `run_pp_batch.sh`
  takes a lock to prevent it.

* **Roughly a third of launches build an unusable eviction set** and decode at
  chance while otherwise looking healthy. `run_pp_batch.sh` therefore judges
  every launch with `capture_health.py` and repeats a key whose channels are
  out of band. A key reported as `UNHEALTHY after N attempts` in the batch log
  should be re-run.

* More traces per key does not improve the result; launch-to-launch variation
  dominates the trace count.

### Combining repeated captures

Capturing the same keys under several tags and keeping only the bits on which
the captures agree trades coverage for accuracy:

```bash
python experiments/v8_constant_time_js/evaluation/combine_pp_captures.py \
    --tags pp_paper,pp_paper2,pp_paper3 --rule agree --min-votes 3
```

This is not what the paper reports; the paper's numbers are the single-capture
ones above.

### Inspecting a capture

```bash
python experiments/v8_constant_time_js/evaluation/capture_health.py \
    build/experiments/v8_constant_time_js/output/pp_paper_k0_r00100
python experiments/v8_constant_time_js/evaluation/plot_ecdh_ct.py -d \
    build/experiments/v8_constant_time_js/output/pp_paper_k0_r00100
```
