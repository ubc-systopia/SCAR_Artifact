# Case Study 5: V8 — Elliptic

V8 version: `v13.9-lkgr`

Elliptic version: `v6.6.1`

## Description

Case Study 5: V8 — Elliptic evaluates the exploitability of Elliptic ECDH under
JIT-compilation.

V8 JIT-compiled code of Elliptic's ECDH implementation contains
secret-dependent control-flow which can be used to recover secret scalars. The
attack is a Prime+Scope on two cache sets of the compiled `mul()`: the ladder
loop header, which is accessed once per iteration and serves as the clock, and
a line exclusive to the `bits[i] == 1` arm, which serves as the bit marker.

## Evaluation

Capture the traces (100 keys x 100 runs, the numbers reported in the paper):

```bash
cd SCAR_Artifact/build
taskset -c 1,3,5,7 ./experiments/v8_ecdh/v8_ecdh_key_pool ../experiments/v8_ecdh/js/elliptic_ecdh_eval.js ../experiments/v8_ecdh/js/elliptic_ecdh_repeat.js ../experiments/v8_ecdh/js/elliptic_ecdh_set_keypair_template.js -tag=full_run --always-turbofan --single-threaded
```

Decode the capture:

```bash
cd SCAR_Artifact
python experiments/v8_ecdh/evaluation/extract_ecdh.py --all_keys ./build/output/full_run
```

The decoder assigns every marker event to its nearest clock tick. The per-trace
tick/bit alignment varies from trace to trace and is resolved by agreement
between the traces before they are voted together.

The paper reports minimum, median and maximum per-key accuracy of 99.6%, 100%
and 100% over 100 keys. Our two 100 x 100 captures decode to:

| capture | bits wrong | per-key min / median | traces used |
| --- | --- | --- | --- |
| `-csi` (cache sets found by fingerprint scan) | 0 / 25110 | 100% / 100% | 8832 of 10000 |
| known-address | 83 / 25110 | 85.1% / 100% | 8560 of 10000 |

The traces a capture does not use are the ones whose clock has a gap the
alignment cannot account for.

Accuracy varies a lot from launch to launch. Seven fresh `-keys=10 -runs=10`
captures taken on one afternoon decoded to 82.1, 89.3, 98.3, 99.2, 99.6, 99.9
and 99.96 percent. A capture that short costs ~1.2MB against ~120MB for the
full run, so it is the cheap way to check a setup -- but take more than one
before concluding anything from it, and see "Checking a capture" for what the
no-decode health test can and cannot tell you.

Each invocation writes into its own `output/<tag>/` subtree, so a re-run never
overwrites a previous capture.

### Running it

Pin the process to one socket (on our machine, NUMA node1 = the odd CPUs): an
unpinned run migrates across sockets, the eviction sets then probe the wrong
LLC, and the common line collapses from ~252 hits to ~12.

Four cores is enough. The capture runs four threads -- three attackers and the
victim -- and measures the same on `-c 1,3,5,7` as on all eight.

Whether the lines are usable is decided per *launch*: ASLR is off so the
virtual addresses are fixed, but the JIT page's physical mapping changes, and a
line that shares a cache set with a hot one fires every iteration no matter how
often its eviction set is rebuilt. Roughly one launch in five is like that. The
binary gives up after its rebuild budget and exits, so the fix is to relaunch,
not to wait out a run of dead traces.

Options (everything not listed here is passed on to V8, which requires its own
flags *after* the three script paths; `NOTES.md` documents the flags used for
measurement rather than reproduction):

| flag | meaning |
| --- | --- |
| `-tag=NAME` | dump traces under `output/NAME/` (default `run_<YYYYmmdd_HHMMSS>`) |
| `-keys=N` | capture the first `N` keys of the pool (default 100) |
| `-runs=N` | capture `N` traces per key (default 100) |
| `-warmup=N` | JIT warmup derives before the capture (default 10) |
| `-csi` | identify the cache sets by fingerprint scan instead of known addresses |

### Cache set identification

The default run probes the two cache sets through their known JIT addresses.
`-csi` performs the identification described in the paper instead: the victim
is invoked with three crafted keys -- `ec_key_csi_1.json` (all ones),
`ec_key_csi_0.json` (a single one), `ec_key_csi_sparse4.json` (`1000` repeating)
-- and a scanned candidate set is accepted as the clock or the marker only when
its trace matches the expectation under all three. `CSI_FLOW.md` documents the
control flow, the measured fingerprints and the open issues.

### Checking a capture

The marker line's median hit count per key should equal that key's number of
1-bits. That is a no-decode test of whether the line is alive and on target,
and it is worth running before a long capture.

It is not a predictor of decode accuracy. Over the seven launches above, the
mean deviation from the popcount ranged from -0.8 to +5.8 bits, and the launch
that deviated most (+5.8) still decoded to 99.6% while one that deviated by
+1.4 decoded to 89.3%. Use it to catch a dead or grossly over-broad eviction
set, not to grade a capture.

```bash
# per-key hit counts against each key's popcount, and how many runs are usable
python experiments/v8_ecdh/evaluation/plot_ecdh_trace.py --summary ./build/output/full_run
# one trace: three channels as a raster, plus the clock's inter-arrival gaps
python experiments/v8_ecdh/evaluation/plot_ecdh_trace.py -i ./build/output/full_run/<key dir>/r0.out
```

### Key Pool Generation

```bash
python3 gen_key_pool.py
```
