# Case Study 5: V8 — Elliptic

Reproduces the results in **paper §4.4** (V8 — Elliptic).

V8 version: `v13.9-lkgr`

Elliptic version: `v6.6.1`

## Description

Elliptic's ECDH scalar multiplication keeps its secret-dependent branch after
V8 JIT-compiles it. The attack monitors two cache sets of the compiled `mul()`
with Prime+Scope: the ladder loop header, which is accessed once per iteration
and acts as a clock, and a line reached only when the secret bit is 1.

## Evaluation

Capture 100 traces for each of the first 100 pool keys:

```bash
cd SCAR_Artifact/build
taskset -c 1,3,5,7 ./experiments/v8_ecdh/v8_ecdh_key_pool ../experiments/v8_ecdh/js/elliptic_ecdh_eval.js ../experiments/v8_ecdh/js/elliptic_ecdh_repeat.js ../experiments/v8_ecdh/js/elliptic_ecdh_set_keypair_template.js -tag=full_run --always-turbofan --single-threaded
```

Decode the capture:

```bash
cd SCAR_Artifact
python experiments/v8_ecdh/evaluation/extract_ecdh.py --all_keys ./build/output/full_run
```

The decoder prints one row per key and a total. The paper reports a minimum,
median and maximum per-key accuracy of 99.6%, 100% and 100%.

Each invocation writes to its own `output/<tag>/`, so a re-run never overwrites
an earlier capture. A short `-keys=10 -runs=10` capture costs ~1.2MB against
~120MB for the full run and is the quick way to check the setup first.

### Requirements for a valid capture

* **Pin the process to one socket** (`taskset`, as above). An unpinned run
  migrates across sockets, the eviction sets then probe the wrong LLC, and the
  clock line collapses from ~252 hits to ~12. Four cores are enough.

* **Some launches are unusable and must be repeated.** The JIT page's physical
  mapping changes per launch, and a probed line that shares a cache set with a
  hot one fires every iteration however often its eviction set is rebuilt.
  Roughly one launch in five is like that. The binary gives up after its
  rebuild budget and exits, so the remedy is to relaunch rather than to wait
  out a run of dead traces. Accuracy also varies between good launches.

### Options

| flag | meaning |
| --- | --- |
| `-tag=NAME` | write traces to `output/NAME/` (default `run_<YYYYmmdd_HHMMSS>`) |
| `-keys=N` | capture the first `N` keys of the pool (default 100) |
| `-runs=N` | capture `N` traces per key (default 100) |
| `-warmup=N` | JIT warmup derives before the capture (default 10) |
| `-csi` | locate the cache sets by fingerprint scan instead of by known address |

V8's own flags must come after the three script paths.

`-csi` performs the cache-set identification described in the paper: the victim
is invoked with three crafted keys (`ec_key_csi_1.json`, all ones;
`ec_key_csi_0.json`, a single one; `ec_key_csi_sparse4.json`, `1000` repeating)
and a scanned candidate is accepted only when it matches under all three.

### Key pool generation

The pool in `ec_key_pool/` is included. To regenerate it:

```bash
python3 gen_key_pool.py
```
