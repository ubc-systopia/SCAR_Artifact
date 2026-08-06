# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this directory is

This is one case study (`experiments/quickjs_rsa/`) inside the larger **SCAR_Artifact**
repository (git root: `/home/ddinh02/SCAR_Artifact`), which is the artifact for the paper
"Cache Side Channel Attacks on Language Runtimes". SCAR_Artifact has five case studies
under `experiments/`; this one attacks QuickJS running OpenPGP.js's RSA signing.

The claim under test: OpenPGP.js's `BigInteger.modExp` (`js/openpgp.js`) does square-and-multiply
with a secret-dependent ternary (`r = lsb ? rx : r`). Even though both the square and the multiply
are computed on every loop iteration (a deliberate timing-balancing attempt), QuickJS lowers the
ternary to condition-dependent bytecode control flow. A same-machine attacker who can monitor LLC
cache-set activity for two specific bytecode-handler cache lines (`sar`, the right-shift that marks
each loop iteration, and `goto8`, the conditional-branch handler tied to the ternary) can recover
the private exponent `d` bit-by-bit from repeated signatures — without measuring total signing time.

`openpgp_patch/` is a follow-up: it evaluates the OpenPGP.js team's proposed branchless
`selectBigInt` replacement and shows the source-level "constant-time" property doesn't survive
lowering to the engine's arbitrary-precision BigInt implementation (see
`openpgp_patch/Readme.md` and `NOTE.md` for the full mechanism).

Read `NOTE.md` first for the detailed writeup of the attack mechanism, calibration, and bit-inference
algorithm — it is more thorough than this file and should be treated as the authoritative
explanation of *why* the code here is structured the way it is.

## Build

This experiment does not build standalone — it's a CMake target of the parent SCAR_Artifact
project, which also builds a modified QuickJS submodule, shared attack primitives, and utility
libraries this code depends on. From the repository root (`/home/ddinh02/SCAR_Artifact`):

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j"$(nproc)"
```

To rebuild just this experiment's targets after initial configuration:

```bash
cmake --build build --target quickjs_rsa -j"$(nproc)"
cmake --build build --target quickjs_rsa_key_pool -j"$(nproc)"
cmake --build build --target quickjs_rsa_fr -j"$(nproc)"
```

CMake's configure step invokes `setup.sh` (pins CPU frequency, disables ASLR) and prompts for
`sudo`; a 2.4 GHz `cpufreq-set`-capable host with CPUs 0–15 is assumed. See the root `Readme.md`
for the full hardware/software preconditions — these experiments are timing-sensitive and results
are not meaningful without them.

Python tooling (`gen_key_pool.py`, `evaluation/extract_openpgp_rsa.py`) runs in the venv described
in the root `Readme.md` (`python3 -m venv .venv && pip install -r requirements.txt`, run from
`/home/ddinh02/SCAR_Artifact`).

## Running the experiment

Three C binaries act as the *attacker* and coordinate with a QuickJS *victim* process through the
artifact's shared-memory synchronization context (`shared_memory.h`, `QUICKJS_PROJ_ID`).
`quickjs_rsa.c`/`quickjs_rsa_key_pool.c` are Prime+Scope and share the same eviction-set
calibration logic; `quickjs_rsa_fr.c` is a Flush+Reload attacker (single-key only, `KEY_ID=0`) that
needs no eviction sets since it flushes/reloads `target_goto8`/`target_sar` directly in the
`libquickjs.so` pages shared with the victim — see `NOTE.md`'s "Flush+Reload variant" section.

Victim (run from `build/`):
```bash
taskset -c 1,3,5,7,9,11,13,15 ./src/runtime/quickjs/quickjs_rt ../experiments/quickjs_rsa/js/openpgp_rsa.js
```

Attacker — single key (`quickjs_rsa.c`, reads `VICTIM_RUNS` env var, default 1 run):
```bash
taskset -c 1,3,5,7,9,11,13,15 ./experiments/quickjs_rsa/quickjs_rsa
```

Attacker — full key pool (`quickjs_rsa_key_pool.c`, the main evaluation path):
```bash
taskset -c 1,3,5,7,9,11,13,15 ./experiments/quickjs_rsa/quickjs_rsa_key_pool [num_keys] [num_runs] [goto8_base_freq] [sar_base_freq]
# defaults: 128 keys x 128 runs, goto8_base_freq=10800, sar_base_freq=5400
```

Both attacker binaries: locate the LLC sets containing the `goto8`/`sar` bytecode-handler cache
lines by profiling every L3 set during a synchronized QuickJS warm-up and testing candidate sets
against expected timestamp-spacing distributions and power-spectrum frequencies
(`identify_quickjs_target_sets`); then run two `PS_attacker_thread` (Prime+Scope) threads
concurrently, one per cache line, dumping per-key traces used by the evaluation script. If no
matching sets are found, the key-pool binary signals the victim to exit via
`sync_ctx_set_action(SYNC_CTX_EXIT)` rather than hanging.

Extract bits and score accuracy against the known keys (run from the repo root):
```bash
python experiments/quickjs_rsa/evaluation/extract_openpgp_rsa.py -p build/output/quickjs_rsa_key_pool --at PS
```
`--at` selects the attack technique (`FR`/`PS`/`PP`); `-p/--keypool`, `-d/--directory`, and
`-f/--file` (mutually exclusive) select what trace data to score; `--plot` and `--adaptive` control
extra output. The script is where all the bit-inference intelligence lives — see below.

### Key pool

`gen_key_pool.py` (run from this directory) generates the RSA-4096 test keys via `openssl genrsa`
and re-encodes them (`n`, `e`, `d`, `p`, `q`, `u` as `0x`-prefixed hex) into `rsa_key_pool/rsa_key_<id>.json`.
Regenerate with:
```bash
python3 gen_key_pool.py
```
`js/openpgp_rsa.js` reads `KEY_ID` from the environment and loads the matching JSON to sign with.

### Patch follow-up study

```bash
cd openpgp_patch
./run_eval.sh -n 200000 -b 4095 -s 1 -c 10   # timing bench on qjs + d8 (V8)
python3 plot_dist.py                          # -> results/leakage_summary.csv, distribution.html
```
For QuickJS bytecode-handler timing and Intel PT instruction-path localization
(`run_opcode_timing.sh`, `run_intel_pt.sh`), see `openpgp_patch/INTEL_PT_LOCALIZATION.md` — these
depend on modified engine binaries, CPU pinning, and Intel PT/perf availability that aren't part of
the default build.

## Architecture

- **`quickjs_rsa.c`** / **`quickjs_rsa_key_pool.c`** — the Prime+Scope attacker/controller binaries.
  Both link against the shared `utils`, `prime_probe`, and `quickjs_runtime` libraries defined at the
  SCAR_Artifact root (`src/utils`, `src/attack`, `src/runtime/quickjs`). `quickjs_rsa_key_pool.c` is
  the one actually used for the paper's evaluation; `quickjs_rsa.c` is a simpler single-key variant.
  Cache-line targets (`target_goto8`, `target_sar`) come from
  `quickjs_get_bytecode_handler_cacheline()` in the shared `quickjs_runtime` library — this is where
  to look if the QuickJS build changes and handler addresses need to be relocated.
- **`quickjs_rsa_fr.c`** — the Flush+Reload attacker (single-key, `KEY_ID=0` only). Links
  `flush_reload` (`include/flush_reload.h`, `FLUSH_CACHE_LINE`/`RELOAD_CACHE_LINE`/`FR_wait`) plus
  `prime_probe` (only for `dump_profiling_traces`, the shared trace-dump format). It drives the
  victim through the exact same `sync_ctx.barrier` handshake `PS_profile_once` uses internally
  (see `src/attack/prime_probe.c`), just with a flush/wait/reload loop instead of cache-set probing.
  Its `waiting_time` constant is a hardware-timing guess, not a derived value.
- **`js/openpgp.js`** — bundled OpenPGP.js v5.11.2; `js/openpgp_rsa.js` is the victim entry point run
  under `quickjs_rt`; `js/utils.js` provides `FindProjectRoot()` for locating the key pool from
  inside the QuickJS sandbox.
- **`rsa_key_pool/`** — 128 pre-generated RSA-4096 keys (`rsa_key_<id>.json`) used both as victim
  input and as ground truth for scoring the attack. Regenerate via `gen_key_pool.py`, not by hand.
- **`evaluation/extract_openpgp_rsa.py`** — turns raw probe-latency traces into handler-hit events,
  segments them per signing execution, estimates the `sar` interval, walks the trace in reverse
  (exponentiation consumes `d` LSB-first) to infer each bit from `goto8` presence/absence within a
  `sar` interval, merges repeated-trace votes with a confidence band (`[0.85, 0.98]`: below → 0,
  above → 1, between → unknown), and scores against the real `d` from the key pool. `evaluation/utils.py`
  holds shared helpers. This script — not the C code — is where the actual side-channel signal
  processing and inference logic lives; changes to the attack's accuracy characteristics almost
  always mean changes here.
- **`openpgp_patch/`** — a separate, mostly self-contained sub-experiment (own `js/`, `bench.mjs`,
  shell scripts, Python plotting) evaluating the proposed branchless `selectBigInt` fix. Not linked
  into the main CMake attack binaries; it drives QuickJS/V8 (`d8`) directly as subprocesses.

## Notes for making changes

- Base frequencies (`goto8_base_freq`/`sar_base_freq`) and distribution-check thresholds
  (`check_goto8_distribution`, `check_sar_distribution`) in the C attacker code are calibrated to
  the observed handler-invocation rate for the current QuickJS build/key size; if the victim
  workload or QuickJS commit changes, these likely need recalibrating.
- The two attacker binaries duplicate most of their calibration logic (`identify_quickjs_target_sets`,
  `check_*_distribution`, `qsort_lt`) — this is existing duplication in the codebase, not something
  introduced by a task; keep both in sync if you touch the shared calibration approach.
