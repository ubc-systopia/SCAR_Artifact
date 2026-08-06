# QuickJS/OpenPGP.js RSA experiment

## What this case study asks

This experiment asks whether a JavaScript cryptographic routine can leak an RSA
private key through the JavaScript engine even when the routine attempts to
balance its high-level arithmetic work.

The victim is OpenPGP.js v5.11.2 running on QuickJS commit `3b45d15`. During an
RSA signature, OpenPGP.js performs modular exponentiation with the private
exponent `d`. The experiment observes QuickJS's bytecode execution through a
cache side channel and attempts to reconstruct the bits of `d`.

There are two related studies in this directory:

1. The main SCAR case study (`quickjs_rsa*.c`, `js/`, and `evaluation/`) attacks
   the original OpenPGP.js implementation with Prime+Scope-style cache probes.
2. `openpgp_patch/` evaluates a proposed branchless replacement and shows why
   source-level constant-time code can still have condition-dependent timing in
   a JavaScript engine's BigInt implementation.

## The vulnerable computation

The relevant OpenPGP.js code is `BigInteger.modExp` in `js/openpgp.js`:

```js
while (exp > 0n) {
  const lsb = exp & 1n;
  exp >>= 1n;
  const rx = (r * x) % n;
  r = lsb ? rx : r;
  x = (x * x) % n;
}
```

This is a right-to-left square-and-multiply exponentiation. Each loop iteration
consumes the current least-significant secret-exponent bit. Multiplication and
reduction are calculated on every iteration, which helps balance the obvious
arithmetic workload, but the assignment still uses a ternary expression whose
condition is the secret bit.

QuickJS lowers that ternary to condition-dependent bytecode control flow. In
particular, the experiment follows two bytecode-handler cache lines:

- `sar`: the right-shift in `exp >>= 1n`; it acts as a marker for each exponent
  bit/loop iteration.
- `goto8`: a conditional-control-flow handler associated with the ternary; its
  presence in a `sar` interval indicates one value of the secret bit.

Thus, `sar` supplies the clock or iteration boundaries and `goto8` supplies the
bit-dependent signal. The attack is not measuring the total signing time. It
is observing which interpreter code is brought into the shared last-level
cache and when.

## Victim workload and key pool

`js/openpgp_rsa.js` is the victim program. It:

1. reads `KEY_ID` from the environment;
2. loads `rsa_key_pool/rsa_key_<id>.json`;
3. generates an AES-256 session key and hashes it with SHA-256; and
4. creates an RSA signature with the loaded private key.

The JSON files contain `n`, `e`, `d`, `p`, `q`, and `u`. `gen_key_pool.py`
generates 128 RSA-4096 keys by default using OpenSSL, then converts them to this
format. The pool permits evaluation across many independent private exponents
instead of presenting one favorable key as the result.

## Main cache attack

The C executables are built as part of the parent SCAR artifact and use its
QuickJS runtime, shared-memory synchronization, cache utilities, and
Prime+Scope/Prime+Probe machinery.

### 1. Locate the relevant LLC sets

`quickjs_get_bytecode_handler_cacheline()` obtains the addresses of the target
QuickJS handlers. The attacker builds eviction sets and tests candidate LLC
sets whose page offsets match `goto8` and `sar`.

During a synchronized QuickJS warm-up, each candidate is profiled. A candidate
is accepted only if its timestamp-spacing distribution and power spectrum
match the expected handler frequency. This calibration avoids assuming that
the attacker already knows the physical LLC-set mapping.

The default key-pool program expects approximate base frequencies of 10,800 for
`goto8` and 5,400 for `sar`; both can be overridden on the command line.

### 2. Trace signing

After finding both sets, two attacker threads monitor them concurrently—one
for `goto8`, one for `sar`. The victim and attacker coordinate through the
artifact's shared synchronization context. For each key, the controller sends
`KEY_ID=<id>` to the victim and records timestamp/latency traces while the
victim signs.

`quickjs_rsa_key_pool` defaults to 128 keys and 128 victim runs per key. Its
arguments are:

```text
quickjs_rsa_key_pool [num_keys] [num_runs] [goto8_base_freq] [sar_base_freq]
```

`quickjs_rsa` is the corresponding single-key/simpler experiment; its number
of victim runs can be set with `VICTIM_RUNS`.

### 3. Infer private-exponent bits

`evaluation/extract_openpgp_rsa.py` converts probe latencies into handler-hit
events, orders them by timestamp, and separates repeated signing executions at
large gaps. It estimates the median distance between `sar` hits and walks a
trace in reverse because modular exponentiation consumes `d` from least to
most significant bit, whereas keys are normally written most significant bit
first.

For each expected `sar` interval, a suitably placed `goto8` hit is interpreted
as a 1; its absence is interpreted as a 0. The script includes heuristics for
duplicate samples, missed `sar` events, noisy intervals, and finding the end of
the exponentiation region. It also supplies the known leading and trailing 1
bits expected for the RSA private exponent.

One trace yields a noisy candidate bit string. Candidates from repeated
signatures of the same key are merged by counting how often each position was
inferred as 1. With the configured confidence band `[0.85, 0.98]`:

- a 1-rate at or above 0.98 is reported as 1;
- a 1-rate at or below 0.85 is reported as 0; and
- an intermediate rate is left unknown rather than guessed.

Because this is an artifact evaluation, the real `d` from the key pool is then
used to report known-bit accuracy, unknown bits, wrong bits, and aggregate
statistics across the pool. Ground truth is for scoring the attack, not an
input to the trace-to-bit inference itself (apart from knowing the exponent
length and the optional evaluation-time choice of thresholds).

## What the main experiment demonstrates

The intended conclusion is that timing-balanced source code is insufficient
when a secret controls interpreter bytecode flow. A colocated attacker able to
observe shared LLC activity can recover most or all private-exponent bits from
repeated RSA signatures, even though both square and multiply arithmetic is
performed on every exponent iteration.

This is a controlled local side-channel experiment. It assumes the attacker
can run concurrently on the same machine/LLC, construct eviction sets, and
synchronize with or identify victim executions. It is not, by itself, a
demonstration of remote key recovery from network timing.

## Flush+Reload variant

`quickjs_rsa_fr.c` is a Flush+Reload attacker against the same `goto8`/`sar`
targets, single-key only (it always attacks the default `KEY_ID=0`, unlike
`quickjs_rsa_key_pool.c`'s key sweep). QuickJS is built as `libquickjs.so`
(`third_party/CMakeLists.txt`) and dynamically linked into both the victim
(`quickjs_rt`) and the attacker, so with ASLR disabled both processes map the
handler dispatch table at the same address in the same shared physical pages —
`clflush`/timed-reload against `target_goto8`/`target_sar` (still computed
in-process via `quickjs_get_bytecode_handler_cacheline()`) observes the victim's
actual cache activity directly, with no eviction-set construction or LLC-set
calibration needed (that machinery is Prime+Scope-only).

Each measurement round flushes both target lines, waits a fixed number of TSC
cycles (`waiting_time`), then times a reload of each — repeating up to
`profile_iterations` times per victim signing pass. This produces the same
`tsc:latency` trace format Prime+Scope already produces
(`evaluation/extract_openpgp_rsa.py`'s bit-inference walk is driven by an
empirically-computed `sar_median` per trace, not a hardcoded frequency, so it is
reused unchanged for Flush+Reload traces via `--at FR`); the only attack-specific
constants are `waiting_time` (C) and the matching `FR_sample_interval`/`FR_fs`/
`FR_target_freq` (`evaluation/utils.py`), which feed `post_processing_boundary`'s
STFT-based trace-boundary detector. These are hardware-timing constants, exactly
like Prime+Scope's `goto8_base_freq`/`sar_base_freq`, and ship as starting guesses
that need tuning against real traces (compare recovered bits to the key pool's
known `d`) rather than derived analytically.

## Follow-up: evaluation of the proposed patch

The OpenPGP.js team proposed replacing the secret-dependent ternary with:

```js
function selectBigInt(cond, a, b, maxBitLength) {
  const mask = 1n << maxBitLength;
  return (a & (mask - cond)) | (b & (mask - 1n + cond));
}
```

At the JavaScript level this contains no conditional branch. The
`openpgp_patch/` experiments ask a different question: is one call to this
selection actually indistinguishable for `cond = 0n` and `cond = 1n` after the
engine implements all of those BigInt operations?

### End-to-end timing test

`run_eval.sh` runs `bench.mjs` on both QuickJS and V8 (`d8`). It uses fixed,
4095-bit random operands by default, warms the engine, randomly interleaves the
two conditions, and times exactly one selection per sample using `rdtscp`.
Deterministic seeds give the engines the same operands and condition sequence.
The ternary implementation is included as a comparison. The plotting scripts
summarize median timing differences and single-sample distinguishability (AUC).

The directory README states the observed result: the branchless selection is
still distinguishable on both engines because their arbitrary-precision BigInt
operations are not constant-time.

### QuickJS bytecode timing and Intel PT localization

The follow-up then localizes the QuickJS effect in two complementary ways:

- `run_opcode_timing.sh` instruments QuickJS bytecode handlers and compares
  cycles for false and true calls over repeated runs.
- `run_intel_pt.sh` records Intel Processor Trace for one fixed-false and one
  fixed-true call, decodes their native instruction paths, and creates
  `pt_results/path_diff.txt`.

The stored ten-run summary identifies `add` as the dominant stable difference:
its median true-minus-false cost is about +1455 cycles. Intel PT locates the
first important divergence in QuickJS's `bf_add_internal` at the test for a
zero-length operand. In the expression `mask - 1n + cond`:

```text
cond = 0n: large BigInt + 0n  -> zero-operand copy shortcut
cond = 1n: large BigInt + 1n  -> allocation and full limb arithmetic
```

Intel PT establishes that the native paths differ; the handler timing
experiment establishes that the difference has a stable cycle cost. Together
they explain why removing the explicit JavaScript branch did not make the
operation constant-time.

## Reproduction map

From the artifact build directory, the victim and main key-pool attack are run
as documented in `Readme.md`, commonly pinned with `taskset`:

```bash
# Victim QuickJS runtime
taskset -c 1,3,5,7,9,11,13,15 \
  ./src/runtime/quickjs/quickjs_rt \
  ../experiments/quickjs_rsa/js/openpgp_rsa.js

# Attacker/controller (defaults: 128 keys x 128 runs)
taskset -c 1,3,5,7,9,11,13,15 \
  ./experiments/quickjs_rsa/quickjs_rsa_key_pool
```

Then extract and score the key pool from the artifact root:

```bash
python experiments/quickjs_rsa/evaluation/extract_openpgp_rsa.py \
  -p build/output/quickjs_rsa_key_pool --at PS
```

For the patch timing study:

```bash
cd experiments/quickjs_rsa/openpgp_patch
./run_eval.sh -n 200000 -b 4095 -s 1 -c 10
python3 plot_dist.py
```

For QuickJS handler timing and Intel PT localization, see
`openpgp_patch/INTEL_PT_LOCALIZATION.md`; those steps depend on the modified
engine binaries, CPU pinning, and Intel PT/perf availability described there.

## File guide

- `Readme.md`: short instructions for the main case study.
- `js/openpgp_rsa.js`: RSA-signing victim.
- `js/openpgp.js`: bundled OpenPGP.js containing the original `modExp`.
- `quickjs_rsa.c`: single-experiment Prime+Scope cache attacker.
- `quickjs_rsa_key_pool.c`: multi-key, repeated-trace Prime+Scope attacker/controller.
- `quickjs_rsa_fr.c`: single-key Flush+Reload attacker against the same
  `goto8`/`sar` cache lines, viable because `libquickjs.so` is a shared library
  mapped by both the victim and the attacker (see "Flush+Reload variant" below).
  Its timing constants are starting guesses and need hardware-specific
  calibration, same as the Prime+Scope base frequencies below.
- `gen_key_pool.py` and `rsa_key_pool/`: RSA-4096 test-key generation/data.
- `evaluation/extract_openpgp_rsa.py`: trace segmentation, bit inference,
  repeated-trace voting, and accuracy reporting.
- `openpgp_patch/`: end-to-end timing, bytecode timing, and Intel PT analysis of
  the proposed branchless selection.

