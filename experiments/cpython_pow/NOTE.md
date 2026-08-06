# Understanding `cpython_pow.c`

`cpython_pow.c` is a cache side-channel profiler targeting CPython's modular
exponentiation routine. It runs alongside a Python victim that performs an RSA
signature and records when three secret-dependent paths inside CPython's
`long_pow()` execute.

The goal is to turn those cache observations into information about the RSA
private exponent.

## Basic idea

The victim executes:

```python
rsa.sign(b"Hello, world!", key, "SHA-256")
```

Python-RSA eventually performs a computation equivalent to:

```python
pow(message, private_exponent, modulus)
```

For large exponents, CPython uses sliding-window exponentiation. Its control
flow depends on the exponent bits. This repository's instrumented CPython
exposes three useful code locations:

- `consume_zero`: a zero outside a pending exponent window was processed.
- `absorb_window`: a bit inside a full exponent window was processed.
- `absorb_trailing`: a trailing zero belonging to a window was processed.

By observing the timing of these locations, the evaluation scripts can infer
the exponent's bit pattern.

The targets are declared in `cpython_pow.h`:

```c
#define CPYTHON_TARGET_CACHELINE(V)                         \
    V(consume_zero, python_language_feature_targets[2], 1)  \
    V(absorb_window, python_language_feature_targets[3], 1) \
    V(absorb_trailing, python_language_feature_targets[5], 1)
```

## Buffers and synchronization

The profiler monitors three cache lines and stores at most 16,384 samples per
line:

```c
#define CACHE_LINE_COUNT (3)
#define PROFILE_ITERATIONS (1 << 14)
```

`tsc_buffer` stores CPU timestamp-counter values. `lat_buffer` stores reload or
probe latencies. They are divided into three logical slices:

```text
slot 0 -> consume_zero
slot 1 -> absorb_window
slot 2 -> absorb_trailing
```

The attacker and victim communicate through `sync_ctx`. Shared barriers
coordinate initialization, key changes, the beginning and end of a signature,
and process termination.

The target macros resolve each exported CPython instrumentation address and
align it to a cache-line boundary:

```c
target_NAME = ((uintptr_t)(BASE_ADDR + OFFSET) & CACHE_LINE_MASK);
```

The profiler then monitors a line at `target_NAME + 2 * CACHE_LINE_SIZE`, based
on the layout of the instrumented branch code.

## Flush+Reload mode

`FF_profile_pow()` implements the Flush+Reload attack. For every victim run it:

1. Tells the victim to begin.
2. Flushes all three target cache lines.
3. Waits 80,000 cycles.
4. Reloads each line and measures its access time.
5. Repeats up to 16,384 times.
6. Dumps the timestamp and reload-latency traces.

Its central loop is:

```c
FLUSH_CACHE_LINE(consume_zero, 2);
FLUSH_CACHE_LINE(absorb_window, 2);
FLUSH_CACHE_LINE(absorb_trailing, 2);

FR_wait(waiting_time);

RELOAD_CACHE_LINE(consume_zero, 2, 0);
RELOAD_CACHE_LINE(absorb_window, 2, 1);
RELOAD_CACHE_LINE(absorb_trailing, 2, 2);
```

If the victim executed one of these lines during the wait, it brought that line
back into the cache, making the attacker's reload relatively fast.

## Prime+Scope mode

`PS_profile_pow()` implements the more involved Prime+Scope path. Instead of
directly reloading victim code, the attacker creates an eviction set for each
target. An eviction set is a collection of attacker-controlled addresses that
map to the same cache set as the victim address.

```text
Attacker primes a cache set
          |
Victim executes target code
          |
Victim conflicts with attacker data
          |
Attacker observes a slow probe
```

Three concurrent attacker threads monitor the three targets. A local barrier
makes them start each profiling run together. The shared `PS_profile_once()`
routine records an event when probe latency exceeds the detected L2 threshold
but remains below the interrupt/noise threshold.

## Finding eviction sets

Prime+Scope supports two strategies.

### Direct construction

Without `-csi`, `build_cpython_pow_evsets()` calls `prepare_evset()` with each
known target address. It retries construction up to four times per target.

### Cache-set identification

With `-csi`, the profiler searches candidate cache sets using specially
patterned calibration exponents:

- `csi_cz.pem`: one followed by zeros, emphasizing `consume_zero`.
- `csi_aw.pem`: all ones, emphasizing `absorb_window`.
- `csi_at.pem`: repeated `10000`, emphasizing `absorb_trailing`.

For each candidate, `identify_one_target()`:

1. Tells the victim to load the relevant calibration key.
2. Profiles the candidate eviction set.
3. Examines gaps between recorded timestamps.
4. Accepts the set if the gaps match the expected calibration pattern.

The candidate search filters by `page_slot`. Cache-index bits contained in the
page offset are known from the target virtual address, so incompatible cache
sets can be skipped.

## Key handling

Normally, the victim loads:

```text
experiments/cpython_pow/private.pem
```

With `-key_pool`, the program instead profiles keys named:

```text
rsa_key_0.pem
rsa_key_1.pem
...
```

The default pool size is 128, and `-num_keys N` changes it. Each key receives a
separate trace prefix such as:

```text
cpython_pow_key_pool/cpython_pow_key00042
```

## Command-line interface

```text
cpython_pow [-FR | -PS] [-csi] [-key_pool [-num_keys count]] [iterations]
```

Examples:

```bash
cpython_pow -FR 10
cpython_pow -PS 10
cpython_pow -PS -csi 10
cpython_pow -PS -csi -key_pool -num_keys 128 5
```

The program rejects missing or conflicting attack modes, use of `-key_pool`
with Flush+Reload, and zero victim iterations.

## End-to-end flow

```text
Start cpython_pow attacker
        |
Synchronize with Python runtime
        |
Resolve three CPython code locations
        |
Build or discover their eviction sets
        |
Tell the victim which RSA key to load
        |
Start synchronized profiler threads
        |
Victim calls rsa.sign(), which invokes pow()
        |
Record zero/window/trailing events
        |
Dump timestamp and latency traces
        |
evaluation/extract.py infers exponent information
```

In short, `cpython_pow.c` does not calculate `pow()`. It observes CPython
calculating `pow()` and records secret-dependent cache activity produced by the
RSA private exponent.

## Small code observations

- The `cz_freq`, `aw_freq`, `at_freq`, `aw_side_freq`, and `at_side_freq`
  constants are unused in this file.
- The `cfg` variable created by `main()` is unused.
- `use_ps` mainly participates in argument validation. Once Flush+Reload has
  been ruled out, execution enters `PS_profile_pow()`.
