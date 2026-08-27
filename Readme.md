# SCAR Artifact

Artifact for "Cache Side Channel Attacks on Language Runtimes"

## Hardware/Software Setup
- CPU: Intel Xeon(R) Silver 4390Y SP
- DVFS: `Off`
- CpuFreq: `2.4GHz`
- Hyperthreading: `Off`
- ASLR: `Off`


## Getting the sources

The runtimes and the eviction-set library are git submodules, and one of them
(LLCFeasible) has a submodule of its own, so the checkout has to be recursive.
A tree without them fails at CMake configure time with `third_party/LLCFeasible
does not contain a CMakeLists.txt file`, and one that is only one level deep
fails to compile with `ptedit_header.h: No such file or directory`.

```bash
git clone --recurse-submodules <repository-url> SCAR_Artifact
cd SCAR_Artifact
```

For a checkout that already exists:

```bash
git submodule update --init --recursive
```

## Python environment

Create a virtual environment for evaluation and plotting scripts:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The build creates a separate CPython 3.13 virtual environment for the CPython
runtime experiments.

## System configuration

[`setup.sh`](./setup.sh) performs the following operations:

```text
Set CPUs 0--15 to 2.4 GHz
Disable ASLR by writing 0 to /proc/sys/kernel/randomize_va_space
```

It is invoked automatically during CMake configuration and prompts for `sudo`.
Before continuing, ensure the host exposes CPUs 0--15 and supports a 2.4 GHz
frequency through `cpufreq-set`. Hyperthreading and DVFS must be configured in
the firmware or operating system separately.

To restore ASLR after running the experiments:

```bash
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

Restore the normal CPU-frequency governor using the method appropriate for your
Linux distribution.

## Build

From the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j"$(nproc)"
```

This builds the modified QuickJS and CPython submodules and fetches/builds V8 if
it is not already present. The first complete build can therefore take a long
time: the V8 fetch alone pulls tens of gigabytes through `depot_tools` and is
followed by a full V8 compile. A successful build produces 31 CMake targets,
including these eleven experiment binaries:

```text
build/experiments/quickjs_rsa/{quickjs_rsa,quickjs_rsa_key_pool,quickjs_rsa_fr,
                               quickjs_select_fr,quickjs_select_rsa_fr,
                               quickjs_select_rsa_ps}
build/experiments/quickjs_jpeg/quickjs_jpeg
build/experiments/cpython_dictionary/cpython_dictionary
build/experiments/cpython_pow/cpython_pow
build/experiments/v8_ecdh/v8_ecdh_key_pool
build/experiments/v8_constant_time_js/v8_ctjs_ecdh
```

### Build options

V8 is required: two of the six case studies run inside it, and it is always
built. If a V8 checkout already exists elsewhere on the machine, point the
build at it with `V8_SRC_DIR` instead of fetching a second copy. The directory
must already contain `out.gn/x64.release` with `libv8_monolith.a`,
`libv8_libbase.a` and `libv8_libplatform.a`:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DV8_SRC_DIR=/path/to/v8
cmake --build build -j"$(nproc)"
```

To rebuild only one experiment after the initial configuration, pass its CMake
target. For example:

```bash
cmake --build build --target quickjs_jpeg -j"$(nproc)"
```

Generated traces and other experiment results are written below `build/output/`.

## Case Studies

Each case study has its own Readme with the commands to reproduce it and the
result to expect. Everything else about the attacks is in the paper.

| # | case study | paper |
| --- | --- | --- |
| 1 | [QuickJS — OpenPGP.js](./experiments/quickjs_rsa/Readme.md) | §4.2 |
| 2 | [QuickJS — jpeg-js](./experiments/quickjs_jpeg/Readme.md) | §4.3 |
| 3 | [CPython — Dictionaries](./experiments/cpython_dictionary/Readme.md) | §4.6 |
| 4 | [CPython — `pow`](./experiments/cpython_pow/Readme.md) | §4.7 |
| 5 | [V8 — Elliptic](./experiments/v8_ecdh/Readme.md) | §4.4 |
| 6 | [V8 — constant-time-js](./experiments/v8_constant_time_js/Readme.md) | §4.5 |

The disclosure and patch analysis in §4.2 has two further directories:
[`openpgp_patch/`](./experiments/quickjs_rsa/openpgp_patch/Readme.md) for the
timing distributions and
[`openpgp_patch_rsa/`](./experiments/quickjs_rsa/openpgp_patch_rsa/Readme.md)
for the key-recovery attack on the patched selector.
