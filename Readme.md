# SCAR Artifact

Artifact for "Cache Side Channel Attacks on Language Runtimes"

## Hardware/Software Setup
- CPU: Intel Xeon(R) Silver 4390Y SP
- DVFS: `Off`
- CpuFreq: `2.4GHz`
- Hyperthreading: `Off`
- ASLR: `Off`


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
time.

To rebuild only one experiment after the initial configuration, pass its CMake
target. For example:

```bash
cmake --build build --target quickjs_jpeg -j"$(nproc)"
```

Generated traces and other experiment results are written below `build/output/`.

## Case Studies
1. [QuickJS — OpenPGP.js](./experiments/quickjs_rsa/Readme.md)
2. [QuickJS — jpeg-js](./experiments/quickjs_jpeg/Readme.md)
3. [CPython — Dictionaries](./experiments/cpython_dictionary/Readme.md)
4. [CPython — `pow`](./experiments/cpython_pow/Readme.md)
5. [V8 — Elliptic](./experiments/v8_ecdh/Readme.md)
