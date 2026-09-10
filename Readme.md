# SCAR Artifact

Artifact for "Cache Side-Channel Attacks on Language Runtimes"

## Hardware/Software Setup
- CPU: Intel Xeon(R) Silver 4390Y SP
- DVFS: `Off`
- CpuFreq: `2.4GHz`
- Hyperthreading: `Off`
- ASLR: `Off`


## Getting the sources

```bash
git clone --recurse-submodules <repository-url> SCAR_Artifact
cd SCAR_Artifact
```

## Python environment

Create a virtual environment for evaluation scripts:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## System configuration

[`setup.sh`](./setup.sh) performs the following operations:

```text
Set CPUs 0--15 to 2.4 GHz
Disable ASLR by writing 0 to /proc/sys/kernel/randomize_va_space
```

## Build

From the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j"$(nproc)"
```

### Build options

If a V8 checkout already exists, point the build at it with `V8_SRC_DIR`.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DV8_SRC_DIR=/path/to/v8
cmake --build build -j"$(nproc)"
```


## Case Studies

Each case study has its own Readme with the commands to reproduce it and the
result to expect. Everything else about the attacks is in the paper.

| #  | case study                                                            | paper |
|----|-----------------------------------------------------------------------|-------|
| 1  | [QuickJS — OpenPGP.js](./experiments/quickjs_rsa/Readme.md)           | §5.1   |
| 1a | [OpenPGP.js patch](./experiments/quickjs_rsa/openpgp_patch/Readme.md) | §5.1.3 |
| 2  | [QuickJS — jpeg-js](./experiments/quickjs_jpeg/Readme.md)             | §5.2   |
| 3  | [V8 — Elliptic](./experiments/v8_ecdh/Readme.md)                      | §5.3   |
| 4  | [V8 — constant-time-js](./experiments/v8_constant_time_js/Readme.md)  | §5.4   |
| 5  | [CPython — Dictionaries](./experiments/cpython_dictionary/Readme.md)  | §5.5   |
| 6  | [CPython — `pow`](./experiments/cpython_pow/Readme.md)                | §5.6   |
