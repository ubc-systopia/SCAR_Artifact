# Case Study 5: CPython — Dictionary

Reproduces the results in **paper §5.5** (CPython — Dictionaries).

CPython version: `v3.13.1`

## Description

This case study evaluates the exploitability of data access patterns in
Python's dictionary implementation.

CPython's dictionary contains secret-dependent data access patterns. An
adversary can use them to recover which entry was looked up.

## Evaluation

To run the evaluation execute the following commands:

```bash
./experiments/cpython_dictionary/evaluation/run_dict.sh
```

## Replay the attack

```text
build/experiments/cpython_dictionary/output/cpython_dict_<YYYYmmdd_HHMMSS>/
    meta.txt          configuration and the hit-count band
    targets.txt       the four target dictionary indices
    select_sets.txt   the LLC sets that form the fingerprint
    fingerprints.txt  per-target reference LLC hit vector
    calibration.txt   self and cross similarity, and the chosen threshold
    attack.txt        one row per attack access, with ground truth
```

```bash
build/cpython/venv/bin/python3 experiments/cpython_dictionary/evaluation/replay_dict.py \
    build/experiments/cpython_dictionary/output/cpython_dict_<stamp>
```

### Plotting the attack

```bash
scp -r leapx02:/home/yayu/Project/SCAR_Artifact/build/output/ae_backup/cpython_dictionary_replay_2026-09-20/cpython_dict_fin4_try1 /tmp/
.venv/bin/python experiments/cpython_dictionary/evaluation/replay_dict.py \
    /tmp/cpython_dict_fin4_try1 --plot /tmp/attack.html
```
