# Case Study 3: CPython — Dictionary

CPython version: `v3.13.1`

## Description

Case Study 3: CPython — Dictionary evaluates the exploitability of data access patterns in Python's dictionary implementation.

CPython's internal implementation of dictionaries contains secret-dependent data access patterns that can be used to recover keys used to access the dictionary. 

## Evaluation

To run the evaluation execute the following commands:

```bash
cd build/src/runtime/cpython/
./cpython_rt <absolute_project_path>/experiments/cpython_dictionary/cpython_dictionary.py 32
```

```bash
cd build/experiments/cpython_dictionary/
./cpython_dictionary
```
