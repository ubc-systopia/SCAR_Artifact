#!/usr/bin/env python3

import os
import pathlib
import subprocess
import sys
import time
from argparse import ArgumentParser
from datetime import datetime

from extract import extract
from metrics import aggregate_metrics


class ResultsLogger(object):
    def __init__(self, out):
        self.terminal = out
        self.log = open("results.log", "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        # this flush method is needed for python 3 compatibility.
        # this handles the flush command by doing nothing.
        # you might want to specify some extra behavior here.
        pass


args_parser = ArgumentParser(
    prog="cpython_builtin_pow_lib_rsa_cross_e2e",
    description="Evaluate the attack performance of the e2e attack on python-rsa",
)
args_parser.add_argument("--output", type=str, required=False, help="Output file path")
args_parser.add_argument(
    "--iterations", type=int, required=False, help="Number of iterations", default=100
)
args_parser.add_argument(
    "--repetitions", type=int, required=False, help="Number of repetitions", default=64
)
args_parser.add_argument(
    "--traces-only",
    action="store_true",
    required=False,
    help="Only collect the traces",
    default=False,
)
args_parser.add_argument(
    "--analyze-only",
    action="store_true",
    required=False,
    help="Only analyze the traces",
    default=False,
)
args = args_parser.parse_args()

print(args)

project_dir = pathlib.Path.cwd()
root_dir = pathlib.Path(project_dir.root)
while project_dir != root_dir:
    if (project_dir / ".project").exists():
        break
    project_dir = project_dir.parent

if project_dir == root_dir:
    print("No project directory found")
    exit(1)

print("Found project directory:", project_dir)

if args.output:
    results_folder = args.output
else:
    timestamp = datetime.now().isoformat()
    results_folder = project_dir / "experiments/cpython_pow/results" / timestamp

print(f"Results will be saved in {results_folder}")
os.makedirs(results_folder, exist_ok=True)
os.chdir(results_folder)

if not args.analyze_only:
    print("Generating traces")
    for i in range(args.iterations):
        os.makedirs(str(i), exist_ok=True)
        os.chdir(str(i))

        print(f"Generating private key {i + 1}/{args.iterations}")
        subprocess.run(
            ["openssl", "genrsa", "-out", "private.pem", "-traditional", "4096"],
            stdout=subprocess.DEVNULL,
        )

        print(f"Generating traces {i + 1}/{args.iterations}")
        runtime = subprocess.Popen(
            [
                project_dir / "build/src/runtime/cpython/cpython_rt",
                project_dir / "experiments/cpython_pow/python/cpython_pow.py",
                "1",
            ],
            stdout=subprocess.DEVNULL,
        )
        time.sleep(0.1)
        attacker = subprocess.Popen(
            [
                project_dir / "build/experiments/cpython_pow/cpython_pow",
                str(args.repetitions),
            ],
            stdout=subprocess.DEVNULL,
        )

        attacker.wait()
        runtime.wait()

        os.chdir("..")


print("Analyzing traces")

stdout = sys.stdout
rout = ResultsLogger(stdout)

if not args.traces_only:
    res = []
    for i in range(args.iterations):
        print(f"Analyzing trace {i + 1}/{args.iterations}")
        os.chdir(str(i))
        # TODO: extract and analyze separately
        r = extract(".")
        for j, item in enumerate(r):
            if j < len(res):
                res[j].append(item)
            else:
                res.append([item])
        # print(res)
        os.chdir("..")

    print("Aggregating metrics")
    sys.stdout = rout
    for m in res:
        aggregate_metrics(m)
    sys.stdout = stdout

print("Done")
