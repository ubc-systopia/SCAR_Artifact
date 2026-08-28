#!/usr/bin/env python3
import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Compare SELECT handler timings for false and true conditions"
    )
    parser.add_argument("csv", nargs="*", default=["opcode_timing.csv"])
    args = parser.parse_args()

    differences = defaultdict(list)
    print("run,handler,false_n,true_n,false_median,true_median,true_minus_false")
    for csv_path in args.csv:
        timings = defaultdict(lambda: {"false": [], "true": []})
        with open(csv_path, newline="") as source:
            for row in csv.DictReader(source):
                timings[row["handler"]][row["condition"]].append(
                    int(row["cycles"])
                )

        run = Path(csv_path).stem
        for handler in sorted(timings):
            false_values = timings[handler]["false"]
            true_values = timings[handler]["true"]
            if not false_values or not true_values:
                continue
            false_median = statistics.median(false_values)
            true_median = statistics.median(true_values)
            difference = true_median - false_median
            differences[handler].append(difference)
            print(
                f"{run},{handler},{len(false_values)},{len(true_values)},"
                f"{false_median:g},{true_median:g},{difference:+g}"
            )

    if len(args.csv) > 1:
        print("\nhandler,runs,median_difference,min_difference,max_difference")
        for handler in sorted(differences):
            values = differences[handler]
            print(
                f"{handler},{len(values)},{statistics.median(values):+g},"
                f"{min(values):+g},{max(values):+g}"
            )


if __name__ == "__main__":
    main()
