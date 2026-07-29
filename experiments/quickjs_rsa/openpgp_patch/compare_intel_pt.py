#!/usr/bin/env python3
import argparse
import difflib
import re


TARGETS = (
    "case_OP_add",
    "js_add_slow",
    "js_binary_arith_bigint",
    "bf_add",
    "__bf_add",
    "bf_add_internal",
    "bf_resize",
    "bf_normalize_and_round",
)


def load(path):
    lines = []
    with open(path, errors="replace") as source:
        for raw_line in source:
            line = raw_line.strip()
            if any(target in line for target in TARGETS):
                # Remove absolute instruction addresses. Symbol-relative offsets
                # remain, so traces are comparable even when ASLR is enabled.
                line = re.sub(r"\b(?:0x)?[0-9a-f]{12,16}\b", "<address>", line)
                lines.append(line)
    return lines


def main():
    parser = argparse.ArgumentParser(
        description="Compare focused false/true Intel PT instruction traces"
    )
    parser.add_argument("false_trace")
    parser.add_argument("true_trace")
    parser.add_argument("--context", type=int, default=8)
    args = parser.parse_args()

    false_lines = load(args.false_trace)
    true_lines = load(args.true_trace)
    if not false_lines or not true_lines:
        raise SystemExit(
            "no target instructions found; inspect the decoded .trace files "
            "and adjust perf's --itrace/-F options for this perf version"
        )

    print(f"false target instructions: {len(false_lines)}")
    print(f"true target instructions:  {len(true_lines)}")
    print("\n".join(difflib.unified_diff(
        false_lines,
        true_lines,
        fromfile="false",
        tofile="true",
        n=args.context,
        lineterm="",
    )))


if __name__ == "__main__":
    main()
